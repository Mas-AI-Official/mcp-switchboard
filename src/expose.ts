/**
 * `switchboard expose` — put the governed `/mcp` endpoint on the public internet through a
 * tunnel so cloud agents (ChatGPT Developer mode, remote MCP clients) can reach a machine
 * that lives behind NAT, with zero inbound firewall changes.
 *
 * Security model — why this is a SEPARATE listener, not the dashboard:
 *   - A tunnel binary (cloudflared/ngrok/tailscale) runs locally and connects to 127.0.0.1,
 *     so to the dashboard's loopback guards tunnel traffic looks local. That means the
 *     dashboard's `isLocalRequest` checks and `require_auth: auto` would NOT defend the
 *     console or the mutating `/api/*` routes if the dashboard port were tunnelled directly.
 *   - So `expose` stands up a dedicated express app that serves ONLY `/mcp`, with auth
 *     FORCED on regardless of the loopback bind, and 404s everything else. The tunnel points
 *     at THIS port. The dashboard/console and the loopback-only `/api/*` endpoints are never
 *     exposed — run `switchboard dashboard` for the console, locally, as usual.
 *   - `enableJsonResponse: true` makes `/mcp` answer with plain JSON instead of SSE, which is
 *     required behind tunnels that don't carry Server-Sent Events (e.g. cloudflared quick
 *     tunnels). Safe for the stateless server pattern (one request → one response).
 */

import { spawn, type ChildProcess } from "node:child_process";
import express from "express";
import type { Gateway } from "./gateway.js";
import type { SwitchboardConfig } from "./types.js";
import { ApiKeyStore } from "./apikeys.js";
import { mountMcpEndpoint } from "./dashboard.js";
import { log, out } from "./logger.js";

export type TunnelKind = "cloudflared" | "ngrok" | "tailscale";

export const TUNNEL_KINDS: TunnelKind[] = ["cloudflared", "ngrok", "tailscale"];

interface TunnelSpec {
  /** Binary name; spawned without a shell, so it must be on PATH. */
  bin: string;
  /** Argv to point the tunnel at the local /mcp listener on `port`. */
  args: (port: number) => string[];
  /** First match in the child's combined stdout/stderr is the public URL. */
  urlRegex: RegExp;
  /** Shown when the binary is missing (ENOENT). */
  install: string;
  /** Caveat printed before the tunnel starts. */
  note?: string;
}

const TUNNELS: Record<TunnelKind, TunnelSpec> = {
  cloudflared: {
    bin: "cloudflared",
    args: (port) => ["tunnel", "--url", `http://127.0.0.1:${port}`],
    urlRegex: /https:\/\/[a-z0-9-]+\.trycloudflare\.com/i,
    install:
      "install cloudflared — https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/ (or `winget install Cloudflare.cloudflared`)",
    note: "cloudflared quick tunnel: the URL is ephemeral and changes every run, and a config.yaml in ~/.cloudflared disables quick tunnels.",
  },
  ngrok: {
    bin: "ngrok",
    args: (port) => ["http", String(port), "--log=stdout", "--log-format=json"],
    urlRegex: /https:\/\/[a-z0-9-]+\.ngrok(?:-free)?\.(?:app|dev|io)/i,
    install:
      "install ngrok — https://ngrok.com/download (or `winget install ngrok.ngrok`), then `ngrok config add-authtoken <token>`",
    note: "ngrok's free tier injects a browser interstitial that can break programmatic MCP clients — a paid plan or reserved domain avoids it.",
  },
  tailscale: {
    bin: "tailscale",
    args: (port) => ["funnel", String(port)],
    urlRegex: /https:\/\/[a-z0-9-]+(?:\.[a-z0-9-]+)*\.ts\.net/i,
    install:
      "install Tailscale — https://tailscale.com/download, then enable Funnel for this node (HTTPS certs + the `funnel` node attribute).",
    note: "tailscale funnel serves on your tailnet's stable *.ts.net name (no random URL) but requires Funnel to be enabled for this node.",
  },
};

/**
 * Stand up the dedicated `/mcp`-only listener: bearer auth forced on, JSON responses for
 * tunnel compatibility, and a catch-all 404 so nothing but `/mcp` is ever served.
 */
async function startMcpListener(
  gateway: Gateway,
  host: string,
  port: number,
  apiKeys: ApiKeyStore,
): Promise<{ url: string; close: () => Promise<void> }> {
  const app = express();
  app.use(express.json());
  // Auth is unconditionally required here — this listener is, by definition, public.
  mountMcpEndpoint(app, gateway, { requireAuth: () => true, apiKeys, enableJsonResponse: true });
  app.use((_req, res) => res.status(404).json({ error: "not found — only /mcp is exposed" }));

  return new Promise((resolveListener, reject) => {
    const server = app.listen(port, host, () => {
      resolveListener({
        url: `http://${host}:${port}/mcp`,
        close: () => new Promise<void>((done) => server.close(() => done())),
      });
    });
    server.on("error", (err) => {
      const e = err as NodeJS.ErrnoException;
      reject(
        new Error(
          e.code === "EADDRINUSE"
            ? `local port ${port} is busy — pass --port <n> to pick another`
            : e.message,
        ),
      );
    });
  });
}

/**
 * Spawn the tunnel binary and resolve once it prints its public URL. Rejects on a missing
 * binary (with an install hint), on a premature exit, or after a 45s timeout.
 */
function spawnTunnel(kind: TunnelKind, targetPort: number): Promise<{ child: ChildProcess; publicUrl: string }> {
  const spec = TUNNELS[kind];
  const child = spawn(spec.bin, spec.args(targetPort), { stdio: ["ignore", "pipe", "pipe"] });

  return new Promise((resolveUrl, reject) => {
    let settled = false;
    let buf = "";
    const tail = () => buf.slice(-2000) || "(no output captured)";

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      child.kill();
      reject(new Error(`timed out after 45s waiting for ${kind} to report a public URL.\nCaptured output:\n${tail()}`));
    }, 45_000);

    const scan = (chunk: Buffer): void => {
      if (settled) return;
      buf += chunk.toString();
      const m = buf.match(spec.urlRegex);
      if (m) {
        settled = true;
        clearTimeout(timer);
        resolveUrl({ child, publicUrl: m[0] });
      }
    };
    child.stdout?.on("data", scan);
    child.stderr?.on("data", scan);

    child.on("error", (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const e = err as NodeJS.ErrnoException;
      reject(new Error(e.code === "ENOENT" ? `'${spec.bin}' not found — ${spec.install}` : e.message));
    });
    child.on("exit", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new Error(`${kind} exited (code ${code ?? "?"}) before reporting a URL.\nCaptured output:\n${tail()}`));
    });
  });
}

/** Print the paste-ready connection block once the public URL is known. */
function printConnectionInfo(publicMcp: string, apiKeys: ApiKeyStore, issuedToken: string | null): void {
  out("");
  out("  ┌─ Switchboard is live on the public internet ────────────────────");
  out("  │");
  out(`  │  MCP endpoint:  ${publicMcp}`);
  out("  │  Auth:          required — bearer API key");
  out("  │");
  if (issuedToken) {
    out("  │  API key (shown once — copy it now):");
    out(`  │    ${issuedToken}`);
  } else {
    out(`  │  Present one of your ${apiKeys.count} existing API keys as the bearer token.`);
    out("  │  Lost it? `switchboard apikey new <name>`, or rerun with --new-token.");
  }
  out("  │");
  out("  │  ChatGPT (Settings → Connectors → Developer mode → Add):");
  out(`  │    URL     ${publicMcp}`);
  out("  │    Header  Authorization: Bearer <token>");
  out("  │");
  out("  │  Claude Desktop / Claude Code reach localhost directly — no tunnel needed.");
  out("  │  claude.ai (web) requires OAuth 2.1, not a bearer token (Phase 5).");
  out("  │");
  out("  │  Leave this running. Ctrl+C stops the tunnel and closes the endpoint.");
  out("  └─────────────────────────────────────────────────────────────────");
  out("");
}

export interface ExposeOptions {
  tunnel: TunnelKind;
  /** Local port for the dedicated /mcp listener (NOT the dashboard port). */
  port: number;
  /** If a fresh key was just minted, the plaintext token to print once; else null. */
  issuedToken: string | null;
}

/**
 * Orchestrate exposure: start the `/mcp`-only listener, spawn the tunnel, print the config,
 * and wire clean shutdown. Resolves once everything is up — the listener and the tunnel
 * child keep the event loop alive until Ctrl+C.
 */
export async function runExpose(
  gateway: Gateway,
  _cfg: SwitchboardConfig,
  apiKeys: ApiKeyStore,
  opts: ExposeOptions,
): Promise<void> {
  const host = "127.0.0.1";
  const spec = TUNNELS[opts.tunnel];

  const listener = await startMcpListener(gateway, host, opts.port, apiKeys);
  log.ok(`/mcp listener up on ${listener.url} (auth required; dashboard/console stay local and un-tunnelled)`);

  if (spec.note) log.warn(spec.note);
  log.info(`starting ${opts.tunnel} tunnel → ${host}:${opts.port} …`);

  let tunnel: { child: ChildProcess; publicUrl: string };
  try {
    tunnel = await spawnTunnel(opts.tunnel, opts.port);
  } catch (err) {
    await listener.close();
    throw err;
  }

  const publicMcp = `${tunnel.publicUrl.replace(/\/$/, "")}/mcp`;
  log.ok(`${opts.tunnel} tunnel live: ${tunnel.publicUrl}`);
  printConnectionInfo(publicMcp, apiKeys, opts.issuedToken);

  let shuttingDown = false;
  const shutdown = async (exitCode: number): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;
    log.info("shutting down tunnel + /mcp listener …");
    tunnel.child.kill();
    await listener.close();
    await gateway.shutdown().catch(() => {});
    process.exit(exitCode);
  };
  process.on("SIGINT", () => void shutdown(0));
  process.on("SIGTERM", () => void shutdown(0));
  tunnel.child.on("exit", (code) => {
    if (shuttingDown) return;
    log.warn(`tunnel process exited (code ${code ?? "?"}) — the public URL is no longer served.`);
    void shutdown(code ?? 0);
  });
}
