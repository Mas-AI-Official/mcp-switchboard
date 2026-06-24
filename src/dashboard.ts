/**
 * HTTP server — hosts two things on one port:
 *   1. The MCP Streamable HTTP endpoint at `/mcp` (stateless: a fresh Server +
 *      transport per request, the pattern the SDK recommends for stateless servers).
 *   2. The dashboard UI at `/` plus a small JSON API the UI polls.
 *
 * Bound to `gateway.http.host` (127.0.0.1 by default) — local-first means the
 * endpoint is not exposed to the network unless the operator deliberately changes it.
 */

import express, { type Request, type Response } from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { Gateway } from "./gateway.js";
import type { SwitchboardConfig } from "./types.js";
import { writeConfig } from "./config.js";
import { recentAudit } from "./audit.js";
import { inferScope } from "./policy.js";
import { ApiKeyStore } from "./apikeys.js";
import { log } from "./logger.js";

export interface DashboardHandle {
  url: string;
  close: () => Promise<void>;
}

/** A loopback bind needs no network auth; anything else is reachable by other hosts. */
function isLoopbackHost(host: string): boolean {
  return host === "127.0.0.1" || host === "localhost" || host === "::1" || host.startsWith("127.");
}

/** Resolve whether `/mcp` requires an API key, given the configured mode and bind host. */
function authRequired(mode: "auto" | "always" | "never", host: string): boolean {
  if (mode === "always") return true;
  if (mode === "never") return false;
  return !isLoopbackHost(host); // auto: require iff exposed beyond loopback
}

/** Pull a bearer token from `Authorization: Bearer <t>` or the `x-api-key` header. */
function presentedToken(req: Request): string | null {
  const auth = req.headers["authorization"];
  if (typeof auth === "string" && auth.startsWith("Bearer ")) return auth.slice(7).trim();
  const apiKey = req.headers["x-api-key"];
  if (typeof apiKey === "string" && apiKey.trim()) return apiKey.trim();
  return null;
}

/** True if the request originated from the local machine (loopback peer address). */
function isLocalRequest(req: Request): boolean {
  const ip = req.ip ?? req.socket.remoteAddress ?? "";
  return ip === "127.0.0.1" || ip === "::1" || ip === "::ffff:127.0.0.1" || ip.startsWith("127.");
}

/**
 * Start the HTTP server. `configPath` is where enable/disable toggles are persisted so
 * they survive a restart; pass undefined to keep toggles in-memory only.
 */
export async function startDashboard(
  gateway: Gateway,
  cfg: SwitchboardConfig,
  html: string,
  configPath?: string,
): Promise<DashboardHandle> {
  const app = express();
  app.use(express.json());

  const apiKeys = new ApiKeyStore();
  const { host, port } = cfg.gateway.http;
  const requireAuth = authRequired(cfg.gateway.http.require_auth, host);

  // --- MCP Streamable HTTP endpoint (stateless) ---
  app.all("/mcp", async (req: Request, res: Response) => {
    // Gate before doing any work. Fail closed: a missing/invalid key is a 401, and we
    // never echo or log the presented token.
    if (requireAuth) {
      const token = presentedToken(req);
      if (!token || !apiKeys.verify(token)) {
        res.set("WWW-Authenticate", 'Bearer realm="switchboard"');
        res.status(401).json({ error: "unauthorized: missing or invalid API key" });
        return;
      }
    }
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => void transport.close());
    try {
      const server = gateway.buildServer();
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      log.error(`/mcp request failed: ${msg}`);
      if (!res.headersSent) res.status(500).json({ error: msg });
    }
  });

  // --- Dashboard UI ---
  app.get("/", (_req: Request, res: Response) => {
    res.type("html").send(html);
  });

  // --- JSON API for the dashboard ---
  app.get("/api/state", (_req: Request, res: Response) => {
    const endpoint = `http://${cfg.gateway.http.host}:${cfg.gateway.http.port}/mcp`;
    const servers = cfg.servers.map((s) => {
      const mounted = gateway.registry.get(s.id);
      const policy = s.policy ?? cfg.gateway.default_policy;
      const tools = (mounted?.tools ?? []).map((t) => ({
        name: t.name,
        enabled: s.tools?.[t.name]?.enabled !== false,
        scope: s.tools?.[t.name]?.policy ?? inferScope(t.name),
      }));
      return { id: s.id, source: s.source, policy, enabled: s.enabled !== false, tools };
    });
    res.json({ endpoint, servers });
  });

  app.get("/api/audit", (_req: Request, res: Response) => {
    res.json(recentAudit(100));
  });

  // --- API keys: bearer tokens that authenticate `/mcp` (Composio "API Keys" page) ---
  // Listing is redacted (never the hash). Issuing/revoking mutate local state and are
  // restricted to loopback callers so a tunnelled dashboard can't mint itself a key.
  app.get("/api/apikeys", (_req: Request, res: Response) => {
    res.json({ keys: apiKeys.list(), require_auth: cfg.gateway.http.require_auth, enforced: requireAuth });
  });

  app.post("/api/apikeys", (req: Request, res: Response) => {
    if (!isLocalRequest(req)) {
      res.status(403).json({ error: "API keys can only be issued from the local machine" });
      return;
    }
    const name = typeof req.body?.name === "string" ? req.body.name : "";
    const { token, record } = apiKeys.issue(name);
    // The plaintext token is returned ONCE here and never again.
    res.json({ token, key: record });
  });

  app.delete("/api/apikeys/:id", (req: Request, res: Response) => {
    if (!isLocalRequest(req)) {
      res.status(403).json({ error: "API keys can only be revoked from the local machine" });
      return;
    }
    const removed = apiKeys.revoke(String(req.params.id));
    if (!removed) {
      res.status(404).json({ error: `unknown key '${req.params.id}'` });
      return;
    }
    res.json({ revoked: req.params.id });
  });

  // --- OAuth catalog (Phase 3): browse providers, connect via local loopback ---
  const redirectUri = `http://${cfg.gateway.http.host}:${cfg.gateway.http.port}/oauth/callback`;

  app.get("/api/catalog", (_req: Request, res: Response) => {
    res.json(gateway.oauth.catalog());
  });

  app.post("/api/connect/:provider", (req: Request, res: Response) => {
    try {
      const { authorizeUrl } = gateway.oauth.beginAuth(String(req.params.provider), redirectUri);
      res.json({ authorizeUrl });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(400).json({ error: msg });
    }
  });

  // The provider redirects the browser here after consent. Exchange the code, seal the
  // token, and show a self-closing confirmation page. Fails closed with a visible message.
  app.get("/oauth/callback", async (req: Request, res: Response) => {
    const state = typeof req.query.state === "string" ? req.query.state : "";
    const code = typeof req.query.code === "string" ? req.query.code : "";
    const err = typeof req.query.error === "string" ? req.query.error : "";
    if (err) {
      res.status(400).type("html").send(callbackPage(`Authorization was denied: ${err}`, false));
      return;
    }
    if (!state || !code) {
      res.status(400).type("html").send(callbackPage("Missing 'state' or 'code' in the callback.", false));
      return;
    }
    try {
      const token = await gateway.oauth.completeAuth(state, code);
      res.type("html").send(callbackPage(`Connected ${token.provider}. You can close this tab.`, true));
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      res.status(400).type("html").send(callbackPage(msg, false));
    }
  });

  app.post("/api/servers/:id/toggle", async (req: Request, res: Response) => {
    const id = req.params.id;
    const server = cfg.servers.find((s) => s.id === id);
    if (!server) {
      res.status(404).json({ error: `unknown server '${id}'` });
      return;
    }
    server.enabled = server.enabled === false;
    try {
      if (server.enabled) await gateway.registry.mount(server);
      else await gateway.registry.unmount(server.id);
      if (configPath) writeConfig(configPath, cfg);
      res.json({ id, enabled: server.enabled });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: msg });
    }
  });

  // Surface the auth posture loudly at startup so a misconfigured exposure is obvious.
  if (requireAuth) {
    if (apiKeys.count === 0) {
      log.warn(
        `/mcp requires an API key but none exist — run \`switchboard apikey new <name>\` to issue one; clients cannot connect until you do`,
      );
    } else {
      log.info(`/mcp authentication required (${apiKeys.count} API key${apiKeys.count === 1 ? "" : "s"} issued)`);
    }
  } else if (!isLoopbackHost(host)) {
    log.warn(
      `/mcp is exposed on ${host} WITHOUT authentication (require_auth: never) — anyone who can reach this host can use your tools`,
    );
  }

  return new Promise<DashboardHandle>((resolve) => {
    const httpServer = app.listen(port, host, () => {
      const url = `http://${host}:${port}`;
      log.ok(`dashboard + HTTP endpoint on ${url}`);
      resolve({
        url,
        close: () =>
          new Promise<void>((done) => {
            httpServer.close(() => done());
          }),
      });
    });
  });
}

/** Minimal self-contained HTML for the OAuth redirect landing page. No external requests. */
function callbackPage(message: string, ok: boolean): string {
  const safe = message.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" })[c] ?? c);
  const color = ok ? "#3fb950" : "#f85149";
  const title = ok ? "Connected" : "Authorization failed";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8" />
<title>Switchboard · ${title}</title>
<style>
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
    background:#0d1117; color:#e6edf3; font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
  .box { max-width:440px; padding:32px 36px; border:1px solid #2a3340; border-radius:14px; background:#161b22; text-align:center; }
  .dot { width:14px; height:14px; border-radius:50%; background:${color}; display:inline-block; margin-bottom:14px; }
  h1 { margin:0 0 8px; font-size:18px; }
  p { margin:0; color:#8b98a5; }
</style></head>
<body><div class="box"><span class="dot"></span><h1>${title}</h1><p>${safe}</p></div></body></html>`;
}
