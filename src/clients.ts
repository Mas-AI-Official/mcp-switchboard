/**
 * clients.ts — `switchboard install <client>`: wire MCP Switchboard into an MCP client's config.
 *
 * The whole point of an aggregator is that you point ONE thing at it and every upstream tool
 * shows up. This module writes the small config snippet each popular MCP client expects so the
 * user doesn't have to hand-edit JSON/TOML in five different formats and locations.
 *
 * Two connection shapes, picked per client by what that client's config schema actually accepts
 * (grounded against each vendor's 2026 docs, not guessed):
 *
 *   • stdio  — the client launches `switchboard serve` as a child process and speaks JSON-RPC
 *              over its stdio. Used for Claude Desktop, whose local config validates stdio
 *              servers only (no `url`/`type:http`). Zero separate server process to babysit.
 *   • http   — the client dials the already-running gateway's Streamable-HTTP `/mcp` endpoint.
 *              Used for Claude Code, Cursor, VS Code, and Codex, all of which support a remote
 *              URL. This is the shared-control-plane model: one `switchboard serve`, many agents.
 *
 * Every write is an idempotent MERGE: we read the existing config, set only our one server entry
 * under the client's server map (JSON) or table (TOML), and preserve everything else — so running
 * `install` twice, or alongside other MCP servers the user already has, never clobbers them.
 *
 * Sources (config shapes): Claude Code MCP docs (type:http + url), VS Code MCP configuration
 * reference (`servers` key, type:http), Cursor MCP docs (`mcpServers` + url), OpenAI Codex
 * config reference (`[mcp_servers.<id>]` url=, streamable HTTP), Claude Desktop config (stdio).
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, posix, win32 } from "node:path";

export const SUPPORTED_CLIENTS = ["claude-desktop", "claude-code", "cursor", "vscode", "codex"] as const;
export type ClientId = (typeof SUPPORTED_CLIENTS)[number];

/** Where the gateway's HTTP endpoint lives, mirrored from `cfg.gateway.http`. */
export interface EndpointInfo {
  host: string;
  port: number;
  requireAuth: "auto" | "always" | "never";
}

export interface InstallTarget {
  client: ClientId;
  /** "stdio" launches `switchboard serve`; "http" dials the running `/mcp` endpoint. */
  transport: "stdio" | "http";
  format: "json" | "toml";
  /** Top-level key holding the server map for JSON clients ("mcpServers" or VS Code's "servers"). */
  jsonKey: string;
  /** Absolute path to the config file we will read/merge/write. */
  path: string;
  label: string;
}

export interface InstallPlan {
  target: InstallTarget;
  /** The full file content after the merge — exactly what `writePlan` would write. */
  content: string;
  /** Whether the target file already existed. */
  existed: boolean;
  /** False ⇒ the merge is a no-op (already configured identically). */
  changed: boolean;
  /** Non-fatal advisories to print (run `serve`, auth required, etc.). */
  notes: string[];
}

/** Options that steer path resolution; the `*` overrides exist so the oracle is OS-independent. */
export interface ResolveOptions {
  global?: boolean;
  baseDir?: string;
  platform?: NodeJS.Platform;
  home?: string;
  appData?: string;
}

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "localhost"]);

/** The URL a client should dial. A wildcard bind (0.0.0.0) is reached over loopback. */
export function mcpUrl(ep: EndpointInfo): string {
  const host = ep.host === "0.0.0.0" || LOOPBACK_HOSTS.has(ep.host) ? "127.0.0.1" : ep.host;
  return `http://${host}:${ep.port}/mcp`;
}

/** Whether `/mcp` will demand a bearer token — mirrors the gateway's own `require_auth` logic. */
export function authRequired(ep: EndpointInfo): boolean {
  if (ep.requireAuth === "always") return true;
  if (ep.requireAuth === "never") return false;
  return !LOOPBACK_HOSTS.has(ep.host); // "auto": required the moment we're not on loopback
}

/** Compute the on-disk target (path/format/transport/key) for a client. */
export function resolveTarget(client: ClientId, opts: ResolveOptions = {}): InstallTarget {
  const platform = opts.platform ?? process.platform;
  const joinForPlatform = platform === "win32" ? win32.join : posix.join;
  const home = opts.home ?? homedir();
  const appData = opts.appData ?? process.env.APPDATA ?? joinForPlatform(home, "AppData", "Roaming");
  const base = opts.baseDir ?? process.cwd();

  // OS-specific user-config dir for an app that keeps config under the platform's app-data root.
  const appConfigDir = (app: string): string => {
    if (platform === "win32") return joinForPlatform(appData, app);
    if (platform === "darwin") return joinForPlatform(home, "Library", "Application Support", app);
    return joinForPlatform(home, ".config", app);
  };

  switch (client) {
    case "claude-desktop":
      // Claude Desktop has no project scope and accepts stdio servers only.
      return {
        client,
        transport: "stdio",
        format: "json",
        jsonKey: "mcpServers",
        path: joinForPlatform(appConfigDir("Claude"), "claude_desktop_config.json"),
        label: "Claude Desktop",
      };
    case "claude-code":
      return {
        client,
        transport: "http",
        format: "json",
        jsonKey: "mcpServers",
        path: opts.global ? joinForPlatform(home, ".claude.json") : joinForPlatform(base, ".mcp.json"),
        label: "Claude Code",
      };
    case "cursor":
      return {
        client,
        transport: "http",
        format: "json",
        jsonKey: "mcpServers",
        path: opts.global ? joinForPlatform(home, ".cursor", "mcp.json") : joinForPlatform(base, ".cursor", "mcp.json"),
        label: "Cursor",
      };
    case "vscode":
      return {
        client,
        transport: "http",
        format: "json",
        jsonKey: "servers", // VS Code uses `servers`, not `mcpServers`
        path: opts.global ? joinForPlatform(appConfigDir("Code"), "User", "mcp.json") : joinForPlatform(base, ".vscode", "mcp.json"),
        label: "VS Code",
      };
    case "codex":
      return {
        client,
        transport: "http",
        format: "toml",
        jsonKey: "",
        path: opts.global ? joinForPlatform(home, ".codex", "config.toml") : joinForPlatform(base, ".codex", "config.toml"),
        label: "Codex CLI",
      };
  }
}

/** The stdio launcher Claude Desktop runs: `node <cli.js> --config <cfg> serve`. */
export interface Launcher {
  command: string;
  cliPath: string;
  configPath: string;
}

interface EntryParams {
  url: string;
  launcher: Launcher;
  authHeader?: string;
}

/** Build the per-server JSON object for a client (stdio command/args, or http url). */
export function buildJsonEntry(target: InstallTarget, p: EntryParams): Record<string, unknown> {
  if (target.transport === "stdio") {
    return { command: p.launcher.command, args: [p.launcher.cliPath, "--config", p.launcher.configPath, "serve"] };
  }
  const entry: Record<string, unknown> = {};
  if (target.client !== "cursor") entry.type = "http"; // Cursor infers transport from `url`; the rest want it explicit
  entry.url = p.url;
  if (p.authHeader) entry.headers = { Authorization: p.authHeader };
  return entry;
}

/** Merge our one server entry into an existing JSON config, preserving every other key. */
export function mergeJsonConfig(existing: string | null, key: string, name: string, entry: object): string {
  let root: Record<string, unknown> = {};
  if (existing && existing.trim()) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(existing);
    } catch {
      throw new Error("existing config is not valid JSON — refusing to overwrite; fix or move it first");
    }
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) root = parsed as Record<string, unknown>;
  }
  const map = root[key];
  const servers = map && typeof map === "object" && !Array.isArray(map) ? (map as Record<string, unknown>) : {};
  servers[name] = entry;
  root[key] = servers;
  return JSON.stringify(root, null, 2) + "\n";
}

/** Insert or replace a single TOML table by exact header, preserving the surrounding document. */
export function upsertTomlTable(text: string, header: string, body: string[]): string {
  const block = [header, ...body];
  const lines = text.split(/\r?\n/);
  const start = lines.findIndex((l) => l.trim() === header);
  if (start === -1) {
    const trimmed = text.replace(/\s*$/, "");
    return (trimmed ? trimmed + "\n\n" : "") + block.join("\n") + "\n";
  }
  // The table runs until the next table header `[...]` (or EOF).
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    if (/^\s*\[/.test(lines[i])) {
      end = i;
      break;
    }
  }
  const before = lines.slice(0, start);
  const after = lines.slice(end);
  let out = [...before, ...block].join("\n");
  const tail = after.join("\n").replace(/^\s*\n/, "").replace(/\s*$/, "");
  if (tail) out += "\n\n" + tail;
  return out.replace(/\n{3,}/g, "\n\n").replace(/\s*$/, "") + "\n";
}

export interface BuildContext {
  name?: string;
  endpoint: EndpointInfo;
  launcher: Launcher;
  global?: boolean;
  baseDir?: string;
  platform?: NodeJS.Platform;
  home?: string;
  appData?: string;
}

/** Resolve the target, build the merged content, and return a plan WITHOUT touching disk for the
 *  write (it does read the existing file to merge). Pure enough to diff/print before committing. */
export function buildPlan(client: ClientId, ctx: BuildContext): InstallPlan {
  const target = resolveTarget(client, {
    global: ctx.global,
    baseDir: ctx.baseDir,
    platform: ctx.platform,
    home: ctx.home,
    appData: ctx.appData,
  });
  const name = ctx.name ?? "switchboard";
  const url = mcpUrl(ctx.endpoint);
  const needAuth = authRequired(ctx.endpoint);

  const notes: string[] = [];
  if (target.transport === "http") {
    notes.push(`Run \`switchboard serve\` with the \`http\` transport enabled so ${target.label} can reach ${url}.`);
  } else {
    notes.push(`${target.label} launches \`switchboard serve\` over stdio on demand — restart ${target.label} to load it.`);
  }
  if (needAuth) {
    notes.push(
      `The endpoint requires a bearer token (require_auth=${ctx.endpoint.requireAuth}). Issue one with ` +
        "`switchboard apikey new <name>` and put it in the SWITCHBOARD_TOKEN environment variable.",
    );
  }

  const existed = existsSync(target.path);
  const existing = existed ? readFileSync(target.path, "utf8") : null;

  let content: string;
  if (target.format === "toml") {
    const body = [`url = "${url}"`];
    if (needAuth) body.push('bearer_token_env_var = "SWITCHBOARD_TOKEN"');
    content = upsertTomlTable(existing ?? "", `[mcp_servers.${name}]`, body);
  } else {
    const entry = buildJsonEntry(target, {
      url,
      launcher: ctx.launcher,
      authHeader: needAuth ? "Bearer ${env:SWITCHBOARD_TOKEN}" : undefined,
    });
    content = mergeJsonConfig(existing, target.jsonKey, name, entry);
  }

  return { target, content, existed, changed: existing !== content, notes };
}

/** Commit a plan to disk (creating parent directories as needed). */
export function writePlan(plan: InstallPlan): void {
  mkdirSync(dirname(plan.target.path), { recursive: true });
  writeFileSync(plan.target.path, plan.content, "utf8");
}
