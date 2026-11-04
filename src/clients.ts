/**
 * clients.ts: where each MCP client keeps its server list and what `switchboard install <client>` writes there
 * (design 3.13).
 *
 * The default entry is the BRIDGE: the client launches `node <dist/cli.js> bridge --client <id>`, a stdio process
 * that relays to the one shared HTTP gateway with that client's own key, so every client has an identity and no
 * token sits in any client's config file. The alternative, `--mode http`, writes the gateway's `/mcp` URL for the
 * clients whose config can carry a bearer token by environment reference.
 *
 * This module is the pure half: paths, entry shapes, merge and removal of one entry in JSON, TOML and the dsh
 * YAML patch, each refusing a file it cannot parse. installer.ts is the flow around it (preview, confirmation,
 * backup, the client's own CLI, probe, rollback). Every write goes through the atomic helper (atomicfile.ts).
 *
 * Shapes and locations, from each client's own documentation (checked 2026-10-23) and the local installs:
 *
 *   claude-code     user: ~/.claude.json mcpServers; project: <dir>/.mcp.json. `claude mcp add-json <name> <json> --scope`.
 *                   stdio {type, command, args}; http {type:"http", url, headers} with ${VAR} expansion (code.claude.com/docs/en/mcp).
 *   claude-desktop  %APPDATA%/Claude/claude_desktop_config.json mcpServers, stdio {command, args} only.
 *   codex           $CODEX_HOME or ~/.codex/config.toml [mcp_servers.<name>] command/args or url/bearer_token_env_var;
 *                   project: <dir>/.codex/config.toml. `codex mcp add <name> -- <command> <args...>` (user config only).
 *   gemini          ~/.gemini/settings.json mcpServers {command, args}; project: <dir>/.gemini/settings.json.
 *   antigravity     `agy` 1.4.5 reads ~/.gemini/config/mcp_config.json mcpServers {command, args}: Observed with
 *                   `agy mcp list`, which shows exactly that file's servers and none of the ones still in the older
 *                   ~/.gemini/antigravity/mcp_config.json. `agy mcp add [flags] <name> <command> [args...]` (add or update).
 *   dsh             $DSH_HOME or ~/.dsh/profiles/<profile>/cordis.patch.yml (see dshpatch.ts).
 *   cursor          ~/.cursor/mcp.json or <dir>/.cursor/mcp.json mcpServers.
 *   vscode          <APPDATA>/Code/User/mcp.json or <dir>/.vscode/mcp.json, key `servers`, entries carry `type`.
 */

import { existsSync, mkdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, posix, win32 } from "node:path";
import { atomicWriteFileSync } from "./atomicfile.js";
import { DEFAULT_BRIDGE_URL } from "./bridge.js";
import { inspectDshPatch, removeDshPatch, upsertDshPatch, type DshSpec } from "./dshpatch.js";
import { InstallRefusal } from "./installerror.js";
import { headerPath, pathStartsWith, scanToml, type TomlHeader, type TomlScan } from "./tomlscan.js";

export { InstallRefusal };

export const SUPPORTED_CLIENTS = ["claude-code", "claude-desktop", "codex", "gemini", "antigravity", "dsh", "cursor", "vscode"] as const;
export type ClientId = (typeof SUPPORTED_CLIENTS)[number];
export type InstallMode = "bridge" | "http";
export type InstallScope = "user" | "project";

/** The name an entry is registered under: a TOML bare key, a dsh serverName (at most 32), safe in every file and command line. */
export const SERVER_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$/;
export const BAD_SERVER_NAME = "invalid --name: use 1 to 32 characters from letters, digits, '-' and '_', starting with a letter or digit";

/** Where the gateway's HTTP endpoint lives, mirrored from `cfg.gateway.http`. */
export interface EndpointInfo {
  host: string;
  port: number;
  requireAuth: "auto" | "always" | "never";
}

export interface InstallTarget {
  client: ClientId;
  /**
   * How the client dials a remote gateway in `--mode http`: "http" when its config can name a URL and carry the bearer
   * token by environment reference, "stdio" when it cannot (Claude Desktop, Gemini CLI, Antigravity), so only the
   * bridge works there. It is also the default mode of the legacy `buildPlan` / `buildJsonEntry` calls.
   */
  transport: "stdio" | "http";
  format: "json" | "toml" | "yaml";
  /** Top-level key holding the server map for JSON clients ("mcpServers" or VS Code's "servers"). */
  jsonKey: string;
  /** Absolute path to the config file we will read/merge/write. */
  path: string;
  label: string;
  scope: InstallScope;
  /** The client's own CLI, when it has a documented command that writes this entry. */
  cli?: "claude" | "codex" | "agy";
}

/** One normalised description of what is written, for the preview and the probe. */
export type EntryDesc = { kind: "stdio"; command: string; args: string[] } | { kind: "http"; url: string; tokenEnv: boolean };

export interface InstallPlan {
  target: InstallTarget;
  mode: InstallMode;
  name: string;
  entry: EntryDesc;
  /** The full file content after the merge, exactly what `writePlan` would write. */
  content: string;
  /** Whether the target file already existed. */
  existed: boolean;
  /** False when the entry is already there with the same content (no write needed). */
  changed: boolean;
  /** The file as it was read (null when absent); the write is refused if the file differs when it happens. */
  originalText: string | null;
  /** What the file holds for this entry now: the JSON object, or the text of the TOML table / dsh block. Undefined when none. */
  previous?: unknown;
  /** The JSON object written for a JSON client (also the argument of `claude mcp add-json`). */
  jsonEntry?: Record<string, unknown>;
  /** The dsh patch entry, for a dsh plan. */
  dshSpec?: DshSpec;
  /** Non-fatal advisories to print. */
  notes: string[];
}

/** Options that steer path resolution; the `*` overrides exist so the oracle is OS-independent. */
export interface ResolveOptions {
  /** Legacy spelling of `scope: "user"`. */
  global?: boolean;
  scope?: InstallScope;
  baseDir?: string;
  platform?: NodeJS.Platform;
  home?: string;
  appData?: string;
  /** Source of CODEX_HOME and DSH_HOME (the installer passes process.env). Omitted: those variables are not consulted. */
  env?: NodeJS.ProcessEnv;
  dshProfile?: string;
}

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "localhost"]);

/** The URL a client should dial. A wildcard bind (0.0.0.0) is reached over loopback. */
export function mcpUrl(ep: EndpointInfo): string {
  const host = ep.host === "0.0.0.0" || LOOPBACK_HOSTS.has(ep.host) ? "127.0.0.1" : ep.host;
  return `http://${host}:${ep.port}/mcp`;
}

/** Whether `/mcp` will demand a bearer token because of `require_auth` (a configured client also demands one: see `clientsConfigured`). */
export function authRequired(ep: EndpointInfo): boolean {
  if (ep.requireAuth === "always") return true;
  if (ep.requireAuth === "never") return false;
  return !LOOPBACK_HOSTS.has(ep.host); // "auto": required the moment we're not on loopback
}

/** Compute the on-disk target (path/format/transport/key) for a client. Throws InstallRefusal for a scope the client does not have. */
export function resolveTarget(client: ClientId, opts: ResolveOptions = {}): InstallTarget {
  const platform = opts.platform ?? process.platform;
  const join = platform === "win32" ? win32.join : posix.join;
  const home = opts.home ?? homedir();
  const appData = opts.appData ?? process.env.APPDATA ?? join(home, "AppData", "Roaming");
  const base = opts.baseDir ?? process.cwd();
  const env = opts.env ?? {};
  const scope: InstallScope = opts.scope ?? (opts.global ? "user" : "project");
  const user = scope === "user";

  // OS-specific user-config dir for an app that keeps config under the platform's app-data root.
  const appConfigDir = (app: string): string => {
    if (platform === "win32") return join(appData, app);
    if (platform === "darwin") return join(home, "Library", "Application Support", app);
    return join(home, ".config", app);
  };
  const noProject = (label: string, why: string): never => {
    throw new InstallRefusal(`${label} has no project scope (${why}); use --scope user`);
  };

  switch (client) {
    case "claude-desktop":
      if (opts.scope === "project") noProject("Claude Desktop", "its config is one file per user");
      return { client, transport: "stdio", format: "json", jsonKey: "mcpServers", path: join(appConfigDir("Claude"), "claude_desktop_config.json"), label: "Claude Desktop", scope: "user" };
    case "claude-code":
      return { client, transport: "http", format: "json", jsonKey: "mcpServers", path: user ? join(home, ".claude.json") : join(base, ".mcp.json"), label: "Claude Code", scope, cli: "claude" };
    case "cursor":
      return { client, transport: "http", format: "json", jsonKey: "mcpServers", path: user ? join(home, ".cursor", "mcp.json") : join(base, ".cursor", "mcp.json"), label: "Cursor", scope };
    case "vscode":
      // VS Code uses `servers`, not `mcpServers`.
      return { client, transport: "http", format: "json", jsonKey: "servers", path: user ? join(appConfigDir("Code"), "User", "mcp.json") : join(base, ".vscode", "mcp.json"), label: "VS Code", scope };
    case "codex": {
      const codexHome = env.CODEX_HOME && env.CODEX_HOME.trim() !== "" ? env.CODEX_HOME : join(home, ".codex");
      const path = user ? join(codexHome, "config.toml") : join(base, ".codex", "config.toml");
      return { client, transport: "http", format: "toml", jsonKey: "", path, label: "Codex CLI", scope, ...(user ? { cli: "codex" as const } : {}) };
    }
    case "gemini":
      return { client, transport: "stdio", format: "json", jsonKey: "mcpServers", path: user ? join(home, ".gemini", "settings.json") : join(base, ".gemini", "settings.json"), label: "Gemini CLI", scope };
    case "antigravity": {
      if (opts.scope === "project") noProject("Antigravity", "`agy mcp add` writes the user configuration only");
      const current = join(home, ".gemini", "config", "mcp_config.json");
      const legacy = join(home, ".gemini", "antigravity", "mcp_config.json");
      // agy 1.4.5 reads the first; the second is where earlier Antigravity builds kept it. Use the legacy file only on a machine that never migrated.
      const migrated = existsSync(current) || existsSync(join(home, ".gemini", "config", ".migrated"));
      const path = migrated || !existsSync(legacy) ? current : legacy;
      return { client, transport: "stdio", format: "json", jsonKey: "mcpServers", path, label: "Antigravity (agy)", scope: "user", cli: "agy" };
    }
    case "dsh": {
      if (opts.scope === "project") noProject("dsh", "a profile under DSH_HOME is the unit of configuration");
      const profile = opts.dshProfile ?? "web";
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(profile)) throw new InstallRefusal("invalid --dsh-profile: use letters, digits, '.', '-' and '_'");
      const dshHome = env.DSH_HOME && env.DSH_HOME.trim() !== "" ? env.DSH_HOME : join(home, ".dsh");
      return { client, transport: "http", format: "yaml", jsonKey: "", path: join(dshHome, "profiles", profile, "cordis.patch.yml"), label: `dsh (profile ${profile})`, scope: "user" };
    }
  }
}

/** The launcher a bridge entry runs: `<command> <cliPath> bridge --client <id>`. */
export interface Launcher {
  command: string;
  cliPath: string;
  /** Not used by the bridge; kept so older callers that pass it still type-check. */
  configPath?: string;
}

interface EntryParams {
  url: string;
  launcher: Launcher;
  authHeader?: string;
  mode?: InstallMode;
}

/** Clients whose docs show a `type` field on a stdio entry. */
const TYPED_STDIO = new Set<ClientId>(["claude-code", "cursor", "vscode"]);

/** The arguments after the node executable: the CLI script, `bridge --client <id>`, and `--url` when the gateway is not at the default. */
export function bridgeArgs(cliPath: string, clientId: string, url: string): string[] {
  return [cliPath, "bridge", "--client", clientId, ...(url !== DEFAULT_BRIDGE_URL ? ["--url", url] : [])];
}

const defaultMode = (target: InstallTarget): InstallMode => (target.transport === "stdio" ? "bridge" : "http");

/** Build the per-server JSON object for a client (the bridge command, or the http url). */
export function buildJsonEntry(target: InstallTarget, p: EntryParams): Record<string, unknown> {
  const mode = p.mode ?? defaultMode(target);
  if (mode === "bridge") {
    const entry: Record<string, unknown> = {};
    if (TYPED_STDIO.has(target.client)) entry.type = "stdio";
    entry.command = p.launcher.command;
    entry.args = bridgeArgs(p.launcher.cliPath, target.client, p.url);
    return entry;
  }
  if (target.transport !== "http") {
    throw new InstallRefusal(
      `${target.label} cannot take --mode http: its config has no way to carry the bearer token by environment reference, ` +
        "and a token must never be written into a client file. Use the default --mode bridge.",
    );
  }
  const entry: Record<string, unknown> = {};
  if (target.client !== "cursor") entry.type = "http"; // Cursor infers transport from `url`; the rest want it explicit
  entry.url = p.url;
  if (p.authHeader) entry.headers = { Authorization: p.authHeader };
  return entry;
}

/** Run `fn`; a refusal that does not name the file gets the path in front of it. */
function atPath<T>(path: string, fn: () => T): T {
  try {
    return fn();
  } catch (err) {
    if (err instanceof InstallRefusal && !err.message.includes(path)) throw new InstallRefusal(`${path}: ${err.message}`);
    throw err;
  }
}

const hasControl = (s: string): boolean => /[\u0000-\u001f\u007f]/.test(s);

/** A TOML basic string. JSON escapes are a subset of TOML's; control characters are refused (JSON leaves DEL raw, TOML forbids it). */
const tomlString = (s: string): string => {
  if (hasControl(s)) throw new InstallRefusal("a value for the TOML entry contains a control character");
  return JSON.stringify(s);
};

/** The lines under `[mcp_servers.<name>]` for Codex. */
export function buildTomlBody(p: EntryParams & { clientId: string; needAuth: boolean }): string[] {
  if ((p.mode ?? "http") === "bridge") {
    return [`command = ${tomlString(p.launcher.command)}`, `args = [${bridgeArgs(p.launcher.cliPath, p.clientId, p.url).map(tomlString).join(", ")}]`];
  }
  const body = [`url = ${tomlString(p.url)}`];
  if (p.needAuth) body.push('bearer_token_env_var = "SWITCHBOARD_TOKEN"');
  return body;
}

// ── JSON ───────────────────────────────────────────────────────────────────────────────────────

const isPlainObject = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

/** Parse a client's JSON file. Empty text is a fresh config. Anything else that is not a JSON object throws InstallRefusal. */
export function parseJsonConfig(existing: string | null, path = "the existing config"): Record<string, unknown> {
  if (existing === null) return {};
  const text = existing.charCodeAt(0) === 0xfeff ? existing.slice(1) : existing;
  if (text.trim() === "") return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new InstallRefusal(`${path} is not valid JSON (${err instanceof Error ? err.message : String(err)}). Refusing to overwrite it: fix or move it first (comments and trailing commas are not accepted).`);
  }
  if (!isPlainObject(parsed)) throw new InstallRefusal(`${path} does not hold a JSON object at its top level. Refusing to overwrite it: fix or move it first.`);
  return parsed;
}

/** The entry `name` under `key`, or undefined. Throws when `key` holds something that is not an object. */
export function readJsonEntry(root: Record<string, unknown>, key: string, name: string, path = "the existing config"): unknown {
  const map = root[key];
  if (map === undefined) return undefined;
  if (!isPlainObject(map)) throw new InstallRefusal(`${path}: '${key}' is not an object. Refusing to overwrite it: fix or move it first.`);
  return Object.prototype.hasOwnProperty.call(map, name) ? map[name] : undefined;
}

/** True when `prev` already says what `want` says (keys it carries that we do not write are the user's and are left alone). */
export function entryMatches(prev: unknown, want: Record<string, unknown>): boolean {
  if (!isPlainObject(prev)) return false;
  return Object.entries(want).every(([k, v]) => JSON.stringify(prev[k]) === JSON.stringify(v));
}

/** Merge our one server entry into an existing JSON config, preserving every other key. */
export function mergeJsonConfig(existing: string | null, key: string, name: string, entry: object): string {
  const root = parseJsonConfig(existing);
  readJsonEntry(root, key, name); // refuses a non-object map
  const map = isPlainObject(root[key]) ? (root[key] as Record<string, unknown>) : {};
  map[name] = entry;
  root[key] = map;
  return JSON.stringify(root, null, 2) + "\n";
}

/** The config with our entry removed (the map key stays, possibly empty). `removed` is false when it was not there. */
export function removeJsonEntry(existing: string, key: string, name: string, path = "the existing config"): { text: string; removed: boolean } {
  const root = parseJsonConfig(existing, path);
  const map = root[key];
  if (map === undefined) return { text: existing, removed: false };
  if (!isPlainObject(map)) throw new InstallRefusal(`${path}: '${key}' is not an object. Refusing to edit it.`);
  if (!Object.prototype.hasOwnProperty.call(map, name)) return { text: existing, removed: false };
  delete map[name];
  const bom = existing.charCodeAt(0) === 0xfeff ? "﻿" : "";
  return { text: bom + JSON.stringify(root, null, 2) + "\n", removed: true };
}

// ── TOML ───────────────────────────────────────────────────────────────────────────────────────

const splitToml = (text: string): { eol: string; lines: string[] } => {
  const eol = text.includes("\r\n") ? "\r\n" : "\n";
  const lines = text.split(/\r?\n/);
  if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  return { eol, lines };
};

/** Line ranges [start, end) of the table at `prefix` and its sub-tables; trailing blank and comment lines stay with whatever follows. */
function tomlRanges(lines: string[], headers: TomlHeader[], prefix: string[]): [number, number][] {
  const sorted = headers.slice().sort((a, b) => a.line - b.line);
  const ranges: [number, number][] = [];
  sorted.forEach((h, i) => {
    if (h.array || !pathStartsWith(h.path, prefix)) return;
    let end = i + 1 < sorted.length ? sorted[i + 1]!.line : lines.length;
    while (end - 1 > h.line && /^\s*(#.*)?$/.test(lines[end - 1] ?? "")) end--;
    ranges.push([h.line, end]);
  });
  return ranges;
}

/** Why the table named `name` under `mcp_servers` cannot be edited line by line, or null. */
function tomlEntryProblem(scan: Extract<TomlScan, { ok: true }>, name: string): string | null {
  const prefix = ["mcp_servers", name];
  if (scan.headers.some((h) => h.array && pathStartsWith(h.path, prefix))) return `it defines [[mcp_servers.${name}]] as an array of tables`;
  const foreign = scan.assigns.find((a) => !pathStartsWith(a.table, prefix) && pathStartsWith([...a.table, ...a.key], prefix));
  if (foreign) return `'${name}' is defined with dotted keys or an inline table (line ${foreign.line + 1}), not as a [mcp_servers.${name}] table`;
  return null;
}

/** Validate a TOML config for editing: it must scan clean and keep `name` in a form the table edit understands. Throws InstallRefusal. */
export function checkTomlConfig(text: string, name: string, path = "the existing config"): Extract<TomlScan, { ok: true }> {
  const scan = scanToml(text);
  if (!scan.ok) throw new InstallRefusal(`${path} is not valid TOML (line ${scan.line}: ${scan.error}). Refusing to overwrite it: fix or move it first.`);
  const problem = tomlEntryProblem(scan, name);
  if (problem) throw new InstallRefusal(`${path}: ${problem}. Refusing to edit it: change it to a [mcp_servers.${name}] table or remove it by hand first.`);
  return scan;
}

/** The text of the `[mcp_servers.<name>]` table and its sub-tables as they are in the file, or undefined. */
export function readTomlTable(text: string, name: string): string | undefined {
  const scan = scanToml(text);
  if (!scan.ok) return undefined;
  const { lines } = splitToml(text);
  const ranges = tomlRanges(lines, scan.headers, ["mcp_servers", name]);
  if (ranges.length === 0) return undefined;
  return ranges.map(([a, b]) => lines.slice(a, b).join("\n")).join("\n");
}

/**
 * Insert or replace a single TOML table by header, preserving the surrounding document. The header is compared by key
 * path, so `[mcp_servers."x"]` and `[ mcp_servers.x ]` are the same table as `[mcp_servers.x]`; its sub-tables are part
 * of the entry and are replaced with it. Text that does not scan is handled by exact-header line matching (the
 * behaviour before the scanner existed); `install` validates first and never reaches that path.
 */
export function upsertTomlTable(text: string, header: string, body: string[]): string {
  const block = [header, ...body];
  const path = headerPath(header);
  const scan = path ? scanToml(text) : null;
  if (!path || !scan || !scan.ok) return legacyUpsert(text, header, body);
  const { eol, lines } = splitToml(text);
  const ranges = tomlRanges(lines, scan.headers, path);
  let out: string[];
  if (ranges.length === 0) {
    out = lines.slice();
    while (out.length > 0 && out[out.length - 1]!.trim() === "") out.pop();
    if (out.length > 0) out.push("");
    out.push(...block);
  } else {
    out = lines.slice();
    for (const [a, b] of ranges.slice().reverse()) out.splice(a, b - a);
    const at = ranges[0]![0];
    const after = out[at];
    out.splice(at, 0, ...block, ...(after !== undefined && after.trim() !== "" ? [""] : []));
    while (out.length > 0 && out[out.length - 1]!.trim() === "") out.pop();
  }
  return out.join(eol) + eol;
}

function legacyUpsert(text: string, header: string, body: string[]): string {
  const block = [header, ...body];
  const lines = text.split(/\r?\n/);
  const start = lines.findIndex((l) => l.trim() === header);
  if (start === -1) {
    const trimmed = text.replace(/\s*$/, "");
    return (trimmed ? trimmed + "\n\n" : "") + block.join("\n") + "\n";
  }
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    if (/^\s*\[/.test(lines[i]!)) {
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

/** The config with the `[mcp_servers.<name>]` table (and sub-tables) removed. */
export function removeTomlTable(text: string, name: string): { text: string; removed: boolean } {
  const scan = scanToml(text);
  if (!scan.ok) return { text, removed: false };
  const { eol, lines } = splitToml(text);
  const ranges = tomlRanges(lines, scan.headers, ["mcp_servers", name]);
  if (ranges.length === 0) return { text, removed: false };
  const out = lines.slice();
  for (const [a, b] of ranges.slice().reverse()) {
    out.splice(a, b - a);
    // One blank separator line goes with the table.
    if (a > 0 && out[a - 1]!.trim() === "" && (a >= out.length || out[a]!.trim() === "")) out.splice(a - 1, 1);
  }
  while (out.length > 0 && out[out.length - 1]!.trim() === "") out.pop();
  return { text: out.length > 0 ? out.join(eol) + eol : "", removed: true };
}

// ── plans ──────────────────────────────────────────────────────────────────────────────────────

export interface BuildContext {
  name?: string;
  endpoint: EndpointInfo;
  launcher: Launcher;
  mode?: InstallMode;
  scope?: InstallScope;
  /** Legacy spelling of `scope: "user"`. */
  global?: boolean;
  baseDir?: string;
  platform?: NodeJS.Platform;
  home?: string;
  appData?: string;
  env?: NodeJS.ProcessEnv;
  dshProfile?: string;
  /** http mode: the gateway has clients configured, so `/mcp` wants a bearer token whatever `require_auth` says. */
  clientsConfigured?: boolean;
}

/** The authorization header value that names the token by environment reference, in each client's own expansion syntax. */
export function authHeaderFor(client: ClientId): string {
  return client === "claude-code" ? "Bearer ${SWITCHBOARD_TOKEN}" : "Bearer ${env:SWITCHBOARD_TOKEN}";
}

/** Resolve the target, build the merged content, and return a plan WITHOUT touching disk for the write (it does read the existing file). */
export function buildPlan(client: ClientId, ctx: BuildContext): InstallPlan {
  const target = resolveTarget(client, {
    global: ctx.global,
    scope: ctx.scope,
    baseDir: ctx.baseDir,
    platform: ctx.platform,
    home: ctx.home,
    appData: ctx.appData,
    env: ctx.env,
    dshProfile: ctx.dshProfile,
  });
  const name = ctx.name ?? "switchboard";
  if (!SERVER_NAME_RE.test(name)) throw new InstallRefusal(BAD_SERVER_NAME);
  const mode = ctx.mode ?? defaultMode(target);
  const url = mcpUrl(ctx.endpoint);
  const needAuth = authRequired(ctx.endpoint) || ctx.clientsConfigured === true;
  const params: EntryParams = { url, launcher: ctx.launcher, authHeader: needAuth ? authHeaderFor(client) : undefined, mode };

  const notes: string[] = [];
  if (mode === "bridge") {
    notes.push(`${target.label} launches the bridge when it starts; the bridge talks to the gateway at ${url} with this client's own key, so no token is written to the client's config. Run \`switchboard serve\` with the http transport enabled.`);
  } else {
    notes.push(`Run \`switchboard serve\` with the \`http\` transport enabled so ${target.label} can reach ${url}.`);
    if (needAuth) {
      notes.push(
        `The endpoint requires a bearer token (require_auth=${ctx.endpoint.requireAuth}${ctx.clientsConfigured ? ", clients are configured" : ""}). ` +
          "Put one in the SWITCHBOARD_TOKEN environment variable (`switchboard client rotate <id> --print` shows a fresh one once).",
      );
    }
  }

  const existed = existsSync(target.path);
  const originalText = existed ? readFileSync(target.path, "utf8") : null;
  const bom = originalText !== null && originalText.charCodeAt(0) === 0xfeff ? "﻿" : "";
  const label = target.path;

  let content: string;
  let changed: boolean;
  let previous: unknown;
  let entry: EntryDesc;
  let jsonEntry: Record<string, unknown> | undefined;
  let dshSpec: DshSpec | undefined;

  if (target.format === "toml") {
    checkTomlConfig(originalText ?? "", name, label);
    const body = buildTomlBody({ ...params, clientId: client, needAuth });
    content = upsertTomlTable(originalText ?? "", `[mcp_servers.${name}]`, body);
    changed = content !== (originalText ?? "") || !existed;
    previous = readTomlTable(originalText ?? "", name);
    entry = mode === "bridge" ? { kind: "stdio", command: ctx.launcher.command, args: bridgeArgs(ctx.launcher.cliPath, client, url) } : { kind: "http", url, tokenEnv: needAuth };
  } else if (target.format === "yaml") {
    const spec: DshSpec = { name, mode, command: ctx.launcher.command, args: bridgeArgs(ctx.launcher.cliPath, client, url), url };
    dshSpec = spec;
    const r = atPath(label, () => upsertDshPatch(originalText, spec));
    content = r.text;
    changed = r.changed;
    previous = originalText === null ? undefined : (atPath(label, () => inspectDshPatch(originalText, name)).current?.join("\n") ?? undefined);
    entry = mode === "bridge" ? { kind: "stdio", command: spec.command, args: spec.args } : { kind: "http", url, tokenEnv: true };
    if (mode === "bridge") notes.push("dsh reads cordis.patch.yml when it starts: restart the profile to load the entry.");
  } else {
    jsonEntry = buildJsonEntry(target, params);
    const root = parseJsonConfig(originalText, label);
    previous = readJsonEntry(root, target.jsonKey, name, label);
    const unchanged = previous !== undefined && entryMatches(previous, jsonEntry);
    content = unchanged ? originalText! : bom + mergeJsonConfig(originalText, target.jsonKey, name, jsonEntry);
    changed = !unchanged;
    entry = mode === "bridge" ? { kind: "stdio", command: ctx.launcher.command, args: jsonEntry.args as string[] } : { kind: "http", url, tokenEnv: needAuth };
  }
  return { target, mode, name, entry, content, existed, changed, originalText, previous, ...(jsonEntry ? { jsonEntry } : {}), ...(dshSpec ? { dshSpec } : {}), notes };
}

export interface RemovalPlan {
  target: InstallTarget;
  name: string;
  existed: boolean;
  originalText: string | null;
  /** The file after the removal (equal to the original when there is nothing to remove). */
  content: string;
  /** True when our entry is in the file. */
  present: boolean;
  /** What the file holds for the entry now (see InstallPlan.previous). */
  previous?: unknown;
  /** dsh: an entry with this id exists that the tool did not write (zero-based line). */
  unmanagedLine?: number;
}

/** The plan for `uninstall`: the file as it would be without our entry. Throws InstallRefusal for an unreadable file. */
export function buildRemoval(client: ClientId, ctx: Omit<BuildContext, "endpoint" | "launcher"> & { endpoint?: EndpointInfo; launcher?: Launcher }): RemovalPlan {
  const target = resolveTarget(client, { global: ctx.global, scope: ctx.scope, baseDir: ctx.baseDir, platform: ctx.platform, home: ctx.home, appData: ctx.appData, env: ctx.env, dshProfile: ctx.dshProfile });
  const name = ctx.name ?? "switchboard";
  if (!SERVER_NAME_RE.test(name)) throw new InstallRefusal(BAD_SERVER_NAME);
  const existed = existsSync(target.path);
  const originalText = existed ? readFileSync(target.path, "utf8") : null;
  const label = target.path;
  if (originalText === null) return { target, name, existed, originalText, content: "", present: false };
  if (target.format === "toml") {
    checkTomlConfig(originalText, name, label);
    const r = removeTomlTable(originalText, name);
    return { target, name, existed, originalText, content: r.text, present: r.removed, previous: readTomlTable(originalText, name) };
  }
  if (target.format === "yaml") {
    const r = atPath(label, () => removeDshPatch(originalText, name));
    return { target, name, existed, originalText, content: r.text, present: r.removed, previous: atPath(label, () => inspectDshPatch(originalText, name)).current?.join("\n"), ...(r.unmanagedLine !== null ? { unmanagedLine: r.unmanagedLine } : {}) };
  }
  const root = parseJsonConfig(originalText, label);
  const previous = readJsonEntry(root, target.jsonKey, name, label);
  if (previous === undefined) return { target, name, existed, originalText, content: originalText, present: false };
  const r = removeJsonEntry(originalText, target.jsonKey, name, label);
  return { target, name, existed, originalText, content: r.text, present: r.removed, previous };
}

// ── writing ────────────────────────────────────────────────────────────────────────────────────

/** `20261023T101530Z`: the timestamp in backup file names. */
export function backupStamp(now: Date = new Date()): string {
  return now.toISOString().replace(/[-:]/g, "").replace(/\.\d+Z$/, "Z");
}

/** The path a write to `path` really lands on: a symlink (a dotfile manager's) is followed, so the link is not replaced by a file. */
export function writeTarget(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return path;
  }
}

/** Copy `path` byte for byte to `<path>.bak-switchboard-<timestamp>` (a counter is appended if that name is taken). Returns the backup path. */
export function backupFile(path: string, now: Date = new Date()): string {
  const real = writeTarget(path);
  const bytes = readFileSync(real);
  const mode = statSync(real).mode & 0o777;
  const stem = `${real}.bak-switchboard-${backupStamp(now)}`;
  let bak = stem;
  for (let n = 2; existsSync(bak); n++) bak = `${stem}-${n}`;
  atomicWriteFileSync(bak, bytes, { mode });
  return bak;
}

/**
 * Commit a plan to disk atomically (temp file, fsync, rename), creating parent directories as needed. An existing file is
 * copied first to `<file>.bak-switchboard-<timestamp>` unless `backup: false` (0.1.0 overwrote in place with no copy).
 */
export function writePlan(plan: InstallPlan, opts: { backup?: boolean; now?: Date } = {}): { backupPath?: string } {
  return writeFileAtomic(plan.target.path, plan.content, { backup: opts.backup ?? true, ...(opts.now ? { now: opts.now } : {}) });
}

/** Write `content` to `path` through the atomic helper; with `backup`, keep a timestamped copy of what was there. */
export function writeFileAtomic(path: string, content: string | Buffer, opts: { backup?: boolean; now?: Date } = {}): { backupPath?: string } {
  const real = writeTarget(path);
  const backupPath = opts.backup && existsSync(real) ? backupFile(real, opts.now) : undefined;
  mkdirSync(dirname(real), { recursive: true });
  atomicWriteFileSync(real, content);
  return backupPath ? { backupPath } : {};
}
