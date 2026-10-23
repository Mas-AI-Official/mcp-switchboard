/**
 * installer.ts: `switchboard install <client>` and `switchboard uninstall <client>` (design 3.13).
 *
 * Flow for every client: build the plan, print a preview (the exact entry and the target file or CLI command),
 * validate that the existing file parses (otherwise REFUSE, nothing is touched), ask for confirmation (`--yes`
 * skips it), register the client with the gateway when it is not yet configured (the equivalent of
 * `switchboard client add <id>`), back up the target, write, probe, and roll back from the backup when the probe
 * fails. `--dry-run` stops after the preview and changes nothing at all: no file, no client, no command that writes.
 *
 * Write route. The client's own CLI is preferred when it is on PATH and has a documented command for it
 * (`claude mcp add-json`, `codex mcp add`, `agy mcp add`); it is started by absolute path without a shell
 * (cliexec.ts). Otherwise, and for every client without such a command, the file is edited and replaced atomically
 * (temp file, fsync, rename; clients.ts). Both routes end with the same probe.
 *
 * Probe. Registration first: the client's own `get`/`list` command, or a re-read and parse of the file we wrote.
 * Then, in bridge mode and only when a gateway answers at the configured address, the bridge entry is started once
 * with an `initialize` request and must answer with a result. A gateway that is not running is reported, never
 * treated as a failure: starting it later is the normal order.
 *
 * Rollback. A file that existed is restored byte for byte from the `<file>.bak-switchboard-<timestamp>` copy; a file
 * that did not exist is removed again. For `claude mcp`, whose user file is the big, constantly rewritten
 * ~/.claude.json, no file copy is taken: the previous entry is recorded (and saved under SWITCHBOARD_HOME) and put
 * back with the same CLI.
 */

import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, unlinkSync } from "node:fs";
import { createConnection } from "node:net";
import { homedir } from "node:os";
import { isAbsolute, join, win32 } from "node:path";
import { createInterface } from "node:readline";
import { ApiKeyStore } from "./apikeys.js";
import { atomicWriteFileSync, writeJsonAtomic } from "./atomicfile.js";
import { ClientAdmin, type ClientSpec } from "./clientadmin.js";
import { clientKeyPath, readClientKey } from "./clientkeys.js";
import {
  BAD_SERVER_NAME,
  InstallRefusal,
  SERVER_NAME_RE,
  backupFile,
  buildPlan,
  buildRemoval,
  entryMatches,
  mcpUrl,
  parseJsonConfig,
  readJsonEntry,
  readTomlTable,
  writeFileAtomic,
  writeTarget,
  backupStamp,
  type ClientId,
  type EndpointInfo,
  type InstallMode,
  type InstallPlan,
  type InstallScope,
  type RemovalPlan,
} from "./clients.js";
import { resolveExecutable, runExecutable, shimUnsafeReason, type CliResult, type ResolvedExe } from "./cliexec.js";
import { verifyDshPatch } from "./dshpatch.js";
import { log, out } from "./logger.js";
import { safeText } from "./safetext.js";
import type { SwitchboardConfig } from "./types.js";
import { HOME_DIR } from "./vault.js";

/** What a client registered by `install` may do until the owner changes it: every server, writes allowed, any risk (high still needs an approval). */
export const INSTALL_CLIENT_DEFAULTS: ClientSpec = { servers: ["*"], max_scope: "write", max_risk: "high" };

export interface InstallIO {
  /** A line of the preview or result (stdout). */
  out(line: string): void;
  ok(line: string): void;
  warn(line: string): void;
  error(line: string): void;
  /** Ask the owner; resolves false on anything but yes (including end of input). */
  confirm(question: string): Promise<boolean>;
}

const defaultConfirm = (question: string): Promise<boolean> =>
  new Promise((resolve) => {
    const rl = createInterface({ input: process.stdin, output: process.stderr, terminal: false });
    let answered = false;
    rl.question(`${question} [y/N] `, (answer) => {
      answered = true;
      rl.close();
      resolve(/^y(es)?$/i.test(answer.trim()));
    });
    rl.on("close", () => {
      if (!answered) resolve(false);
    });
  });

const defaultIO: InstallIO = { out, ok: log.ok, warn: log.warn, error: log.error, confirm: defaultConfirm };

export interface EnsureResult {
  created: boolean;
  keyIssued: boolean;
}
export type EnsureClientFn = (cfg: SwitchboardConfig, cfgPath: string, id: string) => EnsureResult;

/**
 * The equivalent of `switchboard client add <id>` when the client is not configured; when it is, only a missing or
 * unusable key is replaced (its settings are never touched).
 */
export const ensureClientRegistered: EnsureClientFn = (cfg, cfgPath, id) => {
  const configured = Object.prototype.hasOwnProperty.call(cfg.clients ?? {}, id);
  const store = new ApiKeyStore();
  let keyOk = false;
  try {
    const stored = readClientKey(id);
    keyOk = stored !== null && store.inspect(stored)?.client === id;
  } catch {
    keyOk = false;
  }
  if (configured && keyOk) return { created: false, keyIssued: false };
  const admin = new ClientAdmin({ cfg, configPath: cfgPath, apiKeys: store, actor: "cli" });
  const r = admin.add(id, configured ? {} : { ...INSTALL_CLIENT_DEFAULTS, servers: [...(INSTALL_CLIENT_DEFAULTS.servers ?? [])] });
  return { created: r.created, keyIssued: !r.keyKept };
};

export interface InstallOptions {
  client: ClientId;
  mode: InstallMode;
  scope: InstallScope;
  /** The name the entry is registered under in the client (default "switchboard"). */
  name: string;
  /** Project directory for `--scope project`. */
  dir: string;
  dshProfile: string;
  yes: boolean;
  dryRun: boolean;
  cfg: SwitchboardConfig;
  cfgPath: string;
  /** Absolute path of the node executable the bridge entry runs. */
  nodePath: string;
  /** Absolute path of dist/cli.js. */
  cliPath: string;
  env?: NodeJS.ProcessEnv;
  platform?: NodeJS.Platform;
  home?: string;
  appData?: string;
  io?: Partial<InstallIO>;
  ensureClient?: EnsureClientFn;
  now?: () => Date;
  /** How long the bridge probe waits for the initialize answer. */
  probeTimeoutMs?: number;
}

export type UninstallOptions = Omit<InstallOptions, "mode" | "nodePath" | "cliPath" | "ensureClient" | "probeTimeoutMs">;

export type InstallStatus = "installed" | "unchanged" | "dry-run" | "aborted" | "refused" | "rolled-back" | "failed" | "removed" | "absent";

export interface InstallOutcome {
  status: InstallStatus;
  exitCode: 0 | 1;
  message: string;
  route?: "cli" | "file";
  path?: string;
  backup?: string;
}

const ok = (status: InstallStatus, message: string, extra: Partial<InstallOutcome> = {}): InstallOutcome => ({ status, exitCode: 0, message, ...extra });
const fail = (status: InstallStatus, message: string, extra: Partial<InstallOutcome> = {}): InstallOutcome => ({ status, exitCode: 1, message, ...extra });

// ── the client's own CLI ───────────────────────────────────────────────────────────────────────

interface CliCommands {
  exe: ResolvedExe;
  cwd: string;
  add: string[];
  remove: string[];
  get: string[];
  /** `claude mcp add-json` refuses an existing name: remove first. codex and agy replace it. */
  removeBeforeAdd: boolean;
}

const stripTrailingNl = (s: string): string => s.replace(/\s+$/, "");

/** The CLI route, or null with the reason the file is edited instead. */
function chooseCli(plan: { target: InstallPlan["target"]; name: string }, add: string[] | null, env: NodeJS.ProcessEnv, platform: NodeJS.Platform, cwd: string): { cli: CliCommands | null; why?: string } {
  const { target, name } = plan;
  if (!target.cli) return { cli: null };
  const exe = resolveExecutable(target.cli, env, platform);
  if (!exe) return { cli: null, why: `${target.cli} is not on PATH, so ${target.path} is edited directly` };
  const scope = target.scope;
  const cmds: Record<string, { remove: string[]; get: string[]; removeBeforeAdd: boolean }> = {
    claude: { remove: ["mcp", "remove", name, "--scope", scope], get: ["mcp", "get", name], removeBeforeAdd: true },
    codex: { remove: ["mcp", "remove", name], get: ["mcp", "get", name, "--json"], removeBeforeAdd: false },
    agy: { remove: ["mcp", "remove", name], get: ["mcp", "list"], removeBeforeAdd: false },
  };
  const c = cmds[target.cli]!;
  const all = [...(add ?? []), ...c.remove, ...c.get];
  if (exe.kind === "shim") {
    const unsafe = shimUnsafeReason([exe.path, ...all]);
    if (unsafe) return { cli: null, why: `${target.cli} is a .cmd shim and ${unsafe}; ${target.path} is edited directly` };
  }
  return { cli: { exe, cwd, add: add ?? [], remove: c.remove, get: c.get, removeBeforeAdd: c.removeBeforeAdd } };
}

function addArgs(plan: InstallPlan): string[] | null {
  const { target, name, entry } = plan;
  if (target.cli === "claude") return ["mcp", "add-json", name, JSON.stringify(plan.jsonEntry), "--scope", target.scope];
  if (target.cli === "codex") {
    if (entry.kind === "stdio") return ["mcp", "add", name, "--", entry.command, ...entry.args];
    return ["mcp", "add", name, "--url", entry.url, ...(entry.tokenEnv ? ["--bearer-token-env-var", "SWITCHBOARD_TOKEN"] : [])];
  }
  if (target.cli === "agy") return entry.kind === "stdio" ? ["mcp", "add", name, "--", entry.command, ...entry.args] : null;
  return null;
}

const showArg = (a: string): string => (/^[A-Za-z0-9_@%+=:,./\\-]+$/.test(a) ? a : a.includes("'") ? JSON.stringify(a) : `'${a}'`);
const showCmd = (exe: string, args: string[]): string => [exe, ...args].map(showArg).join(" ");

const firstLine = (s: string): string => safeText(stripTrailingNl(s).split(/\r?\n/).find((l) => l.trim() !== "") ?? "", 240);
const runDetail = (r: CliResult): string => firstLine(r.stderr) || firstLine(r.stdout) || r.error || `exit ${r.status}`;

// ── paths and comparisons ──────────────────────────────────────────────────────────────────────

const norm = (s: string, platform: NodeJS.Platform): string => {
  const t = s.replace(/\\/g, "/");
  return platform === "win32" ? t.toLowerCase() : t;
};

const readIf = (path: string): string | null => {
  const real = writeTarget(path);
  return existsSync(real) ? readFileSync(real, "utf8") : null;
};

const isRegistered = (cfg: SwitchboardConfig, id: string): boolean => Object.prototype.hasOwnProperty.call(cfg.clients ?? {}, id);

function endpointOf(cfg: SwitchboardConfig): EndpointInfo {
  return { host: cfg.gateway.http.host, port: cfg.gateway.http.port, requireAuth: cfg.gateway.http.require_auth };
}

// ── probing ────────────────────────────────────────────────────────────────────────────────────

/** Whether something accepts a TCP connection at the URL's host and port within `timeoutMs`. */
export function gatewayReachable(url: string, timeoutMs = 1000): Promise<boolean> {
  return new Promise((resolve) => {
    let u: URL;
    try {
      u = new URL(url);
    } catch {
      resolve(false);
      return;
    }
    const sock = createConnection({ host: u.hostname.replace(/^\[|\]$/g, ""), port: Number(u.port || 80) });
    const done = (v: boolean): void => {
      sock.destroy();
      resolve(v);
    };
    sock.setTimeout(timeoutMs, () => done(false));
    sock.once("connect", () => done(true));
    sock.once("error", () => done(false));
  });
}

/** Start the bridge entry once, send `initialize`, and require a JSON-RPC result. Always kills the child. */
export function probeBridge(command: string, args: string[], env: NodeJS.ProcessEnv, timeoutMs: number): Promise<{ ok: boolean; detail: string }> {
  return new Promise((resolve) => {
    const childEnv: NodeJS.ProcessEnv = {};
    // The bridge prefers SWITCHBOARD_KEY over the key store; the probe must exercise what the client will use.
    for (const [k, v] of Object.entries(env)) if (k !== "SWITCHBOARD_KEY") childEnv[k] = v;
    let child;
    try {
      child = spawn(command, args, { env: childEnv, stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
    } catch (err) {
      resolve({ ok: false, detail: `cannot start the bridge: ${err instanceof Error ? err.message : String(err)}` });
      return;
    }
    let buf = "";
    let errText = "";
    let settled = false;
    const finish = (okv: boolean, detail: string): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        child.stdin?.end();
      } catch {
        /* already closed */
      }
      setTimeout(() => child.kill(), 1500).unref();
      child.kill();
      resolve({ ok: okv, detail });
    };
    const timer = setTimeout(() => finish(false, `no answer to initialize within ${Math.round(timeoutMs / 1000)} s${errText ? `; bridge said: ${safeText(errText, 200)}` : ""}`), timeoutMs);
    child.once("error", (err) => finish(false, `cannot start the bridge: ${err.message}`));
    child.once("exit", (code) => {
      if (!settled) finish(false, `the bridge exited (code ${code}) before answering${errText ? `: ${safeText(errText, 200)}` : ""}`);
    });
    child.stderr?.on("data", (d: Buffer) => {
      if (errText.length < 2000) errText += d.toString("utf8");
    });
    child.stdout?.on("data", (d: Buffer) => {
      buf += d.toString("utf8");
      let nl: number;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl).trim();
        buf = buf.slice(nl + 1);
        if (!line) continue;
        let msg: { id?: unknown; result?: { protocolVersion?: unknown; serverInfo?: { name?: unknown } }; error?: { message?: unknown } };
        try {
          msg = JSON.parse(line);
        } catch {
          continue;
        }
        if (msg.id !== 1) continue;
        if (msg.result && typeof msg.result === "object") {
          const v = typeof msg.result.protocolVersion === "string" ? msg.result.protocolVersion : "unknown";
          finish(true, `the bridge answered initialize (protocol ${safeText(v, 40)})`);
        } else finish(false, `the bridge answered initialize with an error: ${safeText(String(msg.error?.message ?? "no result"), 240)}`);
        return;
      }
    });
    const init = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "switchboard-install-probe", version: "1.0.0" } } };
    child.stdin?.on("error", () => undefined);
    child.stdin?.write(JSON.stringify(init) + "\n");
  });
}

interface ProbeContext {
  plan: InstallPlan;
  cli: CliCommands | null;
  env: NodeJS.ProcessEnv;
  platform: NodeJS.Platform;
  url: string;
  timeoutMs: number;
}

/** Registration check, then (bridge mode, gateway up) the spawn check. Returns the lines to print and the first failure. */
async function probeInstall(c: ProbeContext): Promise<{ failure?: string; lines: string[] }> {
  const { plan } = c;
  const lines: string[] = [];
  if (c.cli) {
    const r = runExecutable(c.cli.exe, c.cli.get, { cwd: c.cli.cwd, env: c.env, timeoutMs: 120_000 });
    if (!r.ok) return { lines, failure: `\`${plan.target.cli} ${c.cli.get.join(" ")}\` failed (${runDetail(r)})` };
    const mismatch = cliOutputMismatch(plan, r.stdout, c.platform);
    if (mismatch) return { lines, failure: `\`${plan.target.cli} ${c.cli.get.join(" ")}\` shows a different entry: ${mismatch}` };
    lines.push(`registration confirmed by \`${plan.target.cli} ${c.cli.get.join(" ")}\``);
  } else {
    const text = readIf(plan.target.path);
    const bad = verifyFileEntry(plan, text);
    if (bad) return { lines, failure: `the file ${plan.target.path} does not hold the entry after the write (${bad})` };
    lines.push(`re-read and parsed ${plan.target.path}: the entry is there`);
  }
  if (plan.entry.kind !== "stdio") {
    lines.push("http mode: the client dials the gateway itself, so no bridge was started");
    return { lines };
  }
  if (!isAbsolute(plan.entry.command) && !win32.isAbsolute(plan.entry.command)) {
    lines.push("the entry's command is not an absolute path: the bridge was not started");
    return { lines };
  }
  if (!(await gatewayReachable(c.url))) {
    lines.push(`no gateway answers at ${c.url}: the bridge entry was not exercised (start \`switchboard serve\`; the client will connect then)`);
    return { lines };
  }
  const r = await probeBridge(plan.entry.command, plan.entry.args, c.env, c.timeoutMs);
  if (!r.ok) return { lines, failure: `the bridge entry does not work against the gateway at ${c.url}: ${r.detail}` };
  lines.push(`${r.detail} (gateway at ${c.url})`);
  return { lines };
}

/** What a `get`/`list` listing says that differs from the entry we wrote, or null. Only checks what the listing shows. */
function cliOutputMismatch(plan: InstallPlan, stdout: string, platform: NodeJS.Platform): string | null {
  if (plan.entry.kind !== "stdio") return null;
  const cli = norm(plan.entry.args[0] ?? "", platform);
  const text = norm(stdout, platform);
  if (plan.target.cli === "agy") {
    const row = stdout.split(/\r?\n/).find((l) => l.trim().startsWith(plan.name + " ") || l.trim() === plan.name);
    if (!row) return `no '${plan.name}' row in the list`;
    return norm(row, platform).includes(cli) ? null : `the '${plan.name}' row does not run ${plan.entry.args[0]}`;
  }
  if (plan.target.cli === "codex") {
    try {
      const j = JSON.parse(stdout) as { transport?: { command?: unknown; args?: unknown } };
      const t = j.transport;
      if (t && typeof t.command === "string") {
        if (norm(t.command, platform) !== norm(plan.entry.command, platform)) return `command is ${t.command}`;
        if (Array.isArray(t.args) && JSON.stringify(t.args.map((a) => norm(String(a), platform))) !== JSON.stringify(plan.entry.args.map((a) => norm(a, platform)))) return "arguments differ";
      }
    } catch {
      /* not JSON: the exit code was the check */
    }
    return null;
  }
  // claude: `Command:` and `Args:` lines when it prints them (a local-scope entry of the same name would show here instead of ours).
  if (/^\s*Command:/m.test(stdout) && !text.includes(cli)) return `it does not run ${plan.entry.args[0]}`;
  return null;
}

/** True only when `codex mcp get --json` parsed and shows exactly the command and arguments we would write. */
function codexEntryIdentical(plan: InstallPlan, stdout: string, platform: NodeJS.Platform): boolean {
  if (plan.entry.kind !== "stdio") return false;
  try {
    const t = (JSON.parse(stdout) as { transport?: { command?: unknown; args?: unknown } }).transport;
    if (!t || typeof t.command !== "string" || !Array.isArray(t.args)) return false;
    return norm(t.command, platform) === norm(plan.entry.command, platform) && JSON.stringify(t.args.map((a) => norm(String(a), platform))) === JSON.stringify(plan.entry.args.map((a) => norm(a, platform)));
  } catch {
    return false;
  }
}

/** Re-read the file after a write and say what is wrong with the entry (null: fine). */
function verifyFileEntry(plan: InstallPlan, text: string | null): string | null {
  if (text === null) return "the file is missing";
  try {
    if (plan.target.format === "json") {
      const root = parseJsonConfig(text, plan.target.path);
      return entryMatches(readJsonEntry(root, plan.target.jsonKey, plan.name, plan.target.path), plan.jsonEntry ?? {}) ? null : "the entry is missing or differs";
    }
    if (plan.target.format === "toml") {
      return readTomlTable(text, plan.name) === readTomlTable(plan.content, plan.name) && readTomlTable(text, plan.name) !== undefined ? null : "the table is missing or differs";
    }
    const v = verifyDshPatch(text, plan.dshSpec!);
    return v.ok ? null : (v.reason ?? "the patch entry is invalid");
  } catch (err) {
    return err instanceof Error ? err.message : String(err);
  }
}

// ── rollback ───────────────────────────────────────────────────────────────────────────────────

interface Snapshot {
  /** Timestamped copy of the target file (file route, codex, agy). */
  backupPath?: string;
  fileExisted: boolean;
  /** claude: the entry that was there, put back with add-json. */
  previousJson?: unknown;
  /** The file's text when it was planned (restoration target). */
  originalText: string | null;
}

/** Put things back. Returns what was done, one line each. Never throws. */
function rollback(plan: { target: InstallPlan["target"]; name: string }, snap: Snapshot, cli: CliCommands | null, env: NodeJS.ProcessEnv): string[] {
  const done: string[] = [];
  const real = writeTarget(plan.target.path);
  try {
    if (snap.backupPath) {
      atomicWriteFileSync(real, readFileSync(snap.backupPath));
      done.push(`restored ${plan.target.path} from ${snap.backupPath}`);
    } else if (!cli && !snap.fileExisted && existsSync(real)) {
      unlinkSync(real);
      done.push(`removed ${plan.target.path}, which this install had created`);
    }
  } catch (err) {
    done.push(`COULD NOT restore ${plan.target.path} (${err instanceof Error ? err.message : String(err)}); the backup is ${snap.backupPath ?? "not available"}`);
  }
  if (cli) {
    const claude = plan.target.cli === "claude";
    const hadEntry = claude ? snap.previousJson !== undefined : snap.originalText !== null && snap.backupPath !== undefined && entryWasPresent(snap.originalText, plan);
    if (claude) {
      const rm = runExecutable(cli.exe, cli.remove, { cwd: cli.cwd, env, timeoutMs: 60_000 });
      if (hadEntry) {
        const re = runExecutable(cli.exe, ["mcp", "add-json", plan.name, JSON.stringify(snap.previousJson), "--scope", plan.target.scope], { cwd: cli.cwd, env, timeoutMs: 60_000 });
        done.push(re.ok ? "put the previous entry back with `claude mcp add-json`" : `COULD NOT put the previous entry back (${runDetail(re)}); it is recorded in the install record`);
      } else done.push(rm.ok ? "removed the entry with `claude mcp remove`" : `could not remove the entry with \`claude mcp remove\` (${runDetail(rm)}); remove it by hand`);
    } else if (!hadEntry) {
      const rm = runExecutable(cli.exe, cli.remove, { cwd: cli.cwd, env, timeoutMs: 60_000 });
      done.push(rm.ok ? `removed the entry with \`${plan.target.cli} ${cli.remove.join(" ")}\`` : `\`${plan.target.cli} ${cli.remove.join(" ")}\` reported: ${runDetail(rm)} (nothing to remove, or remove it by hand)`);
      try {
        // A config file this install created and the client left empty goes too.
        if (!snap.fileExisted && existsSync(real) && readFileSync(real, "utf8").trim() === "") {
          unlinkSync(real);
          done.push(`removed the empty ${plan.target.path} this install had created`);
        }
      } catch {
        /* leave it */
      }
    }
  }
  return done;
}

function entryWasPresent(text: string, plan: { target: InstallPlan["target"]; name: string }): boolean {
  try {
    if (plan.target.format === "toml") return readTomlTable(text, plan.name) !== undefined;
    if (plan.target.format === "json") return readJsonEntry(parseJsonConfig(text), plan.target.jsonKey, plan.name) !== undefined;
  } catch {
    /* unreadable: treat as absent */
  }
  return false;
}

/** Save what was there before a CLI change, so a crash between the change and the probe leaves a way back. */
function writeInstallRecord(client: string, scope: string, name: string, path: string, previous: unknown, now: Date): string | null {
  try {
    const dir = join(HOME_DIR, "install-backups");
    mkdirSync(dir, { recursive: true });
    const file = join(dir, `${client}-${scope}-${backupStamp(now)}.json`);
    writeJsonAtomic(file, { client, scope, name, target: path, previous: previous ?? null, recorded: now.toISOString() }, { mode: 0o600, backup: false });
    return file;
  } catch {
    return null;
  }
}

// ── install ────────────────────────────────────────────────────────────────────────────────────

function previewLines(o: InstallOptions, plan: InstallPlan, cli: CliCommands | null, why: string | undefined, registered: boolean, keyFile: boolean, url: string): string[] {
  const L: string[] = [];
  L.push("");
  L.push(`Install MCP Switchboard into ${plan.target.label}`);
  L.push(`  mode      ${plan.mode}${plan.mode === "bridge" ? ` (the client starts a stdio bridge that relays to the shared gateway at ${url})` : ` (the client dials ${url} itself)`}`);
  L.push(`  scope     ${plan.target.scope}`);
  L.push(`  client    ${o.client}: ${registered ? `already registered${keyFile ? "" : "; its key file is missing and will be re-issued"}` : `will be registered first (servers ${INSTALL_CLIENT_DEFAULTS.servers!.join(",")}, max_scope ${INSTALL_CLIENT_DEFAULTS.max_scope}, max_risk ${INSTALL_CLIENT_DEFAULTS.max_risk}); its key is stored for the bridge, never in the client's file`}`);
  L.push("  entry");
  for (const l of entryPreview(plan)) L.push(`      ${l}`);
  if (cli) {
    L.push(`  write     run ${cli.exe.kind === "shim" ? "through cmd.exe (a .cmd shim; every argument is quoted and checked)" : "without a shell"}: ${showCmd(cli.exe.path, cli.add)}`);
    if (cli.removeBeforeAdd && plan.previous !== undefined) L.push(`            (the existing entry is removed first with: ${showCmd(cli.exe.path, cli.remove)})`);
  } else {
    L.push(`  write     atomic write (temp file, fsync, rename) of ${plan.target.path}${why ? ` (${why})` : ""}`);
  }
  if (plan.existed) {
    if (cli && plan.target.cli === "claude") L.push(`  target    ${plan.target.path} (read only; the previous entry is recorded for rollback, no copy of the file is made)`);
    else L.push(`  target    ${plan.target.path} (existing file parses; a copy is kept as ${plan.target.path}.bak-switchboard-<timestamp>)`);
  } else L.push(`  target    ${plan.target.path} (does not exist yet and will be created)`);
  if (plan.previous !== undefined) L.push(`  replaces  an existing entry named '${plan.name}' (${previewPrevious(plan.previous)})`);
  L.push(`  then      verify with ${cli ? `\`${plan.target.cli} ${cli.get.join(" ")}\`` : "a re-read and parse of the file"}${plan.mode === "bridge" ? "; start the bridge once with an initialize request when a gateway answers at that address" : ""}; roll back if either fails`);
  return L;
}

const previewPrevious = (p: unknown): string => safeText(typeof p === "string" ? p.replace(/\s+/g, " ") : JSON.stringify(p), 160);

function entryPreview(plan: InstallPlan): string[] {
  if (plan.target.format === "json" && plan.jsonEntry) return JSON.stringify({ [plan.target.jsonKey]: { [plan.name]: plan.jsonEntry } }, null, 2).split("\n");
  if (plan.target.format === "toml") return (readTomlTable(plan.content, plan.name) ?? "").split("\n");
  if (plan.target.format === "yaml") {
    const lines = plan.content.split(/\r?\n/);
    const a = lines.findIndex((l) => /^\s*# switchboard:begin/.test(l));
    const b = lines.findIndex((l) => /^\s*# switchboard:end/.test(l));
    return a >= 0 && b >= a ? lines.slice(a, b + 1) : [];
  }
  return [];
}

function extraNotes(o: InstallOptions, plan: InstallPlan, env: NodeJS.ProcessEnv): string[] {
  const notes = [...plan.notes];
  if (!o.cfg.gateway.transport.includes("http")) notes.push("gateway.transport does not include `http`: the bridge relays to the HTTP endpoint, so add it and restart `switchboard serve`.");
  if (plan.entry.kind === "stdio" && /[\\/]_npx[\\/]/.test(o.cliPath)) notes.push(`this CLI runs from an npx cache (${o.cliPath}), which npm may delete: install it globally (npm i -g) and run install again.`);
  if (plan.entry.kind === "stdio" && env.SWITCHBOARD_HOME) notes.push(`SWITCHBOARD_HOME is set here (${env.SWITCHBOARD_HOME}); the client starts the bridge without it, so the bridge will read the default key store. Install with the default home or set it in the client's environment.`);
  if (plan.target.client === "claude-code" && plan.target.scope === "project") notes.push("Claude Code asks you to approve a project .mcp.json server the first time it sees it.");
  if (plan.target.client === "claude-desktop" || plan.target.client === "cursor" || plan.target.client === "vscode" || plan.target.client === "gemini" || plan.target.client === "antigravity") notes.push(`restart ${plan.target.label} to load the entry.`);
  return notes;
}

export async function runInstall(opts: InstallOptions): Promise<InstallOutcome> {
  const io: InstallIO = { ...defaultIO, ...opts.io };
  try {
    return await install(opts, io);
  } catch (err) {
    if (err instanceof InstallRefusal) {
      io.error(err.message);
      return fail("refused", err.message);
    }
    throw err;
  }
}

async function install(o: InstallOptions, io: InstallIO): Promise<InstallOutcome> {
  const env = o.env ?? process.env;
  const platform = o.platform ?? process.platform;
  const home = o.home ?? homedir();
  const now = o.now ?? (() => new Date());
  if (!SERVER_NAME_RE.test(o.name)) throw new InstallRefusal(BAD_SERVER_NAME);
  if (o.scope === "project" && !existsSync(o.dir)) throw new InstallRefusal(`the project directory ${o.dir} does not exist (--dir)`);
  const endpoint = endpointOf(o.cfg);
  const url = mcpUrl(endpoint);

  const plan = buildPlan(o.client, {
    name: o.name,
    endpoint,
    launcher: { command: o.nodePath, cliPath: o.cliPath },
    mode: o.mode,
    scope: o.scope,
    baseDir: o.dir,
    platform,
    home,
    appData: o.appData ?? env.APPDATA,
    env,
    dshProfile: o.dshProfile,
    clientsConfigured: true,
  });
  const addArgv = addArgs(plan);
  const { cli, why } = chooseCli(plan, addArgv, env, platform, o.scope === "project" ? o.dir : process.cwd());
  const registered = isRegistered(o.cfg, o.client);
  const keyFile = registered && existsSync(clientKeyPath(o.client));
  const notes = extraNotes(o, plan, env);

  // Codex rewrites its own TOML in its own layout, so for an existing entry its `get --json` is the judge of "identical", not our text.
  let unchanged = !plan.changed;
  if (!unchanged && cli && plan.target.cli === "codex" && plan.previous !== undefined) {
    const g = runExecutable(cli.exe, cli.get, { cwd: cli.cwd, env, timeoutMs: 60_000 });
    unchanged = g.ok && codexEntryIdentical(plan, g.stdout, platform);
  }

  if (unchanged) {
    if (!o.dryRun) {
      const ensure = (o.ensureClient ?? ensureClientRegistered)(o.cfg, o.cfgPath, o.client);
      if (ensure.created || ensure.keyIssued) io.ok(`client '${o.client}' ${ensure.created ? "registered" : "key re-issued"}`);
    }
    const msg = `${plan.target.label} already has an identical '${plan.name}' entry in ${plan.target.path}: nothing to change.`;
    io.ok(msg);
    return ok("unchanged", msg, { path: plan.target.path });
  }

  for (const l of previewLines(o, plan, cli, why, registered, keyFile, url)) io.out(l);
  for (const n of notes) io.out(`  note      ${n}`);
  if (o.dryRun) {
    io.out("");
    io.out("Dry run: nothing was written, no client was registered, no command that changes anything was run.");
    return ok("dry-run", "dry run", { path: plan.target.path, route: cli ? "cli" : "file" });
  }
  io.out("");
  if (!o.yes && !(await io.confirm("Apply these changes?"))) {
    const msg = "Not confirmed: nothing was changed (pass --yes to skip the question).";
    io.warn(msg);
    return fail("aborted", msg, { path: plan.target.path });
  }

  // The file may have changed while the owner read the preview: never overwrite a version we did not parse.
  const current = readIf(plan.target.path);
  if (current !== plan.originalText) throw new InstallRefusal(`${plan.target.path} changed after the preview was built; nothing was written. Run the command again.`);

  const ensure = (o.ensureClient ?? ensureClientRegistered)(o.cfg, o.cfgPath, o.client);
  if (ensure.created) io.ok(`client '${o.client}' registered (servers ${INSTALL_CLIENT_DEFAULTS.servers!.join(",")}, max_scope ${INSTALL_CLIENT_DEFAULTS.max_scope}, max_risk ${INSTALL_CLIENT_DEFAULTS.max_risk})`);
  else if (ensure.keyIssued) io.ok(`client '${o.client}': a new key was issued for the bridge`);

  const snap: Snapshot = { fileExisted: plan.existed, originalText: plan.originalText };
  let backup: string | undefined;
  const claudeCli = cli !== null && plan.target.cli === "claude";
  try {
    if (claudeCli) {
      snap.previousJson = plan.previous;
      const record = writeInstallRecord(o.client, plan.target.scope, plan.name, plan.target.path, plan.previous, now());
      if (record) io.out(`  record    previous entry saved to ${record}`);
    } else if (plan.existed) {
      backup = backupFile(plan.target.path, now());
      snap.backupPath = backup;
      io.out(`  backup    ${backup}`);
    }
    if (cli) {
      if (cli.removeBeforeAdd && plan.previous !== undefined) {
        const rm = runExecutable(cli.exe, cli.remove, { cwd: cli.cwd, env, timeoutMs: 60_000 });
        if (!rm.ok) throw new Error(`\`${plan.target.cli} ${cli.remove.join(" ")}\` failed (${runDetail(rm)})`);
      }
      let r = runExecutable(cli.exe, cli.add, { cwd: cli.cwd, env, timeoutMs: 60_000 });
      if (!r.ok && plan.previous !== undefined && !cli.removeBeforeAdd) {
        // codex and agy document add as a replace, but a client that refuses an existing name gets one retry after a remove.
        const rm = runExecutable(cli.exe, cli.remove, { cwd: cli.cwd, env, timeoutMs: 60_000 });
        if (rm.ok) r = runExecutable(cli.exe, cli.add, { cwd: cli.cwd, env, timeoutMs: 60_000 });
      }
      if (!r.ok) throw new Error(`\`${plan.target.cli} ${cli.add.slice(0, 2).join(" ")}\` failed (${runDetail(r)})`);
    } else {
      writeFileAtomic(plan.target.path, plan.content);
    }
  } catch (err) {
    const msg = `the write failed: ${err instanceof Error ? err.message : String(err)}`;
    io.error(msg);
    for (const l of rollback(plan, snap, cli, env)) io.warn(l);
    return fail("failed", msg, { path: plan.target.path, ...(backup ? { backup } : {}) });
  }

  const probe = await probeInstall({ plan, cli, env, platform, url, timeoutMs: o.probeTimeoutMs ?? 15_000 });
  if (probe.failure) {
    io.error(`probe failed: ${probe.failure}`);
    for (const l of probe.lines) io.out(`  probe     ${l}`);
    for (const l of rollback(plan, snap, cli, env)) io.warn(l);
    const msg = `Rolled back: ${probe.failure}`;
    io.error(`${msg}${backup ? ` (the copy taken before the write is kept at ${backup})` : ""}`);
    return fail("rolled-back", msg, { path: plan.target.path, route: cli ? "cli" : "file", ...(backup ? { backup } : {}) });
  }
  for (const l of probe.lines) io.out(`  probe     ${l}`);
  const msg = `${plan.target.label}: '${plan.name}' ${plan.previous === undefined ? "added" : "updated"} (${plan.target.path}).`;
  io.ok(msg);
  return ok("installed", msg, { path: plan.target.path, route: cli ? "cli" : "file", ...(backup ? { backup } : {}) });
}

// ── uninstall ──────────────────────────────────────────────────────────────────────────────────

export async function runUninstall(opts: UninstallOptions): Promise<InstallOutcome> {
  const io: InstallIO = { ...defaultIO, ...opts.io };
  try {
    return await uninstall(opts, io);
  } catch (err) {
    if (err instanceof InstallRefusal) {
      io.error(err.message);
      return fail("refused", err.message);
    }
    throw err;
  }
}

async function uninstall(o: UninstallOptions, io: InstallIO): Promise<InstallOutcome> {
  const env = o.env ?? process.env;
  const platform = o.platform ?? process.platform;
  const home = o.home ?? homedir();
  const now = o.now ?? (() => new Date());
  if (!SERVER_NAME_RE.test(o.name)) throw new InstallRefusal(BAD_SERVER_NAME);
  if (o.scope === "project" && !existsSync(o.dir)) throw new InstallRefusal(`the project directory ${o.dir} does not exist (--dir)`);
  const rem: RemovalPlan = buildRemoval(o.client, { name: o.name, scope: o.scope, baseDir: o.dir, platform, home, appData: o.appData ?? env.APPDATA, env, dshProfile: o.dshProfile });
  const { cli, why } = chooseCli(rem, null, env, platform, o.scope === "project" ? o.dir : process.cwd());

  let present = rem.present;
  if (!present && cli && rem.target.cli === "agy") {
    // The file location for agy is inferred; its own listing is the authority.
    const r = runExecutable(cli.exe, cli.get, { cwd: cli.cwd, env, timeoutMs: 90_000 });
    present = r.ok && r.stdout.split(/\r?\n/).some((l) => l.trim().startsWith(o.name + " "));
  }
  if (!present) {
    const extra = rem.unmanagedLine !== undefined ? ` (an entry with that id at line ${rem.unmanagedLine + 1} was not written by this tool and is left alone)` : "";
    const msg = `${rem.target.label} has no '${o.name}' entry in ${rem.target.path}: nothing to remove${extra}.`;
    io.ok(msg);
    return ok("absent", msg, { path: rem.target.path });
  }

  io.out("");
  io.out(`Remove MCP Switchboard from ${rem.target.label}`);
  io.out(`  scope     ${rem.target.scope}`);
  io.out(`  removes   only the entry named '${o.name}' (${previewPrevious(rem.previous ?? "present")})`);
  if (cli) io.out(`  write     run ${cli.exe.kind === "shim" ? "through cmd.exe (a .cmd shim; every argument is quoted and checked)" : "without a shell"}: ${showCmd(cli.exe.path, cli.remove)}`);
  else io.out(`  write     atomic write of ${rem.target.path}${why ? ` (${why})` : ""}`);
  if (rem.originalText !== null && rem.target.cli !== "claude") io.out(`  backup    a copy is kept as ${rem.target.path}.bak-switchboard-<timestamp>`);
  io.out(`  keeps     the client '${o.client}' and its key in Switchboard (\`switchboard client rm ${o.client}\` revokes them)`);
  if (o.dryRun) {
    io.out("");
    io.out("Dry run: nothing was changed.");
    return ok("dry-run", "dry run", { path: rem.target.path });
  }
  io.out("");
  if (!o.yes && !(await io.confirm("Remove it?"))) {
    const msg = "Not confirmed: nothing was changed (pass --yes to skip the question).";
    io.warn(msg);
    return fail("aborted", msg, { path: rem.target.path });
  }
  const current = readIf(rem.target.path);
  if (current !== rem.originalText) throw new InstallRefusal(`${rem.target.path} changed after the preview was built; nothing was changed. Run the command again.`);

  const snap: Snapshot = { fileExisted: rem.existed, originalText: rem.originalText };
  let backup: string | undefined;
  const claudeCli = cli !== null && rem.target.cli === "claude";
  try {
    if (claudeCli) {
      snap.previousJson = rem.previous;
      const record = writeInstallRecord(o.client, rem.target.scope, o.name, rem.target.path, rem.previous, now());
      if (record) io.out(`  record    previous entry saved to ${record}`);
    } else if (rem.existed) {
      backup = backupFile(rem.target.path, now());
      snap.backupPath = backup;
      io.out(`  backup    ${backup}`);
    }
    if (cli) {
      const r = runExecutable(cli.exe, cli.remove, { cwd: cli.cwd, env, timeoutMs: 60_000 });
      if (!r.ok) throw new Error(`\`${rem.target.cli} ${cli.remove.join(" ")}\` failed (${runDetail(r)})`);
    } else {
      writeFileAtomic(rem.target.path, rem.content);
    }
    // Verify it is gone from the file (agy's file is inferred, so a missing file proves nothing there).
    const after = readIf(rem.target.path);
    if (after !== null && stillPresent(rem, after, o.name)) throw new Error(`the entry is still in ${rem.target.path} after the removal`);
  } catch (err) {
    const msg = `the removal failed: ${err instanceof Error ? err.message : String(err)}`;
    io.error(msg);
    // Restoring means putting the entry back: the claude path re-adds the recorded entry, the others restore the file copy.
    for (const l of restoreAfterFailedRemoval(rem, snap, cli, env)) io.warn(l);
    return fail("failed", msg, { path: rem.target.path, ...(backup ? { backup } : {}) });
  }
  const msg = `${rem.target.label}: '${o.name}' removed (${rem.target.path}); everything else in the file is untouched.`;
  io.ok(msg);
  return ok("removed", msg, { path: rem.target.path, route: cli ? "cli" : "file", ...(backup ? { backup } : {}) });
}

function stillPresent(rem: RemovalPlan, text: string, name: string): boolean {
  try {
    if (rem.target.format === "toml") return readTomlTable(text, name) !== undefined;
    if (rem.target.format === "json") return readJsonEntry(parseJsonConfig(text, rem.target.path), rem.target.jsonKey, name, rem.target.path) !== undefined;
    return dshBlockPresent(text, name);
  } catch {
    return false;
  }
}

function dshBlockPresent(text: string, name: string): boolean {
  return new RegExp(`^\\s*# switchboard:begin id=${name}(\\s|$)`, "m").test(text);
}

function restoreAfterFailedRemoval(rem: RemovalPlan, snap: Snapshot, cli: CliCommands | null, env: NodeJS.ProcessEnv): string[] {
  const done: string[] = [];
  const real = writeTarget(rem.target.path);
  try {
    if (snap.backupPath) {
      atomicWriteFileSync(real, readFileSync(snap.backupPath));
      done.push(`restored ${rem.target.path} from ${snap.backupPath}`);
    }
  } catch (err) {
    done.push(`COULD NOT restore ${rem.target.path} (${err instanceof Error ? err.message : String(err)}); the backup is ${snap.backupPath ?? "not available"}`);
  }
  if (cli && rem.target.cli === "claude" && snap.previousJson !== undefined) {
    const re = runExecutable(cli.exe, ["mcp", "add-json", rem.name, JSON.stringify(snap.previousJson), "--scope", rem.target.scope], { cwd: cli.cwd, env, timeoutMs: 60_000 });
    done.push(re.ok ? "put the previous entry back with `claude mcp add-json`" : `COULD NOT put the previous entry back (${runDetail(re)}); it is in the install record`);
  }
  return done;
}
