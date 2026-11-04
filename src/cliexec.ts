/**
 * cliexec.ts: find and run a client's own CLI (`claude`, `codex`, `agy`) for `switchboard install` (design 3.13).
 *
 * Two rules matter more than convenience:
 *
 *  - NEVER LAUNCH FROM THE WORKING DIRECTORY. On Windows a bare command name is resolved against the launch cwd
 *    first, and `install --scope project` runs inside someone's project. The name is looked up here, in the
 *    ABSOLUTE entries of PATH only (relative and empty entries are skipped), and the file found is started by its
 *    absolute path. The child also gets NoDefaultCurrentDirectoryInExePath, as oscrypt.ts does for PowerShell.
 *  - NO SHELL STRING FROM DATA. A real executable (`.exe`, or any file on POSIX) is started with an argument
 *    vector and no shell. A Windows `.cmd` or `.bat` shim (the npm global install of `codex`, an npm-installed
 *    `claude`) cannot be started without cmd.exe, and Node refuses to start one with shell:false. For those the
 *    command line is built here: every argument is quoted for the C runtime (backslash and quote rules) and an
 *    argument holding a character cmd.exe would treat as syntax (`& | < > ^ % !`, a control character) is refused
 *    outright. A refused argument is reported to the caller, which falls back to editing the client's file, so
 *    nothing is ever interpreted by a shell.
 */

import { spawnSync } from "node:child_process";
import { statSync } from "node:fs";
import { delimiter, isAbsolute, join, win32 } from "node:path";

export interface ResolvedExe {
  /** Absolute path of the file that will be started. */
  path: string;
  /** `direct`: started with an argument vector. `shim`: a Windows .cmd/.bat that must go through cmd.exe. */
  kind: "direct" | "shim";
}

const isFile = (p: string): boolean => {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
};

/**
 * Look `name` up in the absolute entries of PATH (with PATHEXT on Windows). Null when absent. The first hit in PATH
 * order wins, as it would for a shell, so a stub placed first on PATH shadows the real client (the oracle relies on it).
 */
export function resolveExecutable(name: string, env: NodeJS.ProcessEnv = process.env, platform: NodeJS.Platform = process.platform): ResolvedExe | null {
  const win = platform === "win32";
  const pathKey = Object.keys(env).find((k) => (win ? k.toUpperCase() === "PATH" : k === "PATH"));
  const dirs = String(pathKey ? env[pathKey] ?? "" : "")
    .split(win ? ";" : delimiter)
    .map((d) => d.trim().replace(/^"(.*)"$/, "$1"))
    .filter((d) => d !== "" && (win ? win32.isAbsolute(d) : isAbsolute(d)));
  const exts = win
    ? String(env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD")
        .split(";")
        .filter(Boolean)
        .map((e) => e.toLowerCase())
    : [""];
  for (const dir of dirs) {
    for (const ext of exts) {
      if (win && !/^\.(com|exe|bat|cmd)$/.test(ext)) continue; // .ps1, .js and friends are not started by CreateProcess
      const p = win ? win32.join(dir, name + ext) : join(dir, name);
      if (!isFile(p)) continue;
      return { path: p, kind: win && /\.(cmd|bat)$/.test(ext) ? "shim" : "direct" };
    }
  }
  return null;
}

/** cmd.exe syntax inside an argument. `"` is handled by quoting, but `%` is expanded even inside quotes. */
const CMD_META = /[&|<>^%!\r\n\0]/;

/** Why `args` cannot be passed through a .cmd shim safely, or null when they can. */
export function shimUnsafeReason(args: string[]): string | null {
  for (const a of args) {
    if (CMD_META.test(a)) return `an argument contains a character cmd.exe treats as syntax (one of & | < > ^ % ! or a line break)`;
  }
  return null;
}

/** Quote one argument for the Windows C runtime (the rules `CommandLineToArgvW` and the MSVC startup code share). */
export function quoteCrtArg(arg: string, always = false): string {
  if (arg === "") return '""';
  if (!always && !/[\s"]/.test(arg)) return arg;
  let out = '"';
  let backslashes = 0;
  for (const ch of arg) {
    if (ch === "\\") {
      backslashes++;
      continue;
    }
    if (ch === '"') out += "\\".repeat(backslashes * 2 + 1) + '"';
    else out += "\\".repeat(backslashes) + ch;
    backslashes = 0;
  }
  return out + "\\".repeat(backslashes * 2) + '"';
}

export interface CliResult {
  /** Started and exited with status 0. */
  ok: boolean;
  status: number | null;
  stdout: string;
  stderr: string;
  /** A spawn error (not found, timeout) or the refusal reason when `unsafe` is set. */
  error?: string;
  /** The arguments cannot be passed through a .cmd shim; nothing was started. */
  unsafe?: boolean;
}

export interface RunOptions {
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  timeoutMs?: number;
}

function childEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(env)) if (k.toUpperCase() !== "NODEFAULTCURRENTDIRECTORYINEXEPATH") out[k] = v;
  out.NoDefaultCurrentDirectoryInExePath = "1";
  return out;
}

function systemCmd(env: NodeJS.ProcessEnv): string | null {
  const root = env.SystemRoot || env.windir || "C:\\Windows";
  if (!/^[A-Za-z]:[\\/]/.test(root)) return null;
  const p = win32.join(root, "System32", "cmd.exe");
  return isFile(p) ? p : null;
}

/** Run a resolved CLI synchronously and capture its output. Never throws. */
export function runExecutable(exe: ResolvedExe, args: string[], opts: RunOptions = {}): CliResult {
  const env = childEnv(opts.env ?? process.env);
  const base = { cwd: opts.cwd, env, encoding: "utf8" as const, timeout: opts.timeoutMs ?? 60_000, maxBuffer: 8 << 20, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] as ["ignore", "pipe", "pipe"] };
  let r;
  if (exe.kind === "direct") {
    r = spawnSync(exe.path, args, base);
  } else {
    const unsafe = shimUnsafeReason([exe.path, ...args]);
    if (unsafe) return { ok: false, status: null, stdout: "", stderr: "", error: unsafe, unsafe: true };
    const cmd = systemCmd(opts.env ?? process.env);
    if (!cmd) return { ok: false, status: null, stdout: "", stderr: "", error: "cmd.exe not found under SystemRoot" };
    const line = [exe.path, ...args].map((a) => quoteCrtArg(a, true)).join(" ");
    // /s strips the outer pair of quotes, so every argument keeps its own.
    r = spawnSync(cmd, ["/d", "/s", "/c", `"${line}"`], { ...base, windowsVerbatimArguments: true });
  }
  const stdout = typeof r.stdout === "string" ? r.stdout : "";
  const stderr = typeof r.stderr === "string" ? r.stderr : "";
  if (r.error) return { ok: false, status: r.status, stdout, stderr, error: r.error.message };
  return { ok: r.status === 0, status: r.status, stdout, stderr };
}
