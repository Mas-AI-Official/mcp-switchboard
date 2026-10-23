/**
 * OS user-scope protection for small local secrets (the vault key, client bridge keys).
 *
 * Windows: DPAPI with CurrentUser scope through Windows PowerShell's ProtectedData, plus a fixed
 * purpose entropy, so the blob decrypts only for the same Windows user on the same machine. Other
 * local accounts (including sandbox accounts that can read the file) cannot unwrap it.
 *
 * Elsewhere there is no portable equivalent without a native module, so the bytes are stored as-is
 * and protection comes from file mode 0600 inside a 0700 directory. `isOsProtected()` says which
 * one applies so callers can report it honestly.
 *
 * No secret ever travels through argv or the environment: the payload goes over stdin as base64.
 *
 * PowerShell is launched by ABSOLUTE path, never by bare name. Windows resolves a bare "powershell.exe"
 * against the launch cwd first (unless NoDefaultCurrentDirectoryInExePath is set, which not every MCP
 * client does), and a stdio server runs with cwd = the opened project. A project that shipped its own
 * powershell.exe would otherwise receive the DPAPI blob (read) or the plaintext token (write) on stdin and
 * could answer with a token of its choosing. The child also gets cwd System32 and the same variable.
 */

import { execFileSync } from "node:child_process";
import { statSync } from "node:fs";
import { win32 } from "node:path";

const ENTROPY = "mcp-switchboard/oscrypt/v1";
const TIMEOUT_MS = 30_000;

/**
 * The system Windows PowerShell and the directory to run it in, from SystemRoot (windir as fallback).
 * Throws, never falls back to a bare-name launch, when SystemRoot is not a local absolute path or the
 * executable is not there.
 */
export function systemPowershell(): { exe: string; cwd: string } {
  const sysRoot = process.env.SystemRoot || process.env.windir || "C:\\Windows";
  if (!/^[A-Za-z]:[\\/]/.test(sysRoot)) throw new Error("SystemRoot is not a local absolute path; refusing to launch PowerShell");
  const cwd = win32.join(sysRoot, "System32");
  const exe = win32.join(cwd, "WindowsPowerShell", "v1.0", "powershell.exe");
  let isFile = false;
  try {
    isFile = statSync(exe).isFile();
  } catch {
    /* reported below */
  }
  if (!isFile) throw new Error(`Windows PowerShell not found at ${exe}`);
  return { exe, cwd };
}

/** The current environment with the launch-cwd executable search switched off (any spelling of the name replaced). */
export function hardenedEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) if (k.toUpperCase() !== "NODEFAULTCURRENTDIRECTORYINEXEPATH") env[k] = v;
  env.NoDefaultCurrentDirectoryInExePath = "1";
  return env;
}

function powershell(script: string, stdin: string): string {
  const { exe, cwd } = systemPowershell();
  return execFileSync(
    exe,
    ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
    // stderr is captured (not inherited): a stdio MCP process must never write PowerShell noise.
    { input: stdin, encoding: "utf8", windowsHide: true, timeout: TIMEOUT_MS, maxBuffer: 1 << 20, stdio: ["pipe", "pipe", "pipe"], cwd, env: hardenedEnv() },
  ).trim();
}

function dpapi(op: "Protect" | "Unprotect", data: Buffer): Buffer {
  const script =
    "Add-Type -AssemblyName System.Security; " +
    "$in = [Console]::In.ReadToEnd().Trim(); " +
    "$bytes = [Convert]::FromBase64String($in); " +
    `$ent = [Text.Encoding]::UTF8.GetBytes('${ENTROPY}'); ` +
    `$out = [System.Security.Cryptography.ProtectedData]::${op}($bytes, $ent, ` +
    "[System.Security.Cryptography.DataProtectionScope]::CurrentUser); " +
    "[Convert]::ToBase64String($out)";
  const b64 = powershell(script, data.toString("base64"));
  if (!/^[A-Za-z0-9+/=]+$/.test(b64)) throw new Error(`DPAPI ${op} returned unexpected output`);
  return Buffer.from(b64, "base64");
}

/** True when bytes are wrapped by the OS (DPAPI); false when only file permissions protect them. */
export function isOsProtected(): boolean {
  return process.platform === "win32";
}

/** Wrap bytes for the current OS user. Throws if the OS facility fails (never silently stores plaintext on Windows). */
export function protectForUser(data: Buffer): Buffer {
  if (!isOsProtected()) return Buffer.from(data);
  return dpapi("Protect", data);
}

/** Unwrap bytes produced by `protectForUser` for the same OS user. Throws on a foreign or corrupt blob. */
export function unprotectForUser(blob: Buffer): Buffer {
  if (!isOsProtected()) return Buffer.from(blob);
  return dpapi("Unprotect", blob);
}
