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
 */

import { execFileSync } from "node:child_process";

const ENTROPY = "mcp-switchboard/oscrypt/v1";
const TIMEOUT_MS = 30_000;

function powershell(script: string, stdin: string): string {
  return execFileSync(
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
    // stderr is captured (not inherited): a stdio MCP process must never write PowerShell noise.
    { input: stdin, encoding: "utf8", windowsHide: true, timeout: TIMEOUT_MS, maxBuffer: 1 << 20, stdio: ["pipe", "pipe", "pipe"] },
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
