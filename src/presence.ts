/**
 * Owner-presence verification for approvals and dashboard login.
 *
 * An AI agent that shares the owner's OS account can run any CLI the owner can, so "the owner typed a
 * command" proves nothing. A presence check asks the machine for a human factor the agent cannot
 * produce: Windows Hello (face, fingerprint or PIN) through UserConsentVerifier. Where Hello is not
 * available the caller may fall back to an interactive TTY challenge, which is weaker (a pseudo-terminal
 * can be scripted) and is reported as such in the audit trail.
 */

import { execFile } from "node:child_process";
import { createInterface } from "node:readline";

export type PresenceMethod = "hello" | "tty" | "none";
export type PresenceResult =
  | { ok: true; method: PresenceMethod }
  | { ok: false; method: PresenceMethod; reason: string };

const HELLO_PREAMBLE =
  "Add-Type -AssemblyName System.Runtime.WindowsRuntime; " +
  "$asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and " +
  "$_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]; " +
  "$null = [Windows.Security.Credentials.UI.UserConsentVerifier, Windows.Security.Credentials.UI, ContentType = WindowsRuntime]; ";

function runPowershell(script: string, timeoutMs: number): Promise<string> {
  return new Promise((resolve) => {
    execFile(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
      { windowsHide: false, timeout: timeoutMs },
      (err, stdout) => resolve(err ? `ERROR:${err.message}` : String(stdout).trim()),
    );
  });
}

/** Whether Windows Hello can be used right now (no prompt is shown). */
export async function helloAvailable(): Promise<boolean> {
  if (process.platform !== "win32") return false;
  const out = await runPowershell(
    HELLO_PREAMBLE +
      "$op = [Windows.Security.Credentials.UI.UserConsentVerifier]::CheckAvailabilityAsync(); " +
      "$t = $asTask.MakeGenericMethod([Windows.Security.Credentials.UI.UserConsentVerifierAvailability]).Invoke($null, @($op)); " +
      "$null = $t.Wait(10000); [string]$t.Result",
    20_000,
  );
  return out.split(/\r?\n/).pop() === "Available";
}

/** Show the Windows Hello prompt with `message`; resolves ok only on "Verified". */
export async function verifyWithHello(message: string): Promise<PresenceResult> {
  if (process.platform !== "win32") return { ok: false, method: "hello", reason: "Windows Hello requires Windows" };
  // The message is passed through an environment variable, never interpolated into the script.
  const script =
    HELLO_PREAMBLE +
    "$msg = $env:SWITCHBOARD_PRESENCE_MESSAGE; " +
    "$op = [Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync($msg); " +
    "$t = $asTask.MakeGenericMethod([Windows.Security.Credentials.UI.UserConsentVerificationResult]).Invoke($null, @($op)); " +
    "$null = $t.Wait(120000); [string]$t.Result";
  const prev = process.env.SWITCHBOARD_PRESENCE_MESSAGE;
  process.env.SWITCHBOARD_PRESENCE_MESSAGE = message.slice(0, 200);
  try {
    const out = (await runPowershell(script, 130_000)).split(/\r?\n/).pop() ?? "";
    if (out === "Verified") return { ok: true, method: "hello" };
    return { ok: false, method: "hello", reason: out || "no result" };
  } finally {
    if (prev === undefined) delete process.env.SWITCHBOARD_PRESENCE_MESSAGE;
    else process.env.SWITCHBOARD_PRESENCE_MESSAGE = prev;
  }
}

/** Interactive challenge: the human must type `expected` at a real terminal. */
export async function verifyWithTty(prompt: string, expected: string): Promise<PresenceResult> {
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    return { ok: false, method: "tty", reason: "no interactive terminal" };
  }
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = await new Promise<string>((resolve) => rl.question(`${prompt} `, resolve));
    return answer.trim().toUpperCase() === expected.toUpperCase()
      ? { ok: true, method: "tty" }
      : { ok: false, method: "tty", reason: "challenge answer did not match" };
  } finally {
    rl.close();
  }
}

/**
 * Verify owner presence with the requested method. `auto` uses Hello when available, else the TTY
 * challenge. `none` is refused unless SWITCHBOARD_INSECURE_APPROVAL=1 (test harnesses only).
 */
export async function verifyOwnerPresence(
  method: PresenceMethod | "auto",
  message: string,
  ttyChallenge: string,
): Promise<PresenceResult> {
  if (method === "none") {
    return process.env.SWITCHBOARD_INSECURE_APPROVAL === "1"
      ? { ok: true, method: "none" }
      : { ok: false, method: "none", reason: "presence 'none' requires SWITCHBOARD_INSECURE_APPROVAL=1" };
  }
  if (method === "hello" || (method === "auto" && (await helloAvailable()))) {
    return verifyWithHello(message);
  }
  return verifyWithTty(`${message}\nType ${ttyChallenge} to confirm:`, ttyChallenge);
}
