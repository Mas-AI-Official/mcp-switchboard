/**
 * Kill switch (design vNext 3.8).
 *
 * One operator action that stops all governed traffic at once: while it is on, every `tools/call`,
 * `resources/read` and `prompts/get` is refused with `SB_KILL_SWITCH`. Two independent triggers, either
 * one is enough:
 *   - the file `<SWITCHBOARD_HOME>/KILL` (`switchboard kill on|off`), checked on EVERY call, so the CLI
 *     in one process stops a gateway running in another with no restart and no IPC;
 *   - `gateway.kill_switch: true` in the config (read from the live config object on every call).
 *
 * The file is the signal, its content is only a note: a bare `touch KILL` by hand trips it too. The check
 * fails CLOSED: if the file cannot be inspected for any reason other than "it does not exist", the
 * switch is treated as on.
 */

import { mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { HOME_DIR } from "./vault.js";

export const KILL_FILE_NAME = "KILL";

/** The slice of the config the switch reads. Structural so callers and tests can pass a bare object. */
export interface KillConfigLike {
  gateway?: { kill_switch?: boolean };
}

export interface KillStatus {
  active: boolean;
  /** The KILL file is present. */
  file: boolean;
  /** `gateway.kill_switch` is true in the config. */
  config: boolean;
  /** Which trigger(s) hold it on; null when off. */
  source: "file" | "config" | "file+config" | null;
  /** ISO timestamp recorded by `switchboard kill on`, when the file carries one. */
  since?: string;
}

export function killFilePath(home: string = HOME_DIR): string {
  return join(home, KILL_FILE_NAME);
}

/** Is the KILL file present? Any error other than not-found counts as present (fail closed). */
function killFileExists(home: string): boolean {
  try {
    statSync(killFilePath(home));
    return true;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    return code !== "ENOENT" && code !== "ENOTDIR";
  }
}

/** Cheap per-call check: is the kill switch on right now? */
export function isKilled(cfg?: KillConfigLike, home: string = HOME_DIR): boolean {
  return cfg?.gateway?.kill_switch === true || killFileExists(home);
}

/** Full status for the CLI, the health endpoints and the dashboard. Never throws. */
export function killStatus(cfg?: KillConfigLike, home: string = HOME_DIR): KillStatus {
  const file = killFileExists(home);
  const config = cfg?.gateway?.kill_switch === true;
  let since: string | undefined;
  if (file) {
    try {
      const note = JSON.parse(readFileSync(killFilePath(home), "utf8")) as { since?: unknown };
      if (typeof note.since === "string") since = note.since;
    } catch {
      /* a hand-made empty or non-JSON file is still a valid switch */
    }
  }
  return {
    active: file || config,
    file,
    config,
    source: file && config ? "file+config" : file ? "file" : config ? "config" : null,
    ...(since ? { since } : {}),
  };
}

/**
 * Turn the KILL file on (atomic write: temp file then rename) or off. Returns whether the file state
 * changed. Turning it off does not touch `gateway.kill_switch`; the CLI reports when that still holds
 * the switch on.
 */
export function setKillFile(on: boolean, home: string = HOME_DIR): { changed: boolean } {
  const path = killFilePath(home);
  const before = killFileExists(home);
  if (on) {
    if (before) return { changed: false }; // already on: keep the original `since` note
    mkdirSync(home, { recursive: true });
    const tmp = `${path}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify({ since: new Date().toISOString(), by: "switchboard kill on" }) + "\n");
    renameSync(tmp, path);
  } else {
    rmSync(path, { force: true });
  }
  return { changed: before !== on };
}
