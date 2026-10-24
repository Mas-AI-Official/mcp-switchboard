/**
 * Kill switch (design vNext 3.8 and 3.15).
 *
 * One operator action that stops all governed traffic at once: while it is on, every `tools/call`,
 * `resources/read` and `prompts/get` is refused with `SB_KILL_SWITCH`. Two independent triggers, either
 * one is enough:
 *   - the file `<SWITCHBOARD_HOME>/KILL` (`switchboard kill on`), checked on EVERY call, so the CLI
 *     in one process stops a gateway running in another with no restart and no IPC;
 *   - `gateway.kill_switch: true` in the config (read from the live config object on every call).
 *
 * The file is the signal, its content is only a note: a bare `touch KILL` by hand trips it too. The check
 * fails CLOSED: if the file cannot be inspected for any reason other than "it does not exist", the
 * switch is treated as on.
 *
 * THE LATCH. A file is state any process of the same OS user can delete, and turning the switch OFF
 * re-opens every tool, so the file alone cannot be the emergency stop: an agent with a shell would undo it
 * with `rm`. The first time THIS process sees the switch on (the file is there, or `setKillFile(true)` ran
 * here) it latches it in memory, and from then on the switch is on whatever the file says. The ONLY way
 * back is `setKillFile(false)`, which the gateway calls after its own owner-presence check (the dashboard
 * toggle and `POST /api/control/kill/off`). A file that vanishes while the switch is latched is treated as
 * tampering: calls stay refused, one `kill.tamper` audit row and one error log line say so.
 *
 * What the latch does not do: it lives in the gateway's memory, so a restart of the gateway starts without
 * it (a file still on disk latches again at the first call). A process of the same OS user that can kill and
 * restart the gateway can therefore still clear a switch whose file it already removed. That needs the
 * gateway out of reach, which no file-based design gives (see the design document, 3.15).
 */

import { readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { audit } from "./audit.js";
import { ensureDir } from "./atomicfile.js";
import { log } from "./logger.js";
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
  /** This process is holding the switch on in memory (it saw the file, or turned it on). */
  latched: boolean;
  /** Latched while the KILL file is gone: it was removed by something other than the presence-checked off route. */
  tampered: boolean;
  /** Which trigger(s) hold it on; null when off. */
  source: "file" | "config" | "file+config" | "latch" | "latch+config" | null;
  /** ISO timestamp recorded by `switchboard kill on` (or taken when the latch engaged); absent when unknown. */
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

/** The `since` note a `kill on` left in the file, if it is readable JSON. */
function fileSince(home: string): string | undefined {
  try {
    const note = JSON.parse(readFileSync(killFilePath(home), "utf8")) as { since?: unknown };
    return typeof note.since === "string" ? note.since : undefined;
  } catch {
    return undefined; // a hand-made empty or non-JSON file is still a valid switch
  }
}

// ── the latch: process memory, keyed by home directory ──────────────────────────────────────────

interface Latch {
  since: string;
  /** The vanished file has been reported for this latch (reset when the file comes back). */
  tamperReported: boolean;
}
const latches = new Map<string, Latch>();

function latchOn(home: string, since?: string): Latch {
  let l = latches.get(home);
  if (!l) {
    l = { since: since ?? new Date().toISOString(), tamperReported: false };
    latches.set(home, l);
  }
  return l;
}

function noteRow(tool: string, decision: "allow" | "deny", reason: string): void {
  try {
    audit({ server: "switchboard", tool, scope: "full", decision, reason, principal: "file:KILL" });
  } catch (err) {
    log.error(`audit write failed for ${tool}: ${err instanceof Error ? err.message : String(err)}`);
  }
}

interface Observation {
  file: boolean;
  latched: boolean;
  tampered: boolean;
  since?: string;
}

/** Look at the file, latch on first sight, report a vanished file once. Never throws. */
function observe(home: string): Observation {
  const file = killFileExists(home);
  let l = latches.get(home);
  if (file) {
    if (!l) {
      l = latchOn(home, fileSince(home));
      noteRow(
        "kill.latched",
        "allow",
        "the KILL file appeared (it was not turned on through this gateway): the switch is latched in this gateway and stays on until the presence-checked off route clears it, whatever happens to the file",
      );
    } else {
      l.tamperReported = false; // the file is back: a second disappearance is a new event
    }
    return { file: true, latched: true, tampered: false, since: l.since };
  }
  if (l) {
    if (!l.tamperReported) {
      l.tamperReported = true;
      log.error(`the KILL file ${killFilePath(home)} vanished while the kill switch was on: calls stay refused until the owner clears it through the gateway (dashboard toggle or \`switchboard kill off\`, both check presence)`);
      noteRow(
        "kill.tamper",
        "deny",
        "the KILL file vanished while the kill switch was latched on, and not through the presence-checked off route: the switch stays on and every call is still refused",
      );
    }
    return { file: false, latched: true, tampered: true, since: l.since };
  }
  return { file: false, latched: false, tampered: false };
}

/** Cheap per-call check: is the kill switch on right now? Latches on first sight of the file. */
export function isKilled(cfg?: KillConfigLike, home: string = HOME_DIR): boolean {
  const seen = observe(home);
  return cfg?.gateway?.kill_switch === true || seen.latched;
}

/**
 * Full status for the CLI, the health endpoints and the dashboard. Never throws. With `passive` the call only
 * looks at the file and the config (no latching, no audit row): that is what a CLI process, which is not the
 * gateway, should use.
 */
export function killStatus(cfg?: KillConfigLike, home: string = HOME_DIR, opts: { passive?: boolean } = {}): KillStatus {
  const config = cfg?.gateway?.kill_switch === true;
  const seen: Observation = opts.passive ? { file: killFileExists(home), latched: false, tampered: false } : observe(home);
  const file = seen.file;
  const since = file ? (fileSince(home) ?? seen.since) : seen.since;
  const held = file || seen.latched;
  const source: KillStatus["source"] = file && config ? "file+config" : file ? "file" : seen.latched && config ? "latch+config" : seen.latched ? "latch" : config ? "config" : null;
  return {
    active: held || config,
    file,
    config,
    latched: seen.latched,
    tampered: seen.tampered,
    source,
    ...(since ? { since } : {}),
  };
}

/**
 * Turn the switch on (write the KILL file atomically: temp file then rename, and latch it in this process at once,
 * so a delete right after cannot beat the gateway to it) or off. Off removes the file AND drops the latch: it is
 * the owner-authorised clear, so a gateway calls it only after its own presence check. Returns whether the file
 * state changed and whether a latch was dropped. Turning it off does not touch `gateway.kill_switch`; the CLI
 * reports when that still holds the switch on.
 */
export function setKillFile(on: boolean, home: string = HOME_DIR): { changed: boolean; unlatched: boolean } {
  const path = killFilePath(home);
  const before = killFileExists(home);
  if (on) {
    latchOn(home);
    if (before) return { changed: false, unlatched: false }; // already on: keep the original `since` note
    ensureDir(home);
    const tmp = `${path}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify({ since: new Date().toISOString(), by: "switchboard kill on" }) + "\n");
    renameSync(tmp, path);
    return { changed: true, unlatched: false };
  }
  rmSync(path, { force: true });
  const unlatched = latches.delete(home);
  return { changed: before, unlatched };
}
