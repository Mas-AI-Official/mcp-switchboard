/**
 * The control token: how the `switchboard` CLI proves to a RUNNING gateway that it is the CLI on this machine
 * (design 3.3). The gateway mints a fresh token every time its HTTP listener starts and keeps it in memory;
 * it also writes it, wrapped for the current OS user (DPAPI on Windows, mode 0600 inside a 0700 directory
 * elsewhere, see oscrypt.ts), to `<SWITCHBOARD_HOME>/control.key`, where the CLI reads it.
 *
 * WHAT THIS IS NOT. It is a convenience, not the security boundary. Anything that runs as the same OS user can
 * read and unwrap the file, so it proves "a process of this user", which is exactly what an AI agent with a
 * shell is. The real gate is owner presence performed INSIDE the gateway (Windows Hello, or a challenge on the
 * gateway's own console) before any approval is signed. The token only keeps stray local callers (a script, a
 * web page that got past the Host check) from poking the control API at all.
 *
 * The token is never logged and never put in an error message.
 */

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { atomicWriteFileSync } from "./atomicfile.js";
import { protectForUser, unprotectForUser } from "./oscrypt.js";
import { HOME_DIR } from "./vault.js";

export const CONTROL_KEY_FILE = "control.key";

/** A control token: the prefix plus 43 base64url characters (32 random bytes). */
const TOKEN_RE = /^sbc_[A-Za-z0-9_-]{43}$/;

export function controlKeyPath(home: string = HOME_DIR): string {
  return join(home, CONTROL_KEY_FILE);
}

/** A fresh token. */
export function newControlToken(): string {
  return `sbc_${randomBytes(32).toString("base64url")}`;
}

/**
 * Store `token` for the current OS user, replacing any earlier one (atomic: temp file, fsync, rename).
 * Returns the file path. Throws, with no secret in the message, when the OS cannot protect it.
 */
export function writeControlKey(token: string, home: string = HOME_DIR): string {
  if (typeof token !== "string" || !TOKEN_RE.test(token)) throw new Error("invalid control token");
  let blob: Buffer;
  try {
    blob = protectForUser(Buffer.from(token, "utf8"));
  } catch {
    // The OS error can carry a command line; say only what failed.
    throw new Error("cannot protect the control key for this OS user");
  }
  const file = controlKeyPath(home);
  atomicWriteFileSync(file, blob, { mode: 0o600 });
  return file;
}

/** The stored token, or null when there is no control key file (no gateway has started here). */
export function readControlKey(home: string = HOME_DIR): string | null {
  const file = controlKeyPath(home);
  let blob: Buffer;
  try {
    blob = readFileSync(file);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new Error("cannot read the control key file");
  }
  let token: string;
  try {
    token = unprotectForUser(blob).toString("utf8").trim();
  } catch {
    throw new Error("the control key file cannot be unwrapped for this OS user; restart the gateway to mint a new one");
  }
  if (!TOKEN_RE.test(token)) throw new Error("the control key file does not hold a valid token; restart the gateway to mint a new one");
  return token;
}

const digest = (s: string): Buffer => createHash("sha256").update(s, "utf8").digest();

/** Constant-time check of a presented token against the live one. A non-string or malformed value is false. */
export function controlTokenMatches(presented: unknown, expected: string): boolean {
  if (typeof presented !== "string" || !TOKEN_RE.test(presented)) return false;
  return timingSafeEqual(digest(presented), digest(expected));
}

/** The bearer token of an `Authorization: Bearer <t>` header, or null. */
export function bearerOf(header: unknown): string | null {
  if (typeof header !== "string" || !header.startsWith("Bearer ")) return null;
  const t = header.slice(7).trim();
  return t === "" ? null : t;
}
