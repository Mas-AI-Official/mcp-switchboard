/**
 * Client key store: the bearer token a registered client uses against the HTTP gateway, kept in
 * `<SWITCHBOARD_HOME>/clients/<clientId>.key` and wrapped for the current OS user (DPAPI on Windows,
 * file mode 0600 inside a 0700 directory elsewhere, see oscrypt.ts). The bridge (bridge.ts) reads it,
 * so no token has to be written into any MCP client's own config file.
 *
 * The token is never logged and never put in an error message.
 */

import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { protectForUser, unprotectForUser } from "./oscrypt.js";
import { HOME_DIR } from "./vault.js";

/** The documented client id shape (design 3.1). */
export const CLIENT_ID_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
/** Windows treats these as devices whatever the extension (`nul.key` would silently swallow the key). */
const RESERVED_DEVICE_RE = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/;
/** A bearer token: printable ASCII with no whitespace, so it is always a valid header value. */
const TOKEN_RE = /^[\x21-\x7e]{1,4096}$/;

const BAD_ID = "invalid client id: use 1 to 64 characters from a-z, 0-9, '-' and '_', starting with a letter or digit";

export function isValidClientId(id: unknown): id is string {
  return typeof id === "string" && CLIENT_ID_RE.test(id) && !RESERVED_DEVICE_RE.test(id);
}

/** Where a client's key lives. Throws for an invalid id, so a path can never escape the directory. */
export function clientKeyPath(clientId: string): string {
  if (!isValidClientId(clientId)) throw new Error(BAD_ID);
  return join(HOME_DIR, "clients", `${clientId}.key`);
}

/**
 * Store a client's token, replacing any previous one. Atomic: the protected blob is written to a
 * temp file in the same directory, flushed, then renamed over the final name, so a crash leaves
 * either the old key or the new one, never a torn file. Returns the file path.
 */
export function writeClientKey(clientId: string, token: string): string {
  const file = clientKeyPath(clientId);
  if (typeof token !== "string" || !TOKEN_RE.test(token)) {
    throw new Error("invalid token: expected 1 to 4096 printable ASCII characters without whitespace");
  }
  let blob: Buffer;
  try {
    blob = protectForUser(Buffer.from(token, "utf8"));
  } catch {
    // The OS error can carry a command line; say only what failed.
    throw new Error("cannot protect the client key for this OS user");
  }
  const dir = join(HOME_DIR, "clients");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = join(dir, `.${clientId}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`);
  let fd: number | undefined;
  try {
    fd = openSync(tmp, "wx", 0o600);
    writeSync(fd, blob);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(tmp, file);
  } catch (err) {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
        /* already closed */
      }
    }
    try {
      unlinkSync(tmp);
    } catch {
      /* never created, or already renamed */
    }
    throw err;
  }
  return file;
}

/** The stored token, or null when the client has no key file. Throws if the file is unreadable or foreign. */
export function readClientKey(clientId: string): string | null {
  const file = clientKeyPath(clientId);
  let blob: Buffer;
  try {
    blob = readFileSync(file);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw new Error(`cannot read the key file for client '${clientId}'`);
  }
  let token: string;
  try {
    token = unprotectForUser(blob).toString("utf8").trim();
  } catch {
    throw new Error(`the key file for client '${clientId}' cannot be unwrapped for this OS user; re-register the client`);
  }
  if (!TOKEN_RE.test(token)) throw new Error(`the key file for client '${clientId}' does not hold a valid token; re-register the client`);
  return token;
}
