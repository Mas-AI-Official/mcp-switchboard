/**
 * API key store — named bearer tokens that authenticate the HTTP `/mcp` endpoint.
 *
 * Tokens are stored ONE-WAY HASHED (SHA-256) in `~/.switchboard/apikeys.json`, never
 * in plaintext and never in the config file. The plaintext is shown exactly once at
 * issuance; thereafter only a short prefix is kept, for display. Verification hashes
 * the presented token and compares in constant time, so a leaked `apikeys.json` does
 * not yield a usable credential.
 *
 * Deliberately separate from the vault (`vault.ts`): vault secrets are REVERSIBLE —
 * decrypted to inject into upstream servers — whereas API keys are one-way and must
 * never be decryptable. Mixing the two would be a category error.
 */

import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { join } from "node:path";
import { HOME_DIR } from "./vault.js";

const APIKEYS_PATH = join(HOME_DIR, "apikeys.json");

/** Stored on disk. The `hash` is never returned to a caller or surfaced to the UI. */
interface ApiKeyRecord {
  /** Short random id used to revoke the key. */
  id: string;
  /** Human label, e.g. "chatgpt", "claude-desktop". */
  name: string;
  /** SHA-256 hex of the full token. */
  hash: string;
  /** First chars of the token (e.g. `sb_AbCd1234`), for display only. */
  prefix: string;
  /** ISO timestamp of issuance. */
  created: string;
  /** ISO timestamp of the last successful verify. */
  last_used?: string;
}

/** A key as exposed to the CLI/dashboard — never includes the hash. */
export interface PublicApiKey {
  id: string;
  name: string;
  prefix: string;
  created: string;
  last_used?: string;
}

interface ApiKeyFile {
  keys: ApiKeyRecord[];
}

function sha256(s: string): string {
  return createHash("sha256").update(s, "utf8").digest("hex");
}

function redact(k: ApiKeyRecord): PublicApiKey {
  return { id: k.id, name: k.name, prefix: k.prefix, created: k.created, last_used: k.last_used };
}

function ensureHome(): void {
  if (!existsSync(HOME_DIR)) mkdirSync(HOME_DIR, { recursive: true });
}

function readApiKeys(): ApiKeyFile {
  if (!existsSync(APIKEYS_PATH)) return { keys: [] };
  try {
    const parsed = JSON.parse(readFileSync(APIKEYS_PATH, "utf8")) as Partial<ApiKeyFile>;
    return { keys: Array.isArray(parsed.keys) ? parsed.keys : [] };
  } catch {
    return { keys: [] };
  }
}

function writeApiKeys(file: ApiKeyFile): void {
  ensureHome();
  writeFileSync(APIKEYS_PATH, JSON.stringify(file, null, 2));
  // chmod is a no-op on Windows; best-effort restrict elsewhere.
  try {
    chmodSync(APIKEYS_PATH, 0o600);
  } catch {
    /* best-effort */
  }
}

export class ApiKeyStore {
  private file: ApiKeyFile;

  constructor() {
    this.file = readApiKeys();
  }

  /** How many keys exist. */
  get count(): number {
    return this.file.keys.length;
  }

  /**
   * Issue a new named key. Returns the plaintext token ONCE — it is hashed on disk and
   * never recoverable afterward. Token format: `sb_<43 url-safe base64 chars>` (32 bytes).
   */
  issue(name: string): { token: string; record: PublicApiKey } {
    const token = `sb_${randomBytes(32).toString("base64url")}`;
    const rec: ApiKeyRecord = {
      id: randomBytes(6).toString("hex"),
      name: name.trim() || "unnamed",
      hash: sha256(token),
      prefix: token.slice(0, 11),
      created: new Date().toISOString(),
    };
    this.file.keys.push(rec);
    writeApiKeys(this.file);
    return { token, record: redact(rec) };
  }

  /** All keys, redacted (never the hash). */
  list(): PublicApiKey[] {
    return this.file.keys.map(redact);
  }

  /** Remove a key by id. Returns true if a key was removed. */
  revoke(id: string): boolean {
    const before = this.file.keys.length;
    this.file.keys = this.file.keys.filter((k) => k.id !== id);
    const removed = this.file.keys.length < before;
    if (removed) writeApiKeys(this.file);
    return removed;
  }

  /**
   * True if the presented token matches any stored key. Constant-time across the whole
   * key set (no early break) and refreshes `last_used` on a hit. Returns false for an
   * empty/missing token, fail-closed.
   */
  verify(presented: string): boolean {
    if (!presented) return false;
    const presentedBuf = Buffer.from(sha256(presented), "hex");
    let matched: ApiKeyRecord | undefined;
    for (const k of this.file.keys) {
      const storedBuf = Buffer.from(k.hash, "hex");
      // Lengths are always equal (SHA-256 → 32 bytes); the guard is defensive.
      if (storedBuf.length === presentedBuf.length && timingSafeEqual(storedBuf, presentedBuf)) {
        matched = k; // keep scanning to hold timing uniform
      }
    }
    if (!matched) return false;
    matched.last_used = new Date().toISOString();
    writeApiKeys(this.file);
    return true;
  }
}
