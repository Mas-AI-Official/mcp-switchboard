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

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { join } from "node:path";
import { WatchedJsonFile } from "./atomicfile.js";
import { log } from "./logger.js";
import { HOME_DIR } from "./vault.js";

/** `last_used` is display-only: it is persisted at most this often per key, so a busy gateway does
 *  not fsync on every request. Pass 0 to persist every verify (the oracle does). */
const LAST_USED_WRITE_INTERVAL_MS = 30_000;

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

/** The file must be an object; a missing `keys` list is tolerated (an older or hand-made file), a wrong type is not. */
function apiKeysShape(value: unknown): string | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return "expected a JSON object with a keys list";
  const keys = (value as { keys?: unknown }).keys;
  if (keys !== undefined && !Array.isArray(keys)) return "'keys' is not a list";
  for (const k of (keys as unknown[] | undefined) ?? []) {
    const r = k as Partial<ApiKeyRecord> | null;
    if (!r || typeof r.id !== "string" || typeof r.hash !== "string") return "a key record has no id or hash";
  }
  return null;
}

export interface ApiKeyStoreOptions {
  /** Home directory holding apikeys.json. Default: the process-wide HOME_DIR. */
  home?: string;
  /** Minimum ms between persisted `last_used` updates per key. Default 30000; 0 = every verify. */
  lastUsedIntervalMs?: number;
}

export class ApiKeyStore {
  private readonly store: WatchedJsonFile<ApiKeyFile>;
  private readonly lastUsedIntervalMs: number;
  private readonly lastWrite = new Map<string, number>();

  /** Throws `StoreCorruptError` when apikeys.json exists but is unusable: an empty store would silently
   *  drop every revocation and, on loopback, switch authentication off. */
  constructor(opts: ApiKeyStoreOptions = {}) {
    this.store = new WatchedJsonFile<ApiKeyFile>(join(opts.home ?? HOME_DIR, "apikeys.json"), () => ({ keys: [] }), {
      validate: apiKeysShape,
      mode: 0o600,
    });
    this.lastUsedIntervalMs = opts.lastUsedIntervalMs ?? LAST_USED_WRITE_INTERVAL_MS;
  }

  private keys(): ApiKeyRecord[] {
    const f = this.store.get();
    return Array.isArray(f.keys) ? f.keys : [];
  }

  /** How many keys exist (re-read when the file changed, so a CLI `apikey new` is seen at once). */
  get count(): number {
    return this.keys().length;
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
    this.store.update((cur) => ({ ...cur, keys: [...(Array.isArray(cur.keys) ? cur.keys : []), rec] }));
    return { token, record: redact(rec) };
  }

  /** All keys, redacted (never the hash). */
  list(): PublicApiKey[] {
    return this.keys().map(redact);
  }

  /** Remove a key by id, in the file as it is now (so a running gateway's revoke and a CLI revoke compose). */
  revoke(id: string): boolean {
    let removed = false;
    this.store.update((cur) => {
      const keys = Array.isArray(cur.keys) ? cur.keys : [];
      const next = keys.filter((k) => k.id !== id);
      removed = next.length < keys.length;
      return removed ? { ...cur, keys: next } : undefined;
    });
    return removed;
  }

  /**
   * True if the presented token matches a stored key in the file AS IT IS NOW. Constant-time across the
   * whole key set (no early break). On a hit `last_used` is merged into the current file under the
   * lock (throttled), never written back from stale memory: a key revoked by another process is not
   * resurrected, and a revocation that lands between the check and the write turns this verify false.
   * Fail-closed: an empty token, or a store file that became unusable, is false.
   */
  verify(presented: string): boolean {
    if (!presented) return false;
    let keys: ApiKeyRecord[];
    try {
      keys = this.keys();
    } catch (err) {
      log.error(`API key store unusable, refusing every key: ${err instanceof Error ? err.message : String(err)}`);
      return false;
    }
    const presentedBuf = Buffer.from(sha256(presented), "hex");
    let matched: ApiKeyRecord | undefined;
    for (const k of keys) {
      const storedBuf = Buffer.from(k.hash, "hex");
      // Lengths are always equal (SHA-256 → 32 bytes); the guard is defensive.
      if (storedBuf.length === presentedBuf.length && timingSafeEqual(storedBuf, presentedBuf)) {
        matched = k; // keep scanning to hold timing uniform
      }
    }
    if (!matched) return false;
    return this.touch(matched);
  }

  /** Persist `last_used` for a verified key. Returns false when the key is gone from the current file. */
  private touch(matched: ApiKeyRecord): boolean {
    const now = Date.now();
    const last = this.lastWrite.get(matched.id);
    if (last !== undefined && now - last < this.lastUsedIntervalMs) return true;
    let stillThere = true;
    try {
      this.store.update((cur) => {
        const rec = (Array.isArray(cur.keys) ? cur.keys : []).find((k) => k.id === matched.id && k.hash === matched.hash);
        stillThere = rec !== undefined;
        if (!rec) return undefined; // revoked since we checked: write nothing
        return { ...cur, keys: cur.keys.map((k) => (k === rec ? { ...k, last_used: new Date(now).toISOString() } : k)) };
      });
    } catch (err) {
      // The token is valid; a disk problem on a display-only field must not lock the client out.
      log.warn(`could not persist last_used for API key ${matched.id}: ${err instanceof Error ? err.message : String(err)}`);
      return true;
    }
    if (stillThere) this.lastWrite.set(matched.id, now);
    return stillThere;
  }
}
