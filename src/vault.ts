/**
 * Local credential vault.
 *
 * Backend: AES-256-GCM encrypted JSON in `~/.switchboard/vault.json`. The 32-byte key lives beside
 * it, protected for the OS user: on Windows as `vault.key.dpapi` (DPAPI, CurrentUser scope, see
 * oscrypt.ts; a raw `vault.key` from an older install is wrapped, verified and removed), elsewhere as
 * `vault.key` with mode 0600 inside a 0700 home. The unwrapped key is cached for the process lifetime,
 * so DPAPI is called once. Writes are atomic (atomicfile.ts) and the store re-reads when the file
 * changes, so `switchboard vault set` reaches a running gateway. Zero native dependencies on purpose:
 * `npm install` must not need build tools.
 *
 * The vault never makes a network call. Secrets are injected into upstream MCP server
 * processes as environment variables at mount time and never travel anywhere else.
 * `${vault:name}` / `${env:NAME}` references in the config are resolved here.
 *
 * OS keychain (Windows Credential Manager / macOS Keychain / libsecret) is on the
 * roadmap as an alternate backend; the encrypted file is the portable default.
 */

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { existsSync, readFileSync, unlinkSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { WatchedJsonFile, atomicWriteFileSync, ensureDir, withFileLock } from "./atomicfile.js";
import { isOsProtected, protectForUser, unprotectForUser } from "./oscrypt.js";

/** MCP Switchboard's home dir. Override with SWITCHBOARD_HOME (used in tests). */
export const HOME_DIR = process.env.SWITCHBOARD_HOME ?? join(homedir(), ".switchboard");

const REF_RE = /\$\{(vault|env):([^}]+)\}/g;

/** An AES-256-GCM sealed value: base64-encoded IV + auth tag + ciphertext. */
export interface SealedSecret {
  iv: string;
  tag: string;
  data: string;
}
type VaultFile = Record<string, SealedSecret>;

/** Seal a plaintext string under a 32-byte key (AES-256-GCM, a fresh IV per call). */
export function seal(key: Buffer, plaintext: string): SealedSecret {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return {
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    data: enc.toString("base64"),
  };
}

/** Reverse `seal`. Throws if the key is wrong or the ciphertext was tampered with. */
export function unseal(key: Buffer, sealed: SealedSecret): string {
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(sealed.iv, "base64"));
  decipher.setAuthTag(Buffer.from(sealed.tag, "base64"));
  const dec = Buffer.concat([decipher.update(Buffer.from(sealed.data, "base64")), decipher.final()]);
  return dec.toString("utf8");
}

const KEY_BYTES = 32;

/** Unwrapped vault keys by home directory, for the process lifetime (DPAPI runs once per home). */
const keyCache = new Map<string, Buffer>();

function readRawKey(path: string): Buffer {
  const key = readFileSync(path);
  if (key.length !== KEY_BYTES) {
    throw new Error(`vault key file ${path} is ${key.length} bytes, expected ${KEY_BYTES}: refusing to guess; restore it from a backup`);
  }
  return key;
}

/** Wrap `key` for the OS user, write it atomically, and read it back: the raw key is only ever
 *  discarded after the wrapped copy is proven to unwrap to the same bytes. */
function writeWrappedKey(path: string, key: Buffer): void {
  atomicWriteFileSync(path, protectForUser(key), { mode: 0o600 });
  let back: Buffer;
  try {
    back = unprotectForUser(readFileSync(path));
  } catch (err) {
    try {
      unlinkSync(path);
    } catch {
      /* leave nothing half-trusted behind */
    }
    throw new Error(`could not verify the DPAPI-wrapped vault key (${err instanceof Error ? err.message : String(err)}); the existing key file was left untouched`);
  }
  if (!back.equals(key)) {
    try {
      unlinkSync(path);
    } catch {
      /* see above */
    }
    throw new Error("the DPAPI-wrapped vault key did not round-trip; the existing key file was left untouched");
  }
}

/** Remove the raw key once the wrapped copy is proven; another process may have got there first. */
function removeRawKey(path: string): void {
  try {
    unlinkSync(path);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
}

/** Windows: `vault.key.dpapi`. Creates, migrates a raw `vault.key`, or unwraps; never silently makes a
 *  new key when one exists (that would orphan every sealed secret). Serialised across processes: the
 *  gateway and a CLI command starting together must not both mint or migrate (DPAPI can take seconds). */
function loadWindowsKey(home: string): Buffer {
  return withFileLock(join(home, "vault.key.dpapi"), () => loadWindowsKeyLocked(home), { timeoutMs: 60_000, staleMs: 120_000 });
}

function loadWindowsKeyLocked(home: string): Buffer {
  const rawPath = join(home, "vault.key");
  const wrappedPath = join(home, "vault.key.dpapi");
  const hasRaw = existsSync(rawPath);
  if (existsSync(wrappedPath)) {
    let key: Buffer;
    try {
      key = unprotectForUser(readFileSync(wrappedPath));
    } catch (err) {
      throw new Error(
        `cannot unwrap ${wrappedPath} (${err instanceof Error ? err.message : String(err)}). It is protected for the Windows user that created it; ` +
          "a different user, a different machine or a damaged file cannot open it. No new key was created, so the vault is untouched.",
      );
    }
    if (hasRaw) {
      // An interrupted migration (wrapped copy written, raw not yet deleted) or a stray copy.
      if (!readRawKey(rawPath).equals(key)) {
        throw new Error(`both ${wrappedPath} and ${rawPath} exist and hold different keys: decide which one sealed the vault and remove the other`);
      }
      removeRawKey(rawPath);
    }
    return key;
  }
  if (hasRaw) {
    const key = readRawKey(rawPath);
    writeWrappedKey(wrappedPath, key);
    removeRawKey(rawPath);
    return key;
  }
  const key = randomBytes(32);
  writeWrappedKey(wrappedPath, key);
  return key;
}

/** Elsewhere: a raw `vault.key` (mode 0600) in the 0700 home. */
function loadPortableKey(home: string): Buffer {
  const rawPath = join(home, "vault.key");
  if (existsSync(rawPath)) return readRawKey(rawPath);
  const key = randomBytes(32);
  atomicWriteFileSync(rawPath, key, { mode: 0o600 });
  return key;
}

/**
 * Load the vault key, creating it on first use. Exported because the OAuth token store
 * (`src/oauth.ts`) and the OAuth Authorization Server seal their state with the same key.
 * Cached per home directory for the process lifetime.
 */
export function loadVaultKey(home: string = HOME_DIR): Buffer {
  const cached = keyCache.get(home);
  if (cached) return Buffer.from(cached);
  ensureDir(home);
  const key = isOsProtected() ? loadWindowsKey(home) : loadPortableKey(home);
  keyCache.set(home, key);
  return Buffer.from(key);
}

function vaultShape(value: unknown): string | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return "expected a JSON object of sealed secrets";
  for (const [name, v] of Object.entries(value as Record<string, unknown>)) {
    const s = v as Partial<SealedSecret> | null;
    if (!s || typeof s.iv !== "string" || typeof s.tag !== "string" || typeof s.data !== "string") {
      return `entry '${name}' is not a sealed secret`;
    }
  }
  return null;
}

export interface VaultOptions {
  /** Home directory holding vault.json and the key. Default: the process-wide HOME_DIR. */
  home?: string;
}

export class Vault {
  private readonly key: Buffer;
  private readonly file: WatchedJsonFile<VaultFile> | null;

  constructor(
    private readonly backend: "encrypted-file" | "env" = "encrypted-file",
    opts: VaultOptions = {},
  ) {
    const home = opts.home ?? HOME_DIR;
    this.key = backend === "encrypted-file" ? loadVaultKey(home) : Buffer.alloc(0);
    this.file =
      backend === "encrypted-file"
        ? new WatchedJsonFile<VaultFile>(join(home, "vault.json"), () => ({}), { validate: vaultShape, mode: 0o600 })
        : null;
  }

  /** Store (or replace) a secret. Merges into the current file, so a gateway never overwrites a newer vault. */
  set(name: string, secret: string): void {
    if (!this.file) {
      throw new Error(`vault backend '${this.backend}' is read-only; secrets come from the environment`);
    }
    const sealed = seal(this.key, secret);
    this.file.update((cur) => ({ ...cur, [name]: sealed }));
  }

  /** Decrypt and return a secret, or undefined if absent. */
  get(name: string): string | undefined {
    const sealed = this.file?.get()[name];
    if (!sealed) return undefined;
    return unseal(this.key, sealed);
  }

  remove(name: string): void {
    this.file?.update((cur) => {
      if (!(name in cur)) return undefined;
      const rest = { ...cur };
      delete rest[name];
      return rest;
    });
  }

  /** Secret names (never values). */
  list(): string[] {
    return Object.keys(this.file?.get() ?? {});
  }

  /**
   * Resolve `${vault:name}` and `${env:NAME}` references inside a config value.
   * Throws (fail-closed) if a referenced secret/env var is missing — we never
   * silently forward a blank credential to an upstream server.
   */
  resolve(value: string): string {
    return value.replace(REF_RE, (_match, kind: string, ref: string) => {
      if (kind === "vault") {
        const secret = this.get(ref);
        if (secret === undefined) {
          throw new Error(`vault secret '${ref}' not set — run \`switchboard vault set ${ref}\``);
        }
        return secret;
      }
      const envVal = process.env[ref];
      if (envVal === undefined) throw new Error(`env var '${ref}' is not set`);
      return envVal;
    });
  }
}
