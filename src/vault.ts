/**
 * Local credential vault.
 *
 * Backend: AES-256-GCM encrypted JSON in `~/.switchboard/vault.json`, with the 32-byte
 * key in `~/.switchboard/vault.key` (file perms restricted where the OS allows it).
 * Zero native dependencies on purpose — `npm install` must not need build tools.
 *
 * The vault never makes a network call. Secrets are injected into upstream MCP server
 * processes as environment variables at mount time and never travel anywhere else.
 * `${vault:name}` / `${env:NAME}` references in the config are resolved here.
 *
 * OS keychain (Windows Credential Manager / macOS Keychain / libsecret) is on the
 * roadmap as an alternate backend; the encrypted file is the portable default.
 */

import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/** Switchboard's home dir. Override with SWITCHBOARD_HOME (used in tests). */
export const HOME_DIR = process.env.SWITCHBOARD_HOME ?? join(homedir(), ".switchboard");

const KEY_PATH = join(HOME_DIR, "vault.key");
const VAULT_PATH = join(HOME_DIR, "vault.json");

const REF_RE = /\$\{(vault|env):([^}]+)\}/g;

interface SealedSecret {
  iv: string;
  tag: string;
  data: string;
}
type VaultFile = Record<string, SealedSecret>;

function ensureHome(): void {
  if (!existsSync(HOME_DIR)) mkdirSync(HOME_DIR, { recursive: true });
}

function restrict(path: string): void {
  // chmod is a no-op on Windows; swallow any platform error.
  try {
    chmodSync(path, 0o600);
  } catch {
    /* best-effort */
  }
}

function loadOrCreateKey(): Buffer {
  ensureHome();
  if (existsSync(KEY_PATH)) return readFileSync(KEY_PATH);
  const key = randomBytes(32);
  writeFileSync(KEY_PATH, key);
  restrict(KEY_PATH);
  return key;
}

function readStore(): VaultFile {
  if (!existsSync(VAULT_PATH)) return {};
  try {
    return JSON.parse(readFileSync(VAULT_PATH, "utf8")) as VaultFile;
  } catch {
    return {};
  }
}

function writeStore(store: VaultFile): void {
  ensureHome();
  writeFileSync(VAULT_PATH, JSON.stringify(store, null, 2));
  restrict(VAULT_PATH);
}

export class Vault {
  private readonly key: Buffer;
  private store: VaultFile;

  constructor(private readonly backend: "encrypted-file" | "env" = "encrypted-file") {
    this.key = backend === "encrypted-file" ? loadOrCreateKey() : Buffer.alloc(0);
    this.store = backend === "encrypted-file" ? readStore() : {};
  }

  /** Store (or replace) a secret. */
  set(name: string, secret: string): void {
    if (this.backend !== "encrypted-file") {
      throw new Error(`vault backend '${this.backend}' is read-only; secrets come from the environment`);
    }
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    const enc = Buffer.concat([cipher.update(secret, "utf8"), cipher.final()]);
    this.store[name] = {
      iv: iv.toString("base64"),
      tag: cipher.getAuthTag().toString("base64"),
      data: enc.toString("base64"),
    };
    writeStore(this.store);
  }

  /** Decrypt and return a secret, or undefined if absent. */
  get(name: string): string | undefined {
    const sealed = this.store[name];
    if (!sealed) return undefined;
    const decipher = createDecipheriv("aes-256-gcm", this.key, Buffer.from(sealed.iv, "base64"));
    decipher.setAuthTag(Buffer.from(sealed.tag, "base64"));
    const dec = Buffer.concat([decipher.update(Buffer.from(sealed.data, "base64")), decipher.final()]);
    return dec.toString("utf8");
  }

  remove(name: string): void {
    delete this.store[name];
    writeStore(this.store);
  }

  /** Secret names (never values). */
  list(): string[] {
    return Object.keys(this.store);
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
