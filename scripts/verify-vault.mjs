/**
 * verify-vault.mjs — deterministic oracle for the local credential vault (Gap 12+14).
 *
 * The vault is the product's load-bearing trust claim: "encrypted local vault, zero custody."
 * If the AES-256-GCM path has a silent flaw, every other guarantee is theatre. So this oracle
 * pins the cryptographic invariants to the byte, with zero dependencies:
 *
 *   • ROUND-TRIP — unseal(key, seal(key, x)) === x across empty / unicode / multiline / long inputs.
 *   • FRESH IV PER CALL (the GCM killer) — sealing the same plaintext under the same key twice yields
 *     a different IV, a different tag, and different ciphertext; 100 seals give 100 distinct IVs.
 *     Nonce reuse under GCM leaks the keystream, so this is the single most important property.
 *   • AUTHENTICATED — a one-byte flip in iv, tag, OR ciphertext makes unseal THROW (never returns
 *     altered plaintext); truncating the ciphertext throws; a wrong 32-byte key throws at final()
 *     rather than leaking garbage.
 *   • SHAPE — 12-byte (96-bit) IV, 16-byte (128-bit) tag, AES-256 key-length enforced.
 *   • AT REST — the on-disk vault.json never contains the plaintext; secrets survive a fresh Vault
 *     instance (real on-disk decrypt), and the key file is stable across loads (restart-safe).
 *   • FAIL-CLOSED resolve() — ${vault:..}/${env:..} resolve, a missing ref THROWS (never a blank
 *     credential), and the read-only `env` backend rejects writes.
 *   • STATIC SCAN — dist/vault.js actually wires aes-256-gcm + a random 12-byte IV + get/setAuthTag.
 *
 * HOME_DIR is captured at module load, so SWITCHBOARD_HOME is set BEFORE the dynamic import.
 *
 * Run: node scripts/verify-vault.mjs   (exits non-zero on any FAIL)
 */

import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const checks = [];
function assert(name, cond, detail = "") {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? `  — ${detail}` : ""}`);
}
function throws(fn) {
  try {
    fn();
    return false;
  } catch {
    return true;
  }
}
/** Flip the first byte of a base64 blob (decode → XOR → re-encode). */
function corrupt(b64) {
  const buf = Buffer.from(b64, "base64");
  buf[0] ^= 0xff;
  return buf.toString("base64");
}

// HOME_DIR is read at module load — point it at a throwaway dir BEFORE importing.
const home = mkdtempSync(join(tmpdir(), "sb-vault-"));
process.env.SWITCHBOARD_HOME = home;
const { Vault, seal, unseal, loadVaultKey, HOME_DIR } = await import("../dist/vault.js");

assert("SWITCHBOARD_HOME override took effect (import ran after env was set)", HOME_DIR === home, HOME_DIR);

const crypto = await import("node:crypto");
const KEY = crypto.randomBytes(32);

// ── 1. round-trip across representative plaintexts ───────────────────────────────────────────
for (const [label, pt] of [
  ["empty", ""],
  ["ascii token", "sk-live-0123456789abcdef"],
  ["unicode", "café — 日本語 — 🔐"],
  ["multiline", "line1\nline2\tindented\r\nwin-eol"],
  ["long (10k)", "x".repeat(10_000)],
]) {
  const sealed = seal(KEY, pt);
  assert(`round-trip: ${label}`, unseal(KEY, sealed) === pt);
}

// ── 2. fresh IV per call — the GCM non-negotiable ────────────────────────────────────────────
{
  const a = seal(KEY, "identical-plaintext");
  const b = seal(KEY, "identical-plaintext");
  assert("same plaintext → different IV (no nonce reuse)", a.iv !== b.iv);
  assert("same plaintext → different ciphertext", a.data !== b.data);
  assert("same plaintext → different auth tag", a.tag !== b.tag);
  const ivs = new Set();
  for (let i = 0; i < 100; i++) ivs.add(seal(KEY, "x").iv);
  assert("100 seals → 100 distinct IVs (randomBytes is live)", ivs.size === 100, `distinct=${ivs.size}`);
}

// ── 3. sealed-value shape: 96-bit IV, 128-bit tag, AES-256 key length ────────────────────────
{
  const s = seal(KEY, "shape-check");
  assert("IV is 12 bytes (96-bit GCM nonce)", Buffer.from(s.iv, "base64").length === 12);
  assert("auth tag is 16 bytes (128-bit)", Buffer.from(s.tag, "base64").length === 16);
  assert("32-byte key seals fine (AES-256)", typeof seal(Buffer.alloc(32), "ok").data === "string");
  assert("16-byte key is rejected (not AES-256)", throws(() => seal(Buffer.alloc(16), "x")));
}

// ── 4. authenticated: any tamper throws, never returns altered plaintext ─────────────────────
{
  const s = seal(KEY, "super-secret-token-value");
  assert("flip a ciphertext byte → unseal throws", throws(() => unseal(KEY, { ...s, data: corrupt(s.data) })));
  assert("flip an auth-tag byte → unseal throws", throws(() => unseal(KEY, { ...s, tag: corrupt(s.tag) })));
  assert("flip an IV byte → unseal throws", throws(() => unseal(KEY, { ...s, iv: corrupt(s.iv) })));
  const truncated = Buffer.from(s.data, "base64").subarray(0, -1).toString("base64");
  assert("truncated ciphertext → unseal throws", throws(() => unseal(KEY, { ...s, data: truncated })));
  const wrongKey = crypto.randomBytes(32);
  assert("wrong 32-byte key → unseal throws (auth fail, no garbage leak)", throws(() => unseal(wrongKey, s)));
}

// ── 5. Vault class: at-rest encryption + persistence ─────────────────────────────────────────
{
  const v = new Vault(); // encrypted-file (default)
  const SECRET = "plaintext-secret-do-not-leak-9f3a";
  v.set("API_TOKEN", SECRET);

  assert("get() returns what set() stored", v.get("API_TOKEN") === SECRET);
  assert("get() of an absent name → undefined", v.get("NOPE") === undefined);
  assert("list() returns names, not values", v.list().includes("API_TOKEN") && !v.list().some((n) => n.includes(SECRET)));

  const raw = readFileSync(join(home, "vault.json"), "utf8");
  assert("on-disk vault.json does NOT contain the plaintext", !raw.includes(SECRET));
  assert("on-disk vault.json keeps the name (keys aren't secret)", raw.includes("API_TOKEN"));
  const parsed = JSON.parse(raw);
  assert("on-disk entry is a sealed {iv,tag,data} triple", ["iv", "tag", "data"].every((k) => typeof parsed.API_TOKEN[k] === "string"));

  const fresh = new Vault(); // re-reads the store from disk → real on-disk decrypt
  assert("a fresh Vault instance decrypts the persisted secret", fresh.get("API_TOKEN") === SECRET);

  fresh.remove("API_TOKEN");
  assert("remove() deletes the secret", new Vault().get("API_TOKEN") === undefined);
}

// ── 6. key file is stable across loads (restart-safe) ────────────────────────────────────────
{
  const k1 = loadVaultKey();
  const k2 = loadVaultKey();
  assert("loadVaultKey() returns a 32-byte key", k1.length === 32);
  assert("loadVaultKey() is stable across calls (not regenerated)", Buffer.compare(k1, k2) === 0);
}

// ── 7. fail-closed resolve() + read-only env backend ─────────────────────────────────────────
{
  const v = new Vault();
  v.set("TK", "sk-abc");
  process.env.SB_TEST_ENV = "envval";

  assert("resolve ${vault:..}", v.resolve("Bearer ${vault:TK}") === "Bearer sk-abc");
  assert("resolve ${env:..}", v.resolve("${env:SB_TEST_ENV}") === "envval");
  assert("resolve passes a no-ref string through unchanged", v.resolve("no refs here") === "no refs here");
  assert("resolve resolves multiple refs in one value", v.resolve("${vault:TK}-${env:SB_TEST_ENV}") === "sk-abc-envval");
  assert("missing ${vault:..} ref THROWS (fail-closed, no blank credential)", throws(() => v.resolve("${vault:MISSING_X}")));
  assert("missing ${env:..} ref THROWS (fail-closed)", throws(() => v.resolve("${env:DEFINITELY_UNSET_98765}")));

  const envVault = new Vault("env");
  assert("env backend rejects set() (read-only)", throws(() => envVault.set("X", "y")));
  assert("env backend get() → undefined (nothing stored)", envVault.get("X") === undefined);
  assert("env backend resolve ${env:..} still works", envVault.resolve("${env:SB_TEST_ENV}") === "envval");
}

// ── 8. static scan — the GCM wiring is actually present in compiled output ────────────────────
const src = readFileSync(join(__dirname, "..", "dist", "vault.js"), "utf8");
assert("dist uses aes-256-gcm (authenticated cipher)", /aes-256-gcm/.test(src));
assert("dist uses a random 12-byte IV", /randomBytes\(\s*12\s*\)/.test(src));
assert("dist generates a 32-byte key", /randomBytes\(\s*32\s*\)/.test(src));
assert("dist sets the auth tag on seal", /getAuthTag/.test(src));
assert("dist verifies the auth tag on unseal", /setAuthTag/.test(src));

// ── footer ──────────────────────────────────────────────────────────────────────────────────
const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
process.exitCode = failed.length === 0 ? 0 : 1;
