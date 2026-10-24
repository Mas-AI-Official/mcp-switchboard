// Deterministic oracle for durable local storage (design vNext 3.9; src/atomicfile.ts and the stores built on it).
//
// A secret store that loses or resurrects data is worse than none, so every guarantee is proven by doing the
// thing and reading the bytes back, against the compiled dist/ and real child processes, in throwaway homes:
//
//   atomic write         temp + fsync + rename; a failed rename (simulated power loss) leaves the old file
//                        byte-identical and no temp file; the previous version is kept as `.bak`.
//   corrupt != empty     a truncated, empty or wrongly shaped store file THROWS a StoreCorruptError that names
//                        the file and the backup, never reads as an empty store, and is never overwritten.
//   live stores          ApiKeyStore and Vault re-read when the file changes: a REAL `switchboard apikey rm`
//                        child process revokes a key on a running store, `apikey new` works with no restart.
//   no stale write-back  four worker processes hammer verify() (persisting last_used every time) while the
//                        parent revokes a key: no verify that starts after the revoke returns true, and the
//                        key never reappears in the file.
//   vault key            Windows: raw vault.key is wrapped (DPAPI), verified, then deleted, and the vault still
//                        decrypts in a fresh process; a damaged or conflicting key file is an error, never a
//                        silently new key. Elsewhere: 0600 key in a 0700 home. SKIP lines say which was not run.
//   every other store    oauth.json, authserver.json, triggers-state.json, config writes, sessions and login
//                        codes use the same helpers (corrupt files fail loudly; writes leave `.bak` or none).
//
// Zero deps. Run `npm run build` first. Run: node scripts/verify-storage.mjs
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, statSync, utimesSync, writeFileSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const checks = [];
let skipped = 0;
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? ` - ${String(detail).replace(/\s+/g, " ").slice(0, 220)}` : ""}`);
};
const skip = (name, why) => {
  skipped++;
  console.log(`SKIP  ${name} - ${why}`);
};
const throwsWith = (fn, re) => {
  try {
    fn();
    return { threw: false, msg: "" };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { threw: true, msg, err, matches: re ? re.test(msg) : true };
  }
};
/** Run `fn` with stderr captured, so an EXPECTED error log neither clutters the run nor reads as a failure; returns what was logged. */
const captureStderr = async (fn) => {
  const real = process.stderr.write.bind(process.stderr);
  let logged = "";
  process.stderr.write = (chunk, ...rest) => {
    logged += String(chunk);
    const cb = rest.find((r) => typeof r === "function");
    if (cb) cb();
    return true;
  };
  try {
    return { value: await fn(), logged };
  } finally {
    process.stderr.write = real;
  }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sha256 = (s) => createHash("sha256").update(s, "utf8").digest("hex");
const text = (p) => readFileSync(p, "utf8");
/** Parsed JSON of a file, or null when it is absent or unparsable (a missing .bak must FAIL a check, not crash the oracle). */
const jsonOrNull = (p) => {
  try {
    return JSON.parse(text(p));
  } catch {
    return null;
  }
};
const WIN = process.platform === "win32";

// ── sandbox: nothing here may touch the operator's real state ────────────────────────────────────────────
const base = mkdtempSync(join(tmpdir(), "sb-storage-"));
const userHome = join(base, "userhome");
for (const d of [userHome, join(base, "appdata"), join(base, "local")]) mkdirSync(d, { recursive: true });
Object.assign(process.env, { HOME: userHome, USERPROFILE: userHome, APPDATA: join(base, "appdata"), LOCALAPPDATA: join(base, "local") });
const DEFAULT_HOME = join(base, "default-home");
process.env.SWITCHBOARD_HOME = DEFAULT_HOME; // HOME_DIR is read at module load: set before the imports below
for (const k of Object.keys(process.env)) if (/_API_KEY$|^SWITCHBOARD_(AUTO_APPROVE|TOKEN)$/.test(k)) delete process.env[k];

const atomic = await import("../dist/atomicfile.js");
const { ApiKeyStore } = await import("../dist/apikeys.js");
const { Vault, loadVaultKey, seal, unseal } = await import("../dist/vault.js");
const { protectForUser, unprotectForUser } = await import("../dist/oscrypt.js");
const { OAuthStore } = await import("../dist/oauth.js");
const { SwitchboardAuthProvider } = await import("../dist/authserver.js");
const { TriggerManager } = await import("../dist/triggers.js");
const { loadConfig, writeConfig, starterConfig } = await import("../dist/config.js");
const { OwnerSessions, LoginCodeStore } = await import("../dist/httpsec.js");
const { StoreCorruptError } = atomic;

let n = 0;
const freshDir = (label) => {
  const d = join(base, `${label}-${n++}`);
  mkdirSync(d, { recursive: true });
  return d;
};
const cliEnv = (home) => ({ ...process.env, SWITCHBOARD_HOME: home, NO_COLOR: "1" });
const runCli = (args, home) => spawnSync(process.execPath, [join(root, "dist", "cli.js"), ...args], { env: cliEnv(home), encoding: "utf8", timeout: 60_000 });
const leftovers = (dir, target) => readdirSync(dir).filter((f) => f !== target && !f.endsWith(".bak"));

// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
// 1. atomic write + .bak
// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
{
  const dir = freshDir("atomic");
  const f = join(dir, "store.json");
  atomic.writeJsonAtomic(f, { v: 1 });
  assert("atomic write creates the file with the content", JSON.parse(text(f)).v === 1);
  assert("atomic write leaves no temp or lock file behind", leftovers(dir, "store.json").length === 0, readdirSync(dir).join(","));
  assert("the first write has no .bak (nothing to keep)", !existsSync(`${f}.bak`));

  atomic.writeJsonAtomic(f, { v: 2 });
  assert("the second write keeps the previous version as .bak", jsonOrNull(`${f}.bak`)?.v === 1 && JSON.parse(text(f)).v === 2);
  atomic.writeJsonAtomic(f, { v: 3 });
  assert(".bak always holds exactly the previous generation", jsonOrNull(`${f}.bak`)?.v === 2);

  // simulated power loss: the process dies after the temp file is written, before the rename lands
  const real = fs.renameSync;
  const before = readFileSync(f);
  fs.renameSync = (a, b) => {
    if (resolve(String(b)) === resolve(f)) throw Object.assign(new Error("simulated power loss before rename"), { code: "EIO" });
    return real(a, b);
  };
  syncBuiltinESMExports();
  let r;
  try {
    r = throwsWith(() => atomic.writeJsonAtomic(f, { v: 4 }));
  } finally {
    fs.renameSync = real;
    syncBuiltinESMExports();
  }
  assert("a write that fails before the rename throws", r.threw && /simulated power loss/.test(r.msg));
  assert("the failed write leaves the old file byte-identical", Buffer.compare(before, readFileSync(f)) === 0);
  assert("the failed write removes its temp file", leftovers(dir, "store.json").length === 0, readdirSync(dir).join(","));
  assert("the failed write left a usable .bak (the primary's own content at that moment)", jsonOrNull(`${f}.bak`)?.v === 3);

  // a crashed writer elsewhere left a half-written temp file: it must be inert
  writeFileSync(`${f}.4242.abc.0.tmp`, '{"v":99,"trunc');
  assert("a stale temp file does not change what the store reads", atomic.readJsonFileSync(f).v === 3);
  atomic.writeJsonAtomic(f, { v: 5 });
  assert("a write beside a stale temp file succeeds and wins", atomic.readJsonFileSync(f).v === 5);
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
// 2. a store file that exists but does not parse is an ERROR, never an empty store
// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
{
  const dir = freshDir("corrupt");
  const f = join(dir, "store.json");
  assert("an absent file reads as undefined (a first run is not corruption)", atomic.readJsonFileSync(f) === undefined);

  atomic.writeJsonAtomic(f, { gen: 1, items: ["a", "b"] });
  atomic.writeJsonAtomic(f, { gen: 2, items: ["a", "b", "c"] });
  const good = readFileSync(f);
  writeFileSync(f, good.subarray(0, Math.floor(good.length / 2))); // a torn write
  const torn = throwsWith(() => atomic.readJsonFileSync(f));
  assert("a truncated file throws a StoreCorruptError", torn.threw && torn.err instanceof StoreCorruptError && torn.err.code === "SB_STORE_CORRUPT");
  assert("the error names the file", torn.msg.includes(f));
  assert("the error says it was NOT replaced with an empty store", /NOT replaced with an empty store/.test(torn.msg));
  assert("the error says a usable backup exists and where", torn.err.backup === "valid" && torn.msg.includes(`${f}.bak`) && /parses/.test(torn.msg));
  assert("the .bak after the torn write really is the last good generation", jsonOrNull(`${f}.bak`)?.gen === 1);
  assert("reading never overwrote the corrupt file", Buffer.compare(readFileSync(f).subarray(0, 4), good.subarray(0, 4)) === 0 && readFileSync(f).length === Math.floor(good.length / 2));

  writeFileSync(f, "");
  const empty = throwsWith(() => atomic.readJsonFileSync(f), /empty/);
  assert("a zero-byte file throws (the old reader returned {})", empty.threw && empty.matches);

  writeFileSync(f, "[1,2,3]");
  const shape = throwsWith(() => atomic.readJsonFileSync(f, { validate: (v) => (Array.isArray(v) ? "expected an object" : null) }), /expected an object/);
  assert("a wrongly shaped file throws through the validator", shape.threw && shape.matches);

  // a corrupt current file must not clobber a good .bak when an operator rewrites it
  writeFileSync(f, JSON.stringify({ gen: 7 }));
  atomic.writeJsonAtomic(f, { gen: 8 }); // .bak = gen 7
  writeFileSync(f, "{broken");
  atomic.writeJsonAtomic(f, { gen: 9 }); // the primary was corrupt: it must not be copied over the good .bak
  assert("a corrupt primary is not copied over a good .bak", jsonOrNull(`${f}.bak`)?.gen === 7 && JSON.parse(text(f)).gen === 9);

  // no backup at all
  const lone = join(dir, "lone.json");
  writeFileSync(lone, "{x");
  const none = throwsWith(() => atomic.readJsonFileSync(lone));
  assert("with no .bak the error says so", none.err?.backup === "absent" && /no backup/.test(none.msg));
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
// 3. the cross-process lock
// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
{
  const dir = freshDir("lock");
  const f = join(dir, "locked.json");
  writeFileSync(`${f}.lock`, `${process.pid}\n${Date.now()}\n`); // a fresh lock held by someone else
  let ran = false;
  const r = throwsWith(() => atomic.withFileLock(f, () => (ran = true), { timeoutMs: 150 }), /could not lock/);
  assert("a held lock times out with a clear error and the work does not run", r.threw && r.matches && !ran);
  const old = new Date(Date.now() - 60_000);
  utimesSync(`${f}.lock`, old, old); // the holder crashed a minute ago
  const got = atomic.withFileLock(f, () => 42, { timeoutMs: 1000, staleMs: 10_000 });
  assert("a lock left by a crashed holder is broken once stale", got === 42);
  assert("the lock file is removed after the work", !existsSync(`${f}.lock`));
  const w = new atomic.WatchedJsonFile(f, () => ({ n: 0 }));
  const w2 = new atomic.WatchedJsonFile(f, () => ({ n: 0 }));
  w.update((c) => ({ ...c, a: 1 }));
  w2.update((c) => ({ ...c, b: 2 })); // w2 was constructed before w wrote: it must merge, not overwrite
  const merged = atomic.readJsonFileSync(f);
  assert("two instances of one store merge their updates (no lost write)", merged.a === 1 && merged.b === 2, JSON.stringify(merged));
  assert("an instance sees the other's change on its next read", w.get().b === 2 && w2.get().a === 1);
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
// 4. API keys: live re-read, CLI revoke and issue, no stale write-back
// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
{
  const home = freshDir("apikeys");
  const live = new ApiKeyStore({ home, lastUsedIntervalMs: 0 });
  const k1 = live.issue("alpha");
  const k2 = live.issue("beta");
  assert("an issued token starts with sb_ and verifies", k1.token.startsWith("sb_") && live.verify(k1.token) && live.verify(k2.token));
  assert("a wrong or empty token is refused", !live.verify("sb_wrong") && !live.verify(""));
  assert("apikeys.json is created owner-only where modes exist", WIN || (statSync(join(home, "apikeys.json")).mode & 0o777) === 0o600);
  assert("apikeys.json holds hashes, never a token", !text(join(home, "apikeys.json")).includes(k1.token));

  // a REAL CLI process revokes a key; the live instance (never restarted) must refuse it at once
  const rm = runCli(["apikey", "rm", k1.record.id], home);
  assert("CLI `apikey rm` exits 0", rm.status === 0, rm.status === 0 ? "" : `exit ${rm.status} ${String(rm.stderr).slice(0, 160)}`);
  assert("a CLI revoke reaches the running store: the revoked token is refused", live.verify(k1.token) === false);
  assert("the other key still works and the count dropped", live.verify(k2.token) === true && live.count === 1);
  assert("the revoked key never reappears after a later last_used write", !JSON.parse(text(join(home, "apikeys.json"))).keys.some((k) => k.id === k1.record.id));

  // a REAL CLI process issues a key; the live instance accepts it with no restart
  const created = runCli(["apikey", "new", "from-cli"], home);
  const token = (created.stdout.match(/\bsb_[A-Za-z0-9_-]{43}\b/) ?? [])[0];
  assert("CLI `apikey new` exits 0 and prints a token", created.status === 0 && !!token, created.status === 0 ? "" : `exit ${created.status}`);
  assert("a key issued by the CLI is accepted by the running store without a restart", !!token && live.verify(token) === true && live.count === 2);

  // stale instance: loaded before the revoke, then verifies the revoked token and another one
  const stale = new ApiKeyStore({ home, lastUsedIntervalMs: 0 });
  const victim = live.issue("victim");
  assert("a store opened after the issue sees the new key", stale.verify(victim.token) === true);
  new ApiKeyStore({ home }).revoke(victim.record.id);
  assert("the stale instance refuses the key a third process revoked", stale.verify(victim.token) === false);
  assert("the stale instance's next last_used write does not resurrect it", stale.verify(k2.token) && !JSON.parse(text(join(home, "apikeys.json"))).keys.some((k) => k.id === victim.record.id));

  // last_used is merged and throttled
  const lu = JSON.parse(text(join(home, "apikeys.json"))).keys.find((k) => k.id === k2.record.id).last_used;
  assert("a successful verify persists last_used", typeof lu === "string" && !Number.isNaN(Date.parse(lu)));
  const throttled = new ApiKeyStore({ home }); // default interval
  throttled.verify(k2.token);
  const stamp1 = atomic.fileStamp(join(home, "apikeys.json"));
  throttled.verify(k2.token);
  assert("last_used writes are throttled (no fsync per request by default)", atomic.fileStamp(join(home, "apikeys.json")) === stamp1);
}

// ── the multi-process race: workers verify with a last_used write on EVERY verify while the parent revokes ──
{
  const home = freshDir("apikeys-race");
  const store = new ApiKeyStore({ home });
  const revoked = store.issue("to-revoke");
  const kept = store.issue("to-keep");
  const fixture = join(root, "scripts", "fixtures", "apikey-hammer.mjs");
  const workers = Array.from({ length: 4 }, () => {
    const child = spawn(process.execPath, [fixture, home, revoked.token, kept.token, "3000"], { env: cliEnv(home), stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    return new Promise((res) => child.on("close", (code) => res({ code, out })));
  });
  // wait until the workers are demonstrably verifying (they stamp last_used on the key we will revoke)
  const apikeysPath = join(home, "apikeys.json");
  const deadline = Date.now() + 15_000;
  const hasUse = () => {
    try {
      return JSON.parse(text(apikeysPath)).keys.some((k) => k.id === revoked.record.id && k.last_used);
    } catch {
      return false;
    }
  };
  while (!hasUse() && Date.now() < deadline) await sleep(25);
  const workersRunning = hasUse();
  await sleep(150);
  const tStart = Date.now();
  const removed = store.revoke(revoked.record.id);
  const tDone = Date.now();
  let resurrected = false;
  let unparsable = 0;
  const watchUntil = Date.now() + 1500;
  while (Date.now() < watchUntil) {
    try {
      if (JSON.parse(text(apikeysPath)).keys.some((k) => k.id === revoked.record.id)) resurrected = true;
    } catch {
      unparsable++;
    }
    await sleep(15);
  }
  const results = (await Promise.all(workers)).map((w) => ({ code: w.code, ...JSON.parse(w.out.trim().split("\n").pop() || "{}") }));
  const lateTrue = results.flatMap((r) => r.revokedTrueAt ?? []).filter((t) => t > tDone);
  const earlyTrue = results.flatMap((r) => r.revokedTrueAt ?? []).filter((t) => t <= tStart);
  assert("race: the workers were verifying (last_used appeared) before the revoke", workersRunning && earlyTrue.length > 0, `${earlyTrue.length} accepted before the revoke`);
  assert("race: the revoke removed the key", removed === true);
  assert("race: no verify that STARTED after the revoke returned true", lateTrue.length === 0, `${lateTrue.length} late acceptances`);
  assert("race: the revoked key never reappeared in the file under last_used pressure", !resurrected);
  assert("race: apikeys.json never parsed as torn or empty while 4 processes wrote it", unparsable === 0, `${unparsable} unparsable reads`);
  assert("race: the kept key kept working in every worker and no worker errored", results.length === 4 && results.every((r) => r.code === 0 && r.errors === 0 && r.keptTrue > 0), JSON.stringify(results.map((r) => [r.iterations, r.keptTrue, r.errors])));
  const final = JSON.parse(text(apikeysPath));
  assert("race: the file ends with exactly the kept key, with a last_used", final.keys.length === 1 && final.keys[0].id === kept.record.id && !!final.keys[0].last_used);
  assert("race: .bak is valid JSON", (() => { try { JSON.parse(text(`${apikeysPath}.bak`)); return true; } catch { return false; } })());
  assert("race: no lock or temp file is left behind", readdirSync(home).filter((f) => f.endsWith(".lock") || f.endsWith(".tmp")).length === 0, readdirSync(home).join(","));
}

// ── a corrupt apikeys.json fails closed and is never replaced ────────────────────────────────────────────
{
  const home = freshDir("apikeys-corrupt");
  const s = new ApiKeyStore({ home, lastUsedIntervalMs: 0 });
  const k = s.issue("one");
  s.issue("two");
  const p = join(home, "apikeys.json");
  const good = readFileSync(p);
  writeFileSync(p, good.subarray(0, 20));
  const opened = throwsWith(() => new ApiKeyStore({ home }), /apikeys\.json/);
  assert("opening a store over a torn apikeys.json throws (an empty store would switch loopback auth off)", opened.threw && opened.err instanceof StoreCorruptError && opened.matches);
  const refused = await captureStderr(() => s.verify(k.token));
  assert("the live instance refuses every key while the file is unusable (fail closed, no throw)", refused.value === false);
  assert("...and says so loudly (the log names apikeys.json and that nothing was replaced)", /apikeys\.json/.test(refused.logged) && /NOT replaced/.test(refused.logged));
  const issue = throwsWith(() => s.issue("three"));
  assert("issuing over a torn file throws and leaves it alone", issue.threw && readFileSync(p).length === 20);
  assert("the .bak holds the last good generation", (jsonOrNull(`${p}.bak`)?.keys?.length ?? 0) >= 1);
  const list = runCli(["apikey", "list"], home);
  assert("CLI `apikey list` over a torn apikeys.json exits 1 and names the file (no stack trace, no empty list)", list.status === 1 && /apikeys\.json/.test(list.stderr) && !/\n\s+at /.test(list.stderr), `exit ${list.status}`);
  const made = runCli(["apikey", "new", "x"], home);
  assert("CLI `apikey new` over a torn apikeys.json exits 1 and leaves the file alone", made.status === 1 && readFileSync(p).length === 20);
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
// 5. vault: live re-read, merge on write, corrupt is an error
// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
{
  const home = freshDir("vault");
  const a = new Vault("encrypted-file", { home });
  a.set("one", "value-one");
  const b = new Vault("encrypted-file", { home });
  b.set("two", "value-two");
  assert("a secret set by another instance is readable without a restart", a.get("two") === "value-two");
  a.set("three", "value-three");
  assert("a stale instance's write merges: it does not overwrite the other's secret", b.get("two") === "value-two" && b.get("one") === "value-one" && b.get("three") === "value-three");
  b.remove("one");
  assert("a removal by another instance is seen by the live one", a.get("one") === undefined && a.list().sort().join() === "three,two");
  assert(
    "vault.json is written atomically with a .bak and no temp or lock file left",
    existsSync(join(home, "vault.json.bak")) && readdirSync(home).every((f) => ["vault.json", "vault.json.bak", "vault.key", "vault.key.dpapi"].includes(f)),
    readdirSync(home).join(","),
  );

  const p = join(home, "vault.json");
  const good = readFileSync(p);
  writeFileSync(p, good.subarray(0, 30));
  const open = throwsWith(() => new Vault("encrypted-file", { home }), /vault\.json/);
  assert("opening a torn vault.json throws (the old reader returned an empty vault)", open.threw && open.err instanceof StoreCorruptError && open.matches);
  const set = throwsWith(() => a.set("four", "x"));
  assert("a write over a torn vault.json throws and does not replace it", set.threw && readFileSync(p).length === 30);
  writeFileSync(p, "[]");
  assert("a vault.json of the wrong shape throws", throwsWith(() => new Vault("encrypted-file", { home })).threw);
  writeFileSync(p, good); // restore: the sealed data was never lost
  assert("restoring the file brings every secret back", new Vault("encrypted-file", { home }).get("three") === "value-three");
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
// 6. home directory and the vault key
// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
{
  const nested = join(base, "newhome", "deep");
  new Vault("encrypted-file", { home: nested });
  assert("a store creates a missing home directory", existsSync(nested));
  if (WIN) {
    skip("home directory is mode 0700", "file modes are not enforced on win32 (the per-user profile ACL is the boundary)");
  } else {
    assert("a created home directory is mode 0700", (statSync(nested).mode & 0o777) === 0o700, (statSync(nested).mode & 0o777).toString(8));
    const loose = join(base, "loosehome");
    mkdirSync(loose, { mode: 0o755 });
    chmodSync(loose, 0o755);
    atomic.ensureDir(loose);
    assert("an existing directory keeps its mode (only creation sets 0700)", (statSync(loose).mode & 0o777) === 0o755);
  }

  // the key is cached for the process lifetime: deleting the file does not make a second call mint a new key
  const home = freshDir("keycache");
  const k1 = loadVaultKey(home);
  for (const f of ["vault.key", "vault.key.dpapi"]) if (existsSync(join(home, f))) fs.unlinkSync(join(home, f));
  const k2 = loadVaultKey(home);
  assert("the unwrapped key is cached for the process lifetime", k1.length === 32 && Buffer.compare(k1, k2) === 0);
  k2[0] ^= 0xff;
  assert("the cache hands out copies (a caller cannot corrupt it)", Buffer.compare(k1, loadVaultKey(home)) === 0);

  const badLen = freshDir("keylen");
  writeFileSync(join(badLen, "vault.key"), Buffer.from("short"));
  const bl = throwsWith(() => loadVaultKey(badLen), /expected 32/);
  assert("a vault.key of the wrong length is an error, not a silently new key", bl.threw && bl.matches && text(join(badLen, "vault.key")) === "short");

  if (!WIN) {
    const h = freshDir("portablekey");
    const key = loadVaultKey(h);
    assert("non-Windows: a fresh key is stored as vault.key, 32 bytes, mode 0600", readFileSync(join(h, "vault.key")).equals(key) && (statSync(join(h, "vault.key")).mode & 0o777) === 0o600);
    assert("non-Windows: no .dpapi file is created", !existsSync(join(h, "vault.key.dpapi")));
    for (const label of ["fresh DPAPI key", "raw key migration", "interrupted migration", "conflicting keys", "damaged blob", "decrypt in a fresh process", "two processes migrating at once"]) {
      skip(`DPAPI: ${label}`, `Windows only; this platform is ${process.platform}`);
    }
  } else {
    skip("vault.key mode 0600", "file modes are not enforced on win32; vault.key.dpapi is protected for the Windows user instead");

    // fresh install: only the wrapped key exists, and it unwraps to the key in use
    const h1 = freshDir("dpapi-fresh");
    const key = loadVaultKey(h1);
    const wrapped1 = readFileSync(join(h1, "vault.key.dpapi"));
    assert("DPAPI: a fresh key is stored as vault.key.dpapi and no raw vault.key exists", !existsSync(join(h1, "vault.key")) && existsSync(join(h1, "vault.key.dpapi")));
    assert("DPAPI: the wrapped blob does not contain the key", key.length === 32 && !wrapped1.includes(key) && !wrapped1.includes(Buffer.from(key.toString("hex"))) && !wrapped1.includes(Buffer.from(key.toString("base64"))));
    assert("DPAPI: the blob unwraps to the key in use", unprotectForUser(wrapped1).equals(key));

    // migration: a 0.1.0 install with a raw key and a sealed vault
    const h2 = freshDir("dpapi-migrate");
    const raw = randomBytes(32);
    writeFileSync(join(h2, "vault.key"), raw);
    writeFileSync(join(h2, "vault.json"), JSON.stringify({ legacy_secret: seal(raw, "legacy-value-0123") }));
    const migrated = new Vault("encrypted-file", { home: h2 });
    assert("DPAPI migration: the raw vault.key is gone", !existsSync(join(h2, "vault.key")));
    assert("DPAPI migration: vault.key.dpapi exists and does not contain the old key", existsSync(join(h2, "vault.key.dpapi")) && !readFileSync(join(h2, "vault.key.dpapi")).includes(raw));
    assert("DPAPI migration: the wrapped key unwraps to the old raw key (round trip)", unprotectForUser(readFileSync(join(h2, "vault.key.dpapi"))).equals(raw));
    assert("DPAPI migration: the vault still decrypts the pre-migration secret", migrated.get("legacy_secret") === "legacy-value-0123");
    const probe = spawnSync(
      process.execPath,
      ["--input-type=module", "-e", `const { Vault } = await import(${JSON.stringify(pathToFileURL(join(root, "dist", "vault.js")).href)}); process.stdout.write(new Vault().get("legacy_secret") ?? "MISSING");`],
      { env: cliEnv(h2), encoding: "utf8", timeout: 60_000 },
    );
    assert("DPAPI migration: a fresh process decrypts the vault through the wrapped key", probe.status === 0 && probe.stdout === "legacy-value-0123", probe.status === 0 ? "" : `exit ${probe.status} ${probe.stderr.slice(0, 120)}`);

    // the gateway and a CLI command start together on a 0.1.0 home: both must end up with the same key and the same vault
    const h2b = freshDir("dpapi-race");
    const rawB = randomBytes(32);
    writeFileSync(join(h2b, "vault.key"), rawB);
    writeFileSync(join(h2b, "vault.json"), JSON.stringify({ legacy_secret: seal(rawB, "race-value-4567") }));
    const reader = `const { Vault } = await import(${JSON.stringify(pathToFileURL(join(root, "dist", "vault.js")).href)}); process.stdout.write(new Vault().get("legacy_secret") ?? "MISSING");`;
    const racers = [0, 1].map(
      () =>
        new Promise((res) => {
          const child = spawn(process.execPath, ["--input-type=module", "-e", reader], { env: cliEnv(h2b), stdio: ["ignore", "pipe", "pipe"] });
          let out = "";
          let err = "";
          child.stdout.on("data", (d) => (out += d));
          child.stderr.on("data", (d) => (err += d));
          child.on("close", (code) => res({ code, out, err }));
        }),
    );
    const raced = await Promise.all(racers);
    assert("DPAPI race: two processes migrating one home at once both succeed and read the vault", raced.every((r) => r.code === 0 && r.out === "race-value-4567"), raced.map((r) => `${r.code}:${r.out || r.err.slice(0, 80)}`).join(" | "));
    assert("DPAPI race: the end state is one wrapped key that unwraps to the old key, no raw key, no lock file", !existsSync(join(h2b, "vault.key")) && unprotectForUser(readFileSync(join(h2b, "vault.key.dpapi"))).equals(rawB) && !existsSync(join(h2b, "vault.key.dpapi.lock")));

    // crash between "wrapped copy written" and "raw deleted"
    const h3 = freshDir("dpapi-interrupted");
    const k3 = randomBytes(32);
    writeFileSync(join(h3, "vault.key.dpapi"), protectForUser(k3));
    writeFileSync(join(h3, "vault.key"), k3);
    const got3 = loadVaultKey(h3);
    assert("DPAPI interrupted migration: the same key is used and the raw copy is removed", got3.equals(k3) && !existsSync(join(h3, "vault.key")));

    // two different keys: never guess
    const h4 = freshDir("dpapi-conflict");
    const wrappedKey = randomBytes(32);
    const strayKey = randomBytes(32);
    writeFileSync(join(h4, "vault.key.dpapi"), protectForUser(wrappedKey));
    writeFileSync(join(h4, "vault.key"), strayKey);
    const conflict = throwsWith(() => loadVaultKey(h4), /different keys/);
    assert("DPAPI conflict: both key files with different keys is an error", conflict.threw && conflict.matches);
    assert("DPAPI conflict: neither file was deleted", existsSync(join(h4, "vault.key")) && existsSync(join(h4, "vault.key.dpapi")));

    // a damaged wrapped key must never be replaced by a new key (that would orphan the vault)
    const h5 = freshDir("dpapi-damaged");
    const junk = randomBytes(60);
    writeFileSync(join(h5, "vault.key.dpapi"), junk);
    const dmg = throwsWith(() => loadVaultKey(h5), /cannot unwrap/);
    assert("DPAPI damaged blob: an error that names the file, not a new key", dmg.threw && dmg.matches && dmg.msg.includes("vault.key.dpapi"));
    assert("DPAPI damaged blob: the file is untouched and no raw key was created", readFileSync(join(h5, "vault.key.dpapi")).equals(junk) && !existsSync(join(h5, "vault.key")));
  }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
// 7. the other stores use the same helpers
// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
{
  // oauth.json (default home: the module reads SWITCHBOARD_HOME at load)
  mkdirSync(DEFAULT_HOME, { recursive: true });
  const oauthPath = join(DEFAULT_HOME, "oauth.json");
  writeFileSync(oauthPath, '{"google": {"iv":');
  const o = throwsWith(() => new OAuthStore(new Vault("env")), /oauth\.json/);
  assert("oauth.json: a torn file throws instead of starting with no tokens", o.threw && o.err instanceof StoreCorruptError && o.matches);
  assert("oauth.json: the torn file was left in place", text(oauthPath) === '{"google": {"iv":');
  fs.unlinkSync(oauthPath);
  const ok = new OAuthStore(new Vault("env"));
  assert("oauth.json: with no file the store starts empty and lists its providers", Array.isArray(ok.catalog()) && ok.catalog().every((p) => p.connected === false));

  // authserver.json
  const asPath = join(DEFAULT_HOME, "authserver.json");
  const opts = { issuerUrl: new URL("https://sb.example.test"), publicUrl: "https://sb.example.test", canonicalResource: "https://sb.example.test/mcp", accessTtlSec: 3600, refreshTtlSec: 3600, consent: false };
  const prov = new SwitchboardAuthProvider(opts);
  prov.clientsStore.registerClient({ client_id: "c-1", client_name: "oracle client", redirect_uris: ["http://127.0.0.1:1/cb"], token_endpoint_auth_method: "none" });
  assert("authserver.json: a registered client is persisted sealed", existsSync(asPath) && !text(asPath).includes("oracle client"));
  assert("authserver.json: a second instance reads the persisted client back", new SwitchboardAuthProvider(opts).clientsStore.getClient("c-1")?.client_name === "oracle client");
  new SwitchboardAuthProvider(opts).clientsStore.registerClient({ client_id: "c-2", client_name: "second", redirect_uris: ["http://127.0.0.1:1/cb"], token_endpoint_auth_method: "none" });
  assert("authserver.json: the second write kept a valid .bak", existsSync(`${asPath}.bak`));
  const asGood = readFileSync(asPath);
  writeFileSync(asPath, asGood.subarray(0, 25));
  const as = throwsWith(() => new SwitchboardAuthProvider(opts), /authserver\.json/);
  assert("authserver.json: a torn file throws (an empty state would revoke every client and token)", as.threw && as.matches && /NOT replaced/.test(as.msg));
  writeFileSync(asPath, asGood);
  assert("authserver.json: restoring the file restores the clients", new SwitchboardAuthProvider(opts).clientsStore.getClient("c-2") !== undefined);

  // triggers-state.json
  const trPath = join(DEFAULT_HOME, "triggers-state.json");
  const trCfg = { gateway: {}, vault: { backend: "env" }, servers: [], settings: {} };
  writeFileSync(trPath, '{"triggers": {"t1": {');
  const tr = throwsWith(() => new TriggerManager({}, trCfg, (r) => r), /triggers-state\.json/);
  assert("triggers-state.json: a torn file throws (an empty state would re-fire every trigger)", tr.threw && tr.err instanceof StoreCorruptError && tr.matches);
  fs.unlinkSync(trPath);
  assert("triggers-state.json: with no file the manager starts empty", !throwsWith(() => new TriggerManager({}, trCfg, (r) => r)).threw);

  // config writes
  const cfgDir = freshDir("config");
  const cfgPath = join(cfgDir, "switchboard.config.yaml");
  const cfg1 = starterConfig();
  writeConfig(cfgPath, cfg1);
  const first = text(cfgPath);
  assert("config: the written file loads back", loadConfig(cfgPath).servers.length === cfg1.servers.length);
  const cfg2 = { ...cfg1, settings: { ...(cfg1.settings ?? {}), call_timeout_ms: 12345 } };
  writeConfig(cfgPath, cfg2);
  assert("config: the previous version is kept as .bak", existsSync(`${cfgPath}.bak`) && text(`${cfgPath}.bak`) === first && loadConfig(cfgPath).settings?.call_timeout_ms === 12345);
  const keep = readFileSync(cfgPath);
  const realRename = fs.renameSync;
  fs.renameSync = (a, b) => {
    if (resolve(String(b)) === resolve(cfgPath)) throw Object.assign(new Error("simulated power loss"), { code: "EIO" });
    return realRename(a, b);
  };
  syncBuiltinESMExports();
  let cr;
  try {
    cr = throwsWith(() => writeConfig(cfgPath, { ...cfg2, settings: { call_timeout_ms: 1 } }));
  } finally {
    fs.renameSync = realRename;
    syncBuiltinESMExports();
  }
  assert("config: a write that dies before the rename leaves the config byte-identical and no temp file", cr.threw && Buffer.compare(keep, readFileSync(cfgPath)) === 0 && leftovers(cfgDir, "switchboard.config.yaml").length === 0);

  // owner sessions and login codes. Adapted for design 3.15: they are memory only. A file under SWITCHBOARD_HOME is
  // writable by every process of the same OS user, so a code or a session kept there is not a credential: the old
  // checks (stored under its hash, atomic temp-file write, no .bak) described files that no longer exist. The new ones
  // prove the same care in the new form: one use, nothing written anywhere, nothing survives a restart.
  const sdir = freshDir("sessions");
  const sbHome = process.env.SWITCHBOARD_HOME;
  let T = 1_000_000;
  const clock = () => T;
  const codes = new LoginCodeStore({ clock });
  const sessions = new OwnerSessions({ clock, codes });
  const code = codes.mint();
  assert("login code: held in memory only (no login-codes directory under SWITCHBOARD_HOME, nothing in a scratch directory)", !existsSync(join(sbHome, "login-codes")) && readdirSync(sdir).length === 0);
  const login = sessions.login(code);
  assert("session: a login code redeems once", !!login && sessions.login(code) === null);
  assert("session: memory only (no sessions.json, no .bak, no temp file under SWITCHBOARD_HOME)", !existsSync(join(sbHome, "sessions.json")) && !existsSync(join(sbHome, "sessions.json.bak")) && !existsSync(join(sbHome, "login-codes")));
  assert("session: a restart (a fresh OwnerSessions) knows neither the session nor the code", new OwnerSessions({ clock }).lookup(login.sid) === null && !new OwnerSessions({ clock }).login(code));
  assert("session: the session works on the instance that made it and expires with the clock", sessions.lookup(login.sid) !== null && ((T += 13 * 3600_000), sessions.lookup(login.sid) === null));
}

// ── footer ───────────────────────────────────────────────────────────────────────────────────────────────
const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed${skipped ? ` (${skipped} skipped, see SKIP lines)` : ""}`);
process.exitCode = failed.length === 0 ? 0 : 1;
