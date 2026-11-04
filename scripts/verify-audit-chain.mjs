// Deterministic oracle for the tamper-evident audit log (design vNext 3.7; src/audit.ts).
//
// Proves, against the compiled dist/ and real child processes, in throwaway homes:
//
//   the chain         every row carries seq, prev_hash and hash; the hash is recomputed HERE with an independent
//                     canonical-JSON implementation (sorted keys, no hash field) and must match; the first row
//                     links to 64 zeros; optional principal/client/risk/approval_id are accepted, hashed, and
//                     absent when not given; a caller cannot forge seq or hash.
//   tamper detection  an edited row breaks at ITS seq; an edit with a recomputed hash breaks at the NEXT seq; a
//                     deleted row, a duplicated row, a swapped pair, a forged unhashed row, a garbage line and a
//                     forged row with a valid hash but the wrong link are all caught at the right seq.
//   rotation          a real 20 MB row triggers rotation to audit.log.<timestamp>; the new file's first row
//                     continues seq and prev_hash; `verify --all` walks both files; tampering inside a rotated
//                     segment is found by --all; reads fall back across segments.
//   no forks          three writer processes plus the parent append at once: one contiguous chain.
//   crash tail        a torn final line is sealed by the next append, the chain stays contiguous, verify reports it.
//   capture_io        defaults OFF (no request/response on any row, and the starter config does not enable it);
//                     when ON every string value is scanned for secret shapes and replaced with [redacted:<kind>],
//                     inside nested objects and arrays, at depth 7, 12 and 40, and past the depth bound; the raw
//                     secret appears nowhere in audit.log.
//   fail-open writes  a disk error while writing the row never throws out of the router after the upstream call.
//   CLI               `switchboard audit verify [--all]` exits 0 on a good chain and 1 on a break, naming the seq.
//
// Zero deps. Run `npm run build` first. Run: node scripts/verify-audit-chain.mjs
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? ` - ${String(detail).replace(/\s+/g, " ").slice(0, 220)}` : ""}`);
};
const info = (msg) => console.log(`INFO  ${msg}`);

// ── sandbox ──────────────────────────────────────────────────────────────────────────────────────────────
const base = mkdtempSync(join(tmpdir(), "sb-auditchain-"));
const userHome = join(base, "userhome");
for (const d of [userHome, join(base, "appdata"), join(base, "local")]) mkdirSync(d, { recursive: true });
Object.assign(process.env, { HOME: userHome, USERPROFILE: userHome, APPDATA: join(base, "appdata"), LOCALAPPDATA: join(base, "local") });
const DEFAULT_HOME = join(base, "default-home");
process.env.SWITCHBOARD_HOME = DEFAULT_HOME; // read at module load: set before the imports below
delete process.env.SWITCHBOARD_AUTO_APPROVE;

const audit = await import("../dist/audit.js");
const { AuditLog, sanitizeForAudit, redactSecretShapes, canonicalJson, GENESIS_HASH, AUDIT_ROTATE_BYTES, recentAudit } = audit;
const { Registry } = await import("../dist/registry.js");
const { Router } = await import("../dist/router.js");
const { Vault } = await import("../dist/vault.js");
const { starterConfig } = await import("../dist/config.js");
import { Server } from "@modelcontextprotocol/server";

let n = 0;
const freshHome = (label) => {
  const d = join(base, `${label}-${n++}`);
  mkdirSync(d, { recursive: true });
  return d;
};
const sha256 = (s) => createHash("sha256").update(s, "utf8").digest("hex");
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
const text = (p) => readFileSync(p, "utf8");

// An INDEPENDENT canonical form and hash (not imported from dist): keys sorted at every depth, no whitespace.
const canon = (v) =>
  v === null || typeof v !== "object"
    ? JSON.stringify(v)
    : Array.isArray(v)
      ? `[${v.map(canon).join(",")}]`
      : `{${Object.keys(v)
          .sort()
          .map((k) => `${JSON.stringify(k)}:${canon(v[k])}`)
          .join(",")}}`;
const expectedHash = (row) => {
  const { hash: _h, ...rest } = row;
  return sha256(canon(rest));
};
const readRows = (home, file = "audit.log") => text(join(home, file)).split("\n").filter(Boolean).map((l) => JSON.parse(l));
const writeRows = (home, rows, file = "audit.log") => writeFileSync(join(home, file), rows.map((r) => (typeof r === "string" ? r : JSON.stringify(r))).join("\n") + "\n");
const rehash = (row) => ({ ...row, hash: expectedHash(row) });

/** A home whose audit.log holds `count` chained rows written through the real AuditLog. */
function makeChain(label, count) {
  const home = freshHome(label);
  const log = new AuditLog(home);
  for (let i = 1; i <= count; i++) {
    log.append({ server: "alpha", tool: `tool_${i}`, scope: i % 2 ? "read" : "write", decision: i % 3 === 0 ? "deny" : "allow", reason: `row ${i}` });
  }
  return { home, log };
}
const runCli = (args, home) =>
  spawnSync(process.execPath, [join(root, "dist", "cli.js"), ...args], { env: { ...process.env, SWITCHBOARD_HOME: home, NO_COLOR: "1" }, encoding: "utf8", timeout: 120_000 });

// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
// 1. the chain
// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
{
  const home = freshHome("chain");
  const log = new AuditLog(home);
  log.append({ server: "voice", tool: "text_to_speech", scope: "write", decision: "approval_required", reason: "gated", principal: "apikey:3f9a", client: "codex", risk: "high", approval_id: "ap_7KQ2M9XD" });
  log.append({ server: "alpha", tool: "read_thing", scope: "read", decision: "allow", duration_ms: 12 });
  for (let i = 0; i < 8; i++) log.append({ server: "alpha", tool: `t${i}`, scope: "read", decision: "allow" });
  const rows = readRows(home);
  assert("every row has an integer seq counting from 1", rows.every((r, i) => r.seq === i + 1));
  assert("the first row links to 64 zeros", rows[0].prev_hash === GENESIS_HASH && GENESIS_HASH === "0".repeat(64));
  assert("every row's prev_hash is the previous row's hash", rows.slice(1).every((r, i) => r.prev_hash === rows[i].hash));
  assert("every hash is 64 lowercase hex characters", rows.every((r) => /^[0-9a-f]{64}$/.test(r.hash)));
  assert("every hash equals SHA-256 over the canonical JSON of the row without hash (independent recompute)", rows.every((r) => r.hash === expectedHash(r)));
  assert("the optional principal, client, risk and approval_id are stored when given", rows[0].principal === "apikey:3f9a" && rows[0].client === "codex" && rows[0].risk === "high" && rows[0].approval_id === "ap_7KQ2M9XD");
  assert("the optional fields are absent when not given", !("principal" in rows[1]) && !("client" in rows[1]) && !("risk" in rows[1]) && !("approval_id" in rows[1]));
  assert("rows keep ts, server, tool, scope, decision", rows.every((r) => typeof r.ts === "string" && !Number.isNaN(Date.parse(r.ts)) && r.server && r.tool && r.scope && r.decision));

  assert("canonicalJson sorts keys at every depth and ignores insertion order", canonicalJson({ b: 1, a: { d: 2, c: [{ z: 1, y: 2 }] } }) === '{"a":{"c":[{"y":2,"z":1}],"d":2},"b":1}' && canonicalJson({ a: 1, b: 2 }) === canonicalJson({ b: 2, a: 1 }));
  assert("canonicalJson omits undefined members like JSON does", canonicalJson({ a: 1, b: undefined }) === '{"a":1}');

  const forged = new AuditLog(freshHome("forge"));
  forged.append({ server: "s", tool: "t", scope: "read", decision: "allow", seq: 999, hash: "f".repeat(64), prev_hash: "e".repeat(64), ts: "1999-01-01T00:00:00.000Z" });
  const fr = readRows(forged.home)[0];
  assert("a caller cannot forge seq, prev_hash, hash or ts", fr.seq === 1 && fr.prev_hash === GENESIS_HASH && fr.hash === expectedHash(fr) && fr.ts !== "1999-01-01T00:00:00.000Z");
  assert("the chain verifies", log.verify().ok === true && log.verify().rows === 10 && log.verify().last_seq === 10);
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
// 2. tamper detection, each at the right seq
// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
{
  const K = 5;
  const tamper = (label, mutate) => {
    const { home, log } = makeChain(label, 10);
    const rows = readRows(home);
    const out = mutate(rows, home);
    writeRows(home, out ?? rows);
    return log.verify();
  };
  const pristine = makeChain("pristine", 10);
  assert("pristine chain: verify ok, 10 rows, seq 1..10, no legacy rows", (() => { const v = pristine.log.verify(); return v.ok && v.rows === 10 && v.first_seq === 1 && v.last_seq === 10 && v.legacy_rows === 0 && !v.break; })());

  let v = tamper("t-edit", (rows) => { rows[K - 1].tool = "tampered"; });
  assert(`an edited row breaks the chain at that row's seq (${K})`, !v.ok && v.break.seq === K && /hash mismatch/.test(v.break.reason) && v.break.line === K, JSON.stringify(v.break));
  assert("rows before the break are counted as verified", v.rows === K - 1);

  v = tamper("t-edit-opt", (rows) => { rows[K - 1].risk = "low"; rows[K - 1].principal = "apikey:forged"; });
  assert("adding or changing an optional field (risk, principal) is detected", !v.ok && v.break.seq === K);

  v = tamper("t-edit-rehash", (rows) => { rows[K - 1].tool = "tampered"; rows[K - 1] = rehash(rows[K - 1]); });
  assert(`an edit with its own hash recomputed is caught at the NEXT row (${K + 1}) through prev_hash`, !v.ok && v.break.seq === K + 1 && /prev_hash/.test(v.break.reason), JSON.stringify(v.break));

  v = tamper("t-delete", (rows) => { rows.splice(K - 1, 1); });
  assert(`a deleted row breaks the chain at the missing seq (${K})`, !v.ok && v.break.seq === K && /missing/.test(v.break.reason), JSON.stringify(v.break));

  v = tamper("t-duplicate", (rows) => { rows.splice(K, 0, { ...rows[K - 1] }); });
  assert(`a duplicated row is caught where seq ${K + 1} was expected`, !v.ok && v.break.seq === K + 1, JSON.stringify(v.break));

  v = tamper("t-swap", (rows) => { [rows[K - 1], rows[K]] = [rows[K], rows[K - 1]]; });
  assert(`two swapped rows are caught at ${K}`, !v.ok && v.break.seq === K, JSON.stringify(v.break));

  v = tamper("t-unhashed", (rows) => { rows.push('{"ts":"2026-01-01T00:00:00.000Z","server":"x","tool":"forged","scope":"read","decision":"allow"}'); });
  assert("a forged row without a hash appended after the chain is caught", !v.ok && v.break.seq === 11 && /without a hash/.test(v.break.reason), JSON.stringify(v.break));

  v = tamper("t-garbage", (rows) => { rows.splice(K - 1, 1, "{this is not json"); });
  assert(`a damaged row breaks the chain at its position (${K})`, !v.ok && v.break.seq === K && /unreadable/.test(v.break.reason), JSON.stringify(v.break));

  v = tamper("t-forged-link", (rows) => {
    const last = rows[rows.length - 1];
    rows.push(rehash({ ts: last.ts, seq: last.seq + 1, server: "x", tool: "forged", scope: "read", decision: "allow", prev_hash: "1".repeat(64) }));
  });
  assert("a forged row with a valid own hash but the wrong prev_hash is caught", !v.ok && v.break.seq === 11 && /prev_hash/.test(v.break.reason), JSON.stringify(v.break));

  // known limit, reported honestly: the chain has no secret
  {
    const { home, log } = makeChain("t-rewrite", 10);
    const rows = readRows(home);
    rows[K - 1].tool = "rewritten";
    for (let i = K - 1; i < rows.length; i++) {
      if (i > 0) rows[i].prev_hash = rows[i - 1].hash;
      rows[i] = rehash(rows[i]);
    }
    writeRows(home, rows);
    info(`known limit: an attacker who rewrites the file AND every later hash is not detected (verify ok=${log.verify().ok}); anchor the latest hash off-box. Cutting rows off the end is likewise undetectable.`);
  }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
// 3. rows written before the chain existed
// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
{
  const home = freshHome("legacy");
  const legacy = [1, 2, 3].map((i) => JSON.stringify({ ts: `2026-01-0${i}T00:00:00.000Z`, server: "old", tool: `t${i}`, scope: "read", decision: "allow" }));
  writeFileSync(join(home, "audit.log"), legacy.join("\n") + "\n");
  const log = new AuditLog(home);
  for (let i = 0; i < 3; i++) log.append({ server: "new", tool: `n${i}`, scope: "read", decision: "allow" });
  const rows = readRows(home);
  assert("appending after pre-chain rows starts the chain at seq 1 from the genesis hash", rows[3].seq === 1 && rows[3].prev_hash === GENESIS_HASH);
  let v = log.verify();
  assert("verify accepts a legacy prefix, counts it, and notes it is unverifiable", v.ok && v.rows === 3 && v.legacy_rows === 3 && v.notes.some((x) => /not verifiable/.test(x)), JSON.stringify(v));
  appendFileSync(join(home, "audit.log"), legacy[0] + "\n");
  v = log.verify();
  assert("an unhashed row AFTER the chain began is a break (legacy rows are only a prefix)", !v.ok && /without a hash/.test(v.break.reason));
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
// 4. rotation at 20 MB
// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
{
  const home = freshHome("rotation");
  const log = new AuditLog(home);
  for (let i = 1; i <= 3; i++) log.append({ server: "alpha", tool: `pre_${i}`, scope: "read", decision: "allow" });
  assert("the rotation threshold is 20 MB", AUDIT_ROTATE_BYTES === 20 * 1024 * 1024);
  log.append({ server: "alpha", tool: "big_row", scope: "read", decision: "allow", reason: "x".repeat(AUDIT_ROTATE_BYTES) }); // seq 4, file now over 20 MB
  const bigHash = readRows(home).at(-1).hash;
  assert("a file under the threshold is not rotated early", readdirSync(home).filter((f) => /^audit\.log\.\d/.test(f)).length === 0);
  log.append({ server: "alpha", tool: "after_rotation_1", scope: "read", decision: "allow" });
  log.append({ server: "alpha", tool: "after_rotation_2", scope: "read", decision: "allow" });
  log.append({ server: "alpha", tool: "after_rotation_3", scope: "read", decision: "allow" });
  const rotated = readdirSync(home).filter((f) => /^audit\.log\.\d{8}T\d{9}Z(-\d+)?$/.test(f));
  assert("crossing 20 MB renames audit.log to audit.log.<timestamp>", rotated.length === 1, readdirSync(home).join(","));
  const cur = readRows(home);
  assert("the new audit.log is small and starts with the next seq", cur.length === 3 && cur[0].seq === 5 && cur.at(-1).seq === 7);
  assert("the new file's first row carries the last hash over (prev_hash = last hash of the old file)", cur[0].prev_hash === bigHash);
  const old = readRows(home, rotated[0]);
  assert("the rotated segment holds seq 1..4 and is untouched", old.length === 4 && old.at(-1).hash === bigHash && old.at(-1).seq === 4);
  let v = log.verify({ all: true });
  assert("verify --all walks both files and the chain is continuous", v.ok && v.rows === 7 && v.files.length === 2 && v.first_seq === 1 && v.last_seq === 7, JSON.stringify({ ...v, notes: undefined }));
  v = log.verify();
  assert("verify (current file) checks the link to the newest rotated segment and passes", v.ok && v.rows === 3 && v.first_seq === 5);
  const recent = new AuditLog(home).recent(10);
  assert("recent() reads back through the rotated segment, newest first", recent.length === 7 && recent[0].seq === 7 && recent.at(-1).seq === 1);

  // a break in the current file's link to the segment
  const curRows = readRows(home);
  writeRows(home, [rehash({ ...curRows[0], prev_hash: "a".repeat(64) }), ...curRows.slice(1)]);
  v = log.verify();
  assert("a wrong link between the rotated segment and the current file is caught without --all", !v.ok && v.break.seq === 5 && /prev_hash/.test(v.break.reason), JSON.stringify(v.break));
  writeRows(home, curRows); // restore the intact rows

  // tamper inside the rotated segment (row 2): only --all reads it
  const oldRows = readRows(home, rotated[0]);
  oldRows[1].tool = "edited_in_old_segment";
  writeRows(home, oldRows, rotated[0]);
  v = log.verify({ all: true });
  assert("verify --all finds an edit inside a rotated segment at its seq (2)", !v.ok && v.break.seq === 2 && v.break.file === rotated[0], JSON.stringify(v.break));

  // CLI
  const cliOk = runCli(["audit", "verify"], home);
  assert("CLI `audit verify` exits 0 for the intact current file and prints OK with the seq range", cliOk.status === 0 && /audit chain OK/.test(cliOk.stdout) && /seq 5\.\.7/.test(cliOk.stdout), `exit ${cliOk.status} ${cliOk.stdout.slice(0, 120)}`);
  const cliAll = runCli(["audit", "verify", "--all"], home);
  assert("CLI `audit verify --all` exits 1 and reports the break with its seq", cliAll.status === 1 && /BROKEN at seq 2/.test(cliAll.stdout), `exit ${cliAll.status} ${cliAll.stdout.slice(0, 160)}`);
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
// 5. concurrent writers keep one chain
// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
{
  const home = freshHome("concurrent");
  const fixture = join(root, "scripts", "fixtures", "audit-append.mjs");
  const workers = ["w1", "w2", "w3"].map((label) => {
    const child = spawn(process.execPath, [fixture, home, label, "100"], { env: { ...process.env, SWITCHBOARD_HOME: home }, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    return new Promise((res) => child.on("close", (code) => res({ code, out })));
  });
  const mine = new AuditLog(home);
  for (let i = 0; i < 50; i++) {
    mine.append({ server: "parent", tool: `p_${i}`, scope: "read", decision: "allow" });
    if (i % 10 === 0) await sleep(2);
  }
  const results = (await Promise.all(workers)).map((w) => ({ code: w.code, ...JSON.parse(w.out.trim().split("\n").pop() || "{}") }));
  const rows = readRows(home);
  const v = new AuditLog(home).verify();
  assert("4 writers (3 processes + the parent) appended 350 rows with no errors", rows.length === 350 && results.every((r) => r.code === 0 && r.errors === 0), `${rows.length} rows`);
  assert("the interleaved chain is one contiguous chain: seq 1..350, every link valid", v.ok && v.rows === 350 && rows.every((r, i) => r.seq === i + 1 && r.hash === expectedHash(r)), JSON.stringify(v.break ?? {}));
  assert("every writer's rows are all present", ["p_", "w1_", "w2_", "w3_"].every((p) => rows.filter((r) => r.tool.startsWith(p)).length === (p === "p_" ? 50 : 100)));
  assert("no lock or temp file is left behind", readdirSync(home).every((f) => f === "audit.log"), readdirSync(home).join(","));
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
// 6. a crash mid-append
// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
{
  const { home, log } = makeChain("torn", 5);
  appendFileSync(join(home, "audit.log"), '{"ts":"2026-01-01T00:00:00.000Z","seq":6,"serv'); // the process died mid-write
  const fresh = new AuditLog(home); // a restarted process reads the tail
  fresh.append({ server: "alpha", tool: "after_crash", scope: "read", decision: "allow" });
  fresh.append({ server: "alpha", tool: "after_crash_2", scope: "read", decision: "allow" });
  const lines = text(join(home, "audit.log")).split("\n").filter(Boolean);
  const whole = lines.flatMap((l) => { try { return [JSON.parse(l)]; } catch { return []; } });
  assert("the torn fragment was sealed on its own line, not glued to the next row", lines.length === 8 && whole.length === 7);
  assert("the chain of whole rows stays contiguous across the fragment (seq 6 and 7 follow 5)", whole.map((r) => r.seq).join() === "1,2,3,4,5,6,7" && whole[5].prev_hash === whole[4].hash);
  const v = log.verify();
  assert("verify still reports the damaged line, at the seq it occupies", !v.ok && v.break.seq === 6 && /unreadable/.test(v.break.reason), JSON.stringify(v.break));
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
// 7. secret scrubbing (capture_io): shapes, nesting, depth
// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
const rep = (s, k) => s.repeat(k);
// A PEM block assembled from fragments (no contiguous header literal in this source file).
const D5 = "-----";
const pem = (label, body, terminated = true) => `${D5}BEGIN ${label}${D5}\n${body}${terminated ? `\n${D5}END ${label}${D5}` : ""}`;
// Obviously fake values built from fragments so no real-looking secret sits in this source file.
const SAMPLES = [
  ["sk-key", "sk-" + rep("Ab3dE6gH", 6)],
  ["sk-key", "sk-proj-" + rep("Zy9xW8vU", 6)],
  ["google-api-key", "AIza" + "Sy" + rep("B", 33)],
  ["github-token", "ghp_" + rep("a1B2c3D4", 5)],
  ["github-token", "gho_" + rep("e5F6g7H8", 5)],
  ["github-token", "github_pat_" + rep("11ABCDEF0", 8)],
  ["slack-token", "xoxb-" + "123456789012-abcdefghijkl"],
  ["slack-token", "xoxa-" + "123456789012-abcdefghijkl"],
  ["slack-token", "xoxp-" + "123456789012-abcdefghijkl"],
  ["slack-token", "xoxr-" + "123456789012-abcdefghijkl"],
  ["huggingface-token", "hf_" + rep("aB3dE5gH7j", 3)],
  ["bearer", "Bearer " + "abcDEF123456.ghiJKL789-oraclefake"],
  ["jwt", "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiJvcmFjbGUifQ" + "." + "c2lnbmF0dXJlLWZha2U"],
  ["pem-block", pem("PRIVATE " + "KEY", "TUlJRXZRSUJBREFOQmdrcWhraUc5dzBCQVFFRkFBU0M=\nZmFrZWZha2VmYWtl")],
  ["pem-block", pem("RSA PRIVATE " + "KEY", "TUlJRXBBSUJBQUtDQVFFQQ== (cut off, never terminated)", false)],
  ["aws-access-key", "AKIA" + "ABCDEFGHIJKLMNOP"],
  ["hex-token", "api_key=" + rep("0123456789abcdef", 2)],
  ["hex-token", '{"token": "' + rep("fedcba9876543210", 3) + '"}'],
  ["b64url-token", "client secret: " + rep("Qw3rTy-_", 5)],
  ["b64url-token", "access_token = " + rep("Zx9Cv_bN-m", 4)],
];
// the part of each sample that must never survive
const secretPart = (sample) =>
  sample.startsWith("api_key=")
    ? sample.slice("api_key=".length)
    : sample.startsWith('{"token"')
      ? sample.match(/[0-9a-f]{40,}/)[0]
      : sample.startsWith("client secret")
        ? sample.slice("client secret: ".length)
        : sample.startsWith("access_token")
          ? sample.slice("access_token = ".length)
          : sample.startsWith(D5)
            ? sample.split("\n")[1]
            : sample.startsWith("Bearer ")
              ? sample.slice(7)
              : sample;
const nest = (depth, leaf) => {
  let v = { leaf };
  for (let i = 0; i < depth; i++) v = i % 2 ? { n: [v, "sibling"] } : { n: v };
  return v;
};
const kindsSeen = new Set();
for (const [kind, sample] of SAMPLES) {
  const raw = secretPart(sample);
  let all = true;
  let why = "";
  for (const depth of [0, 1, 3, 7, 12, 40]) {
    const out = JSON.stringify(sanitizeForAudit(nest(depth, `before ${sample} after`)));
    if (out.includes(raw) || !out.includes(`[redacted:${kind}]`)) {
      all = false;
      why = `depth ${depth}: ${out.slice(0, 160)}`;
      break;
    }
  }
  kindsSeen.add(kind);
  const shortName = sample.slice(0, 12).replace(/\n/g, " ");
  assert(`secret shape ${kind} (${shortName}...) is replaced with [redacted:${kind}] at depth 0, 1, 3, 7, 12 and 40`, all, why);
  assert(`  ...${kind} (${shortName}...): redactSecretShapes() on a bare string`, !redactSecretShapes(sample).includes(raw) && redactSecretShapes(sample).includes(`[redacted:${kind}]`));
}
assert("every kind in the spec is covered: sk-/sk-proj-, AIza, ghp_/gho_/github_pat_, xox[abpr]-, hf_, Bearer, JWT, PEM, AKIA, hex and base64url tokens (11 kinds)", kindsSeen.size === 11, [...kindsSeen].join(","));
{
  const deepSecret = "ghp_" + rep("q1W2e3R4", 5);
  const past = JSON.stringify(sanitizeForAudit(nest(100, deepSecret)));
  assert("past the depth bound the subtree is replaced, never copied: the secret is absent", !past.includes(deepSecret) && /truncated:depth/.test(past));
  const inArray = JSON.stringify(sanitizeForAudit({ list: [["x", { y: ["z", `use ${deepSecret} now`] }]] }));
  assert("a secret inside arrays inside objects inside arrays is redacted", !inArray.includes(deepSecret) && inArray.includes("[redacted:github-token]"));
  const asKey = JSON.stringify(sanitizeForAudit({ [`sk-${rep("Kk9Jj8Hh", 4)}`]: "value" }));
  assert("a secret shape used as an object KEY is redacted too", !asKey.includes("Kk9Jj8Hh") && asKey.includes("[redacted:sk-key]"));
  const top = sanitizeForAudit(`plain ${SAMPLES[0][1]}`);
  assert("a top-level string is scanned", typeof top === "string" && top.includes("[redacted:sk-key]"));
  const text2 = sanitizeForAudit({ content: [{ type: "text", text: `result with ${SAMPLES[2][1]} inside` }], isError: false });
  assert("an MCP result shape (content[].text) is scanned", !JSON.stringify(text2).includes("SyBBBB") && JSON.stringify(text2).includes("[redacted:google-api-key]") && text2.isError === false);

  // name-based masking and the injected-key seam still work, and ordinary values survive
  const named = sanitizeForAudit({ api_key: "plain-looking", nested: { Authorization: "x", note: "keep me", n: 7 } });
  assert("key-name masking is unchanged (exact marker [redacted])", named.api_key === "[redacted]" && named.nested.Authorization === "[redacted]" && named.nested.note === "keep me" && named.nested.n === 7);
  assert("the injected-key seam still masks a benign key name", sanitizeForAudit({ q: "innocuous" }, new Set(["q"])).q === "[redacted]");
  const benign = [
    "The deploy of commit 0123456789abcdef0123456789abcdef01234567 finished",
    "skill-based routing and task-force planning use desk-top mode",
    "key=abc and token: short, the secret to a good key is brevity",
    "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 of the file",
  ];
  assert("ordinary text is left alone (no over-redaction of prose, commit ids, short values, bare hashes)", benign.every((s) => redactSecretShapes(s) === s), benign.filter((s) => redactSecretShapes(s) !== s).join(" | "));
  const circ = { a: 1 };
  circ.self = circ;
  assert("a circular value is still [uncapturable] and an over-cap value still gets a truncation marker", sanitizeForAudit(circ) === "[uncapturable]" && typeof sanitizeForAudit({ b: "y".repeat(9000) })._truncated === "number");

  const errLog = new AuditLog(freshHome("errscrub"));
  errLog.append({ server: "s", tool: "t", scope: "read", decision: "allow", error: `upstream said: invalid key ${SAMPLES[0][1]}`, error_code: "SB_UPSTREAM_ERROR" });
  const er = readRows(errLog.home)[0];
  assert("an upstream error message that echoes a credential is scrubbed even with capture_io off", !er.error.includes("Ab3dE6gH") && er.error.includes("[redacted:sk-key]"));
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
// 8. through the router: capture_io default off, on = scrubbed, a disk error never throws out of forward()
// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
{
  const SECRET_IN = "ghp_" + rep("m4N5o6P7", 5);
  const SECRET_OUT = "AIza" + "Sy" + rep("C", 33);
  const SECRET_DEEP = "sk-proj-" + rep("Tt4Uu5Vv", 5);
  let upstreamCalls = 0;
  const upstream = new Server({ name: "alpha", version: "0.0.0" }, { capabilities: { tools: {} } });
  upstream.setRequestHandler("tools/list", async () => ({ tools: [{ name: "echo", inputSchema: { type: "object", properties: {} } }, { name: "get_echo", inputSchema: { type: "object", properties: {} } }] }));
  upstream.setRequestHandler("tools/call", async (req) => {
    upstreamCalls++;
    return { content: [{ type: "text", text: `echo:${req.params.arguments?.msg ?? ""} saw ${SECRET_OUT}` }] };
  });
  const registry = new Registry(new Vault("env"));
  await registry.mountLocal({ id: "alpha", source: "local", enabled: true, policy: "full" }, upstream);
  const cfg = (settings = {}) => ({ gateway: { default_policy: "full", tool_exposure: "namespaced" }, vault: { backend: "env" }, servers: [], settings });
  const args = { msg: "hello", nested: { list: [{ deep: `token holder ${SECRET_IN}` }] }, far: nest(10, `x ${SECRET_DEEP} y`) };
  const logPath = join(DEFAULT_HOME, "audit.log");
  const lastRow = () => readRows(DEFAULT_HOME).at(-1);

  assert("the starter config does not turn capture_io on", starterConfig().settings?.logs?.capture_io !== true);
  const off = new Router(registry, cfg(), (r) => r);
  const r0 = await off.callTool("alpha__echo", args);
  assert("capture_io unset: the call works", r0.content[0].text.startsWith("echo:hello"));
  let row = lastRow();
  assert("capture_io unset (the default): the audit row has no request and no response", row.tool === "echo" && !("request" in row) && !("response" in row));
  const explicitOff = new Router(registry, cfg({ logs: { capture_io: false } }), (r) => r);
  await explicitOff.callTool("alpha__echo", args);
  row = lastRow();
  assert("capture_io: false: no request and no response either", !("request" in row) && !("response" in row));
  assert("with capture off no argument or result text reaches audit.log at all", !text(logPath).includes(SECRET_IN) && !text(logPath).includes(SECRET_OUT) && !text(logPath).includes("hello"));

  const on = new Router(registry, cfg({ logs: { capture_io: true } }), (r) => r);
  await on.callTool("alpha__echo", args);
  row = lastRow();
  const captured = JSON.stringify([row.request, row.response]);
  assert("capture_io: true: the row carries a request and a response", !!row.request && !!row.response && captured.includes("hello"));
  assert("capture_io: true: shapes are redacted inside nested request values", !captured.includes(SECRET_IN) && captured.includes("[redacted:github-token]"));
  assert("capture_io: true: shapes are redacted in the response text", !captured.includes(SECRET_OUT) && captured.includes("[redacted:google-api-key]"));
  assert("capture_io: true: a secret nested 10 levels deep in the request is redacted", !captured.includes(SECRET_DEEP) && captured.includes("[redacted:sk-key]"));
  const whole = text(logPath);
  assert("the raw secrets appear nowhere in audit.log, whole file", ![SECRET_IN, SECRET_OUT, SECRET_DEEP].some((s) => whole.includes(s)));
  assert("the captured row is part of the verified chain", row.hash === expectedHash(row) && new AuditLog(DEFAULT_HOME).verify().ok);

  // a disk error while writing the row: make audit.log a directory so every append fails
  const before = upstreamCalls;
  renameSync(logPath, `${logPath}.keep-for-test`);
  mkdirSync(logPath);
  let threw = null;
  let res;
  const failed = await captureStderr(async () => {
    try {
      res = await off.callTool("alpha__get_echo", { msg: "during-disk-error" });
    } catch (err) {
      threw = err;
    }
  });
  // Adapted (wave 2, design 3.7): the call above is READ scope, where logging stays after the call. A WRITE or full scope
  // call writes an attempt row first and is refused when that fails; that contract is asserted right after these checks.
  assert("...the failed audit write is logged loudly, naming the server and tool", /audit write failed for alpha\/get_echo/.test(failed.logged), /audit write failed/.test(failed.logged) ? "" : failed.logged.slice(0, 120));
  assert("a disk error writing the audit row does NOT throw out of forward()", threw === null, threw ? String(threw.message).slice(0, 120) : "");
  assert("...the upstream call happened and its result came back intact", upstreamCalls === before + 1 && res?.content?.[0]?.text?.startsWith("echo:during-disk-error") && !res?.isError, JSON.stringify(res).slice(0, 120));
  const beforeWrite = upstreamCalls;
  let writeRes;
  await captureStderr(async () => {
    writeRes = await off.callTool("alpha__echo", { msg: "write-during-disk-error" });
  });
  assert("a WRITE-scope call is refused with SB_AUDIT_FAILED while the audit log cannot be written, and never reaches the upstream (write-ahead)", writeRes?.isError === true && /SB_AUDIT_FAILED/.test(writeRes?.content?.[0]?.text ?? "") && upstreamCalls === beforeWrite, JSON.stringify(writeRes).slice(0, 160));
  const denied = (await captureStderr(() => off.callTool("nope__missing", {}).catch((e) => ({ threw: e })))).value;
  assert("...and the router keeps answering after the failed write", !denied.threw);
  rmSync(logPath, { recursive: true, force: true });
  renameSync(`${logPath}.keep-for-test`, logPath);
  await off.callTool("alpha__echo", { msg: "after-recovery" });
  row = lastRow();
  const chainV = new AuditLog(DEFAULT_HOME).verify();
  assert("once the disk is healthy the next row is written and the chain still verifies", row.tool === "echo" && chainV.ok, JSON.stringify(chainV.break ?? {}));
  assert("the lost row left no lock file behind", !existsSync(`${logPath}.lock`));

  const cli = runCli(["audit", "verify"], DEFAULT_HOME);
  assert("CLI `audit verify` on the router-written log exits 0", cli.status === 0 && /audit chain OK/.test(cli.stdout), `exit ${cli.status} ${cli.stdout.slice(0, 120)}`);
  const lines = text(logPath).split("\n").filter(Boolean);
  const rows = lines.map((l) => JSON.parse(l));
  rows[2].tool = "edited-by-attacker";
  writeFileSync(logPath, rows.map((r) => JSON.stringify(r)).join("\n") + "\n");
  const cliBad = runCli(["audit", "verify"], DEFAULT_HOME);
  assert("CLI `audit verify` exits 1 after an edit and names the seq", cliBad.status === 1 && new RegExp(`BROKEN at seq ${rows[2].seq}\\b`).test(cliBad.stdout), `exit ${cliBad.status} ${cliBad.stdout.slice(0, 160)}`);
  assert("recentAudit() still reads the rows newest first (dashboard path)", recentAudit(3).length === 3 && recentAudit(3)[0].seq > recentAudit(3)[2].seq);
}

// ── footer ───────────────────────────────────────────────────────────────────────────────────────────────
const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
process.exitCode = failed.length === 0 ? 0 : 1;
