// Deterministic oracle for agent-supplied upload references (finding: a UNC or file://host path reached the
// filesystem over SMB before any allowlist refusal, blocking the whole gateway for ~21 s and answering as a
// remote file-existence oracle). It proves, against the real FileService on real temp folders:
//
//   1. THE FINDING: a UNC, device-namespace or file://<host> reference is refused with SB_FILE_REFUSED in under
//      50 ms, the event loop never stalls (heartbeat gap stays small), and NO filesystem call is made on a path
//      the agent supplied (a spy on node:fs sees only owner-controlled paths). Run with a non-empty allowlist
//      and with an empty allowlist beside an existing SWITCHBOARD_HOME/files (both reach realpath in the old code).
//   2. No existence oracle: a path outside the allowlist answers identically whether the file exists or not.
//   3. Windows device names (CON, NUL, COM1, ...), stream syntax (name:stream) and wildcards never reach the
//      filesystem from an agent-supplied path. (The device-name rule is the finding's own fix text, not a
//      reproduced hazard: on Windows 11 with Node 24 a file called NUL or con.txt is written and listed as an
//      ordinary file. staged: therefore refuses stream and wildcard syntax only, never device names.)
//   4. The pure shape gate (localPathRefusal) as a table, for win32 and POSIX regardless of the host OS.
//   5. Nothing legitimate regressed: a plain path, a forward-slash path, a file:///, file://localhost/ and a
//      staged: reference inside the allowlist still resolve; a junction escape is still refused by realpath.
//
// Build first (`npm run build`), then `npm run verify:file-refs`. Isolated temp folders; no network is used,
// including for the hostile references (that is the point).
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOME = mkdtempSync(join(tmpdir(), "sb-fref-"));
const WORK = mkdtempSync(join(tmpdir(), "sb-fref-work-"));
process.env.SWITCHBOARD_HOME = HOME;

const checks = [];
const tidy = (d) => String(d).replace(/\bFAIL\b/g, "fail").replace(/BREACHED/g, "breached");
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? ` - ${cond ? tidy(detail) : detail}` : ""}`);
};
const note = (line) => console.log(`NOTE  ${line}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── a spy on the filesystem calls that take a path ───────────────────────────────────────────────────
const touched = [];
const spy = (name) => {
  const orig = fs[name];
  if (typeof orig !== "function") return;
  const wrapped = function (p, ...rest) {
    touched.push(String(p));
    return orig.call(this, p, ...rest);
  };
  if (typeof orig.native === "function") {
    wrapped.native = function (p, ...rest) {
      touched.push(String(p));
      return orig.native.call(this, p, ...rest);
    };
  }
  fs[name] = wrapped;
};
for (const n of ["realpathSync", "openSync", "statSync", "lstatSync", "existsSync", "accessSync", "readFileSync", "readdirSync", "opendirSync"]) spy(n);
syncBuiltinESMExports();
const norm = (p) => p.toLowerCase().replace(/\\/g, "/");
const touchedMatching = (needle) => touched.filter((p) => norm(p).includes(needle));

const mod = (p) => import(pathToFileURL(join(ROOT, "dist", p)).href);
const F = await mod("connectors/files.js");
const { FileService, localPathRefusal } = F;
// Before the fix the gate does not exist: every table row then fails instead of throwing.
const gate = (p, platform) => (typeof localPathRefusal === "function" ? localPathRefusal(p, platform) : null);

// ── fixtures ─────────────────────────────────────────────────────────────────────────────────────────
const ALLOW = join(WORK, "allowed");
const OUTSIDE = join(WORK, "outside");
mkdirSync(ALLOW, { recursive: true });
mkdirSync(OUTSIDE, { recursive: true });
mkdirSync(join(HOME, "files", "run_abc"), { recursive: true });
const okFile = join(ALLOW, "ok.txt");
writeFileSync(okFile, "hello file");
writeFileSync(join(OUTSIDE, "exists.txt"), "outside");
writeFileSync(join(HOME, "files", "run_abc", "kept.txt"), "staged bytes");
const settings = { upload_allowlist: [ALLOW], max_upload_bytes: 4 * 1024 * 1024 };
const svc = new FileService({ home: HOME, settings: () => settings, now: Date.now });

// ── event loop heartbeat ─────────────────────────────────────────────────────────────────────────────
let last = performance.now();
let maxGap = 0;
const beat = setInterval(() => {
  const n = performance.now();
  maxGap = Math.max(maxGap, n - last);
  last = n;
}, 5);
const resetBeat = () => {
  last = performance.now();
  maxGap = 0;
};

const attempt = async (arg) => {
  const t0 = performance.now();
  try {
    const f = await svc.resolveUpload(arg);
    return { ok: true, file: f, ms: performance.now() - t0 };
  } catch (e) {
    return { ok: false, err: e, ms: performance.now() - t0 };
  }
};
const refused = (r) => !r.ok && r.err?.code === "SB_FILE_REFUSED";

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// 1. the finding: network and device references never touch the filesystem
// ════════════════════════════════════════════════════════════════════════════════════════════════════
const HOSTILE = [
  ["UNC with forward slashes (unroutable host)", "//10.255.255.1/share/x.mp4", "10.255.255.1"],
  ["UNC with backslashes (unroutable host)", "\\\\10.255.255.1\\share\\x.mp4", "10.255.255.1"],
  ["UNC through the \\\\?\\ namespace", "\\\\?\\UNC\\10.255.255.1\\share\\x.mp4", "10.255.255.1"],
  ["device namespace \\\\.\\", "\\\\.\\pipe\\sb-oracle-probe", "sb-oracle-probe"],
  ["device namespace //./", "//./pipe/sb-oracle-probe", "sb-oracle-probe"],
  ["mixed separators \\/", "\\/10.255.255.1/share/x.mp4", "10.255.255.1"],
  ["file:// with an unroutable host", "file://10.255.255.1/share/x.mp4", "10.255.255.1"],
  ["file:// loopback host to an admin share", "file://127.0.0.1/c$/Windows/win.ini", "127.0.0.1"],
  ["loopback admin share as //127.0.0.1/c$/", "//127.0.0.1/c$/Windows/win.ini", "127.0.0.1"],
  ["file:// with a name host", "file://attacker.example/share/x.mp4", "attacker.example"],
];
for (const [mode, cfg] of [["non-empty allowlist", [ALLOW]], ["empty allowlist beside an existing files/ folder", []]]) {
  settings.upload_allowlist = cfg;
  touched.length = 0;
  resetBeat();
  const results = [];
  for (const [label, ref, needle] of HOSTILE) {
    const mark = touched.length;
    const r = await attempt(ref);
    const mine = touched.slice(mark).filter((p) => norm(p).includes(needle.toLowerCase()));
    results.push({ label, r, mine });
  }
  await sleep(40);
  for (const { label, r, mine } of results) {
    assert(`1. [${mode}] ${label}: SB_FILE_REFUSED in under 50 ms`, refused(r) && r.ms < 50, `${r.ms.toFixed(1)} ms ${r.err?.code ?? "RESOLVED"} ${String(r.err?.message ?? "").slice(0, 70)}`);
    assert(`1. [${mode}] ${label}: no filesystem call was made on the agent's path`, mine.length === 0, mine.length ? `touched ${mine.join(" | ")}` : "");
  }
  assert(`1. [${mode}] the event loop never stalled while the hostile references were refused (max gap under 100 ms)`, maxGap < 100, `max gap ${maxGap.toFixed(1)} ms`);
}
settings.upload_allowlist = [ALLOW];

// An owner-configured network folder in the allowlist must not make every upload talk to that host either.
if (process.platform === "win32") {
  settings.upload_allowlist = ["//10.255.254.7/share/media", ALLOW];
  touched.length = 0;
  resetBeat();
  const inside = await attempt(okFile);
  const viaRoot = await attempt("//10.255.254.7/share/media/x.mp4");
  const other = await attempt(join(OUTSIDE, "exists.txt"));
  await sleep(40);
  assert("1. a network folder listed in the owner's allowlist is never contacted: a normal upload still resolves, and no filesystem call names the host", inside.ok && touchedMatching("10.255.254.7").length === 0 && maxGap < 100, `${inside.err?.message ?? "ok"} touched=${touchedMatching("10.255.254.7").join("|")} gap ${maxGap.toFixed(1)} ms`);
  assert("1. a path under that network allowlist entry is still refused (agent paths must be local) and nothing contacts the host", refused(viaRoot) && /network \(UNC\)/.test(viaRoot.err.message) && touchedMatching("10.255.254.7").length === 0, viaRoot.err?.message ?? "RESOLVED");
  assert("1. any outside-the-allowlist refusal carries the note while a network entry is being ignored, so the owner can see why", refused(other) && /ignored/.test(other.err.message), other.err?.message ?? "");
  settings.upload_allowlist = [ALLOW];
} else {
  note(`the network-allowlist-entry rows run on win32 only (on ${process.platform} //host/share is an ordinary absolute path)`);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// 2. no existence oracle
// ════════════════════════════════════════════════════════════════════════════════════════════════════
{
  const a = await attempt(join(OUTSIDE, "exists.txt"));
  const b = await attempt(join(OUTSIDE, "missing.txt"));
  const strip = (r, name) => String(r.err?.message ?? "").replace(name, "<name>");
  assert("2. a path outside the allowlist is refused the same way whether the file exists or not", refused(a) && refused(b) && strip(a, "exists.txt") === strip(b, "missing.txt") && /allowlist/.test(a.err.message), `${a.err?.message} | ${b.err?.message}`);
  touched.length = 0;
  await attempt(join(OUTSIDE, "exists.txt"));
  assert("2. refusing an outside path makes no filesystem call on it", touchedMatching(norm(OUTSIDE)).length === 0, touched.join(" | "));
}

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// 3. Windows device names and stream syntax
// ════════════════════════════════════════════════════════════════════════════════════════════════════
if (process.platform === "win32") {
  for (const [label, ref, needle] of [
    ["a device name (NUL) inside the allowlist", join(ALLOW, "NUL"), "/allowed/nul"],
    ["a device name with an extension (con.txt)", join(ALLOW, "con.txt"), "/allowed/con.txt"],
    ["COM1", join(ALLOW, "COM1"), "/allowed/com1"],
    ["a device name below a real folder", join(ALLOW, "sub", "LPT1.log"), "/allowed/sub/lpt1.log"],
    ["an alternate data stream (name:stream)", `${okFile}:stream`, "ok.txt:stream"],
    ["a wildcard", join(ALLOW, "*.txt"), "/allowed/*.txt"],
  ]) {
    touched.length = 0;
    const r = await attempt(ref);
    assert(`3. ${label}: refused, and the filesystem is not asked about it`, refused(r) && touchedMatching(needle).length === 0, `${r.err?.message ?? "RESOLVED"} touched=${touchedMatching(needle).join("|")}`);
  }
  for (const [label, ref, needle] of [["staged: with stream syntax", "staged:run_abc/kept.txt:s", "kept.txt:s"], ["staged: with a wildcard", "staged:run_abc/*.txt", "/run_abc/*.txt"]]) {
    touched.length = 0;
    const r = await attempt(ref);
    assert(`3. ${label}: refused, and the filesystem is not asked about it`, refused(r) && touchedMatching(needle).length === 0, `${r.err?.message ?? "RESOLVED"}`);
  }
  // A download may legitimately be called aux.pdf (Node writes it as an ordinary file), so staged: must still read it.
  writeFileSync(join(HOME, "files", "run_abc", "aux.pdf"), "staged aux");
  const stagedAux = await attempt("staged:run_abc/aux.pdf");
  assert("3. staged: a saved download whose name only looks like a device (aux.pdf) is still readable", stagedAux.ok && stagedAux.file.bytes.toString() === "staged aux", stagedAux.err?.message ?? "");
} else {
  note(`device-name and stream rows run on win32 only (this host is ${process.platform}); the same rules are proven as a table in section 4`);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// 4. the shape gate as a table, for both platforms
// ════════════════════════════════════════════════════════════════════════════════════════════════════
const WIN_REFUSED = [
  ["\\\\host\\share\\x.mp4", "UNC backslashes"],
  ["//host/share/x.mp4", "UNC forward slashes"],
  ["\\/host/share/x.mp4", "UNC mixed separators"],
  ["/\\host\\share\\x.mp4", "UNC mixed separators, other order"],
  ["\\\\?\\C:\\x.mp4", "\\\\?\\ with a drive"],
  ["\\\\?\\UNC\\host\\share\\x.mp4", "\\\\?\\UNC\\"],
  ["\\\\.\\pipe\\p", "\\\\.\\ device"],
  ["//./pipe/p", "//./ device"],
  ["//?/UNC/host/share/x.mp4", "//?/ forward slashes"],
  ["/rooted/without/drive.txt", "rooted path with no drive"],
  ["\\rooted\\without\\drive.txt", "backslash rooted path with no drive"],
  ["C:drive-relative.txt", "drive-relative path"],
  ["relative\\x.txt", "relative path"],
  ["C:\\a\\NUL", "device NUL"],
  ["C:/a/nul.txt", "device NUL with an extension"],
  ["C:\\a\\CON", "device CON"],
  ["C:\\a\\COM1", "device COM1"],
  ["C:\\a\\com9.bin", "device COM9 with an extension"],
  ["C:\\a\\LPT1.log", "device LPT1 with an extension"],
  ["C:\\a\\AUX ", "device AUX with a trailing space"],
  ["C:\\a\\PRN.", "device PRN with a trailing dot"],
  ["C:\\a\\CONIN$", "device CONIN$"],
  ["C:\\a\\b\\NUL\\c.txt", "a device name as a middle segment"],
  ["C:\\a\\x.txt:stream", "alternate data stream"],
  ["C:\\a\\x.txt::$DATA", "alternate data stream ::$DATA"],
  ["C:\\a\\x*.txt", "wildcard *"],
  ["C:\\a\\x?.txt", "wildcard ?"],
  ["C:\\a\\<x>.txt", "angle brackets"],
  ["C:\\a\\x\u0000.txt", "NUL byte"],
  ["C:\\a\\x\u0007.txt", "control character"],
];
for (const [p, label] of WIN_REFUSED) assert(`4. win32 refuses: ${label}`, typeof gate(p, "win32") === "string" && gate(p, "win32").length > 0, JSON.stringify(p));
const WIN_ACCEPTED = [
  ["C:\\a\\b.txt", "drive path, backslashes"],
  ["c:/A/b c.mp4", "drive path, forward slashes, lower-case drive, space in name"],
  ["D:\\Ideas\\creative\\x.mp4", "typical allowlisted path"],
  ["C:\\a\\console.txt", "name that only starts like CON"],
  ["C:\\a\\nullable.txt", "name that only starts like NUL"],
  ["C:\\a\\com10.txt", "COM10 is not a reserved name"],
  ["C:\\a\\communication.pdf", "name that only starts like COM"],
  ["C:\\a\\auxiliary\\b.txt", "folder that only starts like AUX"],
  ["C:\\a\\b.tar.gz", "several dots"],
];
for (const [p, label] of WIN_ACCEPTED) assert(`4. win32 accepts: ${label}`, gate(p, "win32") === undefined, JSON.stringify(p));
assert("4. posix refuses a NUL byte and accepts an ordinary absolute path", typeof gate("/a/b\u0000c", "linux") === "string" && gate("/a/b.txt", "linux") === undefined && gate("/a/nul", "linux") === undefined && gate("/a/x:y.txt", "linux") === undefined, "a colon or NUL as a name is an ordinary file name on POSIX, except NUL byte");

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// 5. nothing legitimate regressed
// ════════════════════════════════════════════════════════════════════════════════════════════════════
{
  const want = "hello file";
  const plain = await attempt(okFile);
  const fwd = await attempt(okFile.replace(/\\/g, "/"));
  const asUrl = await attempt(pathToFileURL(okFile).href);
  const asLocalhost = await attempt(`file://localhost${pathToFileURL(okFile).pathname}`);
  assert("5. a plain absolute path inside the allowlist still resolves", plain.ok && plain.file.bytes.toString() === want && plain.file.source === "path", plain.err?.message ?? "");
  assert("5. the same path with forward slashes still resolves", fwd.ok && fwd.file.bytes.toString() === want, fwd.err?.message ?? "");
  assert("5. a file:/// URL still resolves", asUrl.ok && asUrl.file.bytes.toString() === want, asUrl.err?.message ?? "");
  assert("5. file://localhost/ (the RFC 8089 spelling of file:///) still resolves", asLocalhost.ok && asLocalhost.file.bytes.toString() === want, asLocalhost.err?.message ?? "");
  const staged = await attempt("staged:run_abc/kept.txt");
  assert("5. staged:<run_id>/<name> still resolves", staged.ok && staged.file.bytes.toString() === "staged bytes" && staged.file.source === "staged", staged.err?.message ?? "");
  const missingIn = await attempt(join(ALLOW, "missing.txt"));
  assert("5. a missing file INSIDE the allowlist still says file not found", refused(missingIn) && /file not found/.test(missingIn.err.message), missingIn.err?.message ?? "");
  const rel = await attempt("relative/file.txt");
  assert("5. a relative path is still refused", refused(rel) && /absolute/.test(rel.err.message), rel.err?.message ?? "");
  const sens = await attempt(join(ALLOW, ".ssh", "id_rsa"));
  assert("5. a sensitive segment is still refused inside the allowlist", refused(sens) && /never uploadable/.test(sens.err.message), sens.err?.message ?? "");

  let linked = false;
  try {
    symlinkSync(OUTSIDE, join(ALLOW, "jlink"), "junction");
    linked = true;
  } catch (e) {
    note(`could not create a junction here (${e.code}); the escape row will fail rather than skip`);
  }
  touched.length = 0;
  const esc = await attempt(join(ALLOW, "jlink", "exists.txt"));
  assert("5. a junction inside the allowlist that points outside is still refused by realpath (the real path is what counts)", linked && refused(esc) && /allowlist/.test(esc.err.message) && touched.some((p) => norm(p).endsWith("/allowed/jlink/exists.txt")), `${esc.err?.message ?? "RESOLVED"}`);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// package registration
// ════════════════════════════════════════════════════════════════════════════════════════════════════
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
assert("package: verify:file-refs is registered and in the verify chain", pkg.scripts["verify:file-refs"] === "node scripts/verify-file-refs.mjs" && pkg.scripts.verify.includes("npm run verify:file-refs"));

// ── teardown and verdict ─────────────────────────────────────────────────────────────────────────────
clearInterval(beat);
for (const d of [WORK, HOME]) {
  try {
    rmSync(d, { recursive: true, force: true });
  } catch {
    /* leftovers in temp are harmless */
  }
}
const passed = checks.filter((c) => c.ok).length;
for (const c of checks.filter((x) => !x.ok)) console.log(`FAILED: ${c.name}${c.detail ? ` - ${c.detail}` : ""}`);
console.log(`\n${passed}/${checks.length} checks passed`);
process.exit(passed === checks.length ? 0 : 1);
