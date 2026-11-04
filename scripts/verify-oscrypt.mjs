// Deterministic oracle for src/oscrypt.ts (OS user-scope wrap used by the client key store and the vault key).
// No model tokens, no network beyond loopback, no real client config, no real operator state.
//
// What it proves (Windows; the other OS branch proves that nothing is spawned there):
//   1. The wrap still works: a DPAPI round trip returns the exact bytes, a foreign blob is refused.
//   2. The Windows PowerShell that does the wrapping is launched by ABSOLUTE path, with cwd System32 and
//      NoDefaultCurrentDirectoryInExePath=1 in the child environment, and the secret never reaches argv.
//      (Seen through a spy on child_process.execFileSync, so production code carries no test seam.)
//   3. THE ATTACK: a compiled marker exe named powershell.exe planted in the launch cwd, with
//      NoDefaultCurrentDirectoryInExePath unset, never runs on the write path, the read path, or through a
//      real `switchboard bridge` process. The bridge sends the real stored token, not the planted one.
//   4. A vacuity guard: the same planted exe DOES run when powershell.exe is launched by bare name from that
//      cwd on this machine, so a pass above cannot be an environment accident.
//   5. Fail closed: a SystemRoot without a PowerShell, or a relative SystemRoot, throws; it never falls back
//      to a bare-name launch (the planted exe stays unrun).
//
// Build first: npm run build && node scripts/verify-oscrypt.mjs

import { spawn, spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, win32 } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const CLI = join(root, "dist", "cli.js");
const OSCRYPT_URL = pathToFileURL(join(root, "dist", "oscrypt.js")).href;
const CLIENTKEYS_URL = pathToFileURL(join(root, "dist", "clientkeys.js")).href;

const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? ` - ${detail}` : ""}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Obviously fake values.
const REAL_TOKEN = "sb_FAKE_real_stored_token_for_the_oscrypt_oracle_0001";
const PLANTED_TOKEN = "sb_FAKE_planted_attacker_token";
const b64 = (s) => Buffer.from(s, "utf8").toString("base64");

const IS_WIN = process.platform === "win32";

/** C# for the planted exe: records that it ran and what it was fed, then answers like an attacker would. */
const MARKER_CS = `
using System;
using System.IO;
using System.Text;
class P {
  static void Main(string[] a) {
    string dir = AppDomain.CurrentDomain.BaseDirectory;
    string mark = Path.Combine(dir, "ran.marker");
    File.AppendAllText(mark, "ran\\n");
    string stdin = Console.In.ReadToEnd();
    string head = stdin.Length > 16 ? stdin.Substring(0, 16) : stdin;
    File.AppendAllText(mark, "stdin-head=" + head + "\\n");
    Console.Out.Write("${b64(PLANTED_TOKEN)}");
  }
}
`;

function compileMarker(base) {
  const sysRoot = process.env.SystemRoot || "C:\\Windows";
  const csc = ["Framework64", "Framework"].map((f) => join(sysRoot, "Microsoft.NET", f, "v4.0.30319", "csc.exe")).find((p) => existsSync(p));
  if (!csc) return { ok: false, why: "csc.exe (.NET Framework 4) not found, cannot build the planted marker exe" };
  const src = join(base, "marker.cs");
  const out = join(base, "marker.exe");
  writeFileSync(src, MARKER_CS);
  const r = spawnSync(csc, ["-nologo", `-out:${out}`, src], { encoding: "utf8", windowsHide: true, timeout: 120_000 });
  if (r.status !== 0 || !existsSync(out)) return { ok: false, why: `csc failed: ${String(r.stdout).slice(0, 200)} ${String(r.stderr).slice(0, 200)}` };
  return { ok: true, exe: out };
}

/** A fresh directory that ships a planted powershell.exe (and the same under System32\...\v1.0 for a SystemRoot=. attack). */
function plantDir(base, name, markerExe) {
  const dir = join(base, name);
  mkdirSync(dir, { recursive: true });
  copyFileSync(markerExe, join(dir, "powershell.exe"));
  const nested = join(dir, "System32", "WindowsPowerShell", "v1.0");
  mkdirSync(nested, { recursive: true });
  copyFileSync(markerExe, join(nested, "powershell.exe"));
  return dir;
}

const markerFile = (dir) => join(dir, "ran.marker");
const markerRan = (dir) => existsSync(markerFile(dir)) || existsSync(join(dir, "System32", "WindowsPowerShell", "v1.0", "ran.marker"));
const clearMarkers = (dir) => {
  rmSync(markerFile(dir), { force: true });
  rmSync(join(dir, "System32", "WindowsPowerShell", "v1.0", "ran.marker"), { force: true });
};

/** Env for children: the oracle's env minus the launch-cwd guard, which the scenario under test must not depend on. */
function childEnv(extra = {}) {
  const env = {};
  for (const [k, v] of Object.entries(process.env)) if (k.toUpperCase() !== "NODEFAULTCURRENTDIRECTORYINEXEPATH") env[k] = v;
  for (const [k, v] of Object.entries(extra)) {
    if (v === undefined) delete env[k];
    else env[k] = v;
  }
  return env;
}

/** Run a small ESM script in a child node process; returns { status, stdout, stderr }. */
function runChild(script, args, cwd, extraEnv = {}) {
  const r = spawnSync(process.execPath, ["--input-type=module", "-e", script, ...args], {
    cwd,
    env: childEnv(extraEnv),
    encoding: "utf8",
    windowsHide: true,
    timeout: 120_000,
  });
  return { status: r.status, stdout: String(r.stdout ?? ""), stderr: String(r.stderr ?? "") };
}

/** Child script: spy on execFileSync (via syncBuiltinESMExports), then wrap and unwrap a secret. */
const SPY_SCRIPT = `
import { createRequire, syncBuiltinESMExports } from "node:module";
const require = createRequire(import.meta.url);
const cp = require("node:child_process");
const real = cp.execFileSync;
const captured = [];
cp.execFileSync = (...a) => {
  const [file, argv, opts] = a;
  captured.push({ file, argv, cwd: opts && opts.cwd, input: opts && opts.input, envKeys: opts && opts.env ? Object.entries(opts.env).filter(([k]) => k.toUpperCase() === "NODEFAULTCURRENTDIRECTORYINEXEPATH") : null });
  return real(...a);
};
syncBuiltinESMExports();
const m = await import(process.argv[1]);
const secret = Buffer.from(process.argv[2], "utf8");
let blob, back, error = null;
try { blob = m.protectForUser(secret); back = m.unprotectForUser(blob); } catch (e) { error = String(e && e.message); }
console.log("RESULT " + JSON.stringify({ captured, error, roundTrip: back ? back.equals(secret) : false, blobIsPlain: blob ? blob.equals(secret) : null, blobLen: blob ? blob.length : null }));
`;

/** Child script: use the real client key store. mode write|read, client id, token. */
const KEYS_SCRIPT = `
const ck = await import(process.argv[1]);
const [mode, id, token] = process.argv.slice(2);
try {
  if (mode === "write") { ck.writeClientKey(id, token); console.log("RESULT " + JSON.stringify({ ok: true })); }
  else { console.log("RESULT " + JSON.stringify({ ok: true, token: ck.readClientKey(id) })); }
} catch (e) { console.log("RESULT " + JSON.stringify({ ok: false, error: String(e && e.message) })); }
`;

/** Child script: point SystemRoot somewhere hostile, then try to wrap. Must throw without spawning anything. */
const FAILCLOSED_SCRIPT = `
import { createRequire, syncBuiltinESMExports } from "node:module";
const require = createRequire(import.meta.url);
const cp = require("node:child_process");
const real = cp.execFileSync;
let spawned = 0;
cp.execFileSync = (...a) => { spawned++; return real(...a); };
syncBuiltinESMExports();
process.env.SystemRoot = process.argv[2];
delete process.env.windir;
delete process.env.WINDIR;
const m = await import(process.argv[1]);
let error = null;
try { m.protectForUser(Buffer.from("sb_FAKE_fail_closed_secret")); } catch (e) { error = String(e && e.message); }
console.log("RESULT " + JSON.stringify({ error, spawned }));
`;

function parseResult(r) {
  const line = r.stdout.split(/\r?\n/).reverse().find((l) => l.startsWith("RESULT "));
  if (!line) return { __none: true, stdout: r.stdout.slice(0, 300), stderr: r.stderr.slice(0, 300), status: r.status };
  return JSON.parse(line.slice("RESULT ".length));
}

/** Drive one real `switchboard bridge` process: send initialize, read the first output line, close stdin. */
function driveBridge(args, cwd, extraEnv) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, "bridge", ...args], { cwd, env: childEnv(extraEnv), stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
    let out = "";
    let err = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    child.stdin.on("error", () => {});
    const timer = setTimeout(() => child.kill(), 90_000);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, out, err });
    });
    child.stdin.write(
      JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "oscrypt-oracle", version: "0.0.0" } } }) + "\n",
    );
    // Close stdin once the reply is in, so the bridge exits by itself.
    const poll = setInterval(() => {
      if (out.includes("\n")) {
        clearInterval(poll);
        child.stdin.end();
      }
    }, 25);
    child.on("close", () => clearInterval(poll));
  });
}

async function main() {
  const base = mkdtempSync(join(tmpdir(), "sb-oscrypt-"));
  const home = join(base, "home");
  const dirs = { home, appdata: join(base, "appdata"), local: join(base, "local"), tmp: join(base, "tmp") };
  for (const d of Object.values(dirs)) mkdirSync(d, { recursive: true });
  const SWITCHBOARD_HOME = join(home, ".switchboard");
  Object.assign(process.env, {
    HOME: dirs.home,
    USERPROFILE: dirs.home,
    APPDATA: dirs.appdata,
    LOCALAPPDATA: dirs.local,
    TEMP: dirs.tmp,
    TMP: dirs.tmp,
    SWITCHBOARD_HOME,
    NO_COLOR: "1",
  });
  const SCRUB = /(_API_KEY|_API_SECRET|TOKEN|SECRET|PASSWORD|CREDENTIALS)$|^SWITCHBOARD_(AUTO_APPROVE|PROFILE|TOKEN|KEY|INSECURE_APPROVAL)$/i;
  for (const k of Object.keys(process.env)) if (SCRUB.test(k)) delete process.env[k];
  // The scenario under test is a launcher that does NOT set NoDefaultCurrentDirectoryInExePath.
  for (const k of Object.keys(process.env)) if (k.toUpperCase() === "NODEFAULTCURRENTDIRECTORYINEXEPATH") delete process.env[k];

  let echo;
  try {
    const { isOsProtected, protectForUser, unprotectForUser } = await import(OSCRYPT_URL);
    assert("oscrypt reports OS protection exactly on Windows", isOsProtected() === IS_WIN, `platform=${process.platform}`);

    // ---------------------------------------------------------------------------------------------
    // 1. The wrap still works, in a normal cwd.
    // ---------------------------------------------------------------------------------------------
    {
      const secret = Buffer.from(REAL_TOKEN, "utf8");
      const blob = protectForUser(secret);
      const back = unprotectForUser(blob);
      assert("protect then unprotect returns the exact bytes", back.equals(secret));
      if (IS_WIN) {
        assert("the Windows blob is a DPAPI wrap, not the plaintext", !blob.includes(secret) && blob.length > secret.length, `${blob.length} bytes`);
        let refused = false;
        try {
          unprotectForUser(Buffer.from("this is not a dpapi blob at all, just text"));
        } catch {
          refused = true;
        }
        assert("a foreign blob is refused (throws)", refused);
      } else {
        assert("off Windows the bytes are stored as-is (file mode is the protection)", blob.equals(secret));
      }
    }

    // ---------------------------------------------------------------------------------------------
    // 2. Non-Windows: nothing may be spawned. Windows: everything below.
    // ---------------------------------------------------------------------------------------------
    if (!IS_WIN) {
      const res = parseResult(runChild(SPY_SCRIPT, [OSCRYPT_URL, REAL_TOKEN], root));
      assert("off Windows no child process is spawned to wrap a secret", res.captured?.length === 0 && res.roundTrip === true, JSON.stringify(res).slice(0, 200));
      return;
    }

    const marker = compileMarker(base);
    assert("planted marker exe compiled (csc.exe, no network)", marker.ok, marker.ok ? marker.exe : marker.why);
    if (!marker.ok) return;
    const sysRoot = process.env.SystemRoot || "C:\\Windows";
    const expectedExe = win32.join(sysRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe").toLowerCase();
    const expectedCwd = win32.join(sysRoot, "System32").toLowerCase();

    // ---------------------------------------------------------------------------------------------
    // 3. Vacuity guard: from a launch cwd that ships powershell.exe, a BARE-NAME launch runs the planted exe.
    // ---------------------------------------------------------------------------------------------
    const ctl = plantDir(base, "control", marker.exe);
    spawnSync("powershell.exe", ["-NoProfile", "-Command", "exit 0"], { cwd: ctl, env: childEnv(), input: "x", encoding: "utf8", windowsHide: true, timeout: 60_000 });
    assert("control: a bare-name powershell.exe launch from the planted cwd runs the planted exe on this machine", markerRan(ctl));

    // ---------------------------------------------------------------------------------------------
    // 4. Launch hardening, seen through a spy on execFileSync, with the planted exe in the cwd.
    // ---------------------------------------------------------------------------------------------
    {
      const planted = plantDir(base, "spy", marker.exe);
      const res = parseResult(runChild(SPY_SCRIPT, [OSCRYPT_URL, REAL_TOKEN], planted));
      const cap = res.captured ?? [];
      assert("spy: protect and unprotect each launched exactly one child", cap.length === 2, `${cap.length} launches; ${JSON.stringify(res).slice(0, 160)}`);
      assert(
        "spy: PowerShell is launched by absolute path under SystemRoot\\System32\\WindowsPowerShell\\v1.0",
        cap.length > 0 && cap.every((c) => win32.isAbsolute(String(c.file)) && String(c.file).toLowerCase() === expectedExe),
        cap.map((c) => c.file).join(" | "),
      );
      assert("spy: the planted exe in the launch cwd did not run", !markerRan(planted));
      assert("spy: the wrap round trip still returns the exact bytes from that cwd", res.roundTrip === true && res.error === null, String(res.error));
      assert("spy: the child's cwd is SystemRoot\\System32, not the caller's cwd", cap.length > 0 && cap.every((c) => String(c.cwd ?? "").toLowerCase() === expectedCwd), cap.map((c) => c.cwd).join(" | "));
      assert(
        "spy: the child environment sets NoDefaultCurrentDirectoryInExePath=1",
        cap.length > 0 && cap.every((c) => Array.isArray(c.envKeys) && c.envKeys.length === 1 && c.envKeys[0][1] === "1"),
        JSON.stringify(cap.map((c) => c.envKeys)),
      );
      const argvText = cap.map((c) => (c.argv ?? []).join(" ")).join("\n");
      assert("spy: the secret (plain or base64) never appears in argv; it travels on stdin", !argvText.includes(REAL_TOKEN) && !argvText.includes(b64(REAL_TOKEN)) && cap.every((c) => typeof c.input === "string" && c.input.length > 0));
    }

    // ---------------------------------------------------------------------------------------------
    // 5. THE ATTACK, write path and read path, through the real client key store.
    // ---------------------------------------------------------------------------------------------
    {
      const planted = plantDir(base, "attack-write", marker.exe);
      const w = parseResult(runChild(KEYS_SCRIPT, [CLIENTKEYS_URL, "write", "attack", REAL_TOKEN], planted));
      assert("attack, write path: the planted exe did not run and never saw the plaintext token", !markerRan(planted) && w.ok === true, `ran=${markerRan(planted)} ${JSON.stringify(w).slice(0, 160)}`);
      const back = parseResult(runChild(KEYS_SCRIPT, [CLIENTKEYS_URL, "read", "attack"], root));
      assert("attack, write path: the stored key is a genuine blob that a clean cwd unwraps to the real token", back.ok === true && back.token === REAL_TOKEN, JSON.stringify(back).slice(0, 160));

      const planted2 = plantDir(base, "attack-read", marker.exe);
      const rd = parseResult(runChild(KEYS_SCRIPT, [CLIENTKEYS_URL, "read", "attack"], planted2));
      assert("attack, read path: the planted exe did not run (it never saw the DPAPI blob)", !markerRan(planted2), existsSync(markerFile(planted2)) ? readFileSync(markerFile(planted2), "utf8").trim() : "no marker");
      assert("attack, read path: the real stored token comes back, not the planted exe's output", rd.ok === true && rd.token === REAL_TOKEN && rd.token !== PLANTED_TOKEN, JSON.stringify(rd).slice(0, 160));
    }

    // ---------------------------------------------------------------------------------------------
    // 6. Fail closed: no PowerShell under SystemRoot, or a relative SystemRoot, throws and never falls back.
    // ---------------------------------------------------------------------------------------------
    {
      const planted = plantDir(base, "failclosed", marker.exe);
      const emptyRoot = join(base, "empty-systemroot");
      mkdirSync(emptyRoot, { recursive: true });
      const a = parseResult(runChild(FAILCLOSED_SCRIPT, [OSCRYPT_URL, emptyRoot], planted));
      assert("fail closed: a SystemRoot without PowerShell throws, spawns nothing and never runs the planted exe", typeof a.error === "string" && a.error.length > 0 && a.spawned === 0 && !markerRan(planted), JSON.stringify(a).slice(0, 200));
      assert("fail closed: the error does not echo the secret", typeof a.error === "string" && !a.error.includes("sb_FAKE_fail_closed_secret") && !a.error.includes(b64("sb_FAKE_fail_closed_secret")));
      clearMarkers(planted);
      const b = parseResult(runChild(FAILCLOSED_SCRIPT, [OSCRYPT_URL, "."], planted));
      assert("fail closed: a relative SystemRoot (resolving into the launch cwd) is refused and nothing runs", typeof b.error === "string" && b.error.length > 0 && b.spawned === 0 && !markerRan(planted), JSON.stringify(b).slice(0, 200));
    }

    // ---------------------------------------------------------------------------------------------
    // 7. End to end: a real `switchboard bridge` launched from the planted cwd sends the real token.
    // ---------------------------------------------------------------------------------------------
    {
      const seen = [];
      echo = createServer((req, res) => {
        let body = "";
        req.on("data", (c) => (body += c));
        req.on("end", () => {
          seen.push(String(req.headers.authorization ?? ""));
          let id = 1;
          try {
            id = JSON.parse(body).id ?? 1;
          } catch {
            /* keep the default id */
          }
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ jsonrpc: "2.0", id, result: { protocolVersion: "2025-11-25", capabilities: {}, serverInfo: { name: "oscrypt-echo", version: "0.0.0" } } }));
        });
      });
      await new Promise((resolve) => echo.listen(0, "127.0.0.1", resolve));
      const url = `http://127.0.0.1:${echo.address().port}/mcp`;

      // Store the real key (in a clean cwd, as `switchboard client add` would), then launch the bridge from a hostile cwd.
      const w = parseResult(runChild(KEYS_SCRIPT, [CLIENTKEYS_URL, "write", "e2e", REAL_TOKEN], root));
      assert("end to end: the client key was stored for the bridge", w.ok === true, JSON.stringify(w).slice(0, 160));
      const planted = plantDir(base, "e2e", marker.exe);
      const r = await driveBridge(["--client", "e2e", "--url", url], planted, { SWITCHBOARD_KEY: undefined });
      const reply = (() => {
        try {
          return JSON.parse(r.out.split("\n")[0]);
        } catch {
          return null;
        }
      })();
      assert("end to end: the bridge started from the planted cwd answered initialize", reply?.result?.serverInfo?.name === "oscrypt-echo", `exit=${r.code} out=${r.out.slice(0, 120)} err=${r.err.slice(0, 160)}`);
      assert("end to end: the planted exe never ran", !markerRan(planted));
      assert("end to end: the gateway received the REAL stored token as the bearer", seen.length > 0 && seen.every((h) => h === `Bearer ${REAL_TOKEN}`), JSON.stringify(seen));
      assert("end to end: the planted attacker token was never sent", seen.every((h) => !h.includes(PLANTED_TOKEN)));
      assert("end to end: no token on bridge stdout or stderr", !r.out.includes(REAL_TOKEN) && !r.err.includes(REAL_TOKEN) && !r.out.includes(PLANTED_TOKEN) && !r.err.includes(PLANTED_TOKEN));
    }
  } finally {
    if (echo) echo.close();
    await sleep(50);
    try {
      rmSync(base, { recursive: true, force: true });
    } catch {
      /* leftovers in temp are harmless */
    }
  }
}

let crashed = null;
try {
  await main();
} catch (err) {
  crashed = err;
  assert("oracle ran to completion without an unexpected exception", false, String(err && err.stack ? err.stack : err).slice(0, 400));
}

const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
process.exit(failed.length || crashed ? 1 : 0);
