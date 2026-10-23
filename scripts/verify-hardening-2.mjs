// Deterministic oracle for the wave-2 hardening closures: eleven review findings reproduced by the wave-1
// reviewers, each closed with a check that fails on the code that had the defect. Nothing here touches the
// operator's real state or a real service: isolated HOME / SWITCHBOARD_HOME, ephemeral loopback ports (never
// 8088), stub executables on a throwaway PATH instead of a real `npx`, an injected owner-presence provider
// (never a real Windows Hello prompt), every child process is killed. Build first (this imports from dist/).
//
//   1  router         a namespaced call to a tool the upstream never listed is SB_UNKNOWN_TOOL, never forwarded
//                     (tools/call, call_tool, batch_call), and the refusal is audited
//   2  server ids     ^[a-z0-9][a-z0-9_-]{0,63}$, no double underscore, unique; config load fails with the
//                     path of the bad id; the dashboard add path de-duplicates and keeps ids valid
//   3  package names  an npm (and PyPI) name pattern: no leading '-', no whitespace, no URLs or paths; new
//                     mounts (dashboard and catalog add) carry an exact version; an unpinned existing entry
//                     still mounts, with a loud warning from the startup log and from `doctor`
//   4  audit          write-ahead 'attempt' row before the upstream call for write and full scope, fail
//                     closed when it cannot be written, read scope keeps after-call logging, the final row
//                     references the attempt seq
//   5  remote MCP     source: remote goes through netguard (private and metadata targets, redirects)
//   6  path params    '.', '..' (and %2e spellings) never reach the URL parser as a path segment
//   7  log text       control characters stripped and length capped for DCR client_name and other provider
//                     strings echoed to the terminal
//   8  PUT settings   the merged config is validated with the zod schema before it is written
//   9  GET /mcp       405 with Allow: POST, never an unbounded SSE stream
//   10 kill off       the CLI and the dashboard clear the kill switch only after gateway-side presence
//   11 webhook        payloads carry the scrubbed error text
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, existsSync, renameSync, rmSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, delimiter } from "node:path";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import http from "node:http";
import net from "node:net";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dist = (f) => pathToFileURL(join(root, "dist", f)).href;
const CLI = join(root, "dist", "cli.js");
const FIXTURE_UP = join(root, "scripts", "fixtures", "approvals-upstream.mjs");

// ---- isolated environment (before any dist module is imported: HOME_DIR is read at import) ---------------------
const base = mkdtempSync(join(tmpdir(), "sb-hardening2-"));
const dirs = { home: join(base, "home"), appdata: join(base, "appdata"), local: join(base, "local"), tmp: join(base, "tmp"), stub: join(base, "stub") };
for (const d of Object.values(dirs)) mkdirSync(d, { recursive: true });
const SBHOME = join(dirs.home, ".switchboard");
Object.assign(process.env, {
  HOME: dirs.home,
  USERPROFILE: dirs.home,
  APPDATA: dirs.appdata,
  LOCALAPPDATA: dirs.local,
  TEMP: dirs.tmp,
  TMP: dirs.tmp,
  SWITCHBOARD_HOME: SBHOME,
  NO_COLOR: "1",
});
const SCRUB = /(_API_KEY|_API_SECRET|TOKEN|SECRET|PASSWORD|CREDENTIALS)$|^SWITCHBOARD_(AUTO_APPROVE|PROFILE|TOKEN|KEY|INSECURE_APPROVAL)$/i;
for (const k of Object.keys(process.env)) if (SCRUB.test(k)) delete process.env[k];

// A stub `npx` first on PATH: whatever the gateway launches as `npx -y <package>` is this script, which runs the
// local stdio fixture and records its argv. The real npx (and the registry behind it) is never reached.
const ARGV_LOG = join(dirs.stub, "argv.log");
writeFileSync(join(dirs.stub, "npx.cmd"), `@echo off\r\necho %* >> "${ARGV_LOG}"\r\nnode "${FIXTURE_UP}"\r\n`);
writeFileSync(join(dirs.stub, "npx"), `#!/bin/sh\necho "$@" >> "${ARGV_LOG}"\nexec node "${FIXTURE_UP}"\n`);
try {
  chmodSync(join(dirs.stub, "npx"), 0o755);
} catch {
  /* Windows has no mode bits */
}
process.env.PATH = `${dirs.stub}${delimiter}${process.env.PATH ?? ""}`;

const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond });
  const clean = String(detail).replace(/\x1b\[[0-9;]*[A-Za-z]/g, "").replace(/\s+/g, " ").trim();
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${!cond && clean ? `: ${clean.slice(0, 400)}` : ""}`);
};
const tryLoad = (p) => {
  try {
    return loadConfig(p);
  } catch {
    return null;
  }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const sha = (buf) => createHash("sha256").update(buf).digest("hex");
const tryImport = async (f) => {
  try {
    return await import(dist(f));
  } catch {
    return {};
  }
};

const { Router } = await import(dist("router.js"));
const { Registry } = await import(dist("registry.js"));
const { Vault } = await import(dist("vault.js"));
const { Gateway } = await import(dist("gateway.js"));
const { startDashboard } = await import(dist("dashboard.js"));
const { Approvals } = await import(dist("approvals.js"));
const AUD = await import(dist("audit.js"));
const { recentAudit, verifyAudit, usageStats } = AUD;
const KS = await import(dist("killswitch.js"));
const CFG = await import(dist("config.js"));
const { validateConfig, loadConfig, writeConfig } = CFG;
const { SB_ERR } = await import(dist("errors.js"));
const NG = await import(dist("netguard.js"));
const { buildDoctorReport } = await import(dist("doctor.js"));
const { buildHttpToolServer } = await import(dist("httptool.js"));
const { buildOpenApiServer } = await import(dist("openapi.js"));
const { LoginCodeStore } = await import(dist("httpsec.js"));
const CKEY = await import(dist("controlkey.js"));
const { loadCatalog } = await import(dist("catalog.js"));
const { log } = await import(dist("logger.js"));
const SAFE = await tryImport("safetext.js");
const PKG = await tryImport("packagespec.js");
const { Server } = await import("@modelcontextprotocol/sdk/server/index.js");
const { StreamableHTTPServerTransport } = await import("@modelcontextprotocol/sdk/server/streamableHttp.js");
const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
const { InMemoryTransport } = await import("@modelcontextprotocol/sdk/inMemory.js");
const { ListToolsRequestSchema, CallToolRequestSchema } = await import("@modelcontextprotocol/sdk/types.js");

// ---- helpers -------------------------------------------------------------------------------------------------------
const freePort = () =>
  new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });

/** Raw HTTP. Never rejects: a hung request is status 0 after `timeoutMs`, so the check fails instead of the oracle. */
function raw(port, method, path, { cookie, headers = {}, body, timeoutMs = 30_000 } = {}) {
  return new Promise((resolve) => {
    const h = { Host: `127.0.0.1:${port}`, ...headers };
    if (cookie) h.Cookie = cookie;
    let data;
    if (body !== undefined) {
      data = typeof body === "string" ? body : JSON.stringify(body);
      h["Content-Length"] = Buffer.byteLength(data);
      if (!Object.keys(h).some((k) => k.toLowerCase() === "content-type")) h["Content-Type"] = "application/json";
    }
    const req = http.request({ host: "127.0.0.1", port, method, path, headers: h, agent: false }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", (err) => resolve({ status: 0, headers: {}, body: "", error: String(err.message) }));
    req.setTimeout(timeoutMs, () => req.destroy(new Error(`timeout ${method} ${path}`)));
    if (data !== undefined) req.write(data);
    req.end();
  });
}
const jsonOf = (r) => {
  try {
    return JSON.parse(r.body);
  } catch {
    return {};
  }
};
const parseSb = (res) => {
  try {
    return JSON.parse(res.content?.[0]?.text ?? "");
  } catch {
    return {};
  }
};
const textOf = (res) => (res.content ?? []).map((c) => c.text ?? "").join(" ");

/** An in-process MCP upstream listing exactly `names`; every executed call is recorded. */
function makeUpstream(id, names, onCall) {
  const executed = [];
  const server = new Server({ name: id, version: "0.0.0" }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: names.map((n) => ({ name: n, description: n, inputSchema: { type: "object", properties: { text: { type: "string" } } } })),
  }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const entry = { name: req.params.name, args: req.params.arguments ?? {} };
    executed.push(entry);
    if (onCall) return onCall(entry);
    return { content: [{ type: "text", text: `done:${req.params.name}` }] };
  });
  return { server, executed };
}

/** A config object shaped like a validated one, with no approval required for any risk unless `approval` says so. */
const rcfg = (extra = {}, approval = { require_for_risk: [] }) => ({
  gateway: { transport: ["stdio"], http: { host: "127.0.0.1", port: 1, require_auth: "auto" }, tool_exposure: "namespaced", default_policy: "full", approval },
  vault: { backend: "env" },
  servers: [],
  settings: {},
  ...extra,
});

/** Capture everything written to stderr while `fn` runs. */
async function captureStderr(fn) {
  const real = process.stderr.write.bind(process.stderr);
  let text = "";
  process.stderr.write = (chunk, ...rest) => {
    text += typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf8");
    const cb = rest.find((r) => typeof r === "function");
    if (cb) cb();
    return true;
  };
  try {
    await fn();
  } finally {
    process.stderr.write = real;
  }
  return text;
}

function runCli(args) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], { env: { ...process.env, NO_COLOR: "1" }, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    const timer = setTimeout(() => child.kill(), 60_000);
    child.on("close", (status) => {
      clearTimeout(timer);
      resolve({ status, stdout: out, stderr: err });
    });
  });
}

const gateways = [];
const handles = [];
const servers = [];

try {
  // ===================================================================================================================
  // 1. ROUTER: a namespaced call to a tool the upstream never listed
  // ===================================================================================================================
  {
    const reg = new Registry(new Vault("env"));
    const up = makeUpstream("alpha", ["echo"]);
    await reg.mountLocal({ id: "alpha", source: "local", enabled: true, policy: "full" }, up.server);
    const router = new Router(reg, rcfg(), (r) => r);
    const ok = await router.callTool("alpha__echo", { text: "hi" });
    assert("1 a listed tool is forwarded", !ok.isError && textOf(ok) === "done:echo" && up.executed.length === 1);

    for (const name of ["alpha__wipe_database", "alpha__echo__x", "alpha__", "alpha__ECHO", "alpha__constructor"]) {
      const before = up.executed.length;
      const r = await router.callTool(name, { text: "x" });
      assert(`1 '${name}' (not listed by the upstream) is refused with SB_UNKNOWN_TOOL and never forwarded`, r.isError === true && parseSb(r).code === SB_ERR.UNKNOWN_TOOL && up.executed.length === before, textOf(r).slice(0, 160));
    }
    const rowsBefore = verifyAudit().rows;
    await router.callTool("alpha__probe_hidden_tool", {});
    const last = recentAudit(1)[0];
    assert("1 the refusal of an unlisted tool on a real server is audited as a deny with the code", verifyAudit().rows === rowsBefore + 1 && last?.server === "alpha" && last?.decision === "deny" && last?.error_code === SB_ERR.UNKNOWN_TOOL, JSON.stringify(last));
    const nobody = await router.callTool("nosuch__echo", {});
    assert("1 an unknown server stays SB_UNKNOWN_TOOL", nobody.isError && parseSb(nobody).code === SB_ERR.UNKNOWN_TOOL && up.executed.length === 1);

    const sr = new Router(reg, rcfg({ gateway: { ...rcfg().gateway, tool_exposure: "search" } }), (r) => r);
    const viaCall = await sr.callTool("call_tool", { name: "alpha__wipe_database", arguments: {} });
    const viaBatch = await sr.callTool("batch_call", { calls: [{ name: "alpha__wipe_database" }, { name: "alpha__echo", arguments: { text: "b" } }] });
    const results = parseSb(viaBatch).results ?? [];
    assert("1 call_tool of an unlisted name is refused", viaCall.isError && parseSb(viaCall).code === SB_ERR.UNKNOWN_TOOL && up.executed.every((e) => e.name === "echo"));
    assert("1 batch_call refuses the unlisted entry in place and still runs the listed one", results.length === 2 && results[0].isError === true && /SB_UNKNOWN_TOOL/.test(results[0].content?.[0]?.text ?? "") && results[1].isError === false, JSON.stringify(results).slice(0, 200));

    const flat = new Router(reg, rcfg({ gateway: { ...rcfg().gateway, tool_exposure: "flat" } }), (r) => r);
    assert("1 flat mode still refuses an unlisted bare name", (await flat.callTool("wipe_database", {})).isError && up.executed.every((e) => e.name === "echo"));
    await reg.unmountAll();
  }

  // ===================================================================================================================
  // 2. SERVER IDS
  // ===================================================================================================================
  {
    const err = (servers) => {
      try {
        validateConfig({ servers }, "oracle");
        return "";
      } catch (e) {
        return String(e.message);
      }
    };
    const srv = (id, extra = {}) => ({ id, source: "binary", command: "x", ...extra });
    const good = ["a", "a1", "a-b", "a_b", "a_b-c9", "0abc", "x".repeat(64)];
    for (const id of good) assert(`2 id '${id.length > 20 ? `${id.slice(0, 8)}...(${id.length})` : id}' is accepted`, err([srv(id)]) === "", err([srv(id)]));
    const bad = [
      ["Upper", "uppercase"],
      ["a__b", "double underscore"],
      ["a___b", "triple underscore"],
      ["_a", "leading underscore"],
      ["-a", "leading hyphen"],
      ["a b", "space"],
      ["a.b", "dot"],
      ["a/b", "slash"],
      ["a:b", "colon"],
      ["", "empty"],
      ["x".repeat(65), "65 characters"],
      ["caf\u00e9", "non-ascii"],
      ["a\nb", "newline"],
    ];
    for (const [id, why] of bad) {
      const m = err([srv(id)]);
      assert(`2 id with ${why} fails the config load and names the field`, m !== "" && /servers\.0\.id/.test(m) && /\^\[a-z0-9\]/.test(m), m.slice(0, 200));
    }
    const dup = err([srv("alpha"), srv("beta"), srv("alpha")]);
    assert("2 a duplicate id fails the config load, names the id and both positions", dup !== "" && /duplicate server id 'alpha'/.test(dup) && /servers\.2/.test(dup) && /servers\.0/.test(dup), dup.slice(0, 240));
    assert("2 two different ids load", err([srv("alpha"), srv("beta")]) === "");
    const yamlFile = join(base, "dup.yaml");
    writeFileSync(yamlFile, "servers:\n  - id: one\n    source: binary\n    command: x\n  - id: one\n    source: binary\n    command: y\n");
    let loadMsg = "";
    try {
      loadConfig(yamlFile);
    } catch (e) {
      loadMsg = String(e.message);
    }
    assert("2 loadConfig of a YAML file with a duplicate id fails and says why", /duplicate server id 'one'/.test(loadMsg), loadMsg.slice(0, 200));
    const u = CFG.uniqueServerId;
    const idOk = (id) => typeof id === "string" && /^[a-z0-9][a-z0-9_-]{0,63}$/.test(id) && !id.includes("__");
    if (typeof u !== "function") assert("2 uniqueServerId is exported", false);
    else {
      const long = u("mcp:" + "Very.Long/Name_".repeat(20), []);
      assert("2 uniqueServerId: a very long slug is cut to a valid id", idOk(long), long);
      const many = new Set();
      let allOk = true;
      let prev = "";
      for (let i = 0; i < 60; i++) {
        const id = u("mcp:" + "q".repeat(100), many);
        if (!idOk(id) || many.has(id)) allOk = false;
        many.add(id);
        prev = id;
      }
      assert("2 uniqueServerId: 60 collisions on a 100 character slug give 60 distinct valid ids", allOk && many.size === 60, prev);
      assert("2 uniqueServerId: strips the registry prefix and lowercases", u("mcp:io.github.Owner/Name", []) === "io-github-owner-name", u("mcp:io.github.Owner/Name", []));
      assert("2 uniqueServerId: a taken id gets -2", u("mcp:foo", ["foo"]) === "foo-2" && u("mcp:foo", ["foo", "foo-2"]) === "foo-3");
      assert("2 uniqueServerId: nothing usable falls back to 'toolkit'", u("mcp:!!!", []) === "toolkit" && idOk(u("mcp:\u00e9\u00e9", [])));
    }
  }

  // ===================================================================================================================
  // 3. PACKAGE STRINGS AND PINNING (pure)
  // ===================================================================================================================
  {
    const npxCfg = (pkg) => ({ servers: [{ id: "p", source: "npx", package: pkg }] });
    const loads = (pkg) => {
      try {
        validateConfig(npxCfg(pkg), "oracle");
        return true;
      } catch {
        return false;
      }
    };
    const badNpm = [
      "-y", "--registry=http://evil.example", "-c touch x", "pkg name", "pkg\tname", "pkg\nname", "", "@scope", "@scope/", "@/pkg", "pkg@",
      "pkg@ 1.2.3", "pkg@-1", "pkg@1.2.3 --yes", "../x", "git+https://evil.example/x.git", "github:user/repo", "file:../x", "https://evil.example/x.tgz",
      "pkg;rm", "pkg|x", "$(x)", "pkg&x", " pkg", "pkg ", "pkg@1.2.3\n", "a".repeat(215), "@Scope/pkg/extra",
    ];
    for (const p of badNpm) assert(`3 config refuses npx package ${JSON.stringify(p.length > 30 ? `${p.slice(0, 12)}...(${p.length})` : p)}`, !loads(p));
    const goodNpm = ["pkg", "pkg@1.2.3", "@scope/pkg", "@scope/pkg@1.2.3", "left-pad@1.3.0", "pkg@latest", "pkg@^1.2.0", "pkg@1.2.3-beta.1", "pkg@1.2.3+build.5", "my.pkg_name~x"];
    for (const p of goodNpm) assert(`3 config accepts npx package '${p}' (unpinned ones still load)`, loads(p));

    if (typeof PKG.checkNpmSpec !== "function") assert("3 packagespec module is present", false);
    else {
      assert("3 checkNpmSpec: null for a good spec, a reason for a bad one", PKG.checkNpmSpec("@a/b@1.0.0") === null && typeof PKG.checkNpmSpec("-y") === "string" && /'-'|hyphen|start/i.test(PKG.checkNpmSpec("-y")), String(PKG.checkNpmSpec("-y")));
      const pinned = ["pkg@1.2.3", "@s/p@1.2.3", "pkg@1.2.3-beta.1", "pkg@10.20.30+b.1", "pkg@0.0.0"];
      const floating = ["pkg", "@s/p", "pkg@latest", "pkg@^1.2.0", "pkg@~1.2.3", "pkg@1.2", "pkg@1", "pkg@1.x", "pkg@>=1.2.3", "pkg@1.2.3 "];
      for (const p of pinned) assert(`3 '${p}' is pinned to an exact version`, PKG.isPinnedNpmSpec(p) === true);
      for (const p of floating) assert(`3 '${p}' is not pinned`, PKG.isPinnedNpmSpec(p) === false);
      assert("3 npmPackageName strips the version, scoped or not", PKG.npmPackageName("@s/p@1.2.3") === "@s/p" && PKG.npmPackageName("pkg@1.2.3") === "pkg" && PKG.npmPackageName("pkg") === "pkg" && PKG.npmPackageName("@s/p") === "@s/p");
      const py = ["requests==2.32.3", "mcp-server_x==1.0.0", "pkg"];
      assert("3 PyPI: names and ==pins are accepted", py.every((p) => PKG.checkPypiSpec(p) === null));
      assert("3 PyPI: a leading '-', whitespace and URLs are refused", ["-r x", "--index-url=x", "pkg name", "git+https://x/y", "pkg==", "pkg==1.0 --pre", ""].every((p) => typeof PKG.checkPypiSpec(p) === "string"));
      assert("3 PyPI: only an exact == pin counts as pinned", PKG.isPinnedPypiSpec("pkg==1.2.3") === true && PKG.isPinnedPypiSpec("pkg") === false && PKG.isPinnedPypiSpec("pkg>=1") === false);
      const w = PKG.unpinnedPackageWarnings([
        { id: "floaty", source: "npx", package: "left-pad" },
        { id: "pinned", source: "npx", package: "left-pad@1.3.0" },
        { id: "remote", source: "remote", url: "https://x.example/mcp" },
        { id: "off", source: "npx", package: "other", enabled: false },
      ]);
      assert("3 unpinnedPackageWarnings names the floating npx servers only", w.length === 2 && /'floaty'/.test(w[0]) && /left-pad/.test(w[0]) && /exact version/.test(w[0]) && /'off'/.test(w[1]), JSON.stringify(w));
      assert("3 unpinnedPackageWarnings can be limited to enabled servers", PKG.unpinnedPackageWarnings([{ id: "off", source: "npx", package: "other", enabled: false }], { enabledOnly: true }).length === 0);
    }
  }

  // ===================================================================================================================
  // 3b. an unpinned existing entry still mounts, warns at startup and in doctor; a bad name never reaches npx
  // ===================================================================================================================
  {
    const cfg = rcfg({ servers: [{ id: "floaty", source: "npx", package: "left-pad", enabled: true, policy: "read" }] });
    const gw = new Gateway(cfg);
    gateways.push(gw);
    const err = await captureStderr(() => gw.mountAll());
    assert("3 an unpinned npx entry still mounts", gw.registry.has("floaty"), err.slice(0, 300));
    assert("3 ...and the startup log warns loudly about it, naming the server and the package", /floaty/.test(err) && /left-pad/.test(err) && /exact version|pin/i.test(err) && /!/.test(err), err.replace(/\x1b\[[0-9;]*m/g, "").slice(0, 400));
    const argv = existsSync(ARGV_LOG) ? readFileSync(ARGV_LOG, "utf8") : "";
    assert("3 the stub npx (not a real one) was launched as `npx -y <package>`", /-y"? "?left-pad/.test(argv), argv.slice(0, 200));
    await gw.shutdown();

    const rep = buildDoctorReport({
      cfg: rcfg({ servers: [{ id: "floaty", source: "npx", package: "left-pad" }, { id: "pinned", source: "npx", package: "left-pad@1.3.0" }] }),
      resolve: (v) => v,
    });
    const warns = rep.warnings ?? [];
    assert("3 doctor warns about the floating package and not about the pinned one", warns.length === 1 && /'floaty'/.test(warns[0]) && /left-pad/.test(warns[0]), JSON.stringify(warns));
    assert("3 the doctor warning does not turn a healthy report into a failing one", rep.ok === true && rep.problems.length === 0, JSON.stringify(rep.problems));

    const reg = new Registry(new Vault("env"));
    const argvBefore = existsSync(ARGV_LOG) ? readFileSync(ARGV_LOG, "utf8").length : 0;
    let msg = "";
    try {
      await reg.mount({ id: "evil", source: "npx", package: "--call=touch pwned", enabled: true });
    } catch (e) {
      msg = String(e.message);
    }
    const argvAfter = existsSync(ARGV_LOG) ? readFileSync(ARGV_LOG, "utf8").length : 0;
    assert("3 mounting a package string that starts with '-' is refused before anything is spawned", /package/i.test(msg) && argvAfter === argvBefore && !reg.has("evil"), `${msg.slice(0, 160)} argv grew ${argvAfter - argvBefore}`);
    await reg.unmountAll();
  }

  // ===================================================================================================================
  // 4. AUDIT WRITE-AHEAD
  // ===================================================================================================================
  {
    const seen = [];
    const up = makeUpstream("store", ["list_items", "save_note", "delete_item", "fail_note"], (entry) => {
      const last = recentAudit(1)[0];
      seen.push({ tool: entry.name, last: last ? { phase: last.phase, tool: last.tool, seq: last.seq, server: last.server } : null });
      if (entry.name === "fail_note") throw new Error("upstream exploded");
      return { content: [{ type: "text", text: `done:${entry.name}` }] };
    });
    const reg = new Registry(new Vault("env"));
    await reg.mountLocal({ id: "store", source: "local", enabled: true, policy: "full" }, up.server);
    const router = new Router(reg, rcfg({ settings: { logs: { capture_io: true } } }), (r) => r);

    const n0 = verifyAudit().rows;
    const u0 = usageStats().total;
    const w = await router.callTool("store__save_note", { text: "alpha" });
    const rows1 = verifyAudit().rows - n0;
    const finalRow = recentAudit(1)[0];
    const attemptRow = recentAudit(2)[1];
    assert("4 a write call succeeds and writes two rows: the attempt, then the result", !w.isError && rows1 === 2, `rows ${rows1}`);
    assert("4 the attempt row is on disk BEFORE the upstream runs (the upstream saw it as the newest row)", seen[0]?.last?.phase === "attempt" && seen[0]?.last?.tool === "save_note" && seen[0]?.last?.server === "store", JSON.stringify(seen[0]));
    assert("4 the attempt row carries the scope and the captured arguments", attemptRow?.phase === "attempt" && attemptRow?.scope === "write" && attemptRow?.decision === "allow" && same(attemptRow?.request, { text: "alpha" }), JSON.stringify(attemptRow));
    assert("4 the final row references the attempt seq and is the normal result row", finalRow?.attempt_seq === attemptRow?.seq && finalRow?.phase === undefined && finalRow?.decision === "allow" && typeof finalRow?.duration_ms === "number", JSON.stringify(finalRow));
    assert("4 usage stats count the call once, not twice", usageStats().total - u0 === 1, `delta ${usageStats().total - u0}`);

    const n1 = verifyAudit().rows;
    const d = await router.callTool("store__delete_item", { text: "x" });
    assert("4 a full-scope call is also written ahead", !d.isError && verifyAudit().rows - n1 === 2 && seen.at(-1)?.last?.phase === "attempt" && recentAudit(1)[0]?.attempt_seq === seen.at(-1)?.last?.seq, JSON.stringify(seen.at(-1)));

    const n2 = verifyAudit().rows;
    const r = await router.callTool("store__list_items", {});
    assert("4 a read-scope call keeps after-call logging: one row, no attempt, no attempt_seq", !r.isError && verifyAudit().rows - n2 === 1 && seen.at(-1)?.last?.phase !== "attempt" && recentAudit(1)[0]?.attempt_seq === undefined, JSON.stringify(seen.at(-1)));

    const n3 = verifyAudit().rows;
    const f = await router.callTool("store__fail_note", {});
    assert("4 a write call whose upstream throws: the error row still references the attempt", f.isError && verifyAudit().rows - n3 === 2 && recentAudit(1)[0]?.error_code === SB_ERR.UPSTREAM_ERROR && recentAudit(1)[0]?.attempt_seq === recentAudit(2)[1]?.seq && recentAudit(2)[1]?.phase === "attempt", JSON.stringify(recentAudit(2)));

    // fail closed: the audit log cannot be written
    const logPath = join(SBHOME, "audit.log");
    const parked = `${logPath}.parked`;
    renameSync(logPath, parked);
    mkdirSync(logPath);
    let wRes;
    let rRes;
    let execBefore;
    const stderr = await captureStderr(async () => {
      execBefore = up.executed.length;
      wRes = await router.callTool("store__save_note", { text: "must not run" });
      rRes = await router.callTool("store__list_items", {});
    });
    const wBody = parseSb(wRes);
    assert("4 a write call is REFUSED when the attempt row cannot be written (SB_AUDIT_FAILED)", wRes.isError === true && wBody.code === SB_ERR.AUDIT_FAILED, textOf(wRes).slice(0, 200));
    assert("4 ...and the upstream was never called for it", up.executed.length === execBefore + 1 && up.executed.at(-1)?.name === "list_items", JSON.stringify(up.executed.slice(-2)));
    assert("4 a read call still succeeds with a broken audit log (after-call logging only)", rRes.isError !== true && textOf(rRes) === "done:list_items");
    assert("4 the failure is logged loudly", /audit/i.test(stderr), stderr.replace(/\x1b\[[0-9;]*m/g, "").slice(0, 200));
    rmSync(logPath, { recursive: true, force: true });
    renameSync(parked, logPath);
    const w2 = await router.callTool("store__save_note", { text: "after repair" });
    const ver = verifyAudit({ all: true });
    assert("4 after the log is back, write calls run again and the hash chain verifies", !w2.isError && ver.ok === true, JSON.stringify(ver.break ?? {}));

    // a gated call: no attempt while it waits, the attempt carries the approval id once it runs
    const approvals = new Approvals({ path: join(SBHOME, "ap-h2.json"), presence: async () => ({ ok: true, method: "none" }) });
    const gated = new Router(reg, rcfg({}, { require_for_risk: ["high"] }), (x) => x, approvals);
    const attemptsBefore = recentAudit(500).filter((x) => x.phase === "attempt").length;
    const pend = await gated.callTool("store__delete_item", { text: "g" });
    const apId = parseSb(pend).approval_id;
    assert("4 a call waiting for approval writes no attempt row", pend.isError && parseSb(pend).code === SB_ERR.APPROVAL_PENDING && recentAudit(500).filter((x) => x.phase === "attempt").length === attemptsBefore);
    const ap = await approvals.approve(apId, "cli");
    const ran = await gated.callTool("store__delete_item", { text: "g" });
    const att = recentAudit(2)[1];
    const fin = recentAudit(1)[0];
    assert("4 once approved it runs; attempt and result rows both carry the approval id and the risk", ap.ok && !ran.isError && att?.phase === "attempt" && att?.approval_id === apId && att?.risk === "high" && fin?.approval_id === apId && fin?.attempt_seq === att?.seq, JSON.stringify([att, fin]));
    await reg.unmountAll();
  }

  // ===================================================================================================================
  // 5. REMOTE MCP UPSTREAMS GO THROUGH NETGUARD
  // ===================================================================================================================
  {
    /** A real Streamable HTTP MCP server on loopback (stateless, one Server per request). `mode` can redirect. */
    const startStub = async (mode = {}) => {
      const hits = [];
      const srv = http.createServer(async (req, res) => {
        hits.push({ method: req.method, url: req.url, auth: req.headers.authorization ?? null });
        if (mode.redirectTo) {
          res.writeHead(307, { location: mode.redirectTo });
          res.end();
          return;
        }
        if (req.method !== "POST") {
          res.writeHead(405, { allow: "POST" });
          res.end();
          return;
        }
        const chunks = [];
        for await (const c of req) chunks.push(c);
        const server = new Server({ name: "remote-stub", version: "0.0.0" }, { capabilities: { tools: {} } });
        server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [{ name: "ping", description: "ping", inputSchema: { type: "object" } }] }));
        server.setRequestHandler(CallToolRequestSchema, async () => ({ content: [{ type: "text", text: "pong" }] }));
        const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
        res.on("close", () => void transport.close());
        await server.connect(transport);
        await transport.handleRequest(req, res, JSON.parse(Buffer.concat(chunks).toString("utf8")));
      });
      await new Promise((r) => srv.listen(0, "127.0.0.1", r));
      servers.push(srv);
      return { port: srv.address().port, hits, close: () => new Promise((r) => srv.close(r)) };
    };
    const tryMount = async (network, url, id = "rem") => {
      const reg = new Registry(new Vault("env"), undefined, () => network);
      try {
        await reg.mount({ id, source: "remote", url, enabled: true, auth: "none" });
        return { reg, ok: true, msg: "" };
      } catch (e) {
        return { reg, ok: false, msg: String(e.message) };
      }
    };

    const stub = await startStub();
    const blocked = await tryMount(undefined, `http://127.0.0.1:${stub.port}/mcp`);
    assert("5 a remote upstream on a loopback address is refused by default, with the allow_private hint", !blocked.ok && /blocked/i.test(blocked.msg) && /allow_private/.test(blocked.msg), blocked.msg.slice(0, 240));
    assert("5 ...and the refused target never received a connection", stub.hits.length === 0, JSON.stringify(stub.hits));
    const byName = await tryMount(undefined, `http://localhost:${stub.port}/mcp`);
    assert("5 the name 'localhost' is refused too", !byName.ok && /localhost|blocked/i.test(byName.msg) && stub.hits.length === 0, byName.msg.slice(0, 200));
    const meta = await tryMount(undefined, "http://169.254.169.254/latest/meta-data/mcp");
    assert("5 the cloud metadata address is refused", !meta.ok && /blocked|metadata|link-local/i.test(meta.msg), meta.msg.slice(0, 200));
    const lan = await tryMount(undefined, "http://10.0.0.5:9/mcp");
    assert("5 an RFC1918 address is refused", !lan.ok && /blocked|private/i.test(lan.msg), lan.msg.slice(0, 200));
    const noDeny = await tryMount({ allow_private: ["127.0.0.1"] }, `http://localhost:${stub.port}/mcp`);
    assert("5 allow_private is an exact-host list: allowing 127.0.0.1 does not allow 'localhost'", !noDeny.ok && stub.hits.length === 0, noDeny.msg.slice(0, 200));

    const allowed = await tryMount({ allow_private: ["127.0.0.1"] }, `http://127.0.0.1:${stub.port}/mcp`);
    assert("5 with the exact host in allow_private the remote upstream mounts and lists its tool (POST, SSE reply, through the guard)", allowed.ok && allowed.reg.get("rem")?.tools.some((t) => t.name === "ping"), allowed.msg.slice(0, 240));
    let called = null;
    if (allowed.ok) {
      const router = new Router(allowed.reg, rcfg({ servers: [] }), (x) => x);
      called = await router.callTool("rem__ping", {});
    }
    assert("5 ...and a governed call to it works end to end", called && !called.isError && textOf(called) === "pong", called ? textOf(called) : "no call");
    await allowed.reg.unmountAll();

    const hostile = await startStub({ redirectTo: "http://169.254.169.254/latest/meta-data/" });
    const red = await tryMount({ allow_private: ["127.0.0.1"] }, `http://127.0.0.1:${hostile.port}/mcp`);
    assert("5 an upstream that redirects to the metadata address is refused (the SDK's same-origin policy, with the guard behind it)", !red.ok && /redirect/i.test(red.msg), red.msg.slice(0, 240));
    await blocked.reg.unmountAll();

    // the guard's own entry point
    if (typeof NG.guardedMcpFetch !== "function") assert("5 netguard exports guardedMcpFetch", false);
    else {
      const f = NG.guardedMcpFetch({ allow_private: ["127.0.0.1"] });
      const ac = new AbortController();
      const res = await f(`http://127.0.0.1:${stub.port}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }), signal: ac.signal });
      assert("5 guardedMcpFetch returns a streaming Response (headers first, body readable)", res instanceof Response && res.status >= 200 && res.body !== null);
      ac.abort();
      let abortedCleanly = true;
      try {
        await res.text();
      } catch (e) {
        abortedCleanly = e?.name === "AbortError" || /abort/i.test(String(e?.message));
      }
      assert("5 aborting the caller signal ends the body with an abort error, not a hang", abortedCleanly);
      let refusal = "";
      try {
        await NG.guardedMcpFetch(undefined)("http://127.0.0.1:1/x", { method: "GET" });
      } catch (e) {
        refusal = String(e.message);
      }
      assert("5 guardedMcpFetch refuses a private target without allow_private", /blocked/i.test(refusal), refusal);
      // a hostile upstream that answers 307 with a Location on the metadata address
      let hop = "";
      try {
        await f(`http://127.0.0.1:${hostile.port}/mcp`, { method: "GET" });
      } catch (e) {
        hop = String(e.message);
      }
      assert("5 the guard follows redirects itself and refuses a hop to the metadata address", /redirect/i.test(hop) && /blocked|metadata|link-local/i.test(hop), hop.slice(0, 240));
      const manual = await f(`http://127.0.0.1:${hostile.port}/mcp`, { method: "GET", redirect: "manual" });
      assert("5 redirect: manual hands the 3xx back unfollowed (the SDK applies its own policy and calls again)", manual.status === 307 && /169\.254\.169\.254/.test(manual.headers.get("location") ?? ""), `${manual.status}`);
      await manual.body?.cancel().catch(() => {});
    }
    await stub.close();
    await hostile.close();
  }

  // ===================================================================================================================
  // 6. PATH PARAMETERS
  // ===================================================================================================================
  {
    assert("6 fact: the URL parser collapses %2e%2e like '..', so encoding dots is not a fix", new URL("https://h.test/a/b/%2E%2e/c").pathname === "/a/c" && new URL("https://h.test/a/b/../c").pathname === "/a/c");
    const captured = [];
    const restore = NG.useFetchStubForTests(() => async (url, init) => {
      captured.push({ url: String(url), method: init?.method });
      return new Response("{}", { status: 200, statusText: "OK" });
    });
    const open = async (generated) => {
      const [ct, st] = InMemoryTransport.createLinkedPair();
      const client = new Client({ name: "h2", version: "0.0.0" });
      await generated.server.connect(st);
      await client.connect(ct);
      return client;
    };
    try {
      const ht = await buildHttpToolServer(
        { id: "h", source: "http-tool", base_url: "https://api.test/v1", http_tools: [{ name: "get_item", method: "GET", path: "/items/{id}/detail" }, { name: "get_abs", method: "GET", url: "https://api.test/v1/x/{id}" }] },
        async () => ({}),
      );
      const hc = await open(ht);
      const call = async (tool, id) => {
        const n = captured.length;
        const r = await hc.callTool({ name: tool, arguments: { id } });
        return { r, sent: captured.length - n, url: captured.at(-1)?.url };
      };
      for (const bad of ["..", "."]) {
        const x = await call("get_item", bad);
        assert(`6 http-tool: path parameter '${bad}' is refused and no request is made`, x.r.isError === true && x.sent === 0 && /path parameter/i.test(textOf(x.r)), `${textOf(x.r).slice(0, 120)} sent ${x.sent}`);
      }
      const abs = await call("get_abs", "..");
      assert("6 http-tool: the same refusal for a tool with an absolute url", abs.r.isError === true && abs.sent === 0);
      const ok = await call("get_item", "42");
      assert("6 http-tool: an ordinary value is substituted", !ok.r.isError && ok.url === "https://api.test/v1/items/42/detail", ok.url);
      const slash = await call("get_item", "a/../../x");
      assert("6 http-tool: a value with slashes stays ONE encoded segment", !slash.r.isError && new URL(slash.url).pathname === "/v1/items/a%2F..%2F..%2Fx/detail", slash.url);
      const pct = await call("get_item", "%2e%2e");
      assert("6 http-tool: a pre-encoded dot segment is escaped, not decoded by the parser", !pct.r.isError && new URL(pct.url).pathname === "/v1/items/%252e%252e/detail", pct.url);
      const dots = await call("get_item", "...");
      assert("6 http-tool: three dots is an ordinary name (only '.' and '..' are dot segments)", !dots.r.isError && new URL(dots.url).pathname === "/v1/items/.../detail", dots.url);
      await hc.close();

      const spec = {
        openapi: "3.0.0",
        info: { title: "P", version: "1" },
        servers: [{ url: "https://api.pet.test/v1" }],
        paths: { "/pet/{petId}": { get: { operationId: "getpetbyid", parameters: [{ name: "petId", in: "path", required: true, schema: { type: "string" } }] } } },
      };
      const specFile = join(base, "pet.json");
      writeFileSync(specFile, JSON.stringify(spec));
      const oa = await open(await buildOpenApiServer({ id: "t", source: "app2mcp", openapi: specFile }, async () => ({})));
      const tool = (await oa.listTools()).tools[0].name;
      for (const bad of ["..", "."]) {
        const n = captured.length;
        const r = await oa.callTool({ name: tool, arguments: { petId: bad } });
        assert(`6 app2mcp: path parameter '${bad}' is refused and no request is made`, r.isError === true && captured.length === n && /path parameter/i.test(textOf(r)), `${textOf(r).slice(0, 120)} sent ${captured.length - n}`);
      }
      const n = captured.length;
      const good = await oa.callTool({ name: tool, arguments: { petId: "7" } });
      assert("6 app2mcp: an ordinary value still works", !good.isError && captured.length === n + 1 && captured.at(-1).url === "https://api.pet.test/v1/pet/7", captured.at(-1)?.url);
      const arr = await oa.callTool({ name: tool, arguments: { petId: ["..", "x"] } });
      assert("6 app2mcp: an array value is checked as one joined segment ('..,x' is an ordinary name)", !arr.isError && captured.at(-1).url === "https://api.pet.test/v1/pet/..%2Cx", captured.at(-1)?.url);
      await oa.close();
    } finally {
      restore();
    }
  }

  // ===================================================================================================================
  // 7. LOG AND TERMINAL TEXT FROM PROVIDERS
  // ===================================================================================================================
  {
    const evil = "ok\x1b]0;pwned\x07\x1b[2J\x1b[31mred\x00\x08\x7f\u0085\u202e\u2028end";
    if (typeof SAFE.safeText !== "function") assert("7 safetext module is present", false);
    else {
      const s = SAFE.safeText(evil, 200);
      assert("7 safeText strips escapes, C0, DEL, C1, bidi and line separators", !/[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069\u2028\u2029]/.test(s) && s.includes("ok") && s.includes("end"), JSON.stringify(s));
      const cap = SAFE.safeText("A".repeat(5000), 100);
      assert("7 safeText caps the length (with a marker)", cap.length <= 110 && cap.length >= 100 && /\u2026|\.\.\.|\[/.test(cap.slice(-14)), `${cap.length} ${cap.slice(-12)}`);
      assert("7 safeText turns newlines into spaces and passes ordinary text through", SAFE.safeText("a\nb\r\nc") === "a b c" && SAFE.safeText("Claude Code 1.2") === "Claude Code 1.2");
      assert("7 safeText accepts non-strings", SAFE.safeText(undefined) === "" && SAFE.safeText(42) === "42" && SAFE.safeText(null) === "");
    }
    const lines = await captureStderr(async () => {
      log.info(`provider says ${evil}`);
      log.warn(`and ${"\x1b[1A\x1b[2K"}rewrites the previous line`);
    });
    const body = lines.replace(/\x1b\[(?:90|36|33|32|31|0)m/g, "");
    assert("7 the logger itself neutralises escape sequences inside a message (only its own colour codes remain)", !/\x1b|\x07|\x00|\u202e|\x7f/.test(body) && /provider says/.test(body) && /rewrites the previous line/.test(body), JSON.stringify(body).slice(0, 240));

    // DCR over HTTP with the OAuth server on
    const port = await freePort();
    const cfg = validateConfig(
      { gateway: { transport: ["http"], http: { host: "127.0.0.1", port, require_auth: "auto" } }, servers: [], settings: { oauth_server: { enabled: true, public_url: "https://sb.example.test", consent: true } } },
      "oracle",
    );
    const gw = new Gateway(cfg);
    gateways.push(gw);
    const dash = await startDashboard(gw, cfg);
    handles.push(dash);
    const name = `evil\x1b]0;pwned\x07\x1b[2J${"N".repeat(5000)}`;
    let reg;
    const err = await captureStderr(async () => {
      reg = await raw(port, "POST", "/register", { body: { client_name: name, redirect_uris: ["http://127.0.0.1:7777/callback"], token_endpoint_auth_method: "none", grant_types: ["authorization_code"], response_types: ["code"] } });
    });
    const clean = err.replace(/\x1b\[(?:90|36|33|32|31|0)m/g, "");
    const regLine = clean.split("\n").find((l) => /registered OAuth client/.test(l)) ?? "";
    assert("7 DCR with a hostile client_name succeeds (the name is data)", reg.status === 201, `${reg.status} ${reg.body.slice(0, 120)}`);
    assert("7 the registration log line carries no control characters", regLine !== "" && !/[\x00-\x1f\x7f-\x9f]/.test(regLine.replace(/\n$/, "")), JSON.stringify(regLine.slice(0, 160)));
    assert("7 ...and is length capped (the name was 5000 characters)", regLine.length > 0 && regLine.length < 400, `length ${regLine.length}`);
    const pageFor = async (clientId) =>
      raw(port, "GET", `/authorize?response_type=code&client_id=${encodeURIComponent(clientId ?? "x")}&redirect_uri=${encodeURIComponent("http://127.0.0.1:7777/callback")}&code_challenge=${"A".repeat(43)}&code_challenge_method=S256&state=s&scope=read&resource=${encodeURIComponent("https://sb.example.test/mcp")}`);
    const shortReg = await raw(port, "POST", "/register", { body: { client_name: "ok-client", redirect_uris: ["http://127.0.0.1:7777/callback"], token_endpoint_auth_method: "none", grant_types: ["authorization_code"], response_types: ["code"] } });
    const longPage = await pageFor(jsonOf(reg).client_id);
    const shortPage = await pageFor(jsonOf(shortReg).client_id);
    assert("7 the sign-in page for the 5000 character name is about as long as the page for a short name", longPage.status === 401 && shortPage.status === 401 && longPage.body.length <= shortPage.body.length + 400, `long ${longPage.body.length} short ${shortPage.body.length}`);
    assert("7 ...and carries no control character", !/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(longPage.body));
  }

  // ===================================================================================================================
  // 8, 9, 10 + add route: one in-process gateway with an injected presence provider
  // ===================================================================================================================
  {
    const port = await freePort();
    const cfgPath = join(base, "dash.yaml");
    const cfg = validateConfig({ gateway: { transport: ["http"], http: { host: "127.0.0.1", port, require_auth: "auto" } }, servers: [], settings: { general: { organization_name: "Local" } } }, "oracle");
    writeConfig(cfgPath, cfg);
    const prompts = [];
    const st = { ok: true };
    const approvals = new Approvals({
      path: join(SBHOME, "approvals.json"),
      presence: async (m) => {
        prompts.push(m);
        return st.ok ? { ok: true, method: "none" } : { ok: false, method: "hello", reason: "declined" };
      },
    });
    const gw = new Gateway(cfg, { approvals });
    gateways.push(gw);
    const dash = await startDashboard(gw, cfg, cfgPath);
    handles.push(dash);
    const code = new LoginCodeStore().mint();
    const sessRes = await raw(port, "POST", "/api/session", { body: { code } });
    const sid = /switchboard_session=([^;]+)/.exec(sessRes.headers["set-cookie"]?.[0] ?? "")?.[1];
    const withS = { cookie: `switchboard_session=${sid}` };
    const withC = { cookie: `switchboard_session=${sid}`, headers: { "x-switchboard-csrf": jsonOf(sessRes).csrf } };
    assert("setup: an owner session was established", !!sid && !!jsonOf(sessRes).csrf);

    // ---- 8. PUT /api/settings --------------------------------------------------------------------------------------
    const fileHash = () => sha(readFileSync(cfgPath));
    const snapshot = async () => (await raw(port, "GET", "/api/settings", withS)).body;
    const h0 = fileHash();
    const s0 = await snapshot();
    const invalidBodies = [
      ["an unknown require_auth value", { gateway: { require_auth: "sometimes" } }],
      ["an unknown default_policy", { gateway: { default_policy: "root" } }],
      ["an unknown tool_exposure", { gateway: { tool_exposure: "everything" } }],
      ["an unknown webhook event", { settings: { webhook: { events: ["bogus"] } } }],
      ["a number as organization_name", { settings: { general: { organization_name: 123 } } }],
      ["an unknown key under general", { settings: { general: { surprise: "x" } } }],
      ["an unknown key under webhook", { settings: { webhook: { enabled: true, targets: ["x"] } } }],
    ];
    for (const [why, body] of invalidBodies) {
      const r = await raw(port, "PUT", "/api/settings", { ...withC, body });
      assert(`8 PUT /api/settings with ${why} is a 400`, r.status === 400, `${r.status} ${r.body.slice(0, 200)}`);
      assert(`8 ...and the file on disk is byte-for-byte unchanged, and the live settings too`, fileHash() === h0 && (await snapshot()) === s0);
    }
    let reload = "";
    try {
      loadConfig(cfgPath);
    } catch (e) {
      reload = String(e.message);
    }
    assert("8 the config file still loads after the refused writes", reload === "", reload.slice(0, 200));
    const bad400 = await raw(port, "PUT", "/api/settings", { ...withC, body: { gateway: { require_auth: "sometimes" } } });
    assert("8 the 400 names the problem", /require_auth/.test(bad400.body), bad400.body.slice(0, 240));

    const goodPut = await raw(port, "PUT", "/api/settings", { ...withC, body: { settings: { general: { organization_name: "Acme" } }, gateway: { require_auth: "always" } } });
    assert("8 a valid update is accepted", goodPut.status === 200 && jsonOf(goodPut).ok === true, `${goodPut.status} ${goodPut.body.slice(0, 160)}`);
    const re = tryLoad(cfgPath) ?? { settings: {}, gateway: { http: {} } };
    assert("8 ...written to disk, loadable, with the new values, and the previous file kept as .bak", re.settings?.general?.organization_name === "Acme" && re.gateway.http.require_auth === "always" && existsSync(`${cfgPath}.bak`) && fileHash() !== h0);

    // ---- 9. GET /mcp ------------------------------------------------------------------------------------------------
    const noKey = await raw(port, "GET", "/mcp", { headers: { accept: "text/event-stream" }, timeoutMs: 3000 });
    assert("9 with auth required, an unauthenticated GET /mcp is still 401 (auth comes first)", noKey.status === 401, `${noKey.status}`);
    await raw(port, "PUT", "/api/settings", { ...withC, body: { gateway: { require_auth: "auto" } } });
    const getMcp = await raw(port, "GET", "/mcp", { headers: { accept: "text/event-stream" }, timeoutMs: 3000 });
    assert("9 GET /mcp answers 405 at once (no SSE stream is opened)", getMcp.status === 405, `${getMcp.status} ${getMcp.error ?? ""}`);
    assert("9 ...with Allow: POST", /^POST$/i.test(String(getMcp.headers.allow ?? "").trim()), String(getMcp.headers.allow));
    const getPlain = await raw(port, "GET", "/mcp", { timeoutMs: 3000 });
    assert("9 a GET without an Accept header gets the same 405", getPlain.status === 405 && /POST/i.test(String(getPlain.headers.allow ?? "")));
    const init = await raw(port, "POST", "/mcp", {
      headers: { accept: "application/json, text/event-stream", "content-type": "application/json" },
      body: { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "h2", version: "0" } } },
      timeoutMs: 10_000,
    });
    assert("9 POST /mcp is unaffected (initialize answers 200)", init.status === 200 && /serverInfo/.test(init.body), `${init.status} ${init.body.slice(0, 120)}`);

    // ---- the dashboard add route: ids (2) and pinned versions (3) --------------------------------------------------
    const catalog = loadCatalog();
    const tkN = catalog.toolkits.find((t) => t.mount.source === "npx");
    const tkR = catalog.toolkits.find((t) => t.mount.source === "remote");
    const ids = async () => (jsonOf(await raw(port, "GET", "/api/state", withS)).servers ?? []).map((s) => s.id);
    const idOk = (id) => typeof id === "string" && /^[a-z0-9][a-z0-9_-]{0,63}$/.test(id) && !id.includes("__");
    if (!tkN || !tkR) assert("add: the shipped catalog has an npx and a remote toolkit", false);
    else {
      const slugN = encodeURIComponent(tkN.slug);
      const n0 = (await ids()).length;
      const unpinned = await raw(port, "POST", `/api/toolkits/${slugN}/add`, { ...withC, body: {} });
      assert("3 adding an npx toolkit with no pinned version is refused (400, a code, and the way out)", unpinned.status === 400 && /SB_PACKAGE_UNPINNED/.test(unpinned.body) && /version/i.test(jsonOf(unpinned).error ?? ""), `${unpinned.status} ${unpinned.body.slice(0, 200)}`);
      assert("3 ...and nothing was added or written", (await ids()).length === n0 && (tryLoad(cfgPath)?.servers.length ?? -1) === n0);
      for (const v of ["latest", "1.2", "1", "^1.2.3", "1.2.3 --registry=http://evil.example", "-1.2.3", "1.2.3\n--yes", "", "x".repeat(300)]) {
        const r = await raw(port, "POST", `/api/toolkits/${slugN}/add`, { ...withC, body: { version: v } });
        assert(`3 add with version ${JSON.stringify(v.length > 20 ? `${v.slice(0, 10)}...` : v)} is refused`, r.status === 400 && (await ids()).length === n0, `${r.status} ${r.body.slice(0, 120)}`);
      }
      const a1 = await raw(port, "POST", `/api/toolkits/${slugN}/add`, { ...withC, body: { version: "1.2.3" } });
      const s1 = jsonOf(a1).server ?? {};
      assert("3 with an exact version the toolkit is added as <package>@<version>, disabled", a1.status === 200 && s1.package === `${tkN.mount.package}@1.2.3` && s1.enabled === false, `${a1.status} ${a1.body.slice(0, 200)}`);
      const a2 = await raw(port, "POST", `/api/toolkits/${slugN}/add`, { ...withC, body: { version: "1.2.3" } });
      const a3 = await raw(port, "POST", `/api/toolkits/${slugN}/add`, { ...withC, body: { version: "2.0.0-rc.1" } });
      const all = await ids();
      assert("2 adding the same toolkit again de-duplicates the id (three adds, three distinct valid ids)", a2.status === 200 && a3.status === 200 && new Set(all).size === all.length && all.length === n0 + 3 && all.every(idOk), JSON.stringify(all));
      let disk = "";
      try {
        const d = loadConfig(cfgPath);
        disk = d.servers.length === n0 + 3 && d.servers.every((s) => s.package?.startsWith(`${tkN.mount.package}@`)) ? "" : "unexpected servers";
      } catch (e) {
        disk = String(e.message);
      }
      assert("2 what the add route wrote still passes the strict config load", disk === "", disk.slice(0, 200));
      const rr = await raw(port, "POST", `/api/toolkits/${encodeURIComponent(tkR.slug)}/add`, { ...withC, body: {} });
      assert("2 a remote toolkit is added with a valid id and needs no version", rr.status === 200 && idOk(jsonOf(rr).id), rr.body.slice(0, 200));
      const toolkitsView = jsonOf(await raw(port, "GET", `/api/toolkits?q=${encodeURIComponent(tkN.name)}&limit=200`, withS));
      assert("3 a versioned server still correlates to its catalog entry (badged as mounted)", (toolkitsView.items ?? []).some((t) => t.slug === tkN.slug && t.mounted === true), JSON.stringify((toolkitsView.items ?? []).map((t) => [t.slug, t.mounted])).slice(0, 200));
    }

    // ---- 10. kill off ------------------------------------------------------------------------------------------------
    const killPath = KS.killFilePath();
    KS.setKillFile(false);
    KS.setKillFile(true);
    const pk = prompts.length;
    st.ok = false;
    const dOff1 = await raw(port, "POST", "/api/kill", { ...withC, body: { on: false } });
    assert("10 dashboard: turning the kill switch off needs gateway presence (refused presence keeps it on)", dOff1.status === 403 && existsSync(killPath) && prompts.length === pk + 1 && /kill switch/i.test(prompts.at(-1)));
    const ctlToken = CKEY.readControlKey();
    const ctl = { headers: { authorization: `Bearer ${ctlToken}` } };
    assert("10 control API: kill/off without a credential is 401, with an owner session alone is 401", (await raw(port, "POST", "/api/control/kill/off", { body: {} })).status === 401 && (await raw(port, "POST", "/api/control/kill/off", { ...withC, body: {} })).status === 401 && existsSync(killPath));
    const c1 = await raw(port, "POST", "/api/control/kill/off", { ...ctl, body: {} });
    assert("10 control API: kill/off with a refused presence check is 403 and the switch stays on", c1.status === 403 && jsonOf(c1).code === "SB_PRESENCE_FAILED" && existsSync(killPath), `${c1.status} ${c1.body.slice(0, 160)}`);
    st.ok = true;
    const pc = prompts.length;
    const c2 = await raw(port, "POST", "/api/control/kill/off", { ...ctl, body: {} });
    assert("10 control API: with presence it clears the switch, after exactly one presence prompt about the kill switch", c2.status === 200 && !existsSync(killPath) && prompts.length === pc + 1 && /kill switch/i.test(prompts.at(-1)), `${c2.status} ${c2.body.slice(0, 160)}`);
    const killRows = recentAudit(300);
    assert("10 the control-API decisions are audited as the CLI owner (refused and cleared)", killRows.some((r) => r.tool === "kill.off_refused" && r.principal === "owner:cli") && killRows.some((r) => r.tool === "kill.off" && r.principal === "owner:cli"));
    const onTry = await raw(port, "POST", "/api/control/kill/on", { ...ctl, body: {} });
    assert("10 the control API has no route that turns the switch on", onTry.status >= 400 && !existsSync(killPath), `${onTry.status}`);

    // the real CLI (a separate process) against this gateway
    const cliOff = (...a) => runCli(["-c", cfgPath, "kill", ...a]);
    KS.setKillFile(true);
    st.ok = false;
    const p1 = prompts.length;
    const k1 = await cliOff("off");
    assert("10 CLI: `kill off` with a refused presence check exits 1 and the KILL file stays", k1.status === 1 && existsSync(killPath) && prompts.length === p1 + 1, `${k1.status} ${k1.stderr.slice(0, 200)}`);
    st.ok = true;
    const p2 = prompts.length;
    const k2 = await cliOff("off");
    assert("10 CLI: `kill off` with presence exits 0 and clears the file (the gateway asked, once, not the CLI)", k2.status === 0 && !existsSync(killPath) && prompts.length === p2 + 1 && /kill switch/i.test(prompts.at(-1)), `${k2.status} ${k2.stdout.slice(0, 120)} ${k2.stderr.slice(0, 200)}`);
    const pn = prompts.length;
    const k3 = await cliOff("off");
    assert("10 CLI: `kill off` when it is already off exits 0 with no prompt", k3.status === 0 && prompts.length === pn && /already off/.test(k3.stdout + k3.stderr), `${k3.status} ${k3.stdout} ${k3.stderr}`);
    const k4 = await cliOff("on");
    assert("10 CLI: `kill on` needs no gateway presence (no prompt) and creates the file", k4.status === 0 && existsSync(killPath) && prompts.length === pn, `${k4.status} ${k4.stderr.slice(0, 120)}`);

    // no gateway at all
    const deadPort = await freePort();
    const deadCfg = join(base, "dead.yaml");
    writeConfig(deadCfg, validateConfig({ gateway: { transport: ["http"], http: { host: "127.0.0.1", port: deadPort } }, servers: [] }, "oracle"));
    const k5 = await runCli(["-c", deadCfg, "kill", "off"]);
    assert("10 CLI: `kill off` with no gateway answering exits 1, keeps the KILL file and says a gateway must verify presence", k5.status === 1 && existsSync(killPath) && /gateway/i.test(k5.stderr) && /presence/i.test(k5.stderr), `${k5.status} ${k5.stderr.slice(0, 240)}`);
    KS.setKillFile(false);
    const k6 = await runCli(["-c", deadCfg, "kill", "off"]);
    assert("10 CLI: with nothing to clear it needs no gateway", k6.status === 0 && /already off/.test(k6.stdout + k6.stderr), `${k6.status} ${k6.stdout} ${k6.stderr}`);
    const cfgOnYaml = join(base, "konfig-on.yaml");
    writeFileSync(cfgOnYaml, "gateway:\n  transport: [stdio]\n  kill_switch: true\nservers: []\n");
    const k7 = await runCli(["-c", cfgOnYaml, "kill", "off"]);
    assert("10 CLI: a switch held only by gateway.kill_switch still exits 1 and says so", k7.status === 1 && /gateway\.kill_switch/.test(k7.stderr), `${k7.status} ${k7.stderr.slice(0, 200)}`);
    KS.setKillFile(false);
  }

  // ===================================================================================================================
  // 11. WEBHOOK PAYLOADS CARRY SCRUBBED ERROR TEXT
  // ===================================================================================================================
  {
    const posts = [];
    const hook = http.createServer((req, res) => {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        posts.push(Buffer.concat(chunks).toString("utf8"));
        res.writeHead(200);
        res.end();
      });
    });
    await new Promise((r) => hook.listen(0, "127.0.0.1", r));
    servers.push(hook);
    const hp = hook.address().port;
    // Fake credentials, assembled at run time so no credential-shaped literal sits in the source.
    const SK = ["s", "k-", "abcdefghijklmnopqrstuvwxyz012345"].join("");
    const BEARER = ["Bea", "rer ", "abcdefghijklmnop0123456789xyz"].join("");
    const GH = ["gh", "p_", "abcdefghijklmnopqrstuvwxyz0123456789"].join("");
    const up = makeUpstream("leaky", ["send_report", "make_report"], (entry) => {
      if (entry.name === "send_report") throw new Error(`auth failed for ${BEARER} using ${SK}`);
      return { isError: true, content: [{ type: "text", text: `rejected token ${GH} for the request` }] };
    });
    const reg = new Registry(new Vault("env"));
    await reg.mountLocal({ id: "leaky", source: "local", enabled: true, policy: "full" }, up.server);
    const cfg = rcfg({ settings: { webhook: { enabled: true, url: `http://127.0.0.1:${hp}/hook`, events: ["allow", "deny"] }, network: { allow_private: ["127.0.0.1"] } } });
    const router = new Router(reg, cfg, (x) => x);
    const t = await router.callTool("leaky__send_report", {});
    const m = await router.callTool("leaky__make_report", {});
    for (let i = 0; i < 40 && posts.filter((p) => /"error"/.test(p)).length < 2; i++) await sleep(50);
    const withErr = posts.filter((p) => /"error"/.test(p));
    assert("11 the webhook was delivered for both failing calls (thrown and error result)", t.isError && m.isError && withErr.length === 2, `${withErr.length} deliveries of ${posts.length}`);
    const all = posts.join("\n");
    assert("11 no webhook payload contains the bearer token, the provider key or the GitHub token", !all.includes(SK) && !all.includes("abcdefghijklmnop0123456789xyz") && !all.includes(GH), all.slice(0, 400));
    assert("11 ...the error text is there, scrubbed (redaction markers)", withErr.every((p) => /redacted/.test(JSON.parse(p).error)) && /auth failed/.test(JSON.parse(withErr[0]).error ?? ""), withErr.map((p) => JSON.parse(p).error).join(" | "));
    const rowsText = JSON.stringify(recentAudit(10));
    assert("11 the audit rows are scrubbed the same way (unchanged behaviour)", !rowsText.includes(SK) && !rowsText.includes(GH));
    await reg.unmountAll();
  }

  // ===================================================================================================================
  // static facts
  // ===================================================================================================================
  {
    const touched = ["src/safetext.ts", "src/packagespec.ts", "src/pathparam.ts", "scripts/verify-hardening-2.mjs"];
    const missing = touched.filter((f) => !existsSync(join(root, f)));
    assert("static: the new modules exist", missing.length === 0, missing.join(", "));
    const dash = "\u2014";
    const offenders = touched.filter((f) => existsSync(join(root, f)) && readFileSync(join(root, f), "utf8").includes(dash));
    assert("static: no em dash in the new files", offenders.length === 0, offenders.join(", "));
    const design = readFileSync(join(root, "docs", "architecture", "MCP_SWITCHBOARD_VNEXT.md"), "utf8");
    assert("static: the design document records the write-ahead audit and the guarded remote transport", /write-ahead/i.test(design) && /guardedMcpFetch/i.test(design));
  }
} catch (e) {
  assert("the oracle ran to completion", false, e && e.stack ? e.stack.split("\n").slice(0, 4).join(" | ") : String(e));
} finally {
  for (const h of handles) await h.close().catch(() => {});
  for (const g of gateways) await g.shutdown().catch(() => {});
  for (const s of servers) await new Promise((r) => s.close(r)).catch(() => {});
  try {
    KS.setKillFile(false);
  } catch {
    /* nothing to clear */
  }
}

const passed = checks.filter((c) => c.ok).length;
console.log(`\n${passed}/${checks.length} checks passed`);
try {
  rmSync(base, { recursive: true, force: true });
} catch {
  /* leftovers in temp are harmless */
}
process.exit(passed === checks.length ? 0 : 1);
