// Deterministic oracle for the wave-3 hardening closures: the review findings of the identity and approvals
// reviewers that were reproduced on 6deb12f, each closed with checks that fail on the code that had the defect.
// Every attack here is carried out the way the adversary named in the design carries it out: a process of the
// SAME OS user (an agent with a shell) that can run the CLI, read and write every file under SWITCHBOARD_HOME,
// and talk to the loopback ports. Nothing touches the operator's real state or a real service: isolated HOME and
// SWITCHBOARD_HOME, ephemeral loopback ports (never 8088), an injected owner-presence provider (never a real
// Windows Hello prompt, and no `dashboard login` is run with a default presence method), every child process is
// killed. Build first (this imports from dist/).
//
//   A  owner login     a login code is minted only INSIDE the running gateway, after the gateway's own presence
//                      check; codes and sessions are memory only; planted login-codes/ and sessions.json files,
//                      `--presence none` and a caller's SWITCHBOARD_INSECURE_APPROVAL do nothing
//   B  kill switch     once the gateway has seen the KILL switch it stays on until the presence-checked off route
//                      clears it, whatever happens to the file; a vanished file is audited as tampering
//   C  clients         `client add|rotate|rm` and `install` registration go through the running gateway and its
//                      presence check; unproven changes are not labelled owner:cli; a client changed behind a
//                      running gateway's back (the YAML file, the key file) is ignored until a restart;
//                      `serve --client` needs the client's key
//   D  session         the owner session is a header held in sessionStorage, never a cookie; the CSRF value is
//                      random per session and is not recoverable from the session id; OAuth consent is decided
//                      through the API with that session
//   E  arguments       one approval executes one upstream call: a rename that collides with a parameter the
//                      client also sent is refused before any approval exists, in every key order
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, existsSync, readdirSync, statSync, rmSync, renameSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import http from "node:http";
import net from "node:net";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dist = (f) => pathToFileURL(join(root, "dist", f)).href;
const CLI = join(root, "dist", "cli.js");

// ---- isolated environment (before any dist module is imported: HOME_DIR is read at import) ---------------------
const base = mkdtempSync(join(tmpdir(), "sb-hardening3-"));
const dirs = { home: join(base, "home"), appdata: join(base, "appdata"), local: join(base, "local"), tmp: join(base, "tmp") };
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

const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond });
  const clean = String(detail).replace(/\x1b\[[0-9;]*[A-Za-z]/g, "").replace(/\s+/g, " ").trim();
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${!cond && clean ? `: ${clean.slice(0, 400)}` : ""}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const sha = (s) => createHash("sha256").update(s, "utf8").digest("hex");

const { Router } = await import(dist("router.js"));
const { Registry } = await import(dist("registry.js"));
const { Vault } = await import(dist("vault.js"));
const { Gateway } = await import(dist("gateway.js"));
const { startDashboard } = await import(dist("dashboard.js"));
const { Approvals } = await import(dist("approvals.js"));
const { recentAudit } = await import(dist("audit.js"));
const KS = await import(dist("killswitch.js"));
const { validateConfig, writeConfig, loadConfig } = await import(dist("config.js"));
const { SB_ERR } = await import(dist("errors.js"));
const CKEY = await import(dist("controlkey.js"));
const { ApiKeyStore } = await import(dist("apikeys.js"));
const { ClientAdmin } = await import(dist("clientadmin.js"));
const { Server } = await import("@modelcontextprotocol/sdk/server/index.js");
const { ListToolsRequestSchema, CallToolRequestSchema } = await import("@modelcontextprotocol/sdk/types.js");
const YAML = await import("yaml");

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
    for (const k of Object.keys(h)) if (h[k] === undefined) delete h[k];
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
    return null;
  }
};

let rpcId = 100;
/** One JSON-RPC request to /mcp (the answer may be SSE or JSON). */
async function mcp(port, token, method, params = {}) {
  const r = await raw(port, "POST", "/mcp", {
    headers: { accept: "application/json, text/event-stream", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: { jsonrpc: "2.0", id: ++rpcId, method, params },
  });
  let msg = null;
  if (/text\/event-stream/.test(r.headers["content-type"] ?? "")) {
    const line = r.body.split(/\r?\n/).find((l) => l.startsWith("data:"));
    if (line) {
      try {
        msg = JSON.parse(line.slice(5).trim());
      } catch {
        msg = null;
      }
    }
  } else msg = jsonOf(r);
  return { status: r.status, body: r.body, result: msg?.result, error: msg?.error };
}
const toolNames = async (port, token) => ((await mcp(port, token, "tools/list")).result?.tools ?? []).map((t) => t.name).sort();
async function callTool(port, token, name, args = {}) {
  const r = await mcp(port, token, "tools/call", { name, arguments: args });
  const text = r.result?.content?.[0]?.text ?? "";
  let sb = null;
  try {
    sb = JSON.parse(text);
  } catch {
    sb = null;
  }
  return { ...r, isError: r.result?.isError === true, text, sb };
}

/** An in-process MCP upstream listing `names`; every executed call is recorded. */
function makeUpstream(id, names) {
  const executed = [];
  const server = new Server({ name: id, version: "0.0.0" }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: names.map((n) => ({ name: n, description: n, inputSchema: { type: "object", properties: { text: { type: "string" }, recipient: { type: "string" } } } })),
  }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const entry = { name: req.params.name, args: req.params.arguments ?? {} };
    executed.push(entry);
    return { content: [{ type: "text", text: `done:${req.params.name}` }] };
  });
  return { server, executed };
}

/** A Node child run to completion. Never rejects. */
function runCli(args, { env = {}, timeoutMs = 60_000 } = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], { env: { ...process.env, NO_COLOR: "1", ...env }, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    const timer = setTimeout(() => killTree(child), timeoutMs);
    child.on("close", (status) => {
      clearTimeout(timer);
      resolve({ status, stdout: out, stderr: err });
    });
  });
}
function killTree(child) {
  try {
    if (process.platform === "win32") spawnSync("taskkill", ["/pid", String(child.pid), "/T", "/F"], { stdio: "ignore" });
    else child.kill("SIGKILL");
  } catch {
    /* already gone */
  }
}

/** Serve over stdio: send `msgs`, wait up to `waitMs` for the first reply or the exit, kill the child. */
function stdioServe(cfgPath, extra, msgs, waitMs = 12_000) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, "-c", cfgPath, "serve", ...extra], { env: { ...process.env, NO_COLOR: "1" }, stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
    let out = "";
    let err = "";
    let exited = null;
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    child.on("close", (code) => (exited = code));
    for (const m of msgs) child.stdin.write(JSON.stringify(m) + "\n");
    const t0 = Date.now();
    const poll = setInterval(() => {
      const answered = /"serverInfo"/.test(out);
      if (answered || exited !== null || Date.now() - t0 > waitMs) {
        clearInterval(poll);
        const code = exited;
        killTree(child);
        resolve({ served: answered, exited: code, out, err });
      }
    }, 100);
  });
}
const INIT = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "h3", version: "0" } } };

const gateways = [];
const handles = [];
const servers = [];
let rigSeq = 0;
let skew = 0;
const clock = () => Date.now() + skew;
const SCOPED_UP = ["get_info", "create_note"];

/**
 * One gateway with its dashboard on an ephemeral port: an injected presence provider (`st.ok` decides, `prompts`
 * records every message the owner would have been shown), two in-process upstreams, and, when asked, configured
 * clients with keys provisioned the way the owner would have done it before the gateway started.
 * Rigs run one at a time: every listener start rewrites SWITCHBOARD_HOME/control.key.
 */
async function startRig({ clients = false, oauth = false } = {}) {
  const port = await freePort();
  const cfgPath = join(base, `rig-${++rigSeq}.yaml`);
  const rawCfg = {
    gateway: { transport: ["http"], http: { host: "127.0.0.1", port, require_auth: "auto" }, tool_exposure: "namespaced", default_policy: "full" },
    servers: [],
    settings: { general: { organization_name: "Local" }, ...(oauth ? { oauth_server: { enabled: true, public_url: `http://127.0.0.1:${port}`, access_token_ttl: 3600, refresh_token_ttl: 3600, consent: true } } : {}) },
    ...(clients
      ? { clients: { boss: { servers: ["*"], max_scope: "full", max_risk: "high" }, lowmodel: { servers: ["alpha"], max_scope: "read", max_risk: "low" } } }
      : {}),
  };
  const cfg = validateConfig(rawCfg, "oracle");
  writeConfig(cfgPath, cfg);
  const tokens = {};
  if (clients) {
    const admin = new ClientAdmin({ cfg, configPath: cfgPath, apiKeys: new ApiKeyStore() });
    // rotate: every rig starts from a key nobody else holds, also when an earlier rig left a working one behind.
    for (const id of ["boss", "lowmodel"]) {
      admin.add(id);
      tokens[id] = admin.rotate(id).token;
    }
  }
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
  const upA = makeUpstream("alpha", SCOPED_UP);
  const upB = makeUpstream("beta", ["get_weather", "send_note"]);
  await gw.registry.mountLocal({ id: "alpha", source: "local", enabled: true, policy: "full" }, upA.server);
  await gw.registry.mountLocal({ id: "beta", source: "local", enabled: true, policy: "full" }, upB.server);
  const dash = await startDashboard(gw, cfg, cfgPath, { clock });
  handles.push(dash);
  const ctl = () => ({ authorization: `Bearer ${CKEY.readControlKey()}` });
  return {
    port,
    cfgPath,
    cfg,
    gw,
    dash,
    prompts,
    st,
    tokens,
    ctl,
    async stop() {
      await dash.close().catch(() => {});
      await gw.shutdown().catch(() => {});
    },
  };
}

/** Sign the owner in the supported way: the gateway checks presence and hands out a code, the code becomes a session. */
async function ownerLogin(rig) {
  const r = await raw(rig.port, "POST", "/api/control/login", { headers: rig.ctl(), body: {} });
  const code = jsonOf(r).code;
  const s = await raw(rig.port, "POST", "/api/session", { body: { code } });
  const b = jsonOf(s);
  const sid = b.session;
  return {
    login: r,
    code,
    exchange: s,
    sid,
    csrf: b.csrf,
    hdr: sid ? { "x-switchboard-session": sid } : {},
    hdrC: sid ? { "x-switchboard-session": sid, "x-switchboard-csrf": b.csrf } : {},
  };
}
const csrfOld = (sid) => createHash("sha256").update(`switchboard-csrf-v1:${sid}`, "utf8").digest("base64url");
const killPath = () => join(SBHOME, "KILL");

async function section(name, fn) {
  const only = process.env.H3_ONLY ? process.env.H3_ONLY.split(",") : null;
  if (only && !only.includes(name)) return;
  try {
    await fn();
  } catch (e) {
    assert(`${name}: the section ran to completion`, false, e && e.stack ? e.stack.split("\n").slice(0, 5).join(" | ") : String(e));
  }
}

try {
  // ===================================================================================================================
  // A. OWNER LOGIN
  // ===================================================================================================================
  await section("A", async () => {
    const rig = await startRig();
    try {
      const { port } = rig;
      const help = await runCli(["dashboard", "login", "--help"]);
      const offersPresence = /--presence/.test(help.stdout + help.stderr);
      assert("A1 `dashboard login` no longer offers --presence (the method is the gateway's business)", !offersPresence, help.stdout.slice(0, 300));

      // The caller's own environment and flags: SWITCHBOARD_INSECURE_APPROVAL=1 plus --presence none, no gateway involved.
      const none = await runCli(["-c", rig.cfgPath, "dashboard", "login", "--presence", "none", "--no-open"], { env: { SWITCHBOARD_INSECURE_APPROVAL: "1" } });
      assert("A1 `dashboard login --presence none` with the caller's SWITCHBOARD_INSECURE_APPROVAL=1 mints nothing (exit 1, no login URL)", none.status !== 0 && !/#login=/.test(none.stdout + none.stderr), `${none.status} ${none.stdout.slice(0, 160)}`);

      if (!offersPresence) {
        // Only now is it safe to run the default form: it asks the gateway, never the machine's own Hello from this process.
        rig.st.ok = false;
        const p0 = rig.prompts.length;
        const refused = await runCli(["-c", rig.cfgPath, "dashboard", "login", "--no-open"], { env: { SWITCHBOARD_INSECURE_APPROVAL: "1" } });
        assert("A1 `dashboard login` asks the GATEWAY: a refused presence check there means exit 1 and no code", refused.status !== 0 && !/#login=/.test(refused.stdout + refused.stderr) && rig.prompts.length === p0 + 1 && /sign in|dashboard/i.test(rig.prompts.at(-1) ?? ""), `${refused.status} ${rig.prompts.length - p0} ${refused.stderr.slice(0, 200)}`);
        rig.st.ok = true;
        const p1 = rig.prompts.length;
        const okRun = await runCli(["-c", rig.cfgPath, "dashboard", "login", "--no-open"]);
        const m = /#login=([A-Za-z0-9_-]{16,200})/.exec(okRun.stdout);
        assert("A1 with the gateway's presence check passed the CLI prints a login URL (one prompt, shown by the gateway)", okRun.status === 0 && !!m && rig.prompts.length === p1 + 1, `${okRun.status} ${okRun.stdout.slice(0, 200)} ${okRun.stderr.slice(0, 200)}`);
        const redeem = await raw(port, "POST", "/api/session", { body: { code: m?.[1] } });
        assert("A1 ...and that code opens an owner session exactly once", redeem.status === 200 && !!jsonOf(redeem).session && (await raw(port, "POST", "/api/session", { body: { code: m?.[1] } })).status === 401, `${redeem.status} ${redeem.body.slice(0, 120)}`);
      }

      // A file-only route: a login code written straight into SWITCHBOARD_HOME.
      const planted = "A".repeat(43);
      mkdirSync(join(SBHOME, "login-codes"), { recursive: true });
      writeFileSync(join(SBHOME, "login-codes", `${sha(planted)}.json`), JSON.stringify({ created: Date.now(), expires: Date.now() + 120_000 }));
      const viaFile = await raw(port, "POST", "/api/session", { body: { code: planted } });
      assert("A2 a login code planted as a file in SWITCHBOARD_HOME/login-codes is not honoured (401)", viaFile.status === 401, `${viaFile.status} ${viaFile.body.slice(0, 120)}`);

      // A file-only route: a session written straight into sessions.json.
      const forgedSid = "B".repeat(43);
      writeFileSync(join(SBHOME, "sessions.json"), JSON.stringify({ sessions: [{ h: sha(forgedSid), expires: Date.now() + 3_600_000 }] }));
      const forgedKill = { cookie: `switchboard_session=${forgedSid}`, headers: { "x-switchboard-session": forgedSid, "x-switchboard-csrf": csrfOld(forgedSid) } };
      const g1 = await raw(port, "GET", "/api/session", { cookie: forgedKill.cookie });
      const g2 = await raw(port, "GET", "/api/session", { headers: { "x-switchboard-session": forgedSid } });
      assert("A3 a session planted in sessions.json is not honoured, as a cookie or as the session header", g1.status === 401 && g2.status === 401, `${g1.status} ${g2.status}`);
      const k1 = await raw(port, "POST", "/api/kill", { ...forgedKill, body: { on: true } });
      const killed = existsSync(killPath());
      if (killed) KS.setKillFile(false);
      assert("A3 ...and the derived CSRF value does not make it work: POST /api/kill is refused and writes nothing", k1.status >= 401 && !killed, `${k1.status} ${k1.body.slice(0, 120)} killfile=${killed}`);

      // The supported way.
      const none2 = await raw(port, "POST", "/api/control/login", { body: {} });
      const bad = await raw(port, "POST", "/api/control/login", { headers: { authorization: `Bearer sbc_${"x".repeat(43)}` }, body: {} });
      assert("A4 the control login route needs the control token (none: 401, wrong: 401)", none2.status === 401 && bad.status === 401, `${none2.status} ${bad.status}`);
      rig.st.ok = false;
      const pr = rig.prompts.length;
      const refusedLogin = await raw(port, "POST", "/api/control/login", { headers: rig.ctl(), body: { presence: "none" } });
      assert("A4 a refused presence check mints no code, whatever the body asks for (403, one prompt)", refusedLogin.status === 403 && !jsonOf(refusedLogin).expires_in && !/^[A-Za-z0-9_-]{40,}$/.test(String(jsonOf(refusedLogin).code ?? "")) && rig.prompts.length === pr + 1, `${refusedLogin.status} prompts+${rig.prompts.length - pr} ${refusedLogin.body.slice(0, 160)}`);
      rig.st.ok = true;
      const owner = await ownerLogin(rig);
      assert("A4 with presence the gateway returns a code, and the code becomes a session (200)", owner.login.status === 200 && typeof owner.code === "string" && owner.exchange.status === 200 && !!owner.sid && !!owner.csrf, `${owner.login.status} ${owner.exchange.status}`);
      assert("A4 the code works once only", (await raw(port, "POST", "/api/session", { body: { code: owner.code } })).status === 401);
      const viaSession = await raw(port, "POST", "/api/control/login", { headers: owner.hdrC, body: {} });
      assert("A4 an owner session does not open the control login route (401)", viaSession.status === 401, `${viaSession.status}`);

      const second = await ownerLogin(rig);
      skew += 125_000;
      const late = await raw(port, "POST", "/api/session", { body: { code: second.code } });
      skew -= 125_000;
      assert("A4 a login code expires after 120 seconds", late.status === 401, `${late.status}`);
      const third = await ownerLogin(rig);
      assert("A4 a fresh code still works after that", third.exchange.status === 200);
      skew += 12 * 3600_000 + 5000;
      const expired = await raw(port, "GET", "/api/session", { headers: third.hdr });
      skew -= 12 * 3600_000 + 5000;
      assert("A4 a session expires after 12 hours", expired.status === 401, `${expired.status}`);

      // Nothing about a code or a session reaches the disk.
      const fresh = await ownerLogin(rig);
      const walk = (d) => readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(d, e.name)) : [join(d, e.name)]));
      const hits = walk(SBHOME).filter((f) => {
        try {
          const t = readFileSync(f, "latin1");
          return t.includes(fresh.code) || t.includes(fresh.sid) || t.includes(sha(fresh.code)) || t.includes(sha(fresh.sid));
        } catch {
          return false;
        }
      });
      assert("A5 neither the code nor the session id (nor a hash of either) is written to SWITCHBOARD_HOME", hits.length === 0, hits.join(", "));

      const rows = recentAudit(400);
      assert("A6 the minting is audited as the CLI owner with the presence method, the refusal as a refusal", rows.some((r) => r.tool === "dashboard.login" && r.principal === "owner:cli" && r.decision === "allow") && rows.some((r) => r.tool === "dashboard.login_refused" && r.decision === "deny"), JSON.stringify(rows.filter((r) => /dashboard\./.test(r.tool ?? "")).slice(-3)));
    } finally {
      await rig.stop();
    }
  });

  // ===================================================================================================================
  // B. KILL SWITCH
  // ===================================================================================================================
  await section("B", async () => {
    // B1: a router, a KILL file made the way `switchboard kill on` makes it, removed by another process.
    const reg = new Registry(new Vault("env"));
    const up = makeUpstream("alpha", ["get_info"]);
    await reg.mountLocal({ id: "alpha", source: "local", enabled: true, policy: "full" }, up.server);
    const cfgK = { gateway: { transport: ["stdio"], http: { host: "127.0.0.1", port: 1, require_auth: "auto" }, tool_exposure: "namespaced", default_policy: "full", approval: { require_for_risk: [] } }, vault: { backend: "env" }, servers: [], settings: {} };
    const router = new Router(reg, cfgK, (r) => r);
    try {
      KS.setKillFile(false);
      assert("B1 baseline: the call works with the switch off", !(await router.callTool("alpha__get_info", {})).isError);
      const on = await runCli(["kill", "on"]);
      assert("B1 `switchboard kill on` (another process) writes the KILL file", on.status === 0 && existsSync(killPath()), on.stderr);
      const r1 = await router.callTool("alpha__get_info", {});
      assert("B1 the gateway refuses the next call (SB_KILL_SWITCH)", parseSb(r1)?.code === SB_ERR.KILL_SWITCH, JSON.stringify(parseSb(r1)));
      const before = up.executed.length;
      const rm = spawnSync(process.execPath, ["-e", "require('node:fs').rmSync(process.argv[1], { force: true })", killPath()], { encoding: "utf8" });
      assert("B1 (setup) another process deletes the KILL file, as any process of the same OS user can", rm.status === 0 && !existsSync(killPath()));
      const r2 = await router.callTool("alpha__get_info", {});
      assert("B1 the call is STILL refused after the file is gone (the gateway latched the switch)", parseSb(r2)?.code === SB_ERR.KILL_SWITCH && up.executed.length === before, JSON.stringify(parseSb(r2)) + ` executed=${up.executed.length - before}`);
      assert("B1 ...for every call, not one", parseSb(await router.callTool("alpha__get_info", {}))?.code === SB_ERR.KILL_SWITCH && parseSb(await router.callTool("alpha__nothing", {}))?.code === SB_ERR.KILL_SWITCH);
      const st = KS.killStatus(cfgK);
      assert("B1 killStatus says the switch is on although the file is gone, and why", st.active === true && st.file === false, JSON.stringify(st));
      assert("B1 a kill.tamper audit row records that the KILL file vanished while the switch was on", recentAudit(200).some((r) => r.tool === "kill.tamper" && r.decision === "deny"), JSON.stringify(recentAudit(5)));
      const tamperRows = () => recentAudit(500).filter((r) => r.tool === "kill.tamper").length;
      const t0 = tamperRows();
      await router.callTool("alpha__get_info", {});
      await router.callTool("alpha__get_info", {});
      assert("B1 ...once, not once per refused call", tamperRows() === t0, `${t0} -> ${tamperRows()}`);

      // A file that comes back and goes again, a rename, an empty touched file: all stay latched.
      writeFileSync(killPath(), "");
      assert("B2 a KILL file touched by hand again is still refusing", parseSb(await router.callTool("alpha__get_info", {}))?.code === SB_ERR.KILL_SWITCH);
      renameSync(killPath(), `${killPath()}.moved`);
      assert("B2 renaming the file away does not reopen the gateway either", parseSb(await router.callTool("alpha__get_info", {}))?.code === SB_ERR.KILL_SWITCH);
      rmSync(`${killPath()}.moved`, { force: true });

      // The one way back: the same function the presence-checked route calls.
      KS.setKillFile(false);
      assert("B3 the owner-authorised clear (setKillFile(false), called after the gateway's presence check) reopens the gateway", !(await router.callTool("alpha__get_info", {})).isError);
      assert("B3 ...and a later file is a fresh switch that latches again", (KS.setKillFile(true), parseSb(await router.callTool("alpha__get_info", {}))?.code === SB_ERR.KILL_SWITCH));
      KS.setKillFile(false);
      cfgK.gateway.kill_switch = true;
      assert("B3 gateway.kill_switch in the config still works and clearing the file does not clear it", parseSb(await router.callTool("alpha__get_info", {}))?.code === SB_ERR.KILL_SWITCH);
      cfgK.gateway.kill_switch = false;
      assert("B3 ...and turning that off is just the config", !(await router.callTool("alpha__get_info", {})).isError);
    } finally {
      KS.setKillFile(false);
      await reg.unmountAll();
    }

    // B4: the live gateway and its owner-only routes.
    const rig = await startRig({ clients: true });
    try {
      const { port } = rig;
      const boss = rig.tokens.boss;
      const ctl = () => ({ headers: rig.ctl(), body: {} });
      KS.setKillFile(false);
      assert("B4 baseline over HTTP: a client call works", !(await callTool(port, boss, "alpha__get_info")).isError);

      // `kill on` while a gateway runs: the gateway latches at once, so a delete right after cannot beat it.
      const onRes = await raw(port, "POST", "/api/control/kill/on", ctl());
      assert("B4 the control API has a kill/on route that engages the switch inside the gateway (200, file written)", onRes.status === 200 && existsSync(killPath()), `${onRes.status} ${onRes.body.slice(0, 160)}`);
      rmSync(killPath(), { force: true });
      const afterOn = await callTool(port, boss, "alpha__get_info");
      assert("B4 ...and deleting the file immediately afterwards (no call in between) does not reopen it", afterOn.sb?.code === SB_ERR.KILL_SWITCH, afterOn.text.slice(0, 200));
      const hz = jsonOf(await raw(port, "GET", "/healthz"));
      assert("B4 /healthz keeps reporting kill_switch: true with the file gone", hz.kill_switch === true, JSON.stringify(hz));

      // Refused presence keeps it on, with the file absent.
      rig.st.ok = false;
      const p0 = rig.prompts.length;
      const off1 = await raw(port, "POST", "/api/control/kill/off", ctl());
      assert("B4 kill/off with a refused presence check stays refused (403) and shows one prompt, although the file is absent", off1.status === 403 && rig.prompts.length === p0 + 1 && (await callTool(port, boss, "alpha__get_info")).sb?.code === SB_ERR.KILL_SWITCH, `${off1.status} ${off1.body.slice(0, 160)}`);
      // The real CLI, file absent but latched: it must ask the gateway, not say "already off".
      const cliRefused = await runCli(["-c", rig.cfgPath, "kill", "off"]);
      assert("B4 CLI `kill off` with the file absent but the gateway still refusing does not claim it is off (exit 1)", cliRefused.status === 1 && !/already off/.test(cliRefused.stdout + cliRefused.stderr), `${cliRefused.status} ${cliRefused.stdout.slice(0, 160)} ${cliRefused.stderr.slice(0, 200)}`);
      const stCli = await runCli(["-c", rig.cfgPath, "kill", "status"]);
      assert("B4 CLI `kill status` reports ON with the gateway's view when the file is absent", stCli.status === 0 && /kill switch: ON/.test(stCli.stdout), stCli.stdout.slice(0, 300));
      rig.st.ok = true;
      const p1 = rig.prompts.length;
      const cliOk = await runCli(["-c", rig.cfgPath, "kill", "off"]);
      assert("B4 CLI `kill off` with presence clears the latched switch (exit 0, one gateway prompt)", cliOk.status === 0 && rig.prompts.length === p1 + 1 && !(await callTool(port, boss, "alpha__get_info")).isError, `${cliOk.status} ${cliOk.stdout.slice(0, 160)} ${cliOk.stderr.slice(0, 200)}`);
      const p2 = rig.prompts.length;
      const cliAgain = await runCli(["-c", rig.cfgPath, "kill", "off"]);
      assert("B4 `kill off` when nothing is on needs no presence prompt and says it is already off", cliAgain.status === 0 && rig.prompts.length === p2 && /already off/.test(cliAgain.stdout + cliAgain.stderr), `${cliAgain.status} ${cliAgain.stdout.slice(0, 160)}`);

      // The dashboard route does the same for the latched-and-absent case.
      const owner = await ownerLogin(rig);
      KS.setKillFile(true);
      rmSync(killPath(), { force: true });
      assert("B4 (setup) latched with the file absent", (await callTool(port, boss, "alpha__get_info")).sb?.code === SB_ERR.KILL_SWITCH);
      const dOff = await raw(port, "POST", "/api/kill", { headers: owner.hdrC, body: { on: false } });
      assert("B4 the dashboard toggle clears it after presence (200) and the gateway works again", dOff.status === 200 && !(await callTool(port, boss, "alpha__get_info")).isError, `${dOff.status} ${dOff.body.slice(0, 160)}`);
    } finally {
      KS.setKillFile(false);
      await rig.stop();
    }
  });

  // ===================================================================================================================
  // C. CLIENTS: administration, the files behind a running gateway, stdio
  // ===================================================================================================================
  await section("C", async () => {
    const rig = await startRig({ clients: true });
    try {
      const { port } = rig;
      const lowTok = rig.tokens.lowmodel;
      const lowBefore = await toolNames(port, lowTok);
      assert("C0 baseline: lowmodel sees alpha read tools only, boss sees both servers", lowBefore.length > 0 && lowBefore.every((n) => n.startsWith("alpha__")) && (await toolNames(port, rig.tokens.boss)).some((n) => n.startsWith("beta__")), lowBefore.join(","));
      const addArgs = ["-c", rig.cfgPath, "client", "add", "mine", "--servers", "*", "--max-scope", "full", "--max-risk", "high", "--print"];

      // C1: an actor that is `lowmodel` mints a full client with the CLI.
      rig.st.ok = false;
      const p0 = rig.prompts.length;
      const refused = await runCli(addArgs);
      const tokRefused = /\n\s+(sb_[A-Za-z0-9_-]+|[A-Za-z0-9_-]{30,})\s*\n/.exec(refused.stdout)?.[1];
      assert("C1 `client add --max-scope full --max-risk high --print` with a refused presence check at the gateway fails (exit 1)", refused.status === 1, `${refused.status} ${refused.stdout.slice(0, 200)}`);
      assert("C1 ...prints no token, creates no client and no key", !tokRefused && !(loadConfig(rig.cfgPath).clients ?? {}).mine && !new ApiKeyStore().list().some((k) => k.client === "mine"), refused.stdout.slice(0, 300));
      assert("C1 ...after exactly one presence prompt, shown by the gateway, naming the client and what it gets", rig.prompts.length === p0 + 1 && /mine/.test(rig.prompts.at(-1) ?? "") && /full/.test(rig.prompts.at(-1) ?? ""), JSON.stringify(rig.prompts.slice(p0)));
      rig.st.ok = true;
      const p1 = rig.prompts.length;
      const granted = await runCli(addArgs);
      const tok = /\n\s+(\S{30,})\s*\n/.exec(granted.stdout)?.[1];
      assert("C1 with the owner present the same command works and prints the token once", granted.status === 0 && !!tok && rig.prompts.length === p1 + 1, `${granted.status} ${granted.stdout.slice(0, 200)} ${granted.stderr.slice(0, 200)}`);
      const mineTools = tok ? await toolNames(port, tok) : [];
      assert("C1 ...and the running gateway accepts the new client at once (both servers visible)", mineTools.some((n) => n.startsWith("alpha__")) && mineTools.some((n) => n.startsWith("beta__")), mineTools.join(","));
      const rows1 = recentAudit(400).filter((r) => r.tool === "client.add" && /'mine'/.test(r.reason ?? ""));
      assert("C1 the audit row is labelled owner:cli (the gateway proved presence) and names the presence method", rows1.length > 0 && rows1.at(0).principal === "owner:cli" && /presence/i.test(rows1.at(0).reason ?? ""), JSON.stringify(rows1.slice(-1)));

      // rotate and rm
      rig.st.ok = false;
      const p2 = rig.prompts.length;
      const rotRefused = await runCli(["-c", rig.cfgPath, "client", "rotate", "mine", "--print"]);
      assert("C2 `client rotate` also needs the gateway's presence check (refused: exit 1, the old key still works)", rotRefused.status === 1 && rig.prompts.length === p2 + 1 && tok && (await toolNames(port, tok)).length > 0, `${rotRefused.status} ${rotRefused.stdout.slice(0, 120)}`);
      rig.st.ok = true;
      const rot = await runCli(["-c", rig.cfgPath, "client", "rotate", "mine", "--print"]);
      const tok2 = /\n\s+(\S{30,})\s*\n/.exec(rot.stdout)?.[1];
      assert("C2 with presence it rotates: the new key works, the old one stops working at once", rot.status === 0 && !!tok2 && (await toolNames(port, tok2)).length > 0 && (await mcp(port, tok, "tools/list")).status === 401, `${rot.status} ${rot.stdout.slice(0, 120)}`);
      const p3 = rig.prompts.length;
      const rm = await runCli(["-c", rig.cfgPath, "client", "rm", "mine", "--purge"]);
      assert("C2 `client rm --purge` revokes without a presence prompt, and the running gateway forgets the client", rm.status === 0 && rig.prompts.length === p3 && (await mcp(port, tok2, "tools/list")).status !== 200 && !(loadConfig(rig.cfgPath).clients ?? {}).mine, `${rm.status} ${rm.stdout.slice(0, 160)} ${rm.stderr.slice(0, 160)}`);

      // C3: the files behind the running gateway's back (a same-user agent edits YAML and the key store).
      const text = readFileSync(rig.cfgPath, "utf8");
      const doc = YAML.parse(text);
      doc.clients.evil = { servers: ["*"], max_scope: "full", max_risk: "high" };
      doc.clients.lowmodel = { servers: ["*"], max_scope: "full", max_risk: "high" };
      writeFileSync(rig.cfgPath, YAML.stringify(doc));
      const evilTok = new ApiKeyStore().issue("evil", { client: "evil" }).token;
      const evil = await mcp(port, evilTok, "tools/list");
      assert("C3 a client added to the YAML file and a key written to the key store behind a running gateway is refused (not 200)", evil.status !== 200 && !(evil.result?.tools ?? []).length, `${evil.status} ${evil.body.slice(0, 120)}`);
      const lowAfter = await toolNames(port, lowTok);
      assert("C3 raising lowmodel's ceiling in the YAML file changes nothing for the running gateway", same(lowAfter, lowBefore), lowAfter.join(","));
      const drift = recentAudit(400).filter((r) => r.tool === "client.drift_ignored");
      assert("C3 the ignored edit is audited once (client.drift_ignored), not once per request", drift.length === 1, `${drift.length}`);
      const cl = await runCli(["-c", rig.cfgPath, "client", "list"]);
      assert("C3 `client list` shows the gateway's view and says the file differs", cl.status === 0 && /differ|drift|restart/i.test(cl.stdout + cl.stderr) && !/\bevil\b[^\n]*max_scope: full/.test(cl.stdout.split("lowmodel")[0] ?? ""), `${cl.stdout.slice(0, 400)}`);
      writeFileSync(rig.cfgPath, text);

      // C5: the install registration. A client file in a project directory, an unconfigured client.
      const projDir = join(base, "proj");
      mkdirSync(projDir, { recursive: true });
      rig.st.ok = false;
      const p4 = rig.prompts.length;
      const instRefused = await runCli(["-c", rig.cfgPath, "install", "cursor", "--scope", "project", "--dir", projDir, "--yes"]);
      assert("C5 `install cursor` registers an unconfigured client through the gateway: a refused presence check means exit 1, no client, no client file", instRefused.status === 1 && rig.prompts.length === p4 + 1 && !(loadConfig(rig.cfgPath).clients ?? {}).cursor && !existsSync(join(projDir, ".cursor", "mcp.json")), `${instRefused.status} ${instRefused.stderr.slice(0, 240)}`);
      rig.st.ok = true;
      const instOk = await runCli(["-c", rig.cfgPath, "install", "cursor", "--scope", "project", "--dir", projDir, "--yes"]);
      assert("C5 with presence the install registers the client (write scope, high risk) and writes the entry", instOk.status === 0 && loadConfig(rig.cfgPath).clients?.cursor?.max_scope === "write" && existsSync(join(projDir, ".cursor", "mcp.json")), `${instOk.status} ${instOk.stderr.slice(0, 300)} ${instOk.stdout.slice(0, 200)}`);
    } finally {
      await rig.stop();
    }

    // C2b: no gateway at all. The change is made, but nothing proved the owner, and the log says so.
    {
      const deadPort = await freePort();
      const deadCfg = join(base, "dead.yaml");
      writeConfig(deadCfg, validateConfig({ gateway: { transport: ["http"], http: { host: "127.0.0.1", port: deadPort, require_auth: "auto" } }, servers: [] }, "oracle"));
      const off = await runCli(["-c", deadCfg, "client", "add", "offline1", "--servers", "alpha"]);
      const row = recentAudit(400).filter((r) => r.tool === "client.add" && /'offline1'/.test(r.reason ?? "")).at(0);
      assert("C2b with no gateway running `client add` still works (the gateway trusts its config at start)", off.status === 0 && !!(loadConfig(deadCfg).clients ?? {}).offline1, `${off.status} ${off.stderr.slice(0, 200)}`);
      assert("C2b ...but the audit row is NOT labelled owner:cli: nothing proved the owner (local:cli, and the reason says so)", !!row && row.principal === "local:cli" && /not proven|unverified|no owner presence/i.test(row.reason ?? ""), JSON.stringify(row));
    }

    // C4: stdio. A client entry with no key (never issued, or revoked) must not be serveable by assertion.
    {
      const cfgS = join(base, "stdio.yaml");
      writeConfig(cfgS, validateConfig({ gateway: { transport: ["stdio"], http: { host: "127.0.0.1", port: await freePort(), require_auth: "auto" } }, servers: [], clients: { s1: { servers: ["*"], max_scope: "read" }, s2: { servers: ["*"], max_scope: "read" } } }, "oracle"));
      const cfgObj = loadConfig(cfgS);
      new ClientAdmin({ cfg: cfgObj, configPath: cfgS, apiKeys: new ApiKeyStore() }).add("s1");
      const noKey = await stdioServe(cfgS, ["--client", "s2"], [INIT]);
      assert("C4 `serve --client s2` for a configured client that has no key does not serve (exit 1)", !noKey.served && noKey.exited === 1 && /key/i.test(noKey.err), `served=${noKey.served} exit=${noKey.exited} ${noKey.err.slice(0, 200)}`);
      const withKey = await stdioServe(cfgS, ["--client", "s1"], [INIT]);
      assert("C4 `serve --client s1` with its key serves", withKey.served, `exit=${withKey.exited} ${withKey.err.slice(0, 200)}`);
      const rmRes = await runCli(["-c", cfgS, "client", "rm", "s1"]);
      const afterRm = await stdioServe(cfgS, ["--client", "s1"], [INIT]);
      assert("C4 after `client rm s1` (keys revoked, entry kept) stdio no longer serves it either", rmRes.status === 0 && !afterRm.served && afterRm.exited === 1, `rm=${rmRes.status} served=${afterRm.served} exit=${afterRm.exited}`);
    }
  });

  // ===================================================================================================================
  // D. THE OWNER SESSION IS NOT A COOKIE
  // ===================================================================================================================
  await section("D", async () => {
    const rig = await startRig({ clients: true });
    try {
      const { port } = rig;
      const owner = await ownerLogin(rig);
      const setCookie = owner.exchange.headers["set-cookie"];
      assert("D1 the login exchange sets no cookie at all (nothing for a browser to send to another port)", !setCookie && !!owner.sid, JSON.stringify(setCookie));
      assert("D1 the session id travels in the response body for the SPA's sessionStorage", typeof owner.sid === "string" && /^[A-Za-z0-9_-]{20,128}$/.test(owner.sid));

      const withHdr = await raw(port, "GET", "/api/session", { headers: owner.hdr });
      assert("D2 the session header authenticates the admin API", withHdr.status === 200 && jsonOf(withHdr).authenticated === true, `${withHdr.status}`);
      assert("D2 ...and the answer does not hand the CSRF value back", jsonOf(withHdr).csrf === undefined, withHdr.body.slice(0, 200));

      // The replay: the other loopback listener received the cookie, so it holds exactly this much.
      const replayCookies = [`switchboard_session=${owner.sid}`, `sid=${owner.sid}`, `session=${owner.sid}; switchboard_session=${owner.sid}`];
      for (const c of replayCookies) {
        const g = await raw(port, "GET", "/api/session", { cookie: c });
        const k = await raw(port, "POST", "/api/apikeys", { cookie: c, headers: { "x-switchboard-csrf": owner.csrf }, body: { name: "x", client: "boss" } });
        assert(`D3 replaying the session id as a cookie ("${c.split("=")[0]}=...") opens nothing: GET /api/session and POST /api/apikeys are 401`, g.status === 401 && k.status === 401 && !/token/.test(k.body), `${g.status} ${k.status} ${k.body.slice(0, 120)}`);
      }
      const csrfOnly = await raw(port, "POST", "/api/apikeys", { headers: { "x-switchboard-csrf": owner.csrf }, body: { name: "x", client: "boss" } });
      assert("D3 the CSRF value alone is not a credential (401)", csrfOnly.status === 401);

      const second = await ownerLogin(rig);
      assert("D4 the CSRF value is random per session: not the old derivation from the session id, and different for every session", owner.csrf !== csrfOld(owner.sid) && second.csrf !== csrfOld(second.sid) && owner.csrf !== second.csrf, `${owner.csrf} ${csrfOld(owner.sid)}`);
      const noCsrf = await raw(port, "POST", "/api/apikeys", { headers: owner.hdr, body: { name: "x" } });
      const wrongCsrf = await raw(port, "POST", "/api/apikeys", { headers: { ...owner.hdr, "x-switchboard-csrf": second.csrf }, body: { name: "x" } });
      const oldDerived = await raw(port, "POST", "/api/apikeys", { headers: { ...owner.hdr, "x-switchboard-csrf": csrfOld(owner.sid) }, body: { name: "x" } });
      const good = await raw(port, "POST", "/api/apikeys", { headers: owner.hdrC, body: { name: "d4" } });
      assert("D4 a mutating call needs this session's CSRF value: none, another session's and the old derived value are 403, the real one works", noCsrf.status === 403 && wrongCsrf.status === 403 && oldDerived.status === 403 && good.status === 200, `${noCsrf.status} ${wrongCsrf.status} ${oldDerived.status} ${good.status}`);
      const clientKeyOnAdmin = await raw(port, "GET", "/api/state", { headers: { authorization: `Bearer ${rig.tokens.boss}`, "x-api-key": rig.tokens.boss } });
      assert("D4 a client key is still never accepted on an admin route (401)", clientKeyOnAdmin.status === 401, `${clientKeyOnAdmin.status}`);

      const out = await raw(port, "DELETE", "/api/session", { headers: owner.hdrC });
      const after = await raw(port, "GET", "/api/session", { headers: owner.hdr });
      assert("D5 signing out revokes the session on the server (200, then 401)", out.status === 200 && after.status === 401 && !out.headers["set-cookie"], `${out.status} ${after.status} ${out.headers["set-cookie"]}`);
      const stillThere = await raw(port, "GET", "/api/session", { headers: second.hdr });
      assert("D5 ...and only that session", stillThere.status === 200);

      // The SPA: the one place the browser side lives.
      const app = readFileSync(join(root, "public", "app.js"), "utf8");
      assert("D6 the SPA keeps the session in sessionStorage and sends it as a header, never as a cookie", /sessionStorage/.test(app) && /X-Switchboard-Session/i.test(app) && !/credentials:\s*"same-origin"/.test(app) && /credentials:\s*"omit"/.test(app));
      assert("D6 ...and does not use localStorage for it", !/localStorage/.test(app));
    } finally {
      await rig.stop();
    }

    // D7: OAuth consent is decided through the API with the header session, not through a form and a cookie.
    const orig = await startRig({ oauth: true });
    try {
      const { port } = orig;
      const PUB = `http://127.0.0.1:${port}`;
      const redirectUri = "http://127.0.0.1:7777/callback";
      const reg = await raw(port, "POST", "/register", { body: { client_name: "h3-client", redirect_uris: [redirectUri], token_endpoint_auth_method: "none", grant_types: ["authorization_code"], response_types: ["code"] } });
      const clientId = jsonOf(reg).client_id;
      const authUrl = `/authorize?response_type=code&client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&code_challenge=${"A".repeat(43)}&code_challenge_method=S256&state=s1&scope=read&resource=${encodeURIComponent(`${PUB}/mcp`)}`;
      const owner = await ownerLogin(orig);
      const asCookie = await raw(port, "GET", authUrl, { cookie: `switchboard_session=${owner.sid}` });
      const asHeader = await raw(port, "GET", authUrl, { headers: owner.hdr });
      const pendingIds = [asCookie, asHeader].map((r) => /#\/oauth\/([A-Za-z0-9_-]+)/.exec(r.body)?.[1]);
      assert("D7 /authorize never renders a consent form, with or without a session: it points the owner at the dashboard (pending request id in the link)", [asCookie, asHeader].every((r) => !/<form|name="pending_id"|name="csrf"/.test(r.body)) && pendingIds.every(Boolean), `${asCookie.status} ${asHeader.status} ${asHeader.body.slice(0, 200)}`);
      const pid = pendingIds[1];
      const noSess = await raw(port, "GET", `/api/oauth/pending/${pid}`);
      const viaCookie = await raw(port, "GET", `/api/oauth/pending/${pid}`, { cookie: `switchboard_session=${owner.sid}` });
      const view = await raw(port, "GET", `/api/oauth/pending/${pid}`, { headers: owner.hdr });
      assert("D7 the pending request is readable only with the header session (none and cookie: 401)", noSess.status === 401 && viaCookie.status === 401 && view.status === 200 && jsonOf(view).client_name === "h3-client" && Array.isArray(jsonOf(view).scopes), `${noSess.status} ${viaCookie.status} ${view.status} ${view.body.slice(0, 160)}`);
      const decide = (extra, body) => raw(port, "POST", "/api/oauth/consent", { ...extra, body });
      const cNone = await decide({}, { pending_id: pid, decision: "approve" });
      const cCookie = await decide({ cookie: `switchboard_session=${owner.sid}`, headers: { "x-switchboard-csrf": owner.csrf } }, { pending_id: pid, decision: "approve" });
      const cNoCsrf = await decide({ headers: owner.hdr }, { pending_id: pid, decision: "approve" });
      assert("D7 approving needs the header session AND the CSRF value (none, cookie only, no CSRF: refused, nothing issued)", cNone.status === 401 && cCookie.status === 401 && cNoCsrf.status === 403 && !/code=/.test(cNone.body + cCookie.body + cNoCsrf.body), `${cNone.status} ${cCookie.status} ${cNoCsrf.status}`);
      const legacy = await raw(port, "POST", "/oauth/consent", { cookie: `switchboard_session=${owner.sid}`, headers: { "content-type": "application/x-www-form-urlencoded" }, body: `pending_id=${pid}&decision=approve&csrf=${owner.csrf}` });
      assert("D7 the old cookie-and-form consent route no longer exists (not 2xx/3xx)", legacy.status >= 400, `${legacy.status} ${legacy.headers.location ?? ""}`);
      const approved = await decide({ headers: owner.hdrC }, { pending_id: pid, decision: "approve" });
      const redirect = jsonOf(approved).redirect ?? "";
      assert("D7 with both, the consent is accepted and the answer carries the redirect with a code and the state", approved.status === 200 && new URL(redirect || "http://x/").searchParams.get("code") !== null && new URL(redirect || "http://x/").searchParams.get("state") === "s1", `${approved.status} ${approved.body.slice(0, 200)}`);
      const again = await decide({ headers: owner.hdrC }, { pending_id: pid, decision: "approve" });
      assert("D7 a decided request cannot be decided again (400/404)", again.status === 400 || again.status === 404, `${again.status}`);
    } finally {
      await orig.stop();
    }
  });

  // ===================================================================================================================
  // E. ONE APPROVAL, ONE UPSTREAM CALL
  // ===================================================================================================================
  await section("E", async () => {
    const reg = new Registry(new Vault("env"));
    const up = makeUpstream("social", ["send_note"]);
    const scfg = { id: "social", source: "local", enabled: true, policy: "full", outward: true, schema_modifiers: { rename_params: { recipient: "to" } } };
    await reg.mountLocal(scfg, up.server);
    const approvals = new Approvals({ path: join(SBHOME, "approvals-e.json"), presence: async () => ({ ok: true, method: "none" }) });
    const cfg = { gateway: { default_policy: "full", tool_exposure: "namespaced", approval: { require_for_risk: ["high"] } }, vault: { backend: "env" }, servers: [], settings: {} };
    const router = new Router(reg, cfg, (r) => r, approvals);
    const P = { id: "k1", client: null, via: "apikey" };
    const call = (args) => router.callTool("social__send_note", args, P);
    /** Call; if it is waiting for the owner, approve it and call again. Returns the last result. */
    const callApproved = async (args) => {
      let r = await call(args);
      const sb = parseSb(r);
      if (sb?.code === SB_ERR.APPROVAL_PENDING) {
        await approvals.approve(sb.approval_id, "cli");
        r = await call(args);
      }
      return r;
    };
    try {
      const A = { to: "alice@example.com", recipient: "bob@example.com" };
      const Areordered = { recipient: "bob@example.com", to: "alice@example.com" };
      assert("E0 (setup) the two spellings are the same arguments for hashing: same keys, same values, different order", same(Object.keys(A).sort(), Object.keys(Areordered).sort()) && JSON.stringify(A) !== JSON.stringify(Areordered));
      const rA = await call(A);
      assert("E1 a call that sends both the exposed name `to` and the upstream name `recipient` is refused with SB_BAD_REQUEST", rA.isError === true && parseSb(rA)?.code === SB_ERR.BAD_REQUEST, JSON.stringify(parseSb(rA))?.slice(0, 200));
      assert("E1 ...before any approval exists (nothing for the owner to look at, nothing to replay)", approvals.list().pending.length === 0 && up.executed.length === 0);
      const rB = await call(Areordered);
      assert("E1 the same arguments in the other key order are refused the same way", parseSb(rB)?.code === SB_ERR.BAD_REQUEST && approvals.list().pending.length === 0 && up.executed.length === 0, JSON.stringify(parseSb(rB))?.slice(0, 200));
      assert("E1 ...and the refusal says which names collide", /to/.test(parseSb(rA)?.error ?? "") && /recipient/.test(parseSb(rA)?.error ?? ""), parseSb(rA)?.error);

      // The end-to-end attack of the finding: approve once, execute in two different orders, compare what the upstream saw.
      await callApproved(A);
      await callApproved(Areordered);
      await callApproved(A);
      const seen = new Set(up.executed.map((e) => JSON.stringify(Object.entries(e.args).sort())));
      assert("E2 whatever the key order, the upstream never receives two different argument sets for the same arguments", seen.size <= 1, JSON.stringify(up.executed.map((e) => e.args)));
      up.executed.length = 0;

      const rOnly = await callApproved({ to: "carol@example.com", text: "hi" });
      assert("E3 an exposed name alone still maps to the upstream name (to -> recipient)", !rOnly.isError && same(up.executed.at(-1)?.args, { recipient: "carol@example.com", text: "hi" }), JSON.stringify(up.executed));
      const rRaw = await callApproved({ recipient: "dave@example.com" });
      assert("E3 the upstream name alone is passed through unchanged (existing behaviour)", !rRaw.isError && same(up.executed.at(-1)?.args, { recipient: "dave@example.com" }), JSON.stringify(up.executed.at(-1)));

      // Names that Object.prototype also knows must not be mistaken for renames.
      const weird = JSON.parse('{"constructor":"c","toString":"t","hasOwnProperty":"h","valueOf":"v","text":"w"}');
      const rW = await callApproved(weird);
      const got = up.executed.at(-1)?.args ?? {};
      assert("E4 arguments named constructor, toString, hasOwnProperty and valueOf reach the upstream under their own names", !rW.isError && got.constructor === "c" && got.toString === "t" && got.hasOwnProperty === "h" && got.valueOf === "v" && got.text === "w" && Object.keys(got).length === 5, JSON.stringify(Object.keys(got)));
    } finally {
      await reg.unmountAll();
    }

    // The pure function: independent of order, throws on a collision.
    const T = await import(dist("transforms.js"));
    const s = { id: "x", source: "npx", schema_modifiers: { rename_params: { recipient: "to", subject: "title" } } };
    let threw = 0;
    for (const args of [{ to: 1, recipient: 2 }, { recipient: 2, to: 1 }, { title: 1, subject: 2, to: 3 }]) {
      try {
        T.applyArgTransforms(args, s, undefined, (r) => r);
      } catch {
        threw++;
      }
    }
    assert("E5 applyArgTransforms itself throws on a collision, in every order (defence in depth for library callers)", threw === 3, `${threw}/3`);
    const ok1 = T.applyArgTransforms({ to: 1, title: 2, other: 3 }, s, undefined, (r) => r);
    const ok2 = T.applyArgTransforms({ other: 3, title: 2, to: 1 }, s, undefined, (r) => r);
    assert("E5 collision-free arguments transform to the same object in every order", same(Object.entries(ok1).sort(), Object.entries(ok2).sort()) && ok1.recipient === 1 && ok1.subject === 2 && ok1.other === 3, JSON.stringify(ok1));
    // An own "__proto__" key (what JSON.parse makes of that text) must stay an own key, not rewrite the prototype.
    const own = T.applyArgTransforms(JSON.parse('{"__proto__":{"x":1},"to":2}'), s, undefined, (r) => r);
    assert("E5 an own __proto__ argument stays an own property of the result and does not change its prototype", Object.prototype.hasOwnProperty.call(own, "__proto__") && Object.getPrototypeOf(own) === Object.prototype && own.recipient === 2 && own.x === undefined, JSON.stringify(own));
  });

  // ===================================================================================================================
  // static facts
  // ===================================================================================================================
  await section("static", async () => {
    const design = readFileSync(join(root, "docs", "architecture", "MCP_SWITCHBOARD_VNEXT.md"), "utf8");
    assert("static: the design records wave 3 (3.15), the gateway-held login, the kill latch and that same-user agents are not isolated", /3\.15/.test(design) && /latch/i.test(design) && /not isolated|are not a boundary/i.test(design) && /sessionStorage/.test(design));
    const readme = readFileSync(join(root, "README.md"), "utf8");
    assert("static: the README no longer promises a cookie session or a --presence flag for dashboard login", !/HttpOnly, SameSite=Strict session cookie/.test(readme) && !/`--presence` takes/.test(readme));
    const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
    assert("static: package.json registers verify:hardening-3 and runs it in the verify chain", pkg.scripts["verify:hardening-3"] === "node scripts/verify-hardening-3.mjs" && /npm run verify:hardening-3\b/.test(pkg.scripts.verify));
    const dash = String.fromCharCode(0x2014);
    // Only files that held no em dash before this wave (the others carry older ones this wave does not own).
    const files = ["src/httpsec.ts", "src/killswitch.ts", "src/clientadmin.ts", "src/clientconfig.ts", "src/installer.ts", "scripts/verify-hardening-3.mjs", "docs/architecture/MCP_SWITCHBOARD_VNEXT.md"];
    const offenders = files.filter((f) => existsSync(join(root, f)) && readFileSync(join(root, f), "utf8").includes(dash));
    assert("static: no em dash in the files this wave touches that were free of it", offenders.length === 0, offenders.join(", "));
  });
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
