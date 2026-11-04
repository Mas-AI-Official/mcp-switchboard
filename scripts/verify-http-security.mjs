// Deterministic oracle for design vNext section 3.2 (HTTP hardening). It drives the REAL listeners:
// startDashboard() in-process (twice: a plain loopback instance and an OAuth instance with a public
// issuer host), the expose listener without a tunnel binary, and the real CLI as child processes.
//
// It proves:
//   Host allowlist     forged Host is a 403 with no detail on every route (admin, /mcp, static, health),
//                      loopback names need the right port, the public issuer host is accepted on /mcp and
//                      the OAuth routes only; the expose listener does the same with its own port and the
//                      tunnel host once known.
//   Origin check       a wrong Origin on any non-GET route or on /mcp is a 403; a matching one passes.
//   Security headers   nosniff, no-referrer, DENY, a CSP with no unsafe script, on every response class;
//                      x-powered-by absent; the SPA files are CSP-clean (no inline script or handler).
//   Owner session      every /api/* route except /healthz and /api/health is 401 without a session
//                      (swept dynamically over every route found in the compiled dashboard), mutating
//                      routes are 403 without the CSRF header, a client API key never opens /api/*.
//   Login codes        (design 3.15) minted only inside the gateway after ITS presence check, single use (also
//                      under concurrency), 120 s expiry by injected clock, memory only (no file is a credential),
//                      no cookie (the session is a header), 12 h session expiry, a restart ends every session.
//   CLI login          `dashboard login` asks the running gateway (which verifies presence), prints the loopback
//                      URL, the code is redeemable once; the caller cannot choose the presence method.
//   OAuth consent      there is no consent form: the decision goes through the admin API with the session and
//                      CSRF headers; without them nothing is decided; DCR is capped (50 clients, 20 per hour).
//   Listen failures    a busy port (also a wildcard or loopback shadow) makes serve, dashboard, expose and
//                      startDashboard fail instead of reporting success.
// Zero deps (node stdlib + the package's compiled output). Build first. Isolated SWITCHBOARD_HOME.
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import http from "node:http";
import net from "node:net";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const tmp = mkdtempSync(join(tmpdir(), "sb-httpsec-"));
const homeRoot = join(tmp, "home");
const SBHOME = join(homeRoot, ".switchboard");
mkdirSync(SBHOME, { recursive: true });
for (const d of ["appdata", "local"]) mkdirSync(join(tmp, d), { recursive: true });
process.env.SWITCHBOARD_HOME = SBHOME;
process.env.HOME = homeRoot;
process.env.USERPROFILE = homeRoot;
process.env.APPDATA = join(tmp, "appdata");
process.env.LOCALAPPDATA = join(tmp, "local");
delete process.env.SWITCHBOARD_INSECURE_APPROVAL;
delete process.env.SWITCHBOARD_AUTO_APPROVE;

const { Gateway } = await import("../dist/gateway.js");
const { startDashboard } = await import("../dist/dashboard.js");
const { startMcpListener } = await import("../dist/expose.js");
const { ApiKeyStore } = await import("../dist/apikeys.js");
const { LoginCodeStore, isPublicRoutePath, CONTENT_SECURITY_POLICY } = await import("../dist/httpsec.js");
const { Approvals } = await import("../dist/approvals.js");
const { ownerSession, mintLoginCode } = await import("./lib/owner.mjs");

// Adapted (design 3.15): the gateway checks owner presence itself (sign-in), so the oracle gives it an injected provider:
// `presence.ok` decides, `presence.prompts` records what was asked. A default gateway would open a real Windows Hello
// prompt, which no oracle may do.
const presence = { ok: true, prompts: [] };
const mkGateway = (cfg) =>
  new Gateway(cfg, {
    approvals: new Approvals({ presence: async (m) => (presence.prompts.push(m), presence.ok ? { ok: true, method: "none" } : { ok: false, method: "hello", reason: "declined" }) }),
  });

const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  const clean = String(detail).replace(/\x1b\[[0-9;]*m/g, "").replace(/[\u2713\u2717]/g, "").replace(/\s+/g, " ").trim();
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${clean ? `: ${clean}` : ""}`);
};
const sha256 = (s) => createHash("sha256").update(s).digest("hex");
const b64url = (b) => b.toString("base64url");

// ---------------------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------------------
const children = [];
const handles = [];

function freePort() {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });
}

/** Raw HTTP with full control of Host, Origin and the session header (fetch would not let us forge Host). */
function raw(port, method, path, { host, origin, session, headers = {}, body } = {}) {
  return new Promise((resolve) => {
    const h = { Host: host ?? `127.0.0.1:${port}`, ...headers };
    if (origin !== undefined) h.Origin = origin;
    if (session) h["X-Switchboard-Session"] = session;
    let data;
    if (body !== undefined) {
      data = typeof body === "string" ? body : JSON.stringify(body);
      h["Content-Length"] = Buffer.byteLength(data);
      if (!Object.keys(h).some((k) => k.toLowerCase() === "content-type")) h["Content-Type"] = "application/json";
    }
    // agent:false = a fresh connection per request, so a restarted server never meets a stale keep-alive socket.
    const req = http.request({ host: "127.0.0.1", port, method, path, headers: h, agent: false }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
    });
    // Never reject: a hung or reset request is a status-0 result, so the check FAILS instead of crashing the oracle.
    req.on("error", (err) => resolve({ status: 0, headers: {}, body: "", error: String(err.message) }));
    req.setTimeout(10_000, () => req.destroy(new Error(`timeout ${method} ${path}`)));
    if (data !== undefined) req.write(data);
    req.end();
  });
}

const json = (r) => {
  try {
    return JSON.parse(r.body);
  } catch {
    return {};
  }
};

const INIT = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "verify-http-security", version: "0" } },
};
const MCP_HEADERS = { accept: "application/json, text/event-stream" };

let T = Date.now(); // injected clock: frozen between steps so boundaries are exact, advanced by the tests
const clock = () => T;
// Adapted (design 3.15): the gateway mints the login code after ITS presence check (the injected provider above); the
// session id comes back in the body and travels as a header. Nothing here can mint a code without the gateway.
async function login(port) {
  const s = await ownerSession(port);
  return { status: s.status, sid: s.sid, csrf: s.csrf, setCookie: s.setCookie, response: s.response, body: s.body };
}

const mkCfg = (port, settings = {}) => ({
  gateway: { transport: ["http"], http: { host: "127.0.0.1", port, require_auth: "auto" }, tool_exposure: "namespaced", default_policy: "read" },
  vault: { backend: "encrypted-file" },
  servers: [],
  settings,
});

function writeCliCfg(port, name) {
  const p = join(tmp, name);
  writeFileSync(p, `gateway:\n  transport: [http]\n  http:\n    host: 127.0.0.1\n    port: ${port}\n    require_auth: auto\nvault:\n  backend: encrypted-file\nservers: []\n`);
  return p;
}

const childEnv = (extra = {}) => {
  const e = { ...process.env, NO_COLOR: "1" };
  delete e.SWITCHBOARD_INSECURE_APPROVAL;
  delete e.SWITCHBOARD_AUTO_APPROVE;
  return { ...e, ...extra };
};

function runCli(args, { env, timeoutMs = 25_000 } = {}) {
  return spawnSync(process.execPath, [join(root, "dist", "cli.js"), ...args], {
    cwd: root,
    env: childEnv(env),
    encoding: "utf8",
    timeout: timeoutMs,
    stdio: ["pipe", "pipe", "pipe"],
  });
}

/** The CLI as an async child: needed whenever it talks to a gateway that lives in THIS process (spawnSync would block it). */
function runCliAsync(args, { env, timeoutMs = 30_000 } = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [join(root, "dist", "cli.js"), ...args], { cwd: root, env: childEnv(env), stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    children.push(child);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    const timer = setTimeout(() => child.kill(), timeoutMs);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ status: code, stdout, stderr });
    });
    child.on("error", (err) => {
      clearTimeout(timer);
      resolve({ status: null, stdout, stderr: String(err.message) });
    });
  });
}

/** Every file under a directory with its text (latin1, so binary files are searchable too). */
function filesUnder(dir) {
  const out = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) out.push(...filesUnder(p));
    else {
      let t = "";
      try {
        t = readFileSync(p, "latin1");
      } catch {
        /* unreadable: nothing to search */
      }
      out.push({ name: p, text: t });
    }
  }
  return out;
}

const listen = (host, port) =>
  new Promise((resolve, reject) => {
    const s = net.createServer((c) => c.destroy());
    s.once("error", reject);
    s.listen(port, host, () => resolve(s));
  });
const closeServer = (s) => new Promise((resolve) => s.close(() => resolve()));

const PUBLIC_B = "https://sb.example.test";

try {
  // =================================================================================================
  // 0. static wiring: no peer-address gate left, headers module wired, SPA is CSP-clean
  // =================================================================================================
  {
    const dash = readFileSync(join(root, "dist", "dashboard.js"), "utf8");
    const exp = readFileSync(join(root, "dist", "expose.js"), "utf8");
    assert("no handler still gates on the peer address (isLocalRequest guard removed)", !/if \(!isLocalRequest\(/.test(dash));
    assert('dashboard disables x-powered-by', dash.includes('app.disable("x-powered-by")'));
    assert('expose listener disables x-powered-by', exp.includes('app.disable("x-powered-by")'));
    assert("dashboard registers the owner gate on /api", dash.includes('app.use("/api", ownerSessionGate('));
    assert("dashboard mounts the Host/Origin guard", dash.includes("guard.handler()"));
    assert("expose mounts the Host/Origin guard", exp.includes("guard.handler()"));
    assert("listen has no resolving callback (Express 5 passes the error to it)", !/app\.listen\(port, host, \(\) =>/.test(dash) && !/app\.listen\(port, host, \(\) =>/.test(exp));

    const indexHtml = readFileSync(join(root, "public", "index.html"), "utf8");
    const appJs = readFileSync(join(root, "public", "app.js"), "utf8");
    const scripts = [...indexHtml.matchAll(/<script\b([^>]*)>/gi)];
    assert("index.html has no inline <script> (script-src 'self' is enough)", scripts.length > 0 && scripts.every((m) => /\bsrc=/.test(m[1])));
    assert("index.html has no inline event-handler attributes", !/\son[a-z]+\s*=\s*["']/i.test(indexHtml));
    assert("app.js builds no inline event-handler attributes (CSP blocks them)", !/\son(error|load|click|change|input|submit|mouseover|mouseout|focus|blur)\s*=\s*["'\\]/i.test(appJs));
    assert("app.js uses no eval or Function constructor", !/\beval\(|new Function\(/.test(appJs));
    assert("the CSP allows no unsafe-inline or unsafe-eval scripts", /script-src 'self'(;|$)/.test(CONTENT_SECURITY_POLICY) && !/script-src[^;]*unsafe/.test(CONTENT_SECURITY_POLICY));
    assert("the CSP forbids framing, plugins and <base>", /frame-ancestors 'none'/.test(CONTENT_SECURITY_POLICY) && /object-src 'none'/.test(CONTENT_SECURITY_POLICY) && /base-uri 'none'/.test(CONTENT_SECURITY_POLICY));
    assert("the CSP has no form-action (it would block the OAuth consent redirect)", !/form-action/.test(CONTENT_SECURITY_POLICY));
    assert("app.js routes every request through ONE fetch wrapper", (appJs.match(/\bfetch\(/g) ?? []).length === 1, `fetch( count=${(appJs.match(/\bfetch\(/g) ?? []).length}`);
    assert("app.js sends the session and CSRF headers and never ambient credentials (design 3.15: no cookie)", /credentials:\s*["']omit["']/.test(appJs) && appJs.includes("X-Switchboard-CSRF") && appJs.includes("X-Switchboard-Session"));
    assert("app.js redeems #login=<code> via POST /api/session and clears the hash", /login=/.test(appJs) && appJs.includes("/api/session") && appJs.includes("history.replaceState"));
    assert("app.js tells the owner to run 'switchboard dashboard login' on a 401", appJs.includes("switchboard dashboard login"));
    assert("isPublicRoutePath: /mcp and the OAuth routes only", isPublicRoutePath("/mcp") && isPublicRoutePath("/authorize") && isPublicRoutePath("/.well-known/oauth-authorization-server") && isPublicRoutePath("/oauth/consent") && !isPublicRoutePath("/api/state") && !isPublicRoutePath("/") && !isPublicRoutePath("/oauth/callback") && !isPublicRoutePath("/app.js"));
  }

  // =================================================================================================
  // A. plain loopback dashboard
  // =================================================================================================
  const portA = await freePort();
  const cfgA = mkCfg(portA);
  const gwA = mkGateway(cfgA);
  let hA = await startDashboard(gwA, cfgA, undefined, { clock });
  handles.push(hA);

  // ---- Host allowlist ----
  const sess = await login(portA);
  assert("login with a fresh code returns 200 and a csrf value", sess.status === 200 && typeof sess.csrf === "string" && sess.csrf.length >= 32, `status ${sess.status}`);
  const withSession = { session: sess.sid };
  const withCsrf = { session: sess.sid, headers: { "x-switchboard-csrf": sess.csrf } };

  {
    const forged = "evil.example";
    const r1 = await raw(portA, "GET", "/api/settings", { host: forged, ...withSession });
    assert("forged Host on GET /api/settings is 403 even with a valid session", r1.status === 403, `status ${r1.status}`);
    const r2 = await raw(portA, "POST", "/api/apikeys", { host: forged, ...withCsrf, body: { name: "x" } });
    assert("forged Host on POST /api/apikeys is 403 even with session and CSRF", r2.status === 403, `status ${r2.status}`);
    const r3 = await raw(portA, "POST", "/mcp", { host: forged, headers: MCP_HEADERS, body: INIT });
    assert("forged Host on POST /mcp is 403", r3.status === 403, `status ${r3.status}`);
    const r4 = await raw(portA, "GET", "/", { host: forged });
    assert("forged Host on the static dashboard page is 403", r4.status === 403, `status ${r4.status}`);
    const r5 = await raw(portA, "GET", "/healthz", { host: forged });
    assert("forged Host on /healthz is 403 (every route)", r5.status === 403, `status ${r5.status}`);
    assert("403 body gives no detail (no host echo, no reason)", r1.body === "forbidden" && !r1.body.includes(forged), JSON.stringify(r1.body));
    const rWrongPort = await raw(portA, "GET", "/healthz", { host: "127.0.0.1:1" });
    assert("loopback name with the wrong port is 403", rWrongPort.status === 403, `status ${rWrongPort.status}`);
    const rNoPort = await raw(portA, "GET", "/healthz", { host: "127.0.0.1" });
    assert("loopback name without the port is 403", rNoPort.status === 403, `status ${rNoPort.status}`);
    const rRebind = await raw(portA, "GET", "/api/state", { host: `127.0.0.1.evil.example:${portA}`, ...withSession });
    assert("a lookalike host (127.0.0.1.evil.example) is 403", rRebind.status === 403, `status ${rRebind.status}`);
    for (const h of [`localhost:${portA}`, `[::1]:${portA}`, `127.0.0.1:${portA}`, `LOCALHOST:${portA}`]) {
      const r = await raw(portA, "GET", "/healthz", { host: h });
      assert(`allowed Host ${h} reaches /healthz`, r.status === 200, `status ${r.status}`);
    }
    const mcpOk = await raw(portA, "POST", "/mcp", { headers: MCP_HEADERS, body: INIT });
    assert("/mcp with Host 127.0.0.1:<port> still works (initialize is 200)", mcpOk.status === 200 && /serverInfo|result/.test(mcpOk.body), `status ${mcpOk.status}`);
    const forgedPublic = await raw(portA, "GET", "/healthz", { host: "sb.example.test" });
    assert("with no public_url configured, an arbitrary public name is refused", forgedPublic.status === 403, `status ${forgedPublic.status}`);
  }

  // ---- Origin check ----
  {
    const evil = "https://evil.example";
    const o1 = await raw(portA, "POST", "/api/apikeys", { origin: evil, ...withCsrf, body: { name: "x" } });
    assert("bad Origin on a mutating admin POST is 403 even with session and CSRF", o1.status === 403, `status ${o1.status}`);
    const o2 = await raw(portA, "POST", "/mcp", { origin: evil, headers: MCP_HEADERS, body: INIT });
    assert("bad Origin on POST /mcp is 403", o2.status === 403, `status ${o2.status}`);
    const o3 = await raw(portA, "GET", "/mcp", { origin: evil, headers: MCP_HEADERS });
    assert("bad Origin on GET /mcp is 403 (the check covers /mcp for every method)", o3.status === 403, `status ${o3.status}`);
    const o4 = await raw(portA, "POST", "/api/session", { origin: evil, body: { code: "x".repeat(43) } });
    assert("bad Origin on the login exchange is 403", o4.status === 403, `status ${o4.status}`);
    const o5 = await raw(portA, "DELETE", "/api/servers/x", { origin: evil, ...withCsrf });
    assert("bad Origin on a DELETE is 403", o5.status === 403, `status ${o5.status}`);
    const okOrigins = [`http://127.0.0.1:${portA}`, `http://localhost:${portA}`, `http://[::1]:${portA}`];
    for (const origin of okOrigins) {
      const r = await raw(portA, "POST", "/mcp", { origin, headers: MCP_HEADERS, body: INIT });
      assert(`matching Origin ${origin} passes on POST /mcp`, r.status === 200, `status ${r.status}`);
    }
    for (const [label, origin] of [["other port", `http://127.0.0.1:${portA + 1}`], ["scheme mismatch", `https://127.0.0.1:${portA}`], ["null origin", "null"], ["empty origin", ""], ["subdomain trick", `http://127.0.0.1:${portA}.evil.example`]]) {
      const r = await raw(portA, "POST", "/mcp", { origin, headers: MCP_HEADERS, body: INIT });
      assert(`Origin ${label} is 403 on POST /mcp`, r.status === 403, `status ${r.status}`);
    }
    const g = await raw(portA, "GET", "/healthz", { origin: evil });
    assert("a plain GET with a foreign Origin is not blocked (design: non-GET and /mcp only)", g.status === 200, `status ${g.status}`);
    const noOrigin = await raw(portA, "POST", "/api/apikeys", { ...withCsrf, body: { name: "no-origin" } });
    assert("a mutating call with NO Origin header (CLI, curl) is allowed when session and CSRF are valid", noOrigin.status === 200, `status ${noOrigin.status}`);
    const sameOrigin = await raw(portA, "POST", "/api/apikeys", { origin: `http://127.0.0.1:${portA}`, ...withCsrf, body: { name: "same-origin" } });
    assert("a same-origin mutating call with session and CSRF succeeds", sameOrigin.status === 200 && typeof json(sameOrigin).token === "string", `status ${sameOrigin.status}`);
  }

  // ---- security headers ----
  {
    const sample = {
      "200 JSON (/healthz)": await raw(portA, "GET", "/healthz"),
      "200 HTML (/)": await raw(portA, "GET", "/"),
      "200 static (/app.js)": await raw(portA, "GET", "/app.js"),
      "401 (/api/state, no session)": await raw(portA, "GET", "/api/state"),
      "403 (forged Host)": await raw(portA, "GET", "/healthz", { host: "evil.example" }),
      "/mcp response": await raw(portA, "POST", "/mcp", { headers: MCP_HEADERS, body: INIT }),
      "404 (unknown path under /api)": await raw(portA, "GET", "/api/definitely-not-a-route", withSession),
    };
    for (const [label, r] of Object.entries(sample)) {
      const h = r.headers;
      assert(`headers on ${label}: nosniff, no-referrer, DENY, CSP`,
        h["x-content-type-options"] === "nosniff" && h["referrer-policy"] === "no-referrer" && h["x-frame-options"] === "DENY" && /script-src 'self'/.test(h["content-security-policy"] ?? ""),
        `status ${r.status}`);
      assert(`x-powered-by is absent on ${label}`, h["x-powered-by"] === undefined);
    }
    assert("the served CSP equals the exported policy", sample["200 JSON (/healthz)"].headers["content-security-policy"] === CONTENT_SECURITY_POLICY);
    assert("the SPA shell is still served on the loopback host", sample["200 HTML (/)"].status === 200 && sample["200 HTML (/)"].body.includes("MCP Switchboard"));
  }

  // ---- owner session: unauthenticated, CSRF, API keys ----
  {
    const getRoutes = ["/api/state", "/api/settings", "/api/apikeys", "/api/audit", "/api/usage", "/api/catalog", "/api/catalog/stats", "/api/toolkits", "/api/triggers", "/api/playground/tools", "/api/trigger-templates", "/api/session"];
    for (const p of getRoutes) {
      const r = await raw(portA, "GET", p);
      assert(`GET ${p} without a session is 401`, r.status === 401 && json(r).code === "SB_OWNER_SESSION_REQUIRED", `status ${r.status}`);
    }
    const h1 = await raw(portA, "GET", "/healthz");
    const h2 = await raw(portA, "GET", "/api/health");
    assert("/healthz needs no session", h1.status === 200, `status ${h1.status}`);
    assert("/api/health needs no session (200 or 503, never 401)", h2.status === 200 || h2.status === 503, `status ${h2.status}`);
    const unknown = await raw(portA, "GET", "/api/definitely-not-a-route");
    assert("an unknown /api path is 401 without a session (no route oracle)", unknown.status === 401, `status ${unknown.status}`);

    // Dynamic sweep over EVERY route registered in the compiled dashboard.
    const src = readFileSync(join(root, "dist", "dashboard.js"), "utf8");
    const routes = [...src.matchAll(/app\.(get|post|put|delete)\(\s*"(\/api\/[^"]*)"/g)].map((m) => ({ verb: m[1].toUpperCase(), path: m[2].replace(/:[A-Za-z_]+/g, "x") }));
    assert("route sweep found the admin API surface", routes.length >= 20, `routes=${routes.length}`);
    let swept401 = 0;
    let sweptCsrf = 0;
    const leaks = [];
    for (const { verb, path } of routes) {
      if (verb === "GET" && path === "/api/health") continue; // exempt by design
      if (verb === "POST" && path === "/api/session") continue; // the login exchange itself
      const r = await raw(portA, verb, path, { body: verb === "GET" || verb === "DELETE" ? undefined : {} });
      if (r.status === 401) swept401++;
      else leaks.push(`${verb} ${path} -> ${r.status}`);
      if (verb !== "GET") {
        const c = await raw(portA, verb, path, { ...withSession, body: verb === "DELETE" ? undefined : {} });
        if (c.status === 403 && json(c).code === "SB_CSRF") sweptCsrf++;
        else leaks.push(`${verb} ${path} with session, no CSRF -> ${c.status}`);
      }
    }
    assert("EVERY registered /api route (bar health and login) is 401 without a session", leaks.every((l) => l.includes("no CSRF")) && swept401 >= 19, leaks.join(" | ") || `${swept401} routes`);
    assert("EVERY mutating /api route is 403 with a session but no CSRF header", !leaks.some((l) => l.includes("no CSRF")) && sweptCsrf >= 12, leaks.join(" | ") || `${sweptCsrf} routes`);

    // Specific mutating cases, with the three CSRF states.
    for (const [verb, path, body] of [["POST", "/api/apikeys", { name: "csrf-probe" }], ["PUT", "/api/settings", { gateway: { default_policy: "read" } }], ["DELETE", "/api/servers/none", undefined], ["POST", "/api/playground/call", { name: "nothing" }]]) {
      const none = await raw(portA, verb, path, { ...withSession, body });
      const wrong = await raw(portA, verb, path, { ...withSession, headers: { "x-switchboard-csrf": "not-the-token" }, body });
      const noSess = await raw(portA, verb, path, { headers: { "x-switchboard-csrf": sess.csrf }, body });
      assert(`${verb} ${path}: session without CSRF is 403`, none.status === 403, `status ${none.status}`);
      assert(`${verb} ${path}: wrong CSRF is 403`, wrong.status === 403, `status ${wrong.status}`);
      assert(`${verb} ${path}: CSRF alone (no session) is 401`, noSess.status === 401, `status ${noSess.status}`);
    }
    const okReads = [await raw(portA, "GET", "/api/state", withSession), await raw(portA, "GET", "/api/settings", withSession), await raw(portA, "GET", "/api/apikeys", withSession)];
    assert("with a session, admin GETs succeed (no CSRF needed for reads)", okReads.every((r) => r.status === 200), okReads.map((r) => r.status).join(","));
    const me = await raw(portA, "GET", "/api/session", withSession);
    assert("GET /api/session confirms the session (authenticated, with an expiry) and does not hand the CSRF value back (the SPA keeps it in sessionStorage)", me.status === 200 && json(me).authenticated === true && !!json(me).expires_at && json(me).csrf === undefined);

    // A client API key never opens the admin API.
    const issued = await raw(portA, "POST", "/api/apikeys", { ...withCsrf, body: { name: "client-key" } });
    const key = json(issued).token ?? "sb_issuance_failed";
    assert("an API key can be issued by the owner session", issued.status === 200 && /^sb_/.test(key ?? ""), `status ${issued.status}`);
    const k1 = await raw(portA, "GET", "/api/settings", { headers: { authorization: `Bearer ${key}` } });
    const k2 = await raw(portA, "GET", "/api/settings", { headers: { "x-api-key": key } });
    const k3 = await raw(portA, "POST", "/api/apikeys", { headers: { authorization: `Bearer ${key}`, "x-switchboard-csrf": sess.csrf }, body: { name: "escalate" } });
    const k4 = await raw(portA, "GET", "/api/apikeys", { headers: { authorization: `Bearer ${key}` } });
    assert("client API key as Bearer is rejected on GET /api/settings", k1.status === 401, `status ${k1.status}`);
    assert("client API key as x-api-key is rejected on GET /api/settings", k2.status === 401, `status ${k2.status}`);
    assert("client API key plus a CSRF header cannot mint another key", k3.status === 401, `status ${k3.status}`);
    assert("client API key cannot list keys", k4.status === 401, `status ${k4.status}`);
  }

  // ---- login codes and sessions ----
  // Adapted for design 3.15 (hardening round 3). Login codes and sessions are memory only, and the session is a header
  // the SPA keeps in sessionStorage, not a cookie. The cookie-flag, login-codes/ file, sessions.json and "survives a
  // restart" checks described the old file-backed, cookie-carried design (files any process of the same OS user could
  // write, a cookie every other local port receives). Each is replaced below by its counterpart in the new form; the
  // single-use, concurrency, expiry, logout and session-lifetime checks keep their meaning and only change how the
  // code is obtained (the gateway mints it after its own presence check) and how the session is carried.
  {
    const mintCode = async () => (await mintLoginCode(portA)).code;

    // no cookie
    assert("login sets no cookie at all (a cookie is not scoped by port: every other local listener would receive it)", sess.setCookie === undefined && (sess.response.headers["set-cookie"] ?? []).length === 0);
    assert("the login answer carries the session id, a CSRF value and an expiry", typeof sess.body.session === "string" && typeof sess.body.csrf === "string" && !!sess.body.expires_at, JSON.stringify(Object.keys(sess.body)));
    assert("session id is 32 random bytes (43 base64url chars)", /^[A-Za-z0-9_-]{43}$/.test(sess.sid) && Buffer.from(sess.sid, "base64url").length === 32, sess.sid.length);
    const asCookie = await raw(portA, "GET", "/api/state", { headers: { cookie: `switchboard_session=${sess.sid}` } });
    assert("the old session cookie is not read: the session id sent as a cookie opens nothing", asCookie.status === 401, `status ${asCookie.status}`);
    const second = await login(portA);
    assert("two logins give different session ids and csrf values", second.sid !== sess.sid && second.csrf !== sess.csrf);
    for (const [label, v] of [["empty", ""], ["over-long", "x".repeat(5000)], ["path-like", "../../etc/passwd"], ["a code instead of a session", await mintCode()]]) {
      const r = await raw(portA, "GET", "/api/state", { session: v });
      assert(`a malformed session header (${label}) fails closed with 401`, r.status === 401, `status ${r.status}`);
    }

    // single use, also under concurrency
    const once = await mintCode();
    const first = await raw(portA, "POST", "/api/session", { body: { code: once } });
    const replay = await raw(portA, "POST", "/api/session", { body: { code: once } });
    assert("a login code redeems once", first.status === 200, `status ${first.status}`);
    assert("the same code is refused the second time", replay.status === 401 && json(replay).code === "SB_LOGIN_CODE", `status ${replay.status}`);
    const race = await mintCode();
    const results = await Promise.all(Array.from({ length: 8 }, () => raw(portA, "POST", "/api/session", { body: { code: race } })));
    assert("8 concurrent redemptions of one code: exactly one wins", results.filter((r) => r.status === 200).length === 1, results.map((r) => r.status).join(","));
    for (const [label, code] of [["unknown", b64url(randomBytes(32))], ["too short", "abc"], ["wrong type", 12345], ["path-like", "../../etc/passwd"], ["empty", ""]]) {
      const r = await raw(portA, "POST", "/api/session", { body: { code } });
      assert(`a ${label} code is 401`, r.status === 401, `status ${r.status}`);
    }
    const noBody = await raw(portA, "POST", "/api/session", {});
    assert("login with no body is 401", noBody.status === 401, `status ${noBody.status}`);

    // expiry by injected clock (TTL is 120 s)
    const justIn = await mintCode();
    const justOut = await mintCode();
    T += 119_999;
    const inTime = await raw(portA, "POST", "/api/session", { body: { code: justIn } });
    T += 2;
    const late = await raw(portA, "POST", "/api/session", { body: { code: justOut } });
    assert("a code redeemed at 119.999 s works", inTime.status === 200, `status ${inTime.status}`);
    assert("a code redeemed at 120.001 s is refused (TTL 120 s)", late.status === 401, `status ${late.status}`);
    const lateAgain = await raw(portA, "POST", "/api/session", { body: { code: justOut } });
    assert("an expired code stays refused (nothing revives it)", lateAgain.status === 401, `status ${lateAgain.status}`);

    // memory only: replaces "stored only as sha256 files under login-codes/"
    const stored = await mintCode();
    assert("a minted code is memory only: there is no login-codes directory under SWITCHBOARD_HOME", !existsSync(join(SBHOME, "login-codes")));
    const scan = filesUnder(SBHOME);
    assert("the plaintext code and the session ids appear in no file name or content under SWITCHBOARD_HOME", !scan.some((f) => f.name.includes(stored) || f.text.includes(stored) || f.text.includes(sess.sid) || f.text.includes(second.sid)), `${scan.length} files scanned`);

    // the old file-backed handoff does not work any more: replaces "a code minted by another store instance redeems"
    const foreign = new LoginCodeStore({ clock }).mint();
    const rForeign = await raw(portA, "POST", "/api/session", { body: { code: foreign } });
    assert("a code minted by another LoginCodeStore instance is not honoured (only this gateway's own memory counts)", rForeign.status === 401, `status ${rForeign.status}`);
    const plantedCode = b64url(randomBytes(32));
    mkdirSync(join(SBHOME, "login-codes"), { recursive: true });
    writeFileSync(join(SBHOME, "login-codes", `${sha256(plantedCode)}.json`), JSON.stringify({ expires: T + 100_000 }));
    const rPlanted = await raw(portA, "POST", "/api/session", { body: { code: plantedCode } });
    rmSync(join(SBHOME, "login-codes"), { recursive: true, force: true });
    assert("a login code file written by hand is not honoured either (the files are not a credential)", rPlanted.status === 401, `status ${rPlanted.status}`);

    // sessions are memory only: replaces "sessions.json lists the hashed id" and "a session survives a restart"
    const s2 = await login(portA);
    assert("sessions are memory only: no sessions.json exists", !existsSync(join(SBHOME, "sessions.json")));
    const plantedSid = b64url(randomBytes(32));
    writeFileSync(join(SBHOME, "sessions.json"), JSON.stringify({ sessions: [{ hash: sha256(plantedSid), id: sha256(plantedSid), expires: T + 1e9, csrf: "c".repeat(43) }] }));
    const rPlantedSid = await raw(portA, "GET", "/api/state", { session: plantedSid });
    rmSync(join(SBHOME, "sessions.json"), { force: true });
    assert("a hand-written sessions.json grants no session", rPlantedSid.status === 401, `status ${rPlantedSid.status}`);
    await hA.close();
    const gwA2 = mkGateway(cfgA);
    hA = await startDashboard(gwA2, cfgA, undefined, { clock });
    handles.push(hA);
    const afterRestart = await raw(portA, "GET", "/api/state", { session: s2.sid });
    assert("a gateway restart ends every session (nothing was persisted)", afterRestart.status === 401, `status ${afterRestart.status}`);

    // session expiry (12 h) by injected clock, on a session of the restarted gateway
    const s2b = await login(portA);
    T += 12 * 3600_000 - 1000;
    const near = await raw(portA, "GET", "/api/state", { session: s2b.sid });
    T += 2000;
    const gone = await raw(portA, "GET", "/api/state", { session: s2b.sid });
    assert("a session is still valid just before 12 h", near.status === 200, `status ${near.status}`);
    assert("a session is refused after 12 h", gone.status === 401, `status ${gone.status}`);

    // logout
    const s3 = await login(portA);
    const outNoCsrf = await raw(portA, "DELETE", "/api/session", { session: s3.sid });
    assert("DELETE /api/session without CSRF is 403 and keeps the session", outNoCsrf.status === 403 && (await raw(portA, "GET", "/api/state", { session: s3.sid })).status === 200);
    const out = await raw(portA, "DELETE", "/api/session", { session: s3.sid, headers: { "x-switchboard-csrf": s3.csrf } });
    assert("DELETE /api/session with CSRF logs out (the session is revoked; no cookie is set or cleared)", out.status === 200 && (out.headers["set-cookie"] ?? []).length === 0, `status ${out.status}`);
    const after = await raw(portA, "GET", "/api/state", { session: s3.sid });
    assert("the logged-out session no longer works", after.status === 401, `status ${after.status}`);
  }

  // ---- real CLI: dashboard login against the running gateway ----
  // Adapted for design 3.15. The code is minted INSIDE the gateway, after the gateway's own presence check (here an
  // injected provider: no real prompt), so the CLI only asks. The caller can no longer pick the presence method or
  // switch it off with an environment variable, so the three old `--presence` checks (none without the env flag, tty
  // without a terminal, a bogus value) become one: `--presence` is not an option at all. The CLI runs asynchronously
  // because the gateway lives in this process.
  {
    T = Date.now();
    const cfgPath = writeCliCfg(portA, "cli-a.yaml");
    presence.prompts.length = 0;
    presence.ok = true;
    const ok = await runCliAsync(["-c", cfgPath, "dashboard", "login", "--no-open"]);
    const urlLine = (ok.stdout ?? "").split(/\r?\n/).map((l) => l.trim()).find((l) => l.startsWith("http://")) ?? "";
    const re = new RegExp(`^http://127\\.0\\.0\\.1:${portA}/#login=([A-Za-z0-9_-]{43})$`);
    assert("CLI `dashboard login --no-open` exits 0", ok.status === 0, `exit ${ok.status} ${String(ok.stderr).slice(0, 160)}`);
    assert("CLI prints http://127.0.0.1:<port>/#login=<code>", re.test(urlLine), urlLine);
    assert("the gateway asked its own presence check before it minted the code", presence.prompts.length === 1 && /Sign in to the MCP Switchboard dashboard/.test(presence.prompts[0]), presence.prompts.join(" | "));
    const code = urlLine.match(re)?.[1];
    const redeem = await raw(portA, "POST", "/api/session", { body: { code } });
    assert("the CLI-minted code is redeemed by the running gateway (cross-process)", redeem.status === 200 && typeof json(redeem).csrf === "string" && typeof json(redeem).session === "string", `status ${redeem.status}`);
    const again = await raw(portA, "POST", "/api/session", { body: { code } });
    assert("the CLI-minted code is single use", again.status === 401, `status ${again.status}`);

    presence.ok = false;
    const declined = await runCliAsync(["-c", cfgPath, "dashboard", "login", "--no-open"]);
    assert("a declined presence check is refused (exit non-zero)", declined.status !== 0 && declined.status !== null, `exit ${declined.status}`);
    assert("a refused presence prints no login URL", !/#login=/.test(declined.stdout ?? ""));
    presence.ok = true;
    const promptsBefore = presence.prompts.length;
    const flagged = await runCliAsync(["-c", cfgPath, "dashboard", "login", "--presence", "none", "--no-open"], { env: { SWITCHBOARD_INSECURE_APPROVAL: "1" } });
    assert("`--presence` is not an option any more: the caller cannot pick the method, even with SWITCHBOARD_INSECURE_APPROVAL=1 (exit non-zero, no URL)", flagged.status !== 0 && flagged.status !== null && !/#login=/.test(flagged.stdout ?? ""), `exit ${flagged.status}`);
    assert("and the refused command minted nothing: the gateway was not even asked", presence.prompts.length === promptsBefore, `${promptsBefore} -> ${presence.prompts.length}`);
  }

  // ---- fail loudly on a busy port ----
  {
    const busy = await freePort();
    const cfgBusy = writeCliCfg(busy, "cli-busy.yaml");
    const sock = await listen("127.0.0.1", busy);
    const dash = runCli(["-c", cfgBusy, "dashboard"], { timeoutMs: 20_000 });
    assert("a second `dashboard` on a busy port exits non-zero", dash.status !== null && dash.status !== 0, `exit ${dash.status}`);
    assert("the busy-port failure is logged as an error naming the port", new RegExp(`${busy}`).test(dash.stderr ?? "") && /already in use|accepted a connection/.test(dash.stderr ?? ""), String(dash.stderr).trim().slice(0, 200));
    assert("a busy-port failure never claims success", !/dashboard \+ HTTP endpoint on/.test(dash.stderr ?? ""));
    const serve = runCli(["-c", cfgBusy, "serve"], { timeoutMs: 20_000 });
    assert("a second `serve` (http transport) on a busy port exits non-zero", serve.status !== null && serve.status !== 0, `exit ${serve.status}`);
    const apikeysBefore = existsSync(join(SBHOME, "apikeys.json")) ? readFileSync(join(SBHOME, "apikeys.json"), "utf8") : "";
    const exp = runCli(["-c", cfgBusy, "expose", "--port", String(busy)], { timeoutMs: 20_000 });
    assert("`expose` on a busy port exits non-zero", exp.status !== null && exp.status !== 0, `exit ${exp.status}`);
    assert("`expose` names the busy port", /already in use|accepted a connection|is busy/.test(exp.stderr ?? "") && new RegExp(`${busy}`).test(exp.stderr ?? ""), String(exp.stderr).trim().slice(0, 200));
    const apikeysAfter = existsSync(join(SBHOME, "apikeys.json")) ? readFileSync(join(SBHOME, "apikeys.json"), "utf8") : "";
    assert("`expose` on a busy port mints no API key", apikeysBefore === apikeysAfter);
    const cfgInproc = mkCfg(busy);
    let rejected = null;
    try {
      await startDashboard(new Gateway(cfgInproc), cfgInproc, undefined, { clock });
    } catch (err) {
      rejected = err;
    }
    assert("startDashboard REJECTS on a busy port (it used to resolve)", rejected instanceof Error && /already in use|accepted a connection/.test(rejected.message), rejected?.message);
    // A bind failure the probe cannot see (an address that is not this machine's) must also reject, never resolve.
    const cfgNoAddr = mkCfg(await freePort());
    cfgNoAddr.gateway.http.host = "203.0.113.5";
    let rejNoAddr = null;
    try {
      await startDashboard(new Gateway(cfgNoAddr), cfgNoAddr, undefined, { clock });
    } catch (err) {
      rejNoAddr = err;
    }
    assert("a listen error that is not EADDRINUSE also rejects (cannot bind 203.0.113.5)", rejNoAddr instanceof Error && /cannot listen/.test(rejNoAddr.message), rejNoAddr?.message);
    await closeServer(sock);

    // a wildcard or ::1 listener would silently shadow a 127.0.0.1 bind on some platforms
    const shadowPort = await freePort();
    const wild = await listen("0.0.0.0", shadowPort);
    const cfgShadow = writeCliCfg(shadowPort, "cli-shadow.yaml");
    const sh = runCli(["-c", cfgShadow, "dashboard"], { timeoutMs: 20_000 });
    assert("a wildcard (0.0.0.0) listener on the port also stops `dashboard` (no silent shadowing)", sh.status !== null && sh.status !== 0, `exit ${sh.status}`);
    await closeServer(wild);
    let v6 = null;
    const v6port = await freePort();
    try {
      v6 = await listen("::1", v6port);
    } catch {
      v6 = null; // no IPv6 loopback on this host: nothing to prove here
    }
    if (v6) {
      const cfgV6 = mkCfg(v6port);
      let rej6 = null;
      try {
        await startDashboard(new Gateway(cfgV6), cfgV6, undefined, { clock });
      } catch (err) {
        rej6 = err;
      }
      assert("a [::1] listener on the port stops startDashboard (localhost could resolve to the stranger)", rej6 instanceof Error, rej6?.message);
      await closeServer(v6);
    }

    // positive control: the same CLI on a FREE port starts, so the failures above are about the port
    const freeP = await freePort();
    const cfgFree = writeCliCfg(freeP, "cli-free.yaml");
    const child = spawn(process.execPath, [join(root, "dist", "cli.js"), "-c", cfgFree, "dashboard"], { cwd: root, env: childEnv(), stdio: ["ignore", "ignore", "pipe"] });
    children.push(child);
    let up = false;
    let exited = null;
    let childErr = "";
    child.stderr.on("data", (d) => (childErr = (childErr + d).slice(-600)));
    child.on("exit", (c) => (exited = c));
    for (let i = 0; i < 60 && !up && exited === null; i++) {
      await new Promise((r) => setTimeout(r, 250));
      try {
        up = (await raw(freeP, "GET", "/healthz")).status === 200;
      } catch {
        /* not yet */
      }
    }
    assert("control: `dashboard` on a free port starts and answers /healthz", up, up ? "" : `exited=${exited} stderr=${childErr.replace(/\x1b\[[0-9;]*m/g, "").trim()}`);
    child.kill();
  }

  // =================================================================================================
  // B. OAuth instance with a public issuer host: public routes, consent, DCR
  // =================================================================================================
  await hA.close();
  const portB = await freePort();
  const cfgB = mkCfg(portB, { oauth_server: { enabled: true, public_url: PUBLIC_B, consent: true, access_token_ttl: 3600, refresh_token_ttl: 1209600 } });
  const gwB = mkGateway(cfgB);
  const hB = await startDashboard(gwB, cfgB, undefined, { clock });
  handles.push(hB);

  {
    const pub = "sb.example.test";
    const meta = await raw(portB, "GET", "/.well-known/oauth-authorization-server", { host: pub });
    assert("public host reaches the OAuth metadata route", meta.status === 200, `status ${meta.status}`);
    const mcpPub = await raw(portB, "POST", "/mcp", { host: pub, headers: MCP_HEADERS, body: INIT });
    assert("public host reaches /mcp (passes the host check; 401 because auth is required)", mcpPub.status === 401, `status ${mcpPub.status}`);
    const mcpPubOrigin = await raw(portB, "POST", "/mcp", { host: pub, origin: PUBLIC_B, headers: MCP_HEADERS, body: INIT });
    assert("the issuer origin is accepted on /mcp through the public host", mcpPubOrigin.status === 401, `status ${mcpPubOrigin.status}`);
    const mcpBadOrigin = await raw(portB, "POST", "/mcp", { host: pub, origin: "https://evil.example", headers: MCP_HEADERS, body: INIT });
    assert("a foreign Origin through the public host is 403", mcpBadOrigin.status === 403, `status ${mcpBadOrigin.status}`);
    const sB = await login(portB);
    for (const [label, path] of [["/api/state", "/api/state"], ["the dashboard page", "/"], ["/app.js", "/app.js"], ["/healthz", "/healthz"], ["/oauth/callback", "/oauth/callback"], ["/api/settings", "/api/settings"]]) {
      const r = await raw(portB, "GET", path, { host: pub, session: sB.sid });
      assert(`public host is refused on ${label} (public routes are /mcp and OAuth only)`, r.status === 403, `status ${r.status}`);
    }
    const postPub = await raw(portB, "POST", "/api/apikeys", { host: pub, origin: PUBLIC_B, session: sB.sid, headers: { "x-switchboard-csrf": sB.csrf }, body: { name: "x" } });
    assert("public host plus issuer Origin plus a valid session still cannot reach the admin API", postPub.status === 403, `status ${postPub.status}`);
    const pubOriginOnDash = await raw(portB, "POST", "/api/apikeys", { origin: PUBLIC_B, session: sB.sid, headers: { "x-switchboard-csrf": sB.csrf }, body: { name: "x" } });
    assert("the issuer Origin is refused on dashboard routes even via a loopback Host", pubOriginOnDash.status === 403, `status ${pubOriginOnDash.status}`);
    const loopbackOauth = await raw(portB, "GET", "/.well-known/oauth-authorization-server");
    assert("loopback host also reaches the OAuth metadata", loopbackOauth.status === 200, `status ${loopbackOauth.status}`);

    // ---- consent needs an owner session (admin API, design 3.15) ----
    const clientMeta = { client_name: "verify-http-security", redirect_uris: ["http://127.0.0.1:7777/callback"], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] };
    let accepted = 0; // clients registered on this instance so far
    const register = async () => {
      const r = await raw(portB, "POST", "/register", { body: clientMeta });
      if (r.status === 201) accepted++;
      return r;
    };
    const cl = json(await register());
    const pkce = () => {
      const verifier = b64url(randomBytes(32));
      return { verifier, challenge: b64url(createHash("sha256").update(verifier).digest()) };
    };
    const authPath = (clientId, challenge, state) =>
      `/authorize?response_type=code&client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(clientMeta.redirect_uris[0])}&code_challenge=${challenge}&code_challenge_method=S256&state=${state}&scope=read&resource=${encodeURIComponent(`${PUBLIC_B}/mcp`)}`;
    const formHeaders = { "content-type": "application/x-www-form-urlencoded" };
    const form = (o) => new URLSearchParams(o).toString();

    assert("DCR returns a client_id", typeof cl.client_id === "string", JSON.stringify(cl).slice(0, 120));
    // Adapted for design 3.15: there is no consent page or form any more. /authorize answers 401 with a page that only
    // points the owner at the dashboard; the decision is made through the admin API (GET /api/oauth/pending/:id and
    // POST /api/oauth/consent) with the session header and the CSRF header. The old checks (form fields, a form csrf
    // field, an inline form for a signed-in owner) become their counterparts on that API. What they proved is kept: no
    // decision without the owner session, none without CSRF or from a foreign Origin, single use, deny works, an unknown
    // id is refused.
    const csrfH = { "x-switchboard-csrf": sB.csrf };
    const consent = (extra, body) => raw(portB, "POST", "/api/oauth/consent", { ...extra, body });
    const p1 = pkce();
    const a1 = await raw(portB, "GET", authPath(cl.client_id, p1.challenge, "s1"));
    const pend1 = a1.body.match(/#\/oauth\/([A-Za-z0-9_-]+)/)?.[1];
    assert("/authorize without an owner session is 401, not a consent form", a1.status === 401 && !/name="decision"/.test(a1.body) && !/name="pending_id"/.test(a1.body) && !/<form/.test(a1.body), `status ${a1.status}`);
    assert("the sign-in page says how to sign in and links to the dashboard view of the pending request", a1.body.includes("switchboard dashboard login") && !!pend1 && a1.body.includes(`http://127.0.0.1:${portB}/#/oauth/`));

    const noSessPost = await consent({}, { pending_id: pend1, decision: "approve" });
    assert("POST /api/oauth/consent without a session is refused: 401, no redirect, no code", noSessPost.status === 401 && json(noSessPost).redirect === undefined, `status ${noSessPost.status}`);
    const apiKeyConsent = await consent({ headers: { authorization: "Bearer sb_not_an_owner" } }, { pending_id: pend1, decision: "approve" });
    assert("an Authorization header does not stand in for the owner session on consent", apiKeyConsent.status === 401 && json(apiKeyConsent).redirect === undefined, `status ${apiKeyConsent.status}`);
    const oldRoute = await raw(portB, "POST", "/oauth/consent", { session: sB.sid, headers: { ...formHeaders, ...csrfH }, body: form({ pending_id: pend1, decision: "approve" }) });
    assert("the old POST /oauth/consent route decides nothing, even with a session and CSRF (no handler, no redirect)", oldRoute.status >= 400 && !oldRoute.headers.location, `status ${oldRoute.status}`);
    const noCsrf = await consent({ session: sB.sid }, { pending_id: pend1, decision: "approve" });
    assert("consent with a session but no CSRF is 403, no redirect", noCsrf.status === 403 && json(noCsrf).redirect === undefined, `status ${noCsrf.status}`);
    const badCsrf = await consent({ session: sB.sid, headers: { "x-switchboard-csrf": "nope" } }, { pending_id: pend1, decision: "approve" });
    assert("consent with a wrong CSRF is 403", badCsrf.status === 403 && json(badCsrf).redirect === undefined, `status ${badCsrf.status}`);
    const bodyCsrf = await consent({ session: sB.sid }, { pending_id: pend1, decision: "approve", csrf: sB.csrf });
    assert("the CSRF value in the body is not accepted (only the header counts): 403", bodyCsrf.status === 403 && json(bodyCsrf).redirect === undefined, `status ${bodyCsrf.status}`);
    const evilOrigin = await consent({ session: sB.sid, origin: "https://evil.example", headers: csrfH }, { pending_id: pend1, decision: "approve" });
    assert("consent with a foreign Origin is 403 even with session and CSRF", evilOrigin.status === 403 && json(evilOrigin).redirect === undefined, `status ${evilOrigin.status}`);

    // the owner's view of the pending request, then the decision
    const pendAnon = await raw(portB, "GET", `/api/oauth/pending/${pend1}`);
    const pendOwner = await raw(portB, "GET", `/api/oauth/pending/${pend1}`, { session: sB.sid });
    assert("a pending request is described only to a signed-in owner: 401 without a session", pendAnon.status === 401 && !pendAnon.body.includes("verify-http-security"), `status ${pendAnon.status}`);
    assert("a signed-in owner sees the client name, the scopes and the audience of the pending request", pendOwner.status === 200 && json(pendOwner).client_name === "verify-http-security" && Array.isArray(json(pendOwner).scopes) && typeof json(pendOwner).resource === "string", `status ${pendOwner.status} ${pendOwner.body.slice(0, 120)}`);
    const approve = await consent({ session: sB.sid, origin: `http://127.0.0.1:${portB}`, headers: csrfH }, { pending_id: pend1, decision: "approve" });
    const loc = json(approve).redirect ?? "";
    const authCode = new URL(loc || "http://x/", "http://x").searchParams.get("code");
    assert("the owner approves with the session and CSRF headers: 200 with a redirect carrying a code and the original state", approve.status === 200 && !!authCode && new URL(loc).searchParams.get("state") === "s1", `status ${approve.status}`);
    const tok = await raw(portB, "POST", "/token", { headers: formHeaders, body: form({ grant_type: "authorization_code", code: authCode, redirect_uri: clientMeta.redirect_uris[0], client_id: cl.client_id, code_verifier: p1.verifier, resource: `${PUBLIC_B}/mcp` }) });
    assert("the code from an owner-approved consent exchanges for a token", tok.status === 200 && typeof json(tok).access_token === "string", `status ${tok.status}`);
    const replay = await consent({ session: sB.sid, headers: csrfH }, { pending_id: pend1, decision: "approve" });
    assert("a pending consent is single use", replay.status === 404 && json(replay).redirect === undefined, `status ${replay.status}`);

    // signed in from the start: /authorize still renders no form (nothing to leak), the CSRF header is the only way, deny works
    const p2 = pkce();
    const a2 = await raw(portB, "GET", authPath(cl.client_id, p2.challenge, "s2"), { session: sB.sid });
    const pend2 = a2.body.match(/#\/oauth\/([A-Za-z0-9_-]+)/)?.[1];
    assert("/authorize renders no consent form even for a signed-in owner, and the page never contains the CSRF value or the session id", a2.status === 401 && !!pend2 && !/<form/.test(a2.body) && !a2.body.includes(sB.csrf) && !a2.body.includes(sB.sid), `status ${a2.status}`);
    const viaHeader = await consent({ session: sB.sid, headers: csrfH }, { pending_id: pend2, decision: "approve" });
    assert("consent accepts the CSRF value in the X-Switchboard-CSRF header", viaHeader.status === 200 && /[?&]code=/.test(json(viaHeader).redirect ?? ""), `status ${viaHeader.status}`);
    const p3 = pkce();
    const a3 = await raw(portB, "GET", authPath(cl.client_id, p3.challenge, "s3"), { session: sB.sid });
    const pend3 = a3.body.match(/#\/oauth\/([A-Za-z0-9_-]+)/)?.[1];
    const deny = await consent({ session: sB.sid, headers: csrfH }, { pending_id: pend3, decision: "deny" });
    assert("the owner can deny: 200 with a redirect carrying error=access_denied and no code", deny.status === 200 && /error=access_denied/.test(json(deny).redirect ?? "") && !/[?&]code=/.test(json(deny).redirect ?? ""), `status ${deny.status}`);
    const unknownPending = await raw(portB, "GET", "/api/oauth/pending/does-not-exist", { session: sB.sid });
    assert("an unknown or expired pending id is 404", unknownPending.status === 404, `status ${unknownPending.status}`);

    // ---- a client API key authenticates /mcp here (auth is required on this instance) ----
    const keyRes = await raw(portB, "POST", "/api/apikeys", { session: sB.sid, headers: { "x-switchboard-csrf": sB.csrf }, body: { name: "b-key" } });
    const bKey = json(keyRes).token ?? "sb_issuance_failed";
    const mcpKey = await raw(portB, "POST", "/mcp", { headers: { ...MCP_HEADERS, authorization: `Bearer ${bKey}` }, body: INIT });
    assert("a client API key authenticates /mcp (MCP only, never the admin API)", mcpKey.status === 200, `status ${mcpKey.status}`);

    // ---- DCR: origin, rate limit, cap ----
    const regBadOrigin = await raw(portB, "POST", "/register", { origin: "https://evil.example", body: clientMeta });
    assert("DCR with a foreign Origin is 403", regBadOrigin.status === 403, `status ${regBadOrigin.status}`);
    T += 3_700_000; // empty the rolling window left by the consent tests
    const before = accepted;
    let okCount = 0;
    for (let i = 0; i < 20; i++) if ((await register()).status === 201) okCount++;
    assert("20 registrations inside an hour are accepted", okCount === 20, `accepted ${okCount}`);
    const over = await register();
    assert("the 21st registration inside the hour is 429 too_many_requests with Retry-After", over.status === 429 && Number(over.headers["retry-after"]) > 0 && json(over).error === "too_many_requests", `status ${over.status}`);
    assert("a refused registration adds no client", accepted === before + 20);
    T += 3_700_000;
    const afterHour = await register();
    assert("after the hour passes registration works again (rolling window follows the clock)", afterHour.status === 201, `status ${afterHour.status}`);
    // fill to the cap of 50, never exceeding 20 per hour
    let filledOk = true;
    let inWindow = 1;
    while (accepted < 50 && filledOk) {
      if (inWindow >= 18) {
        T += 3_700_000;
        inWindow = 0;
      }
      const r = await register();
      filledOk = r.status === 201;
      inWindow++;
    }
    assert("registrations are accepted right up to 50 clients", accepted === 50 && filledOk, `accepted ${accepted}`);
    T += 3_700_000; // a fresh window, so only the cap can explain the next refusal
    const capped = await register();
    assert("the 51st client is refused with too_many_clients (cap 50)", capped.status === 429 && json(capped).error === "too_many_clients" && accepted === 50, `status ${capped.status} ${capped.body.slice(0, 100)}`);
    const cappedAgain = await register();
    assert("the cap holds on repeat", cappedAgain.status === 429 && accepted === 50, `status ${cappedAgain.status}`);
  }

  // =================================================================================================
  // C. the expose listener (no tunnel binary): same Host/Origin/header rules, tunnel host for /mcp
  // =================================================================================================
  {
    const portE = await freePort();
    const apiKeys = new ApiKeyStore();
    const key = apiKeys.issue("expose-oracle").token;
    const L = await startMcpListener(gwA, "127.0.0.1", portE, apiKeys);
    handles.push(L);
    const tunnelHost = "happy-cat-42.trycloudflare.com";
    const bearer = { ...MCP_HEADERS, authorization: `Bearer ${key}` };

    const e1 = await raw(portE, "POST", "/mcp", { host: "evil.example", headers: bearer, body: INIT });
    assert("expose: forged Host on /mcp is 403 even with a valid key", e1.status === 403, `status ${e1.status}`);
    const e2 = await raw(portE, "POST", "/mcp", { headers: MCP_HEADERS, body: INIT });
    assert("expose: its own loopback name passes the host check and auth is forced (401 without a key)", e2.status === 401, `status ${e2.status}`);
    const e3 = await raw(portE, "POST", "/mcp", { headers: bearer, body: INIT });
    assert("expose: loopback Host plus a valid key reaches the gateway (200)", e3.status === 200, `status ${e3.status}`);
    const eDash = await raw(portE, "POST", "/mcp", { host: `127.0.0.1:${portA}`, headers: bearer, body: INIT });
    assert("expose: the DASHBOARD's host:port is not this listener's name (403)", eDash.status === 403, `status ${eDash.status}`);
    const e4 = await raw(portE, "POST", "/mcp", { host: tunnelHost, headers: bearer, body: INIT });
    assert("expose: the tunnel host is refused until the tunnel URL is known", e4.status === 403, `status ${e4.status}`);
    L.allowPublicUrl(`https://${tunnelHost}`);
    const e5 = await raw(portE, "POST", "/mcp", { host: tunnelHost, headers: bearer, body: INIT });
    assert("expose: once the tunnel URL is known its host reaches /mcp", e5.status === 200, `status ${e5.status}`);
    const e6 = await raw(portE, "POST", "/mcp", { host: tunnelHost, origin: `https://${tunnelHost}`, headers: bearer, body: INIT });
    assert("expose: the tunnel Origin is accepted with the tunnel host", e6.status === 200, `status ${e6.status}`);
    const e7 = await raw(portE, "POST", "/mcp", { host: tunnelHost, origin: "https://evil.example", headers: bearer, body: INIT });
    assert("expose: a foreign Origin on /mcp is 403", e7.status === 403, `status ${e7.status}`);
    const e8 = await raw(portE, "GET", "/anything", { host: tunnelHost });
    assert("expose: the tunnel host cannot reach anything but /mcp (403)", e8.status === 403, `status ${e8.status}`);
    const e9 = await raw(portE, "GET", "/anything");
    assert("expose: other paths on the loopback name are the 404 'only /mcp is exposed'", e9.status === 404 && /only \/mcp is exposed/.test(e9.body), `status ${e9.status}`);
    for (const [label, r] of [["200", e3], ["403", e1], ["404", e9]]) {
      assert(`expose: security headers on the ${label} response, no x-powered-by`,
        r.headers["x-content-type-options"] === "nosniff" && r.headers["referrer-policy"] === "no-referrer" && r.headers["x-frame-options"] === "DENY" && !!r.headers["content-security-policy"] && r.headers["x-powered-by"] === undefined);
    }
    let busyRejected = null;
    try {
      await startMcpListener(gwA, "127.0.0.1", portE, apiKeys);
    } catch (err) {
      busyRejected = err;
    }
    assert("expose: a second listener on the same port REJECTS (it used to resolve)", busyRejected instanceof Error, busyRejected?.message);
    let noAddrRejected = null;
    try {
      await startMcpListener(gwA, "203.0.113.5", await freePort(), apiKeys);
    } catch (err) {
      noAddrRejected = err;
    }
    assert("expose: a bind failure other than a busy port also REJECTS", noAddrRejected instanceof Error, noAddrRejected?.message);
  }
} finally {
  for (const h of handles) {
    try {
      await h.close();
    } catch {
      /* already closed */
    }
  }
  for (const c of children) {
    try {
      c.kill();
    } catch {
      /* already gone */
    }
  }
}

const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
process.exit(failed.length === 0 ? 0 : 1);
