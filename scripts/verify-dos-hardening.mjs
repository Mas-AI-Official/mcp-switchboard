// Deterministic oracle for the three pre-auth / hostile-upstream CPU denial-of-service findings of the
// vNext review (HEAD 9ea8591). Each one was a regular expression that goes super-linear on input an
// attacker chooses, on a single-threaded gateway, so one request or one upstream answer stalls everyone.
//
//   F1  trailing-slash trim `replace(/\/+$/, "")` on the REQUEST PATH runs before the Host check
//       (httpsec.ts isPublicRoutePath / isMcpPath, authserver.ts stripSlash): quadratic in the number of
//       slashes, no credentials needed, reachable through the dashboard listener, the OAuth tunnel and the
//       expose listener. Fixed by a linear trim, plus a URL length guard (414) that runs before HostGuard.
//   F2  an upstream-declared RFC 6570 resource template was compiled to a backtracking RegExp and run on
//       the client's URI (router.ts templateMatches): adjacent variables are n^k. Fixed by a linear
//       matcher (src/uritemplate.ts: a Thompson NFA simulation, no RegExp built from upstream text) with a
//       length cap on template and URI and a step budget shared by all templates of one read.
//   F3  the JWT secret shape in redactSecretShapes (audit.ts) is quadratic on `eyJa-eyJa-...`: one 80 KB
//       upstream error text blocked the gateway for about 10 s even with capture_io off, because
//       AuditLog.append scrubs the error text unconditionally. Fixed by a linear JWT scanner plus a hard
//       cap on the text a scrub will look at (cut back to a token boundary so no secret prefix survives).
//
// What it proves, per finding:
//   * a time budget on the pathological input, at the unit level and through the real surface
//     (live listeners, the real Router over a hostile in-memory upstream, the real AuditLog);
//   * the fix changes no behaviour: differential fuzz against a verbatim copy of the pre-fix code on
//     inputs small enough for the old code to finish (paths, templates x URIs, redaction strings);
//   * the catastrophic cases run in a child process under a deadline, so a regression FAILS this oracle
//     instead of hanging it.
// Every credential-shaped string below is fake and assembled from pieces at run time.
// Zero deps (node stdlib + the package's compiled output + its bundled MCP SDK). Build first.
// Isolated SWITCHBOARD_HOME; never binds a fixed port.
import { mkdtempSync, mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import http from "node:http";
import net from "node:net";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const tmp = mkdtempSync(join(tmpdir(), "sb-dos-"));
const homeRoot = join(tmp, "home");
const SBHOME = join(homeRoot, ".switchboard");
mkdirSync(SBHOME, { recursive: true });
for (const d of ["appdata", "local"]) mkdirSync(join(tmp, d), { recursive: true });
process.env.SWITCHBOARD_HOME = SBHOME;
process.env.HOME = homeRoot;
process.env.USERPROFILE = homeRoot;
process.env.APPDATA = join(tmp, "appdata");
process.env.LOCALAPPDATA = join(tmp, "local");
delete process.env.SWITCHBOARD_AUTO_APPROVE;
delete process.env.SWITCHBOARD_INSECURE_APPROVAL;

const dist = (f) => import(pathToFileURL(join(root, "dist", f)).href);
const { Gateway } = await dist("gateway.js");
const { startDashboard } = await dist("dashboard.js");
const { startMcpListener } = await dist("expose.js");
const { ApiKeyStore } = await dist("apikeys.js");
const httpsec = await dist("httpsec.js");
const { isPublicRoutePath, HostGuard } = httpsec;
const audit = await dist("audit.js");
const { redactSecretShapes, sanitizeForAudit, AuditLog } = audit;
const { SwitchboardAuthProvider } = await dist("authserver.js");
const uritemplate = await dist("uritemplate.js").catch(() => null);

const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  const clean = String(detail).replace(/\x1b\[[0-9;]*m/g, "").replace(/\s+/g, " ").trim();
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${clean ? `: ${clean}` : ""}`);
};
const fmt = (ms) => `${ms.toFixed(1)} ms`;
const j = (...parts) => parts.join(""); // assemble a fake credential from pieces
const PEM_BEGIN = j("-----BEGIN ", "PRIVATE KEY-----");
const PEM_END = j("-----END ", "PRIVATE KEY-----");
const PEM_BEGIN_RSA = j("-----BEGIN RSA ", "PRIVATE KEY-----");

/** Best (smallest) wall time of `runs` executions: noise can only add time, so the minimum is the honest estimate. */
function bestMs(fn, runs = 3) {
  let best = Infinity;
  for (let i = 0; i < runs; i++) {
    const t = process.hrtime.bigint();
    fn();
    best = Math.min(best, Number(process.hrtime.bigint() - t) / 1e6);
  }
  return best;
}

/** mulberry32: a seeded generator so every fuzz run sees the same inputs. */
function prng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const pick = (rnd, arr) => arr[Math.floor(rnd() * arr.length)];

/** Run a fixture case in a child process with a hard deadline. */
function runChild(mode, n, deadlineMs) {
  const t = Date.now();
  const r = spawnSync(process.execPath, [join(root, "scripts", "fixtures", "dos-child.mjs"), mode, String(n)], {
    cwd: root,
    env: { ...process.env, NO_COLOR: "1" },
    encoding: "utf8",
    timeout: deadlineMs,
    killSignal: "SIGKILL",
    maxBuffer: 16 << 20,
  });
  const wall = Date.now() - t;
  const line = String(r.stdout ?? "").split(/\r?\n/).find((l) => l.startsWith("RESULT "));
  if (r.error || r.status !== 0 || !line) {
    return { ok: false, timedOut: r.error?.code === "ETIMEDOUT" || r.signal === "SIGKILL", wall, stderr: String(r.stderr ?? "").slice(-300) };
  }
  return { ok: true, wall, ...JSON.parse(line.slice("RESULT ".length)) };
}

// raw HTTP with full control of Host (fetch cannot forge it)
function raw(port, method, path, { host, headers = {}, body } = {}) {
  return new Promise((resolve) => {
    const h = { Host: host ?? `127.0.0.1:${port}`, ...headers };
    let data;
    if (body !== undefined) {
      data = typeof body === "string" ? body : JSON.stringify(body);
      h["Content-Length"] = Buffer.byteLength(data);
      if (!Object.keys(h).some((k) => k.toLowerCase() === "content-type")) h["Content-Type"] = "application/json";
    }
    const t = process.hrtime.bigint();
    const req = http.request({ host: "127.0.0.1", port, method, path, headers: h, agent: false }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8"), ms: Number(process.hrtime.bigint() - t) / 1e6 }));
    });
    req.on("error", (err) => resolve({ status: 0, headers: {}, body: "", ms: Number(process.hrtime.bigint() - t) / 1e6, error: String(err.message) }));
    req.setTimeout(20_000, () => req.destroy(new Error(`timeout ${method}`)));
    if (data !== undefined) req.write(data);
    req.end();
  });
}
/** Like raw(), but the fastest of `runs` identical requests: a scheduling hiccup can only add time, never remove it. */
async function rawBest(port, method, path, opts, runs = 3) {
  let best = null;
  for (let i = 0; i < runs; i++) {
    const r = await raw(port, method, path, opts);
    if (!best || r.ms < best.ms) best = r;
  }
  return best;
}
const freePort = () =>
  new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });
const INIT = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "verify-dos-hardening", version: "0" } } };
const MCP_HEADERS = { accept: "application/json, text/event-stream" };

const handles = [];
try {
  // =================================================================================================
  // F1. trailing-slash trim on the request path
  // =================================================================================================
  {
    // ---- the reference: the pre-fix code, verbatim ----
    const refIsPublic = (path) => {
      const p = path.toLowerCase().replace(/\/+$/, "") || "/";
      return p === "/mcp" || p === "/authorize" || p === "/token" || p === "/register" || p === "/revoke" || p === "/oauth/consent" || p.startsWith("/.well-known/");
    };

    const slashes15k = "/" + "/".repeat(15_000) + "x";
    const t15 = bestMs(() => isPublicRoutePath(slashes15k));
    assert("F1 isPublicRoutePath: a 15,000-slash path is classified in under 20 ms", t15 < 20, fmt(t15));
    const slashes100k = "/" + "/".repeat(100_000) + "x";
    const t100 = bestMs(() => isPublicRoutePath(slashes100k), 1);
    assert("F1 isPublicRoutePath: a 100,000-slash path is classified in under 100 ms (linear, not quadratic)", t100 < 100, fmt(t100));
    const tTrail = bestMs(() => isPublicRoutePath("/mcp" + "/".repeat(1_000_000)), 1);
    assert("F1 isPublicRoutePath: /mcp followed by 1,000,000 trailing slashes is still /mcp, in under 100 ms", isPublicRoutePath("/mcp" + "/".repeat(1_000_000)) === true && tTrail < 100, fmt(tTrail));

    // ---- behaviour is unchanged (differential against the verbatim old function) ----
    const rnd = prng(0xf1);
    const parts = ["/", "//", "///", "mcp", "MCP", "Mcp/", "token", "authorize", "register", "revoke", ".well-known/", ".WELL-KNOWN/x", "oauth/consent", "oauth/callback", "x", "a", "api/state", ""];
    let mismatches = 0;
    let publicCount = 0;
    for (let i = 0; i < 40_000; i++) {
      let p = rnd() < 0.9 ? "/" : "";
      const k = Math.floor(rnd() * 6);
      for (let q = 0; q < k; q++) p += pick(rnd, parts);
      if (rnd() < 0.3) p += "/".repeat(Math.floor(rnd() * 5));
      const want = refIsPublic(p);
      if (want) publicCount++;
      if (isPublicRoutePath(p) !== want) mismatches++;
    }
    assert("F1 isPublicRoutePath equals the pre-fix function on 40,000 random paths", mismatches === 0 && publicCount > 1000, `mismatches ${mismatches}, public ${publicCount}`);
    assert("F1 the route table still holds", isPublicRoutePath("/mcp/") && isPublicRoutePath("/MCP//") && isPublicRoutePath("/.well-known/oauth-authorization-server") && !isPublicRoutePath("/mcpx") && !isPublicRoutePath("/api/state") && !isPublicRoutePath("//"));

    const strip = httpsec.stripTrailingSlashes;
    assert("F1 httpsec exports stripTrailingSlashes", typeof strip === "function");
    if (typeof strip === "function") {
      let bad = 0;
      const alpha = ["/", "/", "/", "a", "b", ".", " ", "é"];
      for (let i = 0; i < 30_000; i++) {
        let s = "";
        const len = Math.floor(rnd() * 14);
        for (let q = 0; q < len; q++) s += pick(rnd, alpha);
        if (strip(s) !== s.replace(/\/+$/, "")) bad++;
      }
      assert("F1 stripTrailingSlashes equals replace(/\\/+$/, '') on 30,000 random strings", bad === 0, `mismatches ${bad}`);
      const tStrip = bestMs(() => strip("a" + "/".repeat(1_000_000) + "b"), 1);
      assert("F1 stripTrailingSlashes: 1,000,000 interior slashes in under 50 ms", tStrip < 50, fmt(tStrip));
    }

    // ---- HostGuard itself (called directly, so the URL length guard cannot be what saves it) ----
    const guard = new HostGuard({ port: 8088 });
    const mkRes = () => ({
      code: 0,
      status(c) {
        this.code = c;
        return this;
      },
      type() {
        return this;
      },
      send() {
        return this;
      },
    });
    const runGuard = (path, host) => {
      const res = mkRes();
      let nexted = false;
      guard.handler()({ path, method: "GET", headers: { host } }, res, () => (nexted = true));
      return { code: res.code, nexted };
    };
    let g = null;
    const tGuardBad = bestMs(() => (g = runGuard(slashes15k, "evil.example")));
    assert("F1 HostGuard: a forged Host with a 15,000-slash path is refused 403 in under 20 ms", g?.code === 403 && !g.nexted && tGuardBad < 20, `${g?.code}, ${fmt(tGuardBad)}`);
    const tGuardOk = bestMs(() => (g = runGuard(slashes15k, "127.0.0.1:8088")));
    assert("F1 HostGuard: a valid Host with a 15,000-slash path passes in under 20 ms", g?.nexted === true && tGuardOk < 20, `${fmt(tGuardOk)}`);
    const tGuard100 = bestMs(() => (g = runGuard(slashes100k, "evil.example")), 1);
    assert("F1 HostGuard: a 100,000-slash path is refused in under 100 ms", g?.code === 403 && tGuard100 < 100, fmt(tGuard100));

    // ---- authserver stripSlash: the `resource` parameter of authorize / token ----
    const provider = new SwitchboardAuthProvider({ issuerUrl: new URL("https://sb.example.test"), publicUrl: "https://sb.example.test", canonicalResource: "https://sb.example.test/mcp", accessTtlSec: 3600, refreshTtlSec: 3600, consent: false });
    const client = { client_id: "c-dos", client_name: "oracle client", redirect_uris: ["http://127.0.0.1:1/cb"], token_endpoint_auth_method: "none" };
    const res = { redirect() {}, set() {}, status() { return this; }, send() {} };
    const authorize = async (resource) => {
      const t = process.hrtime.bigint();
      let outcome = "bound";
      try {
        await provider.authorize(client, { redirectUri: "http://127.0.0.1:1/cb", codeChallenge: "x".repeat(43), resource, scopes: ["read"], state: "s" }, res);
      } catch (err) {
        outcome = err?.constructor?.name ?? "threw";
      }
      return { ms: Number(process.hrtime.bigint() - t) / 1e6, outcome };
    };
    const evil = await authorize(new URL("https://sb.example.test/" + "/".repeat(100_000) + "x"));
    assert("F1 authserver: a 100,000-slash `resource` is refused (wrong audience) in under 100 ms", evil.outcome === "InvalidTargetError" && evil.ms < 100, `${evil.outcome}, ${fmt(evil.ms)}`);
    const good = await authorize(new URL("https://sb.example.test/mcp///"));
    assert("F1 authserver: the canonical resource with trailing slashes is still accepted", good.outcome === "bound", good.outcome);

    // ---- live listeners ----
    const mkCfg = (port, settings = {}) => ({
      gateway: { transport: ["http"], http: { host: "127.0.0.1", port, require_auth: "auto" }, tool_exposure: "namespaced", default_policy: "read" },
      vault: { backend: "encrypted-file" },
      servers: [],
      settings,
    });
    const MAX = httpsec.MAX_URL_CHARS;
    assert("F1 httpsec exports MAX_URL_CHARS (a number between 2048 and 8192)", Number.isInteger(MAX) && MAX >= 2048 && MAX <= 8192, String(MAX));
    const cap = Number.isInteger(MAX) ? MAX : 4096;

    const portD = await freePort();
    const cfgD = mkCfg(portD, { oauth_server: { enabled: true, public_url: "https://sb.example.test", consent: true, access_token_ttl: 3600, refresh_token_ttl: 1209600 } });
    const gw = new Gateway(cfgD);
    const dash = await startDashboard(gw, cfgD);
    handles.push(dash);
    const longPath = "/" + "/".repeat(15_000) + "x";

    const base = await raw(portD, "GET", "/healthz");
    assert("F1 live dashboard: baseline /healthz is 200", base.status === 200, `${base.status}, ${fmt(base.ms)}`);
    for (const [label, host] of [["forged Host", "evil.example"], ["valid loopback Host", `127.0.0.1:${portD}`], ["public issuer Host", "sb.example.test"]]) {
      const r = await rawBest(portD, "GET", longPath, { host });
      assert(`F1 live dashboard: a 15,000-slash path with a ${label} is answered 414 in under 50 ms`, r.status === 414 && r.ms < 50, `${r.status}, ${fmt(r.ms)}`);
    }
    const r414 = await raw(portD, "GET", longPath, { host: "evil.example" });
    assert("F1 the 414 carries the security headers and no detail", r414.headers["x-content-type-options"] === "nosniff" && !!r414.headers["content-security-policy"] && r414.body.length < 64 && !r414.body.includes("evil.example"), JSON.stringify(r414.body));
    const atCap = await raw(portD, "GET", "/healthz?" + "a".repeat(cap - "/healthz?".length));
    assert("F1 a URL of exactly the cap length is not refused", atCap.status === 200, `${atCap.status}`);
    const overCap = await raw(portD, "GET", "/healthz?" + "a".repeat(cap - "/healthz?".length + 1));
    assert("F1 a URL one character over the cap is 414", overCap.status === 414, `${overCap.status}`);
    const longQuery = await raw(portD, "GET", "/healthz?state=" + "a".repeat(2_000));
    assert("F1 a 2 KB query string (a long OAuth state) is not refused", longQuery.status === 200, `${longQuery.status}`);
    const longPost = await raw(portD, "POST", "/mcp?x=" + "a".repeat(cap), { headers: MCP_HEADERS, body: INIT });
    assert("F1 the URL cap applies to POST as well", longPost.status === 414, `${longPost.status}`);

    const midPath = "/" + "/".repeat(cap - 8) + "x";
    const mid = await rawBest(portD, "GET", midPath);
    assert("F1 live dashboard: a path just under the cap made of slashes is answered in under 100 ms", mid.status !== 414 && mid.ms < 100, `${mid.status}, ${fmt(mid.ms)}`);

    // flood: 40 requests in flight while a probe asks for a legitimate answer
    const flood = async (port, path, hostHeader, probe) => {
      const attackers = Array.from({ length: 40 }, () => raw(port, "GET", path, { host: hostHeader }));
      await new Promise((r) => setTimeout(r, 20));
      const probeResult = await probe();
      await Promise.all(attackers);
      return probeResult;
    };
    const underFlood = await flood(portD, longPath, "evil.example", () => raw(portD, "GET", "/healthz"));
    assert("F1 live dashboard: /healthz answers in under 1000 ms while 40 long-path requests are in flight", underFlood.status === 200 && underFlood.ms < 1000, `${underFlood.status}, ${fmt(underFlood.ms)}`);

    // the expose listener (the one reachable from the internet)
    const portE = await freePort();
    const apiKeys = new ApiKeyStore();
    const key = apiKeys.issue("dos-oracle").token;
    const expose = await startMcpListener(gw, "127.0.0.1", portE, apiKeys);
    handles.push(expose);
    expose.allowPublicUrl("https://tunnel.example.test");
    const eBase = await raw(portE, "POST", "/mcp", { headers: { ...MCP_HEADERS, authorization: `Bearer ${key}` }, body: INIT });
    assert("F1 live expose: baseline authenticated initialize is 200", eBase.status === 200, `${eBase.status}, ${fmt(eBase.ms)}`);
    for (const [label, host] of [["forged Host", "evil.example"], ["tunnel Host", "tunnel.example.test"]]) {
      const r = await rawBest(portE, "POST", longPath, { host, headers: MCP_HEADERS, body: INIT });
      assert(`F1 live expose: a 15,000-slash path with a ${label} and no key is answered 414 in under 50 ms`, r.status === 414 && r.ms < 50, `${r.status}, ${fmt(r.ms)}`);
    }
    const eFlood = await flood(portE, longPath, "tunnel.example.test", () => raw(portE, "POST", "/mcp", { headers: { ...MCP_HEADERS, authorization: `Bearer ${key}` }, body: INIT }));
    assert("F1 live expose: a legitimate POST /mcp answers in under 1000 ms while 40 long-path requests are in flight", eFlood.status === 200 && eFlood.ms < 1000, `${eFlood.status}, ${fmt(eFlood.ms)}`);
    const eMid = await rawBest(portE, "GET", midPath, { host: "evil.example" });
    assert("F1 live expose: a slash path just under the cap with a forged Host is refused 403 in under 100 ms", eMid.status === 403 && eMid.ms < 100, `${eMid.status}, ${fmt(eMid.ms)}`);
  }

  // =================================================================================================
  // F2. resource-template matching
  // =================================================================================================
  {
    const staticRouter = readFileSync(join(root, "dist", "router.js"), "utf8");
    assert("F2 router.js builds no RegExp (nothing an upstream declares is ever compiled)", !/new RegExp\(/.test(staticRouter));
    assert("F2 dist/uritemplate.js exports templateMatches", typeof uritemplate?.templateMatches === "function");

    // the pre-fix compiler, verbatim, as the behavioural reference (only ever run on short inputs)
    const refMatches = (template, uri) => {
      let pattern = "^";
      let last = 0;
      for (const m of template.matchAll(/\{([^}]*)\}/g)) {
        const at = m.index ?? 0;
        pattern += template.slice(last, at).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        const op = (m[1] ?? "")[0];
        pattern +=
          op === "+" || op === "#"
            ? ".+"
            : op === "/"
              ? "(?:/[^/?#]+)+"
              : op === "."
                ? "(?:\\.[^/?#.]+)+"
                : op === ";"
                  ? "(?:;[^/?#;]+)+"
                  : op === "?" || op === "&"
                    ? "(?:[?&][^#]*)?"
                    : "[^/?#]+";
        last = at + m[0].length;
      }
      pattern += template.slice(last).replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "$";
      return new RegExp(pattern).test(uri);
    };

    if (typeof uritemplate?.templateMatches === "function") {
      const tm = uritemplate.templateMatches;
      const rnd = prng(0xf2);
      const lits = ["a", "b", "x", "/", ".", ";", "?", "&", "#", "mem://", "a/", "x.", "{", "}", ":"];
      const vars = ["{a}", "{b}", "{+p}", "{#f}", "{/s}", "{.e}", "{;m}", "{?q}", "{&r}", "{}", "{a,b}", "{%x}"];
      const fills = ["a", "b", "x", "/", ".", ";", "?", "&", "#", "ab", "a/b", "x.y", ";k=v", "?q=1", "\n", "-", "mem://"];
      let compared = 0;
      let mismatches = 0;
      let positives = 0;
      let firstBad = "";
      for (let i = 0; i < 60_000; i++) {
        const nTok = 1 + Math.floor(rnd() * 5);
        let template = "";
        const toks = [];
        for (let q = 0; q < nTok; q++) {
          const isVar = rnd() < 0.5;
          const t = isVar ? pick(rnd, vars) : pick(rnd, lits);
          toks.push([isVar, t]);
          template += t;
        }
        // a URI that is usually an expansion of the template (so there are real matches), sometimes mutated
        let uri = "";
        for (const [isVar, t] of toks) {
          if (!isVar) uri += t;
          else {
            const f = 1 + Math.floor(rnd() * 3);
            for (let k = 0; k < f; k++) uri += pick(rnd, fills);
          }
        }
        if (rnd() < 0.35) {
          const cut = Math.floor(rnd() * (uri.length + 1));
          uri = rnd() < 0.5 ? uri.slice(0, cut) : uri.slice(0, cut) + pick(rnd, fills) + uri.slice(cut);
        }
        if (uri.length > 40) continue; // the old code is exponential: keep it to inputs it finishes
        const want = refMatches(template, uri);
        const got = tm(template, uri);
        compared++;
        if (want) positives++;
        if (got !== want) {
          mismatches++;
          if (!firstBad) firstBad = `template ${JSON.stringify(template)} uri ${JSON.stringify(uri)} want ${want} got ${got}`;
        }
      }
      assert("F2 templateMatches equals the pre-fix compiler on random templates and URIs", mismatches === 0 && compared > 40_000 && positives > 5_000, `compared ${compared}, positives ${positives}, mismatches ${mismatches} ${firstBad}`);

      // the shipped examples
      assert("F2 alpha://doc/{id} matches alpha://doc/99 and not alpha://doc/9/9 or beta://doc/9", tm("alpha://doc/{id}", "alpha://doc/99") && !tm("alpha://doc/{id}", "alpha://doc/9/9") && !tm("alpha://doc/{id}", "beta://doc/9"));
      assert("F2 reserved expansion {+path} spans slashes", tm("file:///{+path}", "file:///a/b/c.txt") && !tm("file:///{+path}", "file://"));
      assert("F2 an empty variable value never matches ({id} needs one character)", !tm("alpha://doc/{id}", "alpha://doc/"));

      // adjacent variables: the n^k case
      const hostile = "mem://{a}{b}{c}{d}{e}{f}{g}x";
      const uriOf = (n) => `mem://${"ax".repeat(Math.floor(n / 2))}b`;
      const tNear = bestMs(() => tm(hostile, uriOf(64)), 3);
      assert("F2 7 adjacent variables on a 64 character URI: under 20 ms (old code: seconds)", tNear < 20 && tm(hostile, uriOf(64)) === false, fmt(tNear));
      const tMax = bestMs(() => tm(hostile, uriOf(8_000)), 1);
      assert("F2 7 adjacent variables on an 8,000 character URI: under 250 ms and no match", tMax < 250 && tm(hostile, uriOf(8_000)) === false, fmt(tMax));
      assert("F2 the same template still matches a URI that fits it", tm(hostile, "mem://abcdefgx") === true);
      const sepVars = "mem://{a}x{b}x{c}x{d}x{e}x{f}x{g}y"; // literals between the variables: still n^k for a backtracker
      const tSep = bestMs(() => tm(sepVars, uriOf(6_000)), 1);
      assert("F2 variables separated by a literal that their class also contains: 6,000 characters under 250 ms", tSep < 250 && tm(sepVars, uriOf(6_000)) === false, fmt(tSep));
      const everyOp = "{+a}{#b}{/c}{.d}{;e}{?f}{&g}{h}".repeat(8);
      const tOps = bestMs(() => tm(everyOp, "x".repeat(8_000)), 1);
      assert("F2 every operator, repeated, against 8,000 characters: under 250 ms", tOps < 250, fmt(tOps));

      // limits and the shared budget
      assert("F2 a URI over the length cap never matches", tm("{+a}", "x".repeat(uritemplate.MAX_URI_LEN + 1)) === false && tm("{+a}", "x".repeat(uritemplate.MAX_URI_LEN)) === true);
      assert("F2 a template over the length cap never matches", tm("a".repeat(uritemplate.MAX_TEMPLATE_LEN + 1), "a".repeat(uritemplate.MAX_TEMPLATE_LEN + 1)) === false && tm("a".repeat(uritemplate.MAX_TEMPLATE_LEN), "a".repeat(uritemplate.MAX_TEMPLATE_LEN)) === true);
      assert("F2 a non-string template (a malformed upstream) is a non-match, not a throw", (() => { try { return tm(undefined, "x") === false && tm(42, "x") === false; } catch { return false; } })());
      const budget = { steps: uritemplate.DEFAULT_STEP_BUDGET };
      const worst = "{+a}{#b}{/c}{.d}{;e}{?f}{&g}{h}{+i}{#j}{/k}{.l}{;m}{?n}{&o}{p}".repeat(2);
      const longUri = "x".repeat(uritemplate.MAX_URI_LEN);
      const tMany = bestMs(() => {
        let hit = false;
        for (let i = 0; i < 400; i++) hit = tm(worst, longUri, budget) || hit;
        return hit;
      }, 1);
      assert("F2 400 hostile templates against an 8,192 character URI share one budget: under 1500 ms in total", tMany < 1500 && budget.steps <= 0, `${fmt(tMany)}, steps left ${budget.steps}`);
      assert("F2 once the budget is spent a template is a non-match", tm("a", "a", { steps: 0 }) === false && tm("a", "a", { steps: 1000 }) === true);
    }

    // through the real Router over a hostile in-memory upstream (child process, hard deadline)
    for (const n of [64, 2_000, 8_000]) {
      const r = runChild("template-router", n, 20_000);
      assert(
        `F2 Router.readResource: URI of ${n} characters against 7 adjacent variables is answered in under 1000 ms`,
        r.ok && r.ms < 1000 && r.outcome === "unknown" && r.honestRead === "honest-read",
        r.ok ? `${fmt(r.ms)}, ${r.outcome}, honest upstream read: ${r.honestRead}` : `${r.timedOut ? "TIMED OUT after 20 s" : "failed"} ${r.stderr ?? ""}`,
      );
      if (!r.ok) break; // the catastrophic case would only repeat itself for the larger sizes
    }
  }

  // =================================================================================================
  // F3. secret-shape redaction
  // =================================================================================================
  {
    const CAP = audit.REDACT_MAX_CHARS;
    assert("F3 audit exports REDACT_MAX_CHARS (a number between 2048 and 65536)", Number.isInteger(CAP) && CAP >= 2048 && CAP <= 65536, String(CAP));
    const cap = Number.isInteger(CAP) ? CAP : 8192;

    const hostileJwt = "eyJa-".repeat(Math.floor(cap / 5));
    const t1 = bestMs(() => redactSecretShapes(hostileJwt));
    assert(`F3 redactSecretShapes: eyJa- repeated to the scan cap (${cap} characters) in under 20 ms`, t1 < 20, fmt(t1));
    const t2 = bestMs(() => redactSecretShapes("eyJa-".repeat(16_000)), 1);
    assert("F3 redactSecretShapes: 80,000 characters of eyJa- in under 100 ms (it took 5.9 s)", t2 < 100, fmt(t2));
    const t3 = bestMs(() => sanitizeForAudit({ content: [{ type: "text", text: "eyJa-".repeat(16_000) }] }), 1);
    assert("F3 sanitizeForAudit: an 80 KB upstream result text in under 150 ms (200 KB took 55 s)", t3 < 150, fmt(t3));

    // every shape, with an input built to make that shape's regex work hard
    const N = 200_000;
    const adversarial = {
      jwt: ["eyJa-".repeat(N / 5), "eyJaaaa.".repeat(N / 8), "eyJaaaa.bbbb-".repeat(N / 13), ("eyJ" + "a".repeat(5) + ".").repeat(N / 9), "eyJaaaa.bbbb.cc-".repeat(N / 16)],
      pem: [PEM_BEGIN_RSA.repeat(N / 31), "-----BEGIN ".repeat(N / 11), "-----BEGIN A-----\n" + "A".repeat(N)],
      bearer: ["Bearer ".repeat(N / 7), "Bearer" + " ".repeat(N) + "x"],
      sk: ["sk-".repeat(N / 3), "sk-aaaa".repeat(N / 7)],
      google: ["AIza".repeat(N / 4)],
      github: ["ghp_".repeat(N / 4), "github_pat_".repeat(N / 11)],
      slack: ["xoxb-".repeat(N / 5)],
      hf: ["hf_".repeat(N / 3)],
      aws: ["AKIA".repeat(N / 4)],
      generic: ["key=" + "a".repeat(N), "key" + " ".repeat(N) + "x", "keykeykey".repeat(N / 9), "token: ".repeat(N / 7), "secret is ".repeat(N / 10), ("key=" + "a".repeat(31) + " ").repeat(N / 36)],
    };
    let slowest = { kind: "", ms: 0 };
    for (const [kind, inputs] of Object.entries(adversarial)) {
      for (const input of inputs) {
        const ms = bestMs(() => redactSecretShapes(input), 1);
        if (ms > slowest.ms) slowest = { kind, ms };
      }
    }
    assert("F3 redactSecretShapes: 200,000 characters of adversarial input for every shape, each under 100 ms", slowest.ms < 100, `slowest ${slowest.kind} ${fmt(slowest.ms)}`);

    // the cap: bounded output, no secret prefix survives the cut, a secret inside the cap is still caught
    const big = redactSecretShapes("lorem ipsum ".repeat(50_000));
    assert("F3 an over-cap text is cut to the cap plus a marker", big.length <= cap + 64 && /\[truncated:\d+\]$/.test(big), `${big.length} characters, tail ${JSON.stringify(big.slice(-24))}`);
    const secret = j("s", "k-proj-") + "a1B2c3D4e5F6g7H8".repeat(3);
    const straddle = (pad) => redactSecretShapes("x ".repeat(Math.floor(pad / 2)) + secret + " tail ".repeat(2_000));
    let leaked = 0;
    for (let k = 0; k < 40; k++) {
      const out = straddle(cap - 2 * k - 3);
      if (/sk-p|proj-|a1B2/.test(out)) leaked++; // "[redacted:sk-key]" is fine, key material is not
    }
    assert("F3 a key that straddles the cap leaves no prefix behind (40 cut positions)", leaked === 0, `leaked ${leaked}`);
    const dropped = straddle(cap - 3);
    assert("F3 the straddle case is real: with the cut inside the key the whole key is dropped (no marker, no prefix)", !/redacted|sk-p|proj|a1B2/.test(dropped), dropped.slice(-40));
    assert("F3 a key inside the cap is redacted", redactSecretShapes("api failed with " + secret) === "api failed with [redacted:sk-key]");
    const pem = PEM_BEGIN + "\n" + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n".repeat(400) + PEM_END;
    const pemOut = redactSecretShapes("x ".repeat(cap / 2 - 100) + pem);
    assert("F3 a PEM block that starts inside the cap and runs past it is redacted to the cut", !/MIIEvQ/.test(pemOut) && pemOut.includes("[redacted:pem-block]"), JSON.stringify(pemOut.slice(-60)));

    // differential: the fix changes what is redacted for no short input
    const refShapes = [
      ["pem-block", /-----BEGIN [A-Z0-9 ]{1,40}-----[\s\S]*?(?:-----END [A-Z0-9 ]{1,40}-----|$)/g],
      ["bearer", /\b[Bb]earer\s+[A-Za-z0-9._~+/=-]{8,}/g],
      ["jwt", /\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*/g],
      ["sk-key", /(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{16,}/g],
      ["google-api-key", /(?<![A-Za-z0-9_-])AIza[A-Za-z0-9_-]{30,}/g],
      ["github-token", /(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})/g],
      ["slack-token", /(?<![A-Za-z0-9_-])xox[abpr]-[A-Za-z0-9-]{8,}/g],
      ["huggingface-token", /(?<![A-Za-z0-9_])hf_[A-Za-z0-9]{20,}/g],
      ["aws-access-key", /(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])/g],
    ];
    const refGeneric = /((?:key|token|secret)[A-Za-z_]{0,12}(?:\s+is)?[^A-Za-z0-9\r\n]{1,8})([A-Za-z0-9_-]{32,})(?![A-Za-z0-9_-])/gi;
    const refRedact = (text) => {
      if (text.length < 8) return text;
      let out = text;
      for (const [kind, re] of refShapes) out = out.replace(re, `[redacted:${kind}]`);
      out = out.replace(refGeneric, (_m, lead, token) => `${lead}[redacted:${/^[0-9a-fA-F]+$/.test(token) ? "hex-token" : "b64url-token"}]`);
      return out;
    };
    const rnd = prng(0xf3);
    const frags = [
      "eyJ", "eyJa", "eyJhbGci", "abcd", "abcdefghij", "aB3_-", "-", "_", ".", "..", " ", "\n", "x", "ey", "J",
      "Bearer ", "bearer  ", "sk-", j("sk", "-abcdefghijklmnop"), "AIza", j("AI", "zaSyA1234567890abcdefghijklmnopqrstu"), "ghp_", j("gh", "p_abcdefghijklmnopqrstuvwx"),
      "xoxb-", j("xo", "xb-12345678"), "hf_", j("h", "f_abcdefghijklmnopqrstuvwx"), "AKIA", j("AK", "IAABCDEFGHIJKLMNOP"), "key=", "token: ", "secret is ", "api_key = ",
      "0123456789abcdef0123456789abcdef", PEM_BEGIN, PEM_END, j("ey", "JhbGciOi.eyJzdWIiOiIx.c2ln"), "eyJabcd.abcd.", "eyJabcd.abcd.-x", "eyJabcd.abc",
    ];
    let jwtHits = 0;
    let bad = 0;
    let firstBad = "";
    for (let i = 0; i < 60_000; i++) {
      let s = "";
      const k = 1 + Math.floor(rnd() * 8);
      for (let q = 0; q < k; q++) s += pick(rnd, frags);
      if (s.length > 200) continue;
      const want = refRedact(s);
      if (want.includes("[redacted:jwt]")) jwtHits++;
      const got = redactSecretShapes(s);
      if (got !== want) {
        bad++;
        if (!firstBad) firstBad = `input ${JSON.stringify(s)} want ${JSON.stringify(want)} got ${JSON.stringify(got)}`;
      }
    }
    assert("F3 redactSecretShapes equals the pre-fix redactor on 60,000 random strings built from secret fragments", bad === 0 && jwtHits > 1_500, `mismatches ${bad}, jwt hits ${jwtHits} ${firstBad}`);
    const jwt = j("ey", "JhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk");
    assert("F3 a real-shaped JWT is still redacted, inside prose and after a dash", redactSecretShapes(`token was ${jwt}.`) === "token was [redacted:jwt]." && redactSecretShapes(`x-${jwt}`) === "x-[redacted:jwt]");

    // AuditLog.append: the error text is scrubbed whether or not capture_io is on
    const log = new AuditLog(join(SBHOME, "audit-dos"));
    const tAppend = bestMs(() => log.append({ server: "hostile", tool: "redos_error", scope: "write", decision: "allow", error: "eyJa-".repeat(16_000), error_code: "SB_UPSTREAM_ERROR" }), 1);
    const row = JSON.parse(readFileSync(log.path, "utf8").trim().split("\n").pop());
    assert("F3 AuditLog.append: an 80,000 character error text is stored in under 150 ms, bounded and marked", tAppend < 150 && row.error.length <= cap + 64 && /\[truncated:80000\]$/.test(row.error), `${fmt(tAppend)}, stored ${row.error.length} characters`);
    log.append({ server: "s", tool: "t", scope: "read", decision: "allow", error: "boom " + secret });
    const row2 = JSON.parse(readFileSync(log.path, "utf8").trim().split("\n").pop());
    const capped = sanitizeForAudit({ b: "y".repeat(9_000) });
    assert("F3 sanitizeForAudit: a 9,000 character value is still an over-cap capture with a marker that reports its real size", typeof capped._truncated === "number" && capped._truncated >= 9_000, JSON.stringify(capped).slice(0, 80));
    assert("F3 AuditLog.append still scrubs a credential echoed in a normal error", row2.error === "boom [redacted:sk-key]", row2.error);

    // through the real Router (capture_io off, then on) in a child process with a deadline
    const r = runChild("redact-router", 80_000, 30_000);
    assert(
      "F3 Router.callTool: one upstream error text of 80,000 bytes returns in under 500 ms with capture_io off and on (it took 10 s)",
      r.ok && r.off_ms < 500 && r.on_ms < 500 && r.off_isError && r.on_isError && r.rows === 2 && r.maxErrorLen <= cap + 64,
      r.ok ? `off ${fmt(r.off_ms)}, on ${fmt(r.on_ms)}, rows ${r.rows}, longest stored error ${r.maxErrorLen}` : `${r.timedOut ? "TIMED OUT after 30 s" : "failed"} ${r.stderr ?? ""}`,
    );
  }
} finally {
  for (const h of handles) {
    try {
      await h.close();
    } catch {
      /* already closed */
    }
  }
}

const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
process.exit(failed.length === 0 ? 0 : 1);
