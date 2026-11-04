// Deterministic oracle for the outbound SSRF guard (src/netguard.ts) and its wiring into every
// outbound caller: http-tool, app2mcp (OpenAPI spec fetch and calls), webhooks, OAuth token calls,
// the council and the catalog. Real local http servers on ephemeral ports plus the guard's resolver
// seam; ZERO external network, ZERO model tokens. The oracle computes every verdict itself.
//
// It proves:
//   address classes   - loopback, RFC1918, CGNAT 100.64/10, link-local 169.254/16 and fe80::/10, ULA
//                       fc00::/7, unspecified, multicast, reserved, cloud metadata (incl. the
//                       IPv4-mapped, NAT64 and 6to4 encodings of private IPv4) are refused; public
//                       neighbours of every range boundary pass
//   blocked targets   - 127.0.0.1, 10.x, 169.254.169.254, [::1], decimal and hex IPv4 spellings,
//                       localhost, *.localhost, a metadata hostname, a hostname that resolves to a
//                       private address (also when only ONE of several answers is private): the
//                       connection is never attempted (the local server records zero hits)
//   allowlist         - an exact host in network.allow_private passes; 127.0.0.1 does not allow
//                       localhost and localhost does not allow 127.0.0.1; entries are validated
//   pinned resolution - the connection goes to the address the guard validated (a hostname the OS
//                       cannot resolve is reached through the injected answer), Host header intact
//   redirects         - followed manually, max 3, every hop re-validated (redirect to a metadata
//                       address, a private address, a not-allowlisted spelling of a loopback host
//                       and a non-http scheme are all refused); Authorization, Cookie, API-key style
//                       and caller-named credential headers are dropped on an origin change and kept
//                       on a same-origin hop; 301/302 POST becomes GET without a body; a 307/308 that
//                       would re-send a body to another origin is refused
//   time and size     - a hung server and a stalled body both hit the timeout; the size cap fires
//                       while streaming (chunked, no content-length), on a declared content-length,
//                       on a gzip bomb (decoded bytes are counted) and exactly at the boundary
//   wiring            - http-tool, app2mcp, webhook, council and the local-llm probe use the guard;
//                       no module outside netguard.ts calls fetch() directly; openapi refuses a
//                       spec-derived base host when the server carries credentials or inject_args,
//                       and requires an explicit base_url in that case; spec paths that do not start
//                       with "/" (host confusion) are skipped; the config schema validates network
// Zero deps (node stdlib + the package's compiled output + its bundled MCP SDK). Build first.
import http from "node:http";
import zlib from "node:zlib";
import { mkdtempSync, writeFileSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// Never touch the operator's real state: every path the modules might use lives under a temp dir.
const TMP = mkdtempSync(join(tmpdir(), "sb-netguard-"));
process.env.HOME = join(TMP, "home");
process.env.USERPROFILE = process.env.HOME;
process.env.APPDATA = join(TMP, "appdata");
process.env.LOCALAPPDATA = join(TMP, "local");
process.env.SWITCHBOARD_HOME = join(process.env.HOME, ".switchboard");
process.env.NETGUARD_ORACLE_FAKE_SECRET = "fake-secret-value-for-oracle";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const { guardedFetch, NetGuardError, classifyAddress, parseAllowEntry, assertUrlAllowed, setResolverForTests } =
  await import("../dist/netguard.js");
const { buildHttpToolServer } = await import("../dist/httptool.js");
const { buildOpenApiServer } = await import("../dist/openapi.js");
const { deliverWebhook } = await import("../dist/webhook.js");
const { buildCouncilServer } = await import("../dist/council.js");
const { probeRuntime, withLocalAllowance } = await import("../dist/localllm.js");
const { Registry } = await import("../dist/registry.js");
const { Vault } = await import("../dist/vault.js");
const { loadConfig } = await import("../dist/config.js");
const { Client, InMemoryTransport } = await import("@modelcontextprotocol/client");

const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? ` - ${detail}` : ""}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
/** Turn a hang into a failing check instead of a stuck run (a broken timeout would otherwise never return). */
const within = (ms, p) => Promise.race([p, new Promise((_, reject) => setTimeout(() => reject(new Error(`HUNG after ${ms} ms`)), ms).unref())]);
const MiB = 1024 * 1024;

/** Run a promise and report "OK" or the NetGuardError code (or a non-guard marker). */
async function outcome(p) {
  try {
    await p;
    return "OK";
  } catch (e) {
    return e instanceof NetGuardError ? e.code : `non-guard: ${e && e.message}`;
  }
}
async function errorOf(p) {
  try {
    await p;
    return null;
  } catch (e) {
    return e;
  }
}

// --- local servers on ephemeral ports ------------------------------------------------------------
const servers = [];
function listen(handler) {
  return new Promise((resolve) => {
    const state = { hits: [], port: 0, base: "" };
    const srv = http.createServer((req, res) => {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        const rec = { method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks) };
        state.hits.push(rec);
        handler(req, res, rec, state);
      });
    });
    srv.listen(0, "127.0.0.1", () => {
      state.port = srv.address().port;
      state.base = `http://127.0.0.1:${state.port}`;
      state.server = srv;
      servers.push(srv);
      resolve(state);
    });
  });
}
const text = (res, body, status = 200, headers = {}) => {
  res.writeHead(status, { "content-type": "text/plain", ...headers });
  res.end(body);
};
const redirect = (res, status, location) => {
  res.writeHead(status, { location });
  res.end();
};

const ALLOW = { allow_private: ["127.0.0.1"] };

// ====================================================================================================
// 1. address classification (pure)
// ====================================================================================================
{
  const blocked = [
    "127.0.0.1", "127.255.255.254", "10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255",
    "192.168.1.1", "100.64.0.1", "100.127.255.255", "169.254.169.254", "169.254.1.1", "169.254.170.2",
    "0.0.0.0", "0.1.2.3", "224.0.0.1", "239.255.255.250", "255.255.255.255", "240.0.0.1",
    "192.0.0.192", "192.0.2.1", "198.51.100.7", "203.0.113.9", "168.63.129.16", "100.100.100.200",
    "::1", "::", "fe80::1", "febf::1", "fc00::1", "fd12:3456::1", "fd00:ec2::254", "ff02::1", "fec0::1",
    "::ffff:127.0.0.1", "::ffff:7f00:1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "::ffff:a9fe:a9fe",
    "64:ff9b::7f00:1", "64:ff9b::a00:1", "64:ff9b:1::1", "2002:7f00:1::1", "2002:a9fe:a9fe::1",
    "2001:db8::1", "2001::1", "100::1", "3fff::1", "::127.0.0.1", "fe80::1%eth0",
  ];
  const missed = blocked.filter((ip) => classifyAddress(ip) === null);
  assert(`all ${blocked.length} non-public addresses are classified as blocked`, missed.length === 0, missed.join(", "));

  const pub = [
    "8.8.8.8", "1.1.1.1", "93.184.216.34", "100.63.255.255", "100.128.0.1", "172.15.255.255", "172.32.0.1",
    "169.253.1.1", "169.255.0.1", "192.169.0.1", "192.167.255.255", "11.0.0.1", "9.255.255.255",
    "198.18.0.1", "223.255.255.254",
    "2606:4700:4700::1111", "2001:4860:4860::8888", "::ffff:8.8.8.8", "64:ff9b::808:808", "2002:808:808::1",
  ];
  const wrongly = pub.filter((ip) => classifyAddress(ip) !== null);
  assert(`all ${pub.length} public neighbours of the boundaries pass`, wrongly.length === 0, wrongly.map((ip) => `${ip}:${classifyAddress(ip)}`).join(", "));

  assert("metadata address carries a metadata reason", /metadata/i.test(classifyAddress("169.254.169.254") ?? ""), classifyAddress("169.254.169.254"));
  assert("garbage is refused, not passed", classifyAddress("not-an-ip") !== null && classifyAddress("999.1.1.1") !== null);
}

// ====================================================================================================
// 2. allowlist entry parsing (pure)
// ====================================================================================================
{
  const ok = (e) => parseAllowEntry(e);
  assert("allow entry: ipv4 literal", ok("127.0.0.1").host === "127.0.0.1");
  assert("allow entry: host name is lower-cased", ok("LocalHost").host === "localhost");
  assert("allow entry: bracketed and bare ipv6 normalise alike", ok("[::1]").host === "::1" && ok("::1").host === "::1");
  assert("allow entry: trailing dot is stripped", ok("ollama.lan.").host === "ollama.lan");
  assert("allow entry: decimal ipv4 normalises", ok("2130706433").host === "127.0.0.1");
  for (const bad of ["http://x", "host:11434", "10.0.0.0/8", "*.lan", "", "  ", "a b", "user@host", "host/path", "[::1]:80"]) {
    assert(`allow entry rejected: ${JSON.stringify(bad)}`, typeof parseAllowEntry(bad).error === "string");
  }
}

// ====================================================================================================
// 3. blocked targets: refused before any connection
// ====================================================================================================
{
  const sentinel = await listen((req, res) => text(res, "should never be reached"));
  const port = sentinel.port;
  const t = (url, network) => outcome(guardedFetch(url, {}, network ?? { timeout_ms: 2000 }));

  setResolverForTests(null); // the real OS resolver for localhost and friends
  assert("127.0.0.1 is refused by default", (await t(`http://127.0.0.1:${port}/`)) === "blocked_address");
  assert("refused request never reached the local server", sentinel.hits.length === 0, String(sentinel.hits.length));
  assert("10.x is refused", (await t("http://10.0.0.5:8080/")) === "blocked_address");
  assert("172.16/12 is refused", (await t("http://172.16.4.4/")) === "blocked_address");
  assert("192.168/16 is refused", (await t("http://192.168.0.10/")) === "blocked_address");
  assert("CGNAT 100.64/10 is refused", (await t("http://100.64.0.1/")) === "blocked_address");
  assert("169.254.169.254 is refused", (await t("http://169.254.169.254/latest/meta-data/")) === "blocked_address");
  assert("[::1] is refused", (await t(`http://[::1]:${port}/`)) === "blocked_address");
  assert("[fe80::1] is refused", (await t("http://[fe80::1]/")) === "blocked_address");
  assert("[fc00::1] (ULA) is refused", (await t("http://[fc00::1]/")) === "blocked_address");
  assert("[::ffff:127.0.0.1] is refused", (await t(`http://[::ffff:127.0.0.1]:${port}/`)) === "blocked_address");
  assert("0.0.0.0 is refused", (await t(`http://0.0.0.0:${port}/`)) === "blocked_address");
  assert("multicast 224.0.0.1 is refused", (await t("http://224.0.0.1/")) === "blocked_address");
  assert("decimal ipv4 spelling of 127.0.0.1 is refused", (await t(`http://2130706433:${port}/`)) === "blocked_address");
  assert("hex ipv4 spelling of 127.0.0.1 is refused", (await t(`http://0x7f.0.0.1:${port}/`)) === "blocked_address");
  assert("short ipv4 spelling 127.1 is refused", (await t(`http://127.1:${port}/`)) === "blocked_address");
  assert("octal ipv4 spelling 0177.0.0.1 is refused", (await t(`http://0177.0.0.1:${port}/`)) === "blocked_address");
  assert("ipv4 with a trailing dot is refused", (await t(`http://127.0.0.1.:${port}/`)) === "blocked_address");
  assert("fullwidth-digit ipv4 spelling is refused", (await t(`http://①②⑦.0.0.1:${port}/`)) === "blocked_address");
  assert("long-form ipv4-mapped ipv6 spelling is refused", (await t(`http://[0:0:0:0:0:ffff:7f00:1]:${port}/`)) === "blocked_address");
  assert("localhost is refused", (await t(`http://localhost:${port}/`)) === "blocked_host");
  assert("localhost. (trailing dot) is refused", (await t(`http://localhost.:${port}/`)) === "blocked_host");
  assert("name.localhost is refused", (await t(`http://api.localhost:${port}/`)) === "blocked_host");
  assert("metadata.google.internal is refused by name", (await t("http://metadata.google.internal/computeMetadata/v1/")) === "blocked_host");
  assert("sentinel server saw nothing from any of the blocked requests", sentinel.hits.length === 0, String(sentinel.hits.length));

  const err = await errorOf(guardedFetch(`http://127.0.0.1:${port}/`, {}, { timeout_ms: 2000 }));
  assert("the refusal message tells the operator how to allow a local host", /allow_private/.test(err?.message ?? ""), err?.message);

  // a hostname whose DNS answer is private (resolver seam): single private answer, and a MIXED answer
  const table = {
    "evil.test": [{ address: "169.254.169.254", family: 4 }],
    "mixed.test": [{ address: "93.184.216.34", family: 4 }, { address: "10.0.0.5", family: 4 }],
    "v6.test": [{ address: "fd00::5", family: 6 }],
  };
  setResolverForTests(async (host) => table[host] ?? [{ address: "93.184.216.34", family: 4 }]);
  assert("hostname resolving to 169.254.169.254 is refused", (await t("http://evil.test/x")) === "blocked_address");
  assert("hostname with one private answer among public ones is refused", (await t("http://mixed.test/x")) === "blocked_address");
  assert("hostname resolving to a ULA address is refused", (await t("https://v6.test/x")) === "blocked_address");

  // schemes and embedded credentials
  assert("file: scheme is refused", (await t("file:///etc/passwd")) === "bad_scheme");
  assert("ftp: scheme is refused", (await t("ftp://example.com/x")) === "bad_scheme");
  assert("data: scheme is refused", (await t("data:text/plain,hi")) === "bad_scheme");
  assert("URL with embedded credentials is refused", (await t("http://user:pw@example.com/")) === "invalid_url");
  assert("unparseable URL is refused", (await t("http://")) === "invalid_url");

  assert("assertUrlAllowed refuses without fetching", (await outcome(assertUrlAllowed(`http://127.0.0.1:${port}/`, {}))) === "blocked_address");
  assert("assertUrlAllowed passes an allowlisted host", (await outcome(assertUrlAllowed(`http://127.0.0.1:${port}/`, ALLOW))) === "OK");
  assert("assertUrlAllowed never connected", sentinel.hits.length === 0);
  setResolverForTests(null);
}

// ====================================================================================================
// 4. allowlist semantics, pinned resolution and plain behaviour
// ====================================================================================================
{
  const S = await listen((req, res, rec) => {
    if (req.url === "/json") return text(res, JSON.stringify({ hello: "wörld" }), 200, { "content-type": "application/json" });
    if (req.url === "/echo") return text(res, JSON.stringify({ method: req.method, body: rec.body.toString(), ct: req.headers["content-type"] ?? null, host: req.headers.host, ua: req.headers["user-agent"] ?? null }), 200, { "content-type": "application/json" });
    if (req.url === "/404") return text(res, "nope", 404);
    if (req.url === "/204") { res.writeHead(204); return res.end(); }
    return text(res, "hello");
  });

  setResolverForTests(null);
  const r = await guardedFetch(`${S.base}/`, {}, ALLOW);
  assert("allowlisted 127.0.0.1 passes: status, ok and body", r.status === 200 && r.ok && (await r.text()) === "hello");
  assert("the server saw exactly one request", S.hits.length === 1);

  assert("allow_private [localhost] does NOT allow the 127.0.0.1 literal (exact host)", (await outcome(guardedFetch(`${S.base}/`, {}, { allow_private: ["localhost"] }))) === "blocked_address");
  assert("allow_private [127.0.0.1] does NOT allow localhost (exact host)", (await outcome(guardedFetch(`http://localhost:${S.port}/`, {}, ALLOW))) === "blocked_host");
  const viaLocalhost = await outcome(guardedFetch(`http://localhost:${S.port}/`, {}, { allow_private: ["LOCALHOST"] }));
  assert("allow_private [localhost] allows http://localhost (case-insensitive)", viaLocalhost === "OK", viaLocalhost);
  assert("a settings thunk is honoured", (await outcome(guardedFetch(`${S.base}/`, {}, () => ALLOW))) === "OK");
  assert("a bad allowlist entry in settings never widens access", (await outcome(guardedFetch(`${S.base}/`, {}, { allow_private: ["127.0.0.0/8", "*"] }))) === "blocked_address");

  const j = await guardedFetch(`${S.base}/json`, {}, ALLOW);
  assert("json() parses and utf-8 is decoded", (await j.json()).hello === "wörld");
  const nf = await guardedFetch(`${S.base}/404`, {}, ALLOW);
  assert("404 gives ok=false and the body", nf.status === 404 && nf.ok === false && (await nf.text()) === "nope");
  const nc = await guardedFetch(`${S.base}/204`, {}, ALLOW);
  assert("204 has an empty body", nc.status === 204 && (await nc.text()) === "");

  const post = await guardedFetch(`${S.base}/echo`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ a: 1 }) }, ALLOW);
  const pj = await post.json();
  assert("POST body and content-type reach the server", pj.method === "POST" && pj.body === '{"a":1}' && pj.ct === "application/json", JSON.stringify(pj));
  assert("a default user-agent is sent", typeof pj.ua === "string" && pj.ua.length > 0, String(pj.ua));
  const form = await guardedFetch(`${S.base}/echo`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "x", code: "y" }) }, ALLOW);
  assert("URLSearchParams body is sent form-encoded", (await form.json()).body === "grant_type=x&code=y");

  // pinned resolution: the OS cannot resolve pinned.test, so success proves the guard's answer was used
  let resolverCalls = 0;
  setResolverForTests(async (host) => {
    resolverCalls++;
    return host === "pinned.test" ? [{ address: "127.0.0.1", family: 4 }] : [{ address: "93.184.216.34", family: 4 }];
  });
  let pinned = null;
  let pinnedBody = {};
  const pinnedErr = await errorOf((async () => {
    pinned = await guardedFetch(`http://pinned.test:${S.port}/echo`, {}, { allow_private: ["pinned.test"] });
    pinnedBody = await pinned.json();
  })());
  assert("connection goes to the validated address (unresolvable-by-OS name reached)", pinned?.status === 200, pinnedErr?.message);
  assert("Host header keeps the original name and port", pinnedBody.host === `pinned.test:${S.port}`, pinnedBody.host);
  assert("the name was resolved exactly once", resolverCalls === 1, String(resolverCalls));
  assert("allowlisting the name does not allow the bare address", (await outcome(guardedFetch(`http://pinned.test:${S.port}/`, {}, {}))) === "blocked_address");
  setResolverForTests(null);
}

// ====================================================================================================
// 5. redirects
// ====================================================================================================
{
  const B = await listen((req, res) => text(res, "landing-B"));
  const A = await listen((req, res, rec) => {
    const u = req.url;
    if (u === "/x") return redirect(res, 302, `${B.base}/landing`);
    if (u === "/same") return redirect(res, 302, "/same-final");
    if (u === "/same-final") return text(res, "same-origin-final");
    const hop = u.match(/^\/h\/(\d+)$/);
    if (hop) return Number(hop[1]) === 0 ? text(res, "end-of-chain") : redirect(res, 302, `/h/${Number(hop[1]) - 1}`);
    if (u === "/to-metadata") return redirect(res, 302, "http://169.254.169.254/latest/meta-data/");
    if (u === "/to-private") return redirect(res, 302, "http://10.0.0.5/secret");
    if (u === "/to-localhost-name") return redirect(res, 302, `http://localhost:${B.port}/landing`);
    if (u === "/to-ipv6") return redirect(res, 302, `http://[::1]:${B.port}/landing`);
    if (u === "/to-file") return redirect(res, 302, "file:///etc/passwd");
    if (u === "/post302") return redirect(res, 302, "/after");
    if (u === "/post303") return redirect(res, 303, "/after");
    if (u === "/post307-same") return redirect(res, 307, "/after");
    if (u === "/post307-cross") return redirect(res, 307, `${B.base}/landing`);
    if (u === "/post308-cross") return redirect(res, 308, `${B.base}/landing`);
    if (u === "/no-location") { res.writeHead(302); return res.end("moved?"); }
    if (u === "/after") return text(res, JSON.stringify({ method: req.method, body: rec.body.toString(), ct: req.headers["content-type"] ?? null }), 200, { "content-type": "application/json" });
    return text(res, "A");
  });

  const secretHeaders = {
    Authorization: "Bearer fake-token-for-oracle",
    "X-Api-Key": "fake-key-for-oracle",
    Cookie: "session=fake",
    "Proxy-Authorization": "Basic ZmFrZQ==",
    "X-Custom-Cred": "fake-custom",
    "X-Trace": "trace-1",
  };
  const r = await guardedFetch(`${A.base}/x`, { headers: secretHeaders, credentialHeaders: ["x-custom-cred"] }, ALLOW);
  assert("cross-origin redirect is followed", r.status === 200 && (await r.text()) === "landing-B" && r.redirected === true);
  const a0 = A.hits[0].headers;
  assert("first hop carried every credential header", a0.authorization && a0["x-api-key"] && a0.cookie && a0["proxy-authorization"] && a0["x-custom-cred"]);
  const b0 = B.hits[0].headers;
  assert("Authorization is dropped on an origin change", b0.authorization === undefined);
  assert("Cookie, Proxy-Authorization and the API-key header are dropped", b0.cookie === undefined && b0["proxy-authorization"] === undefined && b0["x-api-key"] === undefined);
  assert("a caller-named injected credential header is dropped", b0["x-custom-cred"] === undefined);
  assert("a benign header survives the redirect", b0["x-trace"] === "trace-1");

  const aBefore = A.hits.length;
  const same = await guardedFetch(`${A.base}/same`, { headers: { Authorization: "Bearer fake-token-for-oracle" } }, ALLOW);
  assert("same-origin redirect is followed", (await same.text()) === "same-origin-final");
  assert("Authorization is KEPT on a same-origin redirect", A.hits[aBefore + 1].headers.authorization === "Bearer fake-token-for-oracle");

  const chain3 = await guardedFetch(`${A.base}/h/3`, {}, ALLOW);
  assert("a chain of exactly 3 redirects is followed", (await chain3.text()) === "end-of-chain");
  assert("a chain of 4 redirects is refused", (await outcome(guardedFetch(`${A.base}/h/4`, {}, ALLOW))) === "redirect_limit");

  const bBefore = B.hits.length;
  const eMeta = await errorOf(guardedFetch(`${A.base}/to-metadata`, {}, ALLOW));
  assert("redirect to 169.254.169.254 is refused", eMeta instanceof NetGuardError && eMeta.code === "blocked_address", eMeta?.message);
  assert("redirect to a private address is refused", (await outcome(guardedFetch(`${A.base}/to-private`, {}, ALLOW))) === "blocked_address");
  assert("redirect to localhost is refused when only 127.0.0.1 is allowlisted", (await outcome(guardedFetch(`${A.base}/to-localhost-name`, {}, ALLOW))) === "blocked_host");
  assert("redirect to [::1] is refused when only 127.0.0.1 is allowlisted", (await outcome(guardedFetch(`${A.base}/to-ipv6`, {}, ALLOW))) === "blocked_address");
  assert("redirect to a file: URL is refused", (await outcome(guardedFetch(`${A.base}/to-file`, {}, ALLOW))) === "bad_scheme");
  assert("the refused redirect targets were never contacted", B.hits.length === bBefore, `${B.hits.length} vs ${bBefore}`);
  assert("the redirect refusal message names the hop", /redirect/i.test(eMeta?.message ?? ""), eMeta?.message);

  const nl = await guardedFetch(`${A.base}/no-location`, {}, ALLOW);
  assert("a 3xx without Location is returned as a response", nl.status === 302 && (await nl.text()) === "moved?");

  const p302 = await guardedFetch(`${A.base}/post302`, { method: "POST", headers: { "content-type": "application/json" }, body: '{"k":"v"}' }, ALLOW);
  const p302j = await p302.json();
  assert("302 turns POST into GET without a body or content-type", p302j.method === "GET" && p302j.body === "" && p302j.ct === null, JSON.stringify(p302j));
  const p303 = await (await guardedFetch(`${A.base}/post303`, { method: "PUT", body: "x" }, ALLOW)).json();
  assert("303 turns PUT into GET", p303.method === "GET" && p303.body === "");
  const p307 = await (await guardedFetch(`${A.base}/post307-same`, { method: "POST", headers: { "content-type": "application/json" }, body: '{"k":"v"}' }, ALLOW)).json();
  assert("307 same-origin keeps method and body", p307.method === "POST" && p307.body === '{"k":"v"}', JSON.stringify(p307));

  const bBefore2 = B.hits.length;
  assert("307 cross-origin with a body is refused", (await outcome(guardedFetch(`${A.base}/post307-cross`, { method: "POST", body: '{"secret":"fake"}' }, ALLOW))) === "redirect_blocked");
  assert("308 cross-origin with a body is refused", (await outcome(guardedFetch(`${A.base}/post308-cross`, { method: "POST", body: '{"secret":"fake"}' }, ALLOW))) === "redirect_blocked");
  assert("the cross-origin body was never sent", B.hits.length === bBefore2);
}

// ====================================================================================================
// 6. timeout and size cap
// ====================================================================================================
{
  const T = await listen((req, res, rec, state) => {
    const u = req.url;
    if (u === "/hang") return; // never answers
    if (u === "/stall-body") {
      res.writeHead(200, { "content-length": "1000" });
      res.write("abc");
      return;
    }
    if (u === "/declared") {
      res.writeHead(200, { "content-length": String(2 * MiB) });
      res.end(Buffer.alloc(2 * MiB, 97));
      return;
    }
    if (u === "/stream") {
      const total = 10 * MiB;
      const chunk = Buffer.alloc(64 * 1024, 98);
      res.writeHead(200, { "content-type": "application/octet-stream" }); // chunked, no content-length
      let sent = 0;
      const sock = res.socket;
      const pump = () => {
        while (sent < total) {
          if (!res.write(chunk)) return void res.once("drain", pump);
          sent += chunk.length;
        }
        res.end();
      };
      // bytes the kernel accepted from this socket when the client went away (not just chunks handed to write())
      res.on("close", () => { state.streamSent = sock ? sock.bytesWritten : sent; state.streamClosed = true; });
      return pump();
    }
    if (u.startsWith("/exact/")) {
      const n = Number(u.slice(7));
      return text(res, "e".repeat(n));
    }
    if (u === "/bomb") {
      const gz = zlib.gzipSync(Buffer.alloc(64 * MiB, 0));
      res.writeHead(200, { "content-encoding": "gzip", "content-length": String(gz.length) });
      return void res.end(gz);
    }
    if (u === "/gzip-small") {
      const gz = zlib.gzipSync(Buffer.from("zipped hello"));
      res.writeHead(200, { "content-encoding": "gzip", "content-length": String(gz.length) });
      return void res.end(gz);
    }
    if (u === "/br-small") {
      const br = zlib.brotliCompressSync(Buffer.from("brotli hello"));
      res.writeHead(200, { "content-encoding": "br" });
      return void res.end(br);
    }
    if (u === "/head-big") {
      res.writeHead(200, { "content-length": String(10 * MiB) });
      return void res.end(req.method === "HEAD" ? undefined : Buffer.alloc(10 * MiB, 104));
    }
    if (u === "/default-cap") {
      return text(res, "d".repeat(5 * MiB + 1));
    }
    return text(res, "ok");
  });

  let t0 = Date.now();
  const e1 = await errorOf(within(5000, guardedFetch(`${T.base}/hang`, {}, { ...ALLOW, timeout_ms: 300 })));
  let dt = Date.now() - t0;
  assert("a server that never answers hits the settings timeout", e1 instanceof NetGuardError && e1.code === "timeout", e1?.message);
  assert("the timeout fires promptly", dt >= 250 && dt < 3000, `${dt} ms`);

  t0 = Date.now();
  assert("timeoutMs on the call overrides the settings", (await outcome(within(5000, guardedFetch(`${T.base}/hang`, { timeoutMs: 200 }, { ...ALLOW, timeout_ms: 60000 })))) === "timeout");
  dt = Date.now() - t0;
  assert("the per-call timeout fires promptly", dt < 3000, `${dt} ms`);

  assert("the timeout also covers a stalled response body", (await outcome(within(5000, guardedFetch(`${T.base}/stall-body`, {}, { ...ALLOW, timeout_ms: 300 })))) === "timeout");

  assert("a caller abort signal is honoured", (await (async () => {
    const ac = new AbortController();
    setTimeout(() => ac.abort(), 150);
    try { await within(5000, guardedFetch(`${T.base}/hang`, { signal: ac.signal, timeoutMs: 60000 }, ALLOW)); return "OK"; } catch (e) { return e instanceof NetGuardError ? e.code : `non-guard: ${e.message}`; }
  })()) === "aborted");

  const small = { ...ALLOW, max_response_bytes: 100_000 };
  assert("declared content-length above the cap is refused", (await outcome(guardedFetch(`${T.base}/declared`, {}, small))) === "too_large");

  const eStream = await errorOf(guardedFetch(`${T.base}/stream`, {}, small));
  assert("chunked body without content-length is cut at the cap while streaming", eStream instanceof NetGuardError && eStream.code === "too_large", eStream?.message);
  await sleep(300);
  assert("the server saw the connection close long before 10 MiB was sent", T.streamClosed === true && T.streamSent > 0 && T.streamSent < 8 * MiB, `${T.streamSent} bytes sent`);

  const cap = { ...ALLOW, max_response_bytes: 1000 };
  assert("a body of exactly the cap passes", (await outcome(guardedFetch(`${T.base}/exact/1000`, {}, cap))) === "OK");
  assert("a body one byte over the cap is refused", (await outcome(guardedFetch(`${T.base}/exact/1001`, {}, cap))) === "too_large");
  assert("maxBytes on the call overrides the settings", (await outcome(guardedFetch(`${T.base}/exact/1001`, { maxBytes: 5000 }, cap))) === "OK");

  assert("a gzip bomb is cut on DECODED bytes", (await outcome(guardedFetch(`${T.base}/bomb`, {}, { ...ALLOW, max_response_bytes: MiB }))) === "too_large");
  const gz = await guardedFetch(`${T.base}/gzip-small`, {}, ALLOW);
  assert("gzip responses are decoded", (await gz.text()) === "zipped hello");
  const br = await guardedFetch(`${T.base}/br-small`, {}, ALLOW);
  assert("brotli responses are decoded", (await br.text()) === "brotli hello");

  const head = await guardedFetch(`${T.base}/head-big`, { method: "HEAD" }, { ...ALLOW, max_response_bytes: 1000 });
  assert("HEAD with a huge Content-Length is not size-refused and has no body", head.status === 200 && (await head.text()) === "");
  assert("the same URL as GET is refused by the cap", (await outcome(guardedFetch(`${T.base}/head-big`, {}, { ...ALLOW, max_response_bytes: 1000 }))) === "too_large");
  assert("the default cap is 5 MiB", (await outcome(guardedFetch(`${T.base}/default-cap`, {}, ALLOW))) === "too_large");
  const ok4 = await guardedFetch(`${T.base}/exact/${4 * MiB}`, {}, ALLOW);
  assert("4 MiB passes under the 5 MiB default", (await ok4.text()).length === 4 * MiB);
}

// ====================================================================================================
// 7. config schema
// ====================================================================================================
{
  const base = (network) => `gateway:
  transport: [stdio]
  http: { host: 127.0.0.1, port: 8088, require_auth: auto }
  tool_exposure: namespaced
  default_policy: read
vault: { backend: env }
servers: []
settings:
  network: ${network}
`;
  const load = (network) => {
    const p = join(TMP, `cfg-${Math.random().toString(36).slice(2)}.yaml`);
    writeFileSync(p, base(network));
    try { return { cfg: loadConfig(p) }; } catch (e) { return { err: e.message }; }
  };
  const good = load(`{ allow_private: [127.0.0.1, localhost, "[::1]"], timeout_ms: 20000, max_response_bytes: 1048576 }`);
  assert("settings.network loads", !!good.cfg && good.cfg.settings.network.timeout_ms === 20000 && good.cfg.settings.network.allow_private.length === 3, good.err);
  assert("a CIDR entry is rejected", !!load(`{ allow_private: ["10.0.0.0/8"] }`).err);
  assert("a URL entry is rejected", !!load(`{ allow_private: ["http://127.0.0.1"] }`).err);
  assert("a host:port entry is rejected", !!load(`{ allow_private: ["127.0.0.1:11434"] }`).err);
  assert("a wildcard entry is rejected", !!load(`{ allow_private: ["*.lan"] }`).err);
  assert("timeout_ms 0 is rejected", !!load(`{ timeout_ms: 0 }`).err);
  assert("an unknown network key is rejected", !!load(`{ allow_all: true }`).err);
  assert("an empty network block is valid", !!load(`{}`).cfg);
  const ex = loadConfig(join(ROOT, "switchboard.config.example.yaml"));
  const exAllow = ex.settings?.network?.allow_private ?? [];
  const exLocal = ex.settings?.council?.providers?.local?.base_url ?? "";
  assert("the shipped example allowlists its local council host", exAllow.includes(new URL(exLocal).hostname), `${exLocal} vs ${exAllow.join(",")}`);
}

// ====================================================================================================
// 8. wiring: http-tool
// ====================================================================================================
const clients = [];
async function connect(server) {
  const [ct, st] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "verify-netguard", version: "0.0.0" });
  await server.connect(st);
  await client.connect(ct);
  clients.push(client);
  return client;
}
{
  const B = await listen((req, res) => text(res, "landing-B"));
  const A = await listen((req, res) => {
    if (req.url === "/hop") return redirect(res, 302, `${B.base}/landing`);
    if (req.url === "/ok") return text(res, "tool-ok");
    return text(res, "A");
  });
  const mkTool = (url, network) =>
    buildHttpToolServer(
      { id: "ht", source: "http-tool", enabled: true, http_tools: [{ name: "get_it", method: "GET", url }] },
      async () => ({ Authorization: "Bearer fake-token-for-oracle", "X-Api-Key": "fake-key" }),
      network,
    ).then((g) => connect(g.server));

  setResolverForTests(async () => [{ address: "93.184.216.34", family: 4 }]);
  let c = await mkTool("http://169.254.169.254/latest/meta-data/", {});
  let r = await c.callTool({ name: "get_it", arguments: {} });
  assert("http-tool call to the metadata address is an isError result", r.isError === true && /blocked/i.test(r.content[0].text), r.content[0].text);
  setResolverForTests(null);

  c = await mkTool(`${A.base}/ok`, {});
  r = await c.callTool({ name: "get_it", arguments: {} });
  assert("http-tool to a local server is refused without allow_private", r.isError === true && /allow_private/.test(r.content[0].text) && A.hits.length === 0, r.content[0].text);

  c = await mkTool(`${A.base}/ok`, ALLOW);
  r = await c.callTool({ name: "get_it", arguments: {} });
  assert("http-tool to a local server works with allow_private", r.isError !== true && /tool-ok/.test(r.content[0].text), r.content[0].text);
  assert("http-tool injected the resolved credential headers", A.hits[0].headers.authorization === "Bearer fake-token-for-oracle");

  c = await mkTool(`${A.base}/hop`, ALLOW);
  r = await c.callTool({ name: "get_it", arguments: {} });
  const landed = B.hits[B.hits.length - 1];
  assert("http-tool follows a cross-origin redirect", r.isError !== true && /landing-B/.test(r.content[0].text), r.content[0].text);
  assert("http-tool injected credentials do NOT follow the redirect", landed && landed.headers.authorization === undefined && landed.headers["x-api-key"] === undefined);
}

// ====================================================================================================
// 9. wiring: app2mcp (spec fetch, credential host rule, path confusion, calls)
// ====================================================================================================
{
  const specs = {};
  const S = await listen((req, res, rec) => {
    const u = req.url.split("?")[0];
    if (specs[u]) return text(res, JSON.stringify(specs[u]), 200, { "content-type": "application/json" });
    if (u === "/v1/ping") return text(res, "pong", 200);
    return text(res, "S");
  });
  const mkSpec = (serverUrl, paths) => ({
    openapi: "3.0.0",
    info: { title: "t", version: "1" },
    ...(serverUrl ? { servers: [{ url: serverUrl }] } : {}),
    paths: paths ?? { "/ping": { get: { operationId: "ping", summary: "ping" } } },
  });
  specs["/hostile.json"] = mkSpec("http://evil.example/v1");
  specs["/metadata.json"] = mkSpec("http://169.254.169.254/v1");
  specs["/local.json"] = mkSpec(`${S.base}/v1`);
  specs["/confusion.json"] = mkSpec(`${S.base}/v1`, {
    "@evil.example/x": { get: { operationId: "bad_at" } },
    ".evil.example/x": { get: { operationId: "bad_dot" } },
    ":99/x": { get: { operationId: "bad_port" } },
    "/ping": { get: { operationId: "ping" } },
  });
  const cfgFor = (spec, extra = {}) => ({ id: "api", source: "app2mcp", enabled: true, openapi: `${S.base}${spec}`, ...extra });
  const CRED = { credentials: { Authorization: "${env:NETGUARD_ORACLE_FAKE_SECRET}" } };
  const build = (cfg, network = ALLOW, headers = async () => ({ Authorization: "Bearer fake-token-for-oracle" })) => buildOpenApiServer(cfg, headers, network);

  const eSpec = await errorOf(buildOpenApiServer(cfgFor("/local.json", { base_url: `${S.base}/v1` }), async () => ({}), {}));
  assert("spec fetch from a local server is refused without allow_private", !!eSpec && /allow_private|blocked/i.test(eSpec.message), eSpec?.message);
  assert("the refused spec fetch never reached the server", S.hits.length === 0);

  const eCred = await errorOf(build(cfgFor("/hostile.json", CRED)));
  assert("credentials + hostile servers[0] + no base_url is refused", !!eCred && /base_url/.test(eCred.message), eCred?.message);
  const eInject = await errorOf(build(cfgFor("/hostile.json", { inject_args: { workspace: "w1" } })));
  assert("inject_args + hostile servers[0] + no base_url is refused", !!eInject && /base_url/.test(eInject.message), eInject?.message);
  const eScheme = await errorOf(build(cfgFor("/hostile.json", { auth_scheme: { kind: "bearer", ref: "${env:NETGUARD_ORACLE_FAKE_SECRET}" } })));
  assert("auth_scheme + hostile servers[0] + no base_url is refused", !!eScheme && /base_url/.test(eScheme.message), eScheme?.message);
  const eMismatch = await errorOf(build(cfgFor("/hostile.json", { ...CRED, base_url: `${S.base}/v1` })));
  assert("credentials + spec host differing from base_url is refused", !!eMismatch && /differs|host/i.test(eMismatch.message), eMismatch?.message);

  const okMatch = await errorOf(build(cfgFor("/local.json", { ...CRED, base_url: `${S.base}/v1` })));
  assert("credentials + base_url on the same host as servers[0] builds", okMatch === null, okMatch?.message);

  setResolverForTests(async (host) => (host === "evil.example" ? [{ address: "169.254.169.254", family: 4 }] : [{ address: "93.184.216.34", family: 4 }]));
  const gen = await build(cfgFor("/hostile.json"), ALLOW);
  const c1 = await connect(gen.server);
  const r1 = await c1.callTool({ name: "ping", arguments: {} });
  assert("no credentials: a hostile spec host builds but its calls are blocked by the guard", r1.isError === true && /blocked/i.test(r1.content[0].text), r1.content[0].text);
  const gen2 = await build(cfgFor("/metadata.json"), ALLOW);
  const r2 = await (await connect(gen2.server)).callTool({ name: "ping", arguments: {} });
  assert("no credentials: a spec pointing at 169.254.169.254 is blocked at call time", r2.isError === true && /blocked/i.test(r2.content[0].text), r2.content[0].text);
  setResolverForTests(null);

  const before = S.hits.length;
  const gen3 = await build(cfgFor("/local.json", { ...CRED, base_url: `${S.base}/v1` }));
  const r3 = await (await connect(gen3.server)).callTool({ name: "ping", arguments: {} });
  const last = S.hits[S.hits.length - 1];
  assert("credentialed call goes to base_url and carries the injected header", r3.isError !== true && /pong/.test(r3.content[0].text) && last.url === "/v1/ping" && last.headers.authorization === "Bearer fake-token-for-oracle" && S.hits.length > before, r3.content[0].text);

  const gen4 = await build(cfgFor("/confusion.json"));
  assert("spec paths that do not start with '/' are skipped (host confusion)", gen4.toolCount === 1, `toolCount ${gen4.toolCount}`);
}

// ====================================================================================================
// 10. wiring: registry passes the network settings to generated servers
// ====================================================================================================
{
  const S = await listen((req, res) => text(res, "registry-ok"));
  const vault = new Vault("env");
  const cfgTool = { id: "reg", source: "http-tool", enabled: true, http_tools: [{ name: "get_it", method: "GET", url: `${S.base}/x` }] };
  const regDeny = new Registry(vault);
  const mDeny = await regDeny.mount(cfgTool);
  const rDeny = await mDeny.client.callTool({ name: "get_it", arguments: {} });
  assert("registry without network settings: loopback target refused", rDeny.isError === true && /allow_private|blocked/i.test(rDeny.content[0].text), rDeny.content[0].text);
  const regAllow = new Registry(vault, undefined, () => ALLOW);
  const mAllow = await regAllow.mount({ ...cfgTool, id: "reg2" });
  const rAllow = await mAllow.client.callTool({ name: "get_it", arguments: {} });
  assert("registry with network settings: allowlisted target reached", rAllow.isError !== true && /registry-ok/.test(rAllow.content[0].text), rAllow.content[0].text);
  await regDeny.unmountAll();
  await regAllow.unmountAll();
}

// ====================================================================================================
// 11. wiring: webhook delivery
// ====================================================================================================
{
  const W = await listen((req, res) => text(res, "ok"));
  const cfg = (network) => ({
    gateway: { transport: ["stdio"], http: { host: "127.0.0.1", port: 8088, require_auth: "auto" }, tool_exposure: "namespaced", default_policy: "read" },
    vault: { backend: "env" },
    servers: [],
    settings: { webhook: { enabled: true, url: `${W.base}/hook` }, ...(network ? { network } : {}) },
  });
  const ev = { decision: "deny", server: "s", tool: "t", scope: "write" };
  deliverWebhook(cfg(undefined), ev, () => "unused");
  await sleep(500);
  assert("webhook to a loopback URL is not delivered without allow_private", W.hits.length === 0, String(W.hits.length));
  deliverWebhook(cfg(ALLOW), ev, () => "unused");
  for (let i = 0; i < 40 && W.hits.length === 0; i++) await sleep(50);
  assert("webhook to an allowlisted loopback URL is delivered", W.hits.length === 1 && W.hits[0].url === "/hook", String(W.hits.length));
}

// ====================================================================================================
// 12. wiring: council (cloud base URLs and the local provider) and the local-llm probe
// ====================================================================================================
{
  const L = await listen((req, res, rec) => {
    const payload = { choices: [{ message: { content: "LOCAL-REPLY" } }], usage: { prompt_tokens: 1, completion_tokens: 2 } };
    text(res, JSON.stringify(payload), 200, { "content-type": "application/json" });
  });
  const vault = new Vault("env");
  const council = { enabled: true, providers: { local: { base_url: `${L.base}/v1`, default_model: "m" } }, max_rounds: 1, token_budget: 64 };
  const ask = async (network) => {
    const built = buildCouncilServer(council, vault, network);
    const c = await connect(built.server);
    return c.callTool({ name: "council_consult", arguments: { provider: "local", prompt: "hi" } });
  };
  const rDeny = await ask(undefined);
  assert("council local provider is refused without allow_private (documented: allowlisted by config)", rDeny.isError === true && /allow_private|blocked/i.test(rDeny.content[0].text) && L.hits.length === 0, rDeny.content[0].text);
  const rOk = await ask(ALLOW);
  assert("council local provider works once its host is in allow_private", rOk.isError !== true && /LOCAL-REPLY/.test(rOk.content[0].text), rOk.content[0].text);

  const P = await listen((req, res) => text(res, JSON.stringify({ data: [{ id: "llama3.1" }] }), 200, { "content-type": "application/json" }));
  const runtime = { id: "t", label: "t", baseUrl: `${P.base}/v1`, modelsUrl: `${P.base}/v1/models` };
  const probe = await probeRuntime(runtime, 2000);
  assert("local-llm probe of a loopback runtime works with no allowlist (explicit local probe)", probe.reachable === true && probe.models.includes("llama3.1"), JSON.stringify(probe));
  const probeLan = await probeRuntime({ ...runtime, modelsUrl: "http://10.0.0.5:11434/v1/models" }, 2000);
  assert("local-llm probe is NOT a loophole: a private non-loopback URL is refused", probeLan.reachable === false && /blocked|allow_private/i.test(probeLan.error ?? ""), probeLan.error);
  // local-llm wire: the allowlist entry is added exactly when the guard would refuse the URL
  const wired = await withLocalAllowance({ gateway: {}, vault: {}, servers: [], settings: { council: { enabled: true } } }, "http://127.0.0.1:11434/v1");
  assert("withLocalAllowance adds the loopback host to settings.network.allow_private", wired.changed === true && wired.config.settings.network.allow_private.join() === "127.0.0.1" && wired.host === "127.0.0.1", JSON.stringify(wired.config.settings.network));
  const again = await withLocalAllowance(wired.config, "http://127.0.0.1:11434/v1");
  assert("withLocalAllowance is idempotent", again.changed === false && again.config.settings.network.allow_private.length === 1);
  setResolverForTests(async () => [{ address: "93.184.216.34", family: 4 }]);
  const pubWire = await withLocalAllowance({ gateway: {}, vault: {}, servers: [], settings: {} }, "https://models.example.com/v1");
  setResolverForTests(null);
  assert("withLocalAllowance leaves a public host alone", pubWire.changed === false && pubWire.config.settings.network === undefined);
  const probeMeta = await probeRuntime({ ...runtime, modelsUrl: "http://169.254.169.254/v1/models" }, 2000);
  assert("local-llm probe never reaches the metadata address", probeMeta.reachable === false && /blocked/i.test(probeMeta.error ?? ""), probeMeta.error);
}

// ====================================================================================================
// 13. static: every outbound call goes through the guard
// ====================================================================================================
{
  const srcDir = join(ROOT, "src");
  // src/*.ts plus src/connectors/*.ts: the connector layer (token exchange, refresh, revoke, identity probe,
  // authenticated calls) is where oauth.ts's network calls went, so it is held to the same rule.
  const files = [
    ...readdirSync(srcDir).filter((f) => f.endsWith(".ts")),
    ...readdirSync(join(srcDir, "connectors")).filter((f) => f.endsWith(".ts")).map((f) => `connectors/${f}`),
  ];
  const bare = [];
  for (const f of files) {
    if (f === "netguard.ts") continue;
    const lines = readFileSync(join(srcDir, f), "utf8").split(/\r?\n/);
    lines.forEach((line, i) => {
      if (/^\s*(\*|\/\*|\/\/)/.test(line)) return; // comment lines
      const code = line.replace(/\/\/.*$/, "").replace(/\/\*.*?\*\//g, "");
      if (/(^|[^.\w])(globalThis\.)?fetch\s*\(/.test(code) && !/guardedFetch/.test(code)) bare.push(`${f}:${i + 1}`);
    });
  }
  assert("no module outside netguard.ts calls fetch() directly", bare.length === 0, bare.join(", "));
  const users = ["httptool.ts", "openapi.ts", "webhook.ts", "connectors/tokenclient.ts", "connectors/probe.ts", "connectors/accounts.ts", "council.ts", "catalog.ts", "localllm.ts", "dashboard.ts"];
  const missing = users.filter((f) => !/guardedFetch\(/.test(readFileSync(join(srcDir, f), "utf8")));
  assert("every outbound module uses guardedFetch", missing.length === 0, missing.join(", "));
  const tlsOff = files.filter((f) => /rejectUnauthorized|NODE_TLS_REJECT_UNAUTHORIZED/.test(readFileSync(join(srcDir, f), "utf8")));
  assert("no source file turns TLS certificate verification off", tlsOff.length === 0, tlsOff.join(", "));
  const gw = readFileSync(join(srcDir, "gateway.ts"), "utf8");
  assert("the gateway hands the network settings to the registry, OAuth store and council", (gw.match(/settings\?\.network/g) ?? []).length >= 3, String((gw.match(/settings\?\.network/g) ?? []).length));
}

// --- teardown -------------------------------------------------------------------------------------
for (const c of clients) {
  try { await c.close(); } catch { /* already closed */ }
}
for (const s of servers) {
  try { s.closeAllConnections(); s.close(); } catch { /* already closed */ }
}
await sleep(200); // let libuv settle before exit (Windows UV_HANDLE_CLOSING guard)

const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
process.exitCode = failed.length === 0 ? 0 : 1;
// Safety net: a broken timeout must not leave this process alive forever.
setTimeout(() => process.exit(process.exitCode), 1500).unref();
