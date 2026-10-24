// Deterministic oracle for the integration of the local connector layer (providers, accounts, toolkits) with the
// governed gateway (principals, clients, approvals, risk, the owner session). It runs a REAL Gateway in this process
// (the registry mounts real `source: connector` servers, the router is the production router, approvals are the
// production out-of-band store) against a MOCK provider API on a loopback ephemeral port. Owner presence is an
// injected provider, never a real Windows Hello prompt. Nothing here touches the operator's real state, a real client
// config or port 8088, and nothing calls a real service.
//
//   A  the client binding picks the account: two clients bound to different accounts of the same provider make the
//        mock see different tokens; a client with no entry uses the provider default; the binding resolver of the
//        account store is installed; a long (64 character) client id is still a client, never the owner's own path
//   B  an `account` argument cannot escape the binding: not another client's account, not past a server pin, not an
//        unknown account (no fallback to the default); only `accounts: { <provider>: "*" }` may choose; every refusal
//        is SB_POLICY_DENY naming the client and nothing reaches the provider; the owner's own path is unchanged
//   C  an approval binds the resolved account and the built request: an approval for account A does not execute for
//        account B; one for the default account does not survive a change of the default; the bound request (method,
//        host, path, body hash) is in the record and equals what the provider received; the pipeline itself refuses
//        a call whose digest differs from the approved one; proxy_request needs a human even when the gateway
//        settings would not ask
//   D  outward writes need an approval and reads do not, by the action's own risk and outward flags, not by its name
//   E  a client's max_risk and max_scope deny a connector action before any approval exists
//   F  a toolkit hidden from a client is uncallable by it: by name, through call_tool, through find_tools, and by a
//        malformed or unknown client identity
//   G  the Connectors admin API needs the owner session (header), not a cookie, not a client key; mutations need CSRF
//   H  `switchboard link | unlink | links` edit the clients config through ClientAdmin (one access-control source) and
//        the running gateway honours the change at once; no link table exists
//
// Build first (`npm run build`), then `npm run verify:integration`. Isolated HOME / SWITCHBOARD_HOME, ephemeral ports,
// every child is killed.
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { spawn, spawnSync } from "node:child_process";
import net from "node:net";
import { fileURLToPath, pathToFileURL } from "node:url";
import { stringify as yamlStringify, parse as yamlParse } from "yaml";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const dist = (f) => pathToFileURL(join(ROOT, "dist", f)).href;
const CLI = join(ROOT, "dist", "cli.js");

// ---- isolated environment (before any dist module is imported: HOME_DIR is read at import) ---------------------
const base = mkdtempSync(join(tmpdir(), "sb-integration-"));
const dirs = { home: join(base, "home"), appdata: join(base, "appdata"), local: join(base, "local"), tmp: join(base, "tmp") };
for (const d of Object.values(dirs)) mkdirSync(d, { recursive: true });
const HOME = join(dirs.home, ".switchboard");
Object.assign(process.env, {
  HOME: dirs.home,
  USERPROFILE: dirs.home,
  APPDATA: dirs.appdata,
  LOCALAPPDATA: dirs.local,
  TEMP: dirs.tmp,
  TMP: dirs.tmp,
  SWITCHBOARD_HOME: HOME,
  NO_COLOR: "1",
});
const SCRUB = /(_API_KEY|_API_SECRET|TOKEN|SECRET|PASSWORD|CREDENTIALS)$|^SWITCHBOARD_(AUTO_APPROVE|PROFILE|TOKEN|KEY|INSECURE_APPROVAL)$/i;
for (const k of Object.keys(process.env)) if (SCRUB.test(k)) delete process.env[k];

const checks = [];
// A passing line's detail is printed without the word FAIL, so the runner's failure scan only ever shows real failures.
const tidy = (d) => String(d).replace(/\bFAIL\b/g, "fail").replace(/BREACHED/g, "breached");
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond });
  const clean = String(detail).replace(/\s+/g, " ").trim();
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${clean ? ` - ${cond ? tidy(clean).slice(0, 160) : clean.slice(0, 400)}` : ""}`);
};
const note = (line) => console.log(`NOTE  ${line}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const hex = (n) => randomBytes(n).toString("hex");
const sha = (b) => createHash("sha256").update(b).digest("hex");
const text = (r) => (r.content ?? []).map((c) => c.text ?? "").join("");
const parsed = (r) => {
  try {
    return JSON.parse(text(r));
  } catch {
    return {};
  }
};
const freePort = () =>
  new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });
const closeServer = (s) => new Promise((resolve) => s.close(() => resolve()));

// ---- the code under test ---------------------------------------------------------------------------------------
const { Connectors } = await import(dist("connectors/index.js"));
const { syncToolkits } = await import(dist("connectors/sync.js"));
const { CLIENT_META_KEY } = await import(dist("connectors/mcpserver.js"));
const { Gateway } = await import(dist("gateway.js"));
const { startDashboard } = await import(dist("dashboard.js"));
const { Approvals } = await import(dist("approvals.js"));
const { Vault } = await import(dist("vault.js"));
const { loadConfig } = await import(dist("config.js"));
const { evaluate, resolveRisk } = await import(dist("policy.js"));
const { recentAudit, verifyAudit } = await import(dist("audit.js"));
const { ownerSession, loopback } = await import("./lib/owner.mjs");

// ---- the mock provider -------------------------------------------------------------------------------------------
const TOK_A = `tokA_CNRY${hex(10)}`;
const TOK_B = `tokB_CNRY${hex(10)}`;
const USERS = { [TOK_A]: { id: "user-a", name: "Alice" }, [TOK_B]: { id: "user-b", name: "Bob" } };
const mock = { base: "", port: 0, log: [] };
const mockServer = createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const body = Buffer.concat(chunks);
    const url = new URL(req.url, "http://x");
    const auth = String(req.headers.authorization ?? "");
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    mock.log.push({ method: req.method, path: url.pathname, query: Object.fromEntries(url.searchParams), host: req.headers.host, body, token });
    const json = (status, obj) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(obj));
    };
    if (url.pathname === "/api/me") return USERS[token] ? json(200, USERS[token]) : json(401, { error: "bad token" });
    if (!USERS[token]) return json(401, { error: { code: 401, message: "invalid credentials" } });
    return json(200, { ok: true, who: USERS[token].id, method: req.method, path: url.pathname });
  });
});
await new Promise((resolve) => mockServer.listen(0, "127.0.0.1", resolve));
mock.port = mockServer.address().port;
mock.base = `http://127.0.0.1:${mock.port}`;
const apiHits = () => mock.log.filter((e) => e.path !== "/api/me");
const nApi = () => apiHits().length;
const lastApi = () => apiHits().at(-1);

const children = new Set();
const handles = [];
const gateways = [];
function killTree(child) {
  try {
    if (process.platform === "win32") spawnSync("taskkill", ["/pid", String(child.pid), "/T", "/F"], { stdio: "ignore" });
    else child.kill("SIGKILL");
  } catch {
    /* already gone */
  }
}
function cliRun(args, { timeoutMs = 90_000 } = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [CLI, ...args], { env: { ...process.env, NO_COLOR: "1" }, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
    children.add(child);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (c) => (stdout += c));
    child.stderr.on("data", (c) => (stderr += c));
    const timer = setTimeout(() => killTree(child), timeoutMs);
    child.on("close", (code) => {
      clearTimeout(timer);
      children.delete(child);
      resolve({ code, stdout, stderr });
    });
  });
}

try {
  // ---- provider, accounts, toolkits (fixture specs shaped like Google Discovery documents) ------------------------
  mkdirSync(join(HOME, "providers"), { recursive: true });
  const providerDef = (slug, toolkits) => ({
    slug,
    name: `Mock ${slug}`,
    toolkits,
    categories: ["mock"],
    api_hosts: ["127.0.0.1"],
    docs_url: "https://example.test/docs",
    owner_setup: { console_url: "https://example.test/console", steps: ["make a token"], redirect_uris: [], notes: [] },
    identity_probe: { method: "GET", url: `${mock.base}/api/me`, id_path: "id", name_path: "name" },
    auth: [{ id: "pat", mode: "bearer", default: true, inject: { in: "header", name: "Authorization", template: "Bearer {token}" }, fields: { auth_config_creation: [], connected_account_initiation: [{ name: "token", label: "Token", required: true, secret: true }] } }],
  });
  writeFileSync(join(HOME, "providers", "mockg.json"), JSON.stringify(providerDef("mockg", ["minivid", "minimail"])));
  const NETWORK = { allow_private: ["127.0.0.1"], timeout_ms: 8000 };
  const vault = new Vault("encrypted-file");
  const rt = new Connectors({ vault, network: NETWORK });
  const accA = (await rt.flows.connectSecret({ provider: "mockg", label: "alice", fields: { token: TOK_A } })).account;
  const accB = (await rt.flows.connectSecret({ provider: "mockg", label: "bob", fields: { token: TOK_B } })).account;
  note(`accounts: ${accA.id} (alice, default) and ${accB.id} (bob)`);

  const FIX = join(ROOT, "scripts", "fixtures", "connectors");
  const patchDoc = (name, from) => readFileSync(join(FIX, name), "utf8").split(from).join(`${mock.base}/`);
  const DOCS = {
    "https://fixtures.test/minivid.json": patchDoc("discovery-minivid.json", "https://minivid.fixture.test/"),
    "https://fixtures.test/minimail.json": patchDoc("discovery-minimail.json", "https://minimail.fixture.test/"),
  };
  const writeOwnerOverlay = (slug, obj) => {
    mkdirSync(join(HOME, "toolkits", slug), { recursive: true });
    writeFileSync(join(HOME, "toolkits", slug, "overlay.json"), JSON.stringify({ provider: "mockg", ...obj }));
  };
  writeOwnerOverlay("minivid", { source: { kind: "discovery", url: "https://fixtures.test/minivid.json" }, important: ["videos_list", "videos_insert", "videos_delete", "videos_rate", "playlists_insert", "playlists_list", "files_get", "comments_threads_insert"], outward: ["videos_insert"] });
  writeOwnerOverlay("minimail", { source: { kind: "discovery", url: "https://fixtures.test/minimail.json" }, important: ["users_get_profile", "users_messages_list", "users_messages_send", "users_drafts_create"] });
  const synced = await syncToolkits(rt.kit, "mockg", { fetcher: async (u) => DOCS[u], clock: () => new Date() });
  assert("setup: both fixture toolkits synced", synced.filter((s) => s.status === "synced").length === 2, synced.map((s) => `${s.toolkit}:${s.status}`).join(" "));

  // ---- the gateway: servers, clients, approvals with an injected presence provider ---------------------------------
  const PORT = await freePort();
  assert("setup: the gateway port is ephemeral and never 8088", PORT !== 8088 && PORT > 1024, String(PORT));
  const LONG_ID = `c${"x".repeat(59)}`;
  const cfgObj = {
    gateway: { transport: ["http"], http: { host: "127.0.0.1", port: PORT, require_auth: "auto" }, tool_exposure: "namespaced", default_policy: "full" },
    vault: { backend: "encrypted-file" },
    servers: [
      { id: "minivid", source: "connector", toolkit: "minivid", enabled: true },
      { id: "minimail", source: "connector", toolkit: "minimail", enabled: true },
      { id: "minivid_pin", source: "connector", toolkit: "minivid", enabled: true, account: accA.id },
    ],
    settings: { network: NETWORK },
    clients: {
      alpha: { servers: ["minivid"], max_scope: "write", max_risk: "high", accounts: { mockg: accA.id } },
      beta: { servers: ["minivid", "minimail"], max_scope: "full", max_risk: "high", accounts: { mockg: accB.id } },
      gamma: { servers: ["*"], max_scope: "full", max_risk: "high", accounts: { mockg: "*" } },
      lowrisk: { servers: ["minivid"], max_scope: "full", max_risk: "medium", accounts: { mockg: accA.id } },
      plain: { servers: ["minivid", "minimail"], max_scope: "full", max_risk: "high" },
      pinconf: { servers: ["minivid_pin"], max_scope: "full", max_risk: "high", accounts: { mockg: accB.id } },
      [LONG_ID]: { servers: ["minivid"], max_scope: "write", max_risk: "high", accounts: { mockg: accB.id } },
      nobody: { servers: [] },
    },
  };
  const cfgPath = join(base, "switchboard.config.yaml");
  writeFileSync(cfgPath, yamlStringify(cfgObj));
  const cfg = loadConfig(cfgPath);
  const prompts = [];
  const approvals = new Approvals({ presence: async (m) => (prompts.push(m), { ok: true, method: "none" }) });
  const gw = new Gateway(cfg, { approvals });
  gateways.push(gw);
  await gw.mountAll();
  const kit = gw.oauth.connectors.kit;
  assert("setup: every connector server mounted (fail closed needs an ACTIVE probed account, which both have)", ["minivid", "minimail", "minivid_pin"].every((id) => gw.registry.has(id)));

  const P = (client, via = "apikey") => ({ id: `k_${client.slice(0, 12)}`, client, via });
  const callAs = (client, tool, args = {}) => gw.router.callTool(tool, args, client === null ? undefined : P(client));
  const pendingNow = () => approvals.list().pending;
  const approveId = async (id) => {
    const o = await approvals.approve(id, "cli");
    return o.ok;
  };
  const LIST = { part: "snippet" };
  const INSERT = (title, extra = {}) => ({ part: "snippet", snippet: { title }, ...extra });

  // ════════════════════════════════════════════════════════════════════════════════════════════════
  // A. the client binding picks the account
  // ════════════════════════════════════════════════════════════════════════════════════════════════
  {
    const rA = await callAs("alpha", "minivid__videos_list", LIST);
    const tokA = lastApi()?.token;
    const rB = await callAs("beta", "minivid__videos_list", LIST);
    const tokB = lastApi()?.token;
    assert("A. two clients bound to different accounts of the same provider make the mock see different tokens", !rA.isError && !rB.isError && tokA === TOK_A && tokB === TOK_B && tokA !== tokB, `${rA.isError ? text(rA).slice(0, 100) : "ok"} | ${rB.isError ? text(rB).slice(0, 100) : "ok"}`);
    const rP = await callAs("plain", "minivid__videos_list", LIST);
    assert("A. a client with no accounts entry uses the provider's default account", !rP.isError && lastApi()?.token === TOK_A);
    const accts = kit.connectors.accounts;
    assert("A. the account store's binding resolver is installed and reads the clients config (alpha -> alice, beta -> bob, plain and the owner -> the default)", accts.resolveForCall("mockg", { client: "alpha" }).id === accA.id && accts.resolveForCall("mockg", { client: "beta" }).id === accB.id && accts.resolveForCall("mockg", { client: "plain" }).id === accA.id && accts.resolveForCall("mockg", {}).id === accA.id);
    const rL = await callAs(LONG_ID, "minivid__videos_list", LIST);
    assert("A. a 59 character client id is still a client: its binding applies (it is not read as the owner's own path)", !rL.isError && lastApi()?.token === TOK_B && LONG_ID.length === 60, `${LONG_ID.length} chars`);
    const rAudit = recentAudit(400).filter((r) => r.server === "minivid" && r.tool === "videos_list" && r.client === "alpha").at(-1);
    assert("A. the audit row of a connector call names the principal, the client, the account id and the toolkit, and carries no token", !!rAudit && rAudit.principal === "apikey:k_alpha" && rAudit.account === accA.id && rAudit.toolkit === "minivid" && rAudit.risk === "low" && !JSON.stringify(rAudit).includes(TOK_A) && !JSON.stringify(rAudit).includes(TOK_B), JSON.stringify(rAudit)?.slice(0, 200));
    const rOwner = await callAs(null, "minivid__videos_list", LIST);
    assert("A. a call with no principal (the owner's playground) is the unscoped path: the default account, not narrowed", !rOwner.isError && lastApi()?.token === TOK_A);
  }

  // ════════════════════════════════════════════════════════════════════════════════════════════════
  // B. an account argument cannot escape the binding
  // ════════════════════════════════════════════════════════════════════════════════════════════════
  {
    const refused = async (label, client, tool, args, wants) => {
      const n = nApi();
      const before = pendingNow().length;
      const r = await callAs(client, tool, args);
      const body = parsed(r);
      // A refusal the router makes is { error, code, hint }; a toolkit's own error keeps its shape { successful, error: { code, message } }.
      const code = body.code ?? body.error?.code;
      const ok = r.isError && code === wants.code && wants.re.test(text(r)) && nApi() === n && pendingNow().length === before;
      assert(label, ok, `${code ?? "no code"} ${text(r).slice(0, 220)}`);
      return r;
    };
    await refused("B. alpha (bound to alice) naming bob's account is SB_POLICY_DENY naming 'alpha', and nothing reaches the provider", "alpha", "minivid__videos_list", { ...LIST, account: accB.id }, { code: "SB_POLICY_DENY", re: /client 'alpha'/ });
    await refused("B. ...the label form of bob's account is refused the same way", "alpha", "minivid__videos_list", { ...LIST, account: "mockg/bob" }, { code: "SB_POLICY_DENY", re: /client 'alpha'/ });
    await refused("B. beta (bound to bob) naming alice's account is refused", "beta", "minivid__videos_list", { ...LIST, account: accA.id }, { code: "SB_POLICY_DENY", re: /client 'beta'/ });
    await refused("B. plain (no entry, default alice) naming bob is refused: an unbound client cannot pick", "plain", "minivid__videos_list", { ...LIST, account: accB.id }, { code: "SB_POLICY_DENY", re: /client 'plain'/ });
    const own = await callAs("alpha", "minivid__videos_list", { ...LIST, account: accA.id });
    const ownLabel = await callAs("alpha", "minivid__videos_list", { ...LIST, account: "mockg/alice" });
    assert("B. naming its own account is allowed (by id and by provider/label), and it is that account that is used", !own.isError && !ownLabel.isError && lastApi()?.token === TOK_A);
    const plainOwn = await callAs("plain", "minivid__videos_list", { ...LIST, account: accA.id });
    assert("B. an unbound client may name the account it would use anyway (the provider default)", !plainOwn.isError && lastApi()?.token === TOK_A);
    await callAs("gamma", "minivid__videos_list", { ...LIST, account: accB.id });
    const gb = lastApi()?.token;
    await callAs("gamma", "minivid__videos_list", { ...LIST, account: accA.id });
    const ga = lastApi()?.token;
    await callAs("gamma", "minivid__videos_list", LIST);
    const gd = lastApi()?.token;
    assert("B. only accounts: { mockg: \"*\" } may choose: gamma reaches bob, alice, and the default when it names none", gb === TOK_B && ga === TOK_A && gd === TOK_A);
    await refused("B. an unknown account is SB_ACCOUNT_NOT_FOUND and never falls back to the default (nothing is sent)", "gamma", "minivid__videos_list", { ...LIST, account: "ca_doesnotexist" }, { code: "SB_ACCOUNT_NOT_FOUND", re: /ca_doesnotexist/ });
    // a server pin is final
    const pinned = await callAs("gamma", "minivid_pin__videos_list", LIST);
    assert("B. a server pin (servers[].account) decides the account when the call names none", !pinned.isError && lastApi()?.token === TOK_A);
    await refused("B. even a client that may choose cannot override a server pin with the account argument", "gamma", "minivid_pin__videos_list", { ...LIST, account: accB.id }, { code: "SB_POLICY_DENY", re: /pinned/ });
    await refused("B. a client bound to bob is refused on a server pinned to alice (a pin is final, the call never runs as an identity the client was not given)", "pinconf", "minivid_pin__videos_list", LIST, { code: "SB_POLICY_DENY", re: /pinned.*client 'pinconf'|client 'pinconf'.*pinned/ });
    const pinSame = await callAs("gamma", "minivid_pin__videos_list", { ...LIST, account: accA.id });
    assert("B. naming the pinned account itself is fine", !pinSame.isError && lastApi()?.token === TOK_A);
    // other doors: the discovery meta tool reaches unlisted actions and must not be a way around the binding
    await refused("B. through call_tool (an unlisted action) the account argument is held to the same binding", "alpha", "call_tool", { name: "minivid__videos_update", arguments: { ...INSERT("t"), id: "v1", account: accB.id } }, { code: "SB_POLICY_DENY", re: /client 'alpha'/ });
    const viaCall = await callAs("alpha", "call_tool", { name: "minivid__videos_update", arguments: { part: "snippet", id: "v1", snippet: { title: "t" } } });
    assert("B. ...and an unlisted action is callable by a client that may use its server, as its bound account", !viaCall.isError && lastApi()?.token === TOK_A && lastApi()?.method === "PUT", text(viaCall).slice(0, 160));
    // the identity the connector server is told comes from the router, never from the call's arguments
    await refused("B. a `client` or `_meta` smuggled in the arguments changes nothing: alpha is still alpha", "alpha", "minivid__videos_list", { ...LIST, client: "gamma", account: accB.id, _meta: { [CLIENT_META_KEY]: "gamma" } }, { code: "SB_POLICY_DENY", re: /client 'alpha'/ });
  }

  // ════════════════════════════════════════════════════════════════════════════════════════════════
  // C. an approval binds the resolved account and the built request
  // ════════════════════════════════════════════════════════════════════════════════════════════════
  {
    const A_ARGS = INSERT("hello", { account: accA.id });
    const B_ARGS = INSERT("hello", { account: accB.id });
    const postsVideos = () => apiHits().filter((e) => e.method === "POST" && e.path === "/minivid/v3/videos");
    const n0 = postsVideos().length;
    const p1 = await callAs("gamma", "minivid__videos_insert", A_ARGS);
    const idA = parsed(p1).approval_id;
    assert("C. an outward write is SB_APPROVAL_PENDING and nothing is sent", p1.isError && parsed(p1).code === "SB_APPROVAL_PENDING" && /^ap_/.test(idA ?? "") && postsVideos().length === n0, text(p1).slice(0, 160));
    const recA = approvals.get(idA);
    const prev = recA?.args_preview ?? {};
    assert("C. the record is high risk and the owner is shown the account and the request first", recA?.risk === "high" && recA?.client === "gamma" && Object.keys(prev)[0] === "account" && Object.keys(prev)[1] === "request" && String(prev.account).startsWith(accA.id) && /^POST 127\.0\.0\.1:\d+\/minivid\/v3\/videos$/.test(String(prev.request)), JSON.stringify(prev).slice(0, 220));
    const bindReq = prev.connector?.request;
    assert("C. the bound record holds the resolved account id and the built method, host, path, query hash and body hash", prev.connector?.account === accA.id && bindReq?.method === "POST" && bindReq?.host === `127.0.0.1:${mock.port}` && bindReq?.path === "/minivid/v3/videos" && /^[0-9a-f]{64}$/.test(bindReq?.body_sha256 ?? "") && /^[0-9a-f]{64}$/.test(bindReq?.query_sha256 ?? ""), JSON.stringify(bindReq));

    // B differs only in the account: its own pending record, and A's approval does not cover it
    const p2 = await callAs("gamma", "minivid__videos_insert", B_ARGS);
    const idB = parsed(p2).approval_id;
    assert("C. the same call for another account is a different pending approval", p2.isError && parsed(p2).code === "SB_APPROVAL_PENDING" && idB && idB !== idA);
    assert("C. approving A's request", (await approveId(idA)) === true);
    const p3 = await callAs("gamma", "minivid__videos_insert", B_ARGS);
    assert("C. an approval granted for account A does not execute for account B (still pending B, nothing sent)", p3.isError && parsed(p3).code === "SB_APPROVAL_PENDING" && parsed(p3).approval_id === idB && postsVideos().length === n0, text(p3).slice(0, 160));
    const r4 = await callAs("gamma", "minivid__videos_insert", A_ARGS);
    const sent = postsVideos().at(-1);
    assert("C. the identical call for account A then executes once, as account A", !r4.isError && postsVideos().length === n0 + 1 && sent?.token === TOK_A, text(r4).slice(0, 160));
    assert("C. what the owner approved is what the provider received: method, host, path and the body's sha256", sent && sent.method === bindReq.method && sent.host === bindReq.host && sent.path === bindReq.path && sha(sent.body) === bindReq.body_sha256, `${sent?.host}${sent?.path} ${sent ? sha(sent.body).slice(0, 12) : ""} vs ${bindReq?.body_sha256?.slice(0, 12)}`);
    const r5 = await callAs("gamma", "minivid__videos_insert", A_ARGS);
    assert("C. the approval was single use: a third identical call needs a new one", r5.isError && parsed(r5).code === "SB_APPROVAL_PENDING" && parsed(r5).approval_id !== idA && postsVideos().length === n0 + 1);
    assert("C. approving B's request lets B (and only B) run, as account B", (await approveId(idB)) === true && !(await callAs("gamma", "minivid__videos_insert", B_ARGS)).isError && postsVideos().length === n0 + 2 && postsVideos().at(-1).token === TOK_B);
    const execRow = recentAudit(500).filter((r) => r.server === "minivid" && r.tool === "videos_insert" && r.decision === "allow" && r.approval_id === idA && r.phase !== "attempt").at(-1);
    assert("C. the executed call's audit row carries the approval id, the account, the client, the risk and outward", !!execRow && execRow.account === accA.id && execRow.client === "gamma" && execRow.risk === "high" && execRow.outward === true, JSON.stringify(execRow)?.slice(0, 200));

    // the default account changes between the approval and the call
    const plainArgs = INSERT("by-default");
    const q1 = await callAs("plain", "minivid__videos_insert", plainArgs);
    const idP = parsed(q1).approval_id;
    assert("C. (default account) a client with no accounts entry gets a pending approval bound to the default (alice)", q1.isError && parsed(q1).code === "SB_APPROVAL_PENDING" && approvals.get(idP)?.args_preview?.connector?.account === accA.id);
    await approveId(idP);
    gw.oauth.connectors.accounts.setDefault(accB.id);
    const nBefore = postsVideos().length;
    const q2 = await callAs("plain", "minivid__videos_insert", plainArgs);
    assert("C. an approval for the old default does not run once the default is bob: a NEW pending approval, nothing sent", q2.isError && parsed(q2).code === "SB_APPROVAL_PENDING" && parsed(q2).approval_id !== idP && approvals.get(parsed(q2).approval_id)?.args_preview?.connector?.account === accB.id && postsVideos().length === nBefore, text(q2).slice(0, 200));
    gw.oauth.connectors.accounts.setDefault(accA.id);
    const q3 = await callAs("plain", "minivid__videos_insert", plainArgs);
    assert("C. with the default back to alice the first approval is still valid (it was never consumed) and runs as alice", !q3.isError && postsVideos().length === nBefore + 1 && postsVideos().at(-1).token === TOK_A, text(q3).slice(0, 160));

    // the pipeline itself refuses a call whose digest differs from the approved one
    const planA = await kit.exec.plan({ toolkit: "minivid", action: "videos_insert", args: INSERT("exec-guard", { account: accA.id }), client: "gamma", server: "minivid" });
    const nx = nApi();
    const wrongAccount = await kit.exec.run({ toolkit: "minivid", action: "videos_insert", args: INSERT("exec-guard", { account: accB.id }), client: "gamma", server: "minivid", bound: { digest: planA.digest } });
    assert("C. the pipeline refuses a call whose account is not the approved one (SB_APPROVAL_DENIED, nothing sent)", !wrongAccount.ok && wrongAccount.error.code === "SB_APPROVAL_DENIED" && nApi() === nx, wrongAccount.error?.message?.slice(0, 160));
    const wrongBody = await kit.exec.run({ toolkit: "minivid", action: "videos_insert", args: INSERT("a-different-body", { account: accA.id }), client: "gamma", server: "minivid", bound: { digest: planA.digest } });
    assert("C. ...and one whose built request (the body hash) is not the approved one", !wrongBody.ok && wrongBody.error.code === "SB_APPROVAL_DENIED" && nApi() === nx, wrongBody.error?.message?.slice(0, 160));
    const rightOne = await kit.exec.run({ toolkit: "minivid", action: "videos_insert", args: INSERT("exec-guard", { account: accA.id }), client: "gamma", server: "minivid", bound: { digest: planA.digest } });
    assert("C. ...while the call that hashes to the approved digest runs", rightOne.ok && nApi() === nx + 1 && lastApi().token === TOK_A, rightOne.error?.message?.slice(0, 160));
    const proxyDirect = await kit.exec.run({ toolkit: "minivid", action: "proxy_request", args: { method: "GET", path: "/minivid/v3/videos" }, client: "gamma", server: "minivid", synthetic: { slug: "proxy_request", title: "Proxy", description: "x", input_schema: { type: "object", properties: { method: { type: "string" }, path: { type: "string" } }, required: ["method"] }, scopes: [], scope: "full", risk: "high", outward: false, idempotent: false, important: true, tags: [], deprecated: false, approval: "always", proxy: true, verification: "mapped" } });
    assert("C. proxy_request reached with no attestation and no approver is refused (SB_APPROVAL_DENIED)", !proxyDirect.ok && proxyDirect.error.code === "SB_APPROVAL_DENIED", proxyDirect.error?.message?.slice(0, 120));

    // proxy_request needs a human whatever the gateway settings say
    const savedApproval = cfg.gateway.approval;
    cfg.gateway.approval = { require_for_risk: [] };
    const nProxy = nApi();
    const px = await callAs("gamma", "minivid__proxy_request", { method: "GET", path: "/minivid/v3/videos", query: { part: "snippet" } });
    const idX = parsed(px).approval_id;
    assert("C. proxy_request is SB_APPROVAL_PENDING even with gateway.approval.require_for_risk set to [] (the action needs a human on every call)", px.isError && parsed(px).code === "SB_APPROVAL_PENDING" && !!idX && nApi() === nProxy, text(px).slice(0, 200));
    const pxPrev = approvals.get(idX)?.args_preview ?? {};
    assert("C. its record binds the account and the raw request it would make", String(pxPrev.request) === `GET 127.0.0.1:${mock.port}/minivid/v3/videos` && pxPrev.connector?.account === accA.id, JSON.stringify(pxPrev).slice(0, 200));
    await approveId(idX);
    const px2 = await callAs("gamma", "minivid__proxy_request", { method: "GET", path: "/minivid/v3/videos", query: { part: "snippet" } });
    assert("C. after the owner approves, the proxy call runs once, host locked, as the bound account", !px2.isError && nApi() === nProxy + 1 && lastApi().path === "/minivid/v3/videos" && lastApi().token === TOK_A, text(px2).slice(0, 160));
    const ins = await callAs("gamma", "minivid__videos_insert", INSERT("settings-say-no-gate"));
    assert("C. the operator's own setting still decides every other call: with require_for_risk [] the outward write needs no approval", !ins.isError, text(ins).slice(0, 160));
    cfg.gateway.approval = savedApproval;
    const evilProxy = await callAs("gamma", "minivid__proxy_request", { method: "GET", url: "https://evil.example.test/steal" });
    const evilId = parsed(evilProxy).approval_id;
    if (evilId) await approveId(evilId);
    const nEvil = nApi();
    const evil2 = await callAs("gamma", "minivid__proxy_request", { method: "GET", url: "https://evil.example.test/steal" });
    assert("C. an approved proxy request to a host outside the provider's api_hosts is still refused (the credential is never sent)", evil2.isError && parsed(evil2).error?.code === "SB_HOST_NOT_ALLOWED" && nApi() === nEvil, text(evil2).slice(0, 200));
  }

  // ════════════════════════════════════════════════════════════════════════════════════════════════
  // D. outward writes need an approval, reads do not (by the action's own facts, not its name)
  // ════════════════════════════════════════════════════════════════════════════════════════════════
  {
    const pend0 = pendingNow().length;
    const n0 = nApi();
    const rd = await callAs("alpha", "minivid__videos_list", LIST);
    assert("D. a read runs at once: no approval record, one request", !rd.isError && pendingNow().length === pend0 && nApi() === n0 + 1);
    const wr = await callAs("alpha", "minivid__playlists_insert", { part: "snippet", snippet: { title: "p" } });
    assert("D. a write that is not outward (medium risk) runs without an approval under the default settings", !wr.isError && pendingNow().length === pend0 && lastApi().method === "POST" && lastApi().path === "/minivid/v3/playlists");
    const out = await callAs("alpha", "minivid__videos_insert", INSERT("outward"));
    assert("D. an outward write (videos_insert, scope write) needs an approval at HIGH risk", out.isError && parsed(out).code === "SB_APPROVAL_PENDING" && approvals.get(parsed(out).approval_id)?.risk === "high" && nApi() === n0 + 2, text(out).slice(0, 160));
    const mail = await callAs("beta", "minimail__users_messages_send", { raw: "UmF3" });
    assert("D. sending mail (outward, a write by its name) needs an approval at high risk", mail.isError && parsed(mail).code === "SB_APPROVAL_PENDING" && approvals.get(parsed(mail).approval_id)?.risk === "high");
    const draftSend = await callAs("beta", "call_tool", { name: "minimail__users_drafts_send", arguments: { id: "d1" } });
    assert("D. an UNLISTED outward action reached through call_tool needs the same approval", draftSend.isError && parsed(draftSend).code === "SB_APPROVAL_PENDING", text(draftSend).slice(0, 160));
    const del = await callAs("beta", "minivid__videos_delete", { id: "v1" });
    assert("D. a full scope action (videos_delete) needs an approval", del.isError && parsed(del).code === "SB_APPROVAL_PENDING");
    const unlistedRead = await callAs("beta", "call_tool", { name: "minimail__users_messages_get", arguments: { id: "m1" } });
    assert("D. an unlisted READ runs without an approval", !unlistedRead.isError && lastApi().path.endsWith("/messages/m1"), text(unlistedRead).slice(0, 160));
    // the policy engine itself: the action's facts raise risk and force an approval, never lower
    const srv = cfg.servers.find((s) => s.id === "minivid");
    const hint = gw.registry.get("minivid").connector.hints.videos_insert;
    assert("D. the mounted toolkit hands the router each action's risk and outward flag (videos_insert: high, outward)", hint?.risk === "high" && hint?.outward === true && gw.registry.get("minivid").connector.hints.proxy_request?.approval === "always");
    const withHint = evaluate(srv, "videos_insert", cfg, "write", undefined, undefined, undefined, undefined, hint);
    const withoutHint = evaluate(srv, "videos_insert", cfg, "write");
    assert("D. without the action's facts the same call would be medium risk and ungated; with them it is high and gated", withoutHint.risk === "medium" && withoutHint.decision === "allow" && withHint.risk === "high" && withHint.decision === "approval_required");
    const outwardOnly = resolveRisk({}, "write", undefined, { outward: true });
    const outwardFull = resolveRisk({}, "full", undefined, { outward: true });
    const outwardRead = resolveRisk({}, "read", undefined, { outward: true });
    assert("D. outward true makes write and full high risk and leaves read alone", outwardOnly === "high" && outwardFull === "high" && outwardRead === "low");
    const lowered = resolveRisk({ risk_defaults: { write: "low" } }, "write", undefined, { risk: "high" });
    const operator = resolveRisk({}, "write", { risk: "low" }, { risk: "high", outward: true });
    assert("D. a server's risk_defaults cannot go under the toolkit's classification; only the operator's explicit per-tool risk can", lowered === "high" && operator === "low");
  }

  // ════════════════════════════════════════════════════════════════════════════════════════════════
  // E. a client's max_risk and max_scope deny a connector action before any approval exists
  // ════════════════════════════════════════════════════════════════════════════════════════════════
  {
    const pend0 = pendingNow().length;
    const n0 = nApi();
    const hi = await callAs("lowrisk", "minivid__videos_insert", INSERT("too-risky"));
    assert("E. client max_risk medium denies a high risk connector action: SB_POLICY_DENY naming the client and max_risk", hi.isError && parsed(hi).code === "SB_POLICY_DENY" && /client 'lowrisk'/.test(text(hi)) && /max_risk/.test(text(hi)), text(hi).slice(0, 220));
    assert("E. ...before any approval exists (nothing is put in front of the owner) and nothing is sent", pendingNow().length === pend0 && nApi() === n0);
    const hiDel = await callAs("lowrisk", "minivid__videos_delete", { id: "v1" });
    assert("E. ...the same for a full scope action", hiDel.isError && parsed(hiDel).code === "SB_POLICY_DENY" && /max_risk/.test(text(hiDel)));
    const med = await callAs("lowrisk", "minivid__playlists_insert", { part: "snippet", snippet: { title: "ok" } });
    assert("E. a medium risk action is within its ceiling and runs", !med.isError && lastApi().path === "/minivid/v3/playlists");
    const scopeDeny = await callAs("alpha", "minivid__videos_delete", { id: "v1" });
    assert("E. client max_scope write denies a full scope connector action (SB_POLICY_DENY naming the client), no approval created", scopeDeny.isError && parsed(scopeDeny).code === "SB_POLICY_DENY" && /client 'alpha'/.test(text(scopeDeny)) && /capped at 'write'/.test(text(scopeDeny)) && pendingNow().length === pend0);
    const scopeUnlisted = await callAs("alpha", "call_tool", { name: "minivid__videos_batch_delete", arguments: { id: "v1" } });
    assert("E. ...and an unlisted full scope action reached through call_tool is capped the same way", scopeUnlisted.isError && parsed(scopeUnlisted).code === "SB_POLICY_DENY" && /capped at 'write'/.test(text(scopeUnlisted)));
  }

  // ════════════════════════════════════════════════════════════════════════════════════════════════
  // F. a toolkit hidden from a client is uncallable by it
  // ════════════════════════════════════════════════════════════════════════════════════════════════
  {
    const names = gw.router.listTools(P("alpha")).map((t) => t.name);
    assert("F. the listing of a client shows its toolkit and neither another toolkit nor a server pinned elsewhere", names.some((n) => n.startsWith("minivid__")) && !names.some((n) => n.startsWith("minimail__")) && !names.some((n) => n.startsWith("minivid_pin__")), `${names.length} tools`);
    assert("F. the discovery tools are listed because alpha may see a toolkit with unlisted actions", names.includes("find_tools") && names.includes("call_tool"));
    const nMail = nApi();
    const direct = await callAs("alpha", "minimail__users_messages_list", { userId: "me" });
    assert("F. calling a hidden toolkit by name is SB_POLICY_DENY naming the client, nothing is sent", direct.isError && parsed(direct).code === "SB_POLICY_DENY" && /client 'alpha'/.test(text(direct)) && nApi() === nMail, text(direct).slice(0, 200));
    const viaCall = await callAs("alpha", "call_tool", { name: "minimail__users_messages_get", arguments: { userId: "me", id: "m1" } });
    assert("F. ...and so is an UNLISTED action of the hidden toolkit through call_tool", viaCall.isError && parsed(viaCall).code === "SB_POLICY_DENY" && /client 'alpha'/.test(text(viaCall)) && nApi() === nMail, text(viaCall).slice(0, 200));
    const found = await callAs("alpha", "find_tools", { query: "messages send mail", limit: 50 });
    const foundNames = (parsed(found).matches ?? []).map((m) => m.name);
    assert("F. find_tools never offers the hidden toolkit's actions to alpha", !found.isError && foundNames.length > 0 && !foundNames.some((n) => n.startsWith("minimail__")), foundNames.slice(0, 5).join(","));
    const foundVid = await callAs("alpha", "find_tools", { query: "update a video", limit: 50 });
    assert("F. ...while its own toolkit's unlisted actions are found (videos_update is searchable, not listed)", (parsed(foundVid).matches ?? []).some((m) => m.name === "minivid__videos_update") && !names.includes("minivid__videos_update"));
    assert("F. a client with no servers sees no tools at all and no discovery tool", gw.router.listTools(P("nobody")).length === 0);
    const denyNobody = await callAs("nobody", "minivid__videos_list", LIST);
    assert("F. ...and cannot call anything", denyNobody.isError && parsed(denyNobody).code === "SB_POLICY_DENY" && /client 'nobody'/.test(text(denyNobody)));
    // the connector server's own caller check (defense in depth behind the router)
    const srv = gw.registry.get("minivid");
    const nRaw = nApi();
    const badId = await srv.client.callTool({ name: "videos_list", arguments: LIST, _meta: { [CLIENT_META_KEY]: "Not A Client!" } });
    assert("F. a malformed client identity reaching the connector server is REFUSED, not read as the owner's unscoped path", badId.isError && /SB_POLICY_DENY/.test(text(badId)) && nApi() === nRaw, text(badId).slice(0, 160));
    const ghost = await srv.client.callTool({ name: "videos_list", arguments: LIST, _meta: { [CLIENT_META_KEY]: "ghost" } });
    assert("F. an unknown client identity is refused by the connector server while clients are configured", ghost.isError && nApi() === nRaw, text(ghost).slice(0, 160));
    const mailSrv = gw.registry.get("minimail");
    const asAlpha = await mailSrv.client.callTool({ name: "users_messages_list", arguments: { userId: "me" }, _meta: { [CLIENT_META_KEY]: "alpha" } });
    assert("F. ...and so is a configured client that may not use that server", asAlpha.isError && nApi() === nRaw, text(asAlpha).slice(0, 160));
    const unscopedRaw = await srv.client.callTool({ name: "videos_list", arguments: LIST });
    assert("F. a connector call with no client at all is still the owner's own path (the CLI and the playground)", !unscopedRaw.isError);
  }

  // ════════════════════════════════════════════════════════════════════════════════════════════════
  // G. the Connectors admin API needs the owner session
  // ════════════════════════════════════════════════════════════════════════════════════════════════
  {
    const dash = await startDashboard(gw, cfg, cfgPath);
    handles.push(dash);
    const routes = [
      ["GET", "/api/connectors/providers"],
      ["GET", "/api/connectors/providers/mockg"],
      ["GET", "/api/connectors/accounts"],
      ["GET", "/api/connectors/toolkits"],
      ["GET", "/api/connectors/coverage"],
      ["POST", "/api/connectors/providers/mockg/connect"],
      ["POST", `/api/connectors/accounts/${accA.id}/probe`],
      ["POST", "/api/connectors/toolkits/minimail/enable"],
      ["POST", "/api/connectors/toolkits/minimail/disable"],
    ];
    const none = [];
    for (const [m, p] of routes) none.push([m, p, (await loopback(PORT, m, p, m === "POST" ? { body: {} } : {})).status]);
    assert("G. every Connectors admin route refuses a caller with no session (401)", none.every(([, , s]) => s === 401), none.map(([m, p, s]) => `${m} ${p} ${s}`).join(" | "));
    const bogus = [];
    for (const [m, p] of routes) bogus.push((await loopback(PORT, m, p, { headers: { "x-switchboard-session": "sess_not_real", "x-switchboard-csrf": "nope" }, ...(m === "POST" ? { body: {} } : {}) })).status);
    assert("G. ...and a made up session id (401)", bogus.every((s) => s === 401), bogus.join(","));
    const owner = await ownerSession(PORT);
    assert("G. setup: the owner signs in through the gateway's presence check and gets a session id and a CSRF value (no cookie)", owner.status === 200 && !!owner.sid && !!owner.csrf && !owner.setCookie, `status ${owner.status}`);
    const cookieOnly = [];
    for (const [m, p] of routes) cookieOnly.push((await loopback(PORT, m, p, { headers: { cookie: `switchboard_session=${owner.sid}; session=${owner.sid}; sid=${owner.sid}; sb_session=${owner.sid}`, "x-switchboard-csrf": owner.csrf }, ...(m === "POST" ? { body: {} } : {}) })).status);
    assert("G. a valid session id in a COOKIE opens nothing: there is no cookie-only path (401 on every route)", cookieOnly.every((s) => s === 401), cookieOnly.join(","));
    const bearer = [];
    const alphaKey = new (await import(dist("apikeys.js"))).ApiKeyStore().issue("alpha-oracle-key", { client: "alpha" }).token;
    for (const [m, p] of routes.slice(0, 3)) bearer.push((await loopback(PORT, m, p, { headers: { authorization: `Bearer ${alphaKey}` } })).status);
    assert("G. a client API key is never accepted on an admin route", bearer.every((s) => s === 401), bearer.join(","));
    // the detail route, not the search: the listing reads every seed file and takes seconds (connectors-seed covers the listing)
    const prov = await loopback(PORT, "GET", "/api/connectors/providers/mockg", { headers: owner.hdr });
    const accs = await loopback(PORT, "GET", "/api/connectors/accounts", { headers: owner.hdr });
    const tks = await loopback(PORT, "GET", "/api/connectors/toolkits", { headers: owner.hdr });
    assert("G. with the session header the reads answer 200", prov.status === 200 && accs.status === 200 && tks.status === 200, `${prov.status} ${accs.status} ${tks.status} ${prov.error ?? ""} ${prov.body.slice(0, 100)}`);
    assert("G. ...and no response carries a credential", ![prov, accs, tks].some((r) => r.body.includes(TOK_A) || r.body.includes(TOK_B)));
    const acctList = JSON.parse(accs.body).accounts ?? [];
    assert("G. the accounts answer lists both accounts as metadata (status, label), not tokens", acctList.length === 2 && acctList.every((a) => a.status === "ACTIVE" && !("token" in a)), JSON.stringify(acctList.map((a) => a.id)));
    const noCsrf = await loopback(PORT, "POST", `/api/connectors/accounts/${accA.id}/probe`, { headers: owner.hdr, body: {} });
    const noCsrf2 = await loopback(PORT, "POST", "/api/connectors/toolkits/minimail/disable", { headers: owner.hdr, body: {} });
    assert("G. a mutation with the session but without the CSRF header is refused (403)", noCsrf.status === 403 && noCsrf2.status === 403, `${noCsrf.status} ${noCsrf2.status}`);
    assert("G. ...and the refused disable changed nothing (minimail is still mounted)", gw.registry.has("minimail") && cfg.servers.find((s) => s.id === "minimail")?.enabled !== false);
    const nProbe = mock.log.filter((e) => e.path === "/api/me").length;
    const probe = await loopback(PORT, "POST", `/api/connectors/accounts/${accA.id}/probe`, { headers: owner.hdrC, body: {} });
    assert("G. with session and CSRF the probe runs and reaches the provider once", probe.status === 200 && mock.log.filter((e) => e.path === "/api/me").length === nProbe + 1, `${probe.status} ${probe.body.slice(0, 100)}`);
    assert("G. ...and the probe answer carries no credential", !probe.body.includes(TOK_A));
    const appJs = readFileSync(join(ROOT, "public", "app.js"), "utf8");
    assert("G. the Connectors page uses the one fetch wrapper (session and CSRF headers, credentials omitted): one fetch call in the page", (appJs.match(/\bfetch\(/g) ?? []).length === 1 && /credentials: "omit"/.test(appJs) && /\/api\/connectors\/providers/.test(appJs) && /X-Switchboard-Session/.test(appJs));

    // ════════════════════════════════════════════════════════════════════════════════════════════
    // H. `switchboard link | unlink | links` edit the clients config; the running gateway honours it
    // ════════════════════════════════════════════════════════════════════════════════════════════
    const cli = (args) => cliRun(["--config", cfgPath, ...args]);
    const fileClients = () => yamlParse(readFileSync(cfgPath, "utf8")).clients ?? {};
    const before = prompts.length;
    const l1 = await cli(["link", "newcomer", "minivid", "--max-scope", "read"]);
    assert("H. `link newcomer minivid` exits 0 and says it created and linked the client", l1.code === 0 && /created and linked/.test(l1.stdout + l1.stderr), (l1.stdout + l1.stderr).slice(0, 200));
    assert("H. the gateway's presence prompt showed the exact grant (the owner is asked, an agent with a shell cannot link itself)", prompts.length === before + 1 && /newcomer/.test(prompts.at(-1)) && /servers minivid/.test(prompts.at(-1)) && /max_scope read/.test(prompts.at(-1)), prompts.at(-1));
    assert("H. the clients config on disk has it: servers [minivid], max_scope read, max_risk low (least privilege for a new client)", JSON.stringify(fileClients().newcomer?.servers) === '["minivid"]' && fileClients().newcomer?.max_scope === "read" && fileClients().newcomer?.max_risk === "low", JSON.stringify(fileClients().newcomer));
    assert("H. the RUNNING gateway has it too, live, with no restart", cfg.clients.newcomer?.max_scope === "read" && JSON.stringify(cfg.clients.newcomer?.servers) === '["minivid"]');
    const nNames = gw.router.listTools(P("newcomer")).map((t) => t.name);
    const nRead = await callAs("newcomer", "minivid__videos_list", LIST);
    const nWrite = await callAs("newcomer", "minivid__playlists_insert", { part: "snippet", snippet: { title: "x" } });
    const nMail = await callAs("newcomer", "minimail__users_messages_list", { userId: "me" });
    assert("H. the running gateway honours it: newcomer sees minivid only, reads, is capped at read, and cannot reach minimail", nNames.some((n) => n.startsWith("minivid__")) && !nNames.some((n) => n.startsWith("minimail__")) && !nRead.isError && nWrite.isError && /capped at 'read'/.test(text(nWrite)) && nMail.isError && /client 'newcomer'/.test(text(nMail)), `${nNames.length} tools; write: ${text(nWrite).slice(0, 80)}`);
    assert("H. the link also issued the client a key (the bridge can authenticate as it)", existsSync(join(HOME, "clients", "newcomer.key")));
    assert("H. there is no separate link table anywhere: no connectors/links.json, no LinkStore in the build or the source", !existsSync(join(HOME, "connectors", "links.json")) && !existsSync(join(ROOT, "dist", "connectors", "links.js")) && !existsSync(join(ROOT, "src", "connectors", "links.ts")) && !readdirSync(join(HOME, "connectors")).includes("links.json"));

    const l2 = await cli(["link", "newcomer", "minimail", "--max-risk", "medium"]);
    assert("H. a second link adds the server and keeps the first (servers [minivid, minimail]), changing only the ceiling given", l2.code === 0 && JSON.stringify(cfg.clients.newcomer.servers) === '["minivid","minimail"]' && cfg.clients.newcomer.max_risk === "medium" && cfg.clients.newcomer.max_scope === "read", JSON.stringify(cfg.clients.newcomer));
    const l3 = await cli(["link", "newcomer", "minivid", "--account", accB.id, "--max-scope", "write"]);
    assert("H. `link --account` binds the client to that account in the clients config (accounts: { mockg: <id> }) and the prompt names it", l3.code === 0 && cfg.clients.newcomer.accounts?.mockg === accB.id && fileClients().newcomer?.accounts?.mockg === accB.id && /accounts mockg=/.test(prompts.at(-1)), `${(l3.stdout + l3.stderr).slice(0, 160)} | ${prompts.at(-1)}`);
    await callAs("newcomer", "minivid__videos_list", LIST);
    const nTok = lastApi()?.token;
    const nOther = await callAs("newcomer", "minivid__videos_list", { ...LIST, account: accA.id });
    assert("H. the running gateway honours the account binding at once (newcomer now runs as bob and cannot name alice)", nTok === TOK_B && nOther.isError && parsed(nOther).code === "SB_POLICY_DENY" && /client 'newcomer'/.test(text(nOther)));
    const canon = (o) => JSON.stringify(o, Object.keys(o ?? {}).sort());
    const snapshotMem = canon(cfg.clients.newcomer);
    const snapshotFile = readFileSync(cfgPath, "utf8");
    const bad1 = await cli(["link", "newcomer", "nosuchtoolkit"]);
    const bad2 = await cli(["link", "newcomer", "minivid", "--account", "ca_missing"]);
    const bad3 = await cli(["link", "newcomer", "minivid", "--max-scope", "root"]);
    assert("H. a bad toolkit, an unknown account or a bad ceiling is refused (exit 1) and changes nothing", bad1.code === 1 && bad2.code === 1 && bad3.code === 1 && canon(cfg.clients.newcomer) === snapshotMem && readFileSync(cfgPath, "utf8") === snapshotFile, `${bad1.code} ${bad2.code} ${bad3.code}`);
    const links = await cli(["links"]);
    assert("H. `links` shows each client's servers, ceilings and accounts, from the gateway's view", links.code === 0 && /newcomer\s+minivid,minimail/.test(links.stdout) && /alpha\s+minivid\s+write\s+high\s+mockg=/.test(links.stdout) && /gamma\s+\*/.test(links.stdout) && /mockg=\*/.test(links.stdout), links.stdout.slice(0, 400));
    const u1 = await cli(["unlink", "newcomer", "minimail"]);
    const afterU1 = gw.router.listTools(P("newcomer")).map((t) => t.name);
    assert("H. `unlink newcomer minimail` removes that server only; the gateway honours it at once", u1.code === 0 && JSON.stringify(cfg.clients.newcomer.servers) === '["minivid"]' && !afterU1.some((n) => n.startsWith("minimail__")) && afterU1.some((n) => n.startsWith("minivid__")), `${(u1.stdout + u1.stderr).slice(0, 160)} ${JSON.stringify(cfg.clients.newcomer?.servers)}`);
    const u2 = await cli(["unlink", "newcomer"]);
    const afterU2 = gw.router.listTools(P("newcomer"));
    const denyAfter = await callAs("newcomer", "minivid__videos_list", LIST);
    assert("H. `unlink newcomer` clears every connector server and the account bindings; the client entry stays and is refused everything", u2.code === 0 && cfg.clients.newcomer && cfg.clients.newcomer.servers.length === 0 && Object.keys(cfg.clients.newcomer.accounts ?? {}).length === 0 && afterU2.length === 0 && denyAfter.isError && parsed(denyAfter).code === "SB_POLICY_DENY", `${(u2.stdout + u2.stderr).slice(0, 160)}`);
    const u3 = await cli(["unlink", "nobody-here", "minivid"]);
    assert("H. unlinking a client that does not exist is a no-op, not an error", u3.code === 0 && /nothing to remove/.test(u3.stdout + u3.stderr));
    const rows = recentAudit(800).filter((r) => r.tool.startsWith("client.") && /newcomer/.test(r.reason ?? ""));
    assert("H. every link and unlink left a client audit row naming the client, attributed to the owner channel that proved presence", rows.length >= 4 && rows.every((r) => r.principal === "owner:cli"), rows.map((r) => `${r.tool}:${r.principal}`).join(","));
    const helpText = (await cli(["link", "--help"])).stdout;
    assert("H. the CLI help says link edits the clients config (the one access-control source)", /clients config|`servers`/.test(helpText) && /accounts/.test(helpText), helpText.slice(0, 200));
  }

  // ════════════════════════════════════════════════════════════════════════════════════════════════
  // I. the whole run left the audit chain intact and leaked no credential
  // ════════════════════════════════════════════════════════════════════════════════════════════════
  {
    const v = verifyAudit();
    assert("I. the audit hash chain verifies after every call above", v.ok === true, JSON.stringify(v).slice(0, 160));
    const all = JSON.stringify(recentAudit(5000));
    assert("I. no audit row holds a provider token", !all.includes(TOK_A) && !all.includes(TOK_B));
    const logText = [readFileSync(join(HOME, "audit.log"), "utf8")].join("");
    assert("I. ...nor does the audit file on disk, the approvals file or the config file", !logText.includes(TOK_A) && !logText.includes(TOK_B) && !readFileSync(join(HOME, "approvals.json"), "utf8").includes(TOK_A) && !readFileSync(cfgPath, "utf8").includes(TOK_A));
    const EM = String.fromCharCode(0x2014);
    const files = ["scripts/verify-integration.mjs", "src/connectors/access.ts", "src/connectors/link.ts"];
    const withDash = files.filter((f) => readFileSync(join(ROOT, f), "utf8").includes(EM));
    assert("I. no em dash in the files this integration created", withDash.length === 0, withDash.join(","));
  }
} catch (err) {
  assert("oracle ran to the end without throwing", false, err && err.stack ? err.stack.split("\n").slice(0, 5).join(" | ") : String(err));
} finally {
  for (const h of handles) await h.close().catch(() => {});
  for (const g of gateways) await g.shutdown().catch(() => {});
  for (const c of children) killTree(c);
  await closeServer(mockServer).catch(() => {});
  await sleep(300);
  try {
    rmSync(base, { recursive: true, force: true });
  } catch {
    /* leftovers in temp are harmless */
  }
}

const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
process.exit(failed.length === 0 ? 0 : 1);
