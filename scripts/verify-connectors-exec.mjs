// Deterministic oracle for the connector execution layer (ADR local-composio, phase P2): versioned toolkits,
// the Discovery and OpenAPI importers, `toolkits sync`, recipes, the execution pipeline, files, media staging,
// the per-toolkit MCP server and honest coverage. It proves the nine acceptance items of ADR section 9 / P2
// against FIXTURE specs written for this oracle and a MOCK provider API on loopback ephemeral ports. It never
// calls a real provider, signs in anywhere or spends money, and it works offline.
//
//   1. The Discovery importer on documents shaped like YouTube, Gmail and Drive: one action per method, 100%
//      of schemas compile in Ajv, names unique and at most 64 characters. (The real YouTube 83 / Gmail 79 /
//      Drive 64 counts are measured live by scripts/live-sync-check.mjs, which needs the network.)
//   2. The OpenAPI 3.x and Swagger 2.0 importers: the same invariants.
//   3. Scope and risk: GET read, DELETE full; an overlay and an upstream hint can only tighten.
//   4. Auth injection per ProviderDef; a redirect to another origin never carries the token; a URL host
//      outside api_hosts is refused.
//   5. File rules: outside the allowlist refused; sensitive segments refused inside it; a symlink escape
//      refused; a size cap; a download lands under SWITCHBOARD_HOME/files/<run_id>/ with its sha256.
//   6. Media stage: the URL serves exactly one file, expires within 15 minutes, bounded fetches, deleted after.
//   7. Toggle and client access: a disabled toolkit is absent from tools/list and its calls are refused; a client
//      allowed one toolkit server sees only it and is refused on another; two clients bound to different accounts
//      make the mock see different tokens. (Adapted after the merge with the governed gateway: the access table is
//      the gateway's `clients:` config, read live through `kit.access`; there is no separate link table.)
//   8. Exposure size: the default tools/list is at most 30 tools per toolkit; find_tools returns an unlisted
//      action in the top 3 for a natural-language query.
//   9. Audit rows carry toolkit, toolkit version, account id, client and risk; the hash chain verifies.
//
// Beyond the nine: the pipeline stage order, the kill switch, argument validation, the retry and double-post
// rules, the 429 pause, provider error mapping, credential scrubbing, resumable upload, recipes (with the
// real YouTube upload recipe run against a stub), sync and its refusals, and the coverage ledger.
//
// Build first (`npm run build`), then `npm run verify:connectors-exec`. Isolated SWITCHBOARD_HOME; every
// listener it starts is closed.
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { createServer, request as httpRequest } from "node:http";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOME = mkdtempSync(join(tmpdir(), "sb-cexec-"));
process.env.SWITCHBOARD_HOME = HOME;
const WORK = mkdtempSync(join(tmpdir(), "sb-cexec-work-"));

const checks = [];
// A passing line's detail is printed with the CLI's glyphs and the word FAIL defused, so the oracle runner's
// failure scan (run-oracles.mjs) only ever shows real failures.
const tidy = (d) => String(d).replace(/[\u2713\u2717]/g, "").replace(/\bFAIL\b/g, "fail").replace(/BREACHED/g, "breached");
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? ` - ${cond ? tidy(detail) : detail}` : ""}`);
};
const note = (line) => console.log(`NOTE  ${line}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const mod = (p) => import(pathToFileURL(join(ROOT, "dist", p)).href);
const { Connectors } = await mod("connectors/index.js");
const { importDiscovery } = await mod("connectors/importers/discovery.js");
const { importOpenApi } = await mod("connectors/importers/openapi.js");
const T = await mod("connectors/toolkits.js");
const { syncToolkits, syncToolkit } = await mod("connectors/sync.js");
const { buildConnectorServer, CLIENT_META_KEY, MAX_LISTED_TOOLS } = await mod("connectors/mcpserver.js");
const { MediaStage, mountMediaRoutes, S3PresignBackend } = await mod("connectors/mediastage.js");
const { DENY_SEGMENTS } = await mod("connectors/files.js");
const R = await mod("connectors/recipes.js");
const { Coverage, formatReport, parseCsv } = await mod("connectors/coverage.js");
const { STAGES } = await mod("connectors/exec.js");
const { Registry } = await mod("registry.js");
const { Router } = await mod("router.js");
const { Vault } = await mod("vault.js");
const { recentAudit, verifyAudit } = await mod("audit.js");
const { Gateway } = await mod("gateway.js");
const { startDashboard } = await mod("dashboard.js");
const { loadConfig } = await mod("config.js");
const { setKillFile } = await mod("killswitch.js");
const express = (await import("express")).default;
const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
const { InMemoryTransport } = await import("@modelcontextprotocol/sdk/inMemory.js");

const FIX = join(ROOT, "scripts", "fixtures", "connectors");
const fixture = (name) => readFileSync(join(FIX, name), "utf8");
const sha = (b) => createHash("sha256").update(b).digest("hex");
const hex = (n) => randomBytes(n).toString("hex");
const text = (r) => (r.content ?? []).map((c) => c.text ?? "").join("");
const parsed = (r) => {
  try {
    return JSON.parse(text(r));
  } catch {
    return {};
  }
};
const freeListen = (server) => new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address().port)));
const closeServer = (s) => new Promise((resolve) => s.close(() => resolve()));

// ── the mock provider API ────────────────────────────────────────────────────────────────────────────
const TOK_A = `tokA_CNRY${hex(10)}`;
const TOK_B = `tokB_CNRY${hex(10)}`;
const USERS = { [TOK_A]: { id: "user-a", name: "Alice" }, [TOK_B]: { id: "user-b", name: "Bob" } };
const CANARIES = [TOK_A, TOK_B];
const FILE_BYTES = Buffer.from(`downloadable-bytes-${hex(40)}`);
const mock = { base: "", port: 0, log: [], mode: {}, count: {}, fetched: [], echoAuth: false };
const other = { base: "", port: 0, log: [] };
const bump = (k) => (mock.count[k] = (mock.count[k] ?? 0) + 1);
const hits = (pred) => mock.log.filter(pred);

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
  });
}

const mockServer = createServer(async (req, res) => {
  const body = await readBody(req);
  const url = new URL(req.url, "http://x");
  const path = url.pathname;
  const auth = String(req.headers.authorization ?? "");
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  const entry = { method: req.method, path, query: Object.fromEntries(url.searchParams), qall: url.searchParams, headers: req.headers, body, token };
  mock.log.push(entry);
  const json = (status, obj, headers = {}) => {
    res.writeHead(status, { "content-type": "application/json", ...headers });
    res.end(JSON.stringify(obj));
  };
  if (path === "/api/me") return USERS[token] ? json(200, USERS[token]) : json(401, { error: "bad token" });
  if (path.startsWith("/session/")) {
    // A pre-authorized resumable session URL: records the bytes, answers like a finished upload.
    entry.bytes = body.length;
    entry.sha = sha(body);
    return json(200, { id: "v_up1", size: body.length });
  }
  if (path === "/public/file.bin") {
    res.writeHead(200, { "content-type": "application/octet-stream" });
    return res.end(FILE_BYTES);
  }
  if (!USERS[token]) return json(401, { error: { code: 401, message: "invalid credentials" } });
  entry.who = USERS[token].id;

  // ── behaviours toggled by the tests ──
  if (path === "/redir") {
    res.writeHead(302, { location: `${other.base}/landing` });
    return res.end();
  }
  if (path === "/minimail/v1/users/me/messages/send") {
    bump("send");
    if (mock.mode.send === "drop") return req.socket.destroy();
    if (mock.mode.send === "503") return json(503, { error: { code: 503, message: "backend unavailable" } });
    return json(200, { id: `m${mock.count.send}`, threadId: "t1" });
  }
  if (path === "/minivid/v3/videos" && req.method === "GET") {
    bump("videos_list");
    if (mock.mode.videosList === "flaky" && mock.count.videos_list <= 2) return json(503, { error: { message: "try later" } });
    return json(200, { items: [], echo: { query: Object.fromEntries(url.searchParams), version: req.headers["x-mock-version"], ...(mock.echoAuth ? { auth } : {}) } });
  }
  if (path === "/minivid/v3/videos/rate") {
    bump("rate");
    if (mock.mode.rate === "429") return json(429, { error: { message: "slow down" } }, { "retry-after": "2" });
    return json(200, { ok: true });
  }
  if (path === "/minivid/v3/playlists" && req.method === "POST") {
    const m = mock.mode.playlists;
    if (m === "400") return json(400, { error: { code: 400, message: "Invalid value for part" } });
    if (m === "403") return json(403, { error: { code: 403, message: "insufficient permission", errors: [{ reason: "forbidden" }] } });
    if (m === "404") return json(404, { error: { code: 404, message: "not found" } });
    if (m === "slack") return json(200, { ok: false, error: "missing_scope" });
    if (m === "500") return json(500, { error: { message: "oops" } });
    return json(200, { id: "pl1", echo: { body: JSON.parse(body.toString() || "{}") } });
  }
  if (path === "/minivid/v3/playlists" && req.method === "GET") return json(200, { items: [], ...(mock.echoAuth ? { echo_auth: auth } : {}) });
  if (path === "/resumable/upload/minivid/v3/videos") {
    bump("init");
    return json(200, { ok: true }, { location: `${mock.base}/session/up1` });
  }
  if (path === "/upload/v1/youtubeish") {
    bump("init2");
    return json(200, { ok: true }, { location: `${mock.base}/session/up2` });
  }
  if (path.startsWith("/minivid/v3/files/") && !path.endsWith("/export")) {
    if (url.searchParams.get("alt") === "media") {
      res.writeHead(200, { "content-type": "application/octet-stream", "content-disposition": 'attachment; filename="clip.bin"' });
      return res.end(FILE_BYTES);
    }
    return json(200, { id: path.split("/").pop(), name: "clip.bin" });
  }
  if (path === "/v1/items/i1/content") {
    res.writeHead(200, { "content-type": "application/octet-stream" });
    return res.end(FILE_BYTES);
  }
  if (path === "/v1/items/i1/files") return json(200, { ok: true, ctype: req.headers["content-type"], size: body.length });
  if (path === "/v1/raw") return json(200, { ok: true, ctype: req.headers["content-type"], size: body.length, sha: sha(body) });
  // ── Instagram shaped container / poll / publish (recipes) ──
  if (path === "/ig/media" && req.method === "POST") {
    const j = JSON.parse(body.toString() || "{}");
    bump("ig_media");
    if (j.image_url) {
      try {
        const r = await fetch(j.image_url);
        const b = Buffer.from(await r.arrayBuffer());
        mock.fetched.push({ url: j.image_url, status: r.status, bytes: b.length, sha: sha(b) });
      } catch (e) {
        mock.fetched.push({ url: j.image_url, error: String(e) });
      }
    }
    return json(200, { id: `c${mock.count.ig_media}` });
  }
  if (path.startsWith("/ig/c") && req.method === "GET") {
    const id = path.split("/").pop();
    mock.count[`poll_${id}`] = (mock.count[`poll_${id}`] ?? 0) + 1;
    if (mock.mode.igStatus === "ERROR") return json(200, { status_code: "ERROR" });
    return json(200, { status_code: mock.count[`poll_${id}`] <= 2 ? "IN_PROGRESS" : "FINISHED" });
  }
  if (path === "/ig/media_publish") {
    bump("publish");
    if (mock.mode.publish === "drop") return req.socket.destroy();
    return json(200, { id: `p${mock.count.publish}` });
  }
  // everything else: an echo, so a test can see what arrived
  return json(200, { echo: { method: req.method, path, query: Object.fromEntries(url.searchParams), body: body.length ? body.toString("utf8").slice(0, 2000) : undefined, ctype: req.headers["content-type"], ...(mock.echoAuth ? { auth } : {}) } });
});
mock.port = await freeListen(mockServer);
mock.base = `http://127.0.0.1:${mock.port}`;
const otherServer = createServer((req, res) => {
  other.log.push({ method: req.method, path: req.url, auth: req.headers.authorization ?? null, headers: req.headers });
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ landed: true }));
});
other.port = await freeListen(otherServer);
other.base = `http://127.0.0.1:${other.port}`;

// ── runtime: provider, accounts, toolkits ────────────────────────────────────────────────────────────
const clock = { ms: Date.now() };
const NETWORK = { allow_private: ["127.0.0.1"], timeout_ms: 8000 };
const ALLOW = join(WORK, "allowed");
const OUTSIDE = join(WORK, "outside");
mkdirSync(ALLOW, { recursive: true });
mkdirSync(OUTSIDE, { recursive: true });
const SETTINGS = { upload_allowlist: [ALLOW], max_upload_bytes: 4 * 1024 * 1024, media: { allow_local: true } };
const BUNDLED = join(WORK, "bundled-toolkits");
const TOOLKITS = ["minivid", "minimail", "miniapi", "miniswag", "bigapi", "igish", "badrecipes"];

mkdirSync(join(HOME, "providers"), { recursive: true });
const providerDef = (slug, toolkits, probe = true) => ({
  slug,
  name: `Mock ${slug}`,
  ...(toolkits ? { toolkits } : {}),
  categories: ["mock"],
  api_hosts: ["127.0.0.1"],
  docs_url: "https://example.test/docs",
  api_headers: { "X-Mock-Version": "7" },
  owner_setup: { console_url: "https://example.test/console", steps: ["make a token"], redirect_uris: [], notes: [] },
  ...(probe ? { identity_probe: { method: "GET", url: `${mock.base}/api/me`, id_path: "id", name_path: "name" } } : {}),
  auth: [{ id: "pat", mode: "bearer", default: true, inject: { in: "header", name: "Authorization", template: "Bearer {token}" }, fields: { auth_config_creation: [], connected_account_initiation: [{ name: "token", label: "Token", required: true, secret: true }] } }],
});
writeFileSync(join(HOME, "providers", "mockg.json"), JSON.stringify(providerDef("mockg", TOOLKITS)));
writeFileSync(join(HOME, "providers", "mocklone.json"), JSON.stringify(providerDef("mocklone", ["lonely"])));

// bundled (test) recipes: an Instagram shaped photo and carousel, and a recipe file that must be rejected
const writeBundled = (slug, rel, obj) => {
  const file = join(BUNDLED, slug, rel);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, JSON.stringify(obj, null, 2));
};
const IG_FILES = { upload: ["image"], download: [] };
const IG_COMMON = { scope: "write", risk: "high", outward: true, idempotent: false, important: true, base_url: mock.base, reconcile: "Check the account's recent media for the caption before posting again." };
writeBundled("igish", "overlay.json", { provider: "mockg" });
writeBundled("igish", "recipes/post_photo.json", {
  slug: "post_photo", title: "Post a photo", description: "Create a media container, wait for it to finish, publish it.", ...IG_COMMON, files: IG_FILES,
  input_schema: { type: "object", properties: { image: { type: "string", "x-file": "public_url" }, caption: { type: "string" } }, required: ["image"] },
  steps: [
    { type: "http", bind: "container", request: { method: "POST", url: "/ig/media", json: { image_url: "{{input.image}}", caption: '{{input.caption | default:""}}' } } },
    { type: "poll", bind: "ready", request: { method: "GET", url: "/ig/{{steps.container.body.id}}", query: { fields: "status_code" } }, until: { path: "response.body.status_code", equals: "FINISHED" }, fail_when: { path: "response.body.status_code", in: ["ERROR", "EXPIRED"] }, interval_ms: 1, max_attempts: 6 },
    { type: "http", bind: "published", request: { method: "POST", url: "/ig/media_publish", json: { creation_id: "{{steps.container.body.id}}" } } },
  ],
  result: { id: "{{steps.published.body.id}}", container: "{{steps.container.body.id}}" },
});
writeBundled("igish", "recipes/post_carousel.json", {
  slug: "post_carousel", title: "Post a carousel", description: "Create one container per image, then a carousel container, then publish.", ...IG_COMMON, important: false, files: { upload: ["images"], download: [] },
  input_schema: { type: "object", properties: { images: { type: "array", items: { type: "string", "x-file": "public_url" } }, caption: { type: "string" } }, required: ["images"] },
  steps: [
    { type: "foreach", bind: "children", items: "{{input.images}}", as: "img", steps: [{ type: "http", bind: "child", request: { method: "POST", url: "/ig/media", json: { image_url: "{{img}}", is_carousel_item: true } } }], collect: "{{steps.child.body.id}}" },
    { type: "map", bind: "refs", items: "{{steps.children}}", as: "cid", to: { id: "{{cid}}" } },
    { type: "assert", that: { path: "steps.children[0]", exists: true }, message: "no child container was created" },
    { type: "http", bind: "carousel", request: { method: "POST", url: "/ig/media", json: { media_type: "CAROUSEL", children: '{{steps.children | join:","}}', caption: '{{input.caption | default:""}}' } } },
    { type: "http", bind: "published", request: { method: "POST", url: "/ig/media_publish", json: { creation_id: "{{steps.carousel.body.id}}" } } },
  ],
  result: { id: "{{steps.published.body.id}}", children: "{{steps.children}}" },
});
writeBundled("badrecipes", "overlay.json", { provider: "mockg" });
writeBundled("badrecipes", "recipes/evil.json", { slug: "evil", title: "Evil", description: "calls a function that does not exist", scope: "write", steps: [{ type: "http", request: { method: "POST", url: "/x", json: { v: '{{ input.a | eval:"1" }}' } } }] });
writeBundled("badrecipes", "recipes/code.json", { slug: "code", title: "Code", description: "a step type that would run code", scope: "write", steps: [{ type: "script", code: "process.exit(1)" }] });
writeBundled("badrecipes", "recipes/fine.json", { slug: "fine", title: "Fine", description: "a valid recipe beside two bad ones", scope: "read", idempotent: true, base_url: mock.base, input_schema: { type: "object", properties: {} }, steps: [{ type: "http", bind: "r", request: { method: "GET", url: "/anything" } }] });
writeBundled("lonely", "overlay.json", { provider: "mocklone" });
writeBundled("lonely", "recipes/ping.json", { slug: "ping", title: "Ping", description: "a call", scope: "read", idempotent: true, base_url: mock.base, input_schema: { type: "object", properties: {} }, steps: [{ type: "http", request: { method: "GET", url: "/anything" } }] });

const vault = new Vault("encrypted-file");
const rt = new Connectors({ vault, network: NETWORK, clock: () => clock.ms, kit: { bundledToolkitDir: BUNDLED, sleep: async () => {}, settings: () => SETTINGS } });
const kit = rt.kit;

const accA = (await rt.flows.connectSecret({ provider: "mockg", label: "alice", fields: { token: TOK_A } })).account;
const accB = (await rt.flows.connectSecret({ provider: "mockg", label: "bob", fields: { token: TOK_B } })).account;
note(`accounts: ${accA.id} (alice, default) and ${accB.id} (bob)`);

// owner overlays name the spec source (a placeholder URL, served by the fetcher below) and the important set
const writeOwnerOverlay = (slug, obj) => {
  mkdirSync(join(HOME, "toolkits", slug), { recursive: true });
  writeFileSync(join(HOME, "toolkits", slug, "overlay.json"), JSON.stringify({ provider: "mockg", ...obj }));
};
const patch = (name, pairs) => pairs.reduce((s, [a, b]) => s.split(a).join(b), fixture(name));
const DOCS = {
  "https://fixtures.test/minivid.json": patch("discovery-minivid.json", [["https://minivid.fixture.test/", `${mock.base}/`]]),
  "https://fixtures.test/minimail.json": patch("discovery-minimail.json", [["https://minimail.fixture.test/", `${mock.base}/`]]),
  "https://fixtures.test/miniapi.json": patch("openapi-miniapi.json", [["https://api.miniapi.fixture.test/v1", `${mock.base}/v1`]]),
  "https://fixtures.test/miniswag.json": patch("swagger-miniswag.json", [["api.miniswag.fixture.test", `127.0.0.1:${mock.port}`], ['"https"', '"http"']]),
};
writeOwnerOverlay("minivid", { source: { kind: "discovery", url: "https://fixtures.test/minivid.json" }, important: ["videos_list", "videos_insert", "videos_delete", "videos_rate", "playlists_insert", "playlists_list", "files_get", "comments_threads_insert"], outward: ["videos_insert"] });
writeOwnerOverlay("minimail", { source: { kind: "discovery", url: "https://fixtures.test/minimail.json" }, important: ["users_get_profile", "users_messages_list", "users_messages_send", "users_drafts_create"], reconcile: { users_messages_send: "Search the SENT label for the message before sending it again." } });
writeOwnerOverlay("miniapi", { source: { kind: "openapi", url: "https://fixtures.test/miniapi.json" }, important: ["list_items", "create_item"] });
writeOwnerOverlay("miniswag", { source: { kind: "openapi", url: "https://fixtures.test/miniswag.json" }, important: ["things_list"] });
const fetcher = async (url) => {
  if (!(url in DOCS)) throw new Error(`no fixture for ${url}`);
  return DOCS[url];
};

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// 1. Discovery importer
// ════════════════════════════════════════════════════════════════════════════════════════════════════
const countMethods = (res) => Object.keys(res.methods ?? {}).length + Object.values(res.resources ?? {}).reduce((n, r) => n + countMethods(r), 0);
const vidDoc = JSON.parse(fixture("discovery-minivid.json"));
const mailDoc = JSON.parse(fixture("discovery-minimail.json"));
const vid = importDiscovery(vidDoc, { toolkit: "minivid", provider: "mockg" });
const mail = importDiscovery(mailDoc, { toolkit: "minimail", provider: "mockg" });
assert("1. Discovery importer: one action per method (video fixture)", vid.actions.length === countMethods(vidDoc) && vid.operations === countMethods(vidDoc), `${vid.actions.length} actions, ${countMethods(vidDoc)} methods`);
assert("1. Discovery importer: one action per method (mail fixture, top level and nested resources)", mail.actions.length === countMethods(mailDoc), `${mail.actions.length} actions, ${countMethods(mailDoc)} methods`);
for (const [label, r, tk] of [["video", vid, "minivid"], ["mail", mail, "minimail"]]) {
  const c = T.compileAll(r.actions);
  const n = T.checkNames(tk, r.actions);
  assert(`1. Discovery ${label}: 100% of input schemas compile in Ajv`, c.compiled === c.total && c.total === r.actions.length, `${c.compiled}/${c.total}${c.failed[0] ? ` first failure ${c.failed[0].slug}: ${c.failed[0].error.slice(0, 80)}` : ""}`);
  assert(`1. Discovery ${label}: names unique, a-z0-9_ only, and <toolkit>__<action> at most 64 characters`, n.ok && new Set(r.actions.map((a) => a.slug)).size === r.actions.length, `longest ${n.max}${n.problems[0] ? ` ${n.problems[0]}` : ""}`);
}
const longOnes = vid.actions.filter((a) => a.slug.startsWith("really_long"));
assert("1. Discovery: a name longer than the budget is cut with a hash tail, stays unique, and fits", longOnes.length === 2 && longOnes[0].slug !== longOnes[1].slug && longOnes.every((a) => a.slug.length <= T.maxActionSlug("minivid") && /_[0-9a-f]{6}$/.test(a.slug)), longOnes.map((a) => a.slug).join(" | "));
const batchSlugs = vid.actions.map((a) => a.slug).filter((s) => s.startsWith("videos_batch_delete"));
assert("1. Discovery: two methods that snake-case to one name get distinct slugs (_2)", batchSlugs.length === 2 && batchSlugs.includes("videos_batch_delete_2"), batchSlugs.join(", "));
const A = (r, slug) => r.actions.find((a) => a.slug === slug);
const insert = A(vid, "videos_insert");
const defsText = JSON.stringify(insert.input_schema.$defs ?? {});
assert("1. Discovery: named schemas stay as $defs references, so the recursive Video type is finite", insert.input_schema.$defs?.Video && JSON.stringify(insert.input_schema).includes('"$ref":"#/$defs/Video"') && defsText.length < 4000, `$defs ${Object.keys(insert.input_schema.$defs ?? {}).join(", ")} (${defsText.length} chars)`);
assert("1. Discovery: the request body's fields are exposed beside the parameters; readOnly fields are not", "snippet" in insert.input_schema.properties && "status" in insert.input_schema.properties && !("etag" in insert.input_schema.properties) && insert.http.body === "merged");
assert("1. Discovery: a field required for this method by annotations.required is required; one required for another method is not", A(vid, "videos_update").input_schema.required.includes("id") && !(insert.input_schema.required ?? []).includes("id") && A(vid, "videos_update").input_schema.required.includes("part"));
const ajv = T.makeAjv();
const listV = ajv.compile(A(vid, "videos_list").input_schema);
const okStr = { part: "snippet,statistics" };
const okArr = { part: ["snippet", "statistics"], maxResults: "7" };
const bad = { part: "snippet", maxResults: 500 };
const coerced = { part: "snippet", maxResults: "7" };
assert("1. Discovery: a repeated parameter accepts a comma separated string and an array", listV(okStr) && listV(okArr));
assert("1. Discovery: scalar coercion only: '7' becomes 7, an out of range value is refused, and a missing required part is refused", listV(coerced) && coerced.maxResults === 7 && !listV(bad) && !listV({ id: "x" }));
assert("1. Discovery: arrays and objects are never reshaped (an object where an array is expected is refused)", !ajv.compile(A(vid, "videos_insert").input_schema)({ part: "snippet", snippet: { title: "x", tags: { not: "an array" } } }));
const profile = A(mail, "users_get_profile");
const profArgs = {};
const profV = ajv.compile(profile.input_schema);
assert("1. Discovery: a path parameter with a default (userId: me) stays optional and fills in", !(profile.input_schema.required ?? []).includes("userId") && profV(profArgs) && profArgs.userId === "me");
assert("1. Discovery: {+name} reserved expansion is recorded so slashes survive", A(mail, "topic_get").http.params.name.reserved === true);
assert("1. Discovery: supportsMediaUpload adds a file argument and the resumable path", insert.input_schema.properties.media_file?.["x-file"] === "upload" && insert.http.upload?.resumable_path === "/resumable/upload/minivid/v3/videos" && insert.files?.upload?.[0] === "media_file");
assert("1. Discovery: supportsMediaDownload exposes alt and raises the download cap", A(vid, "files_get").http.download === true && A(vid, "files_get").input_schema.properties.alt?.enum?.includes("media"));
assert("1. Discovery: a deprecated method is flagged", A(vid, "videos_legacy_report").deprecated === true);
let notDiscovery = "";
try {
  importDiscovery({ openapi: "3.0.0", paths: {} }, { toolkit: "x", provider: "p" });
} catch (e) {
  notDiscovery = String(e.message);
}
assert("1. Discovery: a document that is not a Discovery document is refused", /not a Google Discovery/.test(notDiscovery));
assert("1. Discovery: every action records the operation id and a normalised method and path for coverage matching", vid.actions.every((a) => a.origin?.operation && /^[A-Z]+ \//.test(a.origin.http ?? "")) && A(vid, "videos_list").origin.http === "GET /minivid/v3/videos" && A(mail, "users_get_profile").origin.http === "GET /minimail/v1/users/{}/profile");

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// 2. OpenAPI 3.x and Swagger 2.0 importers
// ════════════════════════════════════════════════════════════════════════════════════════════════════
const oasDoc = JSON.parse(fixture("openapi-miniapi.json"));
const swDoc = JSON.parse(fixture("swagger-miniswag.json"));
const oas = importOpenApi(oasDoc, { toolkit: "miniapi", provider: "mockg" });
const sw = importOpenApi(swDoc, { toolkit: "miniswag", provider: "mockg" });
const opsIn = (d) => Object.entries(d.paths).filter(([p]) => p.startsWith("/")).reduce((n, [, v]) => n + ["get", "put", "post", "delete", "patch", "head"].filter((m) => v[m]).length, 0);
assert("2. OpenAPI 3.x importer: one action per operation (a path that would change the host is skipped and reported)", oas.actions.length === opsIn(oasDoc) && oas.warnings.some((w) => /@evil\.example/.test(w)), `${oas.actions.length} actions, ${opsIn(oasDoc)} operations`);
assert("2. Swagger 2.0 importer: one action per operation", sw.actions.length === opsIn(swDoc) && sw.base_url === "https://api.miniswag.fixture.test/api", `${sw.actions.length} actions, base ${sw.base_url}`);
for (const [label, r, tk] of [["OpenAPI 3.x", oas, "miniapi"], ["Swagger 2.0", sw, "miniswag"]]) {
  const c = T.compileAll(r.actions);
  const n = T.checkNames(tk, r.actions);
  assert(`2. ${label}: 100% of input schemas compile in Ajv`, c.compiled === c.total && c.total > 0, `${c.compiled}/${c.total}${c.failed[0] ? ` ${c.failed[0].slug}: ${c.failed[0].error.slice(0, 80)}` : ""}`);
  assert(`2. ${label}: names unique, a-z0-9_ only, at most 64 characters with the toolkit prefix`, n.ok && new Set(r.actions.map((a) => a.slug)).size === r.actions.length, `longest ${n.max}`);
}
assert("2. OpenAPI: a duplicate operationId gets a distinct slug and a very long one is cut with a hash tail", A(oas, "list_items_2") && oas.actions.some((a) => /^an_extremely_long.*_[0-9a-f]{6}$/.test(a.slug) && a.slug.length <= T.maxActionSlug("miniapi")));
assert("2. OpenAPI: vendor schema defects (duplicate enum entries, an invalid unicode pattern) are repaired so the schema compiles", JSON.stringify(A(oas, "create_item").input_schema).includes('"enum":["a","b"]') && !JSON.stringify(A(oas, "create_item").input_schema).includes("pattern"));
assert("2. OpenAPI: multipart/form-data file properties become file arguments with a multipart body", A(oas, "upload_item_file").input_schema.properties.file?.["x-file"] === "upload" && A(oas, "upload_item_file").http.body_type === "multipart" && A(oas, "upload_item_file").files.upload.includes("file"));
assert("2. OpenAPI: an octet-stream body is a binary file argument; a binary response is a download", A(oas, "upload_raw").http.body_type === "binary" && A(oas, "upload_raw").files?.upload.length === 1 && A(oas, "download_item_content").http.download === true);
assert("2. Swagger 2.0: a formData field typed file becomes a file argument", A(sw, "things_create").input_schema.properties.attachment?.["x-file"] === "upload" && A(sw, "things_create").http.body_type === "multipart");

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// 3. Scope and risk
// ════════════════════════════════════════════════════════════════════════════════════════════════════
assert("3. GET is read/low and DELETE is full/high in both importers", A(oas, "list_items").scope === "read" && A(oas, "list_items").risk === "low" && A(oas, "delete_item").scope === "full" && A(oas, "delete_item").risk === "high" && A(vid, "videos_list").scope === "read" && A(vid, "videos_delete").scope === "full" && A(sw, "things_delete").scope === "full");
assert("3. POST/PUT/PATCH are write/medium; a verb in the name (send, batchDelete, auth.revoke) tightens", A(oas, "create_item").scope === "write" && A(oas, "create_item").risk === "medium" && A(vid, "videos_batch_delete").scope === "full" && A(sw, "auth_revoke").scope === "full" && A(mail, "users_messages_send").outward === true && A(mail, "users_messages_send").risk === "high" && A(oas, "send_message").outward === true);
assert("3. An upstream hint can only tighten: x-mcp-scope full raises a GET; x-mcp-scope read does not lower a DELETE", A(oas, "search_everything").scope === "full" && A(oas, "search_everything").risk === "high" && A(oas, "delete_everything").scope === "full" && A(oas, "delete_everything").risk === "high");
const ov = T.applyOverlay("miniapi", oas.actions, {
  scope: { delete_item: "read", list_items: "write", get_item: "full" },
  risk: { delete_item: "low", list_items: "high", create_item: "low" },
  outward: ["create_item"],
  idempotent: { create_item: false },
});
const O = (slug) => ov.actions.find((a) => a.slug === slug);
assert("3. An overlay cannot loosen: DELETE stays full/high when the overlay says read/low; the attempts are reported", O("delete_item").scope === "full" && O("delete_item").risk === "high" && ov.issues.filter((i) => /would loosen/.test(i)).length >= 2, ov.issues.filter((i) => /would loosen/.test(i)).join(" | ").slice(0, 160));
assert("3. An overlay can tighten: a GET raised to write/high stays raised", O("list_items").scope === "write" && O("list_items").risk === "high" && O("get_item").scope === "full" && O("get_item").risk === "high");
assert("3. outward forces high risk even when the overlay asks for low", O("create_item").outward === true && O("create_item").risk === "high");
const ov2 = T.applyOverlay("miniapi", oas.actions, { hide: ["upload_raw", "nope_such_action"], rename: { list_items: "list_things", get_item: "get_things_2", nope: "x" }, important: ["list_items"], tags: { list_items: ["inventory"] }, description_trim: 20 });
assert("3. Overlay: hide removes an action, rename changes its slug, important and tags apply, descriptions are trimmed", !ov2.actions.some((a) => a.slug === "upload_raw") && ov2.hidden === 1 && ov2.actions.some((a) => a.slug === "list_things" && a.important && a.tags.includes("inventory")) && ov2.actions.every((a) => a.description.length <= 20));
assert("3. Overlay: an entry for an action the spec no longer has is reported, never fatal", ov2.issues.some((i) => /nope_such_action/.test(i)) && ov2.issues.some((i) => /rename names 'nope'/.test(i)));
assert("3. Overlay: an invalid or colliding rename target is ignored", T.applyOverlay("miniapi", oas.actions, { rename: { list_items: "get_item", get_item: "Bad Name" } }).issues.length === 2);

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// sync: fixtures into SWITCHBOARD_HOME/toolkits (never git)
// ════════════════════════════════════════════════════════════════════════════════════════════════════
const day = new Date(clock.ms).toISOString().slice(0, 10).replace(/-/g, "");
const synced = await syncToolkits(kit, "mockg", { fetcher, clock: () => new Date(clock.ms) });
const byTk = Object.fromEntries(synced.map((s) => [s.toolkit, s]));
assert("sync: a provider slug expands to its toolkits and every fixture toolkit syncs", ["minivid", "minimail", "miniapi", "miniswag"].every((t) => byTk[t]?.status === "synced") && synced.some((s) => s.toolkit === "igish" && s.status === "no_source"), synced.map((s) => `${s.toolkit}:${s.status}`).join(" "));
assert("sync: the version is YYYYMMDD_NN and the files are under SWITCHBOARD_HOME/toolkits/<slug>/<version>/actions.json", byTk.minivid.version === `${day}_00` && existsSync(join(HOME, "toolkits", "minivid", `${day}_00`, "actions.json")) && JSON.parse(readFileSync(join(HOME, "toolkits", "minivid", "current.json"), "utf8")).version === `${day}_00`);
assert("sync: the quality gate ran (schemas compiled 100%, longest tool name reported)", byTk.minivid.compile.compiled === byTk.minivid.compile.total && byTk.minivid.max_tool_name <= 64 && byTk.minivid.actions === vid.actions.length, `${byTk.minivid.compile.compiled}/${byTk.minivid.compile.total}, longest ${byTk.minivid.max_tool_name}`);
const again = await syncToolkit(kit, "minivid", { fetcher, clock: () => new Date(clock.ms) });
assert("sync: an unchanged spec makes no new version", again.status === "unchanged" && kit.toolkits.versions("minivid").length === 1);
const DOCS_V1 = DOCS["https://fixtures.test/minivid.json"];
DOCS["https://fixtures.test/minivid.json"] = DOCS_V1.replace("20261001", "20261009");
const check1 = await syncToolkit(kit, "minivid", { fetcher, check: true });
assert("sync --check: a changed spec reports drift and writes nothing", check1.status === "drift" && kit.toolkits.versions("minivid").length === 1);
const second = await syncToolkit(kit, "minivid", { fetcher, clock: () => new Date(clock.ms) });
assert("sync: a changed spec on the same day becomes _01 and current moves to it", second.status === "synced" && second.version === `${day}_01` && kit.toolkits.currentVersion("minivid") === `${day}_01` && kit.toolkits.versions("minivid").length === 2);
const unsyncedCheck = await syncToolkit(kit, "igish", { fetcher, check: true });
assert("sync: a recipe-only toolkit has no source to sync", unsyncedCheck.status === "no_source");
DOCS["https://fixtures.test/hostile.json"] = DOCS["https://fixtures.test/miniapi.json"].split(`${mock.base}/v1`).join("https://evil.example.test/v1");
writeOwnerOverlay("hostile", { source: { kind: "openapi", url: "https://fixtures.test/hostile.json" } });
const hostile = await syncToolkit(kit, "hostile", { fetcher });
assert("sync: a spec whose API host is not one of the provider's api_hosts is refused and nothing is written", hostile.status === "failed" && /api_hosts/.test(hostile.message) && kit.toolkits.versions("hostile").length === 0, hostile.message?.slice(0, 120));
DOCS["https://fixtures.test/broken.json"] = JSON.stringify({ openapi: "3.0.0", info: { title: "x", version: "1" }, servers: [{ url: `${mock.base}/b` }], paths: { "/a": { get: { operationId: "a", parameters: [{ name: "q", in: "query", schema: { type: "bogus-type" } }], responses: { 200: { description: "ok" } } } } } });
writeOwnerOverlay("broken", { source: { kind: "openapi", url: "https://fixtures.test/broken.json" } });
const broken = await syncToolkit(kit, "broken", { fetcher });
assert("sync: a spec whose schema does not compile is refused as a whole, nothing is written", broken.status === "failed" && /compile/.test(broken.message) && kit.toolkits.versions("broken").length === 0, broken.message?.slice(0, 120));
const missing = await syncToolkit(kit, "minimail", { fetcher: async () => { throw new Error("connection refused"); } });
assert("sync: a fetch failure is reported and the synced version is left as it was", missing.status === "failed" && kit.toolkits.currentVersion("minimail") === `${day}_00`);

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// the gateway pieces: registry, router, an MCP client per server
// ════════════════════════════════════════════════════════════════════════════════════════════════════
const cfg = {
  gateway: { transport: ["stdio"], http: { host: "127.0.0.1", port: 8088, require_auth: "auto" }, tool_exposure: "namespaced", default_policy: "full" },
  vault: { backend: "encrypted-file" },
  servers: ["minivid", "minimail", "miniapi", "miniswag", "igish"].map((t) => ({ id: t, source: "connector", toolkit: t, enabled: true })),
  settings: { network: NETWORK, connectors: SETTINGS },
};
const registry = new Registry(vault, { connectors: rt, accessToken: async () => { throw new Error("no oauth here"); } }, () => NETWORK);
const router = new Router(registry, cfg, (ref) => vault.resolve(ref));
for (const s of cfg.servers) await registry.mount(s);
const connect = async (serverCfg) => {
  const built = await buildConnectorServer(kit, serverCfg);
  const [ct, st] = InMemoryTransport.createLinkedPair();
  await built.server.connect(st);
  const client = new Client({ name: "oracle", version: "0.0.0" });
  await client.connect(ct);
  return { client, built };
};
const run = (toolkit, action, args = {}, extra = {}) => kit.exec.run({ toolkit, action, args, ...extra });
const reqs = () => mock.log.filter((e) => e.path !== "/api/me").length;

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// pipeline order, kill switch, validation
// ════════════════════════════════════════════════════════════════════════════════════════════════════
const ADR_ORDER = ["kill_switch", "client_filter", "toolkit_account", "validate", "policy", "approval", "limits", "token", "build", "files", "fetch", "normalize", "output_files", "redact", "audit"];
assert("the stage list in code is exactly the ADR order", JSON.stringify([...STAGES]) === JSON.stringify(ADR_ORDER));
const r1 = await run("minivid", "videos_list", { part: ["snippet", "statistics"], maxResults: "7" });
assert("pipeline: a successful run goes through every stage in the ADR order", r1.ok && JSON.stringify(r1.stages) === JSON.stringify(ADR_ORDER), r1.error?.message ?? "");
const seen1 = hits((e) => e.path === "/minivid/v3/videos").at(-1);
assert("pipeline: scalars are coerced ('7' arrives as 7), an array becomes repeated parameters, an optional default is not invented", seen1.query.maxResults === "7" && seen1.qall.getAll("part").join(",") === "snippet,statistics" && !("pageToken" in seen1.query));
assert("4. auth injection: the provider's header and credential reach the API (the default account's token), once", seen1.token === TOK_A && seen1.headers["x-mock-version"] === "7" && r1.data.echo.version === "7");
setKillFile(true, HOME);
const before = reqs();
const rk = await run("minivid", "videos_list", { part: "snippet" });
setKillFile(false, HOME);
assert("kill switch: the first stage refuses and nothing leaves", !rk.ok && rk.error.code === "SB_KILL_SWITCH" && JSON.stringify(rk.stages) === JSON.stringify(["kill_switch", "audit"]) && reqs() === before);
const rv = await run("minivid", "videos_list", {});
assert("validation: a missing required argument is SB_BAD_REQUEST at the validate stage, before anything is sent", !rv.ok && rv.error.code === "SB_BAD_REQUEST" && rv.stages.at(-2) === "validate" && reqs() === before, rv.error?.message.slice(0, 100));
const rv2 = await run("minivid", "nope_no_such_action", {});
const rv3 = await run("nosuchkit", "x", {});
assert("an unknown action or toolkit is refused with its own code", rv2.error?.code === "SB_ACTION_NOT_FOUND" && rv3.error?.code === "SB_TOOLKIT_NOT_FOUND");

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// 4. host lock, redirect, injection
// ════════════════════════════════════════════════════════════════════════════════════════════════════
const approvals = [];
const decision = { allow: true };
kit.configure({ approve: async (req) => (approvals.push(req), decision.allow) });
{
  // the synthetic proxy action is built by the server, so it is reached through a real MCP connection
  const { client } = await connect({ id: "minivid", source: "connector", toolkit: "minivid", enabled: true });
  const listed = await client.listTools();
  assert("proxy_request and manage_connections are listed beside the actions", listed.tools.some((t) => t.name === "proxy_request") && listed.tools.some((t) => t.name === "manage_connections"));
  const pr = listed.tools.find((t) => t.name === "proxy_request");
  assert("proxy_request is full scope, high risk, host locked, approval always", pr._meta["io.mcpswitchboard/connector"].scope === "full" && pr._meta["io.mcpswitchboard/connector"].risk === "high" && pr.annotations.destructiveHint === true);
  await client.close();
}
const callProxy = async (args, opts = {}) => {
  const { client } = await connect({ id: "minivid", source: "connector", toolkit: "minivid", enabled: true });
  const r = await client.callTool({ name: "proxy_request", arguments: args, ...(opts.client ? { _meta: { [CLIENT_META_KEY]: opts.client } } : {}) });
  await client.close();
  return { ...r, body: parsed(r) };
};
decision.allow = true;
approvals.length = 0;
const evil = await callProxy({ method: "GET", url: "https://evil.example.test/steal" });
assert("4. a URL host outside api_hosts is refused with SB_HOST_NOT_ALLOWED and the credential is not sent", evil.isError && evil.body.error.code === "SB_HOST_NOT_ALLOWED" && !mock.log.some((e) => e.path === "/steal"), evil.body.error?.message.slice(0, 120));
const plain = await callProxy({ method: "GET", url: "http://example.test/x" });
assert("4. plain http to a non-loopback host is refused", plain.isError && plain.body.error.code === "SB_HOST_NOT_ALLOWED");
const nl = other.log.length;
const redir = await callProxy({ method: "GET", path: "/redir" });
assert("4. a redirect to another origin lands there WITHOUT the token", !redir.isError && other.log.length === nl + 1 && other.log.at(-1).auth === null && !JSON.stringify(other.log.at(-1).headers).includes(TOK_A) && mock.log.some((e) => e.path === "/redir" && e.token === TOK_A), `other saw authorization ${other.log.at(-1)?.auth}; reply ${JSON.stringify(redir.body).slice(0, 200)}`);
const forged = await callProxy({ method: "GET", path: "/echo", headers: { Authorization: "Bearer evil-forged", "X-Extra": "1" } });
const forgedSeen = hits((e) => e.path === "/echo").at(-1);
assert("4. an agent-supplied Authorization header cannot replace the account's credential", !forged.isError && forgedSeen.token === TOK_A && forgedSeen.headers["x-extra"] === "1");
const nHost = mock.log.length;
const hostTry = await callProxy({ method: "GET", path: "@evil.example/x" });
const hostSeen = mock.log.slice(nHost).filter((e) => e.path !== "/api/me").at(-1);
assert("4. a path cannot change the host of the API base: an @host trick stays a path on the API's own host", !hostTry.isError && hostSeen?.path === "/@evil.example/x" && hostSeen.headers.host === `127.0.0.1:${mock.port}` && hostSeen.token === TOK_A, hostSeen ? `${hostSeen.path} on ${hostSeen.headers.host}` : "no request seen");
const sel = await run("minivid", "videos_list", { part: "snippet", account: accB.id });
assert("4. an explicit account argument picks that account's token", sel.ok && hits((e) => e.path === "/minivid/v3/videos").at(-1).token === TOK_B);
const sel2 = await run("minivid", "videos_list", { part: "snippet", account: "mockg/alice" });
assert("4. provider/label also names an account", sel2.ok && hits((e) => e.path === "/minivid/v3/videos").at(-1).token === TOK_A);
mock.echoAuth = true;
const echo = await run("minivid", "playlists_list", { part: "snippet" });
mock.echoAuth = false;
assert("4. the credential's own value is scrubbed from anything returned, even when the provider echoes it", echo.ok && !JSON.stringify(echo.data).includes(TOK_A) && JSON.stringify(echo.data).includes("[redacted]"), JSON.stringify(echo.data).slice(0, 120));
assert("4. every proxy_request call asked for a human decision, bound to its arguments (five calls, five requests)", approvals.length === 5 && approvals.every((a) => a.tool === "proxy_request" && a.scope === "full" && a.risk === "high" && /^[0-9a-f]{64}$/.test(a.args_hash)), `${approvals.length} requests; ${JSON.stringify(approvals[0] ?? {}).slice(0, 160)}`);
decision.allow = false;
const nBefore = reqs();
const denied = await callProxy({ method: "GET", path: "/echo" });
assert("4. a refused approval stops the call before anything is sent", denied.isError && denied.body.error.code === "SB_APPROVAL_DENIED" && reqs() === nBefore);
decision.allow = true;
kit.configure({ approve: undefined });
const noHook = await (async () => {
  const k2 = new Connectors({ vault, network: NETWORK, clock: () => clock.ms, kit: { bundledToolkitDir: BUNDLED, settings: () => SETTINGS } }).kit;
  const { client } = await (async () => {
    const built = await buildConnectorServer(k2, { id: "minivid", source: "connector", toolkit: "minivid", enabled: true });
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await built.server.connect(st);
    const c = new Client({ name: "o2", version: "0" });
    await c.connect(ct);
    return { client: c };
  })();
  const r = await client.callTool({ name: "proxy_request", arguments: { method: "GET", path: "/echo" } });
  await client.close();
  return parsed(r);
})();
assert("4. with no approval path installed an approval-always action is refused (fail closed)", noHook.error?.code === "SB_APPROVAL_DENIED");
kit.configure({ approve: async (req) => (approvals.push(req), decision.allow) });

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// 5. files
// ════════════════════════════════════════════════════════════════════════════════════════════════════
const okFile = join(ALLOW, "ok.txt");
writeFileSync(okFile, "hello file");
mkdirSync(join(ALLOW, ".ssh"), { recursive: true });
writeFileSync(join(ALLOW, ".ssh", "id_rsa"), "PRIVATE");
writeFileSync(join(ALLOW, ".env"), "SECRET=1");
mkdirSync(join(ALLOW, "Google", "Chrome", "User Data", "Default"), { recursive: true });
writeFileSync(join(ALLOW, "Google", "Chrome", "User Data", "Default", "Cookies"), "cookies");
mkdirSync(join(ALLOW, "notes"), { recursive: true });
writeFileSync(join(ALLOW, "notes", "vault.key"), "key");
writeFileSync(join(ALLOW, "notes", "server.pem"), "pem");
writeFileSync(join(OUTSIDE, "secret.txt"), "outside the allowlist");
let linked = false;
try {
  symlinkSync(OUTSIDE, join(ALLOW, "jlink"), "junction");
  linked = true;
} catch (e) {
  note(`could not create a junction here (${e.code}); the symlink escape check will fail rather than skip`);
}
const files = kit.files;
const refusal = async (arg) => {
  try {
    await files.resolveUpload(arg);
    return null;
  } catch (e) {
    return e;
  }
};
const good = await files.resolveUpload(okFile);
assert("5. a file inside the allowlist is read, hashed and typed", good.bytes.toString() === "hello file" && good.sha256 === sha(Buffer.from("hello file")) && good.mimeType === "text/plain" && good.source === "path");
const eOut = await refusal(join(OUTSIDE, "secret.txt"));
assert("5. a path outside the allowlist is refused (SB_FILE_REFUSED)", eOut?.code === "SB_FILE_REFUSED" && /allowlist/.test(eOut.message), eOut?.message);
const eRel = await refusal("relative/file.txt");
assert("5. a relative path is refused", eRel?.code === "SB_FILE_REFUSED");
for (const [label, p] of [[".ssh directory", join(ALLOW, ".ssh", "id_rsa")], [".env file", join(ALLOW, ".env")], ["browser profile directory", join(ALLOW, "Google", "Chrome", "User Data", "Default", "Cookies")], ["vault.key file", join(ALLOW, "notes", "vault.key")], ["certificate key file", join(ALLOW, "notes", "server.pem")]]) {
  const e = await refusal(p);
  assert(`5. sensitive path refused even inside the allowlist: ${label}`, e?.code === "SB_FILE_REFUSED" && /never uploadable/.test(e.message), e?.message);
}
const eLink = await refusal(join(ALLOW, "jlink", "secret.txt"));
assert("5. a symlink (junction) that escapes the allowlist is refused by realpath", linked && eLink?.code === "SB_FILE_REFUSED" && /allowlist/.test(eLink.message), eLink?.message ?? "no refusal");
const big = join(ALLOW, "big.bin");
writeFileSync(big, Buffer.alloc(SETTINGS.max_upload_bytes + 10, 1));
const eBig = await refusal(big);
assert("5. a file over the size cap is refused before it is read (SB_FILE_TOO_LARGE)", eBig?.code === "SB_FILE_TOO_LARGE" && /byte/.test(eBig.message), eBig?.message);
const eHome = await refusal(join(HOME, "audit.log"));
assert("5. files inside SWITCHBOARD_HOME (vault, tokens, audit) are never uploadable", eHome?.code === "SB_FILE_REFUSED");
const eDir = await refusal(ALLOW);
assert("5. a directory is not a file", eDir?.code === "SB_FILE_REFUSED");
const savedAllow = SETTINGS.upload_allowlist;
SETTINGS.upload_allowlist = [];
const eNone = await refusal(okFile);
SETTINGS.upload_allowlist = savedAllow;
assert("5. with no allowlist no local path is accepted (closed by default)", eNone?.code === "SB_FILE_REFUSED" && /allowlist/.test(eNone.message));
SETTINGS.upload_deny_segments = ["notes"];
const eExtra = await refusal(join(ALLOW, "notes", "any.txt"));
SETTINGS.upload_deny_segments = [];
assert("5. an owner can add deny segments, and the built-in ones cannot be removed", eExtra?.code === "SB_FILE_REFUSED" && DENY_SEGMENTS.includes(".ssh") && DENY_SEGMENTS.includes(".aws") && DENY_SEGMENTS.includes("user data"));

// download: a Drive style alt=media
const dl = await run("minivid", "files_get", { fileId: "f1", alt: "media" });
const ref = dl.files?.[0];
const savedPath = ref ? files.pathOf(ref) : "";
assert("5. a download lands under SWITCHBOARD_HOME/files/<run_id>/ and comes back as {uri, bytes, sha256, mimeType}", dl.ok && ref && ref.bytes === FILE_BYTES.length && ref.sha256 === sha(FILE_BYTES) && ref.mimeType === "application/octet-stream" && /^file:/.test(ref.uri) && savedPath.replace(/\\/g, "/").includes(`/files/${dl.run_id}/`) && readFileSync(savedPath).equals(FILE_BYTES), `${ref?.name} ${ref?.bytes} bytes`);
assert("5. the agent gets a reference, never the bytes inline", dl.ok && !JSON.stringify(dl.data).includes(FILE_BYTES.toString().slice(0, 20)) && Object.keys(ref).sort().join() === "bytes,mimeType,name,sha256,uri");
const dl2 = await run("minivid", "files_get", { fileId: "f1", alt: "media" });
assert("5. a second download never overwrites the first", dl2.ok && dl2.files[0].uri !== ref.uri && existsSync(savedPath) && dl2.run_id !== dl.run_id);
const stagedId = `${dl.run_id}/${ref.name}`;
const re = await files.resolveUpload(`staged:${stagedId}`);
assert("5. staged:<run_id>/<name> re-reads a saved download", re.sha256 === ref.sha256 && re.source === "staged");
for (const bad of ["staged:../outside", "staged:run_x/../../secret", "staged:a", `staged:${dl.run_id}/..`, "staged:"]) {
  const e = await refusal(bad);
  assert(`5. a staged id that could traverse is refused: ${bad}`, e?.code === "SB_FILE_REFUSED");
}
const fileUrl = await files.resolveUpload(`${mock.base}/public/file.bin`);
const eUrl = await refusal("http://169.254.169.254/latest/meta-data");
const ePriv = await refusal("https://10.0.0.5/secret.bin");
assert("5. an https/loopback URL upload goes through the SSRF guard: a loopback host on the allowlist works, metadata and private hosts are refused", fileUrl.source === "url" && fileUrl.sha256 === sha(FILE_BYTES) && eUrl?.code === "SB_FILE_REFUSED" && ePriv?.code === "SB_FILE_REFUSED", `${eUrl?.message?.slice(0, 80)}`);
assert("5. a plain http URL to a non-loopback host is refused", (await refusal("http://example.test/a.bin"))?.code === "SB_FILE_REFUSED");

// upload through the pipeline: a Discovery media upload is a resumable session; the approval binds to the file's content hash
const upFile = join(ALLOW, "clip.mp4");
writeFileSync(upFile, Buffer.from("video-bytes-v1-" + hex(200)));
const upBytes = readFileSync(upFile);
const nInit = mock.count.init ?? 0;
kit.configure({ needsApproval: (a) => a.slug === "videos_insert" || a.approval === "always" });
approvals.length = 0;
const up1 = await run("minivid", "videos_insert", { part: ["snippet"], snippet: { title: "t" }, media_file: upFile });
const sessionPut = hits((e) => e.path === "/session/up1").at(-1);
const initReq = hits((e) => e.path === "/resumable/upload/minivid/v3/videos").at(-1);
assert("5. a media upload opens a resumable session with the metadata, then PUTs exactly the file's bytes", up1.ok && mock.count.init === nInit + 1 && JSON.parse(initReq.body.toString()).snippet.title === "t" && initReq.query.uploadType === "resumable" && initReq.headers["x-upload-content-length"] === String(upBytes.length) && sessionPut.bytes === upBytes.length && sessionPut.sha === sha(upBytes) && up1.data.id === "v_up1", up1.error?.message ?? "");
const hash1 = approvals.at(-1)?.args_hash;
await run("minivid", "videos_insert", { part: ["snippet"], snippet: { title: "t" }, media_file: upFile });
const hash1b = approvals.at(-1)?.args_hash;
writeFileSync(upFile, Buffer.from("video-bytes-v2-" + hex(200)));
await run("minivid", "videos_insert", { part: ["snippet"], snippet: { title: "t" }, media_file: upFile });
const hash2 = approvals.at(-1)?.args_hash;
assert("5. the approval hash covers file CONTENT: same arguments and file give the same hash, a swapped file at the same path gives another", hash1 && hash1 === hash1b && hash2 && hash2 !== hash1 && approvals.at(-1).files[0].sha256 === sha(readFileSync(upFile)), `${hash1?.slice(0, 8)} ${hash1b?.slice(0, 8)} ${hash2?.slice(0, 8)}`);
decision.allow = false;
const nUp = reqs();
const upDenied = await run("minivid", "videos_insert", { part: ["snippet"], snippet: { title: "t" }, media_file: upFile });
decision.allow = true;
assert("5. a refused approval sends nothing, not even the session request", !upDenied.ok && upDenied.error.code === "SB_APPROVAL_DENIED" && reqs() === nUp);
const upBad = await run("minivid", "videos_insert", { part: ["snippet"], snippet: { title: "t" }, media_file: join(OUTSIDE, "secret.txt") });
assert("5. a file refusal inside an action stops it at the approval stage with SB_FILE_REFUSED and sends nothing", !upBad.ok && upBad.error.code === "SB_FILE_REFUSED" && reqs() === nUp);
// THE finding (agent-supplied UNC or file://host path): refused lexically, before approval and before any filesystem
// call. A host never used before in this Windows session (a random unroutable 10.255.x.y) makes the old code block
// the whole process for ~21 s inside realpathSync, so the timing is a real reproduction, not a mock.
{
  const rnd = () => 1 + Math.floor(Math.random() * 250);
  const h1 = `10.255.${rnd()}.${rnd()}`;
  const h2 = `10.255.${rnd()}.${rnd()}`;
  let tick = Date.now();
  let maxGapMs = 0;
  const beat = setInterval(() => {
    const n = Date.now();
    maxGapMs = Math.max(maxGapMs, n - tick);
    tick = n;
  }, 5);
  decision.allow = false;
  const nApprovals = approvals.length;
  const nReq = reqs();
  const timed = [];
  for (const ref of [`//${h1}/share/x.mp4`, `file://${h2}/share/x.mp4`]) {
    tick = Date.now();
    const t0 = Date.now();
    const r = await run("minivid", "videos_insert", { part: ["snippet"], snippet: { title: "t" }, media_file: ref });
    timed.push({ ref, r, ms: Date.now() - t0 });
  }
  await sleep(40);
  clearInterval(beat);
  decision.allow = true;
  for (const { ref, r, ms } of timed) {
    assert(`5. a network path as an upload argument (${ref.split(":")[0] === "file" ? "file://host" : "//host"}) is refused with SB_FILE_REFUSED before approval, in under 250 ms`, !r.ok && r.error.code === "SB_FILE_REFUSED" && !r.stages.includes("approval") && ms < 250, `${ms} ms, stages ${r.stages.join(">")}`);
  }
  assert("5. the approver was never asked, and nothing was sent, for a network path", approvals.length === nApprovals && reqs() === nReq);
  assert("5. the gateway event loop never stalled while a network path was refused (max gap under 100 ms)", maxGapMs < 100, `max gap ${maxGapMs} ms`);
}
kit.configure({ needsApproval: undefined });
const mp = await run("miniapi", "upload_item_file", { id: "i1", caption: "c", file: okFile });
const mpSeen = hits((e) => e.path === "/v1/items/i1/files").at(-1);
assert("5. a multipart upload sends the file as a part with its name and type", mp.ok && /^multipart\/form-data; boundary=/.test(mpSeen.headers["content-type"]) && mpSeen.body.toString().includes('name="file"; filename="ok.txt"') && mpSeen.body.toString().includes("hello file") && mpSeen.body.toString().includes('name="caption"'), mp.error?.message ?? "");
const raw = await run("miniapi", "upload_raw", { body: okFile });
assert("5. a binary body upload sends the raw bytes with the file's type", raw.ok && raw.data.sha === sha(Buffer.from("hello file")) && raw.data.ctype === "text/plain", raw.error?.message ?? "");
const dl3 = await run("miniapi", "download_item_content", { id: "i1" });
assert("5. an OpenAPI binary response is saved as a file too", dl3.ok && dl3.files?.[0]?.sha256 === sha(FILE_BYTES));
const nSent = reqs();
const upBad2 = await run("miniapi", "upload_raw", { body: join(OUTSIDE, "secret.txt") });
const refusedRows = recentAudit(300).filter((r) => r.error_code === "SB_FILE_REFUSED" && r.decision === "deny");
assert("5. denied uploads are audited as deny rows with SB_FILE_REFUSED, and nothing was sent", !upBad2.ok && upBad2.error.code === "SB_FILE_REFUSED" && refusedRows.length >= 2 && reqs() === nSent, `${refusedRows.length} rows`);

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// 6. media stage
// ════════════════════════════════════════════════════════════════════════════════════════════════════
const mediaApp = express();
const mediaServer = createServer(mediaApp);
const mediaPort = await freeListen(mediaServer);
const mediaBase = `http://127.0.0.1:${mediaPort}`;
mountMediaRoutes(mediaApp, kit.media, mediaBase);
const IMG = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), randomBytes(600)]);
const st = await kit.media.publish({ bytes: IMG, name: "a.jpg", mimeType: "image/jpeg" }, { ttlSeconds: 3600, maxFetches: 2 });
const g1 = await fetch(st.url);
const g1b = Buffer.from(await g1.arrayBuffer());
assert("6. the staged URL serves exactly the staged file, with its type and length", g1.status === 200 && g1b.equals(IMG) && g1.headers.get("content-type") === "image/jpeg" && g1.headers.get("content-length") === String(IMG.length) && g1.headers.get("cache-control") === "no-store" && st.url.startsWith(`${mediaBase}/media/`));
assert("6. the id is 192 bits of randomness", /^[A-Za-z0-9_-]{32}$/.test(st.id));
const st2 = await kit.media.publish({ bytes: Buffer.from("another file"), name: "b.txt", mimeType: "text/plain" });
const other2 = await fetch(st2.url);
assert("6. each URL serves only its own file", Buffer.from(await other2.arrayBuffer()).toString() === "another file");
const probeBodies = [];
for (const probe of [`${mediaBase}/media/${hex(16)}`, `${mediaBase}/media/short`, `${mediaBase}/media/${st.id}x`, `${mediaBase}/media/..%2F..%2Fetc`]) {
  const r = await fetch(probe);
  const t = await r.text();
  probeBodies.push(t);
  assert(`6. an unknown or malformed id is a 404: ${probe.replace(mediaBase, "").slice(0, 40)}`, r.status === 404, `status ${r.status}`);
}
assert("6. every unknown id gets the identical, tiny 404 body (nothing to tell a guess from a near miss)", new Set(probeBodies).size === 1 && probeBodies[0].length < 40, JSON.stringify(probeBodies[0]));
for (const probe of [`${mediaBase}/media/`, `${mediaBase}/media/${st.id}/extra`, `${mediaBase}/media`]) {
  const r = await fetch(probe);
  assert(`6. the route lists nothing and serves nothing beside /media/<id>: ${probe.replace(mediaBase, "")}`, r.status === 404, `status ${r.status}`);
}
const exp = Date.parse(st.expires_at) - clock.ms;
assert("6. the URL expires within 15 minutes even when the caller asked for an hour", exp > 0 && exp <= 15 * 60 * 1000, `${Math.round(exp / 1000)} s`);
const g2 = await fetch(st.url);
const g3 = await fetch(st.url);
assert("6. fetches are bounded: the allowed count is served, the next is 404, and the file is deleted from disk after the last one", g2.status === 200 && g3.status === 404 && !existsSync(join(HOME, "files", "media", st.id)) && !kit.media.has(st.id), `status ${g2.status} then ${g3.status}`);
const st3 = await kit.media.publish({ bytes: Buffer.from("short lived"), name: "c.txt", mimeType: "text/plain" });
const onDisk = existsSync(join(HOME, "files", "media", st3.id));
clock.ms += 15 * 60 * 1000 + 1000;
const g4 = await fetch(st3.url);
assert("6. after expiry the URL is 404 and the file is deleted", onDisk && g4.status === 404 && !existsSync(join(HOME, "files", "media", st3.id)));
assert("6. the other staged file expired and was swept with it", kit.media.count() === 0);
const st4 = await kit.media.publish({ bytes: Buffer.from("release me"), name: "d.txt", mimeType: "text/plain" });
kit.media.release(st4.id);
assert("6. release deletes a staged file at once", !kit.media.has(st4.id) && !existsSync(join(HOME, "files", "media", st4.id)));
const savedMedia = SETTINGS.media;
SETTINGS.media = {};
let noBase = null;
try {
  await kit.media.publish({ bytes: Buffer.from("x"), name: "x", mimeType: "text/plain" });
} catch (e) {
  noBase = e;
}
assert("6. with no public URL configured a media post fails with a clear message and says what to do", noBase?.code === "SB_MEDIA_NOT_CONFIGURED" && /expose/.test(noBase.detail.hint ?? ""), noBase?.message);
SETTINGS.media = { backend: "s3" };
let s3 = null;
try {
  await kit.media.backend().publish({ bytes: Buffer.from("x"), name: "x", mimeType: "text/plain" });
} catch (e) {
  s3 = e;
}
SETTINGS.media = savedMedia;
assert("6. the S3 backend is an interface that refuses until configured", kit.media.backend() instanceof MediaStage && new S3PresignBackend().kind === "s3" && s3?.code === "SB_MEDIA_NOT_CONFIGURED");
SETTINGS.media = { public_base_url: "http://insecure.example.test" };
let insecure = null;
try {
  await kit.media.publish({ bytes: Buffer.from("x"), name: "x", mimeType: "text/plain" });
} catch (e) {
  insecure = e;
}
SETTINGS.media = savedMedia;
assert("6. a public base URL must be https", insecure?.code === "SB_MEDIA_NOT_CONFIGURED");
// the dashboard listener serves /media too, and to a foreign Host only on a configured public host
{
  const rawGet = (port, path, hostHeader) =>
    new Promise((resolve, reject) => {
      const rq = httpRequest({ host: "127.0.0.1", port, path, method: "GET", headers: { host: hostHeader } }, (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
      });
      rq.on("error", reject);
      rq.end();
    });
  const dport = await (async () => {
    const s = createServer();
    const p = await freeListen(s);
    await closeServer(s);
    return p;
  })();
  const PUB = "media-oracle.example.test";
  const dcfg = { gateway: { transport: ["http"], http: { host: "127.0.0.1", port: dport, require_auth: "auto" }, tool_exposure: "namespaced", default_policy: "read" }, vault: { backend: "encrypted-file" }, servers: [], settings: { network: NETWORK, connectors: { media: { allow_local: true, public_base_url: `https://${PUB}` } } } };
  const gw = new Gateway(dcfg);
  const dash = await startDashboard(gw, dcfg);
  try {
    const gk = gw.oauth.connectors.kit;
    const sd = await gk.media.publish({ bytes: IMG, name: "z.jpg", mimeType: "image/jpeg" }, { maxFetches: 5 });
    assert("6. gateway wiring: the kit's settings reach the media stage (public base URL from settings.connectors.media)", sd.url === `https://${PUB}/media/${sd.id}`, sd.url);
    const viaLoop = await rawGet(dport, `/media/${sd.id}`, `127.0.0.1:${dport}`);
    assert("6. the dashboard listener serves /media/<id> to its own loopback host", viaLoop.status === 200 && viaLoop.body.equals(IMG));
    const viaPublic = await rawGet(dport, `/media/${sd.id}`, PUB);
    assert("6. ...and to the configured public host (the tunnel), on that one route", viaPublic.status === 200 && viaPublic.body.equals(IMG));
    const viaEvil = await rawGet(dport, `/media/${sd.id}`, "evil.example.test");
    assert("6. a foreign Host header is refused on /media (403), even with a valid id", viaEvil.status === 403);
    const apiPublic = await rawGet(dport, "/api/servers", PUB);
    assert("6. the public host reaches nothing else on the dashboard (/api/servers is 403 for it)", apiPublic.status === 403);
    const apiEvil = await rawGet(dport, "/api/servers", "evil.example.test");
    assert("6. a foreign Host is refused on the dashboard API", apiEvil.status === 403);
  } finally {
    await dash.close();
    await gw.shutdown();
  }
}
// an action whose argument is flagged x-file: public_url gets an ephemeral URL, and it is released afterwards
SETTINGS.media = { allow_local: true };
const photoPath = join(ALLOW, "photo.jpg");
writeFileSync(photoPath, IMG);
mock.fetched.length = 0;
const ph = await run("igish", "post_photo", { image: photoPath, caption: "hello" });
assert("6. an Instagram shaped recipe: the platform fetched the staged URL once and got the file, then the URL was released", ph.ok && mock.fetched.length === 1 && mock.fetched[0].status === 200 && mock.fetched[0].sha === sha(IMG) && kit.media.count() === 0, ph.error?.message ?? JSON.stringify(mock.fetched[0]));

// the ephemeral public URL is an outward act: it is made only AFTER the human approved, and a refusal makes none
{
  const gate = { stagedAtApproval: [], fetchedAtApproval: [], allow: true };
  let publishes = 0;
  const realPublish = kit.media.publish.bind(kit.media);
  kit.media.publish = async (...a) => (publishes++, realPublish(...a));
  const defaultNeeds = (a) => a.slug === "videos_insert" || a.approval === "always";
  kit.configure({
    needsApproval: (a) => a.slug === "post_photo" || defaultNeeds(a),
    approve: async (req) => (approvals.push(req), gate.stagedAtApproval.push(kit.media.count()), gate.fetchedAtApproval.push(mock.fetched.length), gate.allow),
  });
  mock.fetched.length = 0;
  const okRun = await run("igish", "post_photo", { image: photoPath, caption: "approved" });
  assert("6. a public_url upload is approved BEFORE its URL exists: nothing was staged or fetched when the approver was asked", okRun.ok && gate.stagedAtApproval.at(-1) === 0 && gate.fetchedAtApproval.at(-1) === 0, `staged at approval ${gate.stagedAtApproval.at(-1)}, run ${okRun.error?.message ?? "ok"}`);
  assert("6. after approval the platform still fetches the staged file once, with the approved bytes, and the URL is released", mock.fetched.length === 1 && mock.fetched[0].status === 200 && mock.fetched[0].sha === sha(IMG) && kit.media.count() === 0 && publishes === 1 && approvals.at(-1).files[0].sha256 === sha(IMG));
  gate.allow = false;
  publishes = 0;
  mock.fetched.length = 0;
  const reqMid = reqs();
  const denied = await run("igish", "post_photo", { image: photoPath, caption: "refused" });
  assert("6. a refused approval makes no public URL at all (the media stage was never asked to publish) and sends nothing", !denied.ok && denied.error.code === "SB_APPROVAL_DENIED" && publishes === 0 && mock.fetched.length === 0 && reqs() === reqMid && kit.media.count() === 0, `publish calls ${publishes}`);
  gate.allow = true;
  const approvalsBefore = approvals.length;
  const savedMedia2 = SETTINGS.media;
  SETTINGS.media = {};
  const noMedia = await run("igish", "post_photo", { image: photoPath, caption: "no url" });
  SETTINGS.media = savedMedia2;
  assert("6. with no public URL configured the action is refused BEFORE the approval prompt (nobody is asked to approve what cannot run)", !noMedia.ok && noMedia.error.code === "SB_MEDIA_NOT_CONFIGURED" && approvals.length === approvalsBefore && !noMedia.stages.includes("approval"), `${noMedia.error?.code} stages ${noMedia.stages.join(">")}`);
  delete kit.media.publish;
  kit.configure({ needsApproval: defaultNeeds, approve: async (req) => (approvals.push(req), decision.allow) });
}

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// recipes
// ════════════════════════════════════════════════════════════════════════════════════════════════════
assert("recipe: container, poll until FINISHED, publish returns the bound ids", ph.ok && ph.data.id === "p1" && ph.data.container === "c1" && mock.count.poll_c1 === 3, JSON.stringify(ph.data));
assert("recipe: the pipeline still ran every stage for a recipe", JSON.stringify(ph.stages) === JSON.stringify(ADR_ORDER));
mock.fetched.length = 0;
const imgs = [join(ALLOW, "p1.jpg"), join(ALLOW, "p2.jpg"), join(ALLOW, "p3.jpg")];
for (const [i, p] of imgs.entries()) writeFileSync(p, Buffer.concat([IMG, Buffer.from([i])]));
const car = await run("igish", "post_carousel", { images: imgs, caption: "three" });
assert("recipe: foreach creates one container per image, map and join build the carousel, assert guards it, the publish returns", car.ok && mock.fetched.length === 3 && mock.fetched.every((f) => f.status === 200) && car.data.children.length === 3 && /^p\d+$/.test(car.data.id), car.error?.message ?? JSON.stringify(car.data).slice(0, 100));
const carBody = JSON.parse(hits((e) => e.path === "/ig/media" && e.method === "POST").at(-1).body.toString());
assert("recipe: a joined list and a default are rendered into the request body", carBody.media_type === "CAROUSEL" && carBody.children.split(",").length === 3 && carBody.caption === "three");
mock.mode.igStatus = "ERROR";
const phErr = await run("igish", "post_photo", { image: photoPath });
mock.mode.igStatus = undefined;
assert("recipe: a failure state reported by the poll stops it, names the steps already done, and keeps the reconcile hint", !phErr.ok && phErr.error.code === "SB_RECIPE_FAILED" && /failure state/.test(phErr.error.message) && phErr.error.completed.includes("container") && /recent media/.test(phErr.error.hint ?? "") && !mock.log.some((e) => e.path === "/ig/media_publish" && e === mock.log.at(-1)));
// the double-post guard
const publishBefore = mock.count.publish ?? 0;
mock.mode.publish = "drop";
const dropped = await run("igish", "post_photo", { image: photoPath, caption: "drop" });
mock.mode.publish = undefined;
assert("THE double-post guard: the connection is dropped after the publish request left; it is NOT retried and the result is SB_OUTCOME_UNKNOWN with a reconcile hint", !dropped.ok && dropped.error.code === "SB_OUTCOME_UNKNOWN" && (mock.count.publish ?? 0) === publishBefore + 1 && /recent media/.test(dropped.error.reconcile ?? "") && dropped.error.completed?.includes("container"), `${dropped.error?.code} publish hits ${(mock.count.publish ?? 0) - publishBefore}`);
assert("recipe: a refused recipe file (unknown function, a step type that would run code) is skipped and reported, the good recipe beside it loads", (() => {
  const t = kit.toolkits.load("badrecipes");
  return t && t.actions.length === 1 && t.actions[0].slug === "fine" && t.overlay_issues.some((i) => /unknown function|unknown step type/.test(i)) && t.overlay_issues.length === 2;
})(), kit.toolkits.load("badrecipes")?.overlay_issues.join(" | "));
const stub = (log) => ({
  http: async (req) => (log.push(req), { status: 200, headers: { location: "https://upload.example/session" }, body: { id: "vid9", status: { uploadStatus: "uploaded" } } }),
  file: async () => ({ bytes: new Uint8Array(10), name: "a.mp4", mimeType: "video/mp4", sha256: "0" }),
  put: async (req) => (log.push({ put: req }), { status: 200, headers: {}, body: { id: "vid9" } }),
  sleep: async () => {},
});
const ytRecipe = JSON.parse(readFileSync(join(ROOT, "src", "connectors", "toolkits", "youtube", "recipes", "upload_video.json"), "utf8"));
const slog = [];
const ytOut = await R.runRecipe(ytRecipe.steps, { file: "x.mp4", title: "My video", tags: ["a", "b"], privacy_status: "unlisted" }, ytRecipe.result, stub(slog));
const init = slog.find((x) => x.url?.includes("/upload/youtube/v3/videos"));
assert("recipe: the real YouTube upload recipe builds its resumable init request from the input (stub runtime, no network)", init && init.method === "POST" && init.query.uploadType === "resumable" && init.query.part === "snippet,status" && init.json.snippet.title === "My video" && init.json.snippet.categoryId === "22" && init.json.snippet.tags.length === 2 && init.json.status.privacyStatus === "unlisted" && init.json.status.selfDeclaredMadeForKids === false && init.headers["X-Upload-Content-Length"] === "10");
assert("recipe: and PUTs to the session URL, then returns the video id and watch URL", slog.some((x) => x.put?.url === "https://upload.example/session") && ytOut.value.video_id === "vid9" && ytOut.value.url === "https://www.youtube.com/watch?v=vid9");
const mlog = [];
const rmin = await R.runRecipe(ytRecipe.steps, { file: "x.mp4", title: "T" }, ytRecipe.result, stub(mlog));
const minit = mlog.find((x) => x.url?.includes("/upload/youtube/v3/videos"));
assert("recipe: privacy defaults to private and an absent tags list is dropped, not sent as null", rmin.value.video_id === "vid9" && minit.json.status.privacyStatus === "private" && !("tags" in minit.json.snippet), JSON.stringify(minit?.json));
let assertErr;
try {
  await R.runRecipe([{ type: "assert", that: { path: "input.a", equals: 1 }, message: "a must be 1 but was {{input.a}}" }], { a: 2 }, undefined, stub([]));
} catch (e) {
  assertErr = e;
}
assert("recipe: a failed assert stops with its templated message", assertErr?.code === "SB_RECIPE_ASSERT" && assertErr.message === "a must be 1 but was 2");
let pollErr;
await R.runRecipe([{ type: "poll", request: { method: "GET", url: "/s" }, until: { path: "response.body.done", equals: true }, interval_ms: 0, max_attempts: 3 }], {}, undefined, { ...stub([]), http: async () => ({ status: 200, headers: {}, body: { done: false } }) }).catch((e) => (pollErr = e));
assert("recipe: a poll that never reaches its condition times out after max_attempts", pollErr?.code === "SB_RECIPE_TIMEOUT");
let limErr;
await R.runRecipe([{ type: "foreach", items: "{{input.items}}", as: "x", steps: [{ type: "http", request: { method: "GET", url: "/a" } }] }], { items: new Array(51).fill(1) }, undefined, stub([])).catch((e) => (limErr = e));
assert("recipe: a foreach over more than 50 items is refused", limErr?.code === "SB_RECIPE_LIMIT");
const sc = { input: { a: "x" }, steps: {}, constructor: "NOPE" };
assert("recipe: path lookups follow own properties only (__proto__, constructor, prototype are unreachable)", R.lookup({ a: 1 }, "__proto__") === undefined && R.lookup({ a: {} }, "a.constructor") === undefined && R.lookup(sc, "input.a") === "x" && R.lookup({ a: [1, 2] }, "a[1]") === 2);
assert("recipe: there is no code evaluation: calls, unknown functions and unknown step types are all refused at validation", ["{{ constructor.constructor('return 1')() }}", '{{ input.a | eval:"1" }}', "{{ process.exit(1) }}", "{{ input.a + 1 }}"].every((t) => R.validateRecipeSteps([{ type: "http", request: { method: "GET", url: "/x", json: { v: t } } }]) !== undefined) && R.validateRecipeSteps([{ type: "exec", cmd: "ls" }]) !== undefined);
assert("recipe: a well formed recipe validates", R.validateRecipeSteps(ytRecipe.steps) === undefined && R.validateRecipeSteps(JSON.parse(readFileSync(join(BUNDLED, "igish", "recipes", "post_carousel.json"), "utf8")).steps) === undefined);
const bodyEcho = await R.runRecipe([{ type: "http", bind: "r", request: { method: "POST", url: "/x", json: { s: "a {{input.n}} b", whole: "{{input.n}}", missing: "{{input.nope}}" } } }], { n: 5 }, "{{steps.r.body}}", { ...stub([]), http: async (req) => ({ status: 200, headers: {}, body: req.json }) });
assert("recipe: a whole-value template keeps its type, text around it interpolates, an unset whole-value key is dropped", bodyEcho.value.s === "a 5 b" && bodyEcho.value.whole === 5 && !("missing" in bodyEcho.value));
let interpErr;
await R.runRecipe([{ type: "http", request: { method: "GET", url: "/a/{{input.nope}}" } }], {}, undefined, stub([])).catch((e) => (interpErr = e));
assert("recipe: an unset reference inside text is an error, not the word undefined", interpErr?.code === "SB_RECIPE_INVALID");

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// retries, the double-post rule on plain actions, the 429 pause, provider error mapping
// ════════════════════════════════════════════════════════════════════════════════════════════════════
mock.mode.videosList = "flaky";
mock.count.videos_list = 0;
const flaky = await run("minivid", "videos_list", { part: "snippet" });
mock.mode.videosList = undefined;
assert("an idempotent read is retried on a 503 (two failures, then success)", flaky.ok && mock.count.videos_list === 3, `${mock.count.videos_list} attempts`);
mock.mode.send = "503";
mock.count.send = 0;
const s503 = await run("minimail", "users_messages_send", { raw: "UmF3" });
assert("a non-idempotent send is NEVER retried: one attempt on a 503, with a reconcile hint (the SENT label)", !s503.ok && s503.error.code === "SB_PROVIDER_UNAVAILABLE" && mock.count.send === 1 && /SENT/.test(s503.error.hint ?? ""), `${mock.count.send} attempts; ${s503.error?.hint?.slice(0, 80)}`);
mock.mode.send = "drop";
mock.count.send = 0;
const sdrop = await run("minimail", "users_messages_send", { raw: "UmF3" });
mock.mode.send = undefined;
assert("a dropped connection after a send is SB_OUTCOME_UNKNOWN: one attempt, not retried, hint to check SENT", !sdrop.ok && sdrop.error.code === "SB_OUTCOME_UNKNOWN" && mock.count.send === 1 && /SENT/.test(sdrop.error.reconcile ?? ""), `${sdrop.error?.code}; ${mock.count.send} attempt(s)`);
const closedPort = await (async () => {
  const s = createServer();
  const p = await freeListen(s);
  await closeServer(s);
  return p;
})();
const pxClosed = await callProxy({ method: "POST", url: `http://127.0.0.1:${closedPort}/x` });
assert("a failure to connect before anything is sent says so (nothing happened) and is not an unknown outcome", pxClosed.isError && pxClosed.body.error.code === "SB_PROVIDER_UNREACHABLE" && /nothing was sent/.test(pxClosed.body.error.message), pxClosed.body.error?.message.slice(0, 100));
mock.mode.rate = "429";
mock.count.rate = 0;
const rl1 = await run("minivid", "videos_rate", { id: "v", rating: "like" });
const requestsAfterFirst = reqs();
const rl2 = await run("minivid", "videos_rate", { id: "v", rating: "like" });
assert("a 429 with Retry-After pauses the account: SB_PROVIDER_RATE_LIMITED with the wait, then the next call is refused locally (no request sent)", !rl1.ok && rl1.error.code === "SB_PROVIDER_RATE_LIMITED" && rl1.error.retry_after_s === 2 && !rl2.ok && rl2.error.code === "SB_PROVIDER_RATE_LIMITED" && reqs() === requestsAfterFirst && mock.count.rate === 1 && rl2.stages.at(-2) === "limits", `${rl1.error?.retry_after_s}s; rate hits ${mock.count.rate}`);
const otherAcct = await run("minivid", "videos_rate", { id: "v", rating: "like", account: accB.id });
assert("the pause is per account: another account of the provider is not paused", mock.count.rate === 2 && otherAcct.error?.code === "SB_PROVIDER_RATE_LIMITED");
clock.ms += 3000;
mock.mode.rate = undefined;
const rl3 = await run("minivid", "videos_rate", { id: "v", rating: "like" });
assert("after the Retry-After passes the account is used again", rl3.ok && mock.count.rate === 3);
for (const [mode, code, rx] of [["400", "SB_PROVIDER_BAD_REQUEST", /Invalid value for part/], ["403", "SB_PROVIDER_FORBIDDEN", /insufficient permission/], ["404", "SB_PROVIDER_NOT_FOUND", /not found/], ["500", "SB_PROVIDER_UNAVAILABLE", /oops/], ["slack", "SB_PROVIDER_FORBIDDEN", /missing_scope/]]) {
  mock.mode.playlists = mode;
  const e = await run("minivid", "playlists_insert", { part: "snippet", snippet: { title: "p" } });
  assert(`provider errors map to SB_PROVIDER_*: ${mode === "slack" ? "HTTP 200 with ok:false" : `HTTP ${mode}`} is ${code} and carries the provider's own message`, !e.ok && e.error.code === code && rx.test(e.error.message) && e.decision === "allow", `${e.error?.code}: ${e.error?.message?.slice(0, 80)}`);
}
mock.mode.playlists = undefined;

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// 7. toggle and linking, through the real registry and router
// ════════════════════════════════════════════════════════════════════════════════════════════════════
const names = () => router.listTools().map((t) => t.name);
assert("7. every enabled toolkit server is mounted and listed through the router", ["minivid__videos_list", "minimail__users_messages_list", "miniapi__list_items", "igish__post_photo"].every((n) => names().includes(n)));
await registry.unmount("minivid");
const callOff = await router.callTool("minivid__videos_list", { part: "snippet" });
const n0 = reqs();
assert("7. a disabled toolkit is absent from tools/list and its calls are refused", !names().some((n) => n.startsWith("minivid__")) && callOff.isError && /unknown tool|SB_UNKNOWN_TOOL/.test(text(callOff)) && reqs() === n0, text(callOff).slice(0, 80));
await registry.mount(cfg.servers[0]);
const callOn = await router.callTool("minivid__videos_list", { part: "snippet" });
assert("7. turning it on again lists and serves it", names().includes("minivid__videos_list") && !callOn.isError);
cfg.servers[1].enabled = false;
assert("7. enabled: false in the config also hides a mounted toolkit", !names().some((n) => n.startsWith("minimail__")));
cfg.servers[1].enabled = true;
// fail closed: a toolkit whose provider has no ACTIVE probed account cannot be mounted
let lonelyErr;
await registry.mount({ id: "lonely", source: "connector", toolkit: "lonely", enabled: true }).catch((e) => (lonelyErr = e));
assert("7. fail closed: a toolkit cannot be mounted until its provider has an ACTIVE account that passed its probe", lonelyErr?.code === "SB_ACCOUNT_NOT_ACTIVE" && /switchboard connect mocklone/.test(lonelyErr.message) && !registry.has("lonely"), lonelyErr?.message.slice(0, 120));
let noTkErr;
await registry.mount({ id: "ghost", source: "connector", toolkit: "ghost", enabled: true }).catch((e) => (noTkErr = e));
assert("7. an undefined toolkit cannot be mounted", noTkErr?.code === "SB_TOOLKIT_NOT_FOUND");
// policy ceiling through the router: a read server refuses write actions by their verb, hinted by the action
const roCfg = { ...cfg, servers: [{ id: "minivid_ro", source: "connector", toolkit: "minivid", enabled: true, policy: "read" }] };
const roRegistry = new Registry(vault, { connectors: rt, accessToken: async () => "" }, () => NETWORK);
const roRouter = new Router(roRegistry, roCfg, (ref) => vault.resolve(ref));
await roRegistry.mount(roCfg.servers[0]);
const roWrite = await roRouter.callTool("minivid_ro__playlists_insert", { part: "snippet", snippet: { title: "x" } });
const roRead = await roRouter.callTool("minivid_ro__videos_list", { part: "snippet" });
const roDelete = await roRouter.callTool("minivid_ro__videos_delete", { id: "x" });
assert("3. through the router a server capped at read refuses the write and full actions (the scope comes from the action, not its name) and serves the read", roWrite.isError && /SB_POLICY_DENY/.test(text(roWrite)) && roDelete.isError && /SB_POLICY_DENY/.test(text(roDelete)) && !roRead.isError);
await roRegistry.unmountAll();

// client access: the gateway's `clients:` config is the one source (the merge replaced the link table with it)
const CLIENT_A = "client-a";
const CLIENT_B = "client-b";
const CLIENT_C = "client-c";
const clientsTable = {
  [CLIENT_A]: { servers: ["minivid"], max_scope: "write", max_risk: "high", accounts: { mockg: accA.id } },
  [CLIENT_B]: { servers: ["minivid", "minimail"], max_scope: "write", max_risk: "high", accounts: { mockg: accB.id } },
  // adapted: the caps are per client now (they were per toolkit link), so the read/low-on-mail case is its own client
  [CLIENT_C]: { servers: ["minimail"], max_scope: "read", max_risk: "low", accounts: { mockg: accB.id } },
};
kit.access.setSource(() => clientsTable);
const vidSrv = await connect({ id: "minivid", source: "connector", toolkit: "minivid", enabled: true });
const mailSrv = await connect({ id: "minimail", source: "connector", toolkit: "minimail", enabled: true });
const asClient = (id) => ({ _meta: { [CLIENT_META_KEY]: id } });
const listAs = async (srv, id) => (await srv.client.listTools(id ? asClient(id) : undefined)).tools.map((t) => t.name);
const aVid = await listAs(vidSrv, CLIENT_A);
const aMail = await listAs(mailSrv, CLIENT_A);
const bMail = await listAs(mailSrv, CLIENT_C);
assert("7. client A allowed one toolkit server sees that toolkit's tools and none of another's", aVid.includes("videos_list") && aMail.length === 0);
const aMailCall = await mailSrv.client.callTool({ name: "users_messages_list", arguments: {}, ...asClient(CLIENT_A) });
const nBeforeLink = reqs();
assert("7. client A is refused on the toolkit server it is not allowed (SB_CLIENT_NOT_LINKED) and nothing is sent", aMailCall.isError && parsed(aMailCall).error.code === "SB_CLIENT_NOT_LINKED" && reqs() === nBeforeLink);
assert("7. a client's caps filter the listing: client C is read/low, so it sees the reads and neither the send nor the draft", bMail.includes("users_messages_list") && !bMail.includes("users_messages_send") && !bMail.includes("users_drafts_create") && bMail.includes("manage_connections") && !bMail.includes("proxy_request"), bMail.join(","));
const bSend = await mailSrv.client.callTool({ name: "users_messages_send", arguments: { raw: "UmF3" }, ...asClient(CLIENT_C) });
assert("7. and refuses a call above them (SB_POLICY_DENY)", bSend.isError && parsed(bSend).error.code === "SB_POLICY_DENY" && !(mock.mode.send));
const cNone = await vidSrv.client.callTool({ name: "videos_list", arguments: { part: "snippet" }, ...asClient("client-never-linked") });
assert("7. a named client missing from a non-empty clients config is refused", cNone.isError && parsed(cNone).error.code === "SB_CLIENT_NOT_LINKED");
const unscoped = await vidSrv.client.callTool({ name: "videos_list", arguments: { part: "snippet" } });
assert("7. a call that names no client is the owner's unscoped path and is not narrowed", !unscoped.isError);
await vidSrv.client.callTool({ name: "videos_list", arguments: { part: "snippet" }, ...asClient(CLIENT_A) });
const tokA = hits((e) => e.path === "/minivid/v3/videos").at(-1).token;
await vidSrv.client.callTool({ name: "videos_list", arguments: { part: "snippet" }, ...asClient(CLIENT_B) });
const tokB = hits((e) => e.path === "/minivid/v3/videos").at(-1).token;
assert("7. two clients bound to different accounts make the mock see different tokens", tokA === TOK_A && tokB === TOK_B && tokA !== tokB);
const nBeforeEsc = reqs();
const escape = await vidSrv.client.callTool({ name: "videos_list", arguments: { part: "snippet", account: accB.id }, ...asClient(CLIENT_A) });
// ADAPTED (was: "an explicit account argument still beats the client's binding"). Under the governed gateway an
// argument may only name the client's own account, so naming another client's account is refused (SB_POLICY_DENY)
// and nothing is sent; naming its own is still honoured. The check keeps its subject (the argument vs the binding)
// and states the stricter rule the integration requires.
assert("7. an explicit account argument cannot beat the client's binding: another account is SB_POLICY_DENY and nothing is sent", escape.isError && parsed(escape).error.code === "SB_POLICY_DENY" && /client-a/.test(parsed(escape).error.message) && reqs() === nBeforeEsc);
const ownAcct = await vidSrv.client.callTool({ name: "videos_list", arguments: { part: "snippet", account: accA.id }, ...asClient(CLIENT_A) });
assert("7. ...while naming its own bound account is honoured", !ownAcct.isError && hits((e) => e.path === "/minivid/v3/videos").at(-1).token === TOK_A);
const mc = await vidSrv.client.callTool({ name: "manage_connections", arguments: {}, ...asClient(CLIENT_B) });
const mcData = parsed(mc).data;
assert("7. manage_connections lists the accounts with status and which one this client uses, and never a credential", !mc.isError && mcData.accounts.length === 2 && mcData.accounts.find((a) => a.used_by_this_client).id === accB.id && mcData.accounts.every((a) => a.status === "ACTIVE") && !JSON.stringify(mcData).includes(TOK_A) && !JSON.stringify(mcData).includes(TOK_B) && mcData.bound_account === accB.id);
const lowRisk = await vidSrv.client.callTool({ name: "videos_insert", arguments: { part: "snippet", snippet: { title: "t" } }, ...asClient(CLIENT_A) });
clientsTable[CLIENT_A].max_risk = "medium";
const aVid2 = await listAs(vidSrv, CLIENT_A);
assert("7. lowering a client's max_risk takes effect at once: the outward (high risk) upload leaves its listing and is refused", !aVid2.includes("videos_insert") && aVid.includes("videos_insert") && !lowRisk.isError);
const afterLow = await vidSrv.client.callTool({ name: "videos_insert", arguments: { part: "snippet", snippet: { title: "t" } }, ...asClient(CLIENT_A) });
assert("7. ...and refused when called by name", afterLow.isError && parsed(afterLow).error.code === "SB_POLICY_DENY");
clientsTable[CLIENT_B].servers = ["minivid"];
assert("7. removing a server from a client's servers takes it off that toolkit at once", kit.access.check(CLIENT_B, "minimail").allowed === false && kit.access.check(CLIENT_B, "minivid").allowed === true);
await vidSrv.client.close();
await mailSrv.client.close();

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// 8. exposure size and search
// ════════════════════════════════════════════════════════════════════════════════════════════════════
const RES = ["widgets", "invoices", "customers", "orders", "shipments", "refunds", "products", "coupons", "subscriptions", "tickets", "reports", "webhooks"];
const ONE = (r) => r.replace(/s$/, "");
const VERBS = [["list", "get", "List {rs}"], ["get", "get", "Get one {r}"], ["create", "post", "Create a new {r} entry"], ["update", "patch", "Update an existing {r} entry"], ["delete", "delete", "Delete one {r}"], ["archive", "post", "Archive an old {r} entry"], ["restore", "post", "Restore an archived {r} entry"], ["export", "get", "Export the {rs} to a file"], ["duplicate", "post", "Duplicate a {r} entry"], ["search", "get", "Search the {rs} by keyword"]];
const bigSpec = { openapi: "3.0.3", info: { title: "Big", version: "1" }, servers: [{ url: `${mock.base}/big` }], paths: {} };
const bigImportant = [];
for (const r of RES) {
  for (const [verb, method, summary] of VERBS) {
    const opId = `${verb}_${r}`;
    const path = verb === "list" || verb === "create" || verb === "search" ? `/${r}${verb === "search" ? "/search" : ""}` : `/${r}/{id}${["archive", "restore", "export", "duplicate"].includes(verb) ? `/${verb}` : ""}`;
    bigSpec.paths[path] ??= {};
    bigSpec.paths[path][verb === "list" ? "get" : method === "get" && verb === "get" ? "get" : method] = { operationId: opId, summary: summary.replace("{rs}", r).replace("{r}", ONE(r)), ...(path.includes("{id}") ? { parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }] } : {}), responses: { 200: { description: "ok" } } };
    if (["list", "get", "create"].includes(verb)) bigImportant.push(opId);
  }
}
DOCS["https://fixtures.test/bigapi.json"] = JSON.stringify(bigSpec);
// "refunds" and "coupons" stay out of the important set, so their actions are reachable only through search
const bigOwnerImportant = bigImportant.filter((n) => !/_(refunds|coupons)$/.test(n));
writeOwnerOverlay("bigapi", { source: { kind: "openapi", url: "https://fixtures.test/bigapi.json" }, important: bigOwnerImportant });
const bigSync = await syncToolkit(kit, "bigapi", { fetcher, clock: () => new Date(clock.ms) });
assert("8. a large toolkit imports (every operation, all schemas compile)", bigSync.status === "synced" && bigSync.actions >= 110 && bigSync.compile.compiled === bigSync.compile.total, `${bigSync.actions} actions`);
const bigCfg = { id: "bigapi", source: "connector", toolkit: "bigapi", enabled: true };
const bigSrv = await connect(bigCfg);
const bigList = (await bigSrv.client.listTools()).tools;
assert("8. the default tools/list is at most 30 tools per toolkit (the important set capped at 28 plus the two meta tools)", bigList.length <= MAX_LISTED_TOOLS && bigList.length === 30 && bigSrv.built.unlisted.length === bigSync.actions - 28, `${bigList.length} listed, ${bigSrv.built.unlisted.length} unlisted of ${bigSrv.built.toolCount}`);
await bigSrv.client.close();
const bigRegistry = new Registry(vault, { connectors: rt, accessToken: async () => "" }, () => NETWORK);
const bigRouter = new Router(bigRegistry, { ...cfg, servers: [bigCfg] }, (ref) => vault.resolve(ref));
await bigRegistry.mount(bigCfg);
const listedNames = bigRouter.listTools().map((t) => t.name);
assert("8. through the router the listing holds the important set plus the two discovery tools, and an unlisted action is not in it", listedNames.includes("find_tools") && listedNames.includes("call_tool") && !listedNames.includes("bigapi__create_coupons") && listedNames.filter((n) => n.startsWith("bigapi__")).length === 30 && listedNames.length === 32, `${listedNames.length} tools`);
const found = JSON.parse(text(await bigRouter.callTool("find_tools", { query: "create a new coupon" }))).matches.map((m) => m.name);
assert("8. find_tools returns the unlisted bigapi__create_coupons in the top 3 for 'create a new coupon' (same BM25F method as verify:search)", found.slice(0, 3).includes("bigapi__create_coupons"), found.slice(0, 5).join(", "));
const found2 = JSON.parse(text(await bigRouter.callTool("find_tools", { query: "restore an archived refund" }))).matches.map((m) => m.name);
assert("8. ...and 'restore an archived refund' finds bigapi__restore_refunds in the top 3", found2.slice(0, 3).includes("bigapi__restore_refunds"), found2.slice(0, 5).join(", "));
const callUnlisted = await bigRouter.callTool("call_tool", { name: "bigapi__create_coupons", arguments: {} });
const couponHit = hits((e) => e.path === "/big/coupons" && e.method === "POST").at(-1);
assert("8. an unlisted action is callable through call_tool, governed like any other (the request reached the provider with the account's token)", !callUnlisted.isError && couponHit?.token === TOK_A, text(callUnlisted).slice(0, 100));
const direct = await bigRouter.callTool("bigapi__get_coupons", { id: "c9" });
assert("8. and by its exact name", !direct.isError && hits((e) => e.path === "/big/coupons/c9").length === 1);
const searchCfg = { ...cfg, gateway: { ...cfg.gateway, tool_exposure: "search" }, servers: [bigCfg] };
const searchRouter = new Router(bigRegistry, searchCfg, (ref) => vault.resolve(ref));
const found3 = JSON.parse(text(await searchRouter.callTool("find_tools", { query: "export the subscriptions to a file", servers: ["bigapi"] }))).matches.map((m) => m.name);
assert("8. in search mode the unlisted actions are found too", found3.slice(0, 3).includes("bigapi__export_subscriptions") && searchRouter.listTools().length === 3, found3.slice(0, 4).join(", "));
await bigRegistry.unmountAll();

// the toolkits that ship in the package
const shipped = new T.ToolkitStore({ home: join(WORK, "no-home") });
const shippedSlugs = shipped.slugs();
const overlayFiles = shippedSlugs.map((s) => ({ s, o: shipped.bundledOverlay(s) }));
assert("8. the shipped overlays name a spec source over https, a provider that exists, and keep the important set within the listing budget", ["youtube", "gmail", "drive", "x", "slack", "notion"].every((s) => shippedSlugs.includes(s)) && overlayFiles.every(({ o }) => !o.source || /^https:\/\//.test(o.source.url)) && overlayFiles.every(({ o }) => (o.important ?? []).length + 1 <= 28) && overlayFiles.every(({ o }) => !o.provider || rt.providers.has(o.provider)), overlayFiles.map(({ s, o }) => `${s}:${(o.important ?? []).length}`).join(" "));
assert("8. shipped renames are valid slugs that fit the budget and never collide", overlayFiles.every(({ s, o }) => Object.values(o.rename ?? {}).every((v) => /^[a-z0-9_]+$/.test(v) && v.length <= T.maxActionSlug(s)) && new Set(Object.values(o.rename ?? {})).size === Object.keys(o.rename ?? {}).length));
const ytShipped = shipped.load("youtube");
assert("8. the shipped YouTube toolkit loads its recipe without a synced spec and lists it as important", ytShipped && ytShipped.source === "recipe" && ytShipped.actions.length === 1 && ytShipped.actions[0].slug === "upload_video" && ytShipped.actions[0].important && ytShipped.actions[0].outward && ytShipped.actions[0].risk === "high" && !ytShipped.actions[0].idempotent && ytShipped.overlay_issues.every((i) => /not an action/.test(i)));

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// 9. audit rows
// ════════════════════════════════════════════════════════════════════════════════════════════════════
kit.configure({ ownAudit: false });
await router.callTool("minivid__videos_list", { part: "snippet", account: accB.id });
const viaRouter = recentAudit(5).find((r) => r.tool === "videos_list" && r.toolkit === "minivid");
assert("9. through the router one audit row carries toolkit, toolkit version, account id, client slot and risk (from the connector's own result)", viaRouter && viaRouter.toolkit === "minivid" && /^\d{8}_\d{2}$/.test(viaRouter.toolkit_version) && viaRouter.account === accB.id && viaRouter.risk === "low" && viaRouter.server === "minivid" && viaRouter.decision === "allow" && /^run_/.test(viaRouter.run_id), JSON.stringify(viaRouter));
await router.callTool("minimail__users_messages_list", {});
const rowsBefore = recentAudit(500).length;
kit.configure({ ownAudit: true });
await run("minivid", "videos_list", { part: "snippet" }, { client: CLIENT_A, server: "minivid" });
const own = recentAudit(3).find((r) => r.tool === "videos_list" && r.client === CLIENT_A);
assert("9. a direct run writes its own row with the client and the same fields", own && own.toolkit === "minivid" && own.account === accA.id && own.risk === "low" && own.client === CLIENT_A && /^\d{8}_\d{2}$/.test(own.toolkit_version), JSON.stringify(own));
await run("minivid", "playlists_insert", { part: "snippet" }, { client: "client-never-linked" });
const denyRow = recentAudit(3).find((r) => r.client === "client-never-linked");
assert("9. a refusal before anything is sent is a deny row with its SB_ code", denyRow && denyRow.decision === "deny" && denyRow.error_code === "SB_CLIENT_NOT_LINKED" && denyRow.toolkit === "minivid");
await router.callTool("minivid__playlists_insert", { part: "snippet", snippet: { title: "p" }, junk: 1 });
const spoof = recentAudit(500).filter((r) => r.toolkit === "minivid").length;
assert("9. outward and risk are recorded: the high risk upload row says so", recentAudit(500).some((r) => r.tool === "videos_insert" && r.risk === "high" && r.outward === true) && spoof > 0);
const chain = verifyAudit({ all: true });
assert("9. the audit hash chain verifies after all of it", chain.ok && chain.rows > rowsBefore - 1, `${chain.rows} rows${chain.break ? ` break at ${chain.break.seq}: ${chain.break.reason}` : ""}`);
const logText = readdirSync(HOME).filter((n) => n.startsWith("audit.log")).map((n) => readFileSync(join(HOME, n), "utf8")).join("\n");
assert("9. no token appears in the audit log", CANARIES.every((c) => !logText.includes(c)) && logText.length > 1000);
// a hostile upstream cannot write connector fields into the audit log: only a connector server is believed
{
  const fakeServer = { config: { source: "npx", id: "evil" } };
  const out = router.connectorAudit(fakeServer, { content: [], _meta: { "io.mcpswitchboard/audit": { toolkit: "youtube", account: "ca_fake", client: "root" } } });
  const real = router.connectorAudit({ config: { source: "connector", id: "minivid" } }, { content: [], _meta: { "io.mcpswitchboard/audit": { toolkit: "youtube", account: "ca_ok1", client: "root", risk: "extreme", run_id: "run id with spaces" } } });
  assert("9. audit fields are honoured only from a connector server, and only in a strict shape", Object.keys(out).length === 0 && real.toolkit === "youtube" && real.account === "ca_ok1" && real.client === "root" && !("risk" in real) && !("run_id" in real));
}

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// coverage
// ════════════════════════════════════════════════════════════════════════════════════════════════════
const csvDir = join(WORK, "checklists");
mkdirSync(csvDir, { recursive: true });
const HEAD = "toolkit,action_slug,required_inputs,http_method,endpoint,basis,spec_check,file_params,provider_scopes,notes\n";
writeFileSync(join(csvDir, "youtube.csv"), HEAD + [
  'youtube,YOUTUBE_ADD_VIDEO_TO_PLAYLIST,"videoId,playlistId",POST,/youtube/v3/playlistItems,B,yes,videoId,https://www.googleapis.com/auth/youtube,playlistItems.insert',
  "youtube,YOUTUBE_CREATE_CHANNEL_SECTION,snippet,POST,/youtube/v3/channelSections,R,fuzzy score 0.86,,,fuzzy match to youtube.channelSections.insert",
  "youtube,YOUTUBE_LIST_COMMENT_THREADS,,GET,/youtube/v3/commentThreads,R,x,,,deprecated action; fuzzy match to youtube.commentThreads.list",
  'youtube,YOUTUBE_NOTE_WITH_COMMA,"a,b",GET,/youtube/v3/x,A,x,,,"has, a comma and ""quotes"""',
].join("\n") + "\n");
writeFileSync(join(csvDir, "googledrive.csv"), HEAD + [
  "googledrive,GOOGLEDRIVE_LIST_FILES,,GET,/drive/v3/files,A,x,,,name equals provider spec op",
  "googledrive,GOOGLEDRIVE_PARSE_FILE,,,,B,x,,,composite UNVERIFIED",
  "googledrive,GOOGLEDRIVE_GUESS,,GET,/drive/v3/guess,C,x,,,LOW CONFIDENCE UNREVIEWED fuzzy match",
].join("\n") + "\n");
writeFileSync(join(csvDir, "youtube_triggers.csv"), "trigger_slug,name,type_hint\nYOUTUBE_NEW_VIDEO,New video,\n");
const cov = new Coverage(join(WORK, "cov-home"), () => clock.ms);
const imp = cov.importCsv(csvDir);
assert("coverage: the CSVs import with quoted commas and quotes intact, triggers files are not rows, and the row count is exact", imp.rows === 7 && imp.files === 2 && imp.problems.length === 0 && parseCsv('a,"b,c","d ""e"""\n')[0].join("|") === 'a|b,c|d "e"', JSON.stringify(imp));
const rep0 = cov.report();
const stateOf = (slug) => cov.states().find((s) => s.row.slug === slug).state;
assert("coverage: base states are deduced (a reviewed endpoint is mapped, an unreviewed or empty one is unmapped, 'deprecated action' is deprecated)", stateOf("YOUTUBE_ADD_VIDEO_TO_PLAYLIST") === "mapped" && stateOf("GOOGLEDRIVE_GUESS") === "unmapped" && stateOf("GOOGLEDRIVE_PARSE_FILE") === "unmapped" && stateOf("YOUTUBE_LIST_COMMENT_THREADS") === "deprecated");
const sumStates = (t) => Object.values(t.counts).reduce((a, b) => a + b, 0);
assert("coverage: per-state counts sum to the row count with no row lost, and the deprecated row is excluded by name", sumStates(rep0.total) === 7 && rep0.total.rows === 7 && rep0.deprecated_rows.join() === "YOUTUBE_LIST_COMMENT_THREADS" && rep0.total.addressable === 6 && rep0.toolkits.find((t) => t.our_toolkit === "drive")?.toolkit === "googledrive");
assert("coverage: with nothing proven live the working count is 0, however many rows are mapped", rep0.total.working === 0 && rep0.total.counts.mapped >= 3 && /working = rows proven live[^\n]*: 0 of 6/.test(formatReport(rep0)));
cov.mark("YOUTUBE_ADD_VIDEO_TO_PLAYLIST", "mock_tested", { note: "contract suite" });
assert("coverage: mock_tested is its own state and is not working", stateOf("YOUTUBE_ADD_VIDEO_TO_PLAYLIST") === "mock_tested" && cov.report().total.working === 0);
let noAcct;
try {
  cov.mark("YOUTUBE_ADD_VIDEO_TO_PLAYLIST", "live_verified");
} catch (e) {
  noAcct = e;
}
assert("coverage: live_verified needs the account that proved it", /needs --account/.test(noAcct?.message ?? ""));
cov.mark("YOUTUBE_ADD_VIDEO_TO_PLAYLIST", "live_verified", { account: accA.id, note: "owner probe" });
const rep1 = cov.report();
assert("coverage: only an account-stamped live_verified line makes a row working, and it prints as working", stateOf("YOUTUBE_ADD_VIDEO_TO_PLAYLIST") === "live_verified" && rep1.total.working === 1 && /1 of 6/.test(formatReport(rep1)) && cov.ledger().at(-1).ts && cov.ledger().at(-1).account === accA.id);
writeFileSync(join(WORK, "cov-home", "connectors", "verification.ndjson"), readFileSync(join(WORK, "cov-home", "connectors", "verification.ndjson"), "utf8") + JSON.stringify({ ts: new Date().toISOString(), id: "GOOGLEDRIVE_LIST_FILES", toolkit: "googledrive", state: "live_verified" }) + "\ntorn line\n");
const rep2 = cov.report();
assert("coverage: a hand-written live_verified line with no account is ignored and reported, a torn line is skipped", stateOf("GOOGLEDRIVE_LIST_FILES") === "mapped" && rep2.total.working === 1 && rep2.ignored_lines.includes("GOOGLEDRIVE_LIST_FILES"));
let depErr;
try {
  cov.mark("YOUTUBE_LIST_COMMENT_THREADS", "live_verified", { account: accA.id });
} catch (e) {
  depErr = e;
}
cov.mark("GOOGLEDRIVE_GUESS", "blocked_by_platform", { note: "needs a paid tier" });
cov.mark("GOOGLEDRIVE_PARSE_FILE", "declined");
assert("coverage: a deprecated row cannot be promoted; blocked_by_platform and declined are states of their own and not working", /deprecated/.test(depErr?.message ?? "") && stateOf("GOOGLEDRIVE_GUESS") === "blocked_by_platform" && stateOf("GOOGLEDRIVE_PARSE_FILE") === "declined" && cov.report().total.working === 1);
assert("coverage: a toolkit filter accepts the R1 name or ours and the summary counts rows by our slug", cov.report("drive").total.rows === 3 && cov.report("googledrive").total.rows === 3 && cov.summary("drive").declined === 1);
const R1_DIR = "D:/agents/wiki/reference/mcp-switchboard-rea/checklists";
if (existsSync(R1_DIR)) {
  const real1 = new Coverage(join(WORK, "cov-real"), () => clock.ms);
  const ri = real1.importCsv(R1_DIR);
  const rr = real1.report();
  assert("coverage: the real R1 checklists reconcile: 1,740 rows, 31 deprecated excluded by name, per-state counts sum to 1,740, nothing is working", ri.rows === 1740 && ri.deprecated === 31 && sumStates(rr.total) === 1740 && rr.deprecated_rows.length === 31 && rr.total.working === 0 && rr.total.addressable === 1709 && rr.toolkits.length === 12, `${ri.rows} rows, ${ri.deprecated} deprecated, ${rr.toolkits.length} toolkits, mapped ${rr.total.counts.mapped}, unmapped ${rr.total.counts.unmapped}`);
} else {
  note(`the real R1 checklists were not found at ${R1_DIR}: that reconciliation check was not run (not counted)`);
}

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// repository hygiene: generated vendor specs are never tracked
// ════════════════════════════════════════════════════════════════════════════════════════════════════
const git = (args) => spawnSync("git", args, { cwd: ROOT, encoding: "utf8" });
const tracked = git(["ls-files", "--cached", "--others", "--exclude-standard"]);
const trackedFiles = tracked.status === 0 ? [...new Set(tracked.stdout.split("\n").filter(Boolean))] : null;
if (trackedFiles) {
  const bad = trackedFiles.filter((f) => /(^|\/)toolkits\/[^/]+\/(\d{8}_\d{2}|current\.json)/.test(f) || /actions\.json$/.test(f) || /\.generated\.json$/.test(f) || /coverage-rows\.json$/.test(f));
  assert("hygiene: no generated toolkit output (versioned actions, current pointers, coverage rows) is tracked or would be added by git", bad.length === 0, bad.join(", "));
  const underToolkits = trackedFiles.filter((f) => f.startsWith("src/connectors/toolkits/"));
  const oddName = underToolkits.filter((f) => !/^src\/connectors\/toolkits\/[a-z0-9-]+\/(overlay\.json|recipes\/[a-z0-9_]+\.json)$/.test(f));
  const looksLikeSpec = underToolkits.filter((f) => {
    try {
      const j = JSON.parse(readFileSync(join(ROOT, f), "utf8"));
      return j.kind === "discovery#restDescription" || "openapi" in j || "swagger" in j || "resources" in j || "paths" in j;
    } catch {
      return false;
    }
  });
  assert("hygiene: what is committed under src/connectors/toolkits is only overlays and recipes, and none of it is a vendor spec", oddName.length === 0 && looksLikeSpec.length === 0 && underToolkits.length >= 7, `${underToolkits.length} files${oddName[0] ? `; odd: ${oddName[0]}` : ""}`);
  const ign = git(["check-ignore", "-q", ".switchboard/toolkits/youtube/20261023_00/actions.json"]);
  const ign2 = git(["check-ignore", "-q", "some/home/toolkits/gmail/20261023_01/actions.json"]);
  const ign3 = git(["check-ignore", "-q", "some/home/toolkits/gmail/current.json"]);
  assert("hygiene: .gitignore covers a synced toolkit version, its current pointer and the coverage snapshot wherever a home lands", ign.status === 0 && ign2.status === 0 && ign3.status === 0 && git(["check-ignore", "-q", "a/connectors/coverage-rows.json"]).status === 0);
  const em = trackedFiles.filter((f) => /^(src\/connectors|scripts\/(verify-connectors-exec|live-sync-check))/.test(f) || f.startsWith("scripts/fixtures/connectors")).filter((f) => readFileSync(join(ROOT, f), "utf8").includes("\u2014"));
  assert("hygiene: no em dash character in the connector sources, fixtures or this oracle", em.length === 0, em.join(", "));
} else {
  assert("hygiene: git is available to list tracked files", false, "git ls-files failed");
}
const syncedTree = (function walk(d) {
  return readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(d, e.name)) : [join(d, e.name)]));
})(join(HOME, "toolkits"));
assert("hygiene: generated actions live only under SWITCHBOARD_HOME/toolkits, outside the repository", syncedTree.some((f) => f.endsWith("actions.json")) && syncedTree.every((f) => f.startsWith(HOME)) && !HOME.startsWith(ROOT));

// ════════════════════════════════════════════════════════════════════════════════════════════════════
// the CLI and the build
// ════════════════════════════════════════════════════════════════════════════════════════════════════
const CLI = join(ROOT, "dist", "cli.js");
const cfgFile = join(WORK, "cli.yaml");
writeFileSync(cfgFile, `gateway:\n  transport: [stdio]\n  http: { host: 127.0.0.1, port: 8099 }\n  tool_exposure: namespaced\n  default_policy: read\nvault:\n  backend: encrypted-file\nservers: []\nsettings:\n  network:\n    allow_private: ["127.0.0.1"]\n`);
const cli = (args) => {
  const r = spawnSync(process.execPath, [CLI, "--config", cfgFile, ...args], { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" }, timeout: 60_000 });
  return { code: r.status, out: `${r.stdout}${r.stderr}`.replace(/\u001b\[[0-9;]*m/g, "") };
};
const cImp = cli(["coverage", "--import", csvDir]);
const cRep = cli(["coverage"]);
const cMark = cli(["coverage", "--mark", "YOUTUBE_CREATE_CHANNEL_SECTION", "--state", "live_verified"]);
const cJson = cli(["coverage", "drive", "--json"]);
assert("CLI: coverage --import, coverage and coverage --mark work end to end; live_verified without an account is refused", cImp.code === 0 && /imported 7 rows/.test(cImp.out) && cRep.code === 0 && /working = rows proven live/.test(cRep.out) && cMark.code === 1 && /needs --account/.test(cMark.out) && JSON.parse(cJson.out).total.rows === 3, `${cImp.out.slice(0, 60)} | ${cMark.out.slice(0, 80)}`);
// Adapted: `link`, `unlink` and `links` now edit the clients config (through ClientAdmin) instead of a link table. With no gateway
// running the command writes the config file and the key store directly, so the oracle reads the file afterwards.
const cLinkBad = cli(["link", "cli-client", "nosuchtoolkit"]);
const cLinkBadAcct = cli(["link", "cli-ghost", "minivid", "--account", "mockg/nobody"]);
const cLink = cli(["link", "cli-client", "minivid", "--max-scope", "write", "--account", accB.id]);
const cfgLinked = cLink.code === 0 ? loadConfig(cfgFile).clients?.["cli-client"] : undefined;
const cLinks = cli(["links"]);
const cList = cli(["toolkits", "list"]);
const cShow = cli(["toolkits", "show", "minivid"]);
const cNoSrc = cli(["toolkits", "sync", "igish"]);
const cUnlink = cli(["unlink", "cli-client"]);
const cLinksAfter = cli(["links"]);
assert("CLI: link validates the toolkit, binds an account of its provider in the clients config, and links shows it; toolkits list and show describe what is defined", cLinkBad.code === 1 && cLink.code === 0 && cfgLinked?.accounts?.mockg === accB.id && cfgLinked?.servers.includes("minivid") && cfgLinked?.max_scope === "write" && /cli-client/.test(cLinks.out) && new RegExp(accB.id).test(cLinks.out) && /minivid/.test(cLinks.out) && /minivid/.test(cList.out) && /videos_list|actions/.test(cShow.out) && /read\b.*\d/.test(cShow.out), `${cLink.out.slice(0, 80)} | ${cShow.out.slice(0, 80)}`);
const cfgUnlinked = loadConfig(cfgFile).clients?.["cli-client"];
assert("CLI: toolkits sync <toolkit> with no spec source says so; unlink takes the connector servers and the account binding off the client (the client entry stays)", cNoSrc.code === 0 && /no spec source|nothing to sync/.test(cNoSrc.out) && cUnlink.code === 0 && cfgUnlinked && !cfgUnlinked.servers.includes("minivid") && Object.keys(cfgUnlinked.accounts ?? {}).length === 0 && !new RegExp(accB.id).test(cLinksAfter.out));
assert("CLI: link with an account that does not exist fails and leaves no half-applied link behind", cLinkBadAcct.code === 1 && !/cli-ghost/.test(cLinks.out) && !/cli-ghost/.test(cLinksAfter.out), cLinkBadAcct.out.slice(0, 120));
const cEnable = cli(["toolkits", "enable", "minivid"]);
const cfgAfter = loadConfig(cfgFile);
const cDisable = cli(["toolkits", "disable", "minivid"]);
const cfgOff = loadConfig(cfgFile);
const cLonely = cli(["toolkits", "enable", "youtube"]);
assert("CLI: toolkits enable writes a connector server (needs an ACTIVE probed account), disable turns it off, and a toolkit without an account is refused with the connect command", cEnable.code === 0 && cfgAfter.servers.some((s) => s.source === "connector" && s.toolkit === "minivid" && s.enabled === true) && cDisable.code === 0 && cfgOff.servers.find((s) => s.toolkit === "minivid").enabled === false && cLonely.code === 1 && /switchboard connect google/.test(cLonely.out), `${cLonely.out.slice(0, 120)}`);
const BAD_HEAD = "gateway:\n  transport: [stdio]\n  http: { host: 127.0.0.1, port: 8099 }\n  tool_exposure: namespaced\n  default_policy: read\nvault:\n  backend: encrypted-file\nservers:\n";
const badConfig = (name, entry) => {
  try {
    writeFileSync(join(WORK, name), `${BAD_HEAD}  - ${entry}\n`);
    loadConfig(join(WORK, name));
    return "";
  } catch (e) {
    return String(e.message);
  }
};
const cfgBad = badConfig("bad.yaml", "{ id: x, source: connector }");
const cfgBad2 = badConfig("bad2.yaml", "{ id: y, source: npx, package: some-pkg, toolkit: youtube }");
assert("config: a connector server without a toolkit is refused, and a toolkit on a non-connector server is refused", /needs a `toolkit`/.test(cfgBad) && /belong to `source: connector` only/.test(cfgBad2), `${cfgBad.slice(0, 100)} | ${cfgBad2.slice(0, 100)}`);
const distToolkits = readdirSync(join(ROOT, "dist", "connectors", "toolkits"));
assert("build: dist/connectors/toolkits carries the overlays and recipes next to the code", ["youtube", "gmail", "drive", "x", "slack", "notion"].every((s) => distToolkits.includes(s)) && existsSync(join(ROOT, "dist", "connectors", "toolkits", "youtube", "recipes", "upload_video.json")));
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
assert("package: verify:connectors-exec is registered and in the verify chain", pkg.scripts["verify:connectors-exec"] === "node scripts/verify-connectors-exec.mjs" && pkg.scripts.verify.includes("npm run verify:connectors-exec"));

// ── teardown and verdict ─────────────────────────────────────────────────────────────────────────────
await closeServer(mediaServer);
await closeServer(mockServer);
await closeServer(otherServer);
try {
  rmSync(WORK, { recursive: true, force: true });
} catch {
  /* leftovers in temp are harmless */
}
const passed = checks.filter((c) => c.ok).length;
for (const c of checks.filter((x) => !x.ok)) console.log(`FAILED: ${c.name}${c.detail ? ` - ${c.detail}` : ""}`);
console.log(`\n${passed}/${checks.length} checks passed`);
process.exit(passed === checks.length ? 0 : 1);
