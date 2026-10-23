// Deterministic oracle for the seeded provider breadth and the Connectors admin surface (lead's amendment to the
// local-composio ADR, step C3): provider auth definitions seeded from Activepieces MIT auth settings, the
// dashboard's Connectors page and its admin API, and the public docs. Everything runs against FIXTURES and a MOCK
// authorization and API server on loopback ephemeral ports. It never calls a real provider, signs in anywhere or
// spends money: a socket tripwire (section 9) proves no connection left loopback.
//
//   1. The committed seeds: every file validates, none carries a secret-shaped string, every one is marked
//      unverified_seed with its source commit and piece, the counts by auth mode recomputed here match the
//      extractor's manifest, NOTICE carries the Activepieces MIT copyright notice.
//   2. Curated wins: a seed whose slug is a curated slug or toolkit is shadowed; an owner definition replaces a
//      seed; list() stays curated-only; a bad seed (probe, toolkits, broad wildcard, no mark, bad JSON, wrong
//      file name) is refused without taking the others down; a curated file cannot claim to be a seed.
//   3. A seeded OAuth provider starts a connect flow and completes it against a mock for five shapes (plain,
//      PKCE required, Basic client auth, extra authorize params, client credentials), and its account is stamped.
//   4. A seed never reports working: not in the account list, not in the provider coverage state, not in the
//      ledger (a live_verified mark through a seed account is refused, a hand-written line is ignored), not
//      probe-able; a curated provider's live row still counts.
//   5. The admin API through the real dashboard: owner session and CSRF are required, search and filters and paging,
//      the owner steps when no app is registered, the consent URL, the callback, a pasted key (never echoed), a
//      mode this build does not drive, toolkit enable and disable (live mount and unmount), coverage, and no
//      credential in any answer.
//   6. The extractor on a fixture checkout: it parses and never runs piece code, facts only, deterministic.
//   7. The docs, README section, NOTICE and repository hygiene (no em dash in what this step wrote, no private
//      markers in the public docs, no generated spec output tracked).
//
// Build first (`npm run build`), then `npm run verify:connectors-seed`. Isolated SWITCHBOARD_HOME; every listener
// it starts is closed.
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync, rmSync, appendFileSync, cpSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import net from "node:net";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOME = mkdtempSync(join(tmpdir(), "sb-cseed-"));
process.env.SWITCHBOARD_HOME = HOME;
const WORK = mkdtempSync(join(tmpdir(), "sb-cseed-work-"));

const checks = [];
// A passing line's detail is printed with the word FAIL defused so the oracle runner's failure scan only ever
// shows real failures.
const tidy = (d) => String(d).replace(/[✓✗]/g, "").replace(/\bFAIL\b/g, "fail").replace(/BREACHED/g, "breached");
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? ` - ${cond ? tidy(detail) : detail}` : ""}`);
};
const note = (line) => console.log(`NOTE  ${line}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── socket tripwire: nothing may connect anywhere but loopback ───────────────────────────────────────────
const NONLOCAL = [];
const realConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...args) {
  const o = args[0];
  const host = typeof o === "object" && o !== null ? o.host : typeof args[1] === "string" ? args[1] : undefined;
  if (host && !/^(127\.0\.0\.1|localhost|::1|\[::1\])$/.test(host)) {
    NONLOCAL.push(String(host));
    throw new Error(`oracle tripwire: refused a connection to ${host}`);
  }
  return realConnect.apply(this, args);
};

// Everything the product printed or returned that the canary scan will read.
const OUTPUTS = [];
const leak = (label, text) => OUTPUTS.push({ label, text: String(text) });
const realStderr = process.stderr.write.bind(process.stderr);
process.stderr.write = (chunk, ...rest) => {
  leak("process stderr (engine logs)", Buffer.isBuffer(chunk) ? chunk.toString("utf8") : chunk);
  return realStderr(chunk, ...rest);
};

const mod = (p) => import(pathToFileURL(join(ROOT, "dist", p)).href);
const { Connectors } = await mod("connectors/index.js");
const { ProviderRegistry, validateProviderDef, seedProblems } = await mod("connectors/providers.js");
const { ConnectorAdmin } = await mod("connectors/admin.js");
const { summarize } = await mod("connectors/accounts.js");
const { Vault } = await mod("vault.js");
const { Gateway } = await mod("gateway.js");
const { startDashboard } = await mod("dashboard.js");
const { LoginCodeStore } = await mod("httpsec.js");
const EXTRACT = await import(pathToFileURL(join(ROOT, "scripts", "extract-activepieces-auth.mjs")).href);

const hex = (n) => randomBytes(n).toString("hex");
const sha = (b) => createHash("sha256").update(b).digest("hex");
const clone = (o) => JSON.parse(JSON.stringify(o));
const freeListen = (server) => new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address().port)));
const closeServer = (s) => new Promise((resolve) => s.close(() => resolve()));
const readBody = (req) =>
  new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
  });
const NETWORK = { allow_private: ["127.0.0.1"], timeout_ms: 8000 };

// ── secrets the run mints: the canary list ───────────────────────────────────────────────────────────────
const SECRETS = new Set();
const mint = (prefix) => {
  const t = `${prefix}_CNRY${hex(12)}`;
  SECRETS.add(t);
  return t;
};
const CLIENT_ID = "seed-oracle-client-id";
const CLIENT_SECRET = mint("seed-client-secret");
const TOK_MOCKG = mint("tok-mockg");
const KEY_CANARY = mint("key-airtable");

// ═════════════════════════════════════════════════════════════════════════════════════════════════════
// 1. the committed seeds
// ═════════════════════════════════════════════════════════════════════════════════════════════════════
const SEED_DIR = join(ROOT, "src", "connectors", "providers", "seed");
const seedFiles = readdirSync(SEED_DIR).filter((f) => f.endsWith(".json") && !f.startsWith("_")).sort();
const manifest = JSON.parse(readFileSync(join(SEED_DIR, "_manifest.json"), "utf8"));
const seedDefs = new Map();
{
  const problems = [];
  const badName = [];
  const badMark = [];
  const badProv = [];
  const withExtras = [];
  const badHosts = [];
  const noNote = [];
  const secretHits = [];
  const dashHits = [];
  const badUrls = [];
  const SECRET_PARAM = /client[_-]?(id|secret|key)|secret|token|password|api[_-]?key|apikey|signature/i;
  // a "<ref>" or "<name>" value is the CLI hint's placeholder for a vault reference, never a secret
  const EXTRA = [/\bclient_secret=(?!<[a-z_]+>)[^&\s]{6,}/i, /\b(?:password|passwd)=(?!<[a-z_]+>)[^&\s]{4,}/i, /\bapi[_-]?key=(?!<[a-z_]+>)[A-Za-z0-9]{8,}/i];
  const strings = (v, out = []) => {
    if (typeof v === "string") out.push(v);
    else if (Array.isArray(v)) v.forEach((x) => strings(x, out));
    else if (v && typeof v === "object") for (const [k, x] of Object.entries(v)) (out.push(k), strings(x, out));
    return out;
  };
  let scanned = 0;
  for (const f of seedFiles) {
    const text = readFileSync(join(SEED_DIR, f), "utf8");
    const def = JSON.parse(text);
    seedDefs.set(def.slug, def);
    const p = [...validateProviderDef(def), ...seedProblems(def)];
    if (p.length) problems.push(`${f}: ${p[0]}`);
    if (f !== `${def.slug}.json`) badName.push(f);
    if (def.verification !== "unverified_seed" || !/^[0-9a-f]{40}$/.test(def.source?.activepieces_commit ?? "") || def.source.activepieces_commit !== manifest.source.commit || !def.source.piece) badMark.push(f);
    if (def.provenance?.license !== "MIT" || !/Activepieces/.test(def.provenance?.attribution ?? "") || def.provenance.derived_from.length !== 1) badProv.push(f);
    if (def.toolkits || def.identity_probe) withExtras.push(f);
    for (const h of def.api_hosts) {
      const bare = h.replace(/^\*\./, "");
      if (!/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(bare) || /^\d+\.\d+\.\d+\.\d+$/.test(bare) || bare === "localhost" || /activepieces/.test(bare) || (h.startsWith("*.") && bare.split(".").length < 2)) badHosts.push(`${f}:${h}`);
    }
    if (!def.owner_setup.notes[0]?.startsWith("SEED, unverified") || !/never counts as working/.test(def.owner_setup.notes[0]) || !/^Unverified seed/.test(def.owner_setup.steps[0])) noNote.push(f);
    const masked = text.replaceAll(manifest.source.commit, "<commit>");
    for (const s of [masked, ...strings(JSON.parse(masked))]) {
      scanned++;
      if (EXTRA.some((re) => re.test(s)) || EXTRACT.looksSecret(s)) {
        secretHits.push(f);
        break;
      }
    }
    if (/[\u2013\u2014]/.test(text)) dashHits.push(f);
    for (const a of def.auth) {
      for (const u of [a.oauth2?.authorize_url, a.oauth2?.token_url].filter(Boolean)) {
        let url;
        try {
          url = new URL(u);
        } catch {
          badUrls.push(`${f}:${u}`);
          continue;
        }
        if (url.protocol !== "https:" || url.username || url.password || [...url.searchParams.keys()].some((k) => SECRET_PARAM.test(k))) badUrls.push(`${f}:${url.host}`);
      }
    }
  }
  assert("seeds: the seed folder holds files and a manifest", seedFiles.length > 100 && seedFiles.length === manifest.seeds, `${seedFiles.length} seed files, manifest says ${manifest.seeds}`);
  assert("seeds: every file validates against the provider schema, the semantic rules and the seed rules", problems.length === 0, problems.slice(0, 3).join(" | "));
  assert("seeds: every file is named for its slug", badName.length === 0, badName.slice(0, 5).join(","));
  assert("seeds: every seed is marked unverified_seed with the manifest's source commit and a piece name", badMark.length === 0, badMark.slice(0, 5).join(","));
  assert("seeds: every seed carries MIT provenance naming Activepieces", badProv.length === 0, badProv.slice(0, 5).join(","));
  assert("seeds: no seed declares toolkits or an identity probe (nothing in a seed can look verified)", withExtras.length === 0, withExtras.slice(0, 5).join(","));
  assert("seeds: every api_hosts entry is a plain https host or a wildcard with two or more labels; no loopback, IP or Activepieces host", badHosts.length === 0, badHosts.slice(0, 5).join(","));
  assert("seeds: every seed says it is unverified and assumed, in its steps and its first note", noNote.length === 0, noNote.slice(0, 5).join(","));
  assert("seeds: no secret-shaped string and no secret-named URL parameter in any seed", secretHits.length === 0 && badUrls.length === 0, `scanned ${scanned} strings; ${secretHits.concat(badUrls).slice(0, 4).join(",")}`);
  assert("seeds: no em or en dash in any seed file or the manifest", dashHits.length === 0 && !/[\u2013\u2014]/.test(JSON.stringify(manifest)), dashHits.slice(0, 5).join(","));

  const byMode = {};
  const provByMode = {};
  for (const def of seedDefs.values()) {
    const modes = new Set();
    for (const a of def.auth) {
      byMode[a.mode] = (byMode[a.mode] ?? 0) + 1;
      modes.add(a.mode);
    }
    for (const m of modes) provByMode[m] = (provByMode[m] ?? 0) + 1;
  }
  const sorted = (o) => JSON.stringify(Object.fromEntries(Object.entries(o).sort(([a], [b]) => (a < b ? -1 : 1))));
  assert("seeds: the counts by auth mode recomputed from the files equal the extractor's manifest", sorted(byMode) === JSON.stringify(manifest.auth_definitions_by_mode) && sorted(provByMode) === JSON.stringify(manifest.providers_by_mode), `${sorted(byMode)}`);
  assert("seeds: the manifest's totals add up (auth definitions, seeds, skipped pieces)", Object.values(byMode).reduce((a, b) => a + b, 0) === manifest.auth_definitions && manifest.seeds + manifest.skipped_pieces.total === manifest.pieces_scanned && manifest.skipped_pieces.pieces.length === manifest.skipped_pieces.total, `${manifest.pieces_scanned} pieces: ${manifest.seeds} seeds, ${manifest.skipped_pieces.total} skipped`);
  note(`auth definitions by mode (computed by this script from the committed files): ${sorted(byMode)}`);
  note(`providers by mode: ${sorted(provByMode)}; ${manifest.providers_that_can_start_connect} can start Connect in this build; skipped pieces ${JSON.stringify(manifest.skipped_pieces.reasons)}`);

  const notice = readFileSync(join(ROOT, "NOTICE"), "utf8");
  assert("NOTICE carries the Activepieces MIT copyright notice and the full permission text", notice.includes(manifest.source.copyright) && /Permission is hereby granted, free of charge/.test(notice) && /THE SOFTWARE IS PROVIDED "AS IS"/.test(notice) && notice.includes(manifest.source.commit) && !/[\u2013\u2014]/.test(notice), manifest.source.copyright);
  const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
  assert("package.json ships NOTICE and registers the oracle in the verify chain", pkg.files.includes("NOTICE") && pkg.scripts["verify:connectors-seed"] && /npm run verify:connectors-seed/.test(pkg.scripts.verify));
  assert("the extractor's source license gate: MIT root license and packages/pieces/community outside packages/ee, recorded in the manifest", manifest.source.license === "MIT" && manifest.source.community_outside_ee === true && manifest.source.commit.length === 40);
}

// the build copied the seeds next to the code
assert("build: the seeds and the manifest are copied to dist/connectors/providers/seed", existsSync(join(ROOT, "dist", "connectors", "providers", "seed", "_manifest.json")) && readdirSync(join(ROOT, "dist", "connectors", "providers", "seed")).filter((f) => !f.startsWith("_")).length === seedFiles.length);

// ═════════════════════════════════════════════════════════════════════════════════════════════════════
// 2. curated wins, bad seeds, owner definitions
// ═════════════════════════════════════════════════════════════════════════════════════════════════════
const CURATED = ["buffer", "elevenlabs", "github", "google", "higgsfield", "linear", "linkedin", "meta-facebook", "meta-instagram", "notion", "slack", "tiktok", "x"];
{
  const reg = ProviderRegistry.load({ home: mkdtempSync(join(WORK, "h-")) });
  assert("registry: no issue loading the 13 curated definitions beside the seeds", reg.issues.length === 0 && reg.list().length === 13 && CURATED.every((s) => reg.get(s) && !reg.isSeed(s)), reg.issues.map((i) => i.problems[0]).join("|"));
  assert("registry: list() is curated only (nothing that enumerates providers changed), in load order", JSON.stringify(reg.list().map((p) => p.slug)) === JSON.stringify(CURATED) && reg.list().every((p) => p.source === undefined && p.verification === undefined));
  const seeds = reg.listSeeds();
  const shadowed = reg.shadowedSeeds();
  assert("registry: every seed file loads or is shadowed, none is refused", reg.seedIssues.length === 0 && seeds.length + shadowed.length === seedFiles.length, `${seeds.length} usable, ${shadowed.length} shadowed, ${reg.seedIssues.length} refused`);
  const curatedToolkits = new Set(reg.list().flatMap((p) => p.toolkits ?? [p.slug]));
  const collisions = [...seedDefs.keys()].filter((s) => curatedToolkits.has(s));
  assert("curated wins: every seed that collides with a curated slug or toolkit is shadowed, and nothing else is", JSON.stringify(shadowed.map((s) => s.slug).sort()) === JSON.stringify(collisions.sort()) && collisions.length >= 5, collisions.join(","));
  assert("curated wins: get() on a shadowed slug returns the CURATED definition (slack, github, notion, linear, linkedin, buffer)", ["slack", "github", "notion", "linear", "linkedin", "buffer"].every((s) => reg.get(s)?.verification === undefined && reg.isBundled(s) && !reg.isSeed(s)));
  assert("curated wins: a shadowed toolkit name (gmail, youtube) resolves to its curated provider, never to the seed", reg.providerForToolkit("gmail")?.slug === "google" && reg.providerForToolkit("youtube")?.slug === "google" && reg.get("gmail") === undefined && reg.get("youtube") === undefined);
  const all = reg.listAll();
  assert("registry: listAll() is the curated set then the seeds, with no duplicate slug", all.length === 13 + seeds.length && new Set(all.map((p) => p.slug)).size === all.length && all.slice(13).every((p) => reg.isSeed(p.slug)));
  assert("registry: a path-shaped or malformed slug resolves to nothing and throws nothing", ["../../etc/passwd", "A", "x/y", "x\\y", "", "a".repeat(80), "..", "hubspot.json"].every((s) => reg.get(s) === undefined));
  const hub = reg.get("hubspot");
  assert("registry: a seed resolves through get() and has() with its mark", hub?.verification === "unverified_seed" && reg.has("hubspot") && reg.isSeed("hubspot"));
  reg.useSeedDir(false);
  assert("registry: useSeedDir(false) turns seeds off", reg.get("hubspot") === undefined && reg.listSeeds().length === 0);
}
{
  // an owner definition for a seeded slug replaces the seed
  const home = mkdtempSync(join(WORK, "h-"));
  mkdirSync(join(home, "providers"), { recursive: true });
  const owner = clone(seedDefs.get("hubspot"));
  delete owner.source;
  delete owner.verification;
  owner.name = "HubSpot (mine)";
  writeFileSync(join(home, "providers", "hubspot.json"), JSON.stringify(owner));
  const claims = clone(seedDefs.get("airtable"));
  claims.slug = "claims-seed";
  writeFileSync(join(home, "providers", "claims-seed.json"), JSON.stringify(claims));
  const reg = ProviderRegistry.load({ home });
  assert("owner: an owner's own definition for a seeded slug replaces the seed (curated wins)", reg.get("hubspot")?.name === "HubSpot (mine)" && !reg.isSeed("hubspot") && !reg.listSeeds().some((s) => s.slug === "hubspot") && reg.shadowedSeeds().some((s) => s.slug === "hubspot" && s.by === "hubspot"));
  assert("owner: a curated file that declares source and verification is refused (only a seed may)", reg.issues.some((i) => /claims-seed/.test(i.file) && /only a seed/.test(i.problems.join(" "))) && !reg.get("claims-seed"));
}
{
  // bad seeds are refused one by one; the good one beside them loads
  const dir = mkdtempSync(join(WORK, "seeds-bad-"));
  const base = clone(seedDefs.get("airtable"));
  const put = (name, mutate, slug = name) => {
    const d = clone(base);
    d.slug = slug;
    mutate?.(d);
    writeFileSync(join(dir, `${name}.json`), JSON.stringify(d));
  };
  put("good-seed", null);
  put("with-probe", (d) => (d.identity_probe = { method: "GET", url: `https://${d.api_hosts[0].replace(/^\*\./, "x.")}/me`, id_path: "id" }));
  put("with-toolkits", (d) => (d.toolkits = ["with-toolkits"]));
  put("broad-wild", (d) => (d.api_hosts = ["*.com"]));
  put("no-mark", (d) => delete d.verification);
  put("mismatch", null, "other-slug");
  writeFileSync(join(dir, "bad-json.json"), "{ not json");
  writeFileSync(join(dir, "_manifest.json"), "{}");
  writeFileSync(join(dir, "Not_A_Slug.json"), "{}");
  const reg = ProviderRegistry.load({ home: mkdtempSync(join(WORK, "h-")), seedDir: dir });
  const slugs = reg.listSeeds().map((s) => s.slug);
  const why = (name) => reg.seedIssues.find((i) => i.file.endsWith(`${name}.json`))?.problems.join(" ") ?? "";
  assert("bad seeds: only the good seed loads; the manifest and a non-slug file name are not seeds", JSON.stringify(slugs) === JSON.stringify(["good-seed"]), slugs.join(","));
  assert("bad seeds: a seed with an identity probe is refused", /identity probe/.test(why("with-probe")), why("with-probe"));
  assert("bad seeds: a seed that declares toolkits is refused", /toolkits/.test(why("with-toolkits")), why("with-toolkits"));
  assert("bad seeds: a seed with a wildcard host broader than two labels is refused", /too broad/.test(why("broad-wild")), why("broad-wild"));
  assert("bad seeds: a seed without the unverified_seed mark is refused", /verification/.test(why("no-mark")), why("no-mark"));
  assert("bad seeds: a file whose name does not match its slug is refused", /file name must be/.test(why("mismatch")), why("mismatch"));
  assert("bad seeds: invalid JSON is reported, not fatal", /not valid JSON/.test(why("bad-json")), why("bad-json"));
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════
// the mock authorization + API server, and the seeds derived to point at it
// ═════════════════════════════════════════════════════════════════════════════════════════════════════
const mock = { port: 0, base: "", log: [], codes: new Map(), cc: 0 };
const VARIANTS = {};
const mockServer = createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  const parts = url.pathname.split("/").filter(Boolean);
  const [slug, what] = parts;
  const v = VARIANTS[slug];
  const send = (status, body, headers = {}) => {
    res.writeHead(status, { "content-type": "application/json", ...headers });
    res.end(typeof body === "string" ? body : JSON.stringify(body));
  };
  if (slug === "me") {
    const auth = String(req.headers.authorization ?? "");
    if (auth === `Bearer ${TOK_MOCKG}`) return send(200, { id: "mockg-user-1", name: "Mock G" });
    return send(401, { error: "unauthorized" });
  }
  if (!v) return send(404, { error: "no such variant" });
  if (what === "authorize") {
    const q = url.searchParams;
    const problems = [];
    if (q.get("response_type") !== "code") problems.push("response_type");
    if (q.get(v.clientIdParam) !== CLIENT_ID) problems.push("client id");
    if (!q.get("state")) problems.push("state");
    if (!q.get("redirect_uri")) problems.push("redirect_uri");
    const want = v.scopes.length ? v.scopes.join(" ") : null;
    if (q.get("scope") !== want) problems.push(`scope ${q.get("scope")} != ${want}`);
    const challenge = q.get("code_challenge");
    if (v.pkce === "required" ? !challenge || q.get("code_challenge_method") !== "S256" : challenge !== null) problems.push("pkce");
    for (const [k, val] of Object.entries(v.extra)) if (q.get(k) !== val) problems.push(`extra ${k}`);
    v.lastAuthorize = Object.fromEntries(q);
    if (problems.length) return send(400, { error: "invalid_request", problems });
    const code = mint(`code-${slug}`);
    mock.codes.set(code, { redirect: q.get("redirect_uri"), challenge, used: false });
    const loc = `${q.get("redirect_uri")}${q.get("redirect_uri").includes("?") ? "&" : "?"}code=${encodeURIComponent(code)}&state=${encodeURIComponent(q.get("state"))}`;
    res.writeHead(302, { location: loc });
    return res.end();
  }
  if (what === "token" && req.method === "POST") {
    const params = new URLSearchParams(await readBody(req));
    const authz = req.headers.authorization;
    let cid;
    let csec;
    if (v.clientAuth === "basic") {
      if (!authz?.startsWith("Basic ")) return send(400, { error: "invalid_client", error_description: "Basic expected" });
      [cid, csec] = Buffer.from(authz.slice(6), "base64").toString("utf8").split(":");
    } else {
      if (authz) return send(400, { error: "invalid_request", error_description: "no Authorization header expected" });
      cid = params.get(v.clientIdParam);
      csec = params.get("client_secret") ?? undefined;
    }
    v.lastToken = { grant: params.get("grant_type"), basic: v.clientAuth === "basic" ? Boolean(authz) : false, hasVerifier: Boolean(params.get("code_verifier")), body: Object.fromEntries(params) };
    if (cid !== CLIENT_ID || csec !== CLIENT_SECRET) return send(400, { error: "invalid_client", error_description: "bad client credentials" });
    const out = { access_token: mint(`at-${slug}`), token_type: "Bearer", expires_in: 3600 };
    if (params.get("grant_type") === "client_credentials") {
      mock.cc++;
      return send(200, { ...out, ...(v.scopes.length ? { scope: v.scopes.join(" ") } : {}) });
    }
    const rec = mock.codes.get(params.get("code") ?? "");
    if (!rec || rec.used) return send(400, { error: "invalid_grant", error_description: "unknown or used code" });
    rec.used = true;
    if (params.get("redirect_uri") !== rec.redirect) return send(400, { error: "invalid_grant", error_description: "redirect_uri mismatch" });
    if (rec.challenge) {
      const verifier = params.get("code_verifier") ?? "";
      if (Buffer.from(createHash("sha256").update(verifier).digest()).toString("base64url") !== rec.challenge) return send(400, { error: "invalid_grant", error_description: "PKCE mismatch" });
    }
    return send(200, { ...out, refresh_token: mint(`rt-${slug}`), ...(v.scopes.length ? { scope: v.scopes.join(" ") } : {}) });
  }
  return send(404, { error: "not found" });
});
mock.port = await freeListen(mockServer);
mock.base = `http://127.0.0.1:${mock.port}`;

// derive five mock seeds from real committed ones: every field of the real definition is kept except the hosts
const pickSeed = (pred) => [...seedDefs.values()].find((d) => !CURATED.includes(d.slug) && !["gmail", "youtube"].includes(d.slug) && pred(d));
const oauthOf = (d, mode = "oauth2") => d.auth.find((a) => a.mode === mode)?.oauth2;
const picks = {
  plain: pickSeed((d) => d.auth[0].mode === "oauth2" && oauthOf(d).pkce === "unsupported" && oauthOf(d).client_auth === "body" && oauthOf(d).default_scopes.length > 0 && !oauthOf(d).extra_auth_params),
  pkce: pickSeed((d) => d.auth[0].mode === "oauth2" && oauthOf(d).pkce === "required" && oauthOf(d).client_auth === "body"),
  basic: pickSeed((d) => d.auth[0].mode === "oauth2" && oauthOf(d).client_auth === "basic" && oauthOf(d).default_scopes.length > 0),
  extra: pickSeed((d) => d.auth[0].mode === "oauth2" && oauthOf(d).extra_auth_params && Object.keys(oauthOf(d).extra_auth_params).length > 0 && oauthOf(d).client_auth === "body"),
  cc: pickSeed((d) => d.auth.some((a) => a.mode === "oauth2_cc")),
};
const MOCK_SEEDS = mkdtempSync(join(WORK, "seeds-mock-"));
assert("mock: the committed seeds include each shape this oracle drives (plain, PKCE required, Basic, extra params, client credentials)", Object.values(picks).every(Boolean), Object.entries(picks).map(([k, v]) => `${k}=${v?.slug}`).join(" "));
for (const [kind, real] of Object.entries(picks)) {
  const d = clone(real);
  for (const a of d.auth) {
    if (!a.oauth2) continue;
    a.oauth2.token_url = `${mock.base}/${d.slug}/token`;
    if (a.oauth2.authorize_url) a.oauth2.authorize_url = `${mock.base}/${d.slug}/authorize`;
    delete a.oauth2.revoke;
  }
  d.api_hosts = ["127.0.0.1"];
  writeFileSync(join(MOCK_SEEDS, `${d.slug}.json`), JSON.stringify(d));
  const main = kind === "cc" ? d.auth.find((a) => a.mode === "oauth2_cc") : d.auth.find((a) => a.mode === "oauth2");
  VARIANTS[d.slug] = { kind, authId: main.id, pkce: main.oauth2.pkce, clientAuth: main.oauth2.client_auth, scopes: main.oauth2.default_scopes, extra: main.oauth2.extra_auth_params ?? {}, clientIdParam: main.oauth2.client_id_param ?? "client_id" };
}
// real copies used by the admin API section: an API key seed, a custom-only seed, a seed a curated provider shadows
const KEY_SEED = seedDefs.get("airtable") && seedDefs.get("airtable").auth.some((a) => a.mode === "api_key") ? "airtable" : [...seedDefs.values()].find((d) => d.auth[0].mode === "api_key" && !CURATED.includes(d.slug)).slug;
const CUSTOM_SEED = [...seedDefs.values()].find((d) => d.auth.every((a) => a.mode === "custom") && !CURATED.includes(d.slug))?.slug;
const SHADOWED_SEED = "slack";
for (const s of [KEY_SEED, CUSTOM_SEED, SHADOWED_SEED]) cpSync(join(SEED_DIR, `${s}.json`), join(MOCK_SEEDS, `${s}.json`));

// ═════════════════════════════════════════════════════════════════════════════════════════════════════
// 3. a seeded OAuth provider starts and completes a connect flow against the mock
// ═════════════════════════════════════════════════════════════════════════════════════════════════════
const vault = new Vault("encrypted-file");
vault.set("seed_client_id", CLIENT_ID);
vault.set("seed_client_secret", CLIENT_SECRET);
const HOME3 = mkdtempSync(join(WORK, "home3-"));
const CB = "http://127.0.0.1:1/oauth/callback"; // never fetched: only the Location header is read
const rt3 = new Connectors({ vault, network: NETWORK, home: HOME3, seedProviderDir: MOCK_SEEDS });
const accounts3 = {};
for (const [slug, v] of Object.entries(VARIANTS)) {
  const label = `${v.kind}`;
  assert(`connect (${v.kind}): the derived seed ${slug} resolves as a seed, with the real definition's flow settings`, rt3.providers.isSeed(slug) && rt3.providers.get(slug).verification === "unverified_seed", `pkce=${v.pkce} client_auth=${v.clientAuth} scopes=${v.scopes.length} extra=${Object.keys(v.extra).length}`);
  const cfg = rt3.authConfigs.add({ provider: slug, auth_id: v.authId, client_id_ref: "seed_client_id", client_secret_ref: "seed_client_secret" });
  if (v.kind === "cc") {
    const r = await rt3.flows.connectClientCredentials({ provider: slug, authId: v.authId, label });
    accounts3[v.kind] = r.account;
    assert("connect (cc): a seeded client-credentials provider connects: the grant used the client credentials the way the definition says", r.account.status === "ACTIVE" && v.lastToken?.grant === "client_credentials" && mock.cc === 1, `grant=${v.lastToken?.grant}`);
  } else {
    const begin = rt3.flows.begin({ provider: slug, authId: v.authId, authConfigId: cfg.id, label, redirectUri: CB });
    const au = new URL(begin.authorizeUrl);
    assert(`connect (${v.kind}): the consent URL is built from the seed (host, client id, scope separator, PKCE per the definition, extra params)`, au.origin === mock.base && au.searchParams.get(v.clientIdParam) === CLIENT_ID && (v.scopes.length ? au.searchParams.get("scope") === v.scopes.join(" ") : !au.searchParams.has("scope")) && (v.pkce === "required") === au.searchParams.has("code_challenge") && Object.entries(v.extra).every(([k, val]) => au.searchParams.get(k) === val), `${v.scopes.length} scopes, pkce ${v.pkce}`);
    const r1 = await fetch(begin.authorizeUrl, { redirect: "manual" });
    const loc = r1.status === 302 ? new URL(r1.headers.get("location")) : undefined;
    assert(`connect (${v.kind}): the mock accepted the authorize request (every parameter checked) and redirected with a code`, r1.status === 302 && loc?.searchParams.get("code") && loc.searchParams.get("state") === begin.state, `status ${r1.status} ${r1.status === 400 ? await r1.text() : ""}`);
    const done = await rt3.flows.complete(loc.searchParams.get("state"), loc.searchParams.get("code"));
    accounts3[v.kind] = done.account;
    assert(`connect (${v.kind}): the code exchange used the definition's client authentication and PKCE, and the account is ACTIVE`, done.account.status === "ACTIVE" && v.lastToken?.grant === "authorization_code" && v.lastToken.hasVerifier === (v.pkce === "required") && (v.clientAuth !== "basic" || v.lastToken.basic === true), `basic=${v.lastToken?.basic} verifier=${v.lastToken?.hasVerifier}`);
  }
  const a = accounts3[v.kind];
  assert(`connect (${v.kind}): the stored account is stamped unverified_seed, was not probed, has no identity and no token in its summary`, a.provider_verification === "unverified_seed" && a.last_probe_at === undefined && a.identity.external_id === "unknown" && !("token" in summarize(a)) && summarize(a).has_token === true, `identity ${a.identity.external_id}`);
}
{
  const first = Object.keys(VARIANTS)[0];
  const again = rt3.accounts.list({ provider: first });
  assert("connect: a seeded account is findable through the store like any other (list, default)", again.length === 1 && rt3.accounts.defaultFor(first)?.id === again[0].id);
  const tokenFile = readFileSync(join(HOME3, "connectors", "accounts.json"), "utf8");
  assert("connect: the account file holds no token in the clear (sealed with the vault key)", ![...SECRETS].some((s) => /^(at|rt)-/.test(s.split("_CNRY")[0]) && tokenFile.includes(s)));
}
// the real, un-rewritten seed: begin() builds a URL on the provider's real host and fetches nothing
{
  const real = pickSeed((d) => d.auth[0].mode === "oauth2" && oauthOf(d).default_scopes.length > 0);
  const homeR = mkdtempSync(join(WORK, "homeR-"));
  const rtR = new Connectors({ vault, network: NETWORK, home: homeR });
  assert("real seed: the bundled seed directory resolves in a default build", rtR.providers.isSeed(real.slug) && rtR.providers.listSeeds().length === seedFiles.length - rtR.providers.shadowedSeeds().length);
  rtR.authConfigs.add({ provider: real.slug, auth_id: real.auth[0].id, client_id_ref: "seed_client_id", client_secret_ref: "seed_client_secret" });
  const before = NONLOCAL.length;
  const b = rtR.flows.begin({ provider: real.slug, authId: real.auth[0].id, redirectUri: CB });
  const u = new URL(b.authorizeUrl);
  const o = oauthOf(real);
  assert(`real seed (${real.slug}): the consent URL points at the provider's own authorize host with the seed's scopes, nothing fetched`, u.host === new URL(o.authorize_url).host && u.pathname === new URL(o.authorize_url).pathname && u.searchParams.get("scope") === o.default_scopes.join(" ") && u.searchParams.get("client_id") === CLIENT_ID && NONLOCAL.length === before, u.host);
  rtR.flows.cancel(b.state);
  const none = await (async () => {
    try {
      rtR.flows.begin({ provider: real.slug, authId: real.auth[0].id, authConfigId: "ac_missing", redirectUri: CB });
      return "";
    } catch (e) {
      return e.message;
    }
  })();
  assert("real seed: an unknown auth config is refused with a message, nothing stored", /no auth config/.test(none) && rtR.flows.pending().length === 0, none);
  const noApp = (() => {
    try {
      const h2 = mkdtempSync(join(WORK, "homeN-"));
      new Connectors({ vault, network: NETWORK, home: h2 }).flows.begin({ provider: real.slug, redirectUri: CB });
      return "";
    } catch (e) {
      return `${e.message} | needsApp=${e.detail?.needsApp}`;
    }
  })();
  assert("real seed: Connect with no registered app refuses and names the owner steps (needsApp)", /register your app first|OAuth client id/.test(noApp) && /needsApp=true/.test(noApp), noApp.slice(0, 120));
}

// the generated toolkit the dashboard and the coverage checks mount (a function declaration: hoisted, called after `mock` exists)
function mockkitDoc() {
  return {
    toolkit: "mockkit",
    provider: "mockg",
    version: "20260101_00",
    source: { kind: "openapi", url: `${mock.base}/spec`, fetched_at: "2026-01-01T00:00:00.000Z", spec_hash: "0" },
    base_url: mock.base,
    generated_count: 1,
    actions: [
      {
        slug: "whoami",
        title: "Who am I",
        description: "Return the account identity.",
        input_schema: { type: "object", properties: {}, additionalProperties: false },
        http: { method: "GET", base_url: mock.base, path: "/me", params: {}, body: "none", body_type: "json" },
        scopes: [],
        scope: "read",
        risk: "low",
        outward: false,
        idempotent: true,
        important: true,
        tags: [],
        deprecated: false,
        verification: "mapped",
      },
    ],
  };
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════
// 4. a seed never reports working
// ═════════════════════════════════════════════════════════════════════════════════════════════════════
// an owner (curated) provider with a probe and a toolkit, pointing at the mock: the contrast case
const mockg = {
  slug: "mockg",
  name: "Mock G",
  toolkits: ["mockkit"],
  categories: ["test"],
  api_hosts: ["127.0.0.1"],
  docs_url: "https://example.test/mockg",
  owner_setup: { console_url: "https://example.test/console", steps: ["Create a token in the mock console"], redirect_uris: [], notes: ["a curated provider for the oracle"] },
  identity_probe: { method: "GET", url: `${mock.base}/me`, id_path: "id", name_path: "name" },
  auth: [
    {
      id: "token",
      mode: "bearer",
      default: true,
      inject: { in: "header", name: "Authorization", template: "Bearer {token}" },
      fields: { auth_config_creation: [], connected_account_initiation: [{ name: "token", required: true, secret: true }] },
    },
  ],
};
mkdirSync(join(HOME3, "providers"), { recursive: true });
writeFileSync(join(HOME3, "providers", "mockg.json"), JSON.stringify(mockg));
const rt4 = new Connectors({ vault, network: NETWORK, home: HOME3, seedProviderDir: MOCK_SEEDS });
const kit4 = rt4.kit;
kit4.toolkits.writeGenerated(mockkitDoc());
const curatedAcct = (await rt4.flows.connectSecret({ provider: "mockg", label: "owner", fields: { token: TOK_MOCKG } })).account;
assert("coverage: a curated account connects and passes its identity probe (the contrast case)", curatedAcct.status === "ACTIVE" && curatedAcct.provider_verification === undefined && Boolean(curatedAcct.last_probe_at) && curatedAcct.identity.external_id === "mockg-user-1");
const SEED_ROW = `${KEY_SEED.toUpperCase().replace(/-/g, "_")}_LIST_ROWS`;
const csvDir = mkdtempSync(join(WORK, "csv-"));
const hdr = "toolkit,action_slug,http_method,endpoint,basis,notes\n";
writeFileSync(join(csvDir, "mockkit.csv"), `${hdr}mockkit,MOCKKIT_WHOAMI,GET,/me,A,\nmockkit,MOCKKIT_OTHER,GET,/other,A,\n`);
writeFileSync(join(csvDir, `${KEY_SEED}.csv`), `${hdr}${KEY_SEED},${SEED_ROW},GET,/v0/rows,A,\n`);
const imp = kit4.coverage.importCsv(csvDir);
assert("coverage: the fixture checklist imports (3 rows, one toolkit named like a seed)", imp.rows === 3 && imp.problems.length === 0, JSON.stringify(imp.problems));
const live = kit4.coverage.mark("MOCKKIT_WHOAMI", "live_verified", { account: curatedAcct.id });
assert("coverage: a live_verified mark through a CURATED account counts", live.state === "live_verified" && kit4.coverage.report().total.working === 1);
const keyAuth = seedDefs.get(KEY_SEED).auth.find((a) => a.mode === "api_key");
const keyField = keyAuth.fields.connected_account_initiation[0].name;
const keyAcct = (await rt4.flows.connectSecret({ provider: KEY_SEED, authId: keyAuth.id, label: "seeded", fields: { [keyField]: mint("seeded-key") } })).account;
assert("never working: a seeded provider connects with a pasted key; the account is stamped unverified_seed and not probed", keyAcct.provider_verification === "unverified_seed" && keyAcct.last_probe_at === undefined && keyAcct.status === "ACTIVE", `${keyAcct.provider} ${keyAcct.provider_verification}`);
let refused = "";
try {
  kit4.coverage.mark(SEED_ROW, "live_verified", { account: keyAcct.id });
} catch (e) {
  refused = e.message;
}
assert("never working: coverage refuses a live_verified mark stamped with an account of a seeded provider", /seeded provider/.test(refused) && kit4.coverage.report().total.working === 1, refused.slice(0, 100));
appendFileSync(join(HOME3, "connectors", "verification.ndjson"), `${JSON.stringify({ ts: new Date().toISOString(), id: SEED_ROW, toolkit: KEY_SEED, state: "live_verified", account: keyAcct.id })}\n`);
const rep = kit4.coverage.report();
assert("never working: a hand-written ledger line naming a seed account is ignored when counting (still 1 working row) and reported as ignored", rep.total.working === 1 && rep.ignored_lines.includes(SEED_ROW), `working ${rep.total.working}, ignored ${rep.ignored_lines.join(",")}`);
kit4.coverage.mark(SEED_ROW, "live_verified", { account: curatedAcct.id });
assert("never working: even a row of a checklist toolkit named like a seed that IS proven live by a curated account counts only in the global total (2 of 3)", kit4.coverage.report().total.working === 2 && kit4.coverage.report().total.addressable === 3);
{
  const host = { config: () => ({ servers: [] }), configPath: () => undefined, mount: async () => {}, unmount: async () => {}, redirectUri: () => CB };
  const admin = new ConnectorAdmin(rt4, host);
  const sd = admin.listProviders({ q: KEY_SEED }).providers.find((p) => p.slug === KEY_SEED);
  assert("never working: the provider list says unverified_seed with zero working rows for the seed, although a live row of the same-named checklist toolkit exists", sd?.coverage.state === "unverified_seed" && sd.coverage.working_rows === 0 && sd.verification === "unverified_seed" && sd.source === "seed", JSON.stringify(sd?.coverage));
  const mg = admin.listProviders({ q: "mock" }).providers.find((p) => p.slug === "mockg");
  assert("never working: the curated provider's own live row counts (1 of 2 rows) and nothing is called working beyond that", mg?.coverage.working_rows === 1 && mg.coverage.addressable_rows === 2 && mg.coverage.state === "some_live" && mg.verification === "curated", JSON.stringify(mg?.coverage));
  const acc = admin.accounts({ provider: KEY_SEED });
  assert("never working: a seeded account is listed as a seed, never working, with no probe available", acc.length === 1 && acc[0].source_kind === "seed" && acc[0].working === false && acc[0].probe_available === false && acc[0].provider_verification === "unverified_seed");
  const pr = await admin.probe(keyAcct.id);
  const after = rt4.accounts.find(keyAcct.id);
  assert("never working: probing a seeded account says it cannot be probed and changes nothing (no last_probe_at stamped)", pr.ok === false && /no identity probe/.test(pr.error ?? "") && after.last_probe_at === undefined && !after.last_error, pr.error?.slice(0, 80));
  const cov = admin.coverage();
  assert("never working: the coverage answer counts only rows proven live by a curated account and says seeds cannot be working", cov.imported === true && cov.working === 2 && cov.addressable === 3 && /seeded provider can never be working/.test(String(cov.note)));
  const { toolkitEnableProblem } = await mod("connectors/admin.js");
  const enableProblem = toolkitEnableProblem(rt4, KEY_SEED);
  assert("never working: a seed has no toolkit to enable (nothing to mount)", /not defined here/.test(enableProblem ?? ""), enableProblem);
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════
// 5. the admin API through the real dashboard
// ═════════════════════════════════════════════════════════════════════════════════════════════════════
const dport = await (async () => {
  const s = createServer();
  const p = await freeListen(s);
  await closeServer(s);
  return p;
})();
mkdirSync(join(HOME, "providers"), { recursive: true });
writeFileSync(join(HOME, "providers", "mockg.json"), JSON.stringify(mockg));
const dcfg = { gateway: { transport: ["http"], http: { host: "127.0.0.1", port: dport, require_auth: "auto" }, tool_exposure: "namespaced", default_policy: "read" }, vault: { backend: "encrypted-file" }, servers: [], settings: { network: NETWORK } };
const gw = new Gateway(dcfg);
const gconn = gw.oauth.connectors;
gconn.providers.useSeedDir(MOCK_SEEDS);
gconn.kit.toolkits.writeGenerated(mockkitDoc());
const dash = await startDashboard(gw, dcfg);
const RESPONSES = [];
let cookie = "";
let csrf = "";
const dapi = async (method, path, body, opt = {}) => {
  const headers = { "content-type": "application/json" };
  if (opt.session !== false && cookie) headers.cookie = cookie;
  if (opt.csrf !== false && csrf && method !== "GET") headers["X-Switchboard-CSRF"] = csrf;
  const r = await fetch(`http://127.0.0.1:${dport}${path}`, { method, headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }), redirect: "manual" });
  const text = await r.text();
  RESPONSES.push(text);
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = undefined;
  }
  return { status: r.status, json, text, headers: r.headers };
};
try {
  // owner gate
  const noSession = await dapi("GET", "/api/connectors/providers", undefined, { session: false });
  assert("api: no owner session, no admin API (401) on the listing", noSession.status === 401 && noSession.json?.code === "SB_OWNER_SESSION_REQUIRED");
  const code = new LoginCodeStore().mint();
  const login = await dapi("POST", "/api/session", { code }, { session: false, csrf: false });
  cookie = (login.headers.getSetCookie?.() ?? []).map((c) => c.split(";")[0]).join("; ");
  csrf = login.json?.csrf ?? "";
  assert("api: the owner session is established from a one-time login code", login.status === 200 && cookie.length > 10 && csrf.length > 10);
  const getRoutes = ["/api/connectors/providers", "/api/connectors/providers/hubspot", "/api/connectors/accounts", "/api/connectors/toolkits", "/api/connectors/coverage"];
  const postRoutes = ["/api/connectors/providers/hubspot/connect", "/api/connectors/accounts/ca_abcdefgh12/probe", "/api/connectors/toolkits/mockkit/enable", "/api/connectors/toolkits/mockkit/disable"];
  const noSess = await Promise.all([...getRoutes.map((p) => dapi("GET", p, undefined, { session: false })), ...postRoutes.map((p) => dapi("POST", p, {}, { session: false }))]);
  assert("api: every connectors route refuses a request with no owner session (401)", noSess.every((r) => r.status === 401), noSess.map((r) => r.status).join(","));
  const noCsrf = await Promise.all(postRoutes.map((p) => dapi("POST", p, {}, { csrf: false })));
  assert("api: every connectors mutation refuses a request with a session but no CSRF header (403)", noCsrf.every((r) => r.status === 403 && r.json?.code === "SB_CSRF"), noCsrf.map((r) => r.status).join(","));
  const badCsrf = await dapi("POST", "/api/connectors/providers/hubspot/connect", {}, { csrf: false });
  assert("api: a connect with no CSRF header starts nothing", badCsrf.status === 403 && gconn.flows.pending().length === 0);

  // listing, search, filters, paging
  const list = await dapi("GET", "/api/connectors/providers");
  const L = list.json;
  assert("api: the listing returns curated and seeded providers with facets, source and verification on every row", list.status === 200 && L.providers.length > 0 && L.providers.every((p) => ["curated", "seed"].includes(p.source) && ["curated", "unverified_seed"].includes(p.verification) && Array.isArray(p.auth) && p.auth.every((a) => typeof a.connectable === "boolean") && Array.isArray(p.toolkits) && p.coverage && typeof p.accounts === "number"), `${L.total} providers`);
  assert("api: curated providers come first, then seeds; a seed shadowed by a curated slug (slack) is counted as hidden, never listed twice", L.providers.findIndex((p) => p.source === "seed") > L.providers.findLastIndex((p) => p.source === "curated") && L.providers.filter((p) => p.slug === "slack").length === 1 && L.providers.find((p) => p.slug === "slack").source === "curated" && L.shadowed_seeds >= 1, `shadowed ${L.shadowed_seeds}`);
  const q1 = await dapi("GET", `/api/connectors/providers?q=${encodeURIComponent(picks.plain.name.split(" ")[0])}`);
  assert("api: search by name finds the provider", q1.json.providers.some((p) => p.slug === picks.plain.slug), `${q1.json.total} hits`);
  const q2 = await dapi("GET", "/api/connectors/providers?q=gmail");
  assert("api: search by toolkit name finds the curated provider that owns the toolkit (google owns gmail)", q2.json.providers.some((p) => p.slug === "google" && p.toolkits.some((t) => t.slug === "gmail")));
  const q3 = await dapi("GET", "/api/connectors/providers?q=zzzz-no-such-provider-zzzz");
  assert("api: a search with no match returns an empty page, not an error", q3.status === 200 && q3.json.total === 0 && q3.json.providers.length === 0);
  const fs1 = await dapi("GET", "/api/connectors/providers?source=seed");
  const fc1 = await dapi("GET", "/api/connectors/providers?source=curated");
  assert("api: the source filter separates seeds from curated providers", fs1.json.providers.length > 0 && fs1.json.providers.every((p) => p.source === "seed") && fc1.json.providers.length >= 1 && fc1.json.providers.every((p) => p.source === "curated"));
  const fa = await dapi("GET", "/api/connectors/providers?auth=oauth2_cc");
  assert("api: the auth-mode filter keeps only providers with that mode", fa.json.providers.length >= 1 && fa.json.providers.every((p) => p.auth.some((a) => a.mode === "oauth2_cc")));
  const fcn = await dapi("GET", "/api/connectors/providers?connectable=1");
  assert("api: connectable=1 drops providers whose every mode this build does not drive", fcn.json.providers.every((p) => p.auth.some((a) => a.connectable)) && (!CUSTOM_SEED || !fcn.json.providers.some((p) => p.slug === CUSTOM_SEED)));
  const p1 = await dapi("GET", "/api/connectors/providers?limit=3&offset=0");
  const p2 = await dapi("GET", "/api/connectors/providers?limit=3&offset=3");
  assert("api: paging returns disjoint pages and the same total", p1.json.providers.length === 3 && p2.json.providers.length === 3 && p1.json.total === p2.json.total && !p1.json.providers.some((a) => p2.json.providers.some((b) => b.slug === a.slug)));
  const big = await dapi("GET", "/api/connectors/providers?limit=100000&offset=-5");
  const junk = await dapi("GET", "/api/connectors/providers?limit=abc&offset=%00&q=" + "x".repeat(3000));
  const huge = await dapi("GET", "/api/connectors/providers?q=" + "x".repeat(5000));
  assert("api: limit is clamped to 200, a bad offset or limit is ignored, a long query is cut and a URL over the 4096 guard is refused by the shared 414 check, nothing throws", big.status === 200 && big.json.limit <= 200 && big.json.offset === 0 && junk.status === 200 && junk.json.limit === 60 && junk.json.offset === 0 && huge.status === 414, `big ${big.status} limit ${big.json?.limit} offset ${big.json?.offset}; junk ${junk.status} limit ${junk.json?.limit}; huge ${huge.status}`);

  // detail and the owner steps
  const det = await dapi("GET", `/api/connectors/providers/${picks.plain.slug}`);
  const D = det.json;
  assert("api: the detail of a seed carries the owner steps with the dashboard's loopback callback filled in, the assumptions and the source link", det.status === 200 && D.connect === "needs_app" && D.needs_app === true && D.owner_setup.steps.length >= 3 && D.owner_setup.redirect_uris.every((u) => u === `http://127.0.0.1:${dport}/oauth/callback`) && D.owner_setup.commands.some((c) => c.startsWith("switchboard authconfig add")) && /ASSUMED/.test(D.owner_setup.notes.join(" ")) && /^https:\/\/github\.com\/activepieces\//.test(D.docs_url), D.owner_setup.redirect_uris.join(","));
  assert("api: the detail names the authentication modes, which are driven, and the accounts (none yet)", D.auth_detail.length >= 1 && D.auth_detail.every((a) => typeof a.connectable === "boolean") && D.accounts_detail.length === 0 && D.coverage.state === "unverified_seed");
  const d404 = await dapi("GET", "/api/connectors/providers/no-such-provider");
  const dbad = await dapi("GET", "/api/connectors/providers/..%2F..%2Fetc");
  const dbad2 = await dapi("GET", "/api/connectors/providers/UPPER");
  assert("api: an unknown provider is 404; a path-shaped or malformed slug is 400 or 404 and never reads a file", d404.status === 404 && [400, 404].includes(dbad.status) && dbad2.status === 400);

  // connect: no app registered -> the steps, nothing started
  const c0 = await dapi("POST", `/api/connectors/providers/${picks.plain.slug}/connect`, {});
  assert("api: Connect with no registered app answers needs_setup with the owner steps and starts nothing", c0.status === 200 && c0.json.status === "needs_setup" && c0.json.owner_setup.steps.length >= 3 && gconn.flows.pending().length === 0 && gconn.accounts.list({ provider: picks.plain.slug }).length === 0);
  const cBadLabel = await dapi("POST", `/api/connectors/providers/${picks.plain.slug}/connect`, { label: "bad label!" });
  const cBadScope = await dapi("POST", `/api/connectors/providers/${picks.plain.slug}/connect`, { scopes: ["ok", "bad scope"] });
  const cBadAuth = await dapi("POST", `/api/connectors/providers/${picks.plain.slug}/connect`, { auth_id: "nope" });
  assert("api: a bad label, a bad scope and an unknown authentication are 400 with a message", [cBadLabel, cBadScope, cBadAuth].every((r) => r.status === 400 && typeof r.json?.error === "string"), [cBadLabel, cBadScope, cBadAuth].map((r) => r.status).join(","));
  const cUnknown = await dapi("POST", "/api/connectors/providers/no-such-provider/connect", {});
  assert("api: connecting an unknown provider is 404", cUnknown.status === 404);

  // connect: with a registered app -> consent URL, callback, account
  gconn.authConfigs.add({ provider: picks.plain.slug, auth_id: VARIANTS[picks.plain.slug].authId, client_id_ref: "seed_client_id", client_secret_ref: "seed_client_secret" });
  const c1 = await dapi("POST", `/api/connectors/providers/${picks.plain.slug}/connect`, { label: "dash" });
  assert("api: Connect with a registered app answers redirect with the consent URL (built from the seed)", c1.status === 200 && c1.json.status === "redirect" && new URL(c1.json.authorize_url).origin === mock.base && c1.json.expires_at > Date.now() && gconn.flows.pending().length === 1, c1.json.status);
  const hop = await fetch(c1.json.authorize_url, { redirect: "manual" });
  const cbUrl = hop.headers.get("location");
  assert("api: the mock redirects the browser back to the dashboard's loopback callback", hop.status === 302 && cbUrl.startsWith(`http://127.0.0.1:${dport}/oauth/callback?`), cbUrl?.slice(0, 60));
  const cb = await fetch(cbUrl, { redirect: "manual" });
  const cbText = await cb.text();
  RESPONSES.push(cbText);
  assert("api: the callback completes the flow and the page says connected", cb.status === 200 && /Connected/.test(cbText), `status ${cb.status}`);
  const accs = await dapi("GET", `/api/connectors/accounts?provider=${picks.plain.slug}`);
  const A = accs.json.accounts[0];
  assert("api: the new account is listed ACTIVE, labelled, a seed, never working, with no probe and no token field", accs.status === 200 && accs.json.accounts.length === 1 && A.label === "dash" && A.status === "ACTIVE" && A.source_kind === "seed" && A.working === false && A.probe_available === false && A.provider_verification === "unverified_seed" && !("token" in A) && A.has_token === true);
  const pb = await dapi("POST", `/api/connectors/accounts/${A.id}/probe`, {});
  assert("api: probing the seeded account answers that it cannot be probed, and the account is unchanged", pb.status === 200 && pb.json.ok === false && /no identity probe/.test(pb.json.error) && pb.json.account.last_probe_at === undefined);
  const pbBad = await dapi("POST", "/api/connectors/accounts/not-an-id/probe", {});
  const pb404 = await dapi("POST", "/api/connectors/accounts/ca_zzzzzzzzzz/probe", {});
  assert("api: a malformed account id is 400 and an unknown one 404", pbBad.status === 400 && pb404.status === 404);
  const detAfter = await dapi("GET", `/api/connectors/providers/${picks.plain.slug}`);
  assert("api: after connecting, the provider shows its account and still says unverified_seed with zero live rows", detAfter.json.accounts === 1 && detAfter.json.connected === true && detAfter.json.coverage.state === "unverified_seed" && detAfter.json.coverage.working_rows === 0 && detAfter.json.accounts_detail[0].id === A.id);

  // client credentials through the API (a seed with a client-credentials mode)
  const ccSlug = picks.cc.slug;
  gconn.authConfigs.add({ provider: ccSlug, auth_id: VARIANTS[ccSlug].authId, client_id_ref: "seed_client_id", client_secret_ref: "seed_client_secret" });
  const cc = await dapi("POST", `/api/connectors/providers/${ccSlug}/connect`, { auth_id: VARIANTS[ccSlug].authId, label: "svc" });
  assert("api: a client-credentials seed connects in one call and the account is stamped", cc.status === 200 && cc.json.status === "connected" && cc.json.account.provider_verification === "unverified_seed" && !("token" in cc.json.account), cc.json.status ?? cc.text.slice(0, 100));

  // a pasted key: needs_input, then connected; the value is never echoed
  const k0 = await dapi("POST", `/api/connectors/providers/${KEY_SEED}/connect`, {});
  const keyAuth = seedDefs.get(KEY_SEED).auth.find((a) => a.mode === "api_key");
  assert("api: a key provider asks for its field first (needs_input, secret flagged) and stores nothing", k0.status === 200 && k0.json.status === "needs_input" && k0.json.fields.some((f) => f.name === keyAuth.fields.connected_account_initiation[0].name && f.secret === true) && gconn.accounts.list({ provider: KEY_SEED }).length === 0);
  const kBadField = await dapi("POST", `/api/connectors/providers/${KEY_SEED}/connect`, { fields: { bogus: KEY_CANARY } });
  assert("api: an unknown field is 400 and the error does not echo the value", kBadField.status === 400 && !kBadField.text.includes(KEY_CANARY));
  const k1 = await dapi("POST", `/api/connectors/providers/${KEY_SEED}/connect`, { label: "pasted", fields: { [keyAuth.fields.connected_account_initiation[0].name]: KEY_CANARY } });
  assert("api: a pasted key connects; the answer carries the account but never the key", k1.status === 200 && k1.json.status === "connected" && k1.json.account.provider_verification === "unverified_seed" && !k1.text.includes(KEY_CANARY));
  const kList = await dapi("GET", "/api/connectors/accounts");
  assert("api: no account listing carries the key", !kList.text.includes(KEY_CANARY) && kList.json.accounts.some((a) => a.provider === KEY_SEED && a.source_kind === "seed"));
  // a custom-only seed is not driven
  if (CUSTOM_SEED) {
    const cu = await dapi("POST", `/api/connectors/providers/${CUSTOM_SEED}/connect`, { fields: { x: "y" } });
    assert("api: a seed whose only authentication is custom cannot Connect in this build (400, SB_AUTH_NOT_DRIVEN) and stores nothing", cu.status === 400 && cu.json.code === "SB_AUTH_NOT_DRIVEN" && gconn.accounts.list({ provider: CUSTOM_SEED }).length === 0, cu.json.code);
    const row = (await dapi("GET", `/api/connectors/providers?q=${CUSTOM_SEED}`)).json.providers.find((p) => p.slug === CUSTOM_SEED);
    assert("api: such a seed shows connect: unavailable in the listing", row?.connect === "unavailable" && row.auth.every((a) => a.connectable === false));
  }

  // toolkits: enable and disable, live
  const tk0 = await dapi("GET", "/api/connectors/toolkits");
  const mk0 = tk0.json.toolkits.find((t) => t.slug === "mockkit");
  assert("api: the toolkit table lists the defined toolkit with its state, version, tools and coverage (not ready: no account yet)", mk0 && mk0.defined === true && mk0.version === "20260101_00" && mk0.tools === 1 && mk0.state === "no_server" && mk0.ready === false && mk0.coverage.state === "none_live", JSON.stringify(mk0));
  const en0 = await dapi("POST", "/api/connectors/toolkits/mockkit/enable", {});
  assert("api: enabling a toolkit with no probed account is refused (409) with the fix command, and nothing is mounted", en0.status === 409 && /switchboard connect mockg/.test(en0.json.error) && !gw.registry.get("mockkit") && !dcfg.servers.some((s) => s.id === "mockkit"), en0.json?.error?.slice(0, 80));
  const gacct = (await gconn.flows.connectSecret({ provider: "mockg", label: "owner", fields: { token: TOK_MOCKG } })).account;
  assert("api: a curated account connects and passes its probe", gacct.status === "ACTIVE" && Boolean(gacct.last_probe_at));
  const en1 = await dapi("POST", "/api/connectors/toolkits/mockkit/enable", {});
  const mounted = gw.registry.get("mockkit");
  assert("api: enabling the toolkit mounts it live and records an enabled connector server in the config", en1.status === 200 && en1.json.state === "on" && Boolean(mounted) && mounted.tools.some((t) => t.name.endsWith("whoami")) && dcfg.servers.some((s) => s.id === "mockkit" && s.source === "connector" && s.toolkit === "mockkit" && s.enabled === true), `state ${en1.json.state}, tools ${mounted?.tools.map((t) => t.name).join(",")}`);
  const en2 = await dapi("POST", "/api/connectors/toolkits/nope-kit/enable", {});
  assert("api: an unknown toolkit is 404", en2.status === 404);
  const dis = await dapi("POST", "/api/connectors/toolkits/mockkit/disable", {});
  assert("api: disabling the toolkit unmounts it now; the server stays in the config, disabled", dis.status === 200 && dis.json.state === "off" && !gw.registry.get("mockkit") && dcfg.servers.some((s) => s.id === "mockkit" && s.enabled === false));
  const dis2 = await dapi("POST", "/api/connectors/toolkits/mockkit/disable", {});
  assert("api: disabling an already-off toolkit is harmless (still off)", dis2.status === 200 && dis2.json.state === "off");
  const dNever = await dapi("POST", "/api/connectors/toolkits/mockkit/enable", { account: "mockg/nobody" });
  assert("api: pinning the server to an account that does not exist is refused", dNever.status === 404 && !gw.registry.get("mockkit"), String(dNever.status));
  const en3 = await dapi("POST", "/api/connectors/toolkits/mockkit/enable", { account: "mockg/owner" });
  assert("api: enabling again with a real account pinned works and keeps one server entry", en3.status === 200 && en3.json.state === "on" && en3.json.account === "mockg/owner" && dcfg.servers.filter((s) => s.id === "mockkit").length === 1);
  await dapi("POST", "/api/connectors/toolkits/mockkit/disable", {});

  // coverage
  const cv0 = await dapi("GET", "/api/connectors/coverage");
  assert("api: coverage before any checklist import says so and counts nothing as working", cv0.status === 200 && cv0.json.imported === false && cv0.json.working === 0);
  gconn.kit.coverage.importCsv(csvDir);
  gconn.kit.coverage.mark("MOCKKIT_WHOAMI", "live_verified", { account: gacct.id });
  const seedAccountId = A.id;
  let seedRefusal = "";
  try {
    gconn.kit.coverage.mark(SEED_ROW, "live_verified", { account: seedAccountId });
  } catch (e) {
    seedRefusal = e.message;
  }
  const cv1 = await dapi("GET", "/api/connectors/coverage");
  assert("api: coverage after the import counts the one curated live row (1 of 3) and the seed account's mark was refused", cv1.json.imported === true && cv1.json.working === 1 && cv1.json.addressable === 3 && /seeded provider/.test(seedRefusal));
  const mkRow = (await dapi("GET", "/api/connectors/providers?q=mock")).json.providers.find((p) => p.slug === "mockg");
  assert("api: the curated provider row reports 1 of 2 rows live with the date of the probe", mkRow.coverage.state === "some_live" && mkRow.coverage.working_rows === 1 && typeof mkRow.coverage.last_verified_at === "string");

  // no credential anywhere in anything the API returned
  const allText = RESPONSES.join("\n");
  const hits = [...SECRETS].filter((s) => allText.includes(s));
  assert("api: no secret the run minted (client secret, tokens, pasted key) appears in any response body", hits.length === 0, hits.map((h) => h.split("_CNRY")[0]).join(","));
} finally {
  await dash.close();
  await gw.shutdown();
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════
// 6. the extractor on a fixture checkout
// ═════════════════════════════════════════════════════════════════════════════════════════════════════
const AP = mkdtempSync(join(WORK, "ap-mini-"));
const CANARY_FILE = join(WORK, "piece-code-ran.txt");
process.env.SB_SEED_CANARY = CANARY_FILE;
const FIXTURE_LICENSE = `Copyright (c) 2020-2024 Fixture Org.

Portions of this software are licensed as follows:

* All content that resides under the "packages/ee/" directory of this repository, if that directory exists, is licensed under the license defined in packages/ee/LICENSE
* Content outside of the above mentioned directories or restrictions above is available under the "MIT Expat" license as defined below.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
`;
const FIXTURE_SHA = "0123456789abcdef0123456789abcdef01234567";
const put = (rel, text) => {
  const p = join(AP, rel);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, text);
};
put("LICENSE", FIXTURE_LICENSE);
const piece = (name, files, pkg = {}) => {
  put(`packages/pieces/community/${name}/package.json`, JSON.stringify({ name: `@fixture/piece-${name}`, version: "0.0.1", ...pkg }));
  for (const [rel, text] of Object.entries(files)) put(`packages/pieces/community/${name}/${rel}`, text);
};
const FW = "'@activepieces/pieces-framework'";
piece("alpha", {
  "src/index.ts": `import { createPiece, PieceCategory } from ${FW};\nimport { alphaAuth } from './lib/auth';\nimport { listItems } from './lib/actions/list-items';\nexport const alpha = createPiece({ displayName: 'Alpha Service', description: 'DESCRIPTION-CANARY-ALPHA', auth: alphaAuth, categories: [PieceCategory.PRODUCTIVITY], actions: [listItems], triggers: [] });\n`,
  "src/lib/consts.ts": `export const API_ORIGIN = 'https://api.alphaservice.test';\nexport const AUTH_ORIGIN = 'https://auth.alphaservice.test';\nexport const BASE_SCOPES = ['read:items', 'write:items'];\n`,
  "src/lib/auth.ts": `import { OAuth2AuthorizationMethod, PieceAuth, Property } from ${FW};\nimport { AUTH_ORIGIN, BASE_SCOPES } from './consts';\nexport const alphaAuth = PieceAuth.OAuth2({\n  description: 'DESCRIPTION-CANARY-ALPHA-AUTH',\n  authUrl: \`\${AUTH_ORIGIN}/oauth/authorize?client_id=PUBLIC-APP-ID&lang=en\`,\n  tokenUrl: AUTH_ORIGIN + '/oauth/token',\n  required: true,\n  pkce: true,\n  scope: [...BASE_SCOPES, 'admin:items offline_access'],\n  authorizationMethod: OAuth2AuthorizationMethod.HEADER,\n  extra: { access_type: 'offline', prompt: 'consent', client_secret: 'abcdefABCDEF0123456789abcdefABCDEF0123456789', api_token: 'hunter2' },\n  props: { workspace: Property.ShortText({ displayName: 'Workspace', description: 'DESCRIPTION-CANARY-WS', required: false }) },\n  validate: async ({ auth }) => { throw new Error('this must never run'); },\n});\n`,
  "src/lib/actions/list-items.ts": `import { httpClient, HttpMethod } from '@activepieces/pieces-common';\nimport { createAction } from ${FW};\nimport { API_ORIGIN } from '../consts';\nexport const listItems = createAction({ name: 'list_items', displayName: 'List items', description: 'DESCRIPTION-CANARY-ACTION', props: {}, async run() { return httpClient.sendRequest({ method: HttpMethod.GET, url: \`\${API_ORIGIN}/v1/items\` }); } });\n`,
});
piece("bravo", {
  "src/index.ts": `import { createPiece } from ${FW};\nimport { bravoAuth } from './lib/common/client';\nexport const bravo = createPiece({ displayName: 'Bravo', auth: bravoAuth, actions: [], triggers: [] });\n`,
  "src/lib/common/client.ts": `import { PieceAuth } from ${FW};\nexport const BASE_URL = 'https://api.bravo-service.test/v2';\nconst help = 'https://help.bravo-service.test/x';\nexport const bravoAuth = PieceAuth.SecretText({ displayName: 'API Key', description: 'Get one at https://docs.bravo-service.test/keys DESCRIPTION-CANARY-BRAVO', required: true });\n`,
});
piece("charlie", {
  "src/index.ts": `import { createPiece, PieceAuth } from ${FW};\nimport { httpClient } from '@activepieces/pieces-common';\nexport const charlieAuth = PieceAuth.BasicAuth({ displayName: 'Login', description: 'DESCRIPTION-CANARY-CHARLIE', required: true, username: { displayName: 'Email' }, password: { displayName: 'Password' } });\nexport const charlie = createPiece({ displayName: 'Charlie', auth: charlieAuth, actions: [], triggers: [] });\nexport const ping = () => httpClient.sendRequest({ url: 'https://charlie-api.test/rest/1' });\n`,
});
piece("delta", {
  "src/index.ts": `import { createPiece, PieceAuth, Property } from ${FW};\nimport { httpClient } from '@activepieces/pieces-common';\nexport const deltaAuth = PieceAuth.CustomAuth({ description: 'DESCRIPTION-CANARY-DELTA', required: true, props: { apiKey: PieceAuth.SecretText({ displayName: 'Key', required: true }), subdomain: Property.ShortText({ displayName: 'Subdomain', required: true }), region: Property.StaticDropdown({ displayName: 'Region', required: false, options: { options: [{ label: 'EU', value: 'eu' }] } }) } });\nexport const delta = createPiece({ displayName: 'Delta', auth: deltaAuth, actions: [], triggers: [] });\nexport const ping = (context) => httpClient.sendRequest({ url: \`https://\${context.auth.props.subdomain}.deltaapi.test/v1/ping\` });\n`,
});
piece("echo", { "src/index.ts": `import { createPiece, PieceAuth } from ${FW};\nexport const echoAuth = PieceAuth.OAuth2({ authUrl: '{domain}/oauth/v2/auth', tokenUrl: '{domain}/oauth/v2/token', required: true, scope: ['a'] });\nexport const echo = createPiece({ displayName: 'Echo', auth: echoAuth, actions: [], triggers: [] });\n` });
piece("foxtrot", { "src/index.ts": `import { createPiece, PieceAuth } from ${FW};\nexport const foxtrot = createPiece({ displayName: 'Foxtrot', auth: PieceAuth.None(), actions: [], triggers: [] });\n` });
piece("golf", { "src/index.ts": `import { createPiece, PieceAuth } from ${FW};\nexport const golfAuth = PieceAuth.SecretText({ displayName: 'Key', required: true });\nexport const golf = createPiece({ displayName: 'Golf', auth: golfAuth, actions: [], triggers: [] });\n` });
piece("hotel", {
  "src/index.ts": `import { createPiece } from ${FW};\nimport { createCustomApiCallAction } from '@activepieces/pieces-common';\nimport { hotelAuth } from './lib/auth';\nexport const hotel = createPiece({ displayName: 'Hotel', auth: hotelAuth, actions: [createCustomApiCallAction({ baseUrl: () => 'https://api.hotel-svc.test', auth: hotelAuth })], triggers: [] });\n`,
  "src/lib/auth.ts": `import { OAuth2GrantType, PieceAuth } from ${FW};\nexport const hotelOAuth = PieceAuth.OAuth2({ authUrl: 'https://login.hotel-svc.test/authorize', tokenUrl: 'https://login.hotel-svc.test/token', grantType: OAuth2GrantType.CLIENT_CREDENTIALS, required: true, scope: [] });\nexport const hotelKey = PieceAuth.SecretText({ displayName: 'Key', required: true });\nexport const hotelAuth = [hotelOAuth, hotelKey];\n`,
});
mkdirSync(join(AP, "packages/pieces/outside/src"), { recursive: true });
writeFileSync(join(AP, "packages/pieces/outside/src/auth.ts"), `import { PieceAuth } from ${FW};\nexport const stolenAuth = PieceAuth.SecretText({ displayName: 'Key', required: true });\nexport const U = 'https://stolen-secret-host.test';\n`);
piece("india", { "src/index.ts": `import { createPiece } from ${FW};\nimport { stolenAuth } from '../../../outside/src/auth';\nexport const india = createPiece({ displayName: 'India', auth: stolenAuth, actions: [], triggers: [] });\n` });
piece("evil", {
  "src/index.ts": `import { createPiece, PieceAuth } from ${FW};\nrequire('node:fs').writeFileSync(process.env.SB_SEED_CANARY || 'seed-canary-ran.txt', 'piece code ran');\nprocess.exit(7);\nexport const API_URL = 'https://api.evil-svc.test';\nexport const evilAuth = PieceAuth.SecretText({ displayName: 'Key', required: true });\nexport const evil = createPiece({ displayName: 'Evil Piece', auth: evilAuth, actions: [], triggers: [] });\n`,
});
piece("3d-things", { "src/index.ts": `import { createPiece, PieceAuth } from ${FW};\nexport const BASE_URL = 'https://api.threed.test';\nexport const a = PieceAuth.SecretText({ displayName: 'Key', required: true });\nexport const p = createPiece({ displayName: 'Three D', auth: a, actions: [], triggers: [] });\n` });
piece("this-is-a-very-long-piece-folder-name-ok", { "src/index.ts": `import { createPiece, PieceAuth } from ${FW};\nexport const BASE_URL = 'https://api.longname.test';\nexport const a = PieceAuth.SecretText({ displayName: 'Key', required: true });\nexport const p = createPiece({ displayName: 'Long', auth: a, actions: [], triggers: [] });\n` });
piece("juliet", { "src/index.ts": `import { createPiece, PieceAuth } from ${FW};\nexport const BASE_URL = 'https://api.juliet.test';\nexport const a = PieceAuth.SecretText({ displayName: 'Key', required: true });\nexport const p = createPiece({ displayName: 'Juliet', auth: a, actions: [], triggers: [] });\n` }, { license: "GPL-3.0" });

const before = existsSync(CANARY_FILE);
const run1 = EXTRACT.extractCheckout({ checkout: AP, commit: FIXTURE_SHA });
const run2 = EXTRACT.extractCheckout({ checkout: AP, commit: FIXTURE_SHA });
const seeds = run1.seeds;
const m = run1.manifest;
assert("extractor: it parsed the pieces without running any piece code (the canary file was never written, the process was not exited)", before === false && !existsSync(CANARY_FILE) && !existsSync(join(ROOT, "seed-canary-ran.txt")) && !existsSync(join(process.cwd(), "seed-canary-ran.txt")));
assert("extractor: 13 fixture pieces scanned; the seeds are exactly those with a static auth and an API host", m.pieces_scanned === 13 && [...seeds.keys()].sort().join(",") === ["alpha", "bravo", "charlie", "delta", "evil", "hotel", "p-3d-things", "this-is-a-very-long-piece-folder"].sort().join(","), [...seeds.keys()].join(","));
const why = (p) => m.skipped_pieces.pieces.find((s) => s.piece === p)?.reason;
assert("extractor: skipped pieces carry their reason (templated OAuth URL, no auth, no API host, an import out of the piece, a non-MIT package license)", why("echo") === "oauth2_url_not_static" && why("foxtrot") === "no_auth" && why("golf") === "no_api_host" && why("india") === "no_auth" && why("juliet") === "non_mit_package_license", JSON.stringify(m.skipped_pieces.reasons));
const al = seeds.get("alpha");
const ao = al?.auth[0].oauth2;
assert("extractor: OAuth2 facts through imports, templates, spreads and concatenation (authorize and token URLs, scopes split on whitespace, PKCE, Basic for HEADER)", al.name === "Alpha Service" && al.categories.join() === "productivity" && ao.authorize_url === "https://auth.alphaservice.test/oauth/authorize?lang=en" && ao.token_url === "https://auth.alphaservice.test/oauth/token" && ao.pkce === "required" && ao.client_auth === "basic" && JSON.stringify(ao.default_scopes) === JSON.stringify(["read:items", "write:items", "admin:items", "offline_access"]), JSON.stringify(ao));
assert("extractor: a client id in a URL query and secret-named or secret-shaped extra parameters are dropped; harmless ones are kept", !JSON.stringify(al).includes("PUBLIC-APP-ID") && JSON.stringify(ao.extra_auth_params) === JSON.stringify({ access_type: "offline", prompt: "consent" }));
assert("extractor: the prop becomes a field (name and secret flag only), the API host comes from the request URL, not from the auth or the descriptions", JSON.stringify(al.auth[0].fields.connected_account_initiation) === JSON.stringify([{ name: "workspace", required: false, secret: false }]) && JSON.stringify(al.api_hosts) === JSON.stringify(["api.alphaservice.test"]), JSON.stringify(al.api_hosts));
const br = seeds.get("bravo");
assert("extractor: a secret-text auth is an api_key seed whose host comes from a base URL constant, not from a docs or help link", br.auth[0].mode === "api_key" && JSON.stringify(br.api_hosts) === JSON.stringify(["api.bravo-service.test"]) && br.auth[0].fields.connected_account_initiation[0].secret === true);
const ch = seeds.get("charlie");
assert("extractor: BasicAuth is a basic seed with username and password fields", ch.auth[0].mode === "basic" && ch.auth[0].fields.connected_account_initiation.map((f) => `${f.name}:${f.secret}`).join() === "username:false,password:true" && JSON.stringify(ch.api_hosts) === JSON.stringify(["charlie-api.test"]));
const de = seeds.get("delta");
assert("extractor: CustomAuth props become fields in snake case; a templated subdomain becomes a wildcard host of two labels", de.auth[0].mode === "custom" && de.auth[0].fields.connected_account_initiation.map((f) => `${f.name}:${f.required}:${f.secret}`).join() === "api_key:true:true,subdomain:true:false,region:false:false" && JSON.stringify(de.api_hosts) === JSON.stringify(["*.deltaapi.test"]));
const ho = seeds.get("hotel");
assert("extractor: an auth array through exported constants gives client credentials (no authorize URL) and an API key; a constant thunk gives the host", ho.auth.map((a) => a.mode).join() === "oauth2_cc,api_key" && ho.auth[0].default === true && ho.auth[0].oauth2.authorize_url === undefined && JSON.stringify(ho.api_hosts) === JSON.stringify(["api.hotel-svc.test"]));
assert("extractor: an import that leaves the piece's own folder is not followed (nothing of the outside file appears)", !seeds.has("india") && !JSON.stringify([...seeds.values()]).includes("stolen-secret-host"));
assert("extractor: a piece whose index runs code at import still yields its facts (the code was only read)", seeds.get("evil")?.auth[0].mode === "api_key" && JSON.stringify(seeds.get("evil").api_hosts) === JSON.stringify(["api.evil-svc.test"]));
assert("extractor: slugs are made valid and unique (a leading digit, a name over 32 characters)", seeds.has("p-3d-things") && [...seeds.keys()].every((s) => /^[a-z][a-z0-9-]{0,31}$/.test(s)) && m.slugs_changed.some((c) => c.piece === "3d-things" && c.slug === "p-3d-things"), JSON.stringify(m.slugs_changed));
const everything = JSON.stringify([...seeds.values()]) + JSON.stringify(m);
assert("extractor: no description, label or code from a piece is copied (every DESCRIPTION-CANARY is absent) and no em dash is written", !/DESCRIPTION-CANARY/.test(everything) && !/this must never run/.test(everything) && !/[\u2013\u2014]/.test(everything));
{
  const bad = [];
  for (const [slug, def] of seeds) {
    const p = [...validateProviderDef(def), ...seedProblems(def)];
    if (p.length) bad.push(`${slug}: ${p[0]}`);
    if (EXTRACT.looksSecret(JSON.stringify(def).replaceAll(FIXTURE_SHA, "<commit>"))) bad.push(`${slug}: secret-shaped`);
  }
  assert("extractor: every generated seed passes the registry's own validation and seed rules, and none holds a secret-shaped string", bad.length === 0, bad.join(" | "));
}
assert("extractor: the manifest counts by auth mode are computed from what was written", JSON.stringify(m.auth_definitions_by_mode) === JSON.stringify({ api_key: 5, basic: 1, custom: 1, oauth2: 1, oauth2_cc: 1 }) && m.auth_definitions === 9 && m.seeds === 8 && m.source.commit === FIXTURE_SHA && m.source.license === "MIT", JSON.stringify(m.auth_definitions_by_mode));
assert("extractor: deterministic (two runs give identical seeds and manifest) and the files it writes are byte-stable", JSON.stringify([...run1.seeds.entries()]) === JSON.stringify([...run2.seeds.entries()]) && JSON.stringify(run1.manifest) === JSON.stringify(run2.manifest));
{
  const out1 = join(WORK, "out1");
  const out2 = join(WORK, "out2");
  EXTRACT.writeSeeds(out1, run1);
  EXTRACT.writeSeeds(out2, run2);
  const h = (d) => sha(readdirSync(d).sort().map((f) => `${f}:${readFileSync(join(d, f), "utf8")}`).join("\n"));
  assert("extractor: writing twice gives byte-identical folders, and a stale seed file in the output folder is removed", h(out1) === h(out2) && (writeFileSync(join(out1, "stale.json"), "{}"), EXTRACT.writeSeeds(out1, run1), !existsSync(join(out1, "stale.json"))));
}
{
  // the licence gate
  const lic = (text) => {
    const d = mkdtempSync(join(WORK, "lic-"));
    mkdirSync(join(d, "packages/pieces/community"), { recursive: true });
    writeFileSync(join(d, "LICENSE"), text);
    return d;
  };
  const throws = (d) => {
    try {
      EXTRACT.checkLicense(d);
      return "";
    } catch (e) {
      return e.message;
    }
  };
  assert("licence gate: an MIT root licence with packages/pieces/community outside the ee exception passes", throws(lic(FIXTURE_LICENSE)) === "");
  assert("licence gate: a licence that is not MIT Expat is refused", /LICENSE check failed/.test(throws(lic("Copyright (c) 2024 X\n\nAll rights reserved.\n"))));
  assert("licence gate: an exception that covers packages/pieces/community is refused", /LICENSE check failed/.test(throws(lic(FIXTURE_LICENSE.replace('"packages/ee/"', '"packages/pieces/"')))));
  assert("licence gate: a missing LICENSE is refused", /missing/.test(throws(mkdtempSync(join(WORK, "lic-")))));
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════
// 7. docs, README, hygiene
// ═════════════════════════════════════════════════════════════════════════════════════════════════════
const read = (rel) => readFileSync(join(ROOT, rel), "utf8");
const DOCS = ["docs/architecture/LOCAL_TOOLKITS.md", "docs/connectors/OWNER_SETUP.md"];
{
  const missing = DOCS.filter((d) => !existsSync(join(ROOT, d)));
  assert("docs: LOCAL_TOOLKITS.md and OWNER_SETUP.md exist", missing.length === 0, missing.join(","));
  const arch = read(DOCS[0]);
  const heads = ["The goal", "Architecture", "Data model", "Flows", "Execution pipeline", "Files and media", "Exposure", "Verification and honest counts", "Seeded provider breadth", "Security rules", "Per-platform route", "What you create at each platform"];
  assert("docs: the architecture page has the sections of the ADR (architecture, data model, flows, security rules, route table, owner setup)", heads.every((h) => new RegExp(`^## \\d+\\. ${h}`, "m").test(arch)), heads.filter((h) => !new RegExp(`^## \\d+\\. ${h}`, "m").test(arch)).join(","));
  const platforms = ["YouTube", "Gmail", "Google Drive", "X", "Slack", "Notion", "GitHub", "ElevenLabs", "Facebook Pages", "Instagram", "LinkedIn", "TikTok"];
  assert("docs: the route table names all 12 priority platforms", platforms.every((p) => new RegExp(`^\\| ${p} \\|`, "m").test(arch)), platforms.filter((p) => !new RegExp(`^\\| ${p} \\|`, "m").test(arch)).join(","));
  const setup = read(DOCS[1]);
  const priority = ["google", "meta-facebook", "meta-instagram", "linkedin", "tiktok", "x", "slack", "notion", "github", "elevenlabs"];
  const reg = ProviderRegistry.load({ home: mkdtempSync(join(WORK, "h-")) });
  const notIn = priority.filter((s) => !setup.includes(reg.get(s).owner_setup.console_url) || !new RegExp(`switchboard connect ${s}\\b`).test(setup));
  assert("docs: the owner setup page has, for each priority platform, the provider's console URL and its connect command (kept in step with the provider files)", notIn.length === 0, notIn.join(","));
  // the doc and the provider files agree on the vault and authconfig names
  const drift = [];
  for (const s of ["google", "meta-facebook", "meta-instagram", "linkedin", "tiktok", "x", "github", "linear"]) {
    const step = reg.get(s).owner_setup.steps.find((t) => /switchboard authconfig add/.test(t));
    const cmd = /switchboard authconfig add \S+ --client-id-ref (\S+) --client-secret-ref (\S+)/.exec(step ?? "");
    if (cmd && s !== "linear" && !(setup.includes(`--client-id-ref ${cmd[1]} --client-secret-ref ${cmd[2]}`))) drift.push(s);
  }
  assert("docs: the vault names in the owner setup commands match the provider files' own steps", drift.length === 0, drift.join(","));
  const PRIVATE = [/(?<![A-Za-z0-9])[A-Za-z]:[\\/]/, /\/Users\//i, /\bClaude\b/i, /\bCLAUDE\.md\b/, /\bmemory notes?\b/i, /\bMEMORY\.md\b/, /masoud/i, /masoori/i, /mas-ai\.co/i, /\bDaena\b/i, /\.claude/i, /\bgws\b/i, /locked decision/i, /\bowner decision\b/i, /\bscratchpad\b/i, /\$S\//, /\bR[123] (lane|research|checklist)/i, /\bComposio\b/, /\bADR\b/, /\bEvilbob\b/i];
  for (const d of [...DOCS, "NOTICE"]) {
    const text = read(d);
    const hit = PRIVATE.filter((re) => re.test(text)).map((re) => re.source);
    assert(`docs: ${d} carries no owner-private detail (local paths, memory notes, account or company names, internal rules)`, hit.length === 0, hit.join(" | "));
  }
  const dash = [...DOCS, "NOTICE", "scripts/extract-activepieces-auth.mjs", "scripts/verify-connectors-seed.mjs", "src/connectors/admin.ts"].filter((f) => /[\u2013\u2014]/.test(read(f)));
  assert("hygiene: no em or en dash in the files this step wrote", dash.length === 0, dash.join(","));
  const mixed = ["src/connectors/providers.ts", "src/connectors/coverage.ts", "src/connectors/accounts.ts", "src/connectors/kit.ts", "src/connectors/cli-kit.ts", "src/connectors/cli.ts", "src/connectors/index.ts", "src/connectors/types.ts", "src/connectors/schemas/provider.schema.json", "scripts/copy-connector-assets.mjs", "docs/architecture/CONNECTORS.md"].filter((f) => /[\u2013\u2014]/.test(read(f)));
  assert("hygiene: no em or en dash in the files this step edited that had none", mixed.length === 0, mixed.join(","));
  // files that already held em dashes before this step: the count must not grow (baseline measured at the parent commit)
  const BASE = { "public/app.js": 45, "public/app.css": 1, "public/index.html": 1, "src/dashboard.ts": 23, "package.json": 1, "README.md": 115 };
  const grown = Object.entries(BASE).filter(([f, n]) => (read(f).match(/\u2014/g) ?? []).length > n);
  assert("hygiene: the files that already had em dashes gained none (app.js, app.css, index.html, dashboard.ts, package.json, README.md)", grown.length === 0, grown.map(([f]) => f).join(","));
  const readme = read("README.md");
  assert("README: has the section 'Local connectors (no subscription)' with the five claims (own accounts, seeds never working, curated wins, honest counts, links)", /^## Local connectors \(no subscription\)/m.test(readme) && /never counted as working/.test(readme) && /curated definition always wins/.test(readme) && /docs\/connectors\/OWNER_SETUP\.md/.test(readme) && /docs\/architecture\/LOCAL_TOOLKITS\.md/.test(readme));
  const claimed = (/Beside them ship (\d+) \*\*seeds\*\*/.exec(readme) ?? [])[1];
  assert("README: the seed count it states is the manifest's", Number(claimed) === manifest.seeds, `${claimed} vs ${manifest.seeds}`);
}
{
  // dashboard assets: the page, its nav entry and route, no inline handlers, escaping on every dynamic value
  const js = read("public/app.js");
  const start = js.indexOf("// VIEW: Connectors");
  const end = js.indexOf("// VIEW: Servers");
  const block = js.slice(start, end);
  assert("dashboard: the Connectors view, its route and its nav entry exist", start > 0 && end > start && /"\/connectors": renderConnectors/.test(js) && /href="#\/connectors"/.test(read("public/index.html")));
  assert("dashboard: the view uses the shared api() helper (owner session and CSRF), never fetch directly, and has no inline event handler", !/\bfetch\(/.test(block) && !/\bon(click|change|input|submit|error|load)\s*=/.test(block));
  assert("dashboard: the view marks a seed as unverified wherever it shows coverage", /Unverified seed/.test(block) && /unverified seed/.test(block));
  assert("dashboard: external links are only https and open with noopener", /safeHttps/.test(block) && (block.match(/target="_blank"/g) ?? []).every(() => /rel="noopener noreferrer"/.test(block)));
  assert("dashboard: the page's script parses", spawnSync(process.execPath, ["--check", join(ROOT, "public", "app.js")]).status === 0);
}
{
  const gi = read(".gitignore");
  assert(".gitignore: generated toolkit output stays ignored (the seed folder is not)", /^\/toolkits\/\s*$/m.test(gi) && !/seed/.test(gi));
  const git = spawnSync("git", ["rev-parse", "--is-inside-work-tree"], { cwd: ROOT, encoding: "utf8" });
  if (git.status === 0 && git.stdout.trim() === "true") {
    const tracked = spawnSync("git", ["ls-files"], { cwd: ROOT, encoding: "utf8" }).stdout.split("\n").filter(Boolean);
    const gen = tracked.filter((f) => /(^|\/)toolkits\/generated\//.test(f) || /\.generated\.json$/.test(f) || /(^|\/)toolkits\/[a-z0-9-]+\/\d{8}_\d{2}\//.test(f) || /(^|\/)toolkits\/[a-z0-9-]+\/current\.json$/.test(f));
    assert("git: no generated spec output and no versioned toolkit directory is tracked", gen.length === 0, gen.slice(0, 3).join(","));
    const stray = tracked.filter((f) => /^src\/connectors\/.*\.json$/.test(f) && !/^src\/connectors\/(providers|schemas|providers\/seed)\/[^/]+\.json$/.test(f) && !/^src\/connectors\/toolkits\/[a-z][a-z0-9-]*\/(overlay\.json|recipes\/[A-Za-z0-9_.-]+\.json)$/.test(f));
    assert("git: the only JSON tracked under src/connectors is providers, seeds, the schema, overlays and recipes", stray.length === 0, stray.slice(0, 3).join(","));
    const seeded = tracked.filter((f) => f.startsWith("src/connectors/providers/seed/") && !f.endsWith("_manifest.json")).length;
    note(`git: ${seeded} seed files tracked (0 before the first commit of this step)`);
  } else console.log("SKIP  git: not inside a work tree, so the tracked-file checks did not run");
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════
// 8. canary scan and the tripwire
// ═════════════════════════════════════════════════════════════════════════════════════════════════════
{
  const files = [join(HOME, "audit.log"), join(HOME3, "audit.log"), join(HOME, "connectors", "accounts.json"), join(HOME3, "connectors", "accounts.json"), join(HOME, "connectors", "authconfigs.json"), join(HOME3, "connectors", "authconfigs.json"), join(HOME3, "connectors", "pending.json")];
  for (const f of files) if (existsSync(f)) leak(`file ${f.slice(-40)}`, readFileSync(f, "utf8"));
  const bad = [];
  for (const o of OUTPUTS) for (const s of SECRETS) if (o.text.includes(s)) bad.push(`${o.label}: ${s.split("_CNRY")[0]}`);
  assert("canary: none of the secrets this run minted (client secret, access and refresh tokens, codes, the pasted key) appears in the audit log, the account, auth config and pending files, or the engine's log output", bad.length === 0 && OUTPUTS.length > 3, `${OUTPUTS.length} outputs, ${SECRETS.size} canaries; ${bad.slice(0, 3).join(" | ")}`);
}
assert("tripwire: no socket was opened to anything but loopback during the whole oracle (no real provider was contacted)", NONLOCAL.length === 0, NONLOCAL.join(","));

await closeServer(mockServer);
net.Socket.prototype.connect = realConnect;
for (const d of [HOME, WORK, HOME3]) {
  try {
    rmSync(d, { recursive: true, force: true });
  } catch {
    /* temp leftovers are harmless */
  }
}
const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
if (failed.length) {
  console.log(`${failed.length} failed:`);
  for (const f of failed) console.log(`  - ${f.name}${f.detail ? ` (${f.detail})` : ""}`);
  process.exit(1);
}
process.exit(0);
