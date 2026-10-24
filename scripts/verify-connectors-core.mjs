// Deterministic oracle for the connector core (ADR local-composio, phase P1): provider definitions as
// validated data, auth configs, connected accounts with refresh, the connect flows, the identity probe,
// and the CLI. It proves the nine acceptance items of ADR section 9 / P1 against a MOCK authorization and
// API server on a loopback ephemeral port. It never calls a real provider, signs in anywhere or spends money.
//
//   1. Every ProviderDef validates against the JSON Schema; the 12 priority platforms are present; no
//      secret-shaped string ships in a provider file.
//   2. A mock authorization server covers the 8 quirk profiles (body vs Basic client auth; PKCE required,
//      optional, unsupported; scope separator space vs comma; rotating refresh token; error body on HTTP
//      200; loopback vs https redirect refusal; extra auth params) and each completes connect, ACTIVE,
//      refresh and an API call. A GET token exchange with a wrapped answer and a long-lived exchange, a
//      client_key parameter, Slack's ok:false shape and a client-credentials grant are covered too.
//   3. Single flight: 25 concurrent calls with an expired token make exactly one token request.
//   4. Crash safety: a process killed right after a rotated refresh token was received loses nothing.
//   5. invalid_grant marks EXPIRED in the same call, writes one account_expired audit row, returns
//      SB_ACCOUNT_EXPIRED with the reconnect command, and nothing retries.
//   6. Revoke hits the provider's revoke endpoint, deletes the sealed token, status REVOKED.
//   7. Canary secrets never appear in audit, logs, any /api/* JSON, error text or CLI output.
//   8. Restart keeps accounts; a CLI revoke is seen by a running gateway at once (live reload).
//   9. Migration: an existing oauth.json becomes accounts with unchanged behaviour (verify:oauth, which
//      drives the OAuth authorization server, runs untouched in the same chain).
//
// Zero deps beyond node and the package's own build. Build first (`npm run build`), then
// `npm run verify:connectors-core`. Isolated SWITCHBOARD_HOME; every process it starts is killed.
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, existsSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { createServer as createNetServer } from "node:net";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const HOME = mkdtempSync(join(tmpdir(), "sb-connectors-"));
process.env.SWITCHBOARD_HOME = HOME;
const WORK = mkdtempSync(join(tmpdir(), "sb-connectors-work-"));

const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? ` - ${detail}` : ""}`);
};
const note = (line) => console.log(`NOTE  ${line}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Everything the product printed or returned that the canary scan will read.
const OUTPUTS = [];
const leak = (label, text) => OUTPUTS.push({ label, text: String(text) });
const realStderr = process.stderr.write.bind(process.stderr);
process.stderr.write = (chunk, ...rest) => {
  leak("process stderr (engine logs)", Buffer.isBuffer(chunk) ? chunk.toString("utf8") : chunk);
  return realStderr(chunk, ...rest);
};

// Every process this oracle starts is killed on any exit path (including a crash mid-run).
const CHILDREN = new Set();
process.on("exit", () => {
  for (const c of CHILDREN) {
    try {
      c.kill("SIGKILL");
    } catch {
      /* already gone */
    }
  }
});
const track = (child) => {
  CHILDREN.add(child);
  child.once("exit", () => CHILDREN.delete(child));
  return child;
};

const mod = (p) => import(pathToFileURL(join(ROOT, "dist", p)).href);
const { Connectors, ConnectorError } = await mod("connectors/index.js");
const { ProviderRegistry, validateProviderDef, bundledProviderDir } = await mod("connectors/providers.js");
const { Vault, loadVaultKey, seal, unseal } = await mod("vault.js");
const { OAuthStore } = await mod("oauth.js");
const { AuditLog, redactSecretShapes } = await mod("audit.js");
const { Gateway } = await mod("gateway.js");
const { startDashboard } = await mod("dashboard.js");
// Adapted (merge with the governed gateway, design 3.15): the owner session is a header minted by the gateway after its own
// presence check, not a cookie from a login-code file. The shared helper does exactly what `switchboard dashboard login` does.
const { ownerSession } = await import("./lib/owner.mjs");
const { StoreCorruptError } = await mod("atomicfile.js");

// ── helpers ──────────────────────────────────────────────────────────────────────────────────────────
const freePort = () =>
  new Promise((resolve, reject) => {
    const s = createNetServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });

/** Run fn and return the thrown error (its message is fed to the canary scan), or undefined. */
async function thrown(fn) {
  try {
    await fn();
    return undefined;
  } catch (err) {
    leak("error text", err instanceof Error ? err.message : String(err));
    return err;
  }
}
const b64url = (b) => Buffer.from(b).toString("base64url");
const hex = (n) => randomBytes(n).toString("hex");

// ── the mock authorization + API server ──────────────────────────────────────────────────────────────
const CLIENT_ID = "mock-client-id-7731";
const CLIENT_SECRET = "mock-client-secret-CNRY-" + hex(10);
const SECRETS = new Set([CLIENT_SECRET]); // every secret the mock ever issues or sees: the canary list
const mint = (prefix) => {
  const t = `${prefix}_CNRY${hex(12)}`;
  SECRETS.add(t);
  return t;
};

/** One entry per quirk profile. `slug` is the provider slug the oracle writes into <home>/providers/. */
const PROFILES = {
  qa: { slug: "q-body-pkce", clientAuth: "body", pkce: "required", secretAtExchange: "always", sep: " ", scopes: ["read", "write"], rotates: false, revoke: "client_body" },
  qb: { slug: "q-basic-nopkce", clientAuth: "basic", pkce: "unsupported", secretAtExchange: "always", sep: null, scopes: [], rotates: true, extraAuth: { owner: "user" }, revoke: "client_basic" },
  qc: { slug: "q-pkce-optional", clientAuth: "body", pkce: "supported", secretAtExchange: "optional", sep: ",", scopes: ["alpha", "beta"], rotates: false, noSecret: true },
  qd: { slug: "q-rotating", clientAuth: "body", pkce: "supported", secretAtExchange: "always", sep: " ", scopes: ["read", "write"], rotates: true, revoke: "none" },
  qe: { slug: "q-error200", clientAuth: "body", pkce: "supported", secretAtExchange: "always", sep: " ", scopes: ["read"], rotates: false, errors200: true },
  qf: { slug: "q-https-only", clientAuth: "body", pkce: "supported", secretAtExchange: "always", sep: " ", scopes: ["read"], rotates: false, redirect: "https" },
  qg: { slug: "q-extra-params", clientAuth: "body", pkce: "supported", secretAtExchange: "always", sep: " ", scopes: ["read"], rotates: false, extraAuth: { access_type: "offline", prompt: "consent" }, clientIdParam: "client_key", tokenExtra: { audience: "api" }, acceptJson: false, formResponse: true },
  qh: { slug: "q-slack-shape", clientAuth: "body", pkce: "supported", secretAtExchange: "without_pkce", sep: ",", scopes: ["chat:read", "chat:write"], rotates: true, slack: true },
  qi: { slug: "q-get-exchange", clientAuth: "body", pkce: "unsupported", secretAtExchange: "always", sep: ",", scopes: ["basic"], rotates: false, getToken: true, wrap: "data.0", longLived: true, injectQuery: true },
  qj: { slug: "q-client-creds", clientAuth: "basic", cc: true, secretAtExchange: "always", sep: " ", scopes: ["svc"], rotates: false },
};
const BY_SLUG = Object.fromEntries(Object.entries(PROFILES).map(([k, p]) => [p.slug, k]));

/** Token-style (non-OAuth) provider slugs and the exact credential the mock expects. */
const KEY_API = mint("apikey");
const KEY_BEARER = mint("pat");
const KEY_BASIC_USER = "svc-user";
const KEY_BASIC_PASS = mint("pw");
const KEY_ID = mint("kid");
const KEY_SECRET = mint("ksecret");

const mock = {
  port: 0,
  base: "",
  hooks: { onHang: null },
  capture: [],
  seen: [],
  state: {},
};
for (const k of Object.keys(PROFILES)) {
  mock.state[k] = {
    codes: new Map(),
    access: new Map(),
    refresh: new Map(),
    c: { authorize: 0, token: 0, "authorization_code": 0, "refresh_token": 0, "client_credentials": 0, exchange: 0, revoke: 0, api: 0 },
    last: {},
    delayMs: 0,
    grantRevoked: false,
    revokeStatus: 200,
    lastRefresh: null,
    firstRefresh: null,
  };
}
mock.state.tokens = { api: 0, hang: 0 };

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
  });
}
const send = (res, status, body, headers = {}) => {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  res.writeHead(status, { "content-type": typeof body === "string" ? "text/plain" : "application/json", ...headers });
  res.end(text);
};

function issue(prof, st, user, scopeStr, { withRefresh = true } = {}) {
  const access = mint(`at-${prof.slug}`);
  st.access.set(access, { user, valid: true });
  const out = { access_token: access, token_type: "Bearer", expires_in: prof.expiresIn ?? 3600 };
  if (scopeStr) out.scope = scopeStr;
  if (withRefresh && !prof.cc && !prof.longLived) {
    const refresh = mint(`rt-${prof.slug}`);
    st.refresh.set(refresh, { user, used: false, revoked: false });
    st.lastRefresh = refresh;
    st.firstRefresh ??= refresh;
    out.refresh_token = refresh;
  }
  return out;
}

function tokenShape(prof, req, body) {
  if (prof.wrap) {
    const [a, b] = prof.wrap.split(".");
    return { [a]: [body] }; // data: [ {...} ]  (b is the index)
  }
  const accept = String(req.headers.accept ?? "");
  if (prof.formResponse && !accept.includes("json")) return new URLSearchParams(Object.entries(body).map(([k, v]) => [k, String(v)])).toString();
  return prof.slack ? { ok: true, ...body } : body;
}

async function handleToken(prof, st, req, url) {
  const isGet = req.method === "GET";
  const raw = isGet ? "" : await readBody(req);
  const params = isGet ? url.searchParams : new URLSearchParams(raw);
  st.c.token++;
  st.last = { params: Object.fromEntries(params), headers: { ...req.headers }, method: req.method };
  if (st.delayMs) await sleep(st.delayMs);
  const fail = (code, desc, status = 400) => (prof.errors200 ? [200, { error: code, error_description: desc }] : prof.slack ? [200, { ok: false, error: code }] : [status, { error: code, error_description: desc }]);
  const idParam = prof.clientIdParam ?? "client_id";
  const authz = req.headers.authorization;
  let cid;
  let csec;
  if (prof.clientAuth === "basic") {
    if (authz?.startsWith("Basic ")) [cid, csec] = Buffer.from(authz.slice(6), "base64").toString("utf8").split(":");
    else cid = params.get(idParam);
  } else {
    cid = params.get(idParam);
    csec = params.get("client_secret") ?? undefined;
    if (authz) return fail("invalid_request", "unexpected Authorization header for form-field client auth");
  }
  const grant = params.get("grant_type");
  if (cid !== CLIENT_ID) return fail("invalid_client", "bad client id");
  const hasVerifier = Boolean(params.get("code_verifier"));
  const need = prof.secretAtExchange === "always" || (prof.secretAtExchange === "without_pkce" && grant === "authorization_code" && !hasVerifier) || (prof.secretAtExchange === "without_pkce" && grant === "refresh_token");
  if (need && csec !== CLIENT_SECRET) return fail("invalid_client", "client secret missing or wrong");
  if (csec !== undefined && csec !== CLIENT_SECRET) return fail("invalid_client", "client secret wrong");
  for (const [k, v] of Object.entries(prof.tokenExtra ?? {})) if (params.get(k) !== v) return fail("invalid_request", `missing token parameter ${k}`);
  if (hasVerifier) SECRETS.add(params.get("code_verifier"));
  if (grant === "authorization_code") {
    st.c.authorization_code++;
    const code = st.codes.get(params.get("code") ?? "");
    if (!code || code.used) return fail("bad_verification_code", "the code is unknown or used");
    code.used = true;
    if (params.get("redirect_uri") !== code.redirect) return fail("invalid_grant", "redirect_uri mismatch");
    if (code.challenge) {
      const v = params.get("code_verifier") ?? "";
      if (b64url(createHash("sha256").update(v).digest()) !== code.challenge) return fail("invalid_grant", "PKCE verifier mismatch");
    } else if (hasVerifier) return fail("invalid_request", "a code_verifier was sent to a provider without PKCE");
    const out = issue(prof, st, code.user, prof.sep === null ? "" : prof.scopes.join(prof.sep === "," ? "," : " "), { withRefresh: !prof.longLived });
    return [200, tokenShape(prof, req, out)];
  }
  if (grant === "refresh_token") {
    st.c.refresh_token++;
    const rt = st.refresh.get(params.get("refresh_token") ?? "");
    if (!rt || st.grantRevoked || rt.revoked || (prof.rotates && rt.used)) return fail("invalid_grant", "the refresh token is not valid");
    if (prof.rotates) rt.used = true;
    const out = issue(prof, st, rt.user, "", { withRefresh: prof.rotates });
    if (!prof.rotates) delete out.refresh_token;
    return [200, tokenShape(prof, req, out)];
  }
  if (grant === "client_credentials" && prof.cc) {
    st.c.client_credentials++;
    return [200, issue(prof, st, "svc-account", params.get("scope") ?? "", { withRefresh: false })];
  }
  return fail("unsupported_grant_type", String(grant));
}

function handleExchange(prof, st, url) {
  st.c.exchange++;
  st.lastExchange = Object.fromEntries(url.searchParams);
  const tok = url.searchParams.get("fb_exchange_token") ?? "";
  const rec = st.access.get(tok);
  if (!rec || !rec.valid) return [400, { error: { type: "OAuthException", message: "invalid exchange token" } }];
  if (url.searchParams.get("client_secret") !== CLIENT_SECRET) return [400, { error: { type: "OAuthException", message: "bad secret" } }];
  const out = issue(prof, st, rec.user, "", { withRefresh: false });
  out.expires_in = 5184000;
  return [200, out];
}

function credentialOf(slug, key, req, url) {
  const h = req.headers;
  const prof = PROFILES[key];
  if (prof?.injectQuery) return { kind: "token", value: url.searchParams.get("access_token") ?? "" };
  if (slug === "t-apikey") return { kind: "key", value: h["x-api-key"] ?? "" };
  if (slug === "t-basic") return { kind: "basic", value: h.authorization ?? "" };
  if (slug === "t-multi") return { kind: "multi", value: h.authorization ?? "" };
  const m = /^Bearer (.+)$/.exec(h.authorization ?? "");
  return { kind: "token", value: m ? m[1] : "" };
}

async function route(req, res) {
  const url = new URL(req.url, `http://127.0.0.1:${mock.port}`);
  const parts = url.pathname.split("/").filter(Boolean);
  const slug = parts[0];
  const rest = parts.slice(1).join("/");
  if (slug === "capture") {
    mock.capture.push({ headers: { ...req.headers }, url: req.url });
    return send(res, 200, {});
  }
  const key = BY_SLUG[slug];
  const prof = key ? PROFILES[key] : undefined;
  const st = key ? mock.state[key] : undefined;

  if (rest === "authorize" && prof) {
    st.c.authorize++;
    const q = url.searchParams;
    const problems = [];
    const idParam = prof.clientIdParam ?? "client_id";
    if (q.get("response_type") !== "code") problems.push("response_type");
    if (q.get(idParam) !== CLIENT_ID) problems.push(`client id param ${idParam}`);
    if (!q.get("state")) problems.push("state");
    const redirect = q.get("redirect_uri");
    if (!redirect) problems.push("redirect_uri");
    const wantScope = prof.sep === null ? null : prof.scopes.join(prof.sep);
    if (wantScope === null ? q.get("scope") !== null : q.get("scope") !== wantScope) problems.push(`scope ${q.get("scope")} != ${wantScope}`);
    const challenge = q.get("code_challenge");
    if (prof.pkce === "unsupported" || prof.cc) {
      if (challenge !== null) problems.push("PKCE challenge sent to a provider without PKCE");
    } else if (!challenge || q.get("code_challenge_method") !== "S256") problems.push("PKCE challenge missing");
    for (const [k, v] of Object.entries(prof.extraAuth ?? {})) if (q.get(k) !== v) problems.push(`extra param ${k}`);
    st.lastAuthorize = Object.fromEntries(q);
    if (problems.length) return send(res, 400, { error: "invalid_request", problems });
    const code = mint(`code-${prof.slug}`);
    st.codes.set(code, { redirect, challenge, user: q.get("mock_user") ?? "u1", used: false });
    const loc = `${redirect}${redirect.includes("?") ? "&" : "?"}code=${encodeURIComponent(code)}&state=${encodeURIComponent(q.get("state"))}`;
    res.writeHead(302, { location: loc });
    return res.end();
  }
  if (rest === "token" && prof && (req.method === (prof.getToken ? "GET" : "POST"))) {
    const [status, body] = await handleToken(prof, st, req, url);
    return send(res, status, body);
  }
  if (rest === "exchange" && prof) {
    const [status, body] = handleExchange(prof, st, url);
    return send(res, status, body);
  }
  if (rest === "revoke" && prof) {
    const raw = await readBody(req);
    const params = new URLSearchParams(raw);
    st.c.revoke++;
    st.lastRevoke = { params: Object.fromEntries(params), headers: { ...req.headers } };
    if (st.revokeStatus !== 200) return send(res, st.revokeStatus, { error: "server_error" });
    const tok = params.get("token") ?? "";
    const rec = st.access.get(tok);
    if (rec) rec.valid = false;
    return send(res, 200, {});
  }
  if (rest === "api/me" || rest === "api/echo") {
    mock.state.tokens.api++;
    if (prof) st.c.api++;
    mock.seen.push({ slug, headers: { ...req.headers }, url: req.url });
    const cred = credentialOf(slug, key, req, url);
    let user;
    if (prof) {
      const rec = st.access.get(cred.value);
      if (!rec || !rec.valid) return send(res, 401, { error: "invalid_token" });
      user = rec.user;
      if (user === "ghost") return send(res, 403, { message: `forbidden for token ${cred.value}` });
    } else if (slug === "t-apikey" && cred.value === KEY_API) user = "key-user";
    else if (slug === "t-bearer" && cred.value === KEY_BEARER) user = "pat-user";
    else if (slug === "t-noprobe" && cred.value) user = "np";
    else if (slug === "t-basic" && cred.value === "Basic " + Buffer.from(`${KEY_BASIC_USER}:${KEY_BASIC_PASS}`).toString("base64")) user = "basic-user";
    else if (slug === "t-multi" && cred.value === `Key ${KEY_ID}:${KEY_SECRET}`) user = "multi-user";
    else return send(res, 401, { error: "invalid_credentials" });
    if (rest === "api/echo") return send(res, 200, { user, headers: req.headers, query: Object.fromEntries(url.searchParams) });
    return send(res, 200, { id: user, name: `User ${user}`, avatar: `https://img.example/${user}.png` });
  }
  if (rest === "api/hang") {
    mock.state.tokens.hang++;
    await mock.hooks.onHang?.(req);
    return; // never answered
  }
  if (rest === "api/to-other-origin") {
    res.writeHead(302, { location: `http://127.0.0.2:${mock.port2}/capture` });
    return res.end();
  }
  send(res, 404, { error: "not_found", path: url.pathname });
}

const mockServer = createServer((req, res) => {
  route(req, res).catch((err) => {
    try {
      send(res, 500, { error: "mock_crash", message: String(err) });
    } catch {
      /* socket gone */
    }
  });
});
await new Promise((r) => mockServer.listen(0, "127.0.0.1", r));
mock.port = mockServer.address().port;
mock.base = `http://127.0.0.1:${mock.port}`;

// a second origin for the cross-origin redirect check (a different loopback address)
let mock2 = null;
try {
  mock2 = createServer((req, res) => {
    mock.capture.push({ headers: { ...req.headers }, url: req.url, origin2: true });
    send(res, 200, {});
  });
  await new Promise((resolve, reject) => {
    mock2.once("error", reject);
    mock2.listen(0, "127.0.0.2", resolve);
  });
  mock.port2 = mock2.address().port;
} catch {
  mock2 = null;
}

// ── provider definitions for the mock, written where the owner's own definitions live ────────────────
const urlOf = (prof, path) => `${mock.base}/${prof.slug}/${path}`;
const inject = (prof) => (prof.injectQuery ? { in: "query", name: "access_token", template: "{token}" } : { in: "header", name: "Authorization", template: "Bearer {token}" });
const field = (name, secret = false, required = true) => ({ name, required, secret });

function oauthDef(prof) {
  const o = {
    token_url: urlOf(prof, "token"),
    pkce: prof.pkce ?? "unsupported",
    client_auth: prof.clientAuth,
    client_secret_at_exchange: prof.secretAtExchange,
    scope_separator: prof.sep,
    default_scopes: prof.scopes,
    scope_catalog: prof.scopes.map((s) => ({ scope: s })),
    redirect: prof.redirect ?? "loopback",
    accept_json: prof.acceptJson ?? true,
    refresh: { kind: "refresh_token", rotates: Boolean(prof.rotates) },
  };
  if (!prof.cc) o.authorize_url = urlOf(prof, "authorize");
  if (prof.extraAuth) o.extra_auth_params = prof.extraAuth;
  if (prof.tokenExtra) o.token_request_params = prof.tokenExtra;
  if (prof.clientIdParam) o.client_id_param = prof.clientIdParam;
  if (prof.slack) o.token_shape = "slack";
  if (prof.getToken) o.token_http_method = "GET";
  if (prof.wrap) o.token_response_path = prof.wrap;
  if (prof.revoke) o.revoke = { url: urlOf(prof, "revoke"), auth: prof.revoke, token_param: "token" };
  if (prof.longLived) {
    const step = { method: "GET", url: urlOf(prof, "exchange"), params: { grant_type: "fb_exchange_token", client_id: "{client_id}", client_secret: "{client_secret}", fb_exchange_token: "{access_token}" } };
    o.post_exchange = step;
    o.refresh = { kind: "exchange", rotates: false, exchange: step };
  }
  if (prof.cc) o.refresh = { kind: "none", rotates: false };
  return {
    slug: prof.slug,
    name: prof.slug,
    categories: ["mock"],
    api_hosts: ["127.0.0.1"],
    docs_url: "https://example.test/docs",
    owner_setup: { console_url: "https://example.test/console", steps: ["create an app"], redirect_uris: ["{loopback_redirect}"], notes: [] },
    identity_probe: { method: "GET", url: urlOf(prof, "api/me"), id_path: "id", name_path: "name", avatar_path: "avatar" },
    auth: [
      {
        id: prof.cc ? "oauth2_cc" : "oauth2",
        mode: prof.cc ? "oauth2_cc" : "oauth2",
        default: true,
        oauth2: o,
        inject: inject(prof),
        fields: { auth_config_creation: [field("client_id"), field("client_secret", true, !prof.noSecret)], connected_account_initiation: [] },
      },
    ],
  };
}

function tokenDef(slug, auth, probe = true) {
  const def = {
    slug,
    name: slug,
    categories: ["mock"],
    api_hosts: ["127.0.0.1"],
    docs_url: "https://example.test/docs",
    owner_setup: { console_url: "https://example.test/console", steps: ["make a key"], redirect_uris: [], notes: [] },
    auth: [auth],
  };
  if (probe) def.identity_probe = { method: "GET", url: `${mock.base}/${slug}/api/me`, id_path: "id", name_path: "name" };
  return def;
}
const TOKEN_DEFS = [
  tokenDef("t-apikey", { id: "api_key", mode: "api_key", default: true, inject: { in: "header", name: "X-Api-Key", template: "{token}" }, fields: { auth_config_creation: [], connected_account_initiation: [field("api_key", true)] } }),
  tokenDef("t-bearer", { id: "pat", mode: "bearer", default: true, inject: { in: "header", name: "Authorization", template: "Bearer {token}" }, fields: { auth_config_creation: [], connected_account_initiation: [field("token", true)] } }),
  tokenDef("t-basic", { id: "basic", mode: "basic", default: true, inject: { in: "header", name: "Authorization", template: "Basic {basic}" }, fields: { auth_config_creation: [], connected_account_initiation: [field("username", true), field("password", true)] } }),
  tokenDef("t-multi", { id: "api_key", mode: "api_key", default: true, inject: { in: "header", name: "Authorization", template: "Key {key_id}:{key_secret}" }, fields: { auth_config_creation: [], connected_account_initiation: [field("key_id", true), field("key_secret", true)] } }),
  tokenDef("t-custom", { id: "custom", mode: "custom", default: true, inject: { in: "header", name: "X-Custom", template: "{token}" }, fields: { auth_config_creation: [], connected_account_initiation: [field("token", true)] } }, false),
  tokenDef("t-noprobe", { id: "api_key", mode: "api_key", default: true, inject: { in: "header", name: "X-Api-Key", template: "{token}" }, fields: { auth_config_creation: [], connected_account_initiation: [field("api_key", true)] } }, false),
];

mkdirSync(join(HOME, "providers"), { recursive: true });
const writeProvider = (def) => writeFileSync(join(HOME, "providers", `${def.slug}.json`), JSON.stringify(def, null, 2));
for (const p of Object.values(PROFILES)) writeProvider(oauthDef(p));
for (const d of TOKEN_DEFS) writeProvider(d);

// ── vault, runtime ───────────────────────────────────────────────────────────────────────────────────
const vault = new Vault("encrypted-file");
vault.set("mock_client_id", CLIENT_ID);
vault.set("mock_client_secret", CLIENT_SECRET);
vault.set("mock_api_key", KEY_API);
vault.set("mock_pat", KEY_BEARER);
vault.set("mock_basic_user", KEY_BASIC_USER);
vault.set("mock_basic_pass", KEY_BASIC_PASS);
vault.set("mock_key_id", KEY_ID);
vault.set("mock_key_secret", KEY_SECRET);

const NETWORK = { allow_private: ["127.0.0.1", "127.0.0.2"], timeout_ms: 8000 };
const clock = { off: 0 };
const now = () => Date.now() + clock.off;
const CB = "http://127.0.0.1:1/oauth/callback"; // never fetched: the oracle reads the Location header only
const auditPath = join(HOME, "audit.log");
const auditRows = () => (existsSync(auditPath) ? readFileSync(auditPath, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);

// ── 9. migration of an existing oauth.json (done first, before anything else touches the home) ───────
{
  const key = loadVaultKey(HOME);
  const rec = (provider, accessToken, extra = {}) => ({ provider, accessToken, tokenType: "Bearer", obtainedAt: Date.now() - 1000, ...extra });
  const legacyGithub = mint("legacy-gh");
  const legacyLinear = mint("legacy-lin");
  const legacyRefresh = mint("legacy-lin-r");
  const ghost = mint("legacy-ghost");
  const file = {
    github: seal(key, JSON.stringify(rec("github", legacyGithub, { scope: "repo,read:user" }))),
    linear: seal(key, JSON.stringify(rec("linear", legacyLinear, { refreshToken: legacyRefresh, expiresAt: Date.now() - 5000 }))),
    ghostly: seal(key, JSON.stringify(rec("ghostly", ghost))),
  };
  const legacyPath = join(HOME, "oauth.json");
  writeFileSync(legacyPath, JSON.stringify(file, null, 2));
  const before = createHash("sha256").update(readFileSync(legacyPath)).digest("hex");
  const store = new OAuthStore(vault, NETWORK);
  const cat = store.catalog();
  const gh = cat.find((p) => p.id === "github");
  assert("migration: the old oauth.json token for github is now a connected account", gh?.connected === true && gh.accounts?.length === 1 && gh.accounts[0].label === "default" && gh.accounts[0].source === "legacy", JSON.stringify(gh?.accounts?.map((a) => a.status)));
  assert("migration: behaviour unchanged, ${oauth:github} resolves to the same token", (await store.accessToken("github")) === legacyGithub);
  const lin = cat.find((p) => p.id === "linear");
  assert("migration: an expired token WITH a refresh token stays refreshable (catalog says expired as before)", lin?.connected === true && lin.expired === true && lin.accounts?.[0]?.status === "ACTIVE");
  assert("migration: the catalog still lists the five providers it always had", ["github", "google", "slack", "notion", "linear"].every((id) => cat.some((p) => p.id === id)));
  assert("migration: oauth.json is left on disk byte for byte", createHash("sha256").update(readFileSync(legacyPath)).digest("hex") === before);
  const again = new OAuthStore(vault, NETWORK);
  assert("migration: a second construction imports nothing twice", again.connectors.accounts.list({ provider: "github" }).length === 1);
  assert("migration: an entry for a provider nobody defines is skipped, not fatal", again.connectors.accounts.list({ provider: "ghostly" }).length === 0);
  again.disconnect("github");
  const third = new OAuthStore(vault, NETWORK);
  assert("migration: disconnect forgets the account and it does not come back from oauth.json", third.connectors.accounts.list({ provider: "github" }).length === 0);
  const unknownErr = await thrown(() => third.accessToken("nope"));
  assert("migration: an unknown provider still says so", /unknown OAuth provider 'nope'/.test(unknownErr?.message ?? ""));
  const notConnected = await thrown(() => third.accessToken("google"));
  assert("migration: a provider with no account still says not connected", /not connected/.test(notConnected?.message ?? ""));
  rmSync(legacyPath);
}

// ── runtime used by the rest of the oracle ───────────────────────────────────────────────────────────
const rt = new Connectors({ vault, network: NETWORK, clock: now });
const AUTHCFG = {};
function ensureConfig(slug, opts = {}) {
  const cfg = rt.authConfigs.add({ provider: slug, client_id_ref: "mock_client_id", ...(opts.noSecret ? {} : { client_secret_ref: "mock_client_secret" }), ...(opts.redirect_uri ? { redirect_uri: opts.redirect_uri } : {}) });
  AUTHCFG[slug] = cfg;
  return cfg;
}

/** The browser step: GET the authorize URL at the mock as `user`, return the code and state it redirects with. */
async function consent(authorizeUrl, user = "u1") {
  const u = new URL(authorizeUrl);
  u.searchParams.set("mock_user", user);
  const r = await fetch(u, { redirect: "manual" });
  if (r.status !== 302) {
    const body = await r.text();
    return { status: r.status, body };
  }
  const loc = new URL(r.headers.get("location"));
  return { status: 302, code: loc.searchParams.get("code"), state: loc.searchParams.get("state"), location: loc.href };
}

/** begin + consent + complete. */
async function connectOAuth(slug, { label = "default", user = "u1", scopes, authConfigId, redirectUri = CB } = {}) {
  const begin = rt.flows.begin({ provider: slug, label, redirectUri, ...(scopes ? { scopes } : {}), ...(authConfigId ? { authConfigId } : {}) });
  const c = await consent(begin.authorizeUrl, user);
  if (c.status !== 302) throw new Error(`the mock refused the authorize request: ${c.status} ${c.body}`);
  const done = await rt.flows.complete(c.state, c.code);
  return { begin, ...done };
}
const stOf = (slug) => mock.state[BY_SLUG[slug]];
const apiMe = (slug) => `${mock.base}/${slug}/api/me`;
async function callMe(account, slug) {
  const res = await rt.accounts.authFetch(account.id, apiMe(slug));
  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = undefined;
  }
  return { status: res.status, json };
}
const readAccountsFile = () => JSON.parse(readFileSync(join(HOME, "connectors", "accounts.json"), "utf8"));
const unsealRecord = (rec) => JSON.parse(unseal(loadVaultKey(HOME), rec.token));

// ═════════════════════════════════════════════════════════════════════════════════════════════════════
// 1. provider definitions are validated data
// ═════════════════════════════════════════════════════════════════════════════════════════════════════
{
  const emptyHome = mkdtempSync(join(WORK, "reg-"));
  const reg = ProviderRegistry.load({ home: emptyHome });
  assert("providers: every bundled definition validates against the schema (no issues)", reg.issues.length === 0, JSON.stringify(reg.issues.map((i) => [i.file, i.problems])));
  const need = ["google", "meta-facebook", "meta-instagram", "linkedin", "tiktok", "x", "slack", "notion", "github", "elevenlabs", "higgsfield", "buffer"];
  assert("providers: the 12 priority providers are present (google, meta-facebook, meta-instagram, linkedin, tiktok, x, slack, notion, github, elevenlabs, higgsfield, buffer)", need.every((s) => reg.has(s)), need.filter((s) => !reg.has(s)).join(","));
  const toolkitMap = { youtube: "google", gmail: "google", drive: "google", instagram: "meta-instagram", facebook: "meta-facebook", linkedin: "linkedin", x: "x", tiktok: "tiktok", elevenlabs: "elevenlabs", notion: "notion", slack: "slack", github: "github" };
  assert("providers: all 12 ADR toolkits resolve to exactly one provider", Object.entries(toolkitMap).every(([tk, p]) => reg.providerForToolkit(tk)?.slug === p && reg.list().filter((d) => (d.toolkits ?? [d.slug]).includes(tk)).length === 1));
  const bundled = reg.list();
  assert("providers: each file carries an https docs_url and an owner_setup (console URL, steps, redirect URIs)", bundled.every((d) => /^https:\/\//.test(d.docs_url) && /^https:\/\//.test(d.owner_setup.console_url) && d.owner_setup.steps.length > 0 && Array.isArray(d.owner_setup.redirect_uris)));
  assert("providers: authorization-code providers list the redirect URI to register", bundled.filter((d) => d.auth.some((a) => a.mode === "oauth2")).every((d) => d.owner_setup.redirect_uris.length > 0));
  assert("providers: every shipped authentication uses a mode the engine drives", bundled.every((d) => d.auth.every((a) => ["oauth2", "oauth2_cc", "api_key", "bearer", "basic"].includes(a.mode))));
  const allUrls = [];
  for (const d of bundled) for (const a of d.auth) if (a.oauth2) allUrls.push(a.oauth2.authorize_url, a.oauth2.token_url, a.oauth2.revoke?.url);
  assert("providers: every shipped authorize, token and revoke URL is https", allUrls.filter(Boolean).every((u) => u.startsWith("https://")));
  assert("providers: every credential template stays inside the provider's api_hosts (probe host check)", bundled.every((d) => !d.identity_probe || d.api_hosts.some((h) => h === new URL(d.identity_probe.url).hostname || (h.startsWith("*.") && new URL(d.identity_probe.url).hostname.endsWith(h.slice(1))))));
  const google = reg.get("google");
  const groups = new Set(google.auth[0].oauth2.scope_catalog.map((s) => s.group).filter(Boolean));
  assert("providers: google carries youtube, gmail and drive scope groups", ["youtube", "gmail", "drive"].every((g) => groups.has(g)), [...groups].join(","));
  assert("providers: elevenlabs is an API key; github has a token and an OAuth app; slack has a bot token and OAuth", reg.get("elevenlabs").auth[0].mode === "api_key" && reg.get("github").auth.some((a) => a.mode === "bearer") && reg.get("github").auth.some((a) => a.mode === "oauth2") && reg.get("slack").auth.some((a) => a.id === "bot_token"));
  assert("providers: tiktok uses client_key and an https redirect; slack requires https; facebook exchanges for a long-lived token", reg.get("tiktok").auth[0].oauth2.client_id_param === "client_key" && reg.get("tiktok").auth[0].oauth2.redirect === "https" && reg.get("slack").auth.find((a) => a.id === "oauth2").oauth2.redirect === "https" && Boolean(reg.get("meta-facebook").auth[0].oauth2.post_exchange));

  const dir = bundledProviderDir();
  const files = readdirSync(dir).filter((n) => n.endsWith(".json"));
  const texts = files.map((n) => [n, readFileSync(join(dir, n), "utf8")]);
  assert("providers: no secret-shaped string in any shipped provider file", texts.every(([, t]) => redactSecretShapes(t) === t), texts.filter(([, t]) => redactSecretShapes(t) !== t).map(([n]) => n).join(","));
  const secretKey = /"[A-Za-z_]*(secret|password|token|api_key)[A-Za-z_]*"\s*:\s*"/i;
  const placeholder = /:\s*"\{[a-z_]+\}"/; // a {client_secret} template placeholder is not a value
  const suspicious = texts.flatMap(([n, t]) => t.split("\n").filter((l) => secretKey.test(l) && !placeholder.test(l) && !/_url"|_ref"|_param"|_path"|_header"|_shape"|_catalog"|_separator"|_at_exchange"|_auth"|_method"|"name"|"label"|"description"/.test(l)).map((l) => `${n}: ${l.trim()}`));
  assert("providers: no key named like a secret holds a literal string value", suspicious.length === 0, suspicious.slice(0, 3).join(" | "));
  const distFiles = readdirSync(join(ROOT, "dist", "connectors", "providers")).filter((n) => n.endsWith(".json")).sort();
  const srcFiles = readdirSync(join(ROOT, "src", "connectors", "providers")).filter((n) => n.endsWith(".json")).sort();
  assert("providers: the build copies exactly the source definitions into dist", JSON.stringify(distFiles) === JSON.stringify(srcFiles) && srcFiles.length >= 13, `${srcFiles.length} files`);

  const clone = () => JSON.parse(JSON.stringify(reg.get("github")));
  const bad = (name, mutate, rx) => {
    const d = clone();
    mutate(d);
    const problems = validateProviderDef(d);
    assert(`providers: the schema rejects ${name}`, problems.length > 0 && (!rx || rx.test(problems.join(" | "))), problems.slice(0, 2).join(" | "));
  };
  bad("an inline client_secret property", (d) => (d.auth[1].oauth2.client_secret = "hunter2-hunter2"), /additional|client_secret/i);
  bad("a missing docs_url", (d) => delete d.docs_url, /docs_url/);
  bad("an unknown mode", (d) => (d.auth[0].mode = "magic"), /mode|allowed/i);
  bad("a token URL on plain http to a public host", (d) => (d.auth[1].oauth2.token_url = "http://evil.example/token"), /https/);
  bad("an identity probe outside api_hosts", (d) => (d.identity_probe.url = "https://elsewhere.example/user"), /api_hosts/);
  bad("a credential template with an undeclared placeholder", (d) => (d.auth[0].inject.template = "Bearer {mystery}"), /placeholder|mystery/i);
  bad("a duplicate authentication id", (d) => (d.auth[1].id = d.auth[0].id), /twice/);
  bad("an OAuth flow with no redirect URI to register", (d) => (d.owner_setup.redirect_uris = []), /redirect_uris/);
  bad("a refresh strategy of exchange with no exchange step", (d) => (d.auth[1].oauth2.refresh = { kind: "exchange", rotates: false }), /exchange/);
  bad("an authorization-code flow without an authorize_url", (d) => delete d.auth[1].oauth2.authorize_url, /authorize_url/);

  const userHome = mkdtempSync(join(WORK, "reg-user-"));
  mkdirSync(join(userHome, "providers"), { recursive: true });
  const mine = { ...clone(), slug: "my-tool", name: "My tool" };
  mine.auth = [mine.auth[0]];
  writeFileSync(join(userHome, "providers", "my-tool.json"), JSON.stringify(mine));
  const hijack = clone();
  hijack.auth[1].oauth2.token_url = "https://attacker.example/steal";
  writeFileSync(join(userHome, "providers", "github.json"), JSON.stringify(hijack));
  writeFileSync(join(userHome, "providers", "torn.json"), '{"slug": "torn", ');
  const reg2 = ProviderRegistry.load({ home: userHome });
  assert("providers: the owner's own definition for a NEW slug loads", reg2.has("my-tool") && !reg2.isBundled("my-tool"));
  assert("providers: a user file cannot override a bundled provider (the bundled token_url stands)", reg2.get("github").auth[1].oauth2.token_url === reg.get("github").auth[1].oauth2.token_url && reg2.issues.some((i) => /cannot be overridden/.test(i.problems.join(" "))));
  assert("providers: a torn provider file is reported and does not take the others down", reg2.issues.some((i) => /torn\.json$/.test(i.file)) && reg2.has("google"));
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════
// 2. the quirk profiles: each completes connect, ACTIVE, refresh and an API call
// ═════════════════════════════════════════════════════════════════════════════════════════════════════
const H2 = 2 * 3600 * 1000;
const qname = (p, s) => `quirk ${p.slug}: ${s}`;

/** Step the injected clock forward and call the API: the engine must refresh first. */
async function refreshAndCall(account, prof) {
  const st = mock.state[BY_SLUG[prof.slug]];
  const before = st.c.refresh_token;
  clock.off += H2;
  const out = await callMe(account, prof.slug);
  return { out, grants: st.c.refresh_token - before };
}

{ // qa: form-field client auth, PKCE required, space-separated scopes
  const prof = PROFILES.qa;
  const st = mock.state.qa;
  ensureConfig(prof.slug);
  clock.off = 0;
  const r = await connectOAuth(prof.slug, { label: "main" });
  const ex = { ...st.last };
  assert(qname(prof, "connect completes with the authorize request the quirks demand (client id, S256 challenge, space-separated scope)"), r.account.status === "ACTIVE" && r.account.identity.external_id === "u1" && r.account.identity.display_name === "User u1", `${r.account.status}`);
  assert(qname(prof, "form-field client auth: id and secret in the body, no Authorization header, PKCE verifier sent"), ex.params.client_id === CLIENT_ID && ex.params.client_secret === CLIENT_SECRET && !ex.headers.authorization && Boolean(ex.params.code_verifier) && ex.params.grant_type === "authorization_code");
  assert(qname(prof, "granted scopes come from the token answer"), JSON.stringify(r.account.scopes_granted) === JSON.stringify(["read", "write"]), r.account.scopes_granted.join(","));
  const { out, grants } = await refreshAndCall(r.account, prof);
  assert(qname(prof, "refresh happens before the call, with the same client auth, and the call succeeds"), grants === 1 && out.status === 200 && out.json?.id === "u1" && st.last.params.grant_type === "refresh_token" && st.last.params.client_secret === CLIENT_SECRET, `grants=${grants} status=${out.status}`);
  assert(qname(prof, "the refreshed account stays ACTIVE with a last_refresh_at"), rt.accounts.require(r.account.id).status === "ACTIVE" && Boolean(rt.accounts.require(r.account.id).last_refresh_at));
  clock.off = 0;
}

{ // qb: HTTP Basic client auth, PKCE unsupported, no scope parameter, owner=user, rotating refresh
  const prof = PROFILES.qb;
  const st = mock.state.qb;
  ensureConfig(prof.slug);
  const r = await connectOAuth(prof.slug, { label: "main" });
  const ex = { ...st.last };
  assert(qname(prof, "Basic client auth: Authorization header carries id:secret, the body carries neither"), String(ex.headers.authorization).startsWith("Basic ") && Buffer.from(String(ex.headers.authorization).slice(6), "base64").toString() === `${CLIENT_ID}:${CLIENT_SECRET}` && !("client_secret" in ex.params) && !("client_id" in ex.params));
  assert(qname(prof, "PKCE unsupported: no challenge sent, no verifier sent; the extra owner=user param was sent; no scope param"), !("code_verifier" in ex.params) && st.lastAuthorize.owner === "user" && !("scope" in st.lastAuthorize) && !("code_challenge" in st.lastAuthorize));
  const first = st.firstRefresh;
  const a = await refreshAndCall(r.account, prof);
  const rec1 = unsealRecord(readAccountsFile().accounts[r.account.id]);
  assert(qname(prof, "rotating refresh: the NEW refresh token is what is stored after the refresh"), a.grants === 1 && a.out.status === 200 && rec1.refresh_token === st.lastRefresh && rec1.refresh_token !== first);
  const b = await refreshAndCall(r.account, prof);
  assert(qname(prof, "rotating refresh: a second refresh uses the persisted rotated token and succeeds"), b.grants === 1 && b.out.status === 200 && unsealRecord(readAccountsFile().accounts[r.account.id]).refresh_token === st.lastRefresh);
  clock.off = 0;
}

{ // qc: PKCE optional (supported), comma-separated scopes, client secret optional and absent
  const prof = PROFILES.qc;
  const st = mock.state.qc;
  ensureConfig(prof.slug, { noSecret: true });
  const r = await connectOAuth(prof.slug, { label: "main" });
  const ex = { ...st.last };
  assert(qname(prof, "PKCE supported is used; comma-separated scopes accepted; optional client secret absent from the exchange"), r.account.status === "ACTIVE" && Boolean(ex.params.code_verifier) && !("client_secret" in ex.params) && st.lastAuthorize.scope === "alpha,beta");
  const a = await refreshAndCall(r.account, prof);
  assert(qname(prof, "refresh works for a public client (no secret on record)"), a.grants === 1 && a.out.status === 200 && !("client_secret" in st.last.params));
  clock.off = 0;
}

{ // qe: errors reported with HTTP 200
  const prof = PROFILES.qe;
  const st = mock.state.qe;
  ensureConfig(prof.slug);
  const before = rt.accounts.list({ provider: prof.slug }).length;
  const begin = rt.flows.begin({ provider: prof.slug, label: "bad", redirectUri: CB });
  await consent(begin.authorizeUrl);
  const err = await thrown(() => rt.flows.complete(begin.state, "not-the-code"));
  assert(qname(prof, "error body on HTTP 200 is an error: the exchange fails and says why"), err instanceof ConnectorError && /bad_verification_code/.test(err.message), err?.message);
  assert(qname(prof, "a failed exchange stores nothing and the state is spent"), rt.accounts.list({ provider: prof.slug }).length === before && (await thrown(() => rt.flows.complete(begin.state, "again")))?.message.includes("unknown or already-used"));
  const r = await connectOAuth(prof.slug, { label: "main" });
  assert(qname(prof, "the good path still completes"), r.account.status === "ACTIVE");
  st.grantRevoked = true;
  clock.off += H2;
  const e2 = await thrown(() => callMe(r.account, prof.slug));
  assert(qname(prof, "invalid_grant delivered with HTTP 200 still marks the account EXPIRED"), e2?.code === "SB_ACCOUNT_EXPIRED" && rt.accounts.require(r.account.id).status === "EXPIRED");
  clock.off = 0;
  st.grantRevoked = false;
}

{ // qf: https-only redirect
  const prof = PROFILES.qf;
  const st = mock.state.qf;
  ensureConfig(prof.slug);
  const refused = await thrown(() => rt.flows.begin({ provider: prof.slug, redirectUri: "http://127.0.0.1:8088/oauth/callback" }));
  assert(qname(prof, "a plain http loopback redirect is refused, naming the HTTPS requirement and the way out"), refused instanceof ConnectorError && /HTTPS/.test(refused.message) && /tunnel/.test(refused.message), refused?.message?.slice(0, 120));
  assert(qname(prof, "the refusal wrote no pending flow"), rt.flows.pending().every((p) => p.provider !== prof.slug) && st.c.authorize === 0);
  const tunnel = "https://tunnel.example/oauth/callback";
  const cfg2 = ensureConfig(prof.slug, { redirect_uri: tunnel });
  const begin = rt.flows.begin({ provider: prof.slug, label: "main", redirectUri: CB, authConfigId: cfg2.id });
  assert(qname(prof, "with an https redirect registered in the auth config the flow begins, and uses it"), new URL(begin.authorizeUrl).searchParams.get("redirect_uri") === tunnel);
  const c = await consent(begin.authorizeUrl);
  assert(qname(prof, "the provider redirects to the https URL (the oracle does not follow it)"), c.status === 302 && c.location.startsWith(tunnel));
  const done = await rt.flows.complete(c.state, c.code);
  const cb = await callMe(done.account, prof.slug);
  assert(qname(prof, "completing the callback delivered at the https URL gives an ACTIVE account that can call"), done.account.status === "ACTIVE" && cb.status === 200);
  const a = await refreshAndCall(done.account, prof);
  assert(qname(prof, "refresh works"), a.grants === 1 && a.out.status === 200);
  clock.off = 0;
}

{ // qg: extra auth params, client_key instead of client_id, extra token params, non-JSON answer
  const prof = PROFILES.qg;
  const st = mock.state.qg;
  ensureConfig(prof.slug);
  const r = await connectOAuth(prof.slug, { label: "main" });
  const ex = { ...st.last };
  assert(qname(prof, "extra authorize params (access_type, prompt) and client_key are sent"), r.account.status === "ACTIVE" && st.lastAuthorize.access_type === "offline" && st.lastAuthorize.prompt === "consent" && st.lastAuthorize.client_key === CLIENT_ID && !("client_id" in st.lastAuthorize));
  assert(qname(prof, "the token request uses client_key and the extra token parameter, and asks for form-encoded answers"), ex.params.client_key === CLIENT_ID && !("client_id" in ex.params) && ex.params.audience === "api" && !String(ex.headers.accept ?? "").includes("json"));
  const a = await refreshAndCall(r.account, prof);
  assert(qname(prof, "a form-encoded answer is understood and refresh keeps client_key and audience"), a.grants === 1 && a.out.status === 200 && st.last.params.client_key === CLIENT_ID && st.last.params.audience === "api");
  clock.off = 0;
}

{ // qh: Slack-shaped answers (ok:false on 200), secret not required with PKCE
  const prof = PROFILES.qh;
  const st = mock.state.qh;
  ensureConfig(prof.slug);
  const begin = rt.flows.begin({ provider: prof.slug, label: "bad", redirectUri: CB });
  await consent(begin.authorizeUrl);
  const err = await thrown(() => rt.flows.complete(begin.state, "wrong"));
  assert(qname(prof, "ok:false on HTTP 200 is reported as a Slack OAuth error"), err instanceof ConnectorError && /Slack OAuth error/.test(err.message) && /bad_verification_code/.test(err.message), err?.message);
  const r = await connectOAuth(prof.slug, { label: "main" });
  assert(qname(prof, "comma-separated scopes; completes ACTIVE with PKCE"), r.account.status === "ACTIVE" && st.lastAuthorize.scope === "chat:read,chat:write");
  const a = await refreshAndCall(r.account, prof);
  assert(qname(prof, "rotating refresh works with the Slack answer shape"), a.grants === 1 && a.out.status === 200);
  clock.off = 0;
}

{ // qi: GET token request, wrapped answer, long-lived exchange, refresh by exchange, access_token query injection
  const prof = PROFILES.qi;
  const st = mock.state.qi;
  ensureConfig(prof.slug);
  const r = await connectOAuth(prof.slug, { label: "main" });
  assert(qname(prof, "the code exchange is a GET with the parameters in the query, and the wrapped answer (data.0) is read"), st.last.method === "GET" && r.account.status === "ACTIVE");
  assert(qname(prof, "the long-lived exchange ran once and the stored expiry is the long-lived one (~60 days)"), st.c.exchange === 1 && Date.parse(r.account.expires_at) - now() > 50 * 24 * 3600 * 1000, r.account.expires_at);
  assert(qname(prof, "the exchange carried the app secret and the short-lived token as parameters"), st.lastExchange.fb_exchange_token && st.lastExchange.client_secret === CLIENT_SECRET && st.lastExchange.grant_type === "fb_exchange_token");
  const me = await callMe(r.account, prof.slug);
  const seen = mock.seen.filter((s) => s.slug === prof.slug).at(-1);
  assert(qname(prof, "the credential travels as the access_token query parameter, not a header"), me.status === 200 && new URL(`http://x${seen.url}`).searchParams.has("access_token") && !seen.headers.authorization);
  const ex0 = st.c.exchange;
  clock.off += 5184000 * 1000 - 30 * 1000; // 30 s before the long-lived token expires: inside the refresh margin
  const me2 = await callMe(r.account, prof.slug);
  assert(qname(prof, "refresh by exchange: inside the margin before expiry the still-valid token is traded for a new one"), me2.status === 200 && st.c.exchange === ex0 + 1 && st.c.refresh_token === 0);
  clock.off += 80 * 24 * 3600 * 1000;
  const e = await thrown(() => callMe(r.account, prof.slug));
  assert(qname(prof, "an expired token cannot be exchanged: EXPIRED with the reconnect command, no exchange attempted"), e?.code === "SB_ACCOUNT_EXPIRED" && st.c.exchange === ex0 + 1 && /switchboard connect q-get-exchange --account main/.test(e.message), e?.message);
  clock.off = 0;
}

{ // qj: client credentials
  const prof = PROFILES.qj;
  const st = mock.state.qj;
  const cfg = ensureConfig(prof.slug);
  const r = await rt.flows.connectClientCredentials({ provider: prof.slug, authConfigId: cfg.id, label: "svc" });
  assert(qname(prof, "client-credentials grant: Basic client auth, scope sent, account ACTIVE with the service identity"), r.account.status === "ACTIVE" && r.account.mode === "oauth2_cc" && r.account.identity.external_id === "svc-account" && String(st.last.headers.authorization).startsWith("Basic ") && st.last.params.scope === "svc", JSON.stringify(st.last.params));
  clock.off += H2;
  const out = await callMe(r.account, prof.slug);
  assert(qname(prof, "when it expires the grant is simply requested again, and the call succeeds"), out.status === 200 && st.c.client_credentials === 2);
  clock.off = 0;
}

// the eight quirk profiles ADR P1 names, summarised from the checks above (each is asserted individually)
{
  const need = ["form-field client auth (q-body-pkce)", "Basic client auth (q-basic-nopkce)", "PKCE required (q-body-pkce)", "PKCE optional (q-pkce-optional)", "PKCE unsupported (q-basic-nopkce)", "space scope separator (q-body-pkce)", "comma scope separator (q-pkce-optional)", "rotating refresh (q-basic-nopkce)", "error body on HTTP 200 (q-error200)", "https redirect refusal (q-https-only)", "extra auth params (q-extra-params)"];
  note(`quirk profiles exercised: ${need.join("; ")}`);
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════
// 3. single flight
// ═════════════════════════════════════════════════════════════════════════════════════════════════════
let CRASH_BASE = null;
{
  const prof = PROFILES.qd;
  const st = mock.state.qd;
  ensureConfig(prof.slug);
  const r = await connectOAuth(prof.slug, { label: "sf" });
  const before = st.c.refresh_token;
  st.delayMs = 150;
  clock.off += H2;
  const results = await Promise.all(Array.from({ length: 25 }, () => callMe(r.account, prof.slug)));
  st.delayMs = 0;
  assert("single flight: 25 concurrent calls with an expired token make exactly ONE token request", st.c.refresh_token - before === 1, `${st.c.refresh_token - before} token requests`);
  assert("single flight: all 25 calls succeed", results.length === 25 && results.every((x) => x.status === 200 && x.json?.id === "u1"));
  assert("single flight: the rotated refresh token was persisted once, the account is ACTIVE", unsealRecord(readAccountsFile().accounts[r.account.id]).refresh_token === st.lastRefresh && rt.accounts.require(r.account.id).status === "ACTIVE");
  clock.off = 0;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════
// 4. crash safety: a process killed right after it received a rotated refresh token loses nothing
// ═════════════════════════════════════════════════════════════════════════════════════════════════════
{
  const prof = PROFILES.qd;
  const st = mock.state.qd;
  const r = await connectOAuth(prof.slug, { label: "crash" });
  const gen1 = st.lastRefresh;
  const childFile = join(WORK, "crash-child.mjs");
  writeFileSync(
    childFile,
    `import { pathToFileURL } from "node:url";
const dist = process.env.SB_DIST;
const { Connectors } = await import(pathToFileURL(dist + "/connectors/index.js").href);
const { Vault } = await import(pathToFileURL(dist + "/vault.js").href);
const rt = new Connectors({ vault: new Vault("encrypted-file"), network: { allow_private: ["127.0.0.1"] }, clock: () => Date.now() + ${H2} });
await rt.accounts.authFetch(process.env.SB_ACCOUNT, process.env.SB_HANG_URL);
`,
  );
  let child;
  let diskAtUse;
  const hung = new Promise((resolve) => {
    mock.hooks.onHang = async () => {
      // The new access token has just reached the provider. What does the disk hold right now?
      const rec = unsealRecord(readAccountsFile().accounts[r.account.id]);
      diskAtUse = rec.refresh_token;
      child.kill("SIGKILL");
      resolve();
    };
  });
  child = track(spawn(process.execPath, [childFile], { env: { ...process.env, SB_DIST: join(ROOT, "dist"), SB_ACCOUNT: r.account.id, SB_HANG_URL: `${mock.base}/${prof.slug}/api/hang` }, stdio: ["ignore", "pipe", "pipe"] }));
  child.stdout.on("data", (d) => leak("crash child stdout", d));
  child.stderr.on("data", (d) => leak("crash child stderr", d));
  const exited = new Promise((resolve) => child.once("exit", resolve));
  const timeout = sleep(90_000).then(() => "timeout");
  const winner = await Promise.race([hung.then(() => "hung"), exited.then(() => "exited"), timeout]);
  await Promise.race([exited, sleep(10_000)]);
  mock.hooks.onHang = null;
  assert("crash: the child reached the provider with its refreshed token, then was killed mid-call", winner === "hung" && child.killed, winner);
  assert("crash: at the moment the new access token was first used, the rotated refresh token was already on disk", diskAtUse === st.lastRefresh && diskAtUse !== gen1, "disk refresh == provider's latest, != first generation");
  // a new process (new instance) later: it must be able to refresh from what the dead one left
  const rt2 = new Connectors({ vault, network: NETWORK, clock: () => Date.now() + 2 * H2 });
  const before = st.c.refresh_token;
  const res = await rt2.accounts.authFetch(r.account.id, apiMe(prof.slug));
  assert("crash: after the kill, a new process refreshes with the persisted rotated token and its call succeeds", res.status === 200 && st.c.refresh_token - before === 1);
  const replay = await fetch(`${mock.base}/${prof.slug}/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: gen1, client_id: CLIENT_ID, client_secret: CLIENT_SECRET }) });
  assert("crash: negative control, the first-generation refresh token is dead at the provider (rotation is real)", replay.status === 400);
  CRASH_BASE = r.account.id;
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════
// 5. invalid_grant: EXPIRED in the same call, one audit row, the reconnect command, no retry storm
// ═════════════════════════════════════════════════════════════════════════════════════════════════════
{
  const prof = PROFILES.qd;
  const st = mock.state.qd;
  const r = await connectOAuth(prof.slug, { label: "doomed" });
  st.grantRevoked = true;
  clock.off += H2;
  const before = st.c.refresh_token;
  const err = await thrown(() => callMe(r.account, prof.slug));
  const rows = auditRows().filter((x) => x.tool === "account_expired" && String(x.reason).includes(r.account.id));
  assert("invalid_grant: the SAME call fails with SB_ACCOUNT_EXPIRED", err instanceof ConnectorError && err.code === "SB_ACCOUNT_EXPIRED", err?.code);
  assert("invalid_grant: the error carries the exact reconnect command", err?.message.includes(`switchboard connect ${prof.slug} --account doomed`) && err.detail.reconnect === `switchboard connect ${prof.slug} --account doomed`, err?.message);
  assert("invalid_grant: the account is EXPIRED in the store", rt.accounts.require(r.account.id).status === "EXPIRED");
  assert("invalid_grant: exactly one account_expired audit row, with the SB_ACCOUNT_EXPIRED code", rows.length === 1 && rows[0].error_code === "SB_ACCOUNT_EXPIRED" && rows[0].decision === "deny", `${rows.length} rows`);
  const afterFirst = st.c.refresh_token;
  const storm = await Promise.all(Array.from({ length: 10 }, () => thrown(() => callMe(r.account, prof.slug))));
  for (let i = 0; i < 5; i++) await thrown(() => callMe(r.account, prof.slug));
  assert("invalid_grant: no retry storm, 15 further calls make zero token requests", st.c.refresh_token === afterFirst && afterFirst - before === 1, `${st.c.refresh_token - before} total`);
  assert("invalid_grant: every further call fails the same way, and still only one audit row", storm.every((e) => e?.code === "SB_ACCOUNT_EXPIRED") && auditRows().filter((x) => x.tool === "account_expired" && String(x.reason).includes(r.account.id)).length === 1);
  // disable then enable returns an EXPIRED account to EXPIRED, not ACTIVE
  rt.accounts.disable(r.account.id);
  const back = rt.accounts.enable(r.account.id);
  assert("disable/enable: an EXPIRED account comes back EXPIRED", back.status === "EXPIRED");
  // reconnect heals it in place
  st.grantRevoked = false;
  clock.off = 0;
  const again = await connectOAuth(prof.slug, { label: "doomed" });
  assert("reconnect: the same label keeps the account id and returns it to ACTIVE", again.account.id === r.account.id && again.account.status === "ACTIVE" && !again.account.status_reason);
  const okAgain = await callMe(again.account, prof.slug);
  assert("reconnect: the healed account calls the API again", okAgain.status === 200);
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════
// 6. revoke
// ═════════════════════════════════════════════════════════════════════════════════════════════════════
{
  const prof = PROFILES.qa;
  const st = mock.state.qa;
  const r = await connectOAuth(prof.slug, { label: "revme" });
  const access = unsealRecord(readAccountsFile().accounts[r.account.id]).access_token;
  const res = await rt.accounts.revoke(r.account.id);
  assert("revoke: the provider's revoke endpoint was called with the token and the app credentials", st.c.revoke === 1 && st.lastRevoke.params.token === access && st.lastRevoke.params.client_id === CLIENT_ID && st.lastRevoke.params.client_secret === CLIENT_SECRET && res.provider_revoked === true);
  const file = readAccountsFile().accounts[r.account.id];
  assert("revoke: the sealed token is deleted from the store and the status is REVOKED", file.status === "REVOKED" && !("token" in file) && res.account.has_token === false);
  const dead = await fetch(apiMe(prof.slug), { headers: { authorization: `Bearer ${access}` } });
  assert("revoke: the provider no longer accepts the old access token (negative control)", dead.status === 401);
  const e = await thrown(() => callMe(r.account, prof.slug));
  assert("revoke: using a revoked account fails with SB_ACCOUNT_REVOKED and the reconnect command", e?.code === "SB_ACCOUNT_REVOKED" && e.message.includes("switchboard connect q-body-pkce --account revme"));
  const again = await rt.accounts.revoke(r.account.id);
  assert("revoke: revoking twice is harmless and calls the provider only once", again.provider_revoked === null && st.c.revoke === 1);
  assert("revoke: an account_revoked audit row was written", auditRows().some((x) => x.tool === "account_revoked" && String(x.reason).includes(r.account.id)));

  const pb = PROFILES.qb;
  const sb = mock.state.qb;
  const rb = await connectOAuth(pb.slug, { label: "revbasic" });
  await rt.accounts.revoke(rb.account.id);
  assert("revoke: with Basic revoke auth the app credentials travel in the header", String(sb.lastRevoke.headers.authorization).startsWith("Basic ") && !("client_secret" in sb.lastRevoke.params));
  const rb2 = await connectOAuth(pb.slug, { label: "revfail" });
  sb.revokeStatus = 500;
  const failed = await rt.accounts.revoke(rb2.account.id);
  sb.revokeStatus = 200;
  assert("revoke: when the provider call fails the credential is still deleted locally, and the result says the provider side failed", failed.provider_revoked === false && failed.account.status === "REVOKED" && !("token" in readAccountsFile().accounts[rb2.account.id]) && Boolean(failed.provider_error));
  const pd = PROFILES.qd;
  const rd = await connectOAuth(pd.slug, { label: "revnone" });
  const sd = mock.state.qd;
  await rt.accounts.revoke(rd.account.id);
  assert("revoke: a public revoke endpoint receives only the token", sd.lastRevoke.params.token && !("client_secret" in sd.lastRevoke.params) && !sd.lastRevoke.headers.authorization);
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════
// pending flows: expiry, cancel, probe failure, identity guard
// ═════════════════════════════════════════════════════════════════════════════════════════════════════
{
  const prof = PROFILES.qa;
  const countFor = () => rt.accounts.list({ provider: prof.slug }).length;
  const n0 = countFor();
  const begin = rt.flows.begin({ provider: prof.slug, label: "ttl", redirectUri: CB });
  assert("pending: a begun flow is listed with a 10 minute window and no secret", rt.flows.pending().some((p) => p.provider === prof.slug && p.label === "ttl" && p.expires_at - p.created_at === 10 * 60 * 1000));
  const c = await consent(begin.authorizeUrl);
  clock.off += 10 * 60 * 1000 + 1000;
  const err = await thrown(() => rt.flows.complete(c.state, c.code));
  assert("pending: after 10 minutes the callback is refused as expired", err?.message.includes("state expired"), err?.message);
  assert("pending: an expired flow stores nothing and is gone", countFor() === n0 && rt.flows.pending().every((p) => p.label !== "ttl"));
  clock.off = 0;
  const b2 = rt.flows.begin({ provider: prof.slug, label: "cancelled", redirectUri: CB });
  const cancelled = rt.flows.cancel(b2.state);
  const c2 = await consent(b2.authorizeUrl);
  const err2 = await thrown(() => rt.flows.complete(c2.state, c2.code));
  assert("pending: a cancelled flow stores nothing and its callback is refused", cancelled === true && err2?.message.includes("unknown or already-used") && countFor() === n0);
  const stateFile = JSON.parse(readFileSync(join(HOME, "connectors", "pending.json"), "utf8"));
  assert("pending: the PKCE verifier on disk is sealed, not readable text", Object.values(stateFile.flows).every((f) => !f.verifier || (typeof f.verifier === "object" && "iv" in f.verifier && !JSON.stringify(f).includes("code_verifier"))));

  const ghostErr = await thrown(() => connectOAuth(prof.slug, { label: "ghost", user: "ghost" }));
  assert("probe failure: a credential whose identity probe fails is NOT stored", ghostErr instanceof ConnectorError && ghostErr.code === "SB_CONNECT_FAILED" && /identity probe failed/.test(ghostErr.message) && !rt.accounts.list({ provider: prof.slug }).some((a) => a.label === "ghost"), ghostErr?.message);
  assert("probe failure: the provider echoed the token in its error body, and the message does not contain it", ![...SECRETS].some((s) => ghostErr?.message.includes(s)));

  const pd = PROFILES.qd;
  const g1 = await connectOAuth(pd.slug, { label: "guard", user: "u1" });
  const sealedBefore = JSON.stringify(readAccountsFile().accounts[g1.account.id].token);
  const swap = await thrown(() => connectOAuth(pd.slug, { label: "guard", user: "u2" }));
  assert("identity guard: reconnecting a label as a DIFFERENT account is refused, naming both", swap instanceof ConnectorError && /already belongs to User u1/.test(swap.message) && /User u2/.test(swap.message), swap?.message);
  assert("identity guard: nothing changed in the store", JSON.stringify(readAccountsFile().accounts[g1.account.id].token) === sealedBefore && rt.accounts.require(g1.account.id).identity.external_id === "u1");
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════
// multi-account, default, binding seam, disable / enable
// ═════════════════════════════════════════════════════════════════════════════════════════════════════
{
  const prof = PROFILES.qc;
  const w = await connectOAuth(prof.slug, { label: "work", user: "alice" });
  const h = await connectOAuth(prof.slug, { label: "home", user: "bob" });
  const mine = rt.accounts.list({ provider: prof.slug });
  assert("multi-account: several accounts connect for one provider, each with its own identity", mine.filter((a) => ["work", "home"].includes(a.label)).length === 2 && w.account.identity.external_id === "alice" && h.account.identity.external_id === "bob");
  const firstDefault = rt.accounts.defaultFor(prof.slug);
  assert("multi-account: the provider has a default (the first connected)", firstDefault && mine[0].id === firstDefault.id);
  rt.accounts.setDefault(`${prof.slug}/home`);
  assert("multi-account: the default can be changed, and provider/label addresses an account", rt.accounts.defaultFor(prof.slug).id === h.account.id && rt.accounts.find(`${prof.slug}/work`).id === w.account.id);
  assert("multi-account: with no hint a call resolves to the default; an explicit account wins", rt.accounts.resolveForCall(prof.slug).id === h.account.id && rt.accounts.resolveForCall(prof.slug, { account: "work" }).id === w.account.id);
  rt.accounts.setBindingResolver(({ provider, client }) => (provider === prof.slug && client === "daena" ? "work" : undefined));
  assert("binding seam: an injected resolver picks the account per client; others fall back to the default", rt.accounts.resolveForCall(prof.slug, { client: "daena" }).id === w.account.id && rt.accounts.resolveForCall(prof.slug, { client: "codex" }).id === h.account.id);
  const echoW = await (await rt.accounts.authFetch(rt.accounts.resolveForCall(prof.slug, { client: "daena" }).id, `${mock.base}/${prof.slug}/api/echo`)).json();
  const echoH = await (await rt.accounts.authFetch(rt.accounts.resolveForCall(prof.slug, { client: "codex" }).id, `${mock.base}/${prof.slug}/api/echo`)).json();
  assert("binding seam: two clients bound to different accounts make the provider see different tokens", echoW.user === "alice" && echoH.user === "bob" && echoW.headers.authorization !== echoH.headers.authorization);
  rt.accounts.setBindingResolver(undefined);
  const noAcct = await thrown(() => rt.accounts.resolveForCall("q-https-only", { account: "ca_NOPE" }));
  assert("multi-account: an unknown account is a clear error", noAcct?.code === "SB_ACCOUNT_NOT_FOUND");
  await rt.accounts.revoke(h.account.id);
  const stillHome = rt.accounts.resolveForCall(prof.slug);
  const refusedHome = await thrown(() => callMe(stillHome, prof.slug));
  assert("default: when the default account is revoked, calls report THAT account's state instead of silently using another identity", stillHome.id === h.account.id && refusedHome?.code === "SB_ACCOUNT_REVOKED");
  rt.accounts.setDefault(`${prof.slug}/work`);

  const tg = await connectOAuth(prof.slug, { label: "toggle", user: "carol" });
  const disabled = rt.accounts.disable(tg.account.id);
  const e = await thrown(() => callMe(tg.account, prof.slug));
  assert("disable: a disabled account refuses use with SB_ACCOUNT_DISABLED and the enable command, but keeps its credential", disabled.status === "INACTIVE" && e?.code === "SB_ACCOUNT_DISABLED" && e.message.includes(`switchboard accounts enable ${tg.account.id}`) && rt.accounts.summaries().find((a) => a.id === tg.account.id).has_token === true);
  const enabled = rt.accounts.enable(tg.account.id);
  const ok = await callMe(tg.account, prof.slug);
  assert("enable: the account works again with the credential it kept", enabled.status === "ACTIVE" && ok.status === 200 && ok.json.id === "carol");
  assert("lifecycle audit rows exist for connect, disable, enable", ["account_connected", "account_disabled", "account_enabled"].every((t) => auditRows().some((x) => x.tool === t && String(x.reason).includes(tg.account.id))));
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════
// the host lock and what a caller cannot override
// ═════════════════════════════════════════════════════════════════════════════════════════════════════
{
  const prof = PROFILES.qa;
  const acct = (await connectOAuth(prof.slug, { label: "locks" })).account;
  const seenBefore = mock.seen.length;
  const e = await thrown(() => rt.accounts.authFetch(acct.id, `http://127.0.0.2:${mock.port}/${prof.slug}/api/me`));
  assert("host lock: a URL outside the provider's api_hosts is refused with SB_HOST_NOT_ALLOWED before any request", e?.code === "SB_HOST_NOT_ALLOWED" && mock.seen.length === seenBefore && /was not sent/.test(e.message), e?.message);
  const e2 = await thrown(() => rt.accounts.authFetch(acct.id, "https://attacker.example/steal"));
  assert("host lock: an arbitrary https host is refused too", e2?.code === "SB_HOST_NOT_ALLOWED");
  const echo = await (await rt.accounts.authFetch(acct.id, `${mock.base}/${prof.slug}/api/echo`, { headers: { Authorization: "Bearer evil-caller-token", "X-Extra": "1" } })).json();
  assert("a caller-supplied Authorization header cannot replace the account's credential; other headers pass", String(echo.headers.authorization).startsWith("Bearer at-q-body-pkce") && echo.headers["x-extra"] === "1");
  if (mock2) {
    mock.capture.length = 0;
    const res = await rt.accounts.authFetch(acct.id, `${mock.base}/${prof.slug}/api/to-other-origin`);
    const hit = mock.capture.find((c) => c.origin2);
    assert("redirect: following a redirect to another origin never carries the token", res.status === 200 && Boolean(hit) && !hit.headers.authorization && !hit.url.includes("access_token"), hit ? "arrived without credentials" : "no request arrived");
  } else console.log("SKIP  redirect: this machine cannot bind 127.0.0.2, so the cross-origin check did not run (not counted)");
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════
// token-style connects: API key, bearer / PAT, basic, multi-part key, no probe, unsupported mode
// ═════════════════════════════════════════════════════════════════════════════════════════════════════
{
  const cases = [
    ["t-apikey", { api_key: KEY_API }, "key-user", "API key sent in the X-Api-Key header"],
    ["t-bearer", { token: KEY_BEARER }, "pat-user", "bearer / PAT sent as Authorization: Bearer"],
    ["t-basic", { username: KEY_BASIC_USER, password: KEY_BASIC_PASS }, "basic-user", "basic auth sent as Authorization: Basic base64(user:password)"],
    ["t-multi", { key_id: KEY_ID, key_secret: KEY_SECRET }, "multi-user", "a two-part key rendered through the template (Key id:secret)"],
  ];
  for (const [slug, fields, who, what] of cases) {
    const r = await rt.flows.connectSecret({ provider: slug, label: "k", fields });
    const res = await rt.accounts.authFetch(r.account.id, apiMe(slug));
    const body = await res.json();
    assert(`secret connect ${slug}: ${what}; probe passes, account ACTIVE`, r.account.status === "ACTIVE" && r.account.identity.external_id === who && body.id === who && Boolean(r.account.last_probe_at), `${r.account.status}`);
  }
  const wrong = await thrown(() => rt.flows.connectSecret({ provider: "t-apikey", label: "wrong", fields: { api_key: "definitely-the-wrong-key" } }));
  assert("secret connect: a key the provider rejects fails the connect and stores nothing", wrong instanceof ConnectorError && wrong.code === "SB_CONNECT_FAILED" && !rt.accounts.list({ provider: "t-apikey" }).some((a) => a.label === "wrong"), wrong?.message);
  const unknownField = await thrown(() => rt.flows.connectSecret({ provider: "t-apikey", label: "x", fields: { api_key: KEY_API, extra: "1" } }));
  const missing = await thrown(() => rt.flows.connectSecret({ provider: "t-basic", label: "x", fields: { username: "u" } }));
  assert("secret connect: an unknown field and a missing required field are refused", unknownField?.code === "SB_CONNECTOR_CONFIG" && missing?.code === "SB_CONNECTOR_CONFIG");
  const custom = await thrown(() => rt.flows.connectSecret({ provider: "t-custom", authId: "custom", label: "x", fields: { token: "abc" } }));
  assert("a mode this build does not drive (custom, oauth1) is refused honestly, not half-run", custom?.code === "SB_CONNECTOR_CONFIG" && /does not drive/.test(custom.message), custom?.message);
  const np = await rt.flows.connectSecret({ provider: "t-noprobe", label: "np", fields: { api_key: "any-key-works-here-1234" } });
  assert("no probe defined: the account is stored ACTIVE but with unknown identity and no probe time (honest, not 'verified')", np.account.status === "ACTIVE" && np.account.identity.external_id === "unknown" && !np.account.last_probe_at);
  const badLabel = await thrown(() => rt.flows.connectSecret({ provider: "t-apikey", label: "has space", fields: { api_key: KEY_API } }));
  assert("labels are restricted to a safe alphabet", badLabel?.code === "SB_CONNECTOR_CONFIG");
  const none = await thrown(() => rt.flows.begin({ provider: "no-such-provider", redirectUri: CB }));
  assert("an unknown provider is refused by name", /unknown OAuth provider 'no-such-provider'/.test(none?.message ?? ""));
  const noCfg = await thrown(() => rt.flows.begin({ provider: "github", redirectUri: CB }));
  assert("an OAuth connect with no registered app says how to register one, with the owner setup link", noCfg?.code === "SB_CONNECTOR_CONFIG" && /authconfig add github/.test(noCfg.message) && /github\.com\/settings\/developers/.test(noCfg.message), noCfg?.message?.slice(0, 160));
  const secretRefused = await thrown(() => rt.authConfigs.add({ provider: "q-body-pkce", client_id_ref: "mock_client_id", client_secret_ref: CLIENT_SECRET }));
  const refMsg = secretRefused?.message ?? "";
  assert("authconfig: a raw secret pasted where a reference belongs is refused, stored nowhere and never echoed", secretRefused?.code === "SB_CONNECTOR_CONFIG" && !refMsg.includes(CLIENT_SECRET) && !readFileSync(join(HOME, "connectors", "authconfigs.json"), "utf8").includes(CLIENT_SECRET));
  const fileText = readFileSync(join(HOME, "connectors", "authconfigs.json"), "utf8");
  assert("authconfig: the file holds references and ids, never a secret value", ![...SECRETS].some((s) => fileText.includes(s)) && fileText.includes("${vault:mock_client_secret}"));
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════
// token import
// ═════════════════════════════════════════════════════════════════════════════════════════════════════
{
  const prof = PROFILES.qd;
  const st = mock.state.qd;
  const grant = issue(prof, st, "imported-user", "read write");
  const imp = await rt.flows.importToken({ provider: prof.slug, label: "imp", access_token: grant.access_token, refresh_token: grant.refresh_token, expires_in: 3600 });
  assert("import: an OAuth token the owner already holds is adopted, probed, and marked as imported", imp.account.status === "ACTIVE" && imp.account.source === "import" && imp.account.identity.external_id === "imported-user");
  const a = await refreshAndCall(imp.account, prof);
  assert("import: with its refresh token and the registered app, the imported account refreshes like any other", a.grants === 1 && a.out.status === 200);
  clock.off = 0;
  const qa = PROFILES.qa;
  const grant2 = issue(qa, mock.state.qa, "bare-user", "read");
  const bare = await rt.flows.importToken({ provider: qa.slug, label: "bare", access_token: grant2.access_token, expires_in: 100 });
  clock.off += 3600 * 1000;
  const expired = await thrown(() => callMe(bare.account, qa.slug));
  assert("import: a token with no refresh token that has expired means EXPIRED with the reconnect command, not a silent failure", expired?.code === "SB_ACCOUNT_EXPIRED" && rt.accounts.require(bare.account.id).status === "EXPIRED");
  clock.off = 0;
  const empty = await thrown(() => rt.flows.importToken({ provider: qa.slug, label: "e", access_token: "  " }));
  assert("import: an empty token is refused", empty?.code === "SB_CONNECTOR_CONFIG");
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════
// the real loopback callback on the dashboard port, and the CLI
// ═════════════════════════════════════════════════════════════════════════════════════════════════════
const portA = await freePort();
const portB = await freePort();
const cfgYaml = (port) => `gateway:
  transport: [http]
  http:
    host: 127.0.0.1
    port: ${port}
    require_auth: auto
  tool_exposure: namespaced
  default_policy: read
vault:
  backend: encrypted-file
servers: []
settings:
  network:
    allow_private: ["127.0.0.1", "127.0.0.2"]
`;
const cfgA = join(WORK, "cfg-a.yaml");
const cfgB = join(WORK, "cfg-b.yaml");
writeFileSync(cfgA, cfgYaml(portA));
writeFileSync(cfgB, cfgYaml(portB));

const CLI = join(ROOT, "dist", "cli.js");
function startCli(args, cfg, stdin) {
  const child = track(spawn(process.execPath, [CLI, "--config", cfg, ...args], { env: { ...process.env }, stdio: ["pipe", "pipe", "pipe"] }));
  const state = { stdout: "", stderr: "", child };
  child.stdout.on("data", (d) => {
    state.stdout += d;
    leak("cli stdout", d);
  });
  child.stderr.on("data", (d) => {
    state.stderr += d;
    leak("cli stderr", d);
  });
  child.stdin.end(stdin ?? "");
  state.done = new Promise((resolve) => {
    const timer = setTimeout(() => child.kill("SIGKILL"), 150_000);
    child.once("exit", (code) => {
      clearTimeout(timer);
      resolve(code);
    });
  });
  state.waitFor = async (rx, ms = 90_000) => {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      const m = rx.exec(state.stdout + state.stderr);
      if (m) return m;
      await sleep(100);
    }
    return null;
  };
  return state;
}
const runCli = async (args, cfg, stdin) => {
  const s = startCli(args, cfg, stdin);
  s.code = await s.done;
  return s;
};

const gwCfg = {
  gateway: { transport: ["http"], http: { host: "127.0.0.1", port: portA, require_auth: "auto" }, tool_exposure: "namespaced", default_policy: "read" },
  vault: { backend: "encrypted-file" },
  servers: [],
  settings: { network: NETWORK },
};
const gateway = new Gateway(gwCfg);
const dash = await startDashboard(gateway, gwCfg);
const DASH = `http://127.0.0.1:${portA}`;
let owner = { hdr: {}, hdrC: {} };
try {
  owner = await ownerSession(portA);
  assert("dashboard: an owner session is established for the admin API (header session minted by the gateway after its presence check, no cookie)", owner.status === 200 && owner.sid.length > 10 && owner.csrf.length > 10 && !owner.setCookie);

  // 1) connect through the dashboard's own API and callback (the loopback callback on the dashboard port)
  const prof = PROFILES.qa;
  const startRes = await fetch(`${DASH}/api/connect/${prof.slug}`, { method: "POST", headers: owner.hdrC });
  const start = await startRes.json();
  assert("dashboard: POST /api/connect/:provider returns a consent URL whose redirect is the dashboard's /oauth/callback", startRes.status === 200 && new URL(start.authorizeUrl).searchParams.get("redirect_uri") === `${DASH}/oauth/callback`, JSON.stringify(start).slice(0, 120));
  const c = await consent(start.authorizeUrl, "dash-user");
  const cb = await fetch(c.location); // the browser's redirect: no cookie
  const cbText = await cb.text();
  leak("/oauth/callback page", cbText);
  const viaDash = rt.accounts.find(`${prof.slug}/default`);
  assert("dashboard: the provider's redirect to /oauth/callback completes the flow; the account shows up for a separate instance (shared files)", cb.status === 200 && viaDash?.status === "ACTIVE" && viaDash.identity.external_id === "dash-user", `${cb.status}`);
  const replay = await fetch(c.location);
  leak("/oauth/callback replay", await replay.text());
  assert("dashboard: the same callback cannot be replayed", replay.status === 400);
  const gwToken = await gateway.oauth.connectors.accounts.accessToken(viaDash.id);
  assert("dashboard: the gateway's own store can use the account (the ${oauth:...} path)", typeof gwToken === "string" && gwToken.length > 10);

  // 2) acceptance 8: a CLI revoke is seen by the running gateway
  const gwAccounts = gateway.oauth.connectors.accounts;
  const revoke = await runCli(["accounts", "revoke", viaDash.id], cfgA);
  let seen = false;
  const t0 = Date.now();
  while (Date.now() - t0 < 5000) {
    if (gwAccounts.require(viaDash.id).status === "REVOKED") {
      seen = true;
      break;
    }
    await sleep(50);
  }
  const afterErr = await thrown(() => gwAccounts.accessToken(viaDash.id));
  assert("live reload: `switchboard accounts revoke` run in another process is seen by the running gateway within 5 s", revoke.code === 0 && seen && Date.now() - t0 < 5000, `${Date.now() - t0} ms; exit ${revoke.code}; ${(revoke.stderr + revoke.stdout).replace(/\u001b\[[0-9;]*m/g, "").slice(-400)}`);
  assert("live reload: the running gateway then refuses the revoked account (SB_ACCOUNT_REVOKED)", afterErr?.code === "SB_ACCOUNT_REVOKED");
  assert("CLI revoke: said what happened to the provider side and deleted the credential", /revoked/i.test(revoke.stdout) && /provider confirmed/i.test(revoke.stdout));

  // 3) CLI connect while a gateway holds the port: the gateway completes the flow from the persisted pending state
  const pd = PROFILES.qd;
  const cli1 = startCli(["connect", pd.slug, "--account", "viaCli"], cfgA);
  const m = await cli1.waitFor(/(http:\/\/127\.0\.0\.1:\d+\/q-rotating\/authorize\?[^\s]+)/);
  assert("CLI connect: prints the consent URL for the provider", Boolean(m), (cli1.stderr + cli1.stdout).replace(/\u001b\[[0-9;]*m/g, "").slice(-500));
  const waitMsg = await cli1.waitFor(/served by a running gateway/);
  const cc = await consent(m[1], "cli-user");
  const cbRes = await fetch(cc.location);
  leak("/oauth/callback page (cli flow)", await cbRes.text());
  const code1 = await cli1.done;
  assert("CLI connect: with the dashboard on the port, the CLI waits and the gateway completes the flow (pending state persisted across processes)", Boolean(waitMsg) && cbRes.status === 200 && code1 === 0 && /connected q-rotating\/viaCli/.test(cli1.stdout), `exit ${code1}`);
  assert("CLI connect: the account exists with the identity the provider reported", rt.accounts.find(`${pd.slug}/viaCli`)?.identity.external_id === "cli-user");

  // 4) CLI connect owning the loopback listener itself
  const pc = PROFILES.qc;
  const cli2 = startCli(["connect", pc.slug, "--account", "cliLoop"], cfgB);
  const m2 = await cli2.waitFor(/(http:\/\/127\.0\.0\.1:\d+\/q-pkce-optional\/authorize\?[^\s]+)/);
  const c2 = await consent(m2[1], "loop-user");
  assert("CLI connect: the redirect points at the CLI's own loopback listener", c2.location.startsWith(`http://127.0.0.1:${portB}/oauth/callback`));
  await sleep(200);
  const cb2 = await fetch(c2.location);
  leak("cli loopback page", await cb2.text());
  const code2 = await cli2.done;
  assert("CLI connect: the CLI catches the callback itself, completes, prints the account and exits 0", cb2.status === 200 && code2 === 0 && /connected q-pkce-optional\/cliLoop/.test(cli2.stdout) && rt.accounts.find(`${pc.slug}/cliLoop`)?.status === "ACTIVE");

  // 5) token connects, authconfig and account management through the CLI
  const bad = await runCli(["authconfig", "add", prof.slug, "--client-id-ref", "mock_client_id", "--client-secret-ref", CLIENT_SECRET], cfgB);
  assert("CLI authconfig add: a raw secret in the reference flag is refused (exit 1), not echoed and not saved", bad.code === 1 && !bad.stdout.includes(CLIENT_SECRET) && !bad.stderr.includes(CLIENT_SECRET) && !readFileSync(join(HOME, "connectors", "authconfigs.json"), "utf8").includes(CLIENT_SECRET));
  const add = await runCli(["authconfig", "add", prof.slug, "--client-id-ref", "mock_client_id", "--client-secret-ref", "mock_client_secret", "--label", "cli app"], cfgB);
  assert("CLI authconfig add: references are accepted and saved (exit 0), the id is printed", add.code === 0 && /auth config ac_/.test(add.stdout));
  const lst = await runCli(["authconfig", "list", "--json"], cfgB);
  const cfgs = JSON.parse(lst.stdout);
  assert("CLI authconfig list --json: shows references, never values", lst.code === 0 && cfgs.some((x) => x.label === "cli app" && x.client_secret_ref === "${vault:mock_client_secret}") && !lst.stdout.includes(CLIENT_SECRET));

  const k1 = await runCli(["connect", "t-apikey", "--account", "cli-key", "--token-ref", "mock_api_key"], cfgB);
  assert("CLI connect (key by vault reference): exits 0, prints the account and 'probe passed', never the key", k1.code === 0 && /connected t-apikey\/cli-key/.test(k1.stdout) && /probe passed/.test(k1.stdout) && !k1.stdout.includes(KEY_API));
  const k2 = await runCli(["connect", "t-bearer", "--account", "cli-pat", "--token-stdin"], cfgB, KEY_BEARER + "\n");
  assert("CLI connect (token on stdin): exits 0 and the account is ACTIVE", k2.code === 0 && rt.accounts.find("t-bearer/cli-pat")?.status === "ACTIVE");
  const k3 = await runCli(["connect", "t-apikey", "--account", "cli-raw", "--token-ref", KEY_API], cfgB);
  assert("CLI connect: a raw key in --token-ref is refused (exit 1), not echoed, nothing stored", k3.code === 1 && !k3.stdout.includes(KEY_API) && !k3.stderr.includes(KEY_API) && !rt.accounts.list({ provider: "t-apikey" }).some((a) => a.label === "cli-raw"));
  const k4 = await runCli(["connect", "t-noprobe", "--account", "np-cli", "--token-ref", "mock_api_key"], cfgB);
  assert("CLI connect: a provider with no identity probe says the credential was stored but NOT verified", k4.code === 0 && /NOT verified/.test(k4.stdout));
  const k5 = await runCli(["connect", "t-multi", "--account", "cli-multi", "--field", "key_id=mock_key_id", "--field", "key_secret=mock_key_secret"], cfgB);
  assert("CLI connect: a two-part key is supplied as named vault references", k5.code === 0 && rt.accounts.find("t-multi/cli-multi")?.identity.external_id === "multi-user");
  const k6 = await runCli(["connect", "t-basic", "--account", "cli-basic", "--field", "username=mock_basic_user", "--field", "password=mock_basic_pass"], cfgB);
  assert("CLI connect: basic auth credentials from vault references", k6.code === 0 && rt.accounts.find("t-basic/cli-basic")?.identity.external_id === "basic-user");

  const lj = await runCli(["accounts", "list", "--json"], cfgB);
  const rows = JSON.parse(lj.stdout);
  assert("CLI accounts list --json: lists accounts with status and identity and no credential field", lj.code === 0 && rows.some((r) => r.label === "cli-key" && r.status === "ACTIVE") && rows.every((r) => !("token" in r)) && rows.every((r) => typeof r.has_token === "boolean"));
  const ltxt = await runCli(["accounts", "list"], cfgB);
  assert("CLI accounts list: the human table has ID, PROVIDER, LABEL, STATUS columns and marks defaults", ltxt.code === 0 && /ID\s+PROVIDER\s+LABEL\s+STATUS/.test(ltxt.stdout) && /\*/.test(ltxt.stdout));
  const show = await runCli(["accounts", "show", "t-apikey/cli-key"], cfgB);
  assert("CLI accounts show: provider/label addressing works and prints identity and scopes", show.code === 0 && /identity\s+User key-user/.test(show.stdout));
  const probe = await runCli(["accounts", "probe", "t-apikey/cli-key"], cfgB);
  assert("CLI accounts probe: runs the identity probe and reports ok (exit 0)", probe.code === 0 && /^ok:/m.test(probe.stdout));
  const dis = await runCli(["accounts", "disable", "t-apikey/cli-key"], cfgB);
  const probeDis = await runCli(["accounts", "probe", "t-apikey/cli-key"], cfgB);
  assert("CLI accounts disable: the account refuses use; a probe on it fails with exit 1 and the enable command", dis.code === 0 && probeDis.code === 1 && /accounts enable/.test(probeDis.stdout + probeDis.stderr));
  const ena = await runCli(["accounts", "enable", "t-apikey/cli-key"], cfgB);
  assert("CLI accounts enable: back to ACTIVE", ena.code === 0 && /ACTIVE/.test(ena.stdout));
  const dflt = await runCli(["accounts", "default", "t-bearer/cli-pat"], cfgB);
  assert("CLI accounts default: sets the provider default", dflt.code === 0 && rt.accounts.defaultFor("t-bearer").label === "cli-pat");
  const rv = await runCli(["accounts", "revoke", "t-apikey/cli-key"], cfgB);
  assert("CLI accounts revoke (no provider-side revoke defined): deletes the credential and says to remove the grant in the console", rv.code === 0 && /no provider-side revoke/.test(rv.stdout) && rt.accounts.find("t-apikey/cli-key")?.status === "REVOKED");
  const pl = await runCli(["providers", "list", "--json"], cfgB);
  const plist = JSON.parse(pl.stdout);
  assert("CLI providers list --json: the 12 priority providers are listed as bundled", pl.code === 0 && ["google", "meta-facebook", "meta-instagram", "linkedin", "tiktok", "x", "slack", "notion", "github", "elevenlabs", "higgsfield", "buffer"].every((s) => plist.some((p) => p.slug === s && p.bundled === true)));
  const ps = await runCli(["providers", "show", "google"], cfgB);
  assert("CLI providers show: prints the console URL, steps, the redirect URI to register (with this gateway's port) and notes", ps.code === 0 && /console\.cloud\.google\.com/.test(ps.stdout) && ps.stdout.includes(`http://127.0.0.1:${portB}/oauth/callback`) && /Testing/.test(ps.stdout));
  const unk = await runCli(["connect", "no-such-provider"], cfgB);
  assert("CLI connect: an unknown provider exits 1 with a clear message", unk.code === 1 && /unknown provider/.test(unk.stderr + unk.stdout));
  const noApp = await runCli(["connect", "github", "--auth", "oauth2"], cfgB);
  assert("CLI connect: a browser connect with no registered app stops (exit 1) and prints the owner setup steps and the redirect URI to register", noApp.code === 1 && /register your own OAuth app/.test(noApp.stdout) && /OAuth app \(browser consent\)/.test(noApp.stdout) && noApp.stdout.includes(`http://127.0.0.1:${portB}/oauth/callback`) && /authconfig add github/.test(noApp.stderr + noApp.stdout), (noApp.stdout + noApp.stderr).slice(0, 200));
  const cmdHelp = await runCli(["--help"], cfgB);
  assert("CLI: connect, accounts, authconfig and providers are registered commands", ["connect", "accounts", "authconfig", "providers"].every((c) => new RegExp(`\\n\\s+${c}\\b`).test(cmdHelp.stdout)));

  // 6) every admin JSON route is read for the canary scan, with the owner session
  const routes = ["/api/state", "/api/settings", "/api/apikeys", "/api/audit", "/api/usage", "/api/catalog", "/api/catalog/stats", "/api/toolkits", "/api/triggers", "/api/playground/tools", "/api/trigger-templates"];
  const statuses = [];
  for (const rte of routes) {
    const r = await fetch(`${DASH}${rte}`, { headers: owner.hdr });
    const t = await r.text();
    statuses.push(r.status);
    leak(`GET ${rte}`, t);
  }
  assert("dashboard: the admin JSON routes answered for the canary scan", statuses.length === routes.length && statuses.filter((s) => s === 200).length >= routes.length - 3, statuses.join(","));
  const catalog = await (await fetch(`${DASH}/api/catalog`, { headers: owner.hdr })).json();
  const entry = catalog.find((p) => p.id === prof.slug);
  assert("dashboard: /api/catalog lists the provider with its accounts (status, identity) and no credentials", Array.isArray(entry?.accounts) && entry.accounts.length >= 3 && entry.accounts.every((a) => !("token" in a) && typeof a.has_token === "boolean") && entry.hasClientId === true);
} finally {
  await dash.close();
  await gateway.shutdown();
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════
// 8. restart keeps accounts
// ═════════════════════════════════════════════════════════════════════════════════════════════════════
{
  const before = rt.accounts.list().map((a) => `${a.id}:${a.status}:${a.label}`);
  const fresh = new Connectors({ vault: new Vault("encrypted-file"), network: NETWORK, clock: now });
  const after = fresh.accounts.list().map((a) => `${a.id}:${a.status}:${a.label}`);
  assert("restart: a new process-equivalent instance sees every account with the same id, status and label", before.length > 25 && JSON.stringify(before) === JSON.stringify(after), `${before.length} accounts`);
  const sample = fresh.accounts.find("q-rotating/viaCli");
  const tok = await fresh.accounts.accessToken(sample.id);
  assert("restart: the sealed credential of a connected account still opens and is usable", typeof tok === "string" && tok.length > 10);
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════
// 7. canary secrets never leave: audit, logs, /api/* JSON, error text, CLI output; sealed on disk
// ═════════════════════════════════════════════════════════════════════════════════════════════════════
{
  const secrets = [...SECRETS];
  const find = (items) => {
    const hits = [];
    for (const { label, text } of items) for (const s of secrets) if (text.includes(s)) hits.push(`${label} contains ${s.slice(0, 18)}...`);
    return hits;
  };
  assert("canary scan: the scanner is not vacuous (a planted canary is found)", find([{ label: "planted", text: `prefix ${secrets[0]} suffix` }]).length === 1);
  const stores = [];
  for (const f of ["connectors/accounts.json", "connectors/pending.json", "connectors/authconfigs.json", "vault.json"]) {
    const p = join(HOME, f);
    if (existsSync(p)) stores.push({ label: `on disk: ${f}`, text: readFileSync(p, "utf8") });
  }
  const auditText = [auditPath, ...readdirSync(HOME).filter((n) => /^audit\.log\./.test(n)).map((n) => join(HOME, n))].filter(existsSync).map((p) => ({ label: `audit log ${p.split(/[\\/]/).pop()}`, text: readFileSync(p, "utf8") }));
  const kinds = new Set(OUTPUTS.map((o) => o.label.replace(/^GET .*/, "/api route").replace(/ \(.*\)$/, "")));
  const leaks = find(OUTPUTS);
  assert(`canary scan: ${secrets.length} secrets the provider issued or saw (tokens, codes, verifiers, keys, the client secret) appear in NONE of ${OUTPUTS.length} captured outputs`, leaks.length === 0 && OUTPUTS.length > 100, leaks.slice(0, 3).join(" | "));
  assert("canary scan: the captured outputs include engine logs, error text, CLI stdout and stderr and /api JSON (not just one source)", ["process stderr", "error text", "cli stdout", "cli stderr", "/api route"].every((k) => [...kinds].some((x) => x.startsWith(k))), [...kinds].join(", "));
  const auditLeaks = find(auditText);
  assert("canary scan: the audit log (including the account_expired, connect and revoke rows) holds no secret", auditText.length > 0 && auditLeaks.length === 0 && auditText.some((a) => a.text.includes("account_expired")), auditLeaks.join(" | "));
  const diskLeaks = find(stores);
  assert("canary scan: accounts.json, pending.json, authconfigs.json and vault.json hold no plaintext secret (everything sensitive is sealed)", stores.length >= 4 && diskLeaks.length === 0, diskLeaks.join(" | "));
  const audit = new AuditLog(HOME).verify({ all: true });
  assert("audit: the hash chain still verifies after all the connector rows", audit.ok === true && audit.rows > 20, JSON.stringify(audit.break ?? { rows: audit.rows }));
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════
// generated spec output is never committed
// ═════════════════════════════════════════════════════════════════════════════════════════════════════
{
  const gi = readFileSync(join(ROOT, ".gitignore"), "utf8");
  assert(".gitignore: has rules for generated toolkit output (/toolkits/ at the root, **/toolkits/generated/, *.generated.json)", /^\/toolkits\/\s*$/m.test(gi) && /^\*\*\/toolkits\/generated\/\s*$/m.test(gi) && /^\*\.generated\.json\s*$/m.test(gi));
  const git = spawnSync("git", ["rev-parse", "--is-inside-work-tree"], { cwd: ROOT, encoding: "utf8" });
  if (git.status === 0 && git.stdout.trim() === "true") {
    const probes = ["toolkits/generated/youtube.json", "src/connectors/toolkits/generated/gmail.json", "something.generated.json", "toolkits/youtube/discovery.json"];
    const ignored = probes.map((p) => spawnSync("git", ["check-ignore", "-q", p], { cwd: ROOT }).status === 0);
    assert("git: generated-looking paths are ignored (git check-ignore)", ignored.slice(0, 3).every(Boolean), ignored.join(","));
    const tracked = spawnSync("git", ["ls-files"], { cwd: ROOT, encoding: "utf8" }).stdout.split("\n").filter(Boolean);
    const bad = tracked.filter((f) => /(^|\/)toolkits\/generated\//.test(f) || /\.generated\.json$/.test(f) || (/^src\/connectors\/.*\.json$/.test(f) && !/^src\/connectors\/(providers|schemas|providers\/seed)\/[^/]+\.json$/.test(f) && !/^src\/connectors\/toolkits\/[a-z][a-z0-9-]*\/(overlay\.json|recipes\/[A-Za-z0-9_.-]+\.json)$/.test(f)));
    assert("git: no generated spec output and no stray JSON is tracked under src/connectors (only provider definitions, seeds, the schema, overlays and recipes)", bad.length === 0, bad.join(","));
  } else {
    console.log("SKIP  git: not inside a work tree, so the tracked-file checks did not run (the .gitignore text check above did)");
  }
}

// ═════════════════════════════════════════════════════════════════════════════════════════════════════
// a torn oauth.json is an error, never an empty store (the contract the old OAuthStore had)
// ═════════════════════════════════════════════════════════════════════════════════════════════════════
{
  const legacyPath = join(HOME, "oauth.json");
  writeFileSync(legacyPath, '{"google": {"iv":');
  const err = await thrown(() => new OAuthStore(new Vault("env"), NETWORK));
  assert("oauth.json: a torn file still throws StoreCorruptError naming it, and is left in place", err instanceof StoreCorruptError && /oauth\.json/.test(err.message) && readFileSync(legacyPath, "utf8") === '{"google": {"iv":');
  rmSync(legacyPath);
  const ok = new OAuthStore(new Vault("env"), NETWORK);
  assert("oauth.json: with no file the store starts and lists its providers (none connected through env vault)", Array.isArray(ok.catalog()) && ok.catalog().length >= 10);
}

// ── teardown ───────────────────────────────────────────────────────────────────────────────────────
await new Promise((r) => mockServer.close(r));
if (mock2) await new Promise((r) => mock2.close(r));
try {
  rmSync(WORK, { recursive: true, force: true });
  rmSync(HOME, { recursive: true, force: true });
} catch {
  /* temp leftovers are harmless */
}
process.stderr.write = realStderr;
const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
process.exit(failed.length === 0 ? 0 : 1);
