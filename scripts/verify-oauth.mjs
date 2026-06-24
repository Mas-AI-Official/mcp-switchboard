// Deterministic oracle for the built-in OAuth 2.1 + PKCE Authorization Server. Drives the
// FULL flow against the real startDashboard() wiring: AS metadata → protected-resource
// metadata → 401 challenge → DCR → authorize → consent → token → authed /mcp → bogus-token
// reject → refresh rotation → revoke. Zero deps (node stdlib + global fetch). It imports the
// built output, so run `npm run build` first, then `npm run verify:oauth`. Uses an isolated
// SWITCHBOARD_HOME temp dir and mounts no upstream servers, so it never touches real state.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash, randomBytes } from "node:crypto";

process.env.SWITCHBOARD_HOME = mkdtempSync(join(tmpdir(), "sb-oauth-"));

const { Gateway } = await import("../dist/gateway.js");
const { startDashboard } = await import("../dist/dashboard.js");

const PORT = 8099;
const PUBLIC = `http://127.0.0.1:${PORT}`; // loopback http is fine for this offline oracle
const b64url = (b) => b.toString("base64url");
const sameOrigin = (a, b) => String(a).replace(/\/+$/, "") === String(b).replace(/\/+$/, ""); // WHATWG canonicalizes issuer with a trailing slash
const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
};

const cfg = {
  gateway: { transport: ["http"], http: { host: "127.0.0.1", port: PORT, require_auth: "auto" }, tool_exposure: "namespaced", default_policy: "read" },
  vault: { backend: "encrypted-file" },
  servers: [],
  settings: { oauth_server: { enabled: true, public_url: PUBLIC, access_token_ttl: 3600, refresh_token_ttl: 1209600, consent: true } },
};

const gateway = new Gateway(cfg);
const handle = await startDashboard(gateway, cfg);

try {
  // 1) AS metadata (RFC 8414)
  const asMeta = await (await fetch(`${PUBLIC}/.well-known/oauth-authorization-server`)).json();
  assert("AS metadata issuer matches public_url", sameOrigin(asMeta.issuer, PUBLIC), asMeta.issuer);
  assert("AS advertises authorize/token/register endpoints", asMeta.authorization_endpoint && asMeta.token_endpoint && asMeta.registration_endpoint);
  assert("AS requires PKCE S256", Array.isArray(asMeta.code_challenge_methods_supported) && asMeta.code_challenge_methods_supported.includes("S256"), JSON.stringify(asMeta.code_challenge_methods_supported));
  assert("AS advertises scopes read/write/full", JSON.stringify(asMeta.scopes_supported) === JSON.stringify(["read", "write", "full"]), JSON.stringify(asMeta.scopes_supported));

  // 2) Protected-resource metadata (RFC 9728)
  const prRes = await fetch(`${PUBLIC}/.well-known/oauth-protected-resource/mcp`);
  const prMeta = await prRes.json();
  assert("protected-resource metadata 200", prRes.status === 200, String(prRes.status));
  assert("PR resource is <public>/mcp", prMeta.resource === `${PUBLIC}/mcp`, prMeta.resource);
  assert("PR points at this AS", Array.isArray(prMeta.authorization_servers) && prMeta.authorization_servers.some((s) => sameOrigin(s, PUBLIC)), JSON.stringify(prMeta.authorization_servers));

  // 3) Unauthenticated /mcp → 401 with RFC 9728 resource_metadata challenge
  const unauth = await fetch(`${PUBLIC}/mcp`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }) });
  const wwwAuth = unauth.headers.get("www-authenticate") ?? "";
  assert("/mcp unauthenticated is 401", unauth.status === 401, String(unauth.status));
  assert("401 advertises resource_metadata", wwwAuth.includes("resource_metadata="), wwwAuth);

  // 4) Dynamic Client Registration (RFC 7591)
  const redirectUri = "http://127.0.0.1:7777/callback";
  const reg = await fetch(`${PUBLIC}/register`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_name: "verify-script", redirect_uris: [redirectUri], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] }),
  });
  const client = await reg.json();
  assert("DCR returns a client_id", reg.status === 201 && typeof client.client_id === "string", `${reg.status} ${client.client_id ?? client.error}`);

  // 5) /authorize with PKCE → consent page (consent:true)
  const verifier = b64url(randomBytes(32));
  const challenge = b64url(createHash("sha256").update(verifier).digest());
  const state = b64url(randomBytes(8));
  const authUrl = `${PUBLIC}/authorize?response_type=code&client_id=${encodeURIComponent(client.client_id)}&redirect_uri=${encodeURIComponent(redirectUri)}&code_challenge=${challenge}&code_challenge_method=S256&state=${state}&scope=read&resource=${encodeURIComponent(`${PUBLIC}/mcp`)}`;
  const authRes = await fetch(authUrl, { redirect: "manual" });
  const authHtml = await authRes.text();
  const pendingMatch = authHtml.match(/name="pending_id"\s+value="([^"]+)"/);
  assert("/authorize renders consent page with pending_id", authRes.status === 200 && !!pendingMatch, pendingMatch ? "pending_id found" : `status ${authRes.status}`);

  // 6) Approve consent → 302 back to redirect_uri with ?code=
  const consentRes = await fetch(`${PUBLIC}/oauth/consent`, {
    method: "POST", redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ pending_id: pendingMatch[1], decision: "approve" }).toString(),
  });
  const loc = consentRes.headers.get("location") ?? "";
  const code = new URL(loc, PUBLIC).searchParams.get("code");
  const returnedState = new URL(loc, PUBLIC).searchParams.get("state");
  assert("consent approve 302s to redirect_uri with code", (consentRes.status === 302 || consentRes.status === 303) && !!code, `${consentRes.status} loc=${loc}`);
  assert("authorization code preserves state", returnedState === state, `${returnedState} vs ${state}`);

  // 7) Token exchange (authorization_code + PKCE verifier + resource)
  const tokRes = await fetch(`${PUBLIC}/token`, {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: redirectUri, client_id: client.client_id, code_verifier: verifier, resource: `${PUBLIC}/mcp` }).toString(),
  });
  const tok = await tokRes.json();
  assert("token endpoint returns Bearer access_token", tokRes.status === 200 && tok.token_type?.toLowerCase() === "bearer" && typeof tok.access_token === "string", `${tokRes.status} ${tok.error ?? ""}`);
  assert("token endpoint returns a refresh_token", typeof tok.refresh_token === "string");

  // 8) Authenticated /mcp with the access token → gate passes (not 401)
  const authedMcp = await fetch(`${PUBLIC}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${tok.access_token}` },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "verify", version: "0" } } }),
  });
  assert("/mcp accepts a valid OAuth bearer (not 401)", authedMcp.status !== 401, `status ${authedMcp.status}`);

  // 9) Wrong token still rejected
  const badMcp = await fetch(`${PUBLIC}/mcp`, { method: "POST", headers: { "content-type": "application/json", authorization: "Bearer not-a-real-token" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }) });
  assert("/mcp rejects a bogus bearer (401)", badMcp.status === 401, `status ${badMcp.status}`);

  // 10) Refresh-token rotation
  const refRes = await fetch(`${PUBLIC}/token`, {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: tok.refresh_token, client_id: client.client_id, resource: `${PUBLIC}/mcp` }).toString(),
  });
  const ref = await refRes.json();
  assert("refresh_token grant mints a new access_token", refRes.status === 200 && typeof ref.access_token === "string" && ref.access_token !== tok.access_token, `${refRes.status} ${ref.error ?? ""}`);

  // 11) Revocation (RFC 7009) — revoke the rotated access token, then it must 401
  const revRes = await fetch(`${PUBLIC}/revoke`, {
    method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ token: ref.access_token, client_id: client.client_id }).toString(),
  });
  assert("revoke endpoint returns 200", revRes.status === 200, String(revRes.status));
  const afterRevoke = await fetch(`${PUBLIC}/mcp`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${ref.access_token}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }) });
  assert("revoked token is rejected (401)", afterRevoke.status === 401, `status ${afterRevoke.status}`);
} finally {
  await handle.close();
}

const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
process.exit(failed.length === 0 ? 0 : 1);
