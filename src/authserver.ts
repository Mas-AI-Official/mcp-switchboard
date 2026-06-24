/**
 * authserver.ts — a local OAuth 2.1 + PKCE Authorization Server.
 *
 * claude.ai (web) and other hosted MCP clients can only reach a Switchboard that is
 * fronted by a public HTTPS tunnel (see `switchboard expose`), and they REQUIRE OAuth
 * 2.1 with PKCE + Dynamic Client Registration before they will call `/mcp`. This module
 * implements the SDK's `OAuthServerProvider` so the same process is both the
 * Authorization Server and the Resource Server — no external IdP, no hosted dependency.
 *
 * Design choices (local-first, governance-first, zero custody):
 *   - Tokens are OPAQUE (`base64url(randomBytes(32))`), looked up server-side. We are the
 *     sole AS+RS, so a JWT would only add signing keys to manage for no benefit.
 *   - Token VALUES are stored SHA-256-hashed (like `apikeys.ts`); the full state file is
 *     additionally SEALED with the vault key (AES-256-GCM) because it holds the
 *     recoverable `client_secret` the SDK compares for confidential clients.
 *   - The consent screen IS the human approval gate: by default every authorization needs
 *     an explicit click (`consent: true`). Set `consent: false` to auto-approve.
 *   - PKCE (S256) is mandatory and verified by the SDK via `challengeForAuthorizationCode`.
 *   - RFC 8707 Resource Indicators: validate-if-present, default-bind-if-absent. Every
 *     issued token is audience-bound to this server's canonical `/mcp` resource.
 *
 * SCOPE NOTE: this layer is a BINARY authenticator for `/mcp` (a valid, audience-matched
 * token ⇒ the request is allowed to reach the gateway). The gateway's existing
 * policy → approval → audit pipeline still authorizes every individual tool call. Per-scope
 * tool filtering from the OAuth grant is intentionally NOT wired in here (it would mean
 * threading `AuthInfo` through `gateway.buildServer()` and the router); scopes are
 * recorded and advertised, not enforced per-call.
 */

import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import type { Response } from "express";
import type {
  OAuthServerProvider,
  AuthorizationParams,
} from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type {
  OAuthTokens,
  OAuthClientInformationFull,
  OAuthTokenRevocationRequest,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import {
  InvalidClientError,
  InvalidGrantError,
  InvalidScopeError,
  InvalidTargetError,
  InvalidTokenError,
} from "@modelcontextprotocol/sdk/server/auth/errors.js";
import { HOME_DIR, loadVaultKey, seal, unseal, type SealedSecret } from "./vault.js";
import type { SwitchboardConfig, SettingsConfig } from "./types.js";
import { log } from "./logger.js";

/** Scopes this AS advertises (RFC 8414 `scopes_supported`). Recorded, not per-call enforced. */
export const OAUTH_SCOPES_SUPPORTED = ["read", "write", "full"] as const;

const STATE_PATH = join(HOME_DIR, "authserver.json");
const AUTH_CODE_TTL_MS = 60_000; // RFC 6749 §4.1.2 — codes are short-lived + single-use.
const PENDING_TTL_MS = 10 * 60_000; // a consent screen left open this long is abandoned.

// ── local crypto helpers (kept module-private; mirrors the apikeys.ts convention) ──────
const sha256 = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");
const randomToken = (): string => randomBytes(32).toString("base64url");
const randomId = (): string => randomBytes(16).toString("base64url");

const stripSlash = (s: string): string => s.replace(/\/+$/, "");
const nowSec = (): number => Math.floor(Date.now() / 1000);

/** Append query params to a URL string, preserving any it already carries. */
function appendQuery(base: string, params: Record<string, string | undefined>): string {
  const u = new URL(base);
  for (const [k, v] of Object.entries(params)) if (v !== undefined) u.searchParams.set(k, v);
  return u.toString();
}

/** Mask the five HTML-significant characters for safe interpolation into the consent page. */
function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// ── persisted + in-memory state shapes ─────────────────────────────────────────────────
interface StoredToken {
  clientId: string;
  scopes: string[];
  /** RFC 8707 audience this token is bound to (canonical `/mcp` URL). */
  resource: string;
  /** Epoch seconds. 0 ⇒ never expires (refresh tokens may opt out via `refresh_token_ttl: 0`). */
  expiresAt: number;
}

interface AuthServerState {
  clients: Record<string, OAuthClientInformationFull>;
  /** Keyed by SHA-256(token). Values never contain the plaintext token. */
  accessTokens: Record<string, StoredToken>;
  refreshTokens: Record<string, StoredToken>;
}

interface AuthCode {
  clientId: string;
  codeChallenge: string;
  redirectUri: string;
  scopes: string[];
  resource: string;
  expiresAt: number; // epoch ms
}

interface PendingAuth {
  clientId: string;
  codeChallenge: string;
  redirectUri: string;
  scopes: string[];
  resource: string;
  state?: string;
  clientName: string;
  expiresAt: number; // epoch ms
}

const emptyState = (): AuthServerState => ({ clients: {}, accessTokens: {}, refreshTokens: {} });

/** Resolved, validated OAuth-server runtime options (or null when the feature is off). */
export interface ResolvedOAuthOptions {
  issuerUrl: URL;
  /** Public HTTPS origin+path of this Switchboard, no trailing slash. */
  publicUrl: string;
  /** RFC 8707 canonical audience every token is bound to: `${publicUrl}/mcp`. */
  canonicalResource: string;
  accessTtlSec: number;
  /** 0 ⇒ refresh tokens are not issued. */
  refreshTtlSec: number;
  consent: boolean;
}

/**
 * Read `settings.oauth_server` and resolve it. Returns null (feature off) whenever it is
 * disabled OR misconfigured — fail-closed: a tunnel-fronted endpoint must never fall back
 * to "no auth" because the operator fat-fingered `public_url`.
 */
export function resolveOAuthServerOptions(cfg: SwitchboardConfig): ResolvedOAuthOptions | null {
  const o = cfg.settings?.oauth_server;
  if (!o?.enabled) return null;
  if (!o.public_url) {
    log.error("settings.oauth_server.enabled is true but public_url is unset — OAuth server stays OFF (fail-closed)");
    return null;
  }
  let issuerUrl: URL;
  try {
    issuerUrl = new URL(o.public_url);
  } catch {
    log.error(`settings.oauth_server.public_url is not a valid URL: ${o.public_url} — OAuth server stays OFF`);
    return null;
  }
  if (issuerUrl.protocol !== "https:") {
    // claude.ai web (and the OAuth 2.1 issuer rules) require https for a non-loopback issuer.
    log.warn(`settings.oauth_server.public_url is not https (${issuerUrl.protocol}//) — hosted clients like claude.ai will reject it`);
  }
  const publicUrl = stripSlash(o.public_url);
  return {
    issuerUrl,
    publicUrl,
    canonicalResource: `${publicUrl}/mcp`,
    accessTtlSec: o.access_token_ttl ?? 3600,
    refreshTtlSec: o.refresh_token_ttl ?? 60 * 60 * 24 * 14, // 14 days
    consent: o.consent ?? true,
  };
}

/**
 * The SDK `OAuthServerProvider` implementation. One instance per dashboard process.
 * Codes + pending-consent live in memory (short-lived, single-use); clients + issued
 * tokens are sealed to disk so a restart doesn't invalidate a connected claude.ai.
 */
export class SwitchboardAuthProvider implements OAuthServerProvider {
  private readonly key: Buffer;
  private state: AuthServerState;
  private readonly codes = new Map<string, AuthCode>();
  private readonly pending = new Map<string, PendingAuth>();
  private readonly brand: NonNullable<SettingsConfig["auth_screen"]>;

  constructor(
    private readonly opts: ResolvedOAuthOptions,
    brand?: SettingsConfig["auth_screen"],
  ) {
    this.key = loadVaultKey();
    this.state = this.load();
    this.brand = brand ?? {};
  }

  // ── persistence (sealed JSON, mirrors vault.ts file conventions) ────────────────────
  private load(): AuthServerState {
    if (!existsSync(STATE_PATH)) return emptyState();
    try {
      const sealed = JSON.parse(readFileSync(STATE_PATH, "utf8")) as SealedSecret;
      const parsed = JSON.parse(unseal(this.key, sealed)) as AuthServerState;
      return { ...emptyState(), ...parsed };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      log.error(`could not read ${STATE_PATH} (${msg}); starting with an empty OAuth store`);
      return emptyState();
    }
  }

  private save(): void {
    const sealed = seal(this.key, JSON.stringify(this.state));
    writeFileSync(STATE_PATH, JSON.stringify(sealed));
    try {
      chmodSync(STATE_PATH, 0o600);
    } catch {
      /* best-effort; no-op on Windows */
    }
  }

  /** Drop expired in-memory codes + pending-consent entries. Called on every lookup path. */
  private gc(): void {
    const now = Date.now();
    for (const [code, rec] of this.codes) if (rec.expiresAt <= now) this.codes.delete(code);
    for (const [id, rec] of this.pending) if (rec.expiresAt <= now) this.pending.delete(id);
  }

  // ── OAuthRegisteredClientsStore (RFC 7591 Dynamic Client Registration) ──────────────
  get clientsStore(): OAuthRegisteredClientsStore {
    return {
      getClient: (clientId: string) => this.state.clients[clientId],
      // The SDK's register handler stamps `client_id` + `client_id_issued_at` onto the
      // object BEFORE calling this, so we read the runtime id off it, persist, and return
      // it unchanged. Casting up is safe — the runtime shape is already the full record.
      registerClient: (client) => {
        const full = client as OAuthClientInformationFull;
        this.state.clients[full.client_id] = full;
        this.save();
        log.info(`registered OAuth client '${full.client_name ?? full.client_id}' (${full.client_id})`);
        return full;
      },
    };
  }

  // ── authorization endpoint ──────────────────────────────────────────────────────────
  /**
   * Called by the SDK after it has validated `client_id` + `redirect_uri`. We bind/validate
   * the RFC 8707 resource, then either auto-issue a code (consent disabled) or render the
   * consent screen. Throwing an OAuthError here makes the SDK redirect the error to
   * `redirect_uri`; writing to `res` ourselves completes the flow with no double-write.
   */
  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    this.gc();
    const resource = this.bindResource(params.resource);
    const scopes = this.grantedScopes(params.scopes);

    if (!this.opts.consent) {
      const url = this.issueCode(client.client_id, params, scopes, resource);
      res.redirect(appendQuery(params.redirectUri, { code: url, state: params.state }));
      return;
    }

    const id = randomId();
    this.pending.set(id, {
      clientId: client.client_id,
      codeChallenge: params.codeChallenge,
      redirectUri: params.redirectUri,
      scopes,
      resource,
      state: params.state,
      clientName: client.client_name ?? client.client_id,
      expiresAt: Date.now() + PENDING_TTL_MS,
    });
    res.set("Content-Type", "text/html; charset=utf-8");
    res.set("Cache-Control", "no-store");
    res.send(this.consentPage(id, client, scopes, resource));
  }

  /**
   * Finalize a consent decision posted to the `/oauth/consent` route. Returns the URL to
   * redirect the user-agent to (carrying either `code` or `error=access_denied`), or null
   * if the pending request is unknown/expired (the route should then 400).
   */
  completeConsent(pendingId: string, approved: boolean): string | null {
    this.gc();
    const p = this.pending.get(pendingId);
    if (!p) return null;
    this.pending.delete(pendingId); // single-use

    if (!approved) {
      return appendQuery(p.redirectUri, { error: "access_denied", state: p.state });
    }
    const code = this.issueCode(
      p.clientId,
      { codeChallenge: p.codeChallenge, redirectUri: p.redirectUri, state: p.state },
      p.scopes,
      p.resource,
    );
    return appendQuery(p.redirectUri, { code, state: p.state });
  }

  /** Mint a single-use PKCE-bound authorization code and stash it in memory. */
  private issueCode(
    clientId: string,
    params: { codeChallenge: string; redirectUri: string; state?: string },
    scopes: string[],
    resource: string,
  ): string {
    const code = randomToken();
    this.codes.set(code, {
      clientId,
      codeChallenge: params.codeChallenge,
      redirectUri: params.redirectUri,
      scopes,
      resource,
      expiresAt: Date.now() + AUTH_CODE_TTL_MS,
    });
    return code;
  }

  // ── PKCE: hand the SDK the stored S256 challenge WITHOUT consuming the code ──────────
  async challengeForAuthorizationCode(_client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
    this.gc();
    const rec = this.codes.get(authorizationCode);
    if (!rec) throw new InvalidGrantError("authorization code is invalid or expired");
    return rec.codeChallenge;
  }

  // ── token endpoint: authorization_code grant ────────────────────────────────────────
  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string, // PKCE already verified by the SDK against challengeForAuthorizationCode
    redirectUri?: string,
    resource?: URL,
  ): Promise<OAuthTokens> {
    this.gc();
    const rec = this.codes.get(authorizationCode);
    if (!rec) throw new InvalidGrantError("authorization code is invalid or expired");
    this.codes.delete(authorizationCode); // single-use, consumed on first exchange

    if (rec.clientId !== client.client_id) throw new InvalidGrantError("authorization code was issued to a different client");
    if (redirectUri !== undefined && redirectUri !== rec.redirectUri) {
      throw new InvalidGrantError("redirect_uri does not match the authorization request");
    }
    if (resource && stripSlash(resource.href) !== rec.resource) {
      throw new InvalidTargetError("resource does not match the authorization request");
    }
    return this.mintTokens(client.client_id, rec.scopes, rec.resource);
  }

  // ── token endpoint: refresh_token grant (with rotation) ─────────────────────────────
  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
    resource?: URL,
  ): Promise<OAuthTokens> {
    const hash = sha256(refreshToken);
    const rec = this.state.refreshTokens[hash];
    if (!rec) throw new InvalidGrantError("refresh token is invalid");
    if (rec.clientId !== client.client_id) throw new InvalidGrantError("refresh token was issued to a different client");
    if (rec.expiresAt !== 0 && rec.expiresAt <= nowSec()) {
      delete this.state.refreshTokens[hash];
      this.save();
      throw new InvalidGrantError("refresh token has expired");
    }
    if (resource && stripSlash(resource.href) !== rec.resource) {
      throw new InvalidTargetError("resource does not match the original grant");
    }
    // A refresh MAY narrow scope but never widen it (RFC 6749 §6).
    let finalScopes = rec.scopes;
    if (scopes && scopes.length) {
      const widened = scopes.filter((s) => !rec.scopes.includes(s));
      if (widened.length) throw new InvalidScopeError(`cannot grant scope(s) not in the original token: ${widened.join(", ")}`);
      finalScopes = scopes;
    }
    delete this.state.refreshTokens[hash]; // rotate: the old refresh token is now dead
    return this.mintTokens(client.client_id, finalScopes, rec.resource);
  }

  /** Issue an access token (+ refresh token when enabled), storing only their hashes. */
  private mintTokens(clientId: string, scopes: string[], resource: string): OAuthTokens {
    const accessToken = randomToken();
    const accessExp = nowSec() + this.opts.accessTtlSec;
    this.state.accessTokens[sha256(accessToken)] = { clientId, scopes, resource, expiresAt: accessExp };

    const tokens: OAuthTokens = {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: this.opts.accessTtlSec,
      scope: scopes.join(" "),
    };

    if (this.opts.refreshTtlSec > 0) {
      const refreshToken = randomToken();
      this.state.refreshTokens[sha256(refreshToken)] = {
        clientId,
        scopes,
        resource,
        expiresAt: nowSec() + this.opts.refreshTtlSec,
      };
      tokens.refresh_token = refreshToken;
    }
    this.save();
    return tokens;
  }

  // ── resource server: verify a presented bearer token ────────────────────────────────
  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const rec = this.state.accessTokens[sha256(token)];
    if (!rec) throw new InvalidTokenError("access token is invalid or unknown");
    if (rec.expiresAt <= nowSec()) {
      delete this.state.accessTokens[sha256(token)];
      this.save();
      throw new InvalidTokenError("access token has expired");
    }
    return {
      token,
      clientId: rec.clientId,
      scopes: rec.scopes,
      expiresAt: rec.expiresAt,
      resource: new URL(rec.resource),
    };
  }

  /** Convenience for the dashboard `/mcp` gate: resolve to AuthInfo or null, never throws. */
  async verifyToken(token: string): Promise<AuthInfo | null> {
    try {
      return await this.verifyAccessToken(token);
    } catch {
      return null;
    }
  }

  // ── RFC 7009 token revocation (always best-effort 200) ──────────────────────────────
  async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
    const hash = sha256(request.token);
    const access = this.state.accessTokens[hash];
    const refresh = this.state.refreshTokens[hash];
    // Only let a client revoke its own tokens; otherwise no-op (still a 200 per RFC 7009).
    if (access && access.clientId !== client.client_id) throw new InvalidClientError("cannot revoke another client's token");
    if (refresh && refresh.clientId !== client.client_id) throw new InvalidClientError("cannot revoke another client's token");
    let changed = false;
    if (access) {
      delete this.state.accessTokens[hash];
      changed = true;
    }
    if (refresh) {
      delete this.state.refreshTokens[hash];
      changed = true;
    }
    if (changed) this.save();
  }

  // ── helpers ─────────────────────────────────────────────────────────────────────────
  /** RFC 8707: bind to the requested resource iff it matches our canonical one; default to it. */
  private bindResource(requested?: URL): string {
    if (!requested) return this.opts.canonicalResource;
    if (stripSlash(requested.href) !== this.opts.canonicalResource) {
      throw new InvalidTargetError(`resource must be ${this.opts.canonicalResource}`);
    }
    return this.opts.canonicalResource;
  }

  /** Intersect the requested scopes with what we support; default to all when none asked. */
  private grantedScopes(requested?: string[]): string[] {
    const supported = OAUTH_SCOPES_SUPPORTED as readonly string[];
    if (!requested || !requested.length) return [...supported];
    const granted = requested.filter((s) => supported.includes(s));
    return granted.length ? granted : [...supported];
  }

  /** Self-contained themed consent page (no framework, no external assets). */
  private consentPage(
    pendingId: string,
    client: OAuthClientInformationFull,
    scopes: string[],
    resource: string,
  ): string {
    const accent = /^#[0-9a-fA-F]{3,8}$/.test(this.brand.accent_color ?? "") ? this.brand.accent_color! : "#2dd4bf";
    const title = esc(this.brand.title || "Authorize access");
    const clientName = esc(client.client_name ?? client.client_id);
    const logo =
      this.brand.logo_url && /^https?:\/\//.test(this.brand.logo_url)
        ? `<img src="${esc(this.brand.logo_url)}" alt="" style="height:40px;margin-bottom:18px"/>`
        : `<div class="mark">⎔</div>`;
    const support =
      this.brand.support_url && /^https?:\/\//.test(this.brand.support_url)
        ? `<a class="support" href="${esc(this.brand.support_url)}">Need help?</a>`
        : "";
    const scopeList = scopes
      .map((s) => `<li><span class="dot"></span>${esc(s)}</li>`)
      .join("");
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${title}</title><style>
:root{--accent:${accent}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0d1117;color:#e6edf3;
font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.card{width:min(440px,92vw);background:#161b22;border:1px solid #30363d;border-radius:14px;
padding:32px;text-align:center;box-shadow:0 12px 40px rgba(0,0,0,.4)}
.mark{font-size:40px;color:var(--accent);margin-bottom:18px}
h1{font-size:19px;margin:0 0 6px}
.sub{color:#8b949e;font-size:14px;margin:0 0 22px}
.client{font-weight:600;color:var(--accent)}
ul{list-style:none;padding:0;margin:0 0 24px;text-align:left;border:1px solid #30363d;border-radius:10px;overflow:hidden}
li{padding:11px 16px;border-bottom:1px solid #21262d;display:flex;align-items:center;gap:10px;font-size:14px}
li:last-child{border-bottom:0}
.dot{width:7px;height:7px;border-radius:50%;background:var(--accent);flex:0 0 auto}
.res{color:#6e7681;font-size:12px;word-break:break-all;margin:-12px 0 22px}
.row{display:flex;gap:12px}
button{flex:1;padding:12px;border-radius:9px;font-size:14px;font-weight:600;cursor:pointer;border:1px solid #30363d}
.approve{background:var(--accent);color:#0d1117;border-color:var(--accent)}
.deny{background:transparent;color:#e6edf3}
.support{display:inline-block;margin-top:18px;color:#8b949e;font-size:12px}
</style></head><body>
<form class="card" method="post" action="/oauth/consent">
${logo}
<h1>${title}</h1>
<p class="sub"><span class="client">${clientName}</span> wants to connect to your local Switchboard.</p>
<ul>${scopeList}</ul>
<p class="res">Audience: ${esc(resource)}</p>
<input type="hidden" name="pending_id" value="${esc(pendingId)}"/>
<div class="row">
<button class="deny" type="submit" name="decision" value="deny">Deny</button>
<button class="approve" type="submit" name="decision" value="approve">Approve</button>
</div>
${support}
</form></body></html>`;
  }
}
