/**
 * OAuth-per-provider — managed locally, zero cloud, zero custody (Phase 3).
 *
 * Runs the Authorization-Code + PKCE flow on the operator's own machine: the
 * dashboard opens the provider's consent page, the provider redirects back to a
 * loopback URL the dashboard already serves, and the resulting token is sealed
 * into `~/.switchboard/oauth.json` with the **same** AES-256-GCM key the vault
 * uses (`loadVaultKey`/`seal`/`unseal`). Tokens never leave the machine.
 *
 * Each provider's quirks (PKCE required vs. optional, client-secret-at-exchange,
 * Basic vs. body client auth, scope separator, Slack's `ok:false`-on-200 errors,
 * Notion's mandatory `owner=user`, Linear's rotating refresh tokens) are encoded
 * in the `PROVIDERS` table from primary-source docs — see the grounded notes per
 * entry. The token exchange parses the response **body**, never the HTTP status,
 * because GitHub and Slack return errors with `200 OK`.
 *
 * Client id/secret are not stored here — they live in the vault by convention
 * (`oauth_<provider>_client_id` / `oauth_<provider>_client_secret`), so this
 * module never persists a long-lived app secret of its own.
 *
 * Network: the only outbound call is the token exchange/refresh via the global
 * `fetch` (Node ≥18.18). **Zero native dependencies.**
 */

import { createHash, randomBytes } from "node:crypto";
import { join } from "node:path";
import { WatchedJsonFile } from "./atomicfile.js";
import { HOME_DIR, loadVaultKey, seal, unseal, type SealedSecret } from "./vault.js";
import type { Vault } from "./vault.js";
import { log } from "./logger.js";

const STORE_PATH = join(HOME_DIR, "oauth.json");
/** A connect flow's pending state is only valid for this long. */
const STATE_TTL_MS = 10 * 60 * 1000;
/** Refresh a token this many ms before it actually expires (clock-skew margin). */
const EXPIRY_SKEW_MS = 60 * 1000;

type StoreFile = Record<string, SealedSecret>;

function storeShape(value: unknown): string | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? null : "expected a JSON object of sealed tokens";
}

/** Per-provider OAuth quirks, encoded from each provider's primary-source docs. */
interface ProviderConfig {
  label: string;
  authorizeUrl: string;
  tokenUrl: string;
  /** Does the provider require / support / forbid PKCE? */
  pkce: "required" | "supported" | "unsupported";
  /** When must the client_secret accompany the token exchange? */
  clientSecretAtExchange: "always" | "withoutPkce" | "optional";
  /** Where the client credentials go at exchange. */
  tokenAuth: "body" | "basic";
  /** How multiple scopes are joined in the authorize URL (`null` = no scope param). */
  scopeSeparator: " " | "," | null;
  defaultScopes: string[];
  /** Extra fixed query params for the authorize URL (e.g. Notion's `owner=user`). */
  extraAuthParams?: Record<string, string>;
  /** `https` providers reject a bare http loopback redirect — fail closed honestly. */
  redirect: "loopback" | "https" | "customScheme";
  /** Always send `Accept: application/json` at exchange. */
  acceptJson: boolean;
  /** Slack nests its error under `ok:false` and returns the bot token at top-level. */
  tokenShape?: "slack";
}

/**
 * The five launch providers, grounded against primary docs:
 *  - GitHub  — PKCE supported but secret still required; errors return HTTP 200.
 *  - Google  — PKCE required; refresh via access_type=offline + prompt=consent.
 *  - Slack   — HTTPS redirect mandatory (loopback http rejected); ok:false errors.
 *  - Notion  — no PKCE, HTTP Basic client auth, mandatory owner=user, no scopes.
 *  - Linear  — PKCE optional; ~24h tokens; refresh tokens rotate (persist newest).
 */
const PROVIDERS: Record<string, ProviderConfig> = {
  github: {
    label: "GitHub",
    authorizeUrl: "https://github.com/login/oauth/authorize",
    tokenUrl: "https://github.com/login/oauth/access_token",
    pkce: "supported",
    clientSecretAtExchange: "always",
    tokenAuth: "body",
    scopeSeparator: " ",
    defaultScopes: ["repo", "read:user"],
    redirect: "loopback",
    acceptJson: true,
  },
  google: {
    label: "Google",
    authorizeUrl: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenUrl: "https://oauth2.googleapis.com/token",
    pkce: "required",
    clientSecretAtExchange: "always",
    tokenAuth: "body",
    scopeSeparator: " ",
    defaultScopes: ["openid", "email", "profile"],
    extraAuthParams: { access_type: "offline", prompt: "consent" },
    redirect: "loopback",
    acceptJson: true,
  },
  slack: {
    label: "Slack",
    authorizeUrl: "https://slack.com/oauth/v2/authorize",
    tokenUrl: "https://slack.com/api/oauth.v2.access",
    pkce: "supported",
    clientSecretAtExchange: "withoutPkce",
    tokenAuth: "body",
    scopeSeparator: ",",
    defaultScopes: ["channels:read", "chat:write"],
    redirect: "https",
    acceptJson: true,
    tokenShape: "slack",
  },
  notion: {
    label: "Notion",
    authorizeUrl: "https://api.notion.com/v1/oauth/authorize",
    tokenUrl: "https://api.notion.com/v1/oauth/token",
    pkce: "unsupported",
    clientSecretAtExchange: "always",
    tokenAuth: "basic",
    scopeSeparator: null,
    defaultScopes: [],
    extraAuthParams: { owner: "user" },
    redirect: "loopback",
    acceptJson: true,
  },
  linear: {
    label: "Linear",
    authorizeUrl: "https://linear.app/oauth/authorize",
    tokenUrl: "https://api.linear.app/oauth/token",
    pkce: "supported",
    clientSecretAtExchange: "optional",
    tokenAuth: "body",
    scopeSeparator: ",",
    defaultScopes: ["read", "write"],
    redirect: "loopback",
    acceptJson: true,
  },
};

/** A persisted OAuth token (sealed as JSON under the provider id). */
interface TokenRecord {
  provider: string;
  accessToken: string;
  refreshToken?: string;
  tokenType: string;
  scope?: string;
  /** Epoch ms when the access token expires, if it does. */
  expiresAt?: number;
  obtainedAt: number;
}

/** What the dashboard catalog shows for one provider. */
export interface ProviderStatus {
  id: string;
  label: string;
  scopes: string[];
  connected: boolean;
  expired: boolean;
  hasClientId: boolean;
  /** False for providers that need an HTTPS redirect we can't serve from loopback. */
  connectable: boolean;
  note?: string;
}

interface PendingAuth {
  provider: string;
  verifier?: string;
  redirectUri: string;
  scopes: string[];
  createdAt: number;
}

/** URL-safe base64 with no padding (RFC 7636 base64url). */
function base64url(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function makePkce(): { verifier: string; challenge: string } {
  const verifier = base64url(randomBytes(48));
  const challenge = base64url(createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}

function randomState(): string {
  return base64url(randomBytes(24));
}

/**
 * Local OAuth token store + flow driver. One instance per gateway, sharing the
 * vault's encryption key so tokens are sealed at rest exactly like vault secrets.
 */
export class OAuthStore {
  private readonly key: Buffer;
  private readonly store: WatchedJsonFile<StoreFile>;
  private readonly pending = new Map<string, PendingAuth>();
  private static readonly OAUTH_REF = /\$\{oauth:([^}]+)\}/g;

  /** Throws `StoreCorruptError` when oauth.json exists but is unusable (never starts with an empty store). */
  constructor(private readonly vault: Vault) {
    this.key = loadVaultKey();
    this.store = new WatchedJsonFile<StoreFile>(STORE_PATH, () => ({}), { validate: storeShape, mode: 0o600 });
  }

  /** Provider ids this store knows how to drive. */
  static providers(): string[] {
    return Object.keys(PROVIDERS);
  }

  /** Is `value` an `${oauth:provider}` reference the registry should resolve here? */
  static hasOAuthRef(value: string): boolean {
    OAuthStore.OAUTH_REF.lastIndex = 0;
    return OAuthStore.OAUTH_REF.test(value);
  }

  /**
   * Step 1 of the flow: build the provider's consent URL and remember the pending
   * state (with the PKCE verifier) until the callback comes back.
   */
  beginAuth(providerId: string, redirectUri: string, scopes?: string[]): { authorizeUrl: string; state: string } {
    const provider = PROVIDERS[providerId];
    if (!provider) throw new Error(`unknown OAuth provider '${providerId}'`);
    const clientId = this.clientId(providerId); // throws actionable guidance if unset

    if (provider.redirect === "https" && redirectUri.startsWith("http://")) {
      throw new Error(
        `${provider.label} requires an HTTPS redirect URI — a plain http loopback is rejected. ` +
          `Front the callback with an HTTPS tunnel, or store a pre-authed token via \`switchboard vault set\`.`,
      );
    }

    const useScopes = scopes && scopes.length ? scopes : provider.defaultScopes;
    const usePkce = provider.pkce !== "unsupported";
    const pkce = usePkce ? makePkce() : undefined;
    const state = randomState();
    this.pending.set(state, {
      provider: providerId,
      verifier: pkce?.verifier,
      redirectUri,
      scopes: useScopes,
      createdAt: Date.now(),
    });

    const url = new URL(provider.authorizeUrl);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", clientId);
    url.searchParams.set("redirect_uri", redirectUri);
    url.searchParams.set("state", state);
    if (provider.scopeSeparator !== null && useScopes.length) {
      url.searchParams.set("scope", useScopes.join(provider.scopeSeparator));
    }
    if (pkce) {
      url.searchParams.set("code_challenge", pkce.challenge);
      url.searchParams.set("code_challenge_method", "S256");
    }
    for (const [k, v] of Object.entries(provider.extraAuthParams ?? {})) url.searchParams.set(k, v);
    return { authorizeUrl: url.toString(), state };
  }

  /**
   * Step 2: the provider redirected back with `?code&state`. Exchange the code
   * for a token and seal it. Parses the response body (GitHub/Slack return errors
   * with HTTP 200), fails closed on any error, and persists the token on success.
   */
  async completeAuth(state: string, code: string): Promise<TokenRecord> {
    const pend = this.pending.get(state);
    if (!pend) throw new Error("OAuth callback: unknown or already-used state");
    this.pending.delete(state);
    if (Date.now() - pend.createdAt > STATE_TTL_MS) {
      throw new Error("OAuth callback: state expired — restart the connect flow");
    }
    const provider = PROVIDERS[pend.provider];
    const usedPkce = typeof pend.verifier === "string";

    const headers: Record<string, string> = {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: provider.acceptJson ? "application/json" : "*/*",
    };
    const body = new URLSearchParams();
    body.set("grant_type", "authorization_code");
    body.set("code", code);
    body.set("redirect_uri", pend.redirectUri);
    if (usedPkce) body.set("code_verifier", pend.verifier!);
    this.applyClientAuth(pend.provider, provider, headers, body, this.secretRequired(provider, usedPkce));

    const json = await this.postToken(pend.provider, provider, headers, body);
    const accessToken = typeof json.access_token === "string" ? json.access_token : undefined;
    if (!accessToken) throw new Error(`OAuth exchange with '${pend.provider}' returned no access_token`);

    const expiresIn = Number(json.expires_in);
    const record: TokenRecord = {
      provider: pend.provider,
      accessToken,
      refreshToken: typeof json.refresh_token === "string" ? json.refresh_token : undefined,
      tokenType: typeof json.token_type === "string" ? json.token_type : "Bearer",
      scope: typeof json.scope === "string" ? json.scope : pend.scopes.join(" ") || undefined,
      expiresAt: Number.isFinite(expiresIn) && expiresIn > 0 ? Date.now() + expiresIn * 1000 : undefined,
      obtainedAt: Date.now(),
    };
    this.saveRecord(pend.provider, record);
    log.ok(`connected OAuth provider '${pend.provider}'`);
    return record;
  }

  /**
   * Return a usable bare access token for `${oauth:provider}` resolution, refreshing
   * first if it has expired and a refresh token is available. Fails closed otherwise.
   */
  async accessToken(providerId: string): Promise<string> {
    if (!(providerId in PROVIDERS)) throw new Error(`unknown OAuth provider '${providerId}'`);
    let record = this.loadRecord(providerId);
    if (!record) {
      throw new Error(`OAuth provider '${providerId}' is not connected — open the dashboard catalog and connect it`);
    }
    if (record.expiresAt && Date.now() >= record.expiresAt - EXPIRY_SKEW_MS) {
      if (record.refreshToken) record = await this.refresh(providerId, record);
      else throw new Error(`OAuth token for '${providerId}' expired and has no refresh token — reconnect it`);
    }
    return record.accessToken;
  }

  /** Provider list + connection status for the dashboard catalog. */
  catalog(): ProviderStatus[] {
    const store = this.store.get();
    return Object.entries(PROVIDERS).map(([id, p]) => {
      let record: TokenRecord | undefined;
      const sealed = store[id];
      if (sealed) {
        try {
          record = JSON.parse(unseal(this.key, sealed)) as TokenRecord;
        } catch {
          record = undefined;
        }
      }
      const hasClientId = Boolean(this.vault.get(`oauth_${id}_client_id`));
      const connectable = p.redirect !== "https";
      const expired = Boolean(record?.expiresAt && Date.now() >= record.expiresAt);
      let note: string | undefined;
      if (!connectable) {
        note = `${p.label} requires an HTTPS redirect — not connectable via local loopback; use a pre-authed token`;
      } else if (!hasClientId) {
        note = `set client credentials first: \`switchboard vault set oauth_${id}_client_id\` (and …_client_secret)`;
      }
      return { id, label: p.label, scopes: p.defaultScopes, connected: Boolean(record), expired, hasClientId, connectable, note };
    });
  }

  /** Forget a provider's token (the client id/secret stay in the vault). */
  disconnect(providerId: string): void {
    this.store.update((cur) => {
      if (!cur[providerId]) return undefined;
      const rest = { ...cur };
      delete rest[providerId];
      return rest;
    });
  }

  // --- token exchange plumbing ---------------------------------------------

  private async refresh(providerId: string, record: TokenRecord): Promise<TokenRecord> {
    if (!record.refreshToken) throw new Error(`token for '${providerId}' expired and cannot be refreshed`);
    const provider = PROVIDERS[providerId];
    const headers: Record<string, string> = {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: provider.acceptJson ? "application/json" : "*/*",
    };
    const body = new URLSearchParams();
    body.set("grant_type", "refresh_token");
    body.set("refresh_token", record.refreshToken);
    this.applyClientAuth(providerId, provider, headers, body, this.secretRequired(provider, false));

    const json = await this.postToken(providerId, provider, headers, body);
    const accessToken = typeof json.access_token === "string" ? json.access_token : undefined;
    if (!accessToken) throw new Error(`OAuth refresh for '${providerId}' returned no access_token`);

    const expiresIn = Number(json.expires_in);
    const updated: TokenRecord = {
      ...record,
      accessToken,
      // Refresh tokens rotate (Linear) — persist the newest, else carry the old one forward.
      refreshToken: typeof json.refresh_token === "string" ? json.refresh_token : record.refreshToken,
      tokenType: typeof json.token_type === "string" ? json.token_type : record.tokenType,
      scope: typeof json.scope === "string" ? json.scope : record.scope,
      expiresAt: Number.isFinite(expiresIn) && expiresIn > 0 ? Date.now() + expiresIn * 1000 : undefined,
      obtainedAt: Date.now(),
    };
    this.saveRecord(providerId, updated);
    return updated;
  }

  /** POST the token endpoint and parse its body — never trust the HTTP status alone. */
  private async postToken(
    providerId: string,
    provider: ProviderConfig,
    headers: Record<string, string>,
    body: URLSearchParams,
  ): Promise<Record<string, unknown> & { access_token?: string }> {
    const res = await fetch(provider.tokenUrl, { method: "POST", headers, body });
    const text = await res.text();
    let json: Record<string, unknown>;
    try {
      json = JSON.parse(text) as Record<string, unknown>;
    } catch {
      // Some providers answer x-www-form-urlencoded when Accept is ignored — parse defensively.
      json = Object.fromEntries(new URLSearchParams(text).entries());
    }
    if (provider.tokenShape === "slack") {
      if (json.ok === false) throw new Error(`Slack OAuth error: ${String(json.error ?? "unknown")}`);
    } else if (typeof json.error === "string" && json.error) {
      const desc = typeof json.error_description === "string" ? ` — ${json.error_description}` : "";
      throw new Error(`OAuth error from '${providerId}': ${json.error}${desc}`);
    }
    return json;
  }

  /** Attach client credentials to a token request per the provider's scheme. */
  private applyClientAuth(
    providerId: string,
    provider: ProviderConfig,
    headers: Record<string, string>,
    body: URLSearchParams,
    secretNeeded: boolean,
  ): void {
    const clientId = this.clientId(providerId);
    if (provider.tokenAuth === "basic") {
      const secret = this.requireClientSecret(providerId);
      headers.Authorization = "Basic " + Buffer.from(`${clientId}:${secret}`).toString("base64");
      return;
    }
    body.set("client_id", clientId);
    if (secretNeeded) {
      body.set("client_secret", this.requireClientSecret(providerId));
    } else {
      const secret = this.optionalClientSecret(providerId);
      if (secret) body.set("client_secret", secret);
    }
  }

  private secretRequired(provider: ProviderConfig, usedPkce: boolean): boolean {
    if (provider.clientSecretAtExchange === "always") return true;
    if (provider.clientSecretAtExchange === "withoutPkce") return !usedPkce;
    return false; // optional
  }

  // --- vault-backed client credentials -------------------------------------

  private clientId(providerId: string): string {
    const id = this.vault.get(`oauth_${providerId}_client_id`);
    if (!id) {
      throw new Error(
        `OAuth client id for '${providerId}' is not set — run \`switchboard vault set oauth_${providerId}_client_id\``,
      );
    }
    return id;
  }

  private requireClientSecret(providerId: string): string {
    const secret = this.vault.get(`oauth_${providerId}_client_secret`);
    if (!secret) {
      throw new Error(
        `OAuth client secret for '${providerId}' is not set — run \`switchboard vault set oauth_${providerId}_client_secret\``,
      );
    }
    return secret;
  }

  private optionalClientSecret(providerId: string): string | undefined {
    return this.vault.get(`oauth_${providerId}_client_secret`);
  }

  // --- sealed token persistence --------------------------------------------

  private loadRecord(providerId: string): TokenRecord | undefined {
    const sealed = this.store.get()[providerId];
    if (!sealed) return undefined;
    try {
      return JSON.parse(unseal(this.key, sealed)) as TokenRecord;
    } catch {
      return undefined;
    }
  }

  private saveRecord(providerId: string, record: TokenRecord): void {
    const sealed = seal(this.key, JSON.stringify(record));
    this.store.update((cur) => ({ ...cur, [providerId]: sealed }));
  }
}
