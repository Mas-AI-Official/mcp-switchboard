/**
 * Connector data model (ADR local-composio, section 6.2).
 *
 * ProviderDef and AuthDef are DATA (src/connectors/providers/*.json, validated against
 * src/connectors/schemas/provider.schema.json), not code: a provider's quirks are fields, so the engine
 * in oauthflow.ts and accounts.ts has no per-provider branches. AuthConfig and ConnectedAccount are the
 * owner's records, stored under SWITCHBOARD_HOME/connectors/.
 */

import type { SealedSecret } from "../vault.js";

// ── provider definitions (data) ───────────────────────────────────────────────────────────────────

/** `oauth1` and `custom` are named by the ADR but not driven by this build: the engine refuses them. */
export type AuthMode = "oauth2" | "oauth2_cc" | "oauth1" | "api_key" | "bearer" | "basic" | "custom";

/** The modes oauthflow.ts can run today. */
export const IMPLEMENTED_AUTH_MODES: readonly AuthMode[] = ["oauth2", "oauth2_cc", "api_key", "bearer", "basic"];

export interface FieldDef {
  name: string;
  label?: string;
  description?: string;
  required: boolean;
  /** A secret field is only ever accepted as a vault/env reference or on stdin, never stored inline in an AuthConfig. */
  secret: boolean;
}

export interface ScopeCatalogEntry {
  scope: string;
  description?: string;
  /** A group id (for example a toolkit slug) so `--scopes @youtube` expands to every scope in the group. */
  group?: string;
}

export interface RevokeDef {
  url: string;
  /** How the call is authenticated: the app's client credentials (basic or body), the account's own token, or nothing. */
  auth: "none" | "client_basic" | "client_body" | "bearer";
  /** Form field that carries the token, or null when the token only travels in the Authorization header. */
  token_param: string | null;
}

/** One declarative HTTP step against the token host (Meta's long-lived token exchange and refresh). */
export interface HttpStepDef {
  method: "GET" | "POST";
  url: string;
  /** Placeholders: {access_token}, {client_id}, {client_secret}. */
  params: Record<string, string>;
}

export interface RefreshDef {
  /**
   * `refresh_token` = the standard grant; `exchange` = trade the still-valid access token for a new one
   * (Meta, which has no refresh tokens); `none` = no refresh path (expiry means reconnect).
   */
  kind: "refresh_token" | "exchange" | "none";
  exchange?: HttpStepDef;
  /** True when each refresh returns a new refresh token and invalidates the old one. */
  rotates: boolean;
  lifetime_s?: number;
  /** Token endpoint error codes that mean the grant is gone for good (default ["invalid_grant"]). */
  expired_errors?: string[];
}

export interface OAuth2Def {
  /** Absent for client-credentials only definitions. */
  authorize_url?: string;
  token_url: string;
  revoke?: RevokeDef;
  pkce: "required" | "supported" | "unsupported";
  client_auth: "body" | "basic";
  client_secret_at_exchange: "always" | "without_pkce" | "optional";
  scope_separator: " " | "," | null;
  default_scopes: string[];
  /** Always requested, even when the owner passes a narrower list (identity scopes the probe needs). */
  required_scopes?: string[];
  scope_catalog: ScopeCatalogEntry[];
  extra_auth_params?: Record<string, string>;
  /** Extra form parameters sent on every token request. */
  token_request_params?: Record<string, string>;
  redirect: "loopback" | "https" | "custom";
  accept_json: boolean;
  /** `GET` sends the token request parameters in the query string (Facebook documents it that way). Default POST. */
  token_http_method?: "GET" | "POST";
  /** Dotted path to the token object inside the response (Instagram wraps it in `data.0`). */
  token_response_path?: string;
  /** A second request made right after the code exchange (short-lived to long-lived token). */
  post_exchange?: HttpStepDef;
  /** The parameter that names the app: `client_id` everywhere except TikTok's `client_key`. */
  client_id_param?: "client_id" | "client_key";
  token_shape?: "standard" | "slack";
  refresh: RefreshDef;
}

/** How a stored credential is attached to an API call. */
export interface InjectDef {
  in: "header" | "query";
  name: string;
  /** Placeholders: {token} (the access token or API key), {basic} (base64 user:password), {<field>} (a stored field). */
  template: string;
}

export interface AuthDef {
  /** Unique within the provider, for example "oauth2", "api_key", "bot_token". */
  id: string;
  mode: AuthMode;
  label?: string;
  /** The definition `switchboard connect` uses when no `--auth` or auth config says otherwise. */
  default?: boolean;
  oauth2?: OAuth2Def;
  inject: InjectDef;
  fields: {
    auth_config_creation: FieldDef[];
    connected_account_initiation: FieldDef[];
  };
}

export interface IdentityProbeDef {
  method: "GET" | "POST";
  url: string;
  headers?: Record<string, string>;
  query?: Record<string, string>;
  /** JSON body for POST probes (GraphQL providers). */
  body?: unknown;
  /** A top-level boolean field that must be true (Slack answers HTTP 200 with ok:false on failure). */
  ok_field?: string;
  /** Dotted path into the JSON response. */
  id_path?: string;
  /** Used when the provider has no identity endpoint: the identity is this constant. */
  id_static?: string;
  name_path?: string;
  avatar_path?: string;
  /** Response header that lists the scopes the token holds (GitHub: x-oauth-scopes). */
  scopes_header?: string;
}

export interface OwnerSetup {
  console_url: string;
  steps: string[];
  /** Redirect URIs the owner must register. `{loopback_redirect}` expands to this gateway's callback URL. */
  redirect_uris: string[];
  notes: string[];
}

export interface Provenance {
  derived_from: string[];
  license?: string;
  attribution?: string;
}

/** Where a seed's facts came from: an Activepieces community piece at a pinned commit (MIT; see NOTICE). */
export interface SeedSource {
  activepieces_commit: string;
  piece: string;
}

/**
 * A seed is a candidate definition derived from another project's published auth settings. It enables Connect and
 * never counts as working: it is not probed, not verified and carries no toolkits.
 */
export type ProviderVerification = "unverified_seed";

export interface ProviderDef {
  slug: string;
  name: string;
  /** Toolkits this provider backs (google backs youtube, gmail and drive). Defaults to [slug]. */
  toolkits?: string[];
  categories: string[];
  /** The only hosts this provider's credentials may ever be sent to. `*.example.com` matches subdomains. */
  api_hosts: string[];
  docs_url: string;
  api_version_header?: { name: string; value: string };
  /** Extra headers sent on every API call (Accept, User-Agent). */
  api_headers?: Record<string, string>;
  owner_setup: OwnerSetup;
  identity_probe?: IdentityProbeDef;
  auth: AuthDef[];
  provenance?: Provenance;
  /** Seeds only (src/connectors/providers/seed/). */
  source?: SeedSource;
  /** Seeds only. */
  verification?: ProviderVerification;
}

// ── owner records ─────────────────────────────────────────────────────────────────────────────────

export interface AuthConfig {
  id: string;
  provider: string;
  /** Which AuthDef of the provider this config belongs to. */
  auth_id: string;
  mode: AuthMode;
  label?: string;
  /** A client id is not a secret, so a literal is allowed; a ref is preferred. Exactly one of the two is set. */
  client_id?: string;
  client_id_ref?: string;
  client_secret_ref?: string;
  /** Scopes this app requests by default; falls back to the provider's default_scopes. */
  scopes?: string[];
  /** An https redirect (a tunnel) used instead of the loopback callback. */
  redirect_uri?: string;
  created: string;
}

export const ACCOUNT_STATUSES = ["INITIALIZING", "INITIATED", "ACTIVE", "FAILED", "EXPIRED", "INACTIVE", "REVOKED"] as const;
export type AccountStatus = (typeof ACCOUNT_STATUSES)[number];

export interface AccountIdentity {
  external_id: string;
  display_name?: string;
  avatar?: string;
}

/** What is sealed inside an account: never serialized in the clear. */
export interface TokenPayload {
  kind: AuthMode;
  access_token?: string;
  refresh_token?: string;
  token_type?: string;
  /** Epoch ms, when the access token stops working. */
  expires_at?: number;
  obtained_at: number;
  /** Named secret fields for modes that carry more than one (basic: username and password). */
  fields?: Record<string, string>;
}

export interface ConnectedAccount {
  id: string;
  provider: string;
  auth_id: string;
  mode: AuthMode;
  /** The AuthConfig this account was connected through, or `legacy:<provider>` for the vault-name convention. */
  auth_config?: string;
  label: string;
  owner: "owner";
  status: AccountStatus;
  /** Where the status came from when it is not ACTIVE. */
  status_reason?: string;
  /** Status to return to on `accounts enable`. */
  inactive_from?: AccountStatus;
  scopes_granted: string[];
  identity: AccountIdentity;
  created_at: string;
  connected_at: string;
  expires_at?: string;
  last_refresh_at?: string;
  last_probe_at?: string;
  last_error?: string;
  /** Absent after revoke. */
  token?: SealedSecret;
  /** How the account came to exist. */
  source: "connect" | "import" | "legacy";
  /** Set when the account belongs to a seeded provider: it is never counted as working. */
  provider_verification?: ProviderVerification;
}

/** A connected account without its sealed token: the only form that leaves the store. */
export type AccountSummary = Omit<ConnectedAccount, "token"> & { has_token: boolean };

export interface PendingFlow {
  state: string;
  provider: string;
  auth_id: string;
  auth_config?: string;
  label: string;
  redirect_uri: string;
  scopes: string[];
  verifier?: SealedSecret;
  created_at: number;
  status: "INITIATED";
}
