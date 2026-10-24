/**
 * OAuth-per-provider, the gateway's long-standing handle on connected accounts.
 *
 * The provider quirks that used to be a hardcoded table in this file (PKCE required vs optional, client
 * secret at exchange, Basic vs body client auth, scope separator, Slack's ok:false-on-200 errors, Notion's
 * mandatory owner=user, Linear's rotating refresh tokens) are now DATA: `src/connectors/providers/*.json`,
 * validated against a JSON Schema and driven by the connector engine in `src/connectors/`. This class keeps
 * the API the dashboard, the registry and the doctor already use and delegates to that engine, so:
 *
 *   - `beginAuth` / `completeAuth` run the same authorization-code flow on the same loopback callback
 *     (the dashboard's `/oauth/callback`), now with the pending state persisted for 10 minutes so the
 *     process that receives the callback need not be the one that started it;
 *   - `accessToken(provider)` resolves `${oauth:provider}` to the provider's DEFAULT connected account
 *     (`${oauth:provider/label}` picks another), refreshing it single-flight when it is near expiry;
 *   - tokens are sealed with the vault key in `connectors/accounts.json`. An existing `oauth.json` is
 *     imported once as `default` accounts and left on disk untouched;
 *   - client id and secret still come from the vault names `oauth_<provider>_client_id` and
 *     `oauth_<provider>_client_secret` unless an auth config (`switchboard authconfig add`) says otherwise.
 *
 * Network: the only outbound calls are token exchange, refresh, revoke and the identity probe, all through
 * the SSRF guard. Zero native dependencies.
 */

import { HOME_DIR } from "./vault.js";
import type { Vault } from "./vault.js";
import { log } from "./logger.js";
import type { NetworkSource } from "./netguard.js";
import { Connectors } from "./connectors/index.js";
import { ProviderRegistry } from "./connectors/providers.js";
import type { AccountSummary } from "./connectors/types.js";
import { summarize } from "./connectors/accounts.js";

/** What a completed authorization hands back (the shape callers have always received). */
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
  /** Every account connected for this provider (no credentials). */
  accounts?: AccountSummary[];
}

/**
 * Local OAuth token store + flow driver. One instance per gateway, sharing the vault's encryption key so
 * tokens are sealed at rest exactly like vault secrets.
 */
export class OAuthStore {
  readonly connectors: Connectors;
  private static readonly OAUTH_REF = /\$\{oauth:([^}]+)\}/g;

  /** Throws `StoreCorruptError` when oauth.json (or a connector store) exists but is unusable (never starts with an empty store). */
  constructor(vault: Vault, network?: NetworkSource) {
    this.connectors = new Connectors({ vault, ...(network ? { network } : {}) });
  }

  /** Provider ids that have an authorization-code flow. */
  static providers(): string[] {
    return ProviderRegistry.load({ home: HOME_DIR })
      .list()
      .filter((p) => p.auth.some((a) => a.mode === "oauth2"))
      .map((p) => p.slug);
  }

  /** Is `value` an `${oauth:provider}` reference the registry should resolve here? */
  static hasOAuthRef(value: string): boolean {
    OAuthStore.OAUTH_REF.lastIndex = 0;
    return OAuthStore.OAUTH_REF.test(value);
  }

  /**
   * Step 1 of the flow: build the provider's consent URL and remember the pending state (with the PKCE
   * verifier) until the callback comes back.
   */
  beginAuth(providerId: string, redirectUri: string, scopes?: string[]): { authorizeUrl: string; state: string } {
    const r = this.connectors.flows.begin({ provider: providerId, redirectUri, ...(scopes?.length ? { scopes } : {}) });
    return { authorizeUrl: r.authorizeUrl, state: r.state };
  }

  /**
   * Step 2: the provider redirected back with `?code&state`. Exchange the code for a token and seal it.
   * Parses the response body (GitHub/Slack return errors with HTTP 200), fails closed on any error, and
   * persists the account only on success.
   */
  async completeAuth(state: string, code: string): Promise<TokenRecord> {
    const { account, payload } = await this.connectors.flows.complete(state, code);
    log.ok(`connected OAuth provider '${account.provider}'`);
    return {
      provider: account.provider,
      accessToken: payload.access_token ?? "",
      ...(payload.refresh_token ? { refreshToken: payload.refresh_token } : {}),
      tokenType: payload.token_type ?? "Bearer",
      ...(account.scopes_granted.length ? { scope: account.scopes_granted.join(" ") } : {}),
      ...(payload.expires_at !== undefined ? { expiresAt: payload.expires_at } : {}),
      obtainedAt: payload.obtained_at,
    };
  }

  /**
   * Return a usable bare access token for `${oauth:provider}` resolution, refreshing first if it is near
   * expiry. `provider/label` picks a specific account. Fails closed otherwise.
   */
  async accessToken(providerId: string): Promise<string> {
    const provider = providerId.split("/")[0]!;
    if (!this.connectors.providers.has(provider)) throw new Error(`unknown OAuth provider '${providerId}'`);
    const accounts = this.connectors.accounts;
    const acct = providerId.includes("/") ? accounts.find(providerId) : accounts.defaultFor(provider);
    if (!acct) {
      throw new Error(`OAuth provider '${providerId}' is not connected - open the dashboard catalog or run \`switchboard connect ${provider}\``);
    }
    return accounts.accessToken(acct.id);
  }

  /** Provider list + connection status for the dashboard catalog. */
  catalog(): ProviderStatus[] {
    const { providers, accounts, authConfigs } = this.connectors;
    const now = Date.now();
    const out: ProviderStatus[] = [];
    for (const def of providers.list()) {
      const auth = def.auth.find((a) => a.mode === "oauth2");
      const o = auth?.oauth2;
      if (!auth || !o) continue;
      const mine = accounts.list({ provider: def.slug });
      const def0 = accounts.defaultFor(def.slug);
      const cfg = authConfigs.forProvider(def.slug, { auth_id: auth.id });
      const hasClientId = Boolean(cfg);
      const connectable = o.redirect !== "https" || Boolean(cfg?.redirect_uri?.startsWith("https://"));
      const connected = Boolean(def0 && def0.status !== "REVOKED");
      const expired = Boolean(def0 && (def0.status === "EXPIRED" || (def0.expires_at && now >= Date.parse(def0.expires_at))));
      let note: string | undefined;
      if (!connectable) {
        note = `${def.name} requires an HTTPS redirect - not connectable via local loopback; use a bot or pre-authed token`;
      } else if (!hasClientId) {
        note = `set client credentials first: \`switchboard vault set oauth_${def.slug}_client_id\` (and ..._client_secret), or \`switchboard authconfig add ${def.slug}\``;
      }
      out.push({
        id: def.slug,
        label: def.name,
        scopes: o.default_scopes,
        connected,
        expired,
        hasClientId,
        connectable,
        ...(note ? { note } : {}),
        ...(mine.length ? { accounts: mine.map(summarize) } : {}),
      });
    }
    return out;
  }

  /** Forget a provider's default account (the client id/secret stay in the vault). */
  disconnect(providerId: string): void {
    const a = this.connectors.accounts.defaultFor(providerId);
    if (a) this.connectors.accounts.forget(a.id);
  }
}
