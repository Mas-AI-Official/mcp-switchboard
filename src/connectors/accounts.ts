/**
 * ConnectedAccount store (ADR local-composio, 6.1 to 6.3).
 *
 * `SWITCHBOARD_HOME/connectors/accounts.json` holds one record per connected account: status, scopes,
 * identity, expiry and the credential SEALED with the vault key (AES-256-GCM, the same key the vault and
 * the old oauth.json use). Nothing in that file is readable without the key, and nothing outside this
 * module ever sees a record's `token`: callers get an AccountSummary.
 *
 * What lives here:
 *   - multi-account per provider, labels unique per provider, a per-provider default;
 *   - the 7 statuses (INITIALIZING, INITIATED, ACTIVE, FAILED, EXPIRED, INACTIVE, REVOKED). A connect that
 *     fails or is cancelled never reaches this file (oauthflow.ts keeps in-flight flows apart), so FAILED
 *     and the two "in flight" statuses describe flow outcomes, not stored rows;
 *   - refresh: proactive (a margin before expiry) and reactive (one 401). Concurrent callers share ONE
 *     token request per account (single flight). A rotated refresh token is written atomically BEFORE the
 *     new access token is handed to anyone, so a crash between the two never loses the grant. An
 *     `invalid_grant` marks the account EXPIRED in the same call, writes one `account_expired` audit row
 *     and returns SB_ACCOUNT_EXPIRED with the exact reconnect command; nothing retries on its own;
 *   - disable (tokens kept, use refused), enable, revoke (provider revoke endpoint when defined, then the
 *     sealed token is deleted);
 *   - `authFetch`: an API call that carries the credential, locked to the provider's `api_hosts`;
 *   - live reload: the file is re-read whenever it changes, so a CLI `accounts revoke` is seen by a
 *     running gateway on its next call;
 *   - one-time import of the old `oauth.json` (left untouched on disk).
 */

import { join } from "node:path";
import { WatchedJsonFile } from "../atomicfile.js";
import { seal, unseal, type SealedSecret } from "../vault.js";
import type { Vault } from "../vault.js";
import type { AuditInput } from "../audit.js";
import { guardedFetch, type GuardedResponse, type NetworkSource } from "../netguard.js";
import type { AuthConfigStore } from "./authconfigs.js";
import { newId } from "./authconfigs.js";
import { CONNECTOR_ERR, ConnectorError, reconnectCommand } from "./errors.js";
import { applyAuth } from "./inject.js";
import { runIdentityProbe, type ProbeOutcome } from "./probe.js";
import { hostAllowed, isLoopbackHost, type ProviderRegistry } from "./providers.js";
import { scrubAndClip } from "./scrub.js";
import { requestGrant, runExchangeStep, TokenEndpointError, type ClientCredentials, type TokenResponse } from "./tokenclient.js";
import type {
  AccountIdentity,
  AccountStatus,
  AccountSummary,
  AuthDef,
  ConnectedAccount,
  OAuth2Def,
  ProviderDef,
  TokenPayload,
} from "./types.js";

/** Everything the connector stores share. One per Connectors instance. */
export interface ConnectorContext {
  home: string;
  vault: Vault;
  /** The vault key: seals tokens, verifiers and pending flows. */
  key: Buffer;
  network?: NetworkSource;
  now: () => number;
  audit: (entry: AuditInput) => void;
  providers: ProviderRegistry;
  authConfigs: AuthConfigStore;
  /** Refresh this long before expiry (never more than half a token's lifetime). Default 60 s. */
  skewMs: number;
}

interface AccountsFile {
  version: 1;
  accounts: Record<string, ConnectedAccount>;
  /** provider -> default account id */
  defaults: Record<string, string>;
  /** providers already imported from the old oauth.json -> the account id, or "skipped" */
  legacy_imported: Record<string, string>;
}

function accountsShape(value: unknown): string | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return "expected a JSON object";
  const v = value as Partial<AccountsFile>;
  if (typeof v.accounts !== "object" || v.accounts === null || Array.isArray(v.accounts)) return "expected an 'accounts' object";
  for (const [id, a] of Object.entries(v.accounts)) {
    const acct = a as Partial<ConnectedAccount> | null;
    if (!acct || acct.id !== id || typeof acct.provider !== "string" || typeof acct.status !== "string" || typeof acct.label !== "string") {
      return `account '${id}' is malformed`;
    }
  }
  return null;
}

function legacyShape(value: unknown): string | null {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? null : "expected a JSON object of sealed tokens";
}

/** Decides which account a client uses for a provider (the router injects this once clients land; default = provider default). */
export type BindingResolver = (ctx: { provider: string; client?: string }) => string | undefined;

/** Raised inside a refresh when no provider call can renew the credential (no refresh token, expired and not exchangeable). */
class CannotRenew extends Error {}

export interface Credential {
  account: ConnectedAccount;
  payload: TokenPayload;
}

interface RefreshOpts {
  force: boolean;
  /** When forcing: the access token that just failed. If the store already holds a different one, nobody refreshes. */
  staleToken?: string;
}

export interface AuthFetchInit {
  method?: string;
  headers?: Record<string, string>;
  body?: string | Uint8Array | URLSearchParams;
  signal?: AbortSignal;
  timeoutMs?: number;
  maxBytes?: number;
}

export interface RevokeResult {
  account: AccountSummary;
  /** true: the provider confirmed; false: the call failed; null: this authentication has no provider-side revoke. */
  provider_revoked: boolean | null;
  provider_error?: string;
}

export function summarize(a: ConnectedAccount): AccountSummary {
  const { token, ...rest } = a;
  return { ...rest, has_token: Boolean(token) };
}

const iso = (ms: number): string => new Date(ms).toISOString();

export class AccountStore {
  private readonly file: WatchedJsonFile<AccountsFile>;
  private readonly refreshing = new Map<string, Promise<Credential>>();
  private binding: BindingResolver | undefined;

  constructor(private readonly ctx: ConnectorContext) {
    this.file = new WatchedJsonFile<AccountsFile>(
      join(ctx.home, "connectors", "accounts.json"),
      () => ({ version: 1, accounts: {}, defaults: {}, legacy_imported: {} }),
      { validate: accountsShape, mode: 0o600 },
    );
    this.importLegacy();
  }

  // ── reading ───────────────────────────────────────────────────────────────────────────────────

  /** Install the policy that picks an account per client (default: the provider's default account). */
  setBindingResolver(resolver: BindingResolver | undefined): void {
    this.binding = resolver;
  }

  list(filter: { provider?: string; status?: AccountStatus } = {}): ConnectedAccount[] {
    return Object.values(this.file.get().accounts)
      .filter((a) => (!filter.provider || a.provider === filter.provider) && (!filter.status || a.status === filter.status))
      .sort((a, b) => a.created_at.localeCompare(b.created_at) || a.id.localeCompare(b.id));
  }

  summaries(filter: { provider?: string; status?: AccountStatus } = {}): AccountSummary[] {
    return this.list(filter).map(summarize);
  }

  /** Find by id (`ca_...`), `provider/label`, a provider slug (its default), or a label that is unique. */
  find(ref: string): ConnectedAccount | undefined {
    const accounts = this.file.get().accounts;
    if (accounts[ref]) return accounts[ref];
    const slash = ref.indexOf("/");
    if (slash > 0) {
      const provider = ref.slice(0, slash);
      const label = ref.slice(slash + 1);
      return this.list({ provider }).find((a) => a.label === label);
    }
    if (this.ctx.providers.has(ref)) return this.defaultFor(ref);
    const byLabel = this.list().filter((a) => a.label === ref);
    return byLabel.length === 1 ? byLabel[0] : undefined;
  }

  require(ref: string): ConnectedAccount {
    const a = this.find(ref);
    if (a) return a;
    throw new ConnectorError(CONNECTOR_ERR.ACCOUNT_NOT_FOUND, `no connected account matches '${ref}' (switchboard accounts list shows them)`, { hint: "use the id (ca_...), provider/label, or a unique label" });
  }

  /**
   * The default account of a provider. The recorded default wins whatever its status, so a call made
   * through it reports THAT account's state (expired, disabled, revoked) with the fix command instead of
   * silently switching to a different identity. Only when no default is recorded (or it was forgotten)
   * does the oldest ACTIVE account, else the oldest that is not REVOKED, stand in.
   */
  defaultFor(provider: string): ConnectedAccount | undefined {
    const file = this.file.get();
    const recorded = file.defaults[provider] ? file.accounts[file.defaults[provider]!] : undefined;
    if (recorded && recorded.provider === provider) return recorded;
    const mine = this.list({ provider });
    return mine.find((a) => a.status === "ACTIVE") ?? mine.find((a) => a.status !== "REVOKED");
  }

  /** The account a call should use: an explicit one, else the client's bound one, else the provider default. */
  resolveForCall(provider: string, opts: { account?: string; client?: string } = {}): ConnectedAccount {
    const pick = (ref: string): ConnectedAccount => {
      const a = this.find(ref.includes("/") || ref.startsWith("ca_") ? ref : `${provider}/${ref}`);
      if (!a || a.provider !== provider) {
        throw new ConnectorError(CONNECTOR_ERR.ACCOUNT_NOT_FOUND, `no ${provider} account matches '${ref}'`, { provider });
      }
      return a;
    };
    if (opts.account) return pick(opts.account);
    const bound = this.binding?.({ provider, ...(opts.client ? { client: opts.client } : {}) });
    if (bound) return pick(bound);
    const d = this.defaultFor(provider);
    if (!d) {
      throw new ConnectorError(CONNECTOR_ERR.ACCOUNT_NOT_FOUND, `${provider} is not connected: run \`switchboard connect ${provider}\``, { provider, reconnect: `switchboard connect ${provider}` });
    }
    return d;
  }

  setDefault(ref: string): ConnectedAccount {
    const a = this.require(ref);
    if (a.status === "REVOKED") throw new ConnectorError(CONNECTOR_ERR.ACCOUNT_REVOKED, `account ${a.id} is revoked and cannot be the default`);
    this.file.update((cur) => ({ ...cur, defaults: { ...cur.defaults, [a.provider]: a.id } }));
    return this.require(a.id);
  }

  // ── token access ────────────────────────────────────────────────────────────────────────────────

  private payload(a: ConnectedAccount): TokenPayload {
    if (!a.token) {
      throw new ConnectorError(CONNECTOR_ERR.ACCOUNT_NOT_ACTIVE, `account ${a.id} holds no credential`, { account: a.id, provider: a.provider });
    }
    try {
      return JSON.parse(unseal(this.ctx.key, a.token)) as TokenPayload;
    } catch {
      throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `the sealed credential of account ${a.id} cannot be opened with this vault key: reconnect it`, {
        account: a.id,
        provider: a.provider,
        reconnect: reconnectCommand(a.provider, a.label),
      });
    }
  }

  private sealPayload(p: TokenPayload): SealedSecret {
    return seal(this.ctx.key, JSON.stringify(p));
  }

  private defs(a: ConnectedAccount): { def: ProviderDef; auth: AuthDef } {
    const def = this.ctx.providers.get(a.provider);
    const auth = def?.auth.find((x) => x.id === a.auth_id);
    if (!def || !auth) {
      throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `account ${a.id} was connected through ${a.provider}/${a.auth_id}, which is no longer defined`, { account: a.id, provider: a.provider });
    }
    return { def, auth };
  }

  /** Refuse to use an account that is not ACTIVE, with the command that fixes it. */
  private assertUsable(a: ConnectedAccount): void {
    if (a.status === "ACTIVE") return;
    const base = { provider: a.provider, account: a.id };
    switch (a.status) {
      case "EXPIRED":
        throw this.expiredError(a, a.status_reason);
      case "INACTIVE":
        throw new ConnectorError(CONNECTOR_ERR.ACCOUNT_DISABLED, `account ${a.id} (${a.provider}, label "${a.label}") is disabled. Enable it with: switchboard accounts enable ${a.id}`, { ...base, reconnect: `switchboard accounts enable ${a.id}` });
      case "REVOKED":
        throw new ConnectorError(CONNECTOR_ERR.ACCOUNT_REVOKED, `account ${a.id} (${a.provider}, label "${a.label}") was revoked and its credential deleted. Reconnect with: ${reconnectCommand(a.provider, a.label)}`, { ...base, reconnect: reconnectCommand(a.provider, a.label) });
      default:
        throw new ConnectorError(CONNECTOR_ERR.ACCOUNT_NOT_ACTIVE, `account ${a.id} is ${a.status}, not ACTIVE`, base);
    }
  }

  private expiredError(a: ConnectedAccount, reason?: string): ConnectorError {
    const cmd = reconnectCommand(a.provider, a.label);
    return new ConnectorError(
      CONNECTOR_ERR.ACCOUNT_EXPIRED,
      `account ${a.id} (${a.provider}, label "${a.label}") is EXPIRED${reason ? `: ${reason}` : ""}. Reconnect with: ${cmd}`,
      { provider: a.provider, account: a.id, reconnect: cmd },
    );
  }

  private needsRefresh(p: TokenPayload): boolean {
    if (p.expires_at === undefined) return false;
    const lifetime = p.expires_at - p.obtained_at;
    const skew = Math.max(0, Math.min(this.ctx.skewMs, Math.floor(lifetime / 2)));
    return this.ctx.now() >= p.expires_at - skew;
  }

  /**
   * A usable credential for the account: refreshed first when it is inside the expiry margin. With
   * `forceStale` (a 401 just came back for that access token) the store is refreshed unless somebody
   * already replaced it.
   */
  async credential(ref: string, opts: { forceStale?: string } = {}): Promise<Credential> {
    const acct = this.require(ref);
    this.assertUsable(acct);
    const payload = this.payload(acct);
    if (opts.forceStale !== undefined) {
      if (payload.access_token !== opts.forceStale) return { account: acct, payload };
      return this.refresh(acct.id, { force: true, staleToken: opts.forceStale });
    }
    if (!this.needsRefresh(payload)) return { account: acct, payload };
    return this.refresh(acct.id, { force: false });
  }

  /** The bare access token for `${oauth:provider}` style references. */
  async accessToken(ref: string): Promise<string> {
    const { payload } = await this.credential(ref);
    const t = payload.access_token ?? payload.fields?.token ?? payload.fields?.api_key;
    if (!t) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `account ${ref} has no single bearer token (it carries named fields)`);
    return t;
  }

  /** Single flight: concurrent callers for one account share one token request. */
  private refresh(id: string, opts: RefreshOpts): Promise<Credential> {
    const inflight = this.refreshing.get(id);
    if (inflight) return inflight;
    const p = this.doRefresh(id, opts);
    this.refreshing.set(id, p);
    const clear = (): void => {
      if (this.refreshing.get(id) === p) this.refreshing.delete(id);
    };
    p.then(clear, clear);
    return p;
  }

  private clientFor(a: ConnectedAccount, auth: AuthDef): ClientCredentials | undefined {
    const cfg = (a.auth_config ? this.ctx.authConfigs.get(a.auth_config) : undefined) ?? this.ctx.authConfigs.forProvider(a.provider, { auth_id: auth.id });
    if (!cfg) return undefined;
    return this.ctx.authConfigs.resolveClient(cfg);
  }

  private async doRefresh(id: string, opts: RefreshOpts): Promise<Credential> {
    // Re-read: another caller, or another process, may already have refreshed while we waited.
    const acct = this.require(id);
    this.assertUsable(acct);
    const payload = this.payload(acct);
    if (!opts.force && !this.needsRefresh(payload)) return { account: acct, payload };
    if (opts.force && opts.staleToken !== undefined && payload.access_token !== opts.staleToken) return { account: acct, payload };

    const { def, auth } = this.defs(acct);
    const o: OAuth2Def | undefined = auth.oauth2;
    const refreshable = o && (acct.mode === "oauth2_cc" || o.refresh.kind !== "none");
    if (!o || !refreshable) {
      // API keys and bots do not expire; a credential that does and cannot be renewed means reconnect.
      if (payload.expires_at !== undefined && this.ctx.now() >= payload.expires_at) {
        throw this.expire(acct, "the credential expired and this authentication has no refresh path");
      }
      return { account: acct, payload };
    }

    let resp: TokenResponse;
    try {
      resp = await this.exchangeForNewToken(acct, def, auth, o, payload);
    } catch (err) {
      if (err instanceof CannotRenew) throw this.expire(acct, err.message);
      if (err instanceof TokenEndpointError && err.providerCode && (o.refresh.expired_errors ?? ["invalid_grant"]).includes(err.providerCode)) {
        // Lost race with another process that rotated the token first? Adopt what it stored.
        const again = this.find(id);
        if (again && again.status === "ACTIVE") {
          const p2 = this.payload(again);
          if ((p2.refresh_token !== payload.refresh_token || p2.access_token !== payload.access_token) && !this.needsRefresh(p2)) {
            return { account: again, payload: p2 };
          }
        }
        throw this.expire(acct, `the provider refused the refresh token (${err.providerCode})`);
      }
      this.recordError(id, err);
      throw err;
    }

    const now = this.ctx.now();
    const next: TokenPayload = {
      ...payload,
      access_token: resp.access_token,
      obtained_at: now,
    };
    if (resp.refresh_token) next.refresh_token = resp.refresh_token;
    if (resp.token_type) next.token_type = resp.token_type;
    if (resp.expires_in) next.expires_at = now + resp.expires_in * 1000;
    else delete next.expires_at;
    const scopes = resp.scope ? resp.scope.split(/[\s,]+/).filter(Boolean) : undefined;

    // Persist BEFORE the new access token is used or returned: a rotated refresh token that only lived
    // in memory would be lost by a crash, and the old one is already dead at the provider.
    let aborted: ConnectorError | undefined;
    const committed = this.file.update((cur) => {
      const a = cur.accounts[id];
      if (!a || a.status !== "ACTIVE") {
        aborted = a
          ? new ConnectorError(a.status === "REVOKED" ? CONNECTOR_ERR.ACCOUNT_REVOKED : CONNECTOR_ERR.ACCOUNT_NOT_ACTIVE, `account ${id} became ${a.status} while its token was being refreshed; the new token was discarded`, { account: id, provider: a.provider })
          : new ConnectorError(CONNECTOR_ERR.ACCOUNT_NOT_FOUND, `account ${id} was removed while its token was being refreshed`);
        return undefined;
      }
      const updated: ConnectedAccount = {
        ...a,
        token: this.sealPayload(next),
        last_refresh_at: iso(now),
        ...(next.expires_at !== undefined ? { expires_at: iso(next.expires_at) } : {}),
        ...(scopes?.length ? { scopes_granted: scopes } : {}),
      };
      if (next.expires_at === undefined) delete updated.expires_at;
      delete updated.last_error;
      return { ...cur, accounts: { ...cur.accounts, [id]: updated } };
    });
    if (aborted) throw aborted;
    return { account: committed.accounts[id]!, payload: next };
  }

  /** Ask the provider for a new access token by the strategy the definition declares. */
  private async exchangeForNewToken(acct: ConnectedAccount, def: ProviderDef, auth: AuthDef, o: OAuth2Def, payload: TokenPayload): Promise<TokenResponse> {
    const network = this.ctx.network;
    if (acct.mode === "oauth2_cc") {
      const client = this.clientFor(acct, auth);
      if (!client) throw this.noConfig(acct);
      const scope = acct.scopes_granted.join(o.scope_separator ?? " ");
      return requestGrant({ def, auth, o, grant: { grant_type: "client_credentials", ...(scope ? { scope } : {}) }, client, usedPkce: false, ...(network ? { network } : {}) });
    }
    if (o.refresh.kind === "exchange") {
      const step = o.refresh.exchange;
      if (!step) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `${def.slug}: refresh.kind is exchange but no exchange step is defined`);
      if (payload.expires_at !== undefined && this.ctx.now() >= payload.expires_at) {
        // An expired token cannot be traded for a new one (Meta): the person must consent again.
        throw new CannotRenew(`the ${def.slug} access token expired and an expired token cannot be exchanged for a new one`);
      }
      if (!payload.access_token) throw new ConnectorError(CONNECTOR_ERR.ACCOUNT_NOT_ACTIVE, `account ${acct.id} has no access token to exchange`);
      let client: ClientCredentials | undefined;
      try {
        client = this.clientFor(acct, auth);
      } catch {
        client = undefined; // a step that needs the app credentials reports it below
      }
      return runExchangeStep(def, o, step, { access_token: payload.access_token, ...(client ? { client_id: client.clientId, ...(client.clientSecret ? { client_secret: client.clientSecret } : {}) } : {}) }, network);
    }
    // refresh_token
    if (!payload.refresh_token) {
      throw new CannotRenew("the access token expired and there is no refresh token on record");
    }
    const client = this.clientFor(acct, auth);
    if (!client) throw this.noConfig(acct);
    return requestGrant({ def, auth, o, grant: { grant_type: "refresh_token", refresh_token: payload.refresh_token }, client, usedPkce: false, ...(network ? { network } : {}) });
  }

  private noConfig(a: ConnectedAccount): ConnectorError {
    return new ConnectorError(
      CONNECTOR_ERR.CONNECTOR_CONFIG,
      `the auth config account ${a.id} was connected with is gone: register the app again (switchboard authconfig add ${a.provider} ...) before it can refresh`,
      { account: a.id, provider: a.provider },
    );
  }

  // ── status transitions ───────────────────────────────────────────────────────────────────────────

  /** ACTIVE to EXPIRED, once, with one audit row. Returns the error the caller should throw. */
  private expire(a: ConnectedAccount, reason: string): ConnectorError {
    let transitioned = false;
    this.file.update((cur) => {
      const cur1 = cur.accounts[a.id];
      if (!cur1 || cur1.status !== "ACTIVE") return undefined;
      transitioned = true;
      return { ...cur, accounts: { ...cur.accounts, [a.id]: { ...cur1, status: "EXPIRED", status_reason: reason, last_error: scrubAndClip(reason) } } };
    });
    const err = this.expiredError(a, reason);
    if (transitioned) {
      this.safeAudit({
        server: "connectors",
        tool: "account_expired",
        scope: "read",
        decision: "deny",
        reason: `${a.provider}/${a.label} (${a.id}): ${reason}`,
        error: err.message,
        error_code: CONNECTOR_ERR.ACCOUNT_EXPIRED,
      });
    }
    return err;
  }

  private recordError(id: string, err: unknown): void {
    const msg = scrubAndClip(err instanceof Error ? err.message : String(err));
    try {
      this.file.update((cur) => {
        const a = cur.accounts[id];
        if (!a || a.last_error === msg) return undefined;
        return { ...cur, accounts: { ...cur.accounts, [id]: { ...a, last_error: msg } } };
      });
    } catch {
      /* recording a failure must never mask the failure */
    }
  }

  private safeAudit(entry: AuditInput): void {
    try {
      this.ctx.audit(entry);
    } catch {
      /* an unwritable audit log must not break token handling; the gateway's own rows report that */
    }
  }

  private lifecycleAudit(tool: string, a: ConnectedAccount, decision: "allow" | "deny", reason: string): void {
    this.safeAudit({ server: "connectors", tool, scope: "full", decision, reason: `${a.provider}/${a.label} (${a.id}): ${reason}` });
  }

  disable(ref: string): ConnectedAccount {
    const a = this.require(ref);
    if (a.status === "REVOKED") throw new ConnectorError(CONNECTOR_ERR.ACCOUNT_REVOKED, `account ${a.id} is revoked; reconnect it instead`);
    if (a.status === "INACTIVE") return a;
    this.file.update((cur) => {
      const x = cur.accounts[a.id];
      if (!x || x.status === "INACTIVE") return undefined;
      return { ...cur, accounts: { ...cur.accounts, [a.id]: { ...x, status: "INACTIVE", inactive_from: x.status, status_reason: "disabled by the owner" } } };
    });
    const after = this.require(a.id);
    this.lifecycleAudit("account_disabled", after, "deny", "disabled by the owner");
    return after;
  }

  enable(ref: string): ConnectedAccount {
    const a = this.require(ref);
    if (a.status !== "INACTIVE") {
      if (a.status === "REVOKED") throw new ConnectorError(CONNECTOR_ERR.ACCOUNT_REVOKED, `account ${a.id} is revoked; reconnect it instead`);
      return a;
    }
    this.file.update((cur) => {
      const x = cur.accounts[a.id];
      if (!x || x.status !== "INACTIVE") return undefined;
      const back: ConnectedAccount = { ...x, status: x.inactive_from && x.inactive_from !== "INACTIVE" ? x.inactive_from : "ACTIVE" };
      delete back.inactive_from;
      delete back.status_reason;
      return { ...cur, accounts: { ...cur.accounts, [a.id]: back } };
    });
    const after = this.require(a.id);
    this.lifecycleAudit("account_enabled", after, "allow", `enabled, now ${after.status}`);
    return after;
  }

  /** Remove an account record entirely (the old `disconnect`); a provider-side revoke is `revoke`'s job. */
  forget(ref: string): boolean {
    const a = this.find(ref);
    if (!a) return false;
    this.file.update((cur) => {
      if (!cur.accounts[a.id]) return undefined;
      const accounts = { ...cur.accounts };
      delete accounts[a.id];
      const defaults = { ...cur.defaults };
      if (defaults[a.provider] === a.id) delete defaults[a.provider];
      return { ...cur, accounts, defaults };
    });
    return true;
  }

  /**
   * Revoke: tell the provider (when its definition has a revoke endpoint), then delete the sealed token
   * and mark the account REVOKED. A provider that cannot be reached does not stop the local deletion: an
   * owner revoking a credential wants it gone from here at once; the result says what the provider did.
   */
  async revoke(ref: string): Promise<RevokeResult> {
    const a = this.require(ref);
    if (a.status === "REVOKED") return { account: summarize(a), provider_revoked: null };
    let providerRevoked: boolean | null = null;
    let providerError: string | undefined;
    const { def, auth } = this.defs(a);
    const o = auth.oauth2;
    if (a.token && o?.revoke) {
      let payload: TokenPayload | undefined;
      try {
        payload = this.payload(a);
      } catch {
        payload = undefined;
      }
      if (payload?.access_token) {
        try {
          await this.callRevoke(a, def, auth, o, payload.access_token);
          providerRevoked = true;
        } catch (err) {
          providerRevoked = false;
          providerError = scrubAndClip(err instanceof Error ? err.message : String(err), [payload.access_token, payload.refresh_token]);
        }
      }
    }
    this.file.update((cur) => {
      const x = cur.accounts[a.id];
      if (!x || x.status === "REVOKED") return undefined;
      const revoked: ConnectedAccount = { ...x, status: "REVOKED", status_reason: "revoked by the owner" };
      delete revoked.token;
      delete revoked.inactive_from;
      return { ...cur, accounts: { ...cur.accounts, [a.id]: revoked } };
    });
    const after = this.require(a.id);
    this.lifecycleAudit("account_revoked", after, "deny", providerRevoked === null ? "revoked locally (no provider-side revoke for this authentication)" : providerRevoked ? "revoked at the provider and locally" : "revoked locally; the provider call failed");
    return { account: summarize(after), provider_revoked: providerRevoked, ...(providerError ? { provider_error: providerError } : {}) };
  }

  private async callRevoke(a: ConnectedAccount, def: ProviderDef, auth: AuthDef, o: OAuth2Def, token: string): Promise<void> {
    const r = o.revoke!;
    const params = new URLSearchParams();
    const headers: Record<string, string> = { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" };
    const secrets: string[] = [token];
    if (r.token_param) params.set(r.token_param, token);
    if (r.auth === "bearer") headers.Authorization = `Bearer ${token}`;
    if (r.auth === "client_basic" || r.auth === "client_body") {
      const client = this.clientFor(a, auth);
      if (!client) throw this.noConfig(a);
      if (client.clientSecret) secrets.push(client.clientSecret);
      if (r.auth === "client_basic") {
        if (client.clientSecret) headers.Authorization = "Basic " + Buffer.from(`${client.clientId}:${client.clientSecret}`, "utf8").toString("base64");
        else params.set(o.client_id_param ?? "client_id", client.clientId);
      } else {
        params.set(o.client_id_param ?? "client_id", client.clientId);
        if (client.clientSecret) params.set("client_secret", client.clientSecret);
      }
    }
    let res: GuardedResponse;
    try {
      res = await guardedFetch(r.url, { method: "POST", headers, body: params }, this.ctx.network);
    } catch (err) {
      throw new ConnectorError(CONNECTOR_ERR.PROVIDER_ERROR, scrubAndClip(`revoke endpoint of '${def.slug}' is unreachable: ${err instanceof Error ? err.message : String(err)}`, secrets));
    }
    const body = await res.text();
    if (!res.ok) throw new ConnectorError(CONNECTOR_ERR.PROVIDER_ERROR, scrubAndClip(`revoke endpoint of '${def.slug}' answered HTTP ${res.status}`, secrets));
    if (o.token_shape === "slack") {
      try {
        const j = JSON.parse(body) as { ok?: boolean; error?: string };
        if (j.ok === false) throw new ConnectorError(CONNECTOR_ERR.PROVIDER_ERROR, scrubAndClip(`Slack revoke error: ${String(j.error ?? "unknown")}`, secrets));
      } catch (err) {
        if (err instanceof ConnectorError) throw err;
      }
    }
  }

  // ── authenticated calls ──────────────────────────────────────────────────────────────────────────

  /**
   * Call a provider API as an account. The credential is injected per the provider's `inject` block, the
   * URL host must be one of the provider's `api_hosts` (a token never goes anywhere else, and never over
   * plain http except to loopback), and one 401 triggers one refresh and one retry.
   */
  async authFetch(ref: string, input: string | URL, init: AuthFetchInit = {}): Promise<GuardedResponse> {
    const acct = this.require(ref);
    const { def, auth } = this.defs(acct);
    let url: URL;
    try {
      url = input instanceof URL ? new URL(input.href) : new URL(String(input));
    } catch {
      throw new ConnectorError(CONNECTOR_ERR.HOST_NOT_ALLOWED, "the request URL could not be parsed", { provider: def.slug });
    }
    if (!hostAllowed(def.api_hosts, url.hostname)) {
      throw new ConnectorError(CONNECTOR_ERR.HOST_NOT_ALLOWED, `${url.hostname} is not one of ${def.slug}'s API hosts (${def.api_hosts.join(", ")}); the credential was not sent`, { provider: def.slug, account: acct.id });
    }
    if (url.protocol !== "https:" && !isLoopbackHost(url.hostname)) {
      throw new ConnectorError(CONNECTOR_ERR.HOST_NOT_ALLOWED, `refusing to send a ${def.slug} credential over plain http to ${url.hostname}`, { provider: def.slug, account: acct.id });
    }
    let cred = await this.credential(acct.id);
    const send = async (c: Credential): Promise<GuardedResponse> => {
      const injected = applyAuth(def, auth, c.payload, url, init.headers ?? {});
      return guardedFetch(
        injected.url,
        {
          method: init.method ?? "GET",
          headers: injected.headers,
          ...(init.body !== undefined ? { body: init.body } : {}),
          ...(init.signal ? { signal: init.signal } : {}),
          ...(init.timeoutMs ? { timeoutMs: init.timeoutMs } : {}),
          ...(init.maxBytes ? { maxBytes: init.maxBytes } : {}),
          credentialHeaders: injected.credentialHeaders,
        },
        this.ctx.network,
      );
    };
    let res = await send(cred);
    const o = auth.oauth2;
    const canRefresh = Boolean(o && (acct.mode === "oauth2_cc" || o.refresh.kind !== "none"));
    if (res.status === 401 && canRefresh && cred.payload.access_token) {
      cred = await this.credential(acct.id, { forceStale: cred.payload.access_token });
      res = await send(cred);
    }
    return res;
  }

  /** Run the identity probe for an account (refreshing once on a 401) and record the outcome. */
  async probe(ref: string): Promise<ProbeOutcome & { account: AccountSummary }> {
    const acct = this.require(ref);
    const { def, auth } = this.defs(acct);
    let cred: Credential;
    try {
      cred = await this.credential(acct.id);
    } catch (err) {
      const msg = scrubAndClip(err instanceof Error ? err.message : String(err));
      return { ok: false, error: msg, account: summarize(this.require(acct.id)) };
    }
    let out = await runIdentityProbe(def, auth, cred.payload, this.ctx.network);
    const o = auth.oauth2;
    if (!out.ok && out.status === 401 && o && (acct.mode === "oauth2_cc" || o.refresh.kind !== "none") && cred.payload.access_token) {
      try {
        cred = await this.credential(acct.id, { forceStale: cred.payload.access_token });
        out = await runIdentityProbe(def, auth, cred.payload, this.ctx.network);
      } catch (err) {
        out = { ok: false, error: scrubAndClip(err instanceof Error ? err.message : String(err)) };
      }
    }
    const now = this.ctx.now();
    this.file.update((cur) => {
      const x = cur.accounts[acct.id];
      if (!x) return undefined;
      const next: ConnectedAccount = { ...x, last_probe_at: iso(now) };
      if (out.ok && out.identity) {
        if (x.identity.external_id === "unknown" || x.identity.external_id === out.identity.external_id) {
          next.identity = { ...x.identity, ...out.identity };
          delete next.last_error;
        } else {
          next.last_error = `identity changed: this credential now belongs to '${out.identity.display_name ?? out.identity.external_id}', not '${x.identity.display_name ?? x.identity.external_id}'`;
        }
        if (out.scopes?.length) next.scopes_granted = out.scopes;
      } else if (!out.ok) {
        next.last_error = out.error ?? "identity probe failed";
      }
      return { ...cur, accounts: { ...cur.accounts, [acct.id]: next } };
    });
    return { ...out, account: summarize(this.require(acct.id)) };
  }

  // ── writing a connected account (used by oauthflow) ──────────────────────────────────────────────

  /**
   * Create the account, or update the one with this label on this provider (a reconnect keeps its id).
   * Refuses to replace an account with a DIFFERENT identity under the same label: an agent bound to the
   * work account must not silently start posting as someone else.
   */
  saveConnected(args: {
    provider: string;
    auth: AuthDef;
    authConfigId?: string;
    label: string;
    payload: TokenPayload;
    scopes: string[];
    identity: AccountIdentity;
    probed: boolean;
    source: ConnectedAccount["source"];
  }): ConnectedAccount {
    const now = this.ctx.now();
    let result: ConnectedAccount | undefined;
    let refusal: ConnectorError | undefined;
    this.file.update((cur) => {
      const existing = Object.values(cur.accounts).find((a) => a.provider === args.provider && a.label === args.label);
      if (existing && existing.status !== "REVOKED" && existing.identity.external_id !== "unknown" && existing.identity.external_id !== args.identity.external_id) {
        refusal = new ConnectorError(
          CONNECTOR_ERR.CONNECT_FAILED,
          `label "${args.label}" on ${args.provider} already belongs to ${existing.identity.display_name ?? existing.identity.external_id}, but the account that just authorized is ${args.identity.display_name ?? args.identity.external_id}. Nothing was stored. Use another label (--account), or revoke the old one first: switchboard accounts revoke ${existing.id}`,
          { provider: args.provider, account: existing.id },
        );
        return undefined;
      }
      const id = existing?.id ?? this.freshId(cur);
      const rec: ConnectedAccount = {
        id,
        provider: args.provider,
        auth_id: args.auth.id,
        mode: args.auth.mode,
        ...(args.authConfigId ? { auth_config: args.authConfigId } : {}),
        label: args.label,
        owner: "owner",
        status: "ACTIVE",
        scopes_granted: args.scopes,
        identity: args.identity,
        created_at: existing?.created_at ?? iso(now),
        connected_at: iso(now),
        ...(args.payload.expires_at !== undefined ? { expires_at: iso(args.payload.expires_at) } : {}),
        ...(args.probed ? { last_probe_at: iso(now) } : {}),
        token: this.sealPayload(args.payload),
        source: args.source,
        // An account of a seeded provider is never counted as working, however it was connected.
        ...(this.ctx.providers.isSeed(args.provider) ? { provider_verification: "unverified_seed" as const } : {}),
      };
      result = rec;
      const defaults = { ...cur.defaults };
      const current = defaults[args.provider] ? cur.accounts[defaults[args.provider]!] : undefined;
      if (!current || current.status === "REVOKED") defaults[args.provider] = id;
      return { ...cur, accounts: { ...cur.accounts, [id]: rec }, defaults };
    });
    if (refusal) throw refusal;
    this.lifecycleAudit("account_connected", result!, "allow", `connected via ${args.auth.id}${args.probed ? "" : " (not probed)"}`);
    return result!;
  }

  private freshId(cur: AccountsFile): string {
    for (;;) {
      const id = newId("ca", 10);
      if (!cur.accounts[id]) return id;
    }
  }

  // ── one-time import of the old oauth.json ────────────────────────────────────────────────────────

  private importLegacy(): void {
    // Constructing the watcher reads the old file now, so a torn oauth.json fails here exactly as it did
    // when OAuthStore read it directly (a store that exists but cannot be read is an error, never "empty").
    const legacy = new WatchedJsonFile<Record<string, SealedSecret>>(join(this.ctx.home, "oauth.json"), () => ({}), { validate: legacyShape, mode: 0o600 });
    const entries = Object.entries(legacy.get());
    if (!entries.length) return;
    const done = this.file.get().legacy_imported;
    if (entries.every(([p]) => p in done)) return;
    this.file.update((cur) => {
      const next: AccountsFile = { ...cur, accounts: { ...cur.accounts }, defaults: { ...cur.defaults }, legacy_imported: { ...cur.legacy_imported } };
      let changed = false;
      for (const [provider, sealed] of entries) {
        if (provider in next.legacy_imported) continue;
        changed = true;
        const acct = this.legacyAccount(provider, sealed, next);
        next.legacy_imported[provider] = acct ? acct.id : "skipped";
        if (acct) {
          next.accounts[acct.id] = acct;
          if (!next.defaults[provider]) next.defaults[provider] = acct.id;
        }
      }
      return changed ? next : undefined;
    });
  }

  private legacyAccount(provider: string, sealed: SealedSecret, cur: AccountsFile): ConnectedAccount | undefined {
    const def = this.ctx.providers.get(provider);
    const auth = def?.auth.find((a) => a.mode === "oauth2");
    if (!def || !auth) return undefined;
    let rec: { accessToken?: string; refreshToken?: string; tokenType?: string; scope?: string; expiresAt?: number; obtainedAt?: number };
    try {
      rec = JSON.parse(unseal(this.ctx.key, sealed)) as typeof rec;
    } catch {
      return undefined;
    }
    if (!rec.accessToken) return undefined;
    const obtained = rec.obtainedAt ?? this.ctx.now();
    const payload: TokenPayload = {
      kind: "oauth2",
      access_token: rec.accessToken,
      obtained_at: obtained,
      ...(rec.refreshToken ? { refresh_token: rec.refreshToken } : {}),
      token_type: rec.tokenType ?? "Bearer",
      ...(rec.expiresAt !== undefined ? { expires_at: rec.expiresAt } : {}),
    };
    const expiredForGood = rec.expiresAt !== undefined && this.ctx.now() >= rec.expiresAt && !rec.refreshToken;
    return {
      id: this.freshId(cur),
      provider,
      auth_id: auth.id,
      mode: "oauth2",
      auth_config: `legacy:${provider}`,
      label: "default",
      owner: "owner",
      status: expiredForGood ? "EXPIRED" : "ACTIVE",
      ...(expiredForGood ? { status_reason: "the imported token had expired and has no refresh token" } : {}),
      scopes_granted: rec.scope ? rec.scope.split(/[\s,]+/).filter(Boolean) : [],
      identity: { external_id: "unknown" },
      created_at: iso(obtained),
      connected_at: iso(obtained),
      ...(rec.expiresAt !== undefined ? { expires_at: iso(rec.expiresAt) } : {}),
      token: this.sealPayload(payload),
      source: "legacy",
    };
  }
}

