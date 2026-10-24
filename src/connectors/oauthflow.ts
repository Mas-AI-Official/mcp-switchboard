/**
 * Connect flows (ADR local-composio, 6.3): everything that turns "the owner wants this provider" into a
 * stored ConnectedAccount.
 *
 *   OAuth 2 authorization code (+PKCE per the provider's quirk), client credentials, API key, bearer or
 *   personal access token, basic auth, and importing a token the owner already has.
 *
 * Rules every flow obeys:
 *   - A pending authorization lives 10 minutes in `connectors/pending.json` (the PKCE verifier sealed with
 *     the vault key), keyed by the `state` the provider sends back. It is on disk, not in memory, so the
 *     process that receives the loopback callback need not be the one that started the flow: a running
 *     gateway can finish a flow the CLI began. A state works once.
 *   - A flow that is cancelled, expires, is refused by the provider, or fails its identity probe stores
 *     nothing: no account row, no token. A successful flow writes the account in one atomic step.
 *   - A connection counts only when it is real: after the credential is obtained the provider's identity
 *     probe runs, and a failing probe fails the connect.
 *   - Errors are scrubbed of the secrets the flow handled before they leave this module.
 */

import { createHash, randomBytes } from "node:crypto";
import { join } from "node:path";
import { WatchedJsonFile } from "../atomicfile.js";
import { seal, unseal } from "../vault.js";
import type { AccountStore } from "./accounts.js";
import type { ConnectorContext } from "./accounts.js";
import { CONNECTOR_ERR, ConnectorError } from "./errors.js";
import { runIdentityProbe } from "./probe.js";
import { scrubAndClip } from "./scrub.js";
import { requestGrant, runExchangeStep } from "./tokenclient.js";
import { IMPLEMENTED_AUTH_MODES } from "./types.js";
import type { AuthConfig, AuthDef, ConnectedAccount, OAuth2Def, PendingFlow, ProviderDef, TokenPayload } from "./types.js";

/** A pending authorization is valid for this long. */
export const PENDING_TTL_MS = 10 * 60 * 1000;
/** Most pending flows kept at once; the oldest are dropped first. */
export const MAX_PENDING = 50;
const LABEL_RE = /^[A-Za-z0-9._-]{1,48}$/;

interface PendingFile {
  version: 1;
  flows: Record<string, PendingFlow>;
}

function pendingShape(value: unknown): string | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return "expected a JSON object";
  const flows = (value as { flows?: unknown }).flows;
  return typeof flows === "object" && flows !== null && !Array.isArray(flows) ? null : "expected a 'flows' object";
}

const b64url = (buf: Buffer): string => buf.toString("base64url");

function makePkce(): { verifier: string; challenge: string } {
  const verifier = b64url(randomBytes(48));
  return { verifier, challenge: b64url(createHash("sha256").update(verifier).digest()) };
}

/** What `begin` returns. */
export interface BeginResult {
  authorizeUrl: string;
  state: string;
  label: string;
  expires_at: number;
}

export interface CompleteResult {
  account: ConnectedAccount;
  payload: TokenPayload;
}

export interface BeginOptions {
  provider: string;
  authId?: string;
  authConfigId?: string;
  label?: string;
  redirectUri: string;
  /** Raw scopes, or `@group` to expand a scope group from the provider's catalog. */
  scopes?: string[];
}

/** What the CLI and dashboard may show about a pending flow (never the state value or the verifier). */
export interface PendingSummary {
  id: string;
  provider: string;
  label: string;
  created_at: number;
  expires_at: number;
}

export class ConnectFlows {
  private readonly file: WatchedJsonFile<PendingFile>;

  constructor(
    private readonly ctx: ConnectorContext,
    private readonly accounts: AccountStore,
  ) {
    this.file = new WatchedJsonFile<PendingFile>(join(ctx.home, "connectors", "pending.json"), () => ({ version: 1, flows: {} }), {
      validate: pendingShape,
      mode: 0o600,
    });
  }

  // ── pending bookkeeping ────────────────────────────────────────────────────────────────────────

  private live(flows: Record<string, PendingFlow>): Record<string, PendingFlow> {
    const now = this.ctx.now();
    const kept = Object.entries(flows).filter(([, f]) => now - f.created_at <= PENDING_TTL_MS);
    kept.sort((a, b) => a[1].created_at - b[1].created_at);
    return Object.fromEntries(kept.slice(-MAX_PENDING));
  }

  pending(): PendingSummary[] {
    return Object.values(this.live(this.file.get().flows)).map((f) => ({
      id: createHash("sha256").update(f.state).digest("hex").slice(0, 10),
      provider: f.provider,
      label: f.label,
      created_at: f.created_at,
      expires_at: f.created_at + PENDING_TTL_MS,
    }));
  }

  /** Is the authorization behind `state` still waiting for its callback? */
  isPending(state: string): boolean {
    const f = this.file.get().flows[state];
    return Boolean(f) && this.ctx.now() - f!.created_at <= PENDING_TTL_MS;
  }

  /** Abandon a flow: nothing is stored. Returns whether it was pending. */
  cancel(state: string): boolean {
    let had = false;
    this.file.update((cur) => {
      if (!cur.flows[state]) return undefined;
      had = true;
      const flows = { ...cur.flows };
      delete flows[state];
      return { ...cur, flows: this.live(flows) };
    });
    return had;
  }

  // ── helpers ──────────────────────────────────────────────────────────────────────────────────

  private provider(slug: string): ProviderDef {
    const def = this.ctx.providers.get(slug);
    if (!def) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `unknown OAuth provider '${slug}' (switchboard providers list shows the known ones)`, { provider: slug });
    return def;
  }

  private checkLabel(label: string | undefined): string {
    const l = label ?? "default";
    if (!LABEL_RE.test(l)) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, "an account label may use letters, digits, dot, dash and underscore (1 to 48 characters)");
    return l;
  }

  /** Which AuthDef a connect uses: the one named, else the auth config's, else the first of `mode`. */
  private pickAuth(def: ProviderDef, cfg: AuthConfig | undefined, authId: string | undefined, want: AuthDef["mode"][]): AuthDef {
    const id = authId ?? cfg?.auth_id;
    const auth = id ? def.auth.find((a) => a.id === id) : def.auth.find((a) => want.includes(a.mode));
    if (!auth) {
      throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, id ? `provider ${def.slug} has no auth '${id}' (it has: ${def.auth.map((a) => a.id).join(", ")})` : `provider ${def.slug} has no ${want.join(" or ")} authentication`, { provider: def.slug });
    }
    if (!IMPLEMENTED_AUTH_MODES.includes(auth.mode)) {
      throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `authentication '${auth.id}' of ${def.slug} uses mode '${auth.mode}', which this build does not drive`, { provider: def.slug });
    }
    return auth;
  }

  private ownerSetupHint(def: ProviderDef): string {
    return `${def.name} setup: ${def.owner_setup.console_url}  (switchboard providers show ${def.slug} lists the steps)`;
  }

  private requireConfig(def: ProviderDef, authId: string | undefined, configId: string | undefined): AuthConfig {
    const cfg = this.ctx.authConfigs.forProvider(def.slug, { ...(configId ? { id: configId } : {}), ...(authId ? { auth_id: authId } : {}) });
    if (!cfg) {
      const legacyName = `oauth_${def.slug}_client_id`;
      throw new ConnectorError(
        CONNECTOR_ERR.CONNECTOR_CONFIG,
        configId
          ? `no auth config '${configId}'`
          : `OAuth client id for '${def.slug}' is not set - register your app first: switchboard authconfig add ${def.slug} --client-id-ref <vault name> --client-secret-ref <vault name> (the old convention, switchboard vault set ${legacyName}, also works). ${this.ownerSetupHint(def)}`,
        { provider: def.slug, ...(configId ? {} : { needsApp: true }) },
      );
    }
    if (cfg.provider !== def.slug) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `auth config ${cfg.id} belongs to ${cfg.provider}, not ${def.slug}`);
    return cfg;
  }

  /** An explicit auth config belongs to ONE authentication of the provider; connecting through another is a mistake. */
  private matchConfig(def: ProviderDef, auth: AuthDef, cfg: AuthConfig): AuthConfig {
    if (cfg.auth_id !== auth.id) {
      throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `auth config ${cfg.id} is for ${def.slug}/${cfg.auth_id}, not ${def.slug}/${auth.id}`, { provider: def.slug });
    }
    return cfg;
  }

  private expandScopes(o: OAuth2Def, wanted: string[] | undefined, cfg: AuthConfig): string[] {
    const raw = wanted?.length ? wanted : cfg.scopes?.length ? cfg.scopes : o.default_scopes;
    const out: string[] = [];
    const add = (s: string): void => {
      if (s && !out.includes(s)) out.push(s);
    };
    for (const s of raw) {
      if (s.startsWith("@")) {
        const group = s.slice(1);
        const members = o.scope_catalog.filter((e) => e.group === group).map((e) => e.scope);
        if (!members.length) {
          const groups = [...new Set(o.scope_catalog.map((e) => e.group).filter(Boolean))];
          throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `no scope group '${group}'${groups.length ? ` (groups: ${groups.join(", ")})` : ""}`);
        }
        members.forEach(add);
      } else add(s);
    }
    (o.required_scopes ?? []).forEach(add);
    return out;
  }

  private splitScopes(raw: string | undefined, fallback: string[]): string[] {
    const parts = raw ? raw.split(/[\s,]+/).filter(Boolean) : [];
    return parts.length ? parts : fallback;
  }

  // ── OAuth 2 authorization code ─────────────────────────────────────────────────────────────────

  /**
   * Step 1: build the consent URL and remember the pending state (with the sealed PKCE verifier). Nothing
   * is written to the accounts file; the account only exists once the flow completes.
   */
  begin(opts: BeginOptions): BeginResult {
    const def = this.provider(opts.provider);
    const cfg0 = opts.authConfigId ? this.requireConfig(def, opts.authId, opts.authConfigId) : undefined;
    const auth = this.pickAuth(def, cfg0, opts.authId, ["oauth2"]);
    if (auth.mode !== "oauth2" || !auth.oauth2?.authorize_url) {
      throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `authentication '${auth.id}' of ${def.slug} is '${auth.mode}', not an authorization-code flow: connect it with a token or key instead`, { provider: def.slug });
    }
    const o = auth.oauth2;
    const cfg = cfg0 ? this.matchConfig(def, auth, cfg0) : this.requireConfig(def, auth.id, undefined);
    const client = this.ctx.authConfigs.resolveClient(cfg);
    const redirectUri = cfg.redirect_uri ?? opts.redirectUri;
    if (o.redirect === "https" && redirectUri.startsWith("http://")) {
      throw new ConnectorError(
        CONNECTOR_ERR.CONNECT_FAILED,
        `${def.name} requires an HTTPS redirect URI - a plain http loopback is rejected. Front the callback with an HTTPS tunnel and register it (switchboard authconfig add ${def.slug} ... --redirect-uri https://...), or connect with a token instead (switchboard connect ${def.slug} --auth <token auth>). ${this.ownerSetupHint(def)}`,
        { provider: def.slug },
      );
    }
    const label = this.checkLabel(opts.label);
    const scopes = this.expandScopes(o, opts.scopes, cfg);
    const pkce = o.pkce !== "unsupported" ? makePkce() : undefined;
    const state = b64url(randomBytes(24));
    const flow: PendingFlow = {
      state,
      provider: def.slug,
      auth_id: auth.id,
      auth_config: cfg.id,
      label,
      redirect_uri: redirectUri,
      scopes,
      ...(pkce ? { verifier: seal(this.ctx.key, pkce.verifier) } : {}),
      created_at: this.ctx.now(),
      status: "INITIATED",
    };
    this.file.update((cur) => ({ ...cur, version: 1, flows: this.live({ ...cur.flows, [state]: flow }) }));

    const url = new URL(o.authorize_url!);
    url.searchParams.set("response_type", "code");
    url.searchParams.set(o.client_id_param ?? "client_id", client.clientId);
    url.searchParams.set("redirect_uri", redirectUri);
    url.searchParams.set("state", state);
    if (o.scope_separator !== null && scopes.length) url.searchParams.set("scope", scopes.join(o.scope_separator));
    if (pkce) {
      url.searchParams.set("code_challenge", pkce.challenge);
      url.searchParams.set("code_challenge_method", "S256");
    }
    for (const [k, v] of Object.entries(o.extra_auth_params ?? {})) url.searchParams.set(k, v);
    return { authorizeUrl: url.toString(), state, label, expires_at: flow.created_at + PENDING_TTL_MS };
  }

  /**
   * Step 2: the provider redirected back with `?code&state`. The state is consumed first (it works once,
   * pass or fail), then the code is exchanged, the identity probed, and only then is the account written.
   */
  async complete(state: string, code: string): Promise<CompleteResult> {
    let flow: PendingFlow | undefined;
    this.file.update((cur) => {
      flow = cur.flows[state];
      const flows = { ...cur.flows };
      delete flows[state];
      return flow ? { ...cur, flows: this.live(flows) } : undefined;
    });
    if (!flow) throw new ConnectorError(CONNECTOR_ERR.CONNECT_FAILED, "OAuth callback: unknown or already-used state");
    if (this.ctx.now() - flow.created_at > PENDING_TTL_MS) {
      throw new ConnectorError(CONNECTOR_ERR.CONNECT_FAILED, "OAuth callback: state expired - restart the connect flow", { provider: flow.provider });
    }
    const def = this.provider(flow.provider);
    const auth = def.auth.find((a) => a.id === flow!.auth_id);
    const o = auth?.oauth2;
    if (!auth || !o) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `provider ${def.slug} no longer defines auth '${flow.auth_id}'`);
    const cfg = flow.auth_config ? this.ctx.authConfigs.get(flow.auth_config) : undefined;
    if (!cfg) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, "the auth config for this authorization was removed while it was pending; start again");
    const client = this.ctx.authConfigs.resolveClient(cfg);
    const verifier = flow.verifier ? unseal(this.ctx.key, flow.verifier) : undefined;
    const network = this.ctx.network;
    const grant: Record<string, string> = { grant_type: "authorization_code", code, redirect_uri: flow.redirect_uri };
    if (verifier) grant.code_verifier = verifier;
    let resp = await requestGrant({ def, auth, o, grant, client, usedPkce: Boolean(verifier), ...(network ? { network } : {}) });
    if (o.post_exchange) {
      const longer = await runExchangeStep(def, o, o.post_exchange, { access_token: resp.access_token, client_id: client.clientId, ...(client.clientSecret ? { client_secret: client.clientSecret } : {}) }, network);
      resp = { ...resp, access_token: longer.access_token, ...(longer.expires_in ? { expires_in: longer.expires_in } : {}), ...(longer.scope && !resp.scope ? { scope: longer.scope } : {}) };
    }
    const now = this.ctx.now();
    const payload: TokenPayload = {
      kind: "oauth2",
      access_token: resp.access_token,
      token_type: resp.token_type ?? "Bearer",
      obtained_at: now,
      ...(resp.refresh_token ? { refresh_token: resp.refresh_token } : {}),
      ...(resp.expires_in ? { expires_at: now + resp.expires_in * 1000 } : {}),
    };
    return this.finish(def, auth, cfg.id, flow.label, payload, this.splitScopes(resp.scope, flow.scopes), "connect", [client.clientSecret, code, verifier]);
  }

  // ── client credentials ────────────────────────────────────────────────────────────────────────

  async connectClientCredentials(opts: { provider: string; authId?: string; authConfigId?: string; label?: string; scopes?: string[] }): Promise<CompleteResult> {
    const def = this.provider(opts.provider);
    const cfg0 = opts.authConfigId ? this.requireConfig(def, opts.authId, opts.authConfigId) : undefined;
    const auth = this.pickAuth(def, cfg0, opts.authId, ["oauth2_cc"]);
    if (auth.mode !== "oauth2_cc" || !auth.oauth2) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `authentication '${auth.id}' of ${def.slug} is '${auth.mode}', not a client-credentials grant`);
    const o = auth.oauth2;
    const cfg = cfg0 ? this.matchConfig(def, auth, cfg0) : this.requireConfig(def, auth.id, undefined);
    const client = this.ctx.authConfigs.resolveClient(cfg);
    const label = this.checkLabel(opts.label);
    const scopes = this.expandScopes(o, opts.scopes, cfg);
    const scope = o.scope_separator !== null ? scopes.join(o.scope_separator) : "";
    const resp = await requestGrant({ def, auth, o, grant: { grant_type: "client_credentials", ...(scope ? { scope } : {}) }, client, usedPkce: false, ...(this.ctx.network ? { network: this.ctx.network } : {}) });
    const now = this.ctx.now();
    const payload: TokenPayload = {
      kind: "oauth2_cc",
      access_token: resp.access_token,
      token_type: resp.token_type ?? "Bearer",
      obtained_at: now,
      ...(resp.expires_in ? { expires_at: now + resp.expires_in * 1000 } : {}),
    };
    return this.finish(def, auth, cfg.id, label, payload, this.splitScopes(resp.scope, scopes), "connect", [client.clientSecret]);
  }

  // ── API key, bearer / PAT, basic ──────────────────────────────────────────────────────────────

  /**
   * Store a credential the owner already holds. `fields` carries the values by the names the definition
   * declares (`token`, `api_key`, `username`, `password`, ...); the CLI resolves them from vault or
   * environment references or from stdin, so no value ever travels on a command line.
   */
  async connectSecret(opts: { provider: string; authId?: string; label?: string; fields: Record<string, string> }): Promise<CompleteResult> {
    const def = this.provider(opts.provider);
    const auth = this.pickAuth(def, undefined, opts.authId, ["api_key", "bearer", "basic"]);
    if (auth.mode !== "api_key" && auth.mode !== "bearer" && auth.mode !== "basic") {
      throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `authentication '${auth.id}' of ${def.slug} is '${auth.mode}': connect it with its own flow`);
    }
    const declared = auth.fields.connected_account_initiation;
    const known = new Set(declared.map((f) => f.name));
    for (const name of Object.keys(opts.fields)) {
      if (!known.has(name)) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `${def.slug}/${auth.id} has no field '${name}' (it takes: ${[...known].join(", ")})`);
    }
    for (const f of declared) {
      if (f.required && !(opts.fields[f.name] ?? "").trim()) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `${def.slug}/${auth.id} needs the field '${f.name}'`);
    }
    const label = this.checkLabel(opts.label);
    const fields: Record<string, string> = {};
    for (const [k, v] of Object.entries(opts.fields)) fields[k] = v.trim();
    const single = declared.length === 1 ? fields[declared[0]!.name] : undefined;
    const payload: TokenPayload = {
      kind: auth.mode,
      obtained_at: this.ctx.now(),
      fields,
      ...(auth.mode !== "basic" && single ? { access_token: single } : {}),
    };
    return this.finish(def, auth, undefined, label, payload, [], "connect", Object.values(fields));
  }

  // ── token import ────────────────────────────────────────────────────────────────────────────

  /** Adopt an OAuth token the owner already has (a Slack bot token, a refresh token from another tool). */
  async importToken(opts: { provider: string; authId?: string; authConfigId?: string; label?: string; access_token: string; refresh_token?: string; expires_in?: number; scopes?: string[] }): Promise<CompleteResult> {
    const def = this.provider(opts.provider);
    const cfg = opts.authConfigId ? this.requireConfig(def, opts.authId, opts.authConfigId) : this.ctx.authConfigs.forProvider(def.slug, opts.authId ? { auth_id: opts.authId } : {});
    const auth = this.pickAuth(def, cfg, opts.authId, ["oauth2", "oauth2_cc"]);
    if (!auth.oauth2) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `authentication '${auth.id}' of ${def.slug} is not an OAuth token: use connect without --import`);
    const label = this.checkLabel(opts.label);
    if (!opts.access_token.trim()) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, "the token to import is empty");
    const now = this.ctx.now();
    const payload: TokenPayload = {
      kind: auth.mode,
      access_token: opts.access_token.trim(),
      token_type: "Bearer",
      obtained_at: now,
      ...(opts.refresh_token?.trim() ? { refresh_token: opts.refresh_token.trim() } : {}),
      ...(opts.expires_in && opts.expires_in > 0 ? { expires_at: now + opts.expires_in * 1000 } : {}),
    };
    return this.finish(def, auth, cfg?.id, label, payload, opts.scopes ?? [], "import", [payload.access_token, payload.refresh_token]);
  }

  // ── common tail: probe, then store ──────────────────────────────────────────────────────────────

  private async finish(
    def: ProviderDef,
    auth: AuthDef,
    authConfigId: string | undefined,
    label: string,
    payload: TokenPayload,
    scopes: string[],
    source: ConnectedAccount["source"],
    secrets: Array<string | undefined>,
  ): Promise<CompleteResult> {
    let identity = { external_id: "unknown" } as ConnectedAccount["identity"];
    let probed = false;
    let granted = scopes;
    if (def.identity_probe) {
      const out = await runIdentityProbe(def, auth, payload, this.ctx.network);
      if (!out.ok) {
        throw new ConnectorError(
          CONNECTOR_ERR.CONNECT_FAILED,
          scrubAndClip(`${def.name} issued a credential but its identity probe failed, so nothing was stored: ${out.error ?? "unknown error"}`, secrets),
          { provider: def.slug },
        );
      }
      identity = out.identity!;
      probed = true;
      if (out.scopes?.length) granted = out.scopes;
    }
    try {
      const account = this.accounts.saveConnected({
        provider: def.slug,
        auth,
        ...(authConfigId ? { authConfigId } : {}),
        label,
        payload,
        scopes: granted,
        identity,
        probed,
        source,
      });
      return { account, payload };
    } catch (err) {
      if (err instanceof ConnectorError) throw err;
      throw new ConnectorError(CONNECTOR_ERR.CONNECT_FAILED, scrubAndClip(err instanceof Error ? err.message : String(err), secrets));
    }
  }
}

