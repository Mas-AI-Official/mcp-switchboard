/**
 * Connector admin: what the dashboard's Connectors page and the admin API need, in one place.
 *
 *   providers   every provider, curated and seeded, searchable by name, category and toolkit, filterable by
 *               auth mode and by source, with its toolkits, accounts and coverage state
 *   connect     the provider's own flow: an OAuth consent URL, a client-credentials grant, or a pasted key;
 *               when the OAuth app has not been registered it answers with the owner setup steps instead
 *   accounts    connected accounts with status, expiry and last probe (never a token)
 *   toolkits    enable and disable a toolkit's connector server, live
 *   coverage    the honest count: a provider is never called working here. A seeded provider is `unverified_seed`
 *               by definition; a curated one reports how many of its checklist rows an owner-run probe proved.
 *
 * Everything returned is metadata. No method returns, logs or echoes a credential: a pasted key goes straight to
 * the connect flow and any error that comes back has already been scrubbed of it by oauthflow.ts.
 *
 * The routes in dashboard.ts call this class after the owner-session and CSRF gate; this module has no HTTP.
 */

import { writeConfig } from "../config.js";
import type { ServerConfig, SwitchboardConfig } from "../types.js";
import { summarize } from "./accounts.js";
import type { Connectors } from "./index.js";
import { CONNECTOR_ERR, ConnectorError } from "./errors.js";
import type { Toolkit } from "./toolkits.js";
import { IMPLEMENTED_AUTH_MODES } from "./types.js";
import type { AccountSummary, AuthDef, AuthMode, FieldDef, ProviderDef, SeedSource } from "./types.js";

/** An error the HTTP layer maps to a status. `code` is a stable string the SPA can branch on. */
export class AdminError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly code?: string,
  ) {
    super(message);
  }
}

const SLUG_RE = /^[a-z][a-z0-9-]{0,31}$/;
const ACCOUNT_ID_RE = /^ca_[A-Za-z0-9]{4,32}$/;
const LABEL_RE = /^[A-Za-z0-9._-]{1,48}$/;
const SCOPE_RE = /^[@A-Za-z0-9_:./+*%-]{1,200}$/;
const FIELD_NAME_RE = /^[a-z][a-z0-9_]{0,63}$/;

export type CoverageStateName = "unverified_seed" | "none_live" | "some_live" | "all_live";

/** The only place the word "working" is turned into a number: rows proven live by an owner-run probe. */
export interface CoverageState {
  state: CoverageStateName;
  /** Rows of this provider's toolkits that an owner-run live probe proved (live_verified, with an account and a date). */
  working_rows: number;
  /** Checklist rows that can be worked on (everything except deprecated). */
  addressable_rows: number;
  /** Date of the newest live probe among them. */
  last_verified_at?: string;
}

export type ConnectReadiness = "ready" | "needs_app" | "needs_input" | "unavailable";

export interface AuthRow {
  id: string;
  mode: AuthMode;
  label?: string;
  default: boolean;
  /** Can this build run a connect for it? (custom and oauth1 are named by the schema but not driven.) */
  connectable: boolean;
}

export interface ToolkitRow {
  slug: string;
  provider: string;
  /** Has a definition (synced spec or recipes) in this install. */
  defined: boolean;
  version?: string;
  tools: number;
  listed: number;
  /** `on` / `off` once a connector server exists for it; `no_server` before. */
  state: "on" | "off" | "no_server";
  /** The account this server is pinned to, when it is. */
  account?: string;
  /** The provider has an ACTIVE account that passed its identity probe: enabling is allowed. */
  ready: boolean;
  coverage: CoverageState;
}

export interface ProviderRow {
  slug: string;
  name: string;
  source: "curated" | "seed";
  /** `curated` definitions are hand-written; `unverified_seed` ones were derived from another project's data. */
  verification: "curated" | "unverified_seed";
  categories: string[];
  auth: AuthRow[];
  api_hosts: string[];
  toolkits: ToolkitRow[];
  accounts: number;
  connected: boolean;
  /** An OAuth provider whose app (client id and secret) has not been registered yet. */
  needs_app: boolean;
  connect: ConnectReadiness;
  coverage: CoverageState;
  seed_source?: SeedSource;
}

export interface ProviderQuery {
  q?: string;
  auth?: string;
  source?: string;
  connectable?: boolean;
  offset?: number;
  limit?: number;
}

export interface ProviderList {
  total: number;
  offset: number;
  limit: number;
  providers: ProviderRow[];
  facets: { source: { curated: number; seed: number }; mode: Record<string, number>; connectable: number; total: number };
  /** Seeds a curated definition shadows (never shown as providers of their own). */
  shadowed_seeds: number;
  /** Seed files that failed validation and were left out. */
  seed_issues: number;
}

export interface ConnectBody {
  auth_id?: string;
  label?: string;
  scopes?: string[];
  fields?: Record<string, string>;
}

export type ConnectOutcome =
  | { status: "redirect"; authorize_url: string; auth_id: string; expires_at: number }
  | { status: "connected"; auth_id: string; account: AccountSummary }
  | { status: "needs_setup"; auth_id: string; message: string; owner_setup: OwnerSetupView }
  | { status: "needs_input"; auth_id: string; message: string; fields: FieldView[] };

export interface FieldView {
  name: string;
  label?: string;
  required: boolean;
  secret: boolean;
}

export interface OwnerSetupView {
  console_url: string;
  steps: string[];
  redirect_uris: string[];
  notes: string[];
  commands: string[];
}

export interface AdminHost {
  /** The live config the gateway runs on. */
  config(): SwitchboardConfig;
  configPath(): string | undefined;
  mount(server: ServerConfig): Promise<unknown>;
  unmount(id: string): Promise<unknown>;
  /** The loopback OAuth callback URL of this dashboard. */
  redirectUri(): string;
}

const emptyCoverage = (state: CoverageStateName): CoverageState => ({ state, working_rows: 0, addressable_rows: 0 });

/**
 * Why `slug` cannot be enabled right now, or undefined when it can. The same check `switchboard toolkits enable`
 * makes, so the CLI and the dashboard cannot disagree.
 */
export function toolkitEnableProblem(connectors: Connectors, slug: string): string | undefined {
  const kit = connectors.kit;
  const tk = kit.toolkits.load(slug);
  if (!tk) return `toolkit '${slug}' is not defined here (run: switchboard toolkits sync ${slug})`;
  const provider = connectors.providers.providerForToolkit(slug) ?? connectors.providers.get(tk.provider);
  if (!provider) return `no provider definition backs toolkit '${slug}'`;
  const ok = connectors.accounts.list({ provider: provider.slug }).some((a) => a.status === "ACTIVE" && (provider.identity_probe ? Boolean(a.last_probe_at) && !a.last_error : true));
  if (!ok) return `${provider.name} has no ACTIVE account that passed its identity probe, so '${slug}' cannot be enabled. Connect one: switchboard connect ${provider.slug}`;
  return undefined;
}

export class ConnectorAdmin {
  constructor(
    private readonly connectors: Connectors,
    private readonly host: AdminHost,
  ) {}

  // ── helpers ──────────────────────────────────────────────────────────────────────────────────

  private provider(slug: string): ProviderDef {
    if (!SLUG_RE.test(slug)) throw new AdminError(400, "not a provider slug", "SB_BAD_SLUG");
    const def = this.connectors.providers.get(slug);
    if (!def) throw new AdminError(404, `unknown provider '${slug}'`, "SB_PROVIDER_UNKNOWN");
    return def;
  }

  private isSeed(slug: string): boolean {
    return this.connectors.providers.isSeed(slug);
  }

  private authRows(def: ProviderDef): AuthRow[] {
    return def.auth.map((a) => ({ id: a.id, mode: a.mode, ...(a.label ? { label: a.label } : {}), default: a.default === true, connectable: IMPLEMENTED_AUTH_MODES.includes(a.mode) }));
  }

  /** The authentication a connect uses when none is named: the default if driven, else the first driven one. */
  private pickAuth(def: ProviderDef, id?: string): AuthDef {
    if (id) {
      const a = def.auth.find((x) => x.id === id);
      if (!a) throw new AdminError(400, `provider ${def.slug} has no authentication '${id}' (it has: ${def.auth.map((x) => x.id).join(", ")})`, "SB_AUTH_UNKNOWN");
      return a;
    }
    const driven = def.auth.filter((a) => IMPLEMENTED_AUTH_MODES.includes(a.mode));
    const a = driven.find((x) => x.default) ?? driven[0] ?? def.auth.find((x) => x.default) ?? def.auth[0];
    if (!a) throw new AdminError(400, `provider ${def.slug} defines no authentication`, "SB_AUTH_UNKNOWN");
    return a;
  }

  /** How ready a connect is for this authentication. */
  private readiness(def: ProviderDef, auth: AuthDef | undefined): { connect: ConnectReadiness; needsApp: boolean } {
    if (!auth || !IMPLEMENTED_AUTH_MODES.includes(auth.mode)) return { connect: "unavailable", needsApp: false };
    if (auth.mode === "oauth2" || auth.mode === "oauth2_cc") {
      const cfg = this.connectors.authConfigs.forProvider(def.slug, { auth_id: auth.id });
      return cfg ? { connect: "ready", needsApp: false } : { connect: "needs_app", needsApp: true };
    }
    return { connect: "needs_input", needsApp: false };
  }

  // ── coverage ─────────────────────────────────────────────────────────────────────────────────

  /** Per our-toolkit: addressable rows, live rows and the newest probe date. Built once per request. */
  private coverageIndex(): Map<string, { addressable: number; working: number; newest?: string }> {
    const out = new Map<string, { addressable: number; working: number; newest?: string }>();
    for (const { row, state, line } of this.connectors.kit.coverage.states()) {
      const e = out.get(row.our_toolkit) ?? { addressable: 0, working: 0 };
      if (state !== "deprecated") e.addressable += 1;
      if (state === "live_verified") {
        e.working += 1;
        if (line?.ts && (!e.newest || line.ts > e.newest)) e.newest = line.ts;
      }
      out.set(row.our_toolkit, e);
    }
    return out;
  }

  private coverageFor(def: ProviderDef, toolkits: string[], index: Map<string, { addressable: number; working: number; newest?: string }>): CoverageState {
    // A seed is an unverified definition: whatever a ledger line says, it is never working.
    if (this.isSeed(def.slug)) return emptyCoverage("unverified_seed");
    let addressable = 0;
    let working = 0;
    let newest: string | undefined;
    for (const t of toolkits) {
      const e = index.get(t);
      if (!e) continue;
      addressable += e.addressable;
      working += e.working;
      if (e.newest && (!newest || e.newest > newest)) newest = e.newest;
    }
    const state: CoverageStateName = working === 0 ? "none_live" : working >= addressable ? "all_live" : "some_live";
    return { state, working_rows: working, addressable_rows: addressable, ...(newest ? { last_verified_at: newest } : {}) };
  }

  /** The toolkits the kit defines for this provider (seeds have none). */
  private toolkitSlugsOf(def: ProviderDef): string[] {
    const kit = this.connectors.kit;
    return kit.toolkits.slugs().filter((s) => (kit.toolkits.providerSlug(s) ?? s) === def.slug);
  }

  private connectorServer(slug: string): ServerConfig | undefined {
    return this.host.config().servers.find((s) => s.source === "connector" && s.toolkit === slug);
  }

  private toolkitRow(slug: string, def: ProviderDef, index: Map<string, { addressable: number; working: number; newest?: string }>): ToolkitRow {
    const kit = this.connectors.kit;
    const tk: Toolkit | undefined = kit.toolkits.load(slug);
    const srv = this.connectorServer(slug);
    return {
      slug,
      provider: def.slug,
      defined: Boolean(tk),
      ...(tk ? { version: tk.version } : {}),
      tools: tk?.tools_count ?? 0,
      listed: tk ? Math.min(tk.actions.filter((a) => a.important && !a.deprecated).length, 28) : 0,
      state: srv ? (srv.enabled === false ? "off" : "on") : "no_server",
      ...(srv?.account ? { account: srv.account } : {}),
      ready: toolkitEnableProblem(this.connectors, slug) === undefined,
      coverage: this.coverageFor(def, [slug], index),
    };
  }

  // ── providers ────────────────────────────────────────────────────────────────────────────────

  private row(def: ProviderDef, index: Map<string, { addressable: number; working: number; newest?: string }>, accountsBy: Map<string, number>): ProviderRow {
    const seed = this.isSeed(def.slug);
    const slugs = this.toolkitSlugsOf(def);
    const defaultAuth = this.pickAuth(def);
    const { connect, needsApp } = this.readiness(def, defaultAuth);
    const accounts = accountsBy.get(def.slug) ?? 0;
    return {
      slug: def.slug,
      name: def.name,
      source: seed ? "seed" : "curated",
      verification: seed ? "unverified_seed" : "curated",
      categories: def.categories,
      auth: this.authRows(def),
      api_hosts: def.api_hosts,
      toolkits: slugs.map((s) => this.toolkitRow(s, def, index)),
      accounts,
      connected: accounts > 0,
      needs_app: needsApp,
      connect,
      coverage: this.coverageFor(def, slugs, index),
      ...(seed && def.source ? { seed_source: def.source } : {}),
    };
  }

  private accountCounts(): Map<string, number> {
    const m = new Map<string, number>();
    for (const a of this.connectors.accounts.list()) if (a.status !== "REVOKED") m.set(a.provider, (m.get(a.provider) ?? 0) + 1);
    return m;
  }

  listProviders(query: ProviderQuery = {}): ProviderList {
    const reg = this.connectors.providers;
    const q = (query.q ?? "").trim().toLowerCase().slice(0, 80);
    const toolkitNames = (def: ProviderDef): string[] => [...(def.toolkits ?? []), ...this.toolkitSlugsOf(def)];
    const matchesQuery = (def: ProviderDef): boolean => {
      if (!q) return true;
      const hay = [def.slug, def.name, ...def.categories, ...toolkitNames(def), ...def.api_hosts].join(" ").toLowerCase();
      return q.split(/\s+/).every((t) => hay.includes(t));
    };
    const sorted = (list: ProviderDef[]): ProviderDef[] => [...list].sort((a, b) => a.name.localeCompare(b.name) || a.slug.localeCompare(b.slug));
    const all = [...sorted(reg.list()), ...sorted(reg.listSeeds())];
    const bySearch = all.filter(matchesQuery);
    const connectableMode = (def: ProviderDef): boolean => def.auth.some((a) => IMPLEMENTED_AUTH_MODES.includes(a.mode));
    const facets: ProviderList["facets"] = { source: { curated: 0, seed: 0 }, mode: {}, connectable: 0, total: bySearch.length };
    for (const def of bySearch) {
      if (reg.isSeed(def.slug)) facets.source.seed += 1;
      else facets.source.curated += 1;
      for (const mode of new Set(def.auth.map((a) => a.mode))) facets.mode[mode] = (facets.mode[mode] ?? 0) + 1;
      if (connectableMode(def)) facets.connectable += 1;
    }
    const wantSource = query.source === "curated" || query.source === "seed" ? query.source : undefined;
    const filtered = bySearch.filter((def) => {
      if (wantSource && (reg.isSeed(def.slug) ? "seed" : "curated") !== wantSource) return false;
      if (query.auth && !def.auth.some((a) => a.mode === query.auth)) return false;
      if (query.connectable && !connectableMode(def)) return false;
      return true;
    });
    const limit = Math.min(Math.max(Math.trunc(query.limit ?? 60) || 60, 1), 200);
    const offset = Math.max(Math.trunc(query.offset ?? 0) || 0, 0);
    const index = this.coverageIndex();
    const counts = this.accountCounts();
    return {
      total: filtered.length,
      offset,
      limit,
      providers: filtered.slice(offset, offset + limit).map((d) => this.row(d, index, counts)),
      facets,
      shadowed_seeds: reg.shadowedSeeds().length,
      seed_issues: reg.seedIssues.length,
    };
  }

  /** The owner setup the provider declares, with the loopback callback filled in and the exact commands to run. */
  private ownerSetup(def: ProviderDef, auth: AuthDef | undefined): OwnerSetupView {
    const redirect = this.host.redirectUri();
    const commands: string[] = [];
    if (auth && (auth.mode === "oauth2" || auth.mode === "oauth2_cc")) {
      commands.push(`switchboard vault set ${def.slug}_client_id`);
      commands.push(`switchboard vault set ${def.slug}_client_secret`);
      commands.push(`switchboard authconfig add ${def.slug} --client-id-ref ${def.slug}_client_id --client-secret-ref ${def.slug}_client_secret${auth.id !== "oauth2" ? ` --auth ${auth.id}` : ""}`);
      commands.push(`switchboard connect ${def.slug} --account <label>${auth.id !== "oauth2" ? ` --auth ${auth.id}` : ""}`);
    }
    return {
      console_url: def.owner_setup.console_url,
      steps: def.owner_setup.steps,
      redirect_uris: def.owner_setup.redirect_uris.map((u) => u.replaceAll("{loopback_redirect}", redirect)),
      notes: def.owner_setup.notes,
      commands,
    };
  }

  providerDetail(slug: string): Record<string, unknown> {
    const def = this.provider(slug);
    const index = this.coverageIndex();
    const row = this.row(def, index, this.accountCounts());
    const reg = this.connectors.providers;
    const configs = this.connectors.authConfigs.list(def.slug).map((c) => ({
      id: c.id,
      auth_id: c.auth_id,
      ...(c.label ? { label: c.label } : {}),
      client_secret_set: Boolean(c.client_secret_ref),
      ...(c.scopes?.length ? { scopes: c.scopes } : {}),
      ...(c.redirect_uri ? { redirect_uri: c.redirect_uri } : {}),
    }));
    return {
      ...row,
      docs_url: def.docs_url,
      owner_setup: this.ownerSetup(def, this.pickAuth(def)),
      auth_detail: def.auth.map((a) => ({
        id: a.id,
        mode: a.mode,
        default: a.default === true,
        connectable: IMPLEMENTED_AUTH_MODES.includes(a.mode),
        fields: a.fields.connected_account_initiation.map((f): FieldView => ({ name: f.name, ...(f.label ? { label: f.label } : {}), required: f.required, secret: f.secret })),
        ...(a.oauth2
          ? { oauth2: { pkce: a.oauth2.pkce, client_auth: a.oauth2.client_auth, redirect: a.oauth2.redirect, default_scopes: a.oauth2.default_scopes, refresh: a.oauth2.refresh.kind, scope_groups: [...new Set(a.oauth2.scope_catalog.map((s) => s.group).filter(Boolean))] } }
          : {}),
      })),
      auth_configs: configs,
      accounts_detail: this.accounts({ provider: def.slug }),
      ...(reg.isSeed(def.slug) && def.provenance ? { provenance: def.provenance } : {}),
    };
  }

  // ── accounts ─────────────────────────────────────────────────────────────────────────────────

  accounts(filter: { provider?: string } = {}): Array<AccountSummary & { provider_name: string; source_kind: "curated" | "seed"; working: false; probe_available: boolean }> {
    if (filter.provider && !SLUG_RE.test(filter.provider)) throw new AdminError(400, "not a provider slug", "SB_BAD_SLUG");
    return this.connectors.accounts
      .list(filter.provider ? { provider: filter.provider } : {})
      .map((a) => {
        const def = this.connectors.providers.get(a.provider);
        const seed = a.provider_verification === "unverified_seed" || this.isSeed(a.provider);
        // `working` is a per-row notion (coverage); an account itself is never called working here.
        return { ...summarize(a), provider_name: def?.name ?? a.provider, source_kind: seed ? ("seed" as const) : ("curated" as const), working: false as const, probe_available: Boolean(def?.identity_probe) };
      });
  }

  async probe(id: string): Promise<{ ok: boolean; error?: string; status?: number; account: AccountSummary }> {
    if (!ACCOUNT_ID_RE.test(id)) throw new AdminError(400, "not an account id", "SB_BAD_ACCOUNT");
    const acct = this.connectors.accounts.find(id);
    if (!acct) throw new AdminError(404, `no connected account '${id}'`, "SB_ACCOUNT_NOT_FOUND");
    const def = this.connectors.providers.get(acct.provider);
    if (!def?.identity_probe) {
      // A seeded provider defines no probe: say so without touching the account (a failed non-probe must not stamp last_probe_at).
      return { ok: false, error: `${def?.name ?? acct.provider} defines no identity probe, so this account cannot be probed (a seeded definition is unverified by design)`, account: summarize(acct) };
    }
    const out = await this.connectors.accounts.probe(acct.id);
    return { ok: out.ok, ...(out.error ? { error: out.error } : {}), ...(out.status !== undefined ? { status: out.status } : {}), account: out.account };
  }

  // ── connect ──────────────────────────────────────────────────────────────────────────────────

  private checkScopes(scopes: unknown): string[] | undefined {
    if (scopes === undefined) return undefined;
    if (!Array.isArray(scopes) || scopes.length > 100 || !scopes.every((s) => typeof s === "string" && SCOPE_RE.test(s))) throw new AdminError(400, "scopes must be a list of up to 100 scope names", "SB_BAD_SCOPES");
    return scopes as string[];
  }

  private checkFields(auth: AuthDef, fields: unknown): Record<string, string> | undefined {
    if (fields === undefined) return undefined;
    if (typeof fields !== "object" || fields === null || Array.isArray(fields)) throw new AdminError(400, "fields must be an object of name to value", "SB_BAD_FIELDS");
    const declared = new Set(auth.fields.connected_account_initiation.map((f) => f.name));
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(fields as Record<string, unknown>)) {
      if (!FIELD_NAME_RE.test(k) || !declared.has(k)) throw new AdminError(400, `'${k}' is not a field of ${auth.id}`, "SB_BAD_FIELDS");
      if (typeof v !== "string" || v.length > 8192) throw new AdminError(400, `field '${k}' must be a string of at most 8192 characters`, "SB_BAD_FIELDS");
      out[k] = v;
    }
    return out;
  }

  /**
   * Start the provider's own connect flow. OAuth: build the consent URL (the owner opens it; the loopback
   * callback finishes the flow). No registered app: return the owner setup steps. A key or token: ask for the
   * fields, or store them when they are given. A seeded provider connects exactly like a curated one and its
   * account is stamped `unverified_seed`.
   */
  async connect(slug: string, body: ConnectBody = {}): Promise<ConnectOutcome> {
    const def = this.provider(slug);
    const auth = this.pickAuth(def, body.auth_id);
    if (!IMPLEMENTED_AUTH_MODES.includes(auth.mode)) {
      throw new AdminError(400, `${def.name}: authentication '${auth.id}' uses mode '${auth.mode}', which this build does not drive, so Connect is unavailable for it`, "SB_AUTH_NOT_DRIVEN");
    }
    const label = body.label ?? "default";
    if (!LABEL_RE.test(label)) throw new AdminError(400, "an account label may use letters, digits, dot, dash and underscore (1 to 48 characters)", "SB_BAD_LABEL");
    const scopes = this.checkScopes(body.scopes);
    const flows = this.connectors.flows;
    try {
      if (auth.mode === "oauth2" || auth.mode === "oauth2_cc") {
        const cfg = this.connectors.authConfigs.forProvider(def.slug, { auth_id: auth.id });
        if (!cfg) {
          return { status: "needs_setup", auth_id: auth.id, message: `${def.name} needs an OAuth app that you register first (nothing was started)`, owner_setup: this.ownerSetup(def, auth) };
        }
        if (auth.mode === "oauth2_cc") {
          const r = await flows.connectClientCredentials({ provider: def.slug, authId: auth.id, label, ...(scopes ? { scopes } : {}) });
          return { status: "connected", auth_id: auth.id, account: summarize(r.account) };
        }
        const r = flows.begin({ provider: def.slug, authId: auth.id, label, redirectUri: this.host.redirectUri(), ...(scopes ? { scopes } : {}) });
        return { status: "redirect", authorize_url: r.authorizeUrl, auth_id: auth.id, expires_at: r.expires_at };
      }
      const given = this.checkFields(auth, body.fields);
      const declared: FieldDef[] = auth.fields.connected_account_initiation;
      if (!given || declared.some((f) => f.required && !(given[f.name] ?? "").trim())) {
        return { status: "needs_input", auth_id: auth.id, message: `${def.name} connects with ${declared.length === 1 ? "one credential" : "these credentials"}`, fields: declared.map((f): FieldView => ({ name: f.name, ...(f.label ? { label: f.label } : {}), required: f.required, secret: f.secret })) };
      }
      const r = await flows.connectSecret({ provider: def.slug, authId: auth.id, label, fields: given });
      return { status: "connected", auth_id: auth.id, account: summarize(r.account) };
    } catch (err) {
      if (err instanceof AdminError) throw err;
      if (err instanceof ConnectorError) {
        if (err.detail?.needsApp) return { status: "needs_setup", auth_id: auth.id, message: `${def.name} needs an OAuth app that you register first (nothing was started)`, owner_setup: this.ownerSetup(def, auth) };
        throw new AdminError(err.code === CONNECTOR_ERR.ACCOUNT_NOT_FOUND ? 404 : 400, err.message, err.code);
      }
      throw err;
    }
  }

  // ── toolkits ─────────────────────────────────────────────────────────────────────────────────

  toolkits(): ToolkitRow[] {
    const index = this.coverageIndex();
    const out: ToolkitRow[] = [];
    for (const slug of this.connectors.kit.toolkits.slugs()) {
      const providerSlug = this.connectors.kit.toolkits.providerSlug(slug);
      const def = (providerSlug ? this.connectors.providers.get(providerSlug) : undefined) ?? this.connectors.providers.providerForToolkit(slug);
      if (def) out.push(this.toolkitRow(slug, def, index));
    }
    return out;
  }

  private knownToolkit(slug: string): string {
    if (!SLUG_RE.test(slug) || !this.connectors.kit.toolkits.slugs().includes(slug)) throw new AdminError(404, `no toolkit '${slug}' is defined here (switchboard toolkits list)`, "SB_TOOLKIT_NOT_FOUND");
    return slug;
  }

  private persist(): void {
    const path = this.host.configPath();
    if (path) writeConfig(path, this.host.config());
  }

  /** Turn a toolkit on: needs the toolkit synced and an ACTIVE, probed account (fail closed). Live: it is mounted now. */
  async enableToolkit(slug: string, opts: { account?: string } = {}): Promise<ToolkitRow> {
    this.knownToolkit(slug);
    const problem = toolkitEnableProblem(this.connectors, slug);
    if (problem) throw new AdminError(409, problem, "SB_TOOLKIT_NOT_READY");
    let pinned: string | undefined;
    if (opts.account !== undefined) {
      if (typeof opts.account !== "string" || !/^[A-Za-z0-9_./-]{1,80}$/.test(opts.account)) throw new AdminError(400, "not an account reference", "SB_BAD_ACCOUNT");
      const providerSlug = this.connectors.kit.toolkits.providerSlug(slug) ?? slug;
      try {
        const a = this.connectors.accounts.require(opts.account.includes("/") || opts.account.startsWith("ca_") ? opts.account : `${providerSlug}/${opts.account}`);
        if (a.provider !== providerSlug) throw new AdminError(400, `account ${a.id} belongs to ${a.provider}, not to ${slug}'s provider`, "SB_BAD_ACCOUNT");
        pinned = opts.account;
      } catch (err) {
        if (err instanceof ConnectorError) throw new AdminError(404, err.message, err.code);
        throw err;
      }
    }
    const cfg = this.host.config();
    const existing = this.connectorServer(slug);
    let created: ServerConfig | undefined;
    const before = existing ? { enabled: existing.enabled, account: existing.account } : undefined;
    let server: ServerConfig;
    if (existing) {
      existing.enabled = true;
      if (pinned) existing.account = pinned;
      server = existing;
    } else {
      if (cfg.servers.some((s) => s.id === slug)) throw new AdminError(409, `a server with id '${slug}' already exists`, "SB_SERVER_EXISTS");
      created = { id: slug, source: "connector", toolkit: slug, enabled: true, ...(pinned ? { account: pinned } : {}) };
      cfg.servers.push(created);
      server = created;
    }
    try {
      await this.host.unmount(server.id).catch(() => undefined);
      await this.host.mount(server);
      this.persist();
    } catch (err) {
      if (created) cfg.servers.splice(cfg.servers.indexOf(created), 1);
      else if (before) {
        existing!.enabled = before.enabled;
        if (before.account === undefined) delete existing!.account;
        else existing!.account = before.account;
      }
      throw new AdminError(500, err instanceof Error ? err.message : String(err), "SB_MOUNT_FAILED");
    }
    return this.toolkits().find((t) => t.slug === slug)!;
  }

  /** Turn a toolkit off: unmounted now, the server stays in the config. */
  async disableToolkit(slug: string): Promise<ToolkitRow> {
    this.knownToolkit(slug);
    const server = this.connectorServer(slug);
    if (!server) throw new AdminError(404, `no connector server for toolkit '${slug}' (it was never enabled)`, "SB_NO_SERVER");
    const was = server.enabled;
    server.enabled = false;
    try {
      await this.host.unmount(server.id).catch(() => undefined);
      this.persist();
    } catch (err) {
      server.enabled = was;
      throw new AdminError(500, err instanceof Error ? err.message : String(err), "SB_UNMOUNT_FAILED");
    }
    return this.toolkits().find((t) => t.slug === slug)!;
  }

  // ── coverage ─────────────────────────────────────────────────────────────────────────────────

  coverage(): Record<string, unknown> {
    const cov = this.connectors.kit.coverage;
    const rows = cov.rows().length;
    if (rows === 0) return { imported: false, rows: 0, working: 0, addressable: 0, note: "no checklist rows imported: `switchboard coverage --import <dir>` loads them" };
    const r = cov.report();
    return {
      imported: true,
      rows: r.total.rows,
      working: r.total.working,
      addressable: r.total.addressable,
      counts: r.total.counts,
      toolkits: r.toolkits.map((t) => ({ toolkit: t.our_toolkit, rows: t.rows, working: t.working, addressable: t.addressable })),
      ignored_lines: r.ignored_lines.length,
      note: "working means a row proven live by an owner-run probe; registered and mapped rows are not working rows, and a seeded provider can never be working",
    };
  }
}

