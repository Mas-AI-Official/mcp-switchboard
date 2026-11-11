/**
 * publicapi: consented, declarative access to vetted no-key public APIs.
 *
 * One versioned manifest (publicapi/catalog.v1.json) describes every provider: hosts, terms, commercial-use
 * status, rate limits and each tool's request template and result shape. There is NO provider-specific code:
 * this file is a generic executor, and every other language port (MeetingOPS ships a Python one) must pass the
 * same conformance vectors (publicapi/conformance.v1.json). Apps embed the executor; no gateway process needed.
 *
 * Guarantees, in check order (all before any network):
 *   unknown provider/tool -> provider not usable here (UNVERIFIED, UNAVAILABLE, PAID, or non-commercial terms in a
 *   commercial app) -> consent not granted -> provider switched off -> argument validation (no unknown args, types,
 *   pattern, enum, max_length, range) -> https and host allowlist -> local rate limit and daily quota.
 * Redirects are followed by hand (max 3) and each hop must stay on the allowlist. No key, no paid fallback.
 */

import { readFileSync, writeFileSync, mkdirSync, renameSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { guardedFetch, NetGuardError } from "./netguard.js";

export type ProviderStatus = "VERIFIED_FREE" | "FREE_TIER" | "RESTRICTED" | "PAID" | "UNAVAILABLE" | "UNVERIFIED";
export type Consent = "unset" | "granted" | "declined";
export type PublicApiErrorCode =
  | "UNKNOWN_PROVIDER" | "UNKNOWN_TOOL" | "PROVIDER_UNAVAILABLE" | "CONSENT_REQUIRED" | "PROVIDER_DISABLED"
  | "INVALID_ARGS" | "HOST_NOT_ALLOWED" | "RATE_LIMITED" | "OFFLINE" | "TIMEOUT" | "UPSTREAM_ERROR" | "BAD_RESPONSE";

export interface ParamSpec {
  name: string; in: "path" | "query"; type: "string" | "integer" | "number"; required?: boolean;
  pattern?: string; enum?: string[]; max_length?: number; min?: number; max?: number; description?: string;
}
export interface ToolSpec {
  name: string; title: string; description: string; path: string;
  query_fixed?: Record<string, string>; params: ParamSpec[];
  result: { root?: string; max_items?: number; fields: Record<string, string> };
}
export interface ProviderSpec {
  id: string; name: string; category: string; status: ProviderStatus; auth: "none";
  base_url: string; allowed_hosts: string[]; docs_url: string; terms_url: string; source_refs: string[];
  commercial_use: "yes" | "conditional" | "no" | "unknown"; commercial_note: string;
  data_licence: string; attribution: string; cost: string;
  rate_limit: { min_interval_ms: number; per_day: number; note?: string };
  privacy: string; timeout_ms: number; verified_at: string; recommended_for: string[]; apps: string[]; tools: ToolSpec[];
}
export interface Catalog { schema: string; catalog_version: string; user_agent: string; providers: ProviderSpec[] }
export interface AppProfile { id: string; commercial: boolean }
export interface Usage { day: string; count: number; last_ms: number }
export interface PublicApiState { version: 1; consent: Consent; decided_at?: string; enabled: string[]; usage: Record<string, Usage> }
export interface PublicApiError { code: PublicApiErrorCode; message: string }
export type Plan = { ok: true; url: string; provider: ProviderSpec; tool: ToolSpec } | { ok: false; error: PublicApiError };
export type CallResult =
  | { ok: true; data: unknown; source: { provider: string; tool: string; url: string; attribution: string; licence: string; fetched_at: string } }
  | { ok: false; error: PublicApiError };

const MAX_BYTES = 1024 * 1024;
const MAX_REDIRECTS = 3;
const UNUSABLE: ProviderStatus[] = ["UNVERIFIED", "UNAVAILABLE", "PAID"];

export function emptyState(): PublicApiState {
  return { version: 1, consent: "unset", enabled: [], usage: {} };
}

/** The bundled manifest shipped with this package. */
export function loadBundledCatalog(): Catalog {
  const here = dirname(fileURLToPath(import.meta.url));
  return JSON.parse(readFileSync(join(here, "..", "publicapi", "catalog.v1.json"), "utf8")) as Catalog;
}

/** RFC 3986 strict: only unreserved characters stay literal. Identical to Python quote(s, safe=""). */
export function encodeComponent(s: string): string {
  return encodeURIComponent(s).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
}

function fmt(v: string | number): string {
  return typeof v === "number" ? (Number.isInteger(v) ? v.toFixed(0) : String(v)) : v;
}

/** Can this provider ever run inside this app? (Independent of consent and toggles.) */
export function eligibility(p: ProviderSpec, app: AppProfile): { eligible: boolean; reason?: string } {
  if (!p.apps.includes(app.id)) return { eligible: false, reason: `not offered in ${app.id}` };
  if (UNUSABLE.includes(p.status)) return { eligible: false, reason: `status ${p.status}` };
  if (p.auth !== "none") return { eligible: false, reason: "needs a credential" };
  if (app.commercial && (p.status === "RESTRICTED" || p.commercial_use === "no" || p.commercial_use === "unknown"))
    return { eligible: false, reason: "provider terms do not allow commercial use on the free tier" };
  return { eligible: true };
}

function fail(code: PublicApiErrorCode, message: string): { ok: false; error: PublicApiError } {
  return { ok: false, error: { code, message } };
}

function validate(spec: ParamSpec, v: unknown): string | null {
  if (spec.type === "string") {
    if (typeof v !== "string") return "must be a string";
    if (spec.max_length !== undefined && v.length > spec.max_length) return `longer than ${spec.max_length} characters`;
    if (spec.pattern && !new RegExp(spec.pattern).test(v)) return "has an invalid format";
    if (spec.enum && !spec.enum.includes(v)) return "is not an allowed value";
    if (spec.in === "path" && v.length === 0) return "is empty";
    return null;
  }
  if (typeof v !== "number" || !Number.isFinite(v)) return "must be a number";
  if (spec.type === "integer" && !Number.isInteger(v)) return "must be an integer";
  if (spec.min !== undefined && v < spec.min) return `below ${spec.min}`;
  if (spec.max !== undefined && v > spec.max) return `above ${spec.max}`;
  return null;
}

/** Every check that happens before the network, and the exact URL. Pure: the conformance vectors run this. */
export function planCall(
  catalog: Catalog, app: AppProfile, state: PublicApiState, providerId: string, toolName: string,
  args: Record<string, unknown>, now: { ms: number; day: string },
): Plan {
  const provider = catalog.providers.find((p) => p.id === providerId);
  if (!provider) return fail("UNKNOWN_PROVIDER", `no provider ${providerId}`);
  const tool = provider.tools.find((t) => t.name === toolName);
  if (!tool) return fail("UNKNOWN_TOOL", `${providerId} has no tool ${toolName}`);
  const el = eligibility(provider, app);
  if (!el.eligible) return fail("PROVIDER_UNAVAILABLE", `${provider.name} cannot be used here: ${el.reason}`);
  if (state.consent !== "granted") return fail("CONSENT_REQUIRED", "Public API tools are off. Turn them on in Settings first.");
  if (!state.enabled.includes(providerId)) return fail("PROVIDER_DISABLED", `${provider.name} is switched off in Settings.`);

  for (const k of Object.keys(args)) {
    if (!tool.params.some((p) => p.name === k)) return fail("INVALID_ARGS", `unknown argument ${k}`);
  }
  let path = tool.path;
  const query: string[] = Object.entries(tool.query_fixed ?? {}).map(([k, v]) => `${encodeComponent(k)}=${encodeComponent(v)}`);
  for (const spec of tool.params) {
    const v = args[spec.name];
    if (v === undefined || v === null) {
      if (spec.required) return fail("INVALID_ARGS", `${spec.name} is required`);
      continue;
    }
    const problem = validate(spec, v);
    if (problem) return fail("INVALID_ARGS", `${spec.name} ${problem}`);
    const enc = encodeComponent(fmt(v as string | number));
    if (spec.in === "path") path = path.split(`{${spec.name}}`).join(enc);
    else query.push(`${encodeComponent(spec.name)}=${enc}`);
  }
  const url = provider.base_url + path + (query.length ? "?" + query.join("&") : "");
  if (!hostAllowed(url, provider)) return fail("HOST_NOT_ALLOWED", `${url} is outside ${provider.id}'s allowlist`);

  const u = state.usage[providerId];
  if (u && u.day === now.day && u.count >= provider.rate_limit.per_day)
    return fail("RATE_LIMITED", `${provider.name} daily limit (${provider.rate_limit.per_day}) reached; resets tomorrow.`);
  if (u && now.ms - u.last_ms < provider.rate_limit.min_interval_ms)
    return fail("RATE_LIMITED", `${provider.name} was called too recently; try again in a moment.`);
  return { ok: true, url, provider, tool };
}

function hostAllowed(url: string, p: ProviderSpec): boolean {
  try {
    const u = new URL(url);
    return u.protocol === "https:" && p.allowed_hosts.includes(u.hostname.toLowerCase()) && (u.port === "" || u.port === "443");
  } catch {
    return false;
  }
}

function dig(obj: unknown, path: string): unknown {
  if (path === "") return obj;
  let cur: unknown = obj;
  for (const seg of path.split(".")) {
    if (Array.isArray(cur) && /^\d+$/.test(seg)) cur = cur[Number(seg)];
    else if (cur !== null && typeof cur === "object" && !Array.isArray(cur)) cur = (cur as Record<string, unknown>)[seg];
    else return null;
    if (cur === undefined) return null;
  }
  return cur;
}

/** Keep only the declared fields. Pure: the conformance vectors run this. */
export function shapeResult(tool: ToolSpec, body: unknown): unknown {
  const pick = (item: unknown) => Object.fromEntries(Object.entries(tool.result.fields).map(([out, p]) => [out, dig(item, p) ?? null]));
  const root = dig(body, tool.result.root ?? "");
  if (Array.isArray(root)) return root.slice(0, tool.result.max_items ?? 10).map(pick);
  return pick(root);
}

export interface StateStore { load(): PublicApiState; save(s: PublicApiState): void }

/** A JSON file store with atomic replace. */
export function fileStateStore(path: string): StateStore {
  return {
    load() {
      try {
        const s = JSON.parse(readFileSync(path, "utf8")) as PublicApiState;
        return s && s.version === 1 ? { ...emptyState(), ...s } : emptyState();
      } catch {
        return emptyState();
      }
    },
    save(s) {
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path + ".tmp", JSON.stringify(s, null, 2));
      renameSync(path + ".tmp", path);
    },
  };
}

export type FirstRunChoice = "recommended" | "custom" | "not_now";

export class PublicApiClient {
  readonly catalog: Catalog;
  readonly app: AppProfile;
  private store: StateStore;
  private clock: () => number;
  private fetcher: typeof guardedFetch;
  private lastError: Record<string, PublicApiError> = {};

  constructor(opts: { app: AppProfile; store: StateStore; catalog?: Catalog; clock?: () => number; fetcher?: typeof guardedFetch }) {
    this.catalog = opts.catalog ?? loadBundledCatalog();
    this.app = opts.app;
    this.store = opts.store;
    this.clock = opts.clock ?? Date.now;
    this.fetcher = opts.fetcher ?? guardedFetch;
  }

  /** True until the user has answered the first-run question once. */
  needsPrompt(): boolean {
    return this.store.load().consent === "unset";
  }

  recommended(): string[] {
    return this.catalog.providers.filter((p) => p.recommended_for.includes(this.app.id) && eligibility(p, this.app).eligible).map((p) => p.id);
  }

  decide(choice: FirstRunChoice, ids: string[] = []): PublicApiState {
    const s = this.store.load();
    s.decided_at = new Date(this.clock()).toISOString();
    if (choice === "not_now") {
      s.consent = "declined";
    } else {
      const chosen = choice === "recommended" ? this.recommended() : ids;
      this.assertEligible(chosen);
      s.consent = "granted";
      s.enabled = [...new Set(chosen)];
    }
    this.store.save(s);
    return s;
  }

  /** Master switch. Off keeps the per-provider choices so turning it back on restores them. */
  setMaster(on: boolean): PublicApiState {
    const s = this.store.load();
    s.consent = on ? "granted" : "declined";
    s.decided_at = new Date(this.clock()).toISOString();
    if (on && s.enabled.length === 0) s.enabled = this.recommended();
    this.store.save(s);
    return s;
  }

  setProvider(id: string, on: boolean): PublicApiState {
    const s = this.store.load();
    if (on) {
      this.assertEligible([id]);
      if (!s.enabled.includes(id)) s.enabled.push(id);
    } else {
      s.enabled = s.enabled.filter((x) => x !== id);
    }
    this.store.save(s);
    return s;
  }

  private assertEligible(ids: string[]): void {
    for (const id of ids) {
      const p = this.catalog.providers.find((x) => x.id === id);
      if (!p) throw new Error(`unknown provider ${id}`);
      const el = eligibility(p, this.app);
      if (!el.eligible) throw new Error(`${p.name} cannot be enabled here: ${el.reason}`);
    }
  }

  /** Local status only; never touches the network. */
  status() {
    const s = this.store.load();
    const today = this.today();
    return {
      catalog_version: this.catalog.catalog_version,
      consent: s.consent,
      decided_at: s.decided_at ?? null,
      providers: this.catalog.providers.filter((p) => p.apps.includes(this.app.id)).map((p) => {
        const el = eligibility(p, this.app);
        const u = s.usage[p.id];
        return {
          id: p.id, name: p.name, category: p.category, status: p.status, eligible: el.eligible, reason: el.reason ?? null,
          enabled: s.consent === "granted" && s.enabled.includes(p.id), recommended: p.recommended_for.includes(this.app.id) && el.eligible,
          commercial_use: p.commercial_use, commercial_note: p.commercial_note, attribution: p.attribution, privacy: p.privacy,
          docs_url: p.docs_url, terms_url: p.terms_url, verified_at: p.verified_at,
          tools: p.tools.map((t) => ({ name: t.name, title: t.title, description: t.description, params: t.params })),
          used_today: u && u.day === today ? u.count : 0, per_day: p.rate_limit.per_day, last_error: this.lastError[p.id] ?? null,
        };
      }),
    };
  }

  private today(): string {
    return new Date(this.clock()).toISOString().slice(0, 10);
  }

  async call(providerId: string, toolName: string, args: Record<string, unknown>): Promise<CallResult> {
    const s = this.store.load();
    const ms = this.clock();
    const plan = planCall(this.catalog, this.app, s, providerId, toolName, args, { ms, day: this.today() });
    if (!plan.ok) return plan;
    const u = s.usage[providerId];
    s.usage[providerId] = { day: this.today(), count: u && u.day === this.today() ? u.count + 1 : 1, last_ms: ms };
    this.store.save(s);
    const result = await this.fetchJson(plan.url, plan.provider);
    if (!result.ok) {
      this.lastError[providerId] = result.error;
      return result;
    }
    delete this.lastError[providerId];
    return {
      ok: true,
      data: shapeResult(plan.tool, result.body),
      source: {
        provider: plan.provider.id, tool: plan.tool.name, url: plan.url, attribution: plan.provider.attribution,
        licence: plan.provider.data_licence, fetched_at: new Date(this.clock()).toISOString(),
      },
    };
  }

  private async fetchJson(url: string, p: ProviderSpec): Promise<{ ok: true; body: unknown } | { ok: false; error: PublicApiError }> {
    let target = url;
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      if (!hostAllowed(target, p)) return fail("HOST_NOT_ALLOWED", `redirect to ${target} left ${p.id}'s allowlist`);
      let res;
      try {
        res = await this.fetcher(target, {
          method: "GET", redirect: "manual", timeoutMs: p.timeout_ms, maxBytes: MAX_BYTES,
          headers: { "User-Agent": this.catalog.user_agent, Accept: "application/json" },
        });
      } catch (e) {
        if (e instanceof NetGuardError) {
          if (e.code === "timeout") return fail("TIMEOUT", `${p.name} did not answer in ${p.timeout_ms} ms`);
          if (e.code === "dns_failed") return fail("OFFLINE", `${p.name} is unreachable (offline?)`);
          if (e.code === "too_large") return fail("BAD_RESPONSE", `${p.name} answered with more than 1 MB`);
          return fail("UPSTREAM_ERROR", e.message);
        }
        return fail("OFFLINE", `${p.name} is unreachable: ${(e as Error).message}`);
      }
      if ([301, 302, 303, 307, 308].includes(res.status)) {
        const loc = res.headers.get("location");
        if (!loc) return fail("UPSTREAM_ERROR", "redirect without a location");
        target = new URL(loc, target).toString();
        continue;
      }
      if (res.status === 429) return fail("RATE_LIMITED", `${p.name} asked us to slow down (HTTP 429)`);
      if (!res.ok) return fail("UPSTREAM_ERROR", `${p.name} answered HTTP ${res.status}`);
      try {
        return { ok: true, body: await res.json() };
      } catch {
        return fail("BAD_RESPONSE", `${p.name} did not return JSON`);
      }
    }
    return fail("UPSTREAM_ERROR", "too many redirects");
  }
}
