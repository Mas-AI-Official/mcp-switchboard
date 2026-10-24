/**
 * Toolkits (ADR local-composio, sections 6.1 and 6.2): versioned Toolkit and Action definitions.
 *
 * Three kinds of file feed one toolkit, and only the first kind ever leaves the repository's control:
 *   1. GENERATED actions, written by `switchboard toolkits sync` from the provider's own public spec
 *      (Google Discovery document, OpenAPI, Swagger) to `<SWITCHBOARD_HOME>/toolkits/<slug>/<version>/actions.json`
 *      on the operator's machine. They are never committed (vendor spec redistribution terms are not ours to
 *      grant, ADR risk R11) and carry a version `YYYYMMDD_NN` so an audit row names the exact definition used.
 *   2. RECIPES, authored by us (`src/connectors/toolkits/<slug>/recipes/*.json`): multi-step composite actions
 *      for platforms with no machine-readable spec or where one call is not enough (resumable upload,
 *      container then poll then publish). See recipes.ts.
 *   3. an OVERLAY (`src/connectors/toolkits/<slug>/overlay.json`, plus an optional owner copy under
 *      `<SWITCHBOARD_HOME>/toolkits/<slug>/overlay.json`): rename, hide, tags, risk, `important`, description
 *      trim. An overlay may only TIGHTEN a safety property (scope, risk, outward). It can raise a GET to write
 *      or a call to high risk; it can never lower a DELETE to read. A loosening entry is ignored and reported.
 *
 * Tool names are `<toolkit>__<action>` and must stay within 64 characters (a client constraint), so an
 * action slug is at most `64 - len(toolkit) - 2`.
 */

import { existsSync, mkdirSync, readFileSync, readdirSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import AjvImport from "ajv";
import type { ValidateFunction } from "ajv";
import type { Scope } from "../types.js";
import { atomicWriteFileSync } from "../atomicfile.js";
import { validateRecipeSteps, type RecipeStep } from "./recipes.js";

// ── types ─────────────────────────────────────────────────────────────────────────────────────────

export type Risk = "low" | "medium" | "high";

export const VERIFICATION_STATES = ["unmapped", "mapped", "mock_tested", "live_verified", "blocked_by_platform", "declined", "deprecated"] as const;
export type VerificationState = (typeof VERIFICATION_STATES)[number];

export const SCOPE_RANK: Record<Scope, number> = { read: 0, write: 1, full: 2 };
export const RISK_RANK: Record<Risk, number> = { low: 0, medium: 1, high: 2 };

export const MAX_TOOL_NAME = 64;
export const TOOL_SEP = "__";

export const tighterScope = (a: Scope, b: Scope): Scope => (SCOPE_RANK[a] >= SCOPE_RANK[b] ? a : b);
export const tighterRisk = (a: Risk, b: Risk): Risk => (RISK_RANK[a] >= RISK_RANK[b] ? a : b);

/** Where one exposed argument goes in the HTTP request. */
export interface ParamBinding {
  in: "path" | "query" | "header" | "body";
  /** The provider's name for it (the exposed key may differ after a collision). */
  name: string;
  required: boolean;
  /** Path template `{+var}`: reserved expansion, slashes are kept. */
  reserved?: boolean;
  /** `part=a&part=b` instead of one comma separated value. */
  repeated?: boolean;
}

/** Media upload a Discovery method supports (YouTube videos.insert, Drive files.create). */
export interface UploadSpec {
  /** The exposed argument that carries the file (path, https URL or `staged:<id>`). */
  param: string;
  resumable_path?: string;
  simple_path?: string;
  accept: string[];
  max_bytes?: number;
}

/** A single HTTP call. Spec derived actions carry this; recipes carry `steps` instead. */
export interface ActionHttp {
  method: string;
  base_url: string;
  /** Appended to `base_url`; `{name}` segments are filled from the bound path arguments. */
  path: string;
  params: Record<string, ParamBinding>;
  /** `merged`: top level object fields of the body are exposed beside the other arguments; `nested`: one `body` argument. */
  body: "none" | "merged" | "nested";
  body_type: "json" | "form" | "multipart" | "binary";
  upload?: UploadSpec;
  /** The response may be a file (media download): raise the response cap to the download limit. */
  download?: boolean;
}

export interface ActionFiles {
  /** Exposed argument names that take a file. */
  upload: string[];
  /** Dotted paths in the output that are files (informational; binary responses are saved regardless). */
  download: string[];
}

export interface Action {
  /** Without the toolkit prefix. The tool name is `<toolkit>__<slug>`. */
  slug: string;
  title: string;
  description: string;
  input_schema: Record<string, unknown>;
  output_schema?: Record<string, unknown>;
  http?: ActionHttp;
  /** Default base URL for a recipe's relative request paths. */
  base_url?: string;
  /** The raw authenticated call (`proxy_request`): built in code, never stored. */
  proxy?: boolean;
  steps?: RecipeStep[];
  /** Recipe result template; default is the last step's body. */
  result?: unknown;
  /** The provider's OAuth scopes this call needs (informational, used by coverage and the connect flow). */
  scopes: string[];
  scope: Scope;
  risk: Risk;
  /** True when the call is visible to other people (a post, a message, a share). Forces high risk. */
  outward: boolean;
  /** False: never auto-retried; a failure after the request left returns a reconcile hint instead. */
  idempotent: boolean;
  important: boolean;
  tags: string[];
  deprecated: boolean;
  files?: ActionFiles;
  /** What the owner should do to find out whether a non-idempotent call took effect. */
  reconcile?: string;
  /** `always`: a human decision is required on every call (proxy_request). */
  approval?: "always";
  verification: VerificationState;
  /** Where the definition came from, for traceability and coverage mapping. */
  origin?: { operation?: string; http?: string };
}

export interface GeneratedMeta {
  toolkit: string;
  provider: string;
  version: string;
  source: { kind: "discovery" | "openapi"; url: string; fetched_at: string; spec_hash: string; spec_revision?: string; spec_version?: string };
  base_url: string;
  /** Operations the importer produced, before the overlay hid any. */
  generated_count: number;
}

export interface GeneratedDoc extends GeneratedMeta {
  actions: Action[];
}

export interface Toolkit {
  slug: string;
  provider: string;
  version: string;
  available_versions: string[];
  source: "spec" | "recipe" | "mcp" | "piece";
  tools_count: number;
  triggers_count: number;
  verification_summary: Record<VerificationState, number>;
  actions: Action[];
  /** Operations hidden by the overlay (counted, never exposed). */
  hidden_count: number;
  /** Overlay entries that were ignored (a loosening attempt, an action the spec no longer has). */
  overlay_issues: string[];
  base_url?: string;
  spec?: GeneratedMeta["source"];
}

export interface ToolkitOverlay {
  toolkit?: string;
  provider?: string;
  /** Where `toolkits sync` fetches the provider's spec. */
  source?: { kind: "discovery" | "openapi"; url: string; note?: string };
  /** Keys below name the GENERATED action slug (before `rename`). */
  rename?: Record<string, string>;
  hide?: string[];
  /** Owner overlay only: actions a bundled overlay hides that this owner wants back. */
  unhide?: string[];
  tags?: Record<string, string[]>;
  risk?: Record<string, Risk>;
  scope?: Record<string, Scope>;
  /** Actions that are visible to other people: marks `outward` and forces high risk. */
  outward?: string[];
  idempotent?: Record<string, boolean>;
  important?: string[];
  /** Maximum action description length. */
  description_trim?: number;
  reconcile?: Record<string, string>;
}

// ── naming ────────────────────────────────────────────────────────────────────────────────────────

/** `playlistItems.insert` -> `playlist_items_insert`; anything outside [a-z0-9_] becomes `_`. */
export function toSnake(raw: string): string {
  const s = raw
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  return s || "action";
}

export function maxActionSlug(toolkit: string): number {
  return MAX_TOOL_NAME - toolkit.length - TOOL_SEP.length;
}

const sha8 = (s: string): string => createHash("sha256").update(s).digest("hex").slice(0, 6);

/** A slug that fits the length budget and is not in `taken`; the original is cut and given a hash tail. */
export function uniqueSlug(base: string, taken: Set<string>, max: number): string {
  let slug = base.length > max ? `${base.slice(0, Math.max(1, max - 7)).replace(/_+$/, "")}_${sha8(base)}` : base;
  let i = 2;
  while (taken.has(slug)) {
    const suffix = `_${i++}`;
    slug = `${(base.length > max - suffix.length ? base.slice(0, max - suffix.length) : base).replace(/_+$/, "")}${suffix}`;
  }
  taken.add(slug);
  return slug;
}

/** Heuristic: the verb in an action name says other people will see the result. */
const OUTWARD_WORDS = /(^|_)(send|publish|post|tweet|share|invite|reply|comment|message|broadcast|announce|notify|dm)(_|$)/;
/** Heuristic: the verb in an action name says something is removed, whatever HTTP method carries it. */
const DESTRUCTIVE_WORDS = /(^|_)(delete|destroy|purge|remove|revoke|empty|wipe|terminate|trash)(_|$)/;

export interface Safety {
  scope: Scope;
  risk: Risk;
  outward: boolean;
  idempotent: boolean;
}

/**
 * The defaults for a spec derived action: GET and HEAD read, DELETE full, everything else write; DELETE is high
 * risk, writes medium, reads low. A name that says delete/remove/revoke/trash is full and high whatever the verb
 * (a POST `batchDelete`, a Slack GET `auth.revoke`); one that says send/publish/post/comment... is outward and so
 * high risk. Only a
 * human-authored overlay or recipe can raise these further; nothing lowers them.
 */
export function deriveSafety(method: string, name: string, hints: { scope?: unknown; risk?: unknown } = {}): Safety {
  const m = method.toUpperCase();
  const snake = toSnake(name);
  let scope: Scope = m === "GET" || m === "HEAD" || m === "OPTIONS" ? "read" : m === "DELETE" ? "full" : "write";
  // A name that says delete/revoke is destructive even when the provider lets a GET carry it (Slack's auth.revoke).
  if (DESTRUCTIVE_WORDS.test(snake)) scope = "full";
  let risk: Risk = scope === "read" ? "low" : scope === "full" ? "high" : "medium";
  // Operation ids often start with the HTTP verb (`post_search`): that verb says nothing about who sees the result.
  const outward = scope !== "read" && OUTWARD_WORDS.test(snake.replace(/^(get|post|put|patch|delete|head)_/, ""));
  if (outward) risk = tighterRisk(risk, "high");
  // An upstream hint (an `x-mcp-scope` / `x-mcp-risk` vendor extension) can only tighten.
  if (hints.scope === "read" || hints.scope === "write" || hints.scope === "full") scope = tighterScope(scope, hints.scope);
  if (hints.risk === "low" || hints.risk === "medium" || hints.risk === "high") risk = tighterRisk(risk, hints.risk);
  if (scope === "full") risk = tighterRisk(risk, "high");
  return { scope, risk, outward, idempotent: m === "GET" || m === "HEAD" || m === "OPTIONS" || m === "PUT" || m === "DELETE" };
}

// ── overlay ───────────────────────────────────────────────────────────────────────────────────────

export interface OverlayResult {
  actions: Action[];
  hidden: number;
  issues: string[];
}

/**
 * Apply an overlay to generated or recipe actions. Pure: the input is not modified. Safety properties only
 * tighten; every ignored or dangling entry is returned in `issues` so drift after a re-sync is visible.
 */
export function applyOverlay(toolkit: string, input: Action[], overlay: ToolkitOverlay): OverlayResult {
  const issues: string[] = [];
  const bySlug = new Map(input.map((a) => [a.slug, a] as const));
  const known = (key: string, where: string): boolean => {
    if (bySlug.has(key)) return true;
    issues.push(`overlay ${where} names '${key}', which is not an action of ${toolkit}`);
    return false;
  };
  const trim = overlay.description_trim;
  const out: Action[] = [];
  const hide = new Set(overlay.hide ?? []);
  for (const key of hide) known(key, "hide");
  for (const k of Object.keys(overlay.rename ?? {})) known(k, "rename");
  for (const k of Object.keys(overlay.tags ?? {})) known(k, "tags");
  for (const k of Object.keys(overlay.risk ?? {})) known(k, "risk");
  for (const k of Object.keys(overlay.scope ?? {})) known(k, "scope");
  for (const k of overlay.outward ?? []) known(k, "outward");
  for (const k of Object.keys(overlay.idempotent ?? {})) known(k, "idempotent");
  for (const k of overlay.important ?? []) known(k, "important");
  for (const k of Object.keys(overlay.reconcile ?? {})) known(k, "reconcile");

  let hidden = 0;
  for (const a of input) {
    if (hide.has(a.slug)) {
      hidden += 1;
      continue;
    }
    const next: Action = { ...a, tags: [...a.tags], scopes: [...a.scopes] };
    const wantScope = overlay.scope?.[a.slug];
    if (wantScope) {
      if (SCOPE_RANK[wantScope] < SCOPE_RANK[next.scope]) issues.push(`overlay scope '${wantScope}' for '${a.slug}' would loosen '${next.scope}': ignored`);
      else next.scope = wantScope;
    }
    const wantRisk = overlay.risk?.[a.slug];
    if (wantRisk) {
      if (RISK_RANK[wantRisk] < RISK_RANK[next.risk]) issues.push(`overlay risk '${wantRisk}' for '${a.slug}' would loosen '${next.risk}': ignored`);
      else next.risk = wantRisk;
    }
    if (overlay.outward?.includes(a.slug)) next.outward = true;
    // `outward` forces high risk, wherever it came from (ADR 6.4 and risk R6); so does full scope, as in deriveSafety.
    if (next.outward || next.scope === "full") next.risk = tighterRisk(next.risk, "high");
    const idem = overlay.idempotent?.[a.slug];
    if (idem !== undefined) next.idempotent = idem;
    const tags = overlay.tags?.[a.slug];
    if (tags) next.tags = [...new Set([...next.tags, ...tags])];
    if (overlay.important?.includes(a.slug)) next.important = true;
    const rec = overlay.reconcile?.[a.slug];
    if (rec) next.reconcile = rec;
    if (trim && next.description.length > trim) next.description = `${next.description.slice(0, Math.max(1, trim - 3)).trimEnd()}...`;
    out.push(next);
  }

  // Renames last, so every overlay key above names the generated slug.
  const taken = new Set(out.map((a) => a.slug));
  const max = maxActionSlug(toolkit);
  for (const a of out) {
    const to = overlay.rename?.[a.slug];
    if (!to) continue;
    if (!/^[a-z0-9_]+$/.test(to) || to.length > max) {
      issues.push(`overlay rename '${a.slug}' -> '${to}' is not a valid action slug (a-z0-9_ and at most ${max} characters): ignored`);
      continue;
    }
    if (taken.has(to) && to !== a.slug) {
      issues.push(`overlay rename '${a.slug}' -> '${to}' collides with another action: ignored`);
      continue;
    }
    taken.delete(a.slug);
    taken.add(to);
    a.slug = to;
  }
  return { actions: out, hidden, issues };
}

// ── bundled and generated locations ───────────────────────────────────────────────────────────────

const HERE = dirname(fileURLToPath(import.meta.url));

/** The bundled overlays and recipes: the built copy next to this module, else a source checkout. */
export function bundledToolkitDir(): string {
  const candidates = [join(HERE, "toolkits"), join(HERE, "..", "..", "src", "connectors", "toolkits")];
  return candidates.find((d) => existsSync(d)) ?? candidates[0]!;
}

const VERSION_RE = /^\d{8}_\d{2}$/;
const SLUG_RE = /^[a-z][a-z0-9-]{0,31}$/;

function readJson<T>(path: string): T | undefined {
  try {
    return JSON.parse(readFileSync(path, "utf8")) as T;
  } catch {
    return undefined;
  }
}

function stampOf(path: string): string {
  try {
    const s = statSync(path);
    return `${s.mtimeMs}:${s.size}`;
  } catch {
    return "-";
  }
}

export class ToolkitStore {
  private readonly home: string;
  private readonly bundled: string;
  private readonly cache = new Map<string, { stamp: string; toolkit: Toolkit }>();

  constructor(opts: { home: string; bundledDir?: string }) {
    this.home = join(opts.home, "toolkits");
    this.bundled = opts.bundledDir ?? bundledToolkitDir();
  }

  get generatedRoot(): string {
    return this.home;
  }

  /** Every toolkit slug we know a definition for: generated, or bundled with an overlay or recipes. */
  slugs(): string[] {
    const out = new Set<string>();
    for (const root of [this.home, this.bundled]) {
      if (!existsSync(root)) continue;
      for (const e of readdirSync(root, { withFileTypes: true })) if (e.isDirectory() && SLUG_RE.test(e.name)) out.add(e.name);
    }
    return [...out].sort();
  }

  bundledOverlay(slug: string): ToolkitOverlay {
    return readJson<ToolkitOverlay>(join(this.bundled, slug, "overlay.json")) ?? {};
  }

  /** The bundled overlay with the owner's copy merged over it (owner entries win per key). */
  overlay(slug: string): ToolkitOverlay {
    const base = this.bundledOverlay(slug);
    const owner = readJson<ToolkitOverlay>(join(this.home, slug, "overlay.json"));
    if (!owner) return base;
    const merged: ToolkitOverlay = { ...base, ...owner };
    for (const key of ["rename", "tags", "risk", "scope", "idempotent", "reconcile"] as const) {
      if (base[key] || owner[key]) (merged as Record<string, unknown>)[key] = { ...(base[key] ?? {}), ...(owner[key] ?? {}) };
    }
    for (const key of ["hide", "outward", "important"] as const) {
      if (base[key] || owner[key]) (merged as Record<string, unknown>)[key] = [...new Set([...(base[key] ?? []), ...(owner[key] ?? [])])];
    }
    if (owner.unhide?.length) merged.hide = (merged.hide ?? []).filter((h) => !owner.unhide!.includes(h));
    return merged;
  }

  /** Where `toolkits sync` should fetch this toolkit from, or undefined for a recipe only toolkit. */
  sourceOf(slug: string): ToolkitOverlay["source"] | undefined {
    return this.overlay(slug).source;
  }

  providerSlug(slug: string): string | undefined {
    const o = this.overlay(slug);
    return o.provider ?? this.currentMeta(slug)?.provider ?? this.recipeFiles(slug).map((r) => (r as { provider?: string }).provider).find(Boolean);
  }

  versions(slug: string): string[] {
    const dir = join(this.home, slug);
    if (!existsSync(dir)) return [];
    return readdirSync(dir, { withFileTypes: true })
      .filter((e) => e.isDirectory() && VERSION_RE.test(e.name))
      .map((e) => e.name)
      .sort();
  }

  currentVersion(slug: string): string | undefined {
    const pointer = readJson<{ version?: string }>(join(this.home, slug, "current.json"));
    if (pointer?.version && VERSION_RE.test(pointer.version) && existsSync(join(this.home, slug, pointer.version, "actions.json"))) return pointer.version;
    return this.versions(slug).at(-1);
  }

  currentMeta(slug: string): GeneratedMeta | undefined {
    const v = this.currentVersion(slug);
    if (!v) return undefined;
    const doc = readJson<GeneratedDoc>(join(this.home, slug, v, "actions.json"));
    if (!doc) return undefined;
    const { actions: _actions, ...meta } = doc;
    return meta;
  }

  /** The next free `YYYYMMDD_NN` for a day. */
  nextVersion(slug: string, now: Date): string {
    const day = now.toISOString().slice(0, 10).replace(/-/g, "");
    const used = this.versions(slug).filter((v) => v.startsWith(`${day}_`)).map((v) => Number(v.slice(9)));
    const n = used.length ? Math.max(...used) + 1 : 0;
    return `${day}_${String(n).padStart(2, "0")}`;
  }

  /** Write a generated definition and point `current.json` at it (both atomic). */
  writeGenerated(doc: GeneratedDoc): string {
    if (!SLUG_RE.test(doc.toolkit) || !VERSION_RE.test(doc.version)) throw new Error(`refusing to write toolkit '${doc.toolkit}' version '${doc.version}': bad slug or version`);
    const dir = join(this.home, doc.toolkit, doc.version);
    mkdirSync(dir, { recursive: true });
    const file = join(dir, "actions.json");
    atomicWriteFileSync(file, JSON.stringify(doc), { mode: 0o600 });
    atomicWriteFileSync(join(this.home, doc.toolkit, "current.json"), JSON.stringify({ version: doc.version }), { mode: 0o600 });
    this.cache.delete(doc.toolkit);
    return file;
  }

  recipeFiles(slug: string): unknown[] {
    const dir = join(this.bundled, slug, "recipes");
    if (!existsSync(dir)) return [];
    const out: unknown[] = [];
    for (const name of readdirSync(dir).sort()) {
      if (!name.endsWith(".json")) continue;
      const v = readJson<unknown>(join(dir, name));
      if (v !== undefined) out.push(v);
    }
    return out;
  }

  /**
   * The toolkit as the gateway serves it: generated actions (when synced) plus recipes, with the overlay
   * applied. Cached until a source file changes. Undefined when nothing defines the slug.
   */
  load(slug: string): Toolkit | undefined {
    const version = this.currentVersion(slug);
    const stamp = [
      version ?? "-",
      version ? stampOf(join(this.home, slug, version, "actions.json")) : "-",
      stampOf(join(this.home, slug, "overlay.json")),
      stampOf(join(this.bundled, slug, "overlay.json")),
      stampOf(join(this.bundled, slug, "recipes")),
      String(this.recipeFiles(slug).length),
    ].join("|");
    const hit = this.cache.get(slug);
    if (hit && hit.stamp === stamp) return hit.toolkit;

    const overlay = this.overlay(slug);
    const issues: string[] = [];
    const generated = version ? readJson<GeneratedDoc>(join(this.home, slug, version, "actions.json")) : undefined;
    const recipes: Action[] = [];
    for (const r of this.recipeFiles(slug)) {
      const parsed = recipeToAction(slug, r, issues);
      if (parsed) recipes.push(parsed);
    }
    // A source declared but never synced, with no recipes, is not loadable yet.
    if (!generated && recipes.length === 0) return undefined;

    const base: Action[] = [...(generated?.actions ?? [])];
    const taken = new Set(base.map((a) => a.slug));
    for (const r of recipes) {
      if (taken.has(r.slug)) {
        // A recipe replaces the generated action of the same slug: the authored composite wins.
        const i = base.findIndex((a) => a.slug === r.slug);
        base[i] = r;
      } else {
        base.push(r);
        taken.add(r.slug);
      }
    }
    const applied = applyOverlay(slug, base, overlay);
    issues.push(...applied.issues);
    const actions = applied.actions;
    const summary = Object.fromEntries(VERIFICATION_STATES.map((s) => [s, 0])) as Record<VerificationState, number>;
    for (const a of actions) summary[a.deprecated ? "deprecated" : a.verification] += 1;
    const toolkit: Toolkit = {
      slug,
      provider: overlay.provider ?? generated?.provider ?? slug,
      version: generated?.version ?? "recipes",
      available_versions: this.versions(slug),
      source: generated ? "spec" : "recipe",
      tools_count: actions.length,
      triggers_count: 0,
      verification_summary: summary,
      actions,
      hidden_count: applied.hidden,
      overlay_issues: issues,
      ...(generated?.base_url ? { base_url: generated.base_url } : {}),
      ...(generated?.source ? { spec: generated.source } : {}),
    };
    this.cache.set(slug, { stamp, toolkit });
    return toolkit;
  }
}

/** A recipe file is an Action authored by hand; check it and fill the defaults the file may omit. */
function recipeToAction(toolkit: string, raw: unknown, issues: string[]): Action | undefined {
  const r = raw as Partial<Action> & { provider?: string };
  if (!r || typeof r !== "object" || typeof r.slug !== "string") {
    issues.push("a recipe file has no slug: skipped");
    return undefined;
  }
  if (!/^[a-z0-9_]+$/.test(r.slug) || r.slug.length > maxActionSlug(toolkit)) {
    issues.push(`recipe '${r.slug}': slug must be a-z0-9_ and at most ${maxActionSlug(toolkit)} characters: skipped`);
    return undefined;
  }
  if (!Array.isArray(r.steps) || r.steps.length === 0) {
    issues.push(`recipe '${r.slug}': no steps: skipped`);
    return undefined;
  }
  const problem = validateRecipeSteps(r.steps);
  if (problem) {
    issues.push(`recipe '${r.slug}': ${problem}: skipped`);
    return undefined;
  }
  const outward = r.outward === true;
  const scope: Scope = r.scope ?? "write";
  const risk: Risk = outward ? tighterRisk(r.risk ?? "high", "high") : (r.risk ?? (scope === "read" ? "low" : scope === "full" ? "high" : "medium"));
  return {
    slug: r.slug,
    title: r.title ?? r.slug,
    description: r.description ?? r.title ?? r.slug,
    input_schema: r.input_schema ?? { type: "object", properties: {} },
    ...(r.output_schema ? { output_schema: r.output_schema } : {}),
    steps: r.steps,
    ...(r.base_url ? { base_url: r.base_url } : {}),
    ...(r.result !== undefined ? { result: r.result } : {}),
    scopes: r.scopes ?? [],
    scope,
    risk,
    outward,
    idempotent: r.idempotent === true,
    important: r.important === true,
    tags: r.tags ?? [],
    deprecated: r.deprecated === true,
    ...(r.files ? { files: r.files } : {}),
    ...(r.reconcile ? { reconcile: r.reconcile } : {}),
    ...(r.approval ? { approval: r.approval } : {}),
    verification: r.verification ?? "mapped",
  };
}

// ── argument validation (Ajv) ─────────────────────────────────────────────────────────────────────

type AjvCtor = new (opts?: Record<string, unknown>) => { compile: (schema: object) => ValidateFunction };
const Ajv: AjvCtor = ((AjvImport as unknown as { default?: AjvCtor }).default ?? (AjvImport as unknown)) as AjvCtor;

/**
 * One Ajv per toolkit run. Coercion is for scalars only (a model sends "5" for 5 or "true" for true);
 * arrays and objects are never reshaped. Formats are annotations (Discovery names `int64`, `byte`, ...):
 * the provider is the judge of a value's content, we only check its shape.
 */
export function makeAjv(): { compile: (schema: object) => ValidateFunction } {
  return new Ajv({ strict: false, allErrors: false, coerceTypes: true, useDefaults: true, validateFormats: false, allowUnionTypes: true });
}

/**
 * Make a vendor schema safe to compile: duplicate `enum` entries are removed, a `pattern` that is not a valid
 * unicode regular expression is dropped (a vendor's own typo must not take its other operations down), and the
 * draft-04 boolean `exclusiveMinimum`/`exclusiveMaximum` is removed. Returns a new value.
 */
export function sanitizeSchema(node: unknown): unknown {
  if (Array.isArray(node)) return node.map(sanitizeSchema);
  if (!node || typeof node !== "object") return node;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
    if (k === "enum" && Array.isArray(v)) {
      const seen = new Set<string>();
      out[k] = v.filter((x) => (seen.has(JSON.stringify(x)) ? false : (seen.add(JSON.stringify(x)), true)));
    } else if (k === "pattern" && typeof v === "string") {
      try {
        new RegExp(v, "u");
        out[k] = v;
      } catch {
        /* an invalid pattern is dropped, the rest of the schema stands */
      }
    } else if ((k === "exclusiveMinimum" || k === "exclusiveMaximum") && typeof v === "boolean") {
      continue;
    } else out[k] = sanitizeSchema(v);
  }
  return out;
}

export interface CompileReport {
  total: number;
  compiled: number;
  failed: { slug: string; error: string }[];
}

/** Compile every action's input schema. The sync and the oracle require 100%. */
export function compileAll(actions: readonly Action[]): CompileReport {
  const ajv = makeAjv();
  const failed: CompileReport["failed"] = [];
  let compiled = 0;
  for (const a of actions) {
    try {
      ajv.compile(a.input_schema);
      compiled += 1;
    } catch (err) {
      failed.push({ slug: a.slug, error: err instanceof Error ? err.message : String(err) });
    }
  }
  return { total: actions.length, compiled, failed };
}

/** Names unique, within the 64 character tool name budget, and made of tool name characters. */
export function checkNames(toolkit: string, actions: readonly Action[]): { ok: boolean; problems: string[]; max: number } {
  const seen = new Set<string>();
  const problems: string[] = [];
  let max = 0;
  for (const a of actions) {
    const name = `${toolkit}${TOOL_SEP}${a.slug}`;
    max = Math.max(max, name.length);
    if (seen.has(a.slug)) problems.push(`duplicate action slug '${a.slug}'`);
    seen.add(a.slug);
    if (name.length > MAX_TOOL_NAME) problems.push(`'${name}' is ${name.length} characters (limit ${MAX_TOOL_NAME})`);
    if (!/^[a-z0-9_]+$/.test(a.slug)) problems.push(`'${a.slug}' has characters outside a-z0-9_`);
  }
  return { ok: problems.length === 0, problems, max };
}
