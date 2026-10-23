/**
 * ProviderDef registry (ADR local-composio, section 6.1): provider auth definitions as validated data.
 *
 * Two sources, in this order:
 *   1. the bundled definitions, `src/connectors/providers/*.json` (copied to `dist/connectors/providers/`
 *      by the build). They cannot be overridden: a definition decides which host receives a client
 *      secret, so the files that ship with the package are the only ones allowed to claim a shipped slug.
 *   2. the owner's own definitions in `<SWITCHBOARD_HOME>/providers/*.json`, for a provider the package does
 *      not know. A slug that collides with a bundled one is refused and reported.
 *
 * Every file is checked against `schemas/provider.schema.json` (Ajv) and then against the rules a JSON
 * Schema cannot express (https URLs, host locks, template placeholders). A file that fails is left out
 * and listed in `issues`; one bad file never takes the others down.
 */

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import AjvImport from "ajv";
import type { ValidateFunction } from "ajv";
import type { ProviderDef, AuthDef } from "./types.js";

// ajv ships CommonJS; under NodeNext the default import is the class at runtime.
type AjvCtor = new (opts?: Record<string, unknown>) => { compile: (schema: object) => ValidateFunction };
const Ajv: AjvCtor = ((AjvImport as unknown as { default?: AjvCtor }).default ?? (AjvImport as unknown)) as AjvCtor;

const HERE = dirname(fileURLToPath(import.meta.url));

/** Directories that may hold the bundled definitions, in order: the built copy, then a source checkout. */
function bundledCandidates(sub: string): string[] {
  return [join(HERE, sub), join(HERE, "..", "..", "src", "connectors", sub)];
}

export function bundledProviderDir(): string {
  return bundledCandidates("providers").find((d) => existsSync(d)) ?? bundledCandidates("providers")[0]!;
}

function schemaPath(): string {
  const found = bundledCandidates("schemas").map((d) => join(d, "provider.schema.json")).find((f) => existsSync(f));
  if (!found) throw new Error("provider.schema.json not found next to the connectors module: run `npm run build`");
  return found;
}

let validator: ValidateFunction | null = null;
function schemaValidator(): ValidateFunction {
  if (!validator) {
    const ajv = new Ajv({ allErrors: true, strict: true, strictRequired: false, allowUnionTypes: true });
    validator = ajv.compile(JSON.parse(readFileSync(schemaPath(), "utf8")) as object);
  }
  return validator;
}

const LOOPBACK = new Set(["127.0.0.1", "localhost", "[::1]", "::1"]);

export function isLoopbackHost(host: string): boolean {
  return LOOPBACK.has(host.toLowerCase());
}

/** https everywhere, except a loopback address (a mock or a local service). */
function urlProblem(label: string, value: string): string | null {
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    return `${label} is not a valid URL`;
  }
  if (u.username || u.password) return `${label} must not embed credentials`;
  if (u.protocol === "https:") return null;
  if (u.protocol === "http:" && isLoopbackHost(u.hostname)) return null;
  return `${label} must be https (http is only allowed for a loopback host)`;
}

/** Does `host` match one of a provider's `api_hosts` entries (exact, or `*.example.com` for subdomains)? */
export function hostAllowed(apiHosts: readonly string[], host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  return apiHosts.some((pattern) => {
    if (pattern.startsWith("*.")) return h.endsWith(pattern.slice(1)) && h.length > pattern.length - 1;
    return h === pattern;
  });
}

const PLACEHOLDER = /\{([A-Za-z_][A-Za-z0-9_]*)\}/g;

/** Rules beyond the JSON Schema. Returns human-readable problems; empty means the definition is usable. */
export function semanticProblems(def: ProviderDef): string[] {
  const problems: string[] = [];
  const ids = new Set<string>();
  let defaults = 0;
  for (const auth of def.auth) {
    if (ids.has(auth.id)) problems.push(`auth id '${auth.id}' is declared twice`);
    ids.add(auth.id);
    if (auth.default) defaults++;
    const where = `auth '${auth.id}'`;
    const o = auth.oauth2;
    if (o) {
      const t = urlProblem(`${where} token_url`, o.token_url);
      if (t) problems.push(t);
      if (o.authorize_url) {
        const a = urlProblem(`${where} authorize_url`, o.authorize_url);
        if (a) problems.push(a);
      }
      if (o.revoke) {
        const r = urlProblem(`${where} revoke.url`, o.revoke.url);
        if (r) problems.push(r);
      }
      if (auth.mode === "oauth2" && def.owner_setup.redirect_uris.length === 0) {
        problems.push(`${where} is an authorization-code flow but owner_setup.redirect_uris is empty`);
      }
      if (o.refresh.kind === "none" && o.refresh.rotates) problems.push(`${where} refresh.kind is none but rotates is true`);
      if (o.refresh.kind === "exchange" && !o.refresh.exchange) problems.push(`${where} refresh.kind is exchange but refresh.exchange is missing`);
      if (o.refresh.kind !== "exchange" && o.refresh.exchange) problems.push(`${where} refresh.exchange is set but refresh.kind is not exchange`);
      for (const [label, step] of [["post_exchange", o.post_exchange], ["refresh.exchange", o.refresh.exchange]] as const) {
        if (!step) continue;
        const sp = urlProblem(`${where} ${label}.url`, step.url);
        if (sp) problems.push(sp);
      }
      if (o.client_id_param === "client_key" && o.client_auth === "basic") problems.push(`${where} client_key is only defined for form-field client auth`);
    }
    const fieldNames = new Set(auth.fields.connected_account_initiation.map((f) => f.name));
    for (const m of auth.inject.template.matchAll(PLACEHOLDER)) {
      const name = m[1]!;
      if (name === "token" || name === "basic") continue;
      if (!fieldNames.has(name)) problems.push(`${where} inject.template uses {${name}} which is not a connected_account_initiation field`);
    }
  }
  if (defaults > 1) problems.push("more than one auth is marked default");
  if (def.identity_probe) {
    const p = urlProblem("identity_probe.url", def.identity_probe.url);
    if (p) problems.push(p);
    else if (!hostAllowed(def.api_hosts, new URL(def.identity_probe.url).hostname)) {
      problems.push(`identity_probe.url host '${new URL(def.identity_probe.url).hostname}' is not in api_hosts`);
    }
  }
  const du = urlProblem("docs_url", def.docs_url);
  if (du) problems.push(du);
  return problems;
}

/** Validate one parsed definition. Returns problems (schema first, then semantic); empty means valid. */
export function validateProviderDef(raw: unknown): string[] {
  const v = schemaValidator();
  if (!v(raw)) {
    return (v.errors ?? []).map((e) => `${e.instancePath || "(root)"} ${e.message ?? "invalid"}`);
  }
  return semanticProblems(raw as ProviderDef);
}

export interface ProviderIssue {
  file: string;
  problems: string[];
}

export interface ProviderLoadOptions {
  /** SWITCHBOARD_HOME: its `providers/` folder holds the owner's own definitions. */
  home: string;
  /** Replace the bundled directory (tests only). */
  bundledDir?: string;
}

export class ProviderRegistry {
  private readonly byslug = new Map<string, ProviderDef>();
  private readonly bundledSlugs = new Set<string>();
  readonly issues: ProviderIssue[] = [];

  static load(opts: ProviderLoadOptions): ProviderRegistry {
    const reg = new ProviderRegistry();
    reg.readDir(opts.bundledDir ?? bundledProviderDir(), true);
    reg.readDir(join(opts.home, "providers"), false);
    return reg;
  }

  private readDir(dir: string, bundled: boolean): void {
    if (!existsSync(dir)) return;
    const files = readdirSync(dir).filter((n) => n.endsWith(".json")).sort();
    for (const name of files) {
      const file = join(dir, name);
      let raw: unknown;
      try {
        raw = JSON.parse(readFileSync(file, "utf8"));
      } catch (err) {
        this.issues.push({ file, problems: [`not valid JSON: ${err instanceof Error ? err.message : String(err)}`] });
        continue;
      }
      const problems = validateProviderDef(raw);
      if (problems.length) {
        this.issues.push({ file, problems });
        continue;
      }
      const def = raw as ProviderDef;
      if (name !== `${def.slug}.json`) {
        this.issues.push({ file, problems: [`file name must be ${def.slug}.json to match its slug`] });
        continue;
      }
      if (this.byslug.has(def.slug)) {
        this.issues.push({
          file,
          problems: [this.bundledSlugs.has(def.slug) ? `slug '${def.slug}' belongs to a bundled provider and cannot be overridden` : `slug '${def.slug}' is declared twice`],
        });
        continue;
      }
      this.byslug.set(def.slug, def);
      if (bundled) this.bundledSlugs.add(def.slug);
    }
  }

  get(slug: string): ProviderDef | undefined {
    return this.byslug.get(slug);
  }

  has(slug: string): boolean {
    return this.byslug.has(slug);
  }

  /** Slugs in load order (bundled sorted by file name, then the owner's). */
  slugs(): string[] {
    return [...this.byslug.keys()];
  }

  list(): ProviderDef[] {
    return [...this.byslug.values()];
  }

  isBundled(slug: string): boolean {
    return this.bundledSlugs.has(slug);
  }

  /** The provider that backs a toolkit slug (`gmail` -> google). */
  providerForToolkit(toolkit: string): ProviderDef | undefined {
    return this.list().find((p) => (p.toolkits ?? [p.slug]).includes(toolkit));
  }

  /** The AuthDef `connect` uses when none is named: the one marked default, else the first. */
  defaultAuth(def: ProviderDef): AuthDef {
    return def.auth.find((a) => a.default) ?? def.auth[0]!;
  }

  authById(def: ProviderDef, id: string): AuthDef | undefined {
    return def.auth.find((a) => a.id === id);
  }
}
