/**
 * `switchboard toolkits sync <provider|toolkit|all> [--check]` (ADR local-composio, sections 6.1 and 10 R4).
 *
 * Fetches each toolkit's public spec THROUGH THE SSRF GUARD (`guardedFetch`, bulk document caps), imports it
 * (discovery.ts or openapi.ts), holds the result to the invariants, and writes it to
 * `<SWITCHBOARD_HOME>/toolkits/<slug>/<YYYYMMDD_NN>/actions.json`, never into git (ADR risk R11: the specs
 * are the vendors', their redistribution terms are not ours to grant).
 *
 * The invariants a sync must meet before anything is written:
 *   - every action's input schema compiles in Ajv (100%);
 *   - action names are unique, made of `a-z0-9_`, and `<toolkit>__<action>` is at most 64 characters;
 *   - the spec's base host is one of the provider's `api_hosts` (a spec that points elsewhere is refused).
 * A toolkit that fails is reported and left exactly as it was.
 *
 * `--check` fetches and compares the spec hash with the synced version and writes nothing. It reports
 * `unchanged`, `drift` (the vendor's document changed) or `unsynced`, so a weekly job can notice API drift
 * (ADR risk R4); the CLI exits 1 when anything drifted or was never synced.
 */

import { parse as parseYaml } from "yaml";
import { BULK_DOCUMENT_MAX_BYTES, BULK_DOCUMENT_TIMEOUT_MS, guardedFetch, type NetworkSource } from "../netguard.js";
import { hostAllowed } from "./providers.js";
import type { ConnectorKit } from "./kit.js";
import { importDiscovery, specHash } from "./importers/discovery.js";
import { importOpenApi } from "./importers/openapi.js";
import { checkNames, compileAll, type CompileReport, type GeneratedDoc } from "./toolkits.js";

export type SyncStatus = "synced" | "unchanged" | "drift" | "unsynced" | "no_source" | "failed";

export interface SyncOutcome {
  toolkit: string;
  status: SyncStatus;
  version?: string;
  previous?: string;
  operations?: number;
  actions?: number;
  warnings: string[];
  compile?: CompileReport;
  max_tool_name?: number;
  message?: string;
}

export interface SyncOptions {
  check?: boolean;
  /** Replace the fetch (tests and offline fixtures). Receives the spec URL, returns the document text. */
  fetcher?: (url: string) => Promise<string>;
  network?: NetworkSource;
  clock?: () => Date;
}

/** Expand `all`, a provider slug (its toolkits) or a toolkit slug into toolkit slugs. */
export function resolveTargets(kit: ConnectorKit, target: string): string[] {
  const known = kit.toolkits.slugs();
  if (target === "all") return known.filter((s) => kit.toolkits.sourceOf(s));
  const provider = kit.connectors.providers.get(target);
  if (provider) {
    const members = (provider.toolkits ?? [provider.slug]).filter((s) => known.includes(s));
    if (members.length) return members;
  }
  return [target];
}

async function fetchText(url: string, o: SyncOptions): Promise<string> {
  if (o.fetcher) return o.fetcher(url);
  const res = await guardedFetch(url, { maxBytes: BULK_DOCUMENT_MAX_BYTES, timeoutMs: BULK_DOCUMENT_TIMEOUT_MS, headers: { accept: "application/json, application/yaml;q=0.9, */*;q=0.1" } }, o.network);
  if (!res.ok) throw new Error(`HTTP ${res.status} from the spec URL`);
  return res.text();
}

export async function syncToolkit(kit: ConnectorKit, slug: string, o: SyncOptions = {}): Promise<SyncOutcome> {
  const out: SyncOutcome = { toolkit: slug, status: "failed", warnings: [] };
  const source = kit.toolkits.sourceOf(slug);
  if (!source) {
    out.status = "no_source";
    out.message = kit.toolkits.slugs().includes(slug) ? "this toolkit has no spec source (it is built from recipes): nothing to sync" : `no toolkit '${slug}' is defined here`;
    return out;
  }
  const provider = kit.connectors.providers.get(kit.toolkits.overlay(slug).provider ?? "") ?? kit.connectors.providers.providerForToolkit(slug);
  if (!provider) {
    out.message = `no provider definition backs toolkit '${slug}'`;
    return out;
  }
  let raw: string;
  try {
    raw = await fetchText(source.url, o);
  } catch (err) {
    out.message = `could not fetch ${source.url}: ${err instanceof Error ? err.message : String(err)}`;
    return out;
  }
  const hash = specHash(raw);
  const current = kit.toolkits.currentMeta(slug);
  out.previous = current?.version;
  if (current && current.source.spec_hash === hash) {
    out.status = "unchanged";
    out.version = current.version;
    out.message = "the spec has not changed since the synced version";
    return out;
  }
  if (o.check) {
    out.status = current ? "drift" : "unsynced";
    out.message = current ? `the spec changed since ${current.version}` : "never synced";
    return out;
  }

  let doc: unknown;
  try {
    doc = JSON.parse(raw);
  } catch {
    try {
      doc = parseYaml(raw);
    } catch (err) {
      out.message = `the spec is neither JSON nor YAML: ${err instanceof Error ? err.message : String(err)}`;
      return out;
    }
  }
  let imported;
  try {
    imported = source.kind === "discovery" ? importDiscovery(doc, { toolkit: slug, provider: provider.slug }) : importOpenApi(doc, { toolkit: slug, provider: provider.slug });
  } catch (err) {
    out.message = `import failed: ${err instanceof Error ? err.message : String(err)}`;
    return out;
  }
  out.operations = imported.operations;
  out.actions = imported.actions.length;
  out.warnings = imported.warnings;
  const compile = compileAll(imported.actions);
  const names = checkNames(slug, imported.actions);
  out.compile = compile;
  out.max_tool_name = names.max;
  const problems: string[] = [];
  if (compile.failed.length) problems.push(`${compile.failed.length} schema(s) failed to compile (first: ${compile.failed[0]!.slug}: ${compile.failed[0]!.error.slice(0, 120)})`);
  if (!names.ok) problems.push(...names.problems.slice(0, 3));
  let baseHost = "";
  try {
    baseHost = new URL(imported.base_url).hostname;
  } catch {
    problems.push(`the base URL '${imported.base_url}' is not valid`);
  }
  if (baseHost && !hostAllowed(provider.api_hosts, baseHost)) problems.push(`the spec's API host '${baseHost}' is not one of ${provider.slug}'s api_hosts (${provider.api_hosts.join(", ")}): refusing a toolkit that would send credentials elsewhere`);
  if (imported.actions.length === 0) problems.push("the spec yielded no actions");
  if (problems.length) {
    out.message = problems.join("; ");
    return out;
  }

  const now = (o.clock ?? (() => new Date()))();
  const version = kit.toolkits.nextVersion(slug, now);
  const gen: GeneratedDoc = {
    toolkit: slug,
    provider: provider.slug,
    version,
    source: { kind: source.kind, url: source.url, fetched_at: now.toISOString(), spec_hash: hash, ...(imported.spec_revision ? { spec_revision: imported.spec_revision } : {}), ...(imported.spec_version ? { spec_version: imported.spec_version } : {}) },
    base_url: imported.base_url,
    generated_count: imported.actions.length,
    actions: imported.actions,
  };
  kit.toolkits.writeGenerated(gen);
  out.status = "synced";
  out.version = version;
  return out;
}

export async function syncToolkits(kit: ConnectorKit, target: string, o: SyncOptions = {}): Promise<SyncOutcome[]> {
  const slugs = resolveTargets(kit, target);
  const results: SyncOutcome[] = [];
  for (const s of slugs) results.push(await syncToolkit(kit, s, o));
  return results;
}
