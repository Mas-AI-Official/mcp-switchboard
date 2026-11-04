/**
 * Toolkit catalog — the browsable directory of connectable integrations.
 *
 * This is the Composio-style "1000+ toolkits" grid, built LOCALLY and ONLY from
 * open, redistributable sources (never a proprietary catalog):
 *
 *   - the official MCP Registry (registry.modelcontextprotocol.io) — real MCP
 *     servers you can mount directly (`source: remote` or `source: npx`);
 *   - APIs.guru (api.apis.guru) — ~2500 public OpenAPI specs, each mountable
 *     through app2mcp (`source: app2mcp`, `openapi: <spec url>`).
 *
 * `switchboard toolkits sync` regenerates the snapshot at `data/catalog.json`,
 * which ships with the package so the dashboard works offline on first run.
 * Each toolkit carries a `mount` block that maps 1:1 onto a `ServerConfig`, so
 * "Add to MCP Switchboard" can turn a catalog entry into a real mounted server.
 *
 * Zero dependencies: every fetch goes through the SSRF guard (src/netguard.ts) and the standard library.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { isExactNpmVersion } from "./packagespec.js";
import { BULK_DOCUMENT_MAX_BYTES, BULK_DOCUMENT_TIMEOUT_MS, guardedFetch, type NetworkSource } from "./netguard.js";

/** How a catalog entry can be mounted. Mirrors the relevant `ServerConfig` fields. */
export type ToolkitMount =
  | { source: "remote"; url: string; transport: string }
  | { source: "npx"; package: string; /** An exact version the registry lists for this package; absent when it lists none or a floating one. */ version?: string }
  | { source: "app2mcp"; openapi: string; base_url?: string }
  | { source: "manual"; note: string };

/** One browsable integration in the catalog. */
export interface Toolkit {
  /** Stable, collision-free id, e.g. `mcp:io.github.owner/name` or `openapi:github.com`. */
  slug: string;
  /** Display name. */
  name: string;
  /** One-line description (trimmed to a single sentence/line). */
  description: string;
  /** Normalized, human-readable PRIMARY category used by the sidebar filter and headline grouping. */
  category: string;
  /**
   * All categories this toolkit belongs to (Composio-style multi-tag membership). A source like
   * APIs.guru tags many entries with several categories; the filter matches ANY of them and the
   * sidebar histogram counts membership in each, so a "Finance" filter also surfaces a toolkit
   * whose PRIMARY category is "Payments" but which also carries "Finance". Omitted/empty means the
   * entry belongs only to `category` (the common case for single-category MCP-registry entries).
   */
  categories?: string[];
  /** Free-text keywords folded into the search index. */
  tags: string[];
  /** Where this entry came from. */
  origin: "mcp-registry" | "apis-guru";
  /** Provenance: the redistribution license of the SOURCE index (not of the tool itself). */
  source_license: string;
  /** Optional project/provider homepage. */
  homepage?: string;
  /** Optional source-code repository. */
  repository?: string;
  /** Optional logo URL (apis.guru provides these). */
  logo?: string;
  /** How to mount it as a governed server. */
  mount: ToolkitMount;
}

/** The on-disk snapshot shape. */
export interface CatalogSnapshot {
  /** ISO timestamp of when this snapshot was generated (stamped by the caller). */
  generated_at: string;
  /** Per-source counts, for the stats endpoint and `toolkits stats`. */
  counts: { total: number; mcp_registry: number; apis_guru: number };
  /** Sorted list of distinct categories with their entry counts. */
  categories: { name: string; count: number }[];
  toolkits: Toolkit[];
}

const MCP_REGISTRY_URL = "https://registry.modelcontextprotocol.io/v0/servers?limit=100";
const APIS_GURU_URL = "https://api.apis.guru/v2/list.json";
// awesome-mcp-servers (MIT): used ONLY as a category-taxonomy source and for LIVE discovery,
// never bulk-snapshotted. See docs/COMPOSIO-PARITY.md ("parse awesome-mcp-servers headings";
// "enrichment registries = discovery only, never snapshot").
const AWESOME_MCP_README_URL =
  "https://raw.githubusercontent.com/punkpeye/awesome-mcp-servers/main/README.md";
const USER_AGENT = "mcp-switchboard catalog sync (+https://github.com/Mas-AI-Official/mcp-switchboard)";

/** Resolve `data/catalog.json` relative to the package root (one level above dist/ or src/). */
export function defaultCatalogPath(): string {
  return fileURLToPath(new URL("../data/catalog.json", import.meta.url));
}

/** Title-case a snake_case / kebab-case source category, e.g. `developer_tools` -> `Developer Tools`. */
function prettifyCategory(raw: string | undefined | null): string {
  if (!raw || raw === "(none)") return "Uncategorized";
  return raw
    .split(/[_\-\s]+/)
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

/** Collapse a description to a single trimmed line, capped so cards stay tidy. */
function oneLine(text: string | undefined | null, cap = 240): string {
  if (!text) return "";
  const flat = String(text).replace(/\s+/g, " ").trim();
  return flat.length > cap ? flat.slice(0, cap - 1).trimEnd() + "…" : flat;
}

/** A URL we can actually mount without asking the operator to substitute placeholders. */
function isConcreteHttpUrl(value: string): boolean {
  if (/[{}]/.test(value)) return false;
  try {
    const u = new URL(value);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

/** Derive a coarse category for an MCP server from keywords in its name/description. */
function deriveMcpCategory(name: string, description: string): string {
  const h = `${name} ${description}`.toLowerCase();
  const has = (...words: string[]) => words.some((w) => h.includes(w));
  if (has("postgres", "mysql", "sqlite", "mongodb", "database", " sql", "redis", "clickhouse")) return "Databases";
  if (has("github", "gitlab", "git ", "ci/cd", "kubernetes", "docker", "terraform", "deploy")) return "Developer Tools";
  if (has("slack", "discord", "telegram", "email", "gmail", "messaging", "sms", "twilio")) return "Communication";
  if (has("notion", "jira", "linear", "asana", "trello", "calendar", "todo", "task")) return "Productivity";
  if (has("stripe", "payment", "invoice", "billing", "paypal", "quickbooks")) return "Finance";
  if (has("openai", "anthropic", "llm", "embedding", "vector", "rag", " ai ", "ml ", "model")) return "AI / ML";
  if (has("aws", "gcp", "azure", "cloudflare", "s3", "storage", "cloud")) return "Cloud";
  if (has("browser", "scrape", "crawl", "search", "fetch", "web ")) return "Web & Search";
  if (has("file", "filesystem", "drive", "dropbox", "document")) return "Files & Storage";
  return "MCP Servers";
}

/** Fetch JSON with a short timeout and a descriptive UA. Throws on non-2xx. */
async function fetchJson<T>(url: string, network?: NetworkSource): Promise<T> {
  // Public registries are bulk documents (apis.guru list.json is ~9 MB), so they get the bulk caps.
  const res = await guardedFetch(
    url,
    { headers: { "user-agent": USER_AGENT, accept: "application/json" }, maxBytes: BULK_DOCUMENT_MAX_BYTES, timeoutMs: BULK_DOCUMENT_TIMEOUT_MS },
    network,
  );
  if (!res.ok) throw new Error(`${url} -> HTTP ${res.status}`);
  return (await res.json()) as T;
}

// --- Adapter A: the official MCP Registry ----------------------------------

interface RegistryRemote {
  type?: string;
  url?: string;
}
interface RegistryPackage {
  registryType?: string;
  identifier?: string;
  version?: string;
  transport?: { type?: string };
}
interface RegistryServer {
  name?: string;
  title?: string;
  description?: string;
  version?: string;
  remotes?: RegistryRemote[];
  packages?: RegistryPackage[];
  repository?: { url?: string; source?: string };
}
interface RegistryRow {
  server: RegistryServer;
  _meta?: Record<string, unknown>;
}
interface RegistryPage {
  servers: RegistryRow[];
  metadata?: { nextCursor?: string };
}

/** True if the registry row is flagged as the latest version of its server (when the flag is present). */
function isLatestRow(row: RegistryRow): boolean | undefined {
  const meta = row._meta as Record<string, unknown> | undefined;
  const official = meta?.["io.modelcontextprotocol.registry/official"] as Record<string, unknown> | undefined;
  const v = official?.["isLatest"];
  return typeof v === "boolean" ? v : undefined;
}

/**
 * Turn a registry server into a Toolkit, or null if it has no mountable transport. When a `taxonomy`
 * (repo→category, from awesome-mcp-servers) is supplied and this server's repo is in it, that curated
 * category wins over the keyword heuristic: this is what drains the generic "MCP Servers" catch-all.
 */
function toolkitFromRegistry(srv: RegistryServer, taxonomy?: Map<string, string>): Toolkit | null {
  const rawName = (srv.name ?? "").trim();
  if (!rawName) return null;
  const description = oneLine(srv.description);
  const display = srv.title?.trim() || rawName.split("/").pop() || rawName;

  // Prefer a remote endpoint; fall back to an npm package mounted via npx.
  let mount: ToolkitMount | null = null;
  const remote = (srv.remotes ?? []).find((r) => r.url);
  if (remote?.url) {
    mount = isConcreteHttpUrl(remote.url)
      ? { source: "remote", url: remote.url, transport: remote.type || "streamable-http" }
      : { source: "manual", note: `Configure the remote MCP endpoint manually: ${remote.url}` };
  } else {
    const npm = (srv.packages ?? []).find((p) => p.registryType === "npm" && p.identifier);
    if (npm?.identifier) {
      // Keep the registry's version only when it is an exact one: a new mount of this package is pinned to it.
      mount = { source: "npx", package: npm.identifier, ...(isExactNpmVersion(npm.version) ? { version: npm.version } : {}) };
    } else {
      const other = (srv.packages ?? []).find((p) => p.identifier);
      if (other?.identifier) {
        mount = { source: "manual", note: `Install via ${other.registryType ?? "package"}: ${other.identifier}` };
      }
    }
  }
  if (!mount) return null;

  const repoUrl = srv.repository?.url;
  const curatedCategory = taxonomy && repoUrl ? taxonomy.get(normalizeRepoUrl(repoUrl) ?? "") : undefined;

  return {
    slug: `mcp:${rawName}`,
    name: display,
    description,
    category: curatedCategory || deriveMcpCategory(rawName, description),
    tags: rawName.split(/[/.\-_]/).filter((t) => t.length > 1),
    origin: "mcp-registry",
    source_license: "MIT (MCP Registry data)",
    repository: repoUrl,
    homepage: repoUrl,
    mount,
  };
}

/** Page through the MCP Registry, dedupe to the latest version of each server. */
async function ingestMcpRegistry(taxonomy?: Map<string, string>, network?: NetworkSource): Promise<Toolkit[]> {
  const byName = new Map<string, Toolkit>();
  // Track which names we've seen a `isLatest: true` row for, so older rows can't overwrite it.
  const lockedLatest = new Set<string>();
  let url: string | null = MCP_REGISTRY_URL;
  let pages = 0;
  const maxPages = 60; // safety cap (~6000 rows)

  while (url && pages < maxPages) {
    const page: RegistryPage = await fetchJson<RegistryPage>(url, network);
    pages++;
    for (const row of page.servers ?? []) {
      const tk = toolkitFromRegistry(row.server, taxonomy);
      if (!tk) continue;
      const latest = isLatestRow(row);
      if (lockedLatest.has(tk.slug) && latest !== true) continue; // keep the locked latest
      byName.set(tk.slug, tk);
      if (latest === true) lockedLatest.add(tk.slug);
    }
    const cursor = page.metadata?.nextCursor;
    url = cursor ? `https://registry.modelcontextprotocol.io/v0/servers?limit=100&cursor=${encodeURIComponent(cursor)}` : null;
  }
  return [...byName.values()];
}

// --- Adapter B: APIs.guru ---------------------------------------------------

interface ApisGuruVersion {
  swaggerUrl?: string;
  info?: {
    title?: string;
    description?: string;
    "x-providerName"?: string;
    "x-apisguru-categories"?: string[];
    "x-logo"?: { url?: string };
    "x-origin"?: { url?: string }[];
    contact?: { url?: string };
  };
}
interface ApisGuruEntry {
  preferred?: string;
  versions: Record<string, ApisGuruVersion>;
}

/** Convert the apis.guru list into Toolkits (one per API, using the preferred version). */
async function ingestApisGuru(network?: NetworkSource): Promise<Toolkit[]> {
  const list = await fetchJson<Record<string, ApisGuruEntry>>(APIS_GURU_URL, network);
  const out: Toolkit[] = [];
  for (const [key, entry] of Object.entries(list)) {
    const verKey = entry.preferred ?? Object.keys(entry.versions)[0];
    const ver = entry.versions?.[verKey];
    if (!ver) continue;
    const specUrl = ver.swaggerUrl;
    if (!specUrl) continue; // not mountable without a spec
    const info = ver.info ?? {};
    const cats = info["x-apisguru-categories"];
    const provider = info["x-providerName"];
    // Full, prettified, de-duplicated category set (the sidebar filter + histogram match ANY of these).
    const prettyCats = [...new Set((cats ?? []).map((c) => prettifyCategory(c)))];
    out.push({
      slug: `openapi:${key}`,
      name: info.title?.trim() || key,
      description: oneLine(info.description),
      category: prettifyCategory(cats?.[0]),
      ...(prettyCats.length > 1 ? { categories: prettyCats } : {}),
      tags: [provider, ...(cats ?? [])].filter((t): t is string => Boolean(t)),
      origin: "apis-guru",
      source_license: "CC0-1.0 (APIs.guru)",
      homepage: provider ? `https://${provider}` : info.contact?.url,
      logo: info["x-logo"]?.url,
      mount: { source: "app2mcp", openapi: specUrl },
    });
  }
  return out;
}

// --- Adapter C: awesome-mcp-servers (MIT): TAXONOMY + LIVE DISCOVERY ONLY ---
//
// Design boundary (docs/COMPOSIO-PARITY.md): awesome-mcp-servers is NOT a bulk-snapshot source
// (only CC0 sources, MCP Registry + apis.guru, are copied into data/catalog.json). We use it two
// ways, both allowed: (1) its curated category HEADINGS become a taxonomy we apply to servers we
// ALREADY hold from CC0 sources, keyed by GitHub repo: a category NAME is a non-copyrightable fact;
// (2) live `discoverToolkits` surfaces servers NOT in our snapshot at query time, never persisted.
// Attribution: category taxonomy © the awesome-mcp-servers contributors (MIT).

/**
 * Reduce any GitHub URL to its canonical `github.com/owner/repo` join key: lowercased, no
 * protocol / `www.` / `git+` prefix / `.git` suffix / trailing path, first two segments only.
 * Returns null for non-GitHub or unparseable URLs. This is the key that joins our CC0 registry
 * entries (which carry `repository.url`) to awesome-mcp-servers' human-curated category headings.
 */
export function normalizeRepoUrl(url: string | undefined | null): string | null {
  if (!url) return null;
  let s = String(url).trim().replace(/^git\+/i, "");
  if (s.startsWith("git@github.com:")) s = "https://github.com/" + s.slice("git@github.com:".length);
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return null;
  }
  if (!/(^|\.)github\.com$/i.test(u.hostname)) return null;
  const parts = u.pathname.split("/").filter(Boolean);
  if (parts.length < 2) return null;
  const owner = parts[0].toLowerCase();
  const repo = parts[1].replace(/\.git$/i, "").toLowerCase();
  return `github.com/${owner}/${repo}`;
}

/** One parsed awesome-mcp list item: a server under a category heading. */
export interface AwesomeEntry {
  category: string;
  repoUrl: string; // normalized `github.com/owner/repo`
  name: string; // the markdown link text, e.g. "owner/repo"
  description: string;
}

const AWESOME_SECTION_START = /^##\s+Server Implementations\s*$/i;
const AWESOME_H2 = /^##\s+\S/; // any other H2 closes the Server-Implementations section
const AWESOME_H3 = /^###\s+(.*\S)\s*$/;
const AWESOME_BULLET = /^\s*[-*]\s+\S/;
const AWESOME_LINK_TARGET = /\]\((https?:\/\/[^)\s]+)\)/g; // markdown-link targets, in order

/** Strip the `### <emoji?> <a name="…"></a>Category` chrome down to the plain category label. */
function cleanAwesomeCategory(raw: string): string {
  return raw
    .replace(/<a\b[^>]*>.*?<\/a>/gi, "") // drop the <a name="…"></a> anchor
    .replace(/<[^>]+>/g, "") // any other stray HTML
    .replace(/^[^\p{L}\p{N}]+/u, "") // leading emoji / symbols / whitespace ("&"/"/" kept mid-string)
    .trim();
}

/** The repo for a bullet is the first GitHub link target on the line (glama badges live on glama.ai). */
function firstGithubRepo(line: string): string | null {
  AWESOME_LINK_TARGET.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = AWESOME_LINK_TARGET.exec(line))) {
    const norm = normalizeRepoUrl(m[1]);
    if (norm) return norm;
  }
  return null;
}

/** Description = the text after the ` - ` separator, with any leading emoji/dash legend stripped. */
function awesomeDescription(line: string): string {
  const idx = line.indexOf(" - ");
  const tail = idx >= 0 ? line.slice(idx + 3) : "";
  return oneLine(tail.replace(/^[^\p{L}\p{N}(]+/u, "")); // drop a leading emoji/badge legend run
}

/**
 * Parse awesome-mcp-servers' README (MIT) into (category, repo, name, description) records. ONLY the
 * `## Server Implementations` section is walked: its `### <emoji?> <a name>Category` headings are the
 * taxonomy, and each `- [text](url) … - desc` bullet is one server. Pure and offline (feed it the
 * markdown string). The first GitHub link on a bullet is the repo; inline doc links (after the
 * description dash) and glama score badges are ignored.
 */
export function parseAwesomeEntries(markdown: string): AwesomeEntry[] {
  const lines = markdown.split(/\r?\n/);
  const entries: AwesomeEntry[] = [];
  let inSection = false;
  let category = "";
  for (const line of lines) {
    if (!inSection) {
      if (AWESOME_SECTION_START.test(line)) inSection = true;
      continue;
    }
    if (AWESOME_H2.test(line)) break; // next H2 (e.g. "## Frameworks") ends Server Implementations
    const h3 = line.match(AWESOME_H3);
    if (h3) {
      category = cleanAwesomeCategory(h3[1]);
      continue;
    }
    if (!category || !AWESOME_BULLET.test(line)) continue;
    const repoUrl = firstGithubRepo(line);
    if (!repoUrl) continue;
    const nameMatch = line.match(/^\s*[-*]\s+\[([^\]]*)\]/);
    const name = (nameMatch?.[1] ?? "").trim() || repoUrl.replace("github.com/", "");
    entries.push({ category, repoUrl, name, description: awesomeDescription(line) });
  }
  return entries;
}

/** Reduce awesome-mcp entries to a repo→category map (first listing wins on duplicates). */
export function parseAwesomeTaxonomy(markdown: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const e of parseAwesomeEntries(markdown)) {
    if (!map.has(e.repoUrl)) map.set(e.repoUrl, e.category);
  }
  return map;
}

/** Fetch text (README markdown) with the same UA as the JSON adapters. Throws on non-2xx. */
async function fetchText(url: string, network?: NetworkSource): Promise<string> {
  const res = await guardedFetch(
    url,
    { headers: { "user-agent": USER_AGENT }, maxBytes: BULK_DOCUMENT_MAX_BYTES, timeoutMs: BULK_DOCUMENT_TIMEOUT_MS },
    network,
  );
  if (!res.ok) throw new Error(`${url} -> HTTP ${res.status}`);
  return await res.text();
}

/**
 * Live, best-effort fetch of awesome-mcp-servers' category taxonomy. Returns a repo→category map,
 * or an EMPTY map on any failure: category enrichment must never break or fail a catalog sync.
 */
export async function fetchAwesomeTaxonomy(network?: NetworkSource): Promise<Map<string, string>> {
  try {
    return parseAwesomeTaxonomy(await fetchText(AWESOME_MCP_README_URL, network));
  } catch {
    return new Map();
  }
}

/**
 * A live discovery hit from awesome-mcp-servers. DELIBERATELY not a `Toolkit`: it has no `slug`,
 * `mount`, or snapshot `origin`, so it can never be persisted into data/catalog.json nor mounted
 * blindly. Discovery is "query live, don't snapshot": surfaced at query time, never written.
 */
export interface DiscoveryResult {
  name: string;
  repository: string; // https://github.com/owner/repo
  description: string;
  category: string;
  source: "awesome-mcp";
  installable: false;
  note: string;
}

const DISCOVERY_NOTE =
  "discovery-only (awesome-mcp-servers, MIT): not in the CC0 snapshot; vet before mounting";

/** Pure discovery: filter awesome-mcp entries by query terms, excluding repos we already hold. */
export function searchAwesomeServers(
  markdown: string,
  query: string,
  opts: { exclude?: Set<string>; limit?: number } = {},
): DiscoveryResult[] {
  const exclude = opts.exclude ?? new Set<string>();
  const limit = Math.min(50, Math.max(1, opts.limit ?? 20));
  const terms = (query ?? "").toLowerCase().split(/\s+/).filter(Boolean);
  const seen = new Set<string>();
  const out: DiscoveryResult[] = [];
  for (const e of parseAwesomeEntries(markdown)) {
    if (exclude.has(e.repoUrl) || seen.has(e.repoUrl)) continue;
    const hay = `${e.name} ${e.description} ${e.category}`.toLowerCase();
    if (terms.length && !terms.every((t) => hay.includes(t))) continue;
    seen.add(e.repoUrl);
    out.push({
      name: e.name,
      repository: `https://${e.repoUrl}`,
      description: e.description,
      category: e.category,
      source: "awesome-mcp",
      installable: false,
      note: DISCOVERY_NOTE,
    });
    if (out.length >= limit) break;
  }
  return out;
}

/**
 * Live discovery lookup: search awesome-mcp-servers for MCP servers matching `query` that are NOT
 * already in our CC0 snapshot. Fetches live and returns transient results: nothing is written to
 * disk (honors the catalog boundary: enrichment registries are discovery-only, never snapshotted).
 */
export async function discoverToolkits(
  query: string,
  opts: { limit?: number; catalog?: CatalogSnapshot; network?: NetworkSource } = {},
): Promise<DiscoveryResult[]> {
  const snapshot = opts.catalog ?? loadCatalog();
  const exclude = new Set<string>();
  for (const t of snapshot.toolkits) {
    const n = normalizeRepoUrl(t.repository);
    if (n) exclude.add(n);
  }
  const md = await fetchText(AWESOME_MCP_README_URL, opts.network);
  return searchAwesomeServers(md, query, { exclude, limit: opts.limit });
}

/**
 * The distinct set of categories a toolkit belongs to: its primary `category` unioned with any
 * extra `categories`. This is the SINGLE source of truth for category membership — both the sidebar
 * histogram (`tallyCategories`) and the filter (`queryCatalog`) route through it, so the count shown
 * next to a category can never disagree with the number of results that category's filter returns.
 */
export function toolkitCategories(t: Toolkit): string[] {
  return [...new Set([t.category, ...(t.categories ?? [])])];
}

/**
 * Build the category histogram, counting MEMBERSHIP (a toolkit counts once toward each distinct
 * category it belongs to), sorted by descending count then name. Consistent-by-construction with the
 * `queryCatalog` filter via `toolkitCategories`.
 */
export function tallyCategories(toolkits: Toolkit[]): { name: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const t of toolkits) {
    for (const c of toolkitCategories(t)) counts.set(c, (counts.get(c) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
}

/**
 * Fetch both sources and assemble a snapshot. `generated_at` is left as an empty
 * string here (the script runtime forbids reading the clock); the CLI stamps it.
 */
export async function ingestCatalog(network?: NetworkSource): Promise<CatalogSnapshot> {
  const taxonomy = await fetchAwesomeTaxonomy(network); // best-effort; empty map on failure
  const results = await Promise.allSettled([ingestMcpRegistry(taxonomy, network), ingestApisGuru(network)]);
  const mcp = results[0].status === "fulfilled" ? results[0].value : [];
  const apis = results[1].status === "fulfilled" ? results[1].value : [];
  if (results[0].status === "rejected" && results[1].status === "rejected") {
    throw new Error(
      `both catalog sources failed: ${String(results[0].reason)} / ${String(results[1].reason)}`,
    );
  }
  // De-dup across sources by slug (slugs are origin-prefixed, so cross-source collisions are impossible,
  // but guard anyway), sort by name for stable diffs.
  const bySlug = new Map<string, Toolkit>();
  for (const t of [...mcp, ...apis]) bySlug.set(t.slug, t);
  const toolkits = [...bySlug.values()].sort((a, b) => a.name.localeCompare(b.name));

  return {
    generated_at: "",
    counts: { total: toolkits.length, mcp_registry: mcp.length, apis_guru: apis.length },
    categories: tallyCategories(toolkits),
    toolkits,
  };
}

/** Per-source failure detail + taxonomy-enrichment stats, for callers that want to report syncs. */
export async function ingestCatalogVerbose(network?: NetworkSource): Promise<{
  snapshot: CatalogSnapshot;
  errors: { source: string; message: string }[];
  enrichment: { taxonomy_entries: number; reclassified: number };
}> {
  const taxonomy = await fetchAwesomeTaxonomy(network); // best-effort; empty map on failure
  const results = await Promise.allSettled([ingestMcpRegistry(taxonomy, network), ingestApisGuru(network)]);
  const errors: { source: string; message: string }[] = [];
  const mcp = results[0].status === "fulfilled" ? results[0].value : (errors.push({ source: "mcp-registry", message: String((results[0] as PromiseRejectedResult).reason) }), []);
  const apis = results[1].status === "fulfilled" ? results[1].value : (errors.push({ source: "apis-guru", message: String((results[1] as PromiseRejectedResult).reason) }), []);
  if (mcp.length === 0 && apis.length === 0) {
    throw new Error(`both catalog sources failed: ${errors.map((e) => `${e.source}: ${e.message}`).join("; ")}`);
  }
  const bySlug = new Map<string, Toolkit>();
  for (const t of [...mcp, ...apis]) bySlug.set(t.slug, t);
  const toolkits = [...bySlug.values()].sort((a, b) => a.name.localeCompare(b.name));
  // How many registry servers got a curated category from the awesome-mcp taxonomy (repo matched).
  const reclassified = taxonomy.size
    ? mcp.filter((t) => { const n = normalizeRepoUrl(t.repository); return n ? taxonomy.has(n) : false; }).length
    : 0;
  return {
    snapshot: {
      generated_at: "",
      counts: { total: toolkits.length, mcp_registry: mcp.length, apis_guru: apis.length },
      categories: tallyCategories(toolkits),
      toolkits,
    },
    errors,
    enrichment: { taxonomy_entries: taxonomy.size, reclassified },
  };
}

/**
 * Re-apply the awesome-mcp category taxonomy to an ALREADY-LOADED snapshot, in place, WITHOUT a full
 * registry re-fetch. For every `mcp-registry` toolkit whose GitHub repo is in the taxonomy, its primary
 * `category` is overridden with the curated one: identical semantics to `toolkitFromRegistry`'s
 * `curatedCategory || deriveMcpCategory`, just applied post-hoc so `toolkits recategorize` can enrich
 * the shipped catalog cheaply (small reviewable diff, no network re-snapshot). apis-guru entries are
 * NEVER touched (origin-scoped): they carry their own provider-domain categories. The histogram is
 * recomputed so the count==content invariant still holds. Empty taxonomy is a no-op (never wipes
 * categories). Mutates `snapshot`; returns how many entries matched a taxonomy repo and how many
 * actually changed category.
 */
export function applyTaxonomyToSnapshot(
  snapshot: CatalogSnapshot,
  taxonomy: Map<string, string>,
): { matched: number; changed: number } {
  let matched = 0;
  let changed = 0;
  if (taxonomy.size === 0) return { matched, changed };
  for (const t of snapshot.toolkits) {
    if (t.origin !== "mcp-registry") continue;
    const n = normalizeRepoUrl(t.repository);
    const curated = n ? taxonomy.get(n) : undefined;
    if (!curated) continue;
    matched++;
    if (t.category !== curated) {
      t.category = curated;
      changed++;
    }
  }
  snapshot.categories = tallyCategories(snapshot.toolkits);
  return { matched, changed };
}

/** Load the on-disk snapshot. Returns an empty catalog if the file is missing. */
export function loadCatalog(path: string = defaultCatalogPath()): CatalogSnapshot {
  if (!existsSync(path)) {
    return { generated_at: "", counts: { total: 0, mcp_registry: 0, apis_guru: 0 }, categories: [], toolkits: [] };
  }
  try {
    return JSON.parse(readFileSync(path, "utf8")) as CatalogSnapshot;
  } catch {
    return { generated_at: "", counts: { total: 0, mcp_registry: 0, apis_guru: 0 }, categories: [], toolkits: [] };
  }
}

/** Write the snapshot to disk (pretty-printed for a reviewable diff), creating the dir if needed. */
export function writeCatalog(snapshot: CatalogSnapshot, path: string = defaultCatalogPath()): void {
  const dir = dirname(path);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(path, JSON.stringify(snapshot, null, 2) + "\n", "utf8");
}

/**
 * In-memory query over a loaded catalog: free-text search + category filter + ordering + pagination.
 * Search matches name, description, category, and tags (case-insensitive, all terms must hit). The
 * category filter matches ANY of a toolkit's categories (primary + extras) via `toolkitCategories`,
 * so it agrees with the sidebar histogram by construction.
 *
 * Ordering:
 *   - `sortBy: "alpha"` (default) keeps the snapshot's name-sorted order.
 *   - `sortBy: "mounted"` floats toolkits already mounted (`mountedSlugs`) to the top, preserving the
 *     alphabetical order WITHIN the mounted and unmounted groups (a stable partition). This is what
 *     the dashboard uses so the operator sees what they've already connected first.
 */
export function queryCatalog(
  snapshot: CatalogSnapshot,
  opts: {
    q?: string;
    category?: string;
    origin?: string;
    offset?: number;
    limit?: number;
    sortBy?: "alpha" | "mounted";
    mountedSlugs?: Set<string>;
  },
): { total: number; items: Toolkit[] } {
  const terms = (opts.q ?? "").toLowerCase().split(/\s+/).filter(Boolean);
  const cat = opts.category && opts.category !== "All" ? opts.category : null;
  const origin = opts.origin && opts.origin !== "all" ? opts.origin : null;

  const filtered = snapshot.toolkits.filter((t) => {
    if (cat && !toolkitCategories(t).includes(cat)) return false;
    if (origin && t.origin !== origin) return false;
    if (terms.length === 0) return true;
    const hay = `${t.name} ${t.description} ${t.category} ${t.tags.join(" ")}`.toLowerCase();
    return terms.every((term) => hay.includes(term));
  });

  // Stable mounted-first partition (the snapshot is already alpha-sorted, so each group stays alpha).
  let ordered = filtered;
  if (opts.sortBy === "mounted" && opts.mountedSlugs && opts.mountedSlugs.size > 0) {
    const mounted = opts.mountedSlugs;
    const front: Toolkit[] = [];
    const back: Toolkit[] = [];
    for (const t of filtered) (mounted.has(t.slug) ? front : back).push(t);
    ordered = [...front, ...back];
  }

  const offset = Math.max(0, opts.offset ?? 0);
  const limit = Math.min(200, Math.max(1, opts.limit ?? 60));
  return { total: ordered.length, items: ordered.slice(offset, offset + limit) };
}
