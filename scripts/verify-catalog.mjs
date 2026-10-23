// Deterministic oracle for the toolkit catalog query layer (src/catalog.ts). Pure data — NO network,
// NO MCP transport. Imports the compiled query functions and exercises them against synthetic
// snapshots plus the real shipped data/catalog.json.
//
// It proves:
//   membership          — toolkitCategories(t) is the deduped union of the primary category and any
//                          extras; a single-category entry yields exactly [category].
//   multi-cat filter     — a toolkit carrying several categories is returned by EACH of them.
//   count == content     — THE honesty invariant: for every category in the histogram that
//                          tallyCategories() produces, the sidebar count equals the number of results
//                          queryCatalog() returns for that category filter. Tested on a multi-category
//                          synthetic snapshot (where naive primary-only counting would drift) AND on
//                          the shipped catalog so the existing snapshot is proven un-broken.
//   mounted-first sort   — sortBy:"mounted" floats mounted slugs to the front as a STABLE partition
//                          (alpha order preserved within each group); alpha/default keeps snapshot
//                          order; pagination slices the reordered list and total reflects the full
//                          filtered count.
//   search + category     — free-text terms AND the category filter compose.
// Zero deps (node stdlib + the package's compiled output). Build first.
import {
  queryCatalog,
  toolkitCategories,
  tallyCategories,
  loadCatalog,
  normalizeRepoUrl,
  parseAwesomeEntries,
  parseAwesomeTaxonomy,
  searchAwesomeServers,
  applyTaxonomyToSnapshot,
} from "../dist/catalog.js";

const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
};
const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// --- a synthetic snapshot with deliberate multi-category overlap ----------------------------------
// Names are intentionally out of alpha order in the array so we can prove queryCatalog relies on the
// snapshot ALREADY being name-sorted (it is, in production) — here we pre-sort to mirror that.
const mk = (slug, name, category, categories, origin = "apis-guru") => ({
  slug,
  name,
  description: `${name} integration`,
  category,
  ...(categories ? { categories } : {}),
  tags: [name.toLowerCase()],
  origin,
  source_license: "CC0-1.0 (test)",
  mount: { source: "manual", note: "test" },
});
const toolkits = [
  mk("openapi:alpha", "Alpha Pay", "Payments", ["Payments", "Finance"]),
  mk("openapi:bravo", "Bravo Bank", "Finance", ["Finance"]),
  mk("openapi:charlie", "Charlie Chat", "Communication", undefined, "mcp-registry"),
  mk("openapi:delta", "Delta Data", "Databases", ["Databases", "Cloud"]),
  mk("openapi:echo", "Echo Exchange", "Finance", ["Finance", "Payments"]),
].sort((a, b) => a.name.localeCompare(b.name)); // mirror the production name-sorted snapshot
const snap = {
  generated_at: "",
  counts: { total: toolkits.length, mcp_registry: 1, apis_guru: 4 },
  categories: tallyCategories(toolkits),
  toolkits,
};

// --- 1. membership ---------------------------------------------------------------------------------
{
  const alpha = toolkits.find((t) => t.slug === "openapi:alpha");
  const charlie = toolkits.find((t) => t.slug === "openapi:charlie");
  assert("multi-cat entry: union of primary + extras, deduped", eq(toolkitCategories(alpha), ["Payments", "Finance"]), JSON.stringify(toolkitCategories(alpha)));
  assert("single-cat entry (no `categories`): just [category]", eq(toolkitCategories(charlie), ["Communication"]), JSON.stringify(toolkitCategories(charlie)));
  const bravo = toolkits.find((t) => t.slug === "openapi:bravo");
  assert("primary duplicated in `categories` does not double-count", eq(toolkitCategories(bravo), ["Finance"]), JSON.stringify(toolkitCategories(bravo)));
}

// --- 2. multi-cat filter: an entry surfaces under each of its categories ---------------------------
{
  const underPayments = queryCatalog(snap, { category: "Payments" }).items.map((t) => t.slug).sort();
  const underFinance = queryCatalog(snap, { category: "Finance" }).items.map((t) => t.slug).sort();
  // alpha is Payments+Finance, echo is Finance+Payments → both appear under BOTH filters.
  assert("Payments filter returns every Payments member", eq(underPayments, ["openapi:alpha", "openapi:echo"]), underPayments.join(","));
  assert("Finance filter returns every Finance member", eq(underFinance, ["openapi:alpha", "openapi:bravo", "openapi:echo"]), underFinance.join(","));
  assert("a Payments+Finance entry appears under BOTH filters", underPayments.includes("openapi:alpha") && underFinance.includes("openapi:alpha"));
}

// --- 3. THE honesty invariant: histogram count == filter result count, on multi-cat data ----------
{
  let allConsistent = true;
  let firstBad = "";
  for (const { name, count } of snap.categories) {
    const got = queryCatalog(snap, { category: name, limit: 200 }).total;
    if (got !== count) {
      allConsistent = false;
      if (!firstBad) firstBad = `${name}: histogram=${count} filter=${got}`;
    }
  }
  assert("every histogram count equals its filter's result count (synthetic multi-cat)", allConsistent, firstBad);
  // Sanity: the histogram actually reflects multi-membership (Finance has 3, not a primary-only count).
  const fin = snap.categories.find((c) => c.name === "Finance");
  assert("Finance membership count is 3 (multi-cat counted, not primary-only)", fin && fin.count === 3, JSON.stringify(fin));
  const pay = snap.categories.find((c) => c.name === "Payments");
  assert("Payments membership count is 2", pay && pay.count === 2, JSON.stringify(pay));
}

// --- 4. mounted-first stable partition -------------------------------------------------------------
{
  // Mount two entries that are NOT first alphabetically, to prove they float up.
  const mounted = new Set(["openapi:echo", "openapi:delta"]);
  const r = queryCatalog(snap, { sortBy: "mounted", mountedSlugs: mounted, limit: 200 });
  const order = r.items.map((t) => t.slug);
  // Front group = mounted, alpha within (Delta Data < Echo Exchange). Back group = the rest, alpha.
  assert("mounted entries float to the front", mounted.has(order[0]) && mounted.has(order[1]) && !mounted.has(order[2]), order.join(","));
  assert("alpha order preserved WITHIN the mounted group", order.indexOf("openapi:delta") < order.indexOf("openapi:echo"), order.join(","));
  // Unmounted group keeps snapshot (alpha-by-name) order: Alpha Pay, Bravo Bank, Charlie Chat.
  const back = order.slice(2);
  assert("unmounted group keeps alpha order", eq(back, ["openapi:alpha", "openapi:bravo", "openapi:charlie"]), back.join(","));

  const alphaSort = queryCatalog(snap, { sortBy: "alpha", limit: 200 }).items.map((t) => t.slug);
  const defaultSort = queryCatalog(snap, { limit: 200 }).items.map((t) => t.slug);
  assert("sortBy:alpha == default == snapshot name order", eq(alphaSort, defaultSort) && eq(defaultSort, toolkits.map((t) => t.slug)), defaultSort.join(","));
  assert("empty mountedSlugs is a no-op (keeps snapshot order)", eq(queryCatalog(snap, { sortBy: "mounted", mountedSlugs: new Set(), limit: 200 }).items.map((t) => t.slug), defaultSort));
}

// --- 5. pagination operates on the reordered list; total is the full filtered count ---------------
{
  const mounted = new Set(["openapi:echo", "openapi:delta"]);
  const page1 = queryCatalog(snap, { sortBy: "mounted", mountedSlugs: mounted, offset: 0, limit: 2 });
  const page2 = queryCatalog(snap, { sortBy: "mounted", mountedSlugs: mounted, offset: 2, limit: 2 });
  assert("total reflects ALL filtered entries, not the page size", page1.total === 5, String(page1.total));
  assert("page 1 of the mounted-first order is the two mounted entries", eq(page1.items.map((t) => t.slug), ["openapi:delta", "openapi:echo"]), page1.items.map((t) => t.slug).join(","));
  assert("page 2 continues into the unmounted group", eq(page2.items.map((t) => t.slug), ["openapi:alpha", "openapi:bravo"]), page2.items.map((t) => t.slug).join(","));
}

// --- 6. search AND category compose ---------------------------------------------------------------
{
  const r = queryCatalog(snap, { q: "echo", category: "Finance" });
  assert("search term + category filter both apply", eq(r.items.map((t) => t.slug), ["openapi:echo"]), r.items.map((t) => t.slug).join(","));
  const none = queryCatalog(snap, { q: "echo", category: "Databases" });
  assert("a term that matches no entry in the category yields nothing", none.total === 0, String(none.total));
}

// --- 7. regression: the SHIPPED catalog's stored histogram still agrees with the live filter -------
{
  const shipped = loadCatalog();
  if (shipped.toolkits.length === 0) {
    assert("shipped catalog present (skipped invariant — empty/missing snapshot)", true, "no data/catalog.json");
  } else {
    let consistent = true;
    let firstBad = "";
    for (const { name, count } of shipped.categories) {
      const got = queryCatalog(shipped, { category: name, limit: 200 }).total;
      if (got !== count) {
        consistent = false;
        if (!firstBad) firstBad = `${name}: stored=${count} filter=${got}`;
      }
    }
    assert(`shipped catalog (${shipped.toolkits.length} toolkits): stored counts == live filter counts`, consistent, firstBad);
  }
}

// --- 8. shipped mount URLs are concrete and parseable ----------------------------------------------
{
  const shipped = loadCatalog();
  const bad = [];
  for (const tk of shipped.toolkits) {
    const mount = tk.mount || {};
    const url = mount.url || mount.openapi;
    if (!url) continue;
    try {
      const u = new URL(url);
      if (!["http:", "https:"].includes(u.protocol) || /[{}]/.test(url)) bad.push(`${tk.slug} -> ${url}`);
    } catch {
      bad.push(`${tk.slug} -> ${url}`);
    }
  }
  assert("shipped catalog has no invalid or templated mount URLs", bad.length === 0, bad.slice(0, 3).join("; "));
}

// ==================================================================================================
// awesome-mcp-servers adapter (Adapter C) — taxonomy + live discovery. These prove the ENRICHMENT
// layer parses/joins correctly and, critically, that it can NEVER leak into the snapshot.
// ==================================================================================================

// A synthetic README slice covering the awesome-mcp shapes the parser must survive: emoji headings,
// an <a name> anchor, `&` and `/` kept mid-category, a glama badge and a non-github link before the
// real repo, an inline second github link in the description, and content on BOTH sides of the
// `## Server Implementations` boundary that must be excluded.
const AWESOME_FIXTURE = [
  "# awesome-mcp-servers",
  "",
  "## Table of Contents",
  "",
  "- [before/section](https://github.com/before/section) - Must be ignored (pre-section).",
  "",
  "## Server Implementations",
  "",
  "### 🔗 Aggregators",
  "",
  "- [foo/aggregator](https://github.com/foo/aggregator) - Bridges many servers.",
  "- [bar/switch](https://github.com/bar/switch) ![glama](https://glama.ai/mcp/servers/xyz/badge) - Routes requests. See also [related](https://github.com/other/related).",
  "- [docs](https://example.com/docs) [zap/tool](https://github.com/zap/tool) - Zaps things.",
  "",
  '### <a name="finance"></a>💰 Finance & Fintech',
  "",
  "- [baz/pay](https://github.com/baz/pay) - Payment processing.",
  "",
  "### 📂 Cloud / Infra",
  "",
  "- [qux/cloud](https://github.com/qux/cloud) - Cloud object storage.",
  "",
  "## Frameworks",
  "",
  "### For servers",
  "",
  "- [never/parsed](https://github.com/never/parsed) - Should not appear (past the boundary).",
  "",
].join("\n");

// --- 9. normalizeRepoUrl: every URL shape collapses to the canonical join key ---------------------
{
  const cases = [
    ["https://github.com/Owner/Repo.git", "github.com/owner/repo"], // case + .git suffix
    ["git+https://github.com/Owner/Repo", "github.com/owner/repo"], // git+ prefix
    ["git@github.com:Owner/Repo.git", "github.com/owner/repo"], // scp-style
    ["https://www.github.com/Owner/Repo", "github.com/owner/repo"], // www. subdomain
    ["https://github.com/owner/repo/tree/main/pkg", "github.com/owner/repo"], // deep path -> first 2 segs
    ["https://gitlab.com/owner/repo", null], // non-github host
    ["https://github.com/owner", null], // < 2 path segments
    ["https://notgithub.com/owner/repo", null], // host must END in github.com
    ["not a url", null],
    ["", null],
    [null, null],
    [undefined, null],
  ];
  let bad = "";
  for (const [input, want] of cases) {
    const got = normalizeRepoUrl(input);
    if (got !== want) { bad = `${JSON.stringify(input)} -> ${JSON.stringify(got)} (want ${JSON.stringify(want)})`; break; }
  }
  assert("normalizeRepoUrl collapses every URL shape to the canonical key (or null)", !bad, bad);
}

// --- 10. parseAwesomeTaxonomy / parseAwesomeEntries: fidelity + section boundaries -----------------
{
  const tax = parseAwesomeTaxonomy(AWESOME_FIXTURE);
  assert("taxonomy holds exactly the 5 in-section repos", tax.size === 5, `size=${tax.size} [${[...tax.keys()].join(", ")}]`);
  assert("emoji-only heading -> plain category", tax.get("github.com/foo/aggregator") === "Aggregators", tax.get("github.com/foo/aggregator"));
  assert("<a name> anchor stripped AND `&` kept mid-category", tax.get("github.com/baz/pay") === "Finance & Fintech", tax.get("github.com/baz/pay"));
  assert("`/` kept mid-category", tax.get("github.com/qux/cloud") === "Cloud / Infra", tax.get("github.com/qux/cloud"));
  assert("pre-section bullet excluded (before Server Implementations)", !tax.has("github.com/before/section"));
  assert("post-boundary bullet excluded (## Frameworks ends the section)", !tax.has("github.com/never/parsed"));
  assert("inline description github link is NOT a second entry (first-repo-per-line)", !tax.has("github.com/other/related"));

  const entries = parseAwesomeEntries(AWESOME_FIXTURE);
  const agg = entries.find((e) => e.repoUrl === "github.com/foo/aggregator");
  assert("entry name = link text, description = post-dash text", agg && agg.name === "foo/aggregator" && agg.description === "Bridges many servers.", JSON.stringify(agg));
  const zap = entries.find((e) => e.repoUrl === "github.com/zap/tool");
  assert("non-github link before the repo is skipped for the REPO (repo=first github link)", !!zap, JSON.stringify(zap));
}

// --- 11. searchAwesomeServers: pure filter, exclusion, limit clamp, discovery shape ---------------
{
  const hits = searchAwesomeServers(AWESOME_FIXTURE, "payment");
  assert("query matches on name/desc/category", hits.length === 1 && hits[0].repository === "https://github.com/baz/pay", JSON.stringify(hits.map((h) => h.repository)));
  const r = hits[0];
  assert("discovery hit is flagged installable:false + source awesome-mcp", r.installable === false && r.source === "awesome-mcp", JSON.stringify(r));
  assert("discovery hit carries the vet-before-mounting note", typeof r.note === "string" && /discovery-only/i.test(r.note), r.note);
  assert("discovery hit keeps the curated category", r.category === "Finance & Fintech", r.category);

  const excluded = searchAwesomeServers(AWESOME_FIXTURE, "payment", { exclude: new Set(["github.com/baz/pay"]) });
  assert("a repo we already hold is excluded from discovery", excluded.length === 0, String(excluded.length));

  const all = searchAwesomeServers(AWESOME_FIXTURE, "");
  assert("empty query returns every in-section server (deduped)", all.length === 5, String(all.length));
  const clamped = searchAwesomeServers(AWESOME_FIXTURE, "", { limit: 0 });
  assert("limit is clamped to >=1", clamped.length === 1, String(clamped.length));
}

// --- 12. NO-SNAPSHOT invariant: discovery is structurally un-persistable; catalog stays CC0-only ---
{
  const r = searchAwesomeServers(AWESOME_FIXTURE, "payment")[0];
  const forbidden = ["slug", "mount", "origin"].filter((k) => k in r);
  assert("DiscoveryResult has NO slug/mount/origin (can't be written or mounted as a Toolkit)", forbidden.length === 0, forbidden.join(","));

  const shipped = loadCatalog();
  const ok = new Set(["mcp-registry", "apis-guru"]);
  const leaked = shipped.toolkits.filter((t) => !ok.has(t.origin)).map((t) => `${t.slug}:${t.origin}`);
  assert(`shipped catalog is CC0-only (${shipped.toolkits.length} toolkits, every origin ∈ {mcp-registry, apis-guru})`, leaked.length === 0, leaked.slice(0, 3).join("; "));
}

// --- 13. applyTaxonomyToSnapshot: post-hoc recategorize, origin-scoped, invariant-preserving -------
// Proves the `toolkits recategorize` data-layer op: it overrides `category` ONLY for mcp-registry
// entries whose repo joins the taxonomy, NEVER touches apis-guru (even on a repo match), leaves
// non-joining / repo-less entries alone, recomputes the histogram so count==content still holds,
// preserves the toolkit set + CC0-only origins, is a no-op on an empty taxonomy, and is idempotent.
{
  const reg = (slug, name, category, repository) => ({
    slug, name, description: `${name} server`, category,
    tags: [name.toLowerCase()], origin: "mcp-registry",
    source_license: "MIT (MCP Registry data)", repository,
    mount: { source: "manual", note: "test" },
  });
  const api = (slug, name, category, repository) => ({
    slug, name, description: `${name} api`, category,
    tags: [name.toLowerCase()], origin: "apis-guru",
    source_license: "CC0-1.0 (test)", repository,
    mount: { source: "manual", note: "test" },
  });
  const mkSnap = () => {
    const tks = [
      reg("mcp:agg", "Aggregator", "MCP Servers", "https://github.com/foo/aggregator"),
      reg("mcp:pay", "Payer", "MCP Servers", "https://github.com/baz/pay"),
      reg("mcp:orphan", "Orphan", "MCP Servers", "https://github.com/no/match"),
      reg("mcp:norepo", "NoRepo", "MCP Servers", undefined),
      api("openapi:foo", "FooApi", "Cloud", "https://github.com/foo/aggregator"),
    ];
    return { generated_at: "", counts: { total: tks.length, mcp_registry: 4, apis_guru: 1 }, categories: tallyCategories(tks), toolkits: tks };
  };
  const taxonomy = new Map([
    ["github.com/foo/aggregator", "Aggregators"],
    ["github.com/baz/pay", "Finance & Fintech"],
  ]);

  const s = mkSnap();
  const res = applyTaxonomyToSnapshot(s, taxonomy);
  assert("recategorize matched=2, changed=2 (only the two joining mcp-registry entries)", res.matched === 2 && res.changed === 2, JSON.stringify(res));

  const cat = (slug) => s.toolkits.find((t) => t.slug === slug).category;
  assert("mcp-registry + repo∈taxonomy gets the curated category", cat("mcp:agg") === "Aggregators" && cat("mcp:pay") === "Finance & Fintech", `${cat("mcp:agg")} / ${cat("mcp:pay")}`);
  assert("apis-guru is NEVER recategorized, even on a repo match (origin-scoped)", cat("openapi:foo") === "Cloud", cat("openapi:foo"));
  assert("mcp-registry entry whose repo is not in the taxonomy is unchanged", cat("mcp:orphan") === "MCP Servers", cat("mcp:orphan"));
  assert("mcp-registry entry with no repository is unchanged", cat("mcp:norepo") === "MCP Servers", cat("mcp:norepo"));

  // honesty invariant survives the recompute: every histogram count == its live filter count.
  let consistent = true, firstBad = "";
  for (const { name, count } of s.categories) {
    const got = queryCatalog(s, { category: name, limit: 200 }).total;
    if (got !== count) { consistent = false; if (!firstBad) firstBad = `${name}: histogram=${count} filter=${got}`; }
  }
  assert("after recategorize, histogram count == filter count (honesty invariant holds)", consistent, firstBad);
  assert("recomputed histogram reflects the moves (Aggregators=1, MCP Servers=2)", eq(s.categories.find((c) => c.name === "Aggregators"), { name: "Aggregators", count: 1 }) && s.categories.find((c) => c.name === "MCP Servers").count === 2, JSON.stringify(s.categories));

  // structural invariants: toolkit set unchanged, origins stay CC0-only.
  assert("toolkit count is unchanged by recategorize", s.toolkits.length === 5, String(s.toolkits.length));
  const okOrigins = new Set(["mcp-registry", "apis-guru"]);
  assert("origins stay CC0-only after recategorize", s.toolkits.every((t) => okOrigins.has(t.origin)));

  // idempotent: a second apply matches the same 2 but changes nothing.
  const res2 = applyTaxonomyToSnapshot(s, taxonomy);
  assert("recategorize is idempotent (matched=2, changed=0 on re-run)", res2.matched === 2 && res2.changed === 0, JSON.stringify(res2));

  // empty taxonomy is a pure no-op (no matches, categories untouched).
  const s2 = mkSnap();
  const before = JSON.stringify(s2.categories);
  const res3 = applyTaxonomyToSnapshot(s2, new Map());
  assert("empty taxonomy is a no-op (matched=0, changed=0, categories untouched)", res3.matched === 0 && res3.changed === 0 && JSON.stringify(s2.categories) === before, JSON.stringify(res3));
}

const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
process.exitCode = failed.length === 0 ? 0 : 1;
