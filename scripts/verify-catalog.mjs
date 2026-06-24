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
import { queryCatalog, toolkitCategories, tallyCategories, loadCatalog } from "../dist/catalog.js";

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

const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
process.exitCode = failed.length === 0 ? 0 : 1;
