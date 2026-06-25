// Deterministic oracle for the dashboard's pure JSON-API logic (src/dashboard.ts) and the trigger
// template catalog (src/trigger-templates.ts). Pure data — NO network, NO Express, NO MCP transport.
// It imports the compiled, EXPORTED helpers (importing dist/dashboard.js is side-effect-free:
// startDashboard is declared, never invoked) and exercises them against synthetic inputs plus the
// real shipped data/catalog.json.
//
// It proves:
//   correlateMountedSlugs — a configured server is mapped back to the catalog slug it was mounted
//                           from BY UPSTREAM IDENTITY (remote→url, npx→package, app2mcp→openapi),
//                           independent of the server id; manual-source toolkits never match; an
//                           unknown upstream value matches nothing. Closed-loop against the SHIPPED
//                           catalog: a server built exactly how POST /toolkits/:slug/add builds it
//                           round-trips back to the original slug.
//   pageCount             — honest total_pages: clamps limit to the SAME [1,200] window queryCatalog
//                           paginates by, returns 0 for an empty result, and matches the number of
//                           non-empty pages queryCatalog ACTUALLY produces when walked.
//   councilSummary        — surfaces provider presence + the local endpoint/model but NEVER an
//                           api_key_ref value (the redaction invariant); absent council → disabled.
//   trigger templates     — unique ids, item_path/item_key are present together or not at all,
//                           getTriggerTemplate resolves/΄misses, and templateToDefinition stamps a
//                           ready definition (args merge, name/interval override, hash recipes carry
//                           no item wiring, unknown id throws).
//   isLocalRequest        — the loopback predicate every state-mutating endpoint gates on: IPv4/IPv6
//                           loopback (incl. the IPv4-mapped form and the 127/8 block) is local; public
//                           addresses are not; it falls back to socket.remoteAddress when req.ip is unset.
//   mutator gating (wiring)— a STATIC scan of the compiled dist/dashboard.js proves every state-mutating
//                           route handler contains an isLocalRequest guard, while read endpoints and the
//                           deliberately tunnel-reachable OAuth-flow endpoints (/oauth/consent, /oauth/
//                           callback — protected by pending_id/state, not loopback) carry none. This is
//                           the regression guard against a new mutator shipping ungated.
// Zero deps (node stdlib + the package's compiled output). Build first.
import { readFileSync } from "node:fs";
import { correlateMountedSlugs, pageCount, councilSummary, isLocalRequest } from "../dist/dashboard.js";
import { listTriggerTemplates, getTriggerTemplate, templateToDefinition } from "../dist/trigger-templates.js";
import { loadCatalog, queryCatalog } from "../dist/catalog.js";

const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
};
const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// --- 1. correlateMountedSlugs: map servers back to catalog slugs by upstream identity ------------
{
  const toolkits = [
    { slug: "mcp:remote-a", mount: { source: "remote", url: "https://a.example/mcp", transport: "http" } },
    { slug: "mcp:npx-b", mount: { source: "npx", package: "@org/b" } },
    { slug: "openapi:app-c", mount: { source: "app2mcp", openapi: "https://c.example/openapi.json" } },
    { slug: "manual:d", mount: { source: "manual", note: "install by hand" } },
  ];
  const servers = [
    { id: "renamed-1", source: "remote", url: "https://a.example/mcp", enabled: true }, // → remote-a (id differs)
    { id: "s2", source: "npx", package: "@org/b", enabled: false }, // → npx-b
    { id: "s3", source: "app2mcp", openapi: "https://c.example/openapi.json", enabled: true }, // → app-c
    { id: "s4", source: "remote", url: "https://unknown.example/mcp", enabled: true }, // no catalog match
    { id: "s5", source: "manual", enabled: true }, // manual server: no url/package/openapi → nothing to match
  ];
  const mounted = correlateMountedSlugs(toolkits, servers);
  assert("remote server maps to its catalog slug (by url, not id)", mounted.has("mcp:remote-a"));
  assert("npx server maps by package", mounted.has("mcp:npx-b"));
  assert("app2mcp server maps by openapi path", mounted.has("openapi:app-c"));
  assert("manual-source toolkit is never marked mounted", !mounted.has("manual:d"));
  assert("an unknown upstream value matches no slug", mounted.size === 3, `size=${mounted.size}`);
  assert("empty server list → empty set", correlateMountedSlugs(toolkits, []).size === 0);
  assert("empty toolkit list → empty set", correlateMountedSlugs([], servers).size === 0);
}

// --- 2. correlateMountedSlugs round-trips against the SHIPPED catalog + the add-endpoint shape ----
{
  const shipped = loadCatalog();
  if (shipped.toolkits.length === 0) {
    assert("shipped-catalog correlation (skipped — empty/missing snapshot)", true, "no data/catalog.json");
  } else {
    // No servers → nothing is mounted, regardless of catalog size.
    assert("no servers → no mounted slugs over the real catalog", correlateMountedSlugs(shipped.toolkits, []).size === 0);
    // Pick the first mountable real toolkit and build a server EXACTLY how POST /toolkits/:slug/add
    // builds it, then prove correlation recovers the original slug (closes the add→correlate loop).
    const tk = shipped.toolkits.find((t) => t.mount.source === "remote" || t.mount.source === "npx" || t.mount.source === "app2mcp");
    if (!tk) {
      assert("mountable toolkit present in shipped catalog", false, "catalog has only manual mounts");
    } else {
      const server =
        tk.mount.source === "remote"
          ? { id: "x", source: "remote", url: tk.mount.url, enabled: false, auth: "none" }
          : tk.mount.source === "npx"
            ? { id: "x", source: "npx", package: tk.mount.package, enabled: false }
            : { id: "x", source: "app2mcp", openapi: tk.mount.openapi, enabled: false };
      const mounted = correlateMountedSlugs(shipped.toolkits, [server]);
      assert(`add-shaped server round-trips to its slug (${tk.slug})`, mounted.has(tk.slug), [...mounted].join(","));
    }
  }
}

// --- 3. pageCount: honest, clamp-matched, zero-safe ----------------------------------------------
{
  assert("zero results → 0 pages", pageCount(0, 60) === 0);
  assert("exact multiple → no trailing page", pageCount(120, 60) === 2, String(pageCount(120, 60)));
  assert("remainder → one extra page", pageCount(121, 60) === 3, String(pageCount(121, 60)));
  assert("single full page", pageCount(60, 60) === 1);
  assert("one over a page → 2", pageCount(61, 60) === 2);
  // limit above the cap is paginated by 200 (queryCatalog's ceiling), and pageCount says so.
  assert("limit>200 clamps to 200 for the page count", pageCount(500, 500) === 3, String(pageCount(500, 500)));
  // limit 0 / NaN falls back to 60 (matches the handler's `|| 60` before the call).
  assert("limit 0 falls back to 60", pageCount(100, 0) === 2, String(pageCount(100, 0)));
}

// --- 4. pageCount matches the pages queryCatalog ACTUALLY produces on the shipped catalog ---------
{
  const shipped = loadCatalog();
  if (shipped.toolkits.length === 0) {
    assert("pageCount-vs-queryCatalog walk (skipped — empty snapshot)", true, "no data/catalog.json");
  } else {
    const total = queryCatalog(shipped, { limit: 1 }).total;
    // In-range page size (60) — pageCount and queryCatalog agree exactly.
    assert("shipped: pageCount(total,60) == ceil(total/60)", pageCount(total, 60) === Math.ceil(total / 60), `total=${total}`);
    // Walk the catalog at the clamped effective size (limit=500 → 200/page) and count non-empty
    // pages; that count must equal pageCount(total, 500). This proves total_pages is not a lie.
    const effective = 200;
    let pages = 0;
    for (let offset = 0; offset < total; offset += effective) {
      const got = queryCatalog(shipped, { offset, limit: 500 }).items.length;
      if (got > 0) pages++;
    }
    assert("shipped: walked non-empty pages == pageCount(total,500)", pages === pageCount(total, 500), `walked=${pages} pageCount=${pageCount(total, 500)}`);
  }
}

// --- 5. councilSummary: provider presence surfaced, api_key_ref NEVER leaked ----------------------
{
  const absent = councilSummary(undefined);
  assert("absent council → disabled, all providers false, local null", eq(absent, {
    enabled: false,
    providers: { anthropic: false, openai: false, local: false },
    local: null,
    max_rounds: 3,
    token_budget: 2048,
    require_approval: false,
  }), JSON.stringify(absent));

  const cloud = councilSummary({
    enabled: true,
    providers: {
      anthropic: { api_key_ref: "${vault:anthropic_key}", default_model: "claude-x" },
      openai: { api_key_ref: "${vault:openai_key}", default_model: "gpt-x" },
    },
    max_rounds: 5,
    token_budget: 4096,
    require_approval: true,
  });
  assert("cloud providers reported present", cloud.providers.anthropic && cloud.providers.openai && !cloud.providers.local);
  assert("cloud-only → local summary is null", cloud.local === null);
  assert("max_rounds/token_budget/require_approval pass through", cloud.max_rounds === 5 && cloud.token_budget === 4096 && cloud.require_approval === true);
  assert("NO api_key_ref value leaks into the cloud summary", !JSON.stringify(cloud).includes("vault:anthropic_key") && !JSON.stringify(cloud).includes("vault:openai_key"));

  const local = councilSummary({
    enabled: true,
    providers: {
      local: { base_url: "http://localhost:8080/v1", default_model: "qwen2.5-coder", api_key_ref: "${vault:local_key}" },
    },
  });
  assert("local provider reported present", local.providers.local && !local.providers.anthropic);
  assert("local summary carries non-secret base_url + default_model", eq(local.local, { base_url: "http://localhost:8080/v1", default_model: "qwen2.5-coder" }), JSON.stringify(local.local));
  assert("local provider api_key_ref value is NOT surfaced", !JSON.stringify(local).includes("vault:local_key"));
  assert("council defaults applied when omitted", local.max_rounds === 3 && local.token_budget === 2048 && local.require_approval === false);
}

// --- 6. trigger template catalog: shape invariants -----------------------------------------------
{
  const templates = listTriggerTemplates();
  assert("template catalog is a non-empty array", Array.isArray(templates) && templates.length > 0, String(templates.length));
  const ids = templates.map((t) => t.id);
  assert("template ids are unique", new Set(ids).size === ids.length);
  assert("every template has a tool_hint, category, and positive interval", templates.every((t) => t.tool_hint && t.category && t.interval_seconds > 0));
  // Item-detection recipes name BOTH the array path and the unique key; hash recipes omit BOTH.
  assert("item_path and item_key are present together or not at all", templates.every((t) => (t.item_path !== undefined) === (t.item_key !== undefined)), ids.filter((id) => { const t = templates.find((x) => x.id === id); return (t.item_path !== undefined) !== (t.item_key !== undefined); }).join(","));
  const hashRecipes = templates.filter((t) => t.item_path === undefined);
  assert("at least one whole-response hash recipe exists (no item wiring)", hashRecipes.length > 0, hashRecipes.map((t) => t.id).join(","));
}

// --- 7. getTriggerTemplate resolves and misses ---------------------------------------------------
{
  const first = listTriggerTemplates()[0];
  assert("getTriggerTemplate returns the named template", getTriggerTemplate(first.id)?.id === first.id);
  assert("getTriggerTemplate(unknown) → undefined", getTriggerTemplate("__nope__") === undefined);
}

// --- 8. templateToDefinition: stamping, merge, override, hash recipe, throw -----------------------
{
  // An item-detection recipe with default args (github-new-issues: args {state:"open"}, key "number").
  const gh = templateToDefinition("github-new-issues", { id: "gh1", tool: "github__list_issues" });
  assert("stamped def carries the supplied id + tool", gh.id === "gh1" && gh.tool === "github__list_issues");
  assert("stamped def defaults name + interval from the template", gh.name === "New GitHub issues" && gh.interval_seconds === 120);
  assert("stamped def is enabled and carries template default args", gh.enabled === true && eq(gh.args, { state: "open" }), JSON.stringify(gh.args));
  assert("stamped def carries the template's item wiring", gh.item_key === "number" && gh.item_path === "", JSON.stringify({ p: gh.item_path, k: gh.item_key }));

  // opts.args merge ON TOP of template defaults; name + interval override.
  const merged = templateToDefinition("github-new-issues", { id: "gh2", tool: "x", name: "My issues", args: { state: "closed", labels: "bug" }, interval_seconds: 30 });
  assert("opts.args merge over template defaults", eq(merged.args, { state: "closed", labels: "bug" }), JSON.stringify(merged.args));
  assert("name + interval overrides apply", merged.name === "My issues" && merged.interval_seconds === 30);

  // A template with no default args and no opts.args → no `args` key at all.
  const commits = templateToDefinition("github-new-commits", { id: "c1", tool: "x" });
  assert("no template args + no opts args → def omits `args`", commits.args === undefined, JSON.stringify(commits.args));

  // A hash recipe carries NO item_path/item_key (fires on any whole-response change).
  const page = templateToDefinition("http-page-change", { id: "h1", tool: "web__fetch" });
  assert("hash recipe def has no item_path/item_key", page.item_path === undefined && page.item_key === undefined);

  // Unknown template id fails loud.
  let threw = false;
  try { templateToDefinition("__nope__", { id: "z", tool: "y" }); } catch { threw = true; }
  assert("templateToDefinition(unknown) throws", threw);
}

// --- 9. isLocalRequest: the loopback verdict every mutating endpoint gates on ---------------------
{
  // Synthesize the minimal request shape isLocalRequest reads: req.ip first, then socket.remoteAddress.
  const reqOf = (ip, remoteAddress = undefined) => ({ ip, socket: { remoteAddress } });

  assert("127.0.0.1 (IPv4 loopback) is local", isLocalRequest(reqOf("127.0.0.1")) === true);
  assert("::1 (IPv6 loopback) is local", isLocalRequest(reqOf("::1")) === true);
  assert("::ffff:127.0.0.1 (IPv4-mapped loopback) is local", isLocalRequest(reqOf("::ffff:127.0.0.1")) === true);
  assert("127.5.9.1 (anywhere in 127/8) is local", isLocalRequest(reqOf("127.5.9.1")) === true);

  assert("203.0.113.7 (public IPv4) is NOT local", isLocalRequest(reqOf("203.0.113.7")) === false);
  assert("2001:db8::1 (public IPv6) is NOT local", isLocalRequest(reqOf("2001:db8::1")) === false);
  // A near-miss that must NOT pass the 127. prefix test (it's a different /8).
  assert("12.7.0.0.1-style 12.x is NOT local", isLocalRequest(reqOf("12.7.0.1")) === false);

  // Falls back to socket.remoteAddress when Express hasn't populated req.ip (e.g. trust-proxy off).
  assert("falls back to socket.remoteAddress when req.ip is undefined", isLocalRequest(reqOf(undefined, "127.0.0.1")) === true);
  assert("public socket.remoteAddress (no req.ip) is NOT local", isLocalRequest(reqOf(undefined, "8.8.8.8")) === false);
  // No peer information at all → never treated as local (fail closed).
  assert("an empty peer (no ip, no remoteAddress) is NOT local", isLocalRequest(reqOf(undefined, undefined)) === false);
}

// --- 10. mutator gating (static wiring scan of compiled dist/dashboard.js) ------------------------
{
  // tsc emits readable JS (no minification/renaming), so the loopback guard survives verbatim as
  // `isLocalRequest(`. We scan every route registration in source order, slice each handler up to the
  // NEXT registration, and assert the guard is present exactly where it must be. This is the
  // regression guard: a freshly-added mutating endpoint that forgets the guard fails this oracle.
  const src = readFileSync(new URL("../dist/dashboard.js", import.meta.url), "utf8");

  // Every `app.<verb>("<path>", ...)` registration, in file order. (app.use(express.json()) etc. have
  // no string-literal path as the first arg and are correctly skipped.)
  const routeRe = /app\.(get|post|put|delete)\(\s*(["'`])([^"'`]+)\2/g;
  const routes = [];
  let m;
  while ((m = routeRe.exec(src)) !== null) routes.push({ verb: m[1], path: m[3], index: m.index });
  assert("route scan found the dashboard's registrations", routes.length >= 14, `found=${routes.length}`);

  // Map each route to its handler body (slice to the next registration) and whether it's guarded.
  const gatedOf = (verb, path) => {
    const i = routes.findIndex((r) => r.verb === verb && r.path === path);
    if (i === -1) return null; // not found — caller asserts on null to surface the miss
    const start = routes[i].index;
    const end = i + 1 < routes.length ? routes[i + 1].index : src.length;
    return src.slice(start, end).includes("isLocalRequest(");
  };

  // Every state-mutating endpoint MUST carry the loopback guard.
  const MUST_GATE = [
    ["post", "/api/playground/call"],
    ["post", "/api/toolkits/:slug/add"],
    ["post", "/api/apikeys"],
    ["delete", "/api/apikeys/:id"],
    ["put", "/api/settings"],
    ["post", "/api/webhook/test"],
    ["put", "/api/triggers"],
    ["post", "/api/triggers/:id/poll"],
    ["post", "/api/triggers/:id/pause"],
    ["post", "/api/triggers/:id/resume"],
    ["post", "/api/connect/:provider"],
    ["post", "/api/servers/:id/toggle"],
    ["delete", "/api/servers/:id"],
  ];
  for (const [verb, path] of MUST_GATE) {
    assert(`mutator ${verb.toUpperCase()} ${path} is loopback-gated`, gatedOf(verb, path) === true, gatedOf(verb, path) === null ? "ROUTE NOT FOUND" : "");
  }

  // Read endpoints are intentionally ungated (no isLocalRequest) — proves the scan discriminates and
  // that we didn't over-gate read traffic a tunnelled dashboard legitimately serves.
  const MUST_NOT_GATE = [
    ["get", "/api/state"],
    ["get", "/api/audit"],
    ["get", "/api/usage"],
    ["get", "/api/catalog"],
    ["get", "/api/apikeys"], // listing keys (metadata only) is intentionally readable
  ];
  for (const [verb, path] of MUST_NOT_GATE) {
    assert(`read ${verb.toUpperCase()} ${path} is intentionally NOT loopback-gated`, gatedOf(verb, path) === false, gatedOf(verb, path) === null ? "ROUTE NOT FOUND" : "");
  }

  // The OAuth authorization-server flow MUST be tunnel-reachable (a remote agent completes consent),
  // so it deliberately carries NO loopback guard — it's protected by pending_id/state validation
  // instead. Asserting the absence documents the design decision and prevents an accidental gate that
  // would break the OAuth handshake.
  assert("OAuth POST /oauth/consent is deliberately NOT loopback-gated (state-protected, tunnel-reachable)", gatedOf("post", "/oauth/consent") === false, gatedOf("post", "/oauth/consent") === null ? "ROUTE NOT FOUND" : "");
}

const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
process.exitCode = failed.length === 0 ? 0 : 1;
