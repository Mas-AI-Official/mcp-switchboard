/**
 * verify-search.mjs — deterministic oracle for the BM25F tool ranker (src/search-index.ts).
 *
 * No MCP server, no network: it imports the pure ranking function from dist/ and asserts the
 * five properties that separate BM25F from the old additive keyword scorer — IDF (rare terms
 * win), field weighting (a name hit beats a description hit), length normalization, TF
 * saturation, exact-first ordering, the multiplicative `important` boost, and the limit cap —
 * plus one realistic catalogue ranking ("create a github issue" → github__create_issue #1).
 */
import { rankBm25, tokenize } from "../dist/search-index.js";

const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "ok  " : "FAIL"} ${name}${detail ? `  — ${detail}` : ""}`);
};
const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const ids = (rs) => rs.map((r) => r.id);
const scoreOf = (rs, id) => rs.find((r) => r.id === id)?.score ?? 0;

// Field helpers mirroring the Router's SEARCH_FIELDS (name 6/b0, tags 4/b0, props 2/b0, desc 1/b0.75).
const tool = (id, description, props = [], tags = []) => ({
  id,
  fields: [
    { key: "name", text: id, weight: 6, b: 0 },
    { key: "tags", text: tags.join(" "), weight: 4, b: 0 },
    { key: "props", text: props.join(" "), weight: 2, b: 0 },
    { key: "description", text: description, weight: 1, b: 0.75 },
  ],
});

// ── tokenizer ────────────────────────────────────────────────────────────────
assert("tokenize splits delimiters + lowercases", eq(tokenize("GitHub__create_issue"), ["github", "create", "issue"]));
assert("tokenize drops empties", eq(tokenize("  a--b  "), ["a", "b"]));
assert("tokenize empty → []", eq(tokenize(""), []));

// ── degenerate inputs ─────────────────────────────────────────────────────────
assert("empty query → []", eq(rankBm25([tool("x", "y")], ""), []));
assert("whitespace query → []", eq(rankBm25([tool("x", "y")], "   "), []));
assert("empty corpus → []", eq(rankBm25([], "anything"), []));

// ── IDF: a rarer term outranks a common one ────────────────────────────────────
{
  // "get" appears in every doc (common, low IDF); "transmogrify" appears in exactly one (rare, high IDF).
  const filler = Array.from({ length: 8 }, (_, i) => ({
    id: `common_${i}`,
    fields: [{ key: "name", text: "get", weight: 6, b: 0 }],
  }));
  const docCommon = { id: "hit_common", fields: [{ key: "name", text: "get", weight: 6, b: 0 }] };
  const docRare = { id: "hit_rare", fields: [{ key: "name", text: "transmogrify", weight: 6, b: 0 }] };
  const r = rankBm25([docCommon, docRare, ...filler], "get transmogrify");
  assert("IDF: rare-term doc outranks common-term doc", ids(r)[0] === "hit_rare", `order=${ids(r).slice(0, 2)}`);
  assert("IDF: rare term scores strictly higher", scoreOf(r, "hit_rare") > scoreOf(r, "hit_common"));
}

// ── field weighting: a name hit beats a description-only hit ────────────────────
{
  const inName = tool("deploy_service", "unrelated prose about widgets");
  const inDesc = tool("zzz_widget_tool", "this will deploy the service for you");
  const r = rankBm25([inName, inDesc], "deploy");
  assert("field weight: name hit ranks above description hit", ids(r)[0] === "deploy_service", `order=${ids(r)}`);
  assert("field weight: name score > description score", scoreOf(r, "deploy_service") > scoreOf(r, "zzz_widget_tool"));
}

// ── length normalization (b>0): a short field outranks a padded one ─────────────
{
  const short = { id: "short", fields: [{ key: "d", text: "alpha", weight: 1, b: 0.75 }] };
  const long = {
    id: "long",
    fields: [{ key: "d", text: "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda", weight: 1, b: 0.75 }],
  };
  const r = rankBm25([short, long], "alpha");
  assert("length norm (b=0.75): short field outranks long field", ids(r)[0] === "short", `order=${ids(r)}`);

  // Control: with b=0 the same two docs must tie (length is ignored).
  const short0 = { id: "short", fields: [{ key: "d", text: "alpha", weight: 1, b: 0 }] };
  const long0 = { id: "long", fields: [{ key: "d", text: short.fields[0].text + " beta gamma delta epsilon", weight: 1, b: 0 }] };
  const r0 = rankBm25([{ ...short0 }, { id: "long", fields: [{ key: "d", text: "alpha beta gamma delta epsilon", weight: 1, b: 0 }] }], "alpha");
  assert("length norm control (b=0): scores are length-independent", Math.abs(scoreOf(r0, "short") - scoreOf(r0, "long")) < 1e-12,
    `short=${scoreOf(r0, "short")} long=${scoreOf(r0, "long")}`);
}

// ── TF saturation: two occurrences score < twice one occurrence ─────────────────
{
  const once = { id: "once", fields: [{ key: "d", text: "issue", weight: 1, b: 0 }] };
  const twice = { id: "twice", fields: [{ key: "d", text: "issue issue", weight: 1, b: 0 }] };
  const r = rankBm25([once, twice], "issue");
  const s1 = scoreOf(r, "once");
  const s2 = scoreOf(r, "twice");
  assert("TF: more occurrences scores higher", s2 > s1, `once=${s1.toFixed(4)} twice=${s2.toFixed(4)}`);
  assert("TF: saturation — 2× occurrences < 2× score", s2 < 2 * s1, `twice=${s2.toFixed(4)} 2*once=${(2 * s1).toFixed(4)}`);
}

// ── exact-first: an exact match sorts above any non-exact, regardless of text score ──
{
  const exact = { id: "send_message", exact: true, fields: [{ key: "name", text: "send_message", weight: 6, b: 0 }] };
  const fuzzy = {
    id: "send_message_to_many_channels_in_bulk",
    fields: [{ key: "name", text: "send message to many channels in bulk send message", weight: 6, b: 0 }],
  };
  const r = rankBm25([fuzzy, exact], "send message");
  assert("exact-first: exact match is result[0]", ids(r)[0] === "send_message", `order=${ids(r)}`);
}

// ── important boost: a flagged tool outranks an otherwise-identical peer ─────────
{
  const plain = tool("notify_user", "send a notification to the user");
  const boosted = { ...tool("notify_admin", "send a notification to the user"), boost: 1.5 };
  const r = rankBm25([plain, boosted], "send notification");
  assert("important boost: boosted doc ranks first", ids(r)[0] === "notify_admin", `order=${ids(r)}`);
  assert("important boost: boosted score ≈ 1.5× peer", Math.abs(scoreOf(r, "notify_admin") - 1.5 * scoreOf(r, "notify_user")) < 1e-9);
}

// ── limit cap ───────────────────────────────────────────────────────────────────
{
  const corpus = Array.from({ length: 10 }, (_, i) => tool(`search_tool_${i}`, "search things"));
  const r = rankBm25(corpus, "search", { limit: 3 });
  assert("limit caps result count", r.length === 3, `len=${r.length}`);
}

// ── realistic catalogue ranking ─────────────────────────────────────────────────
{
  const catalog = [
    tool("github__create_issue", "Create a new issue in a GitHub repository", ["title", "body", "repo"], ["github", "issues"]),
    tool("github__list_issues", "List issues in a GitHub repository", ["repo", "state"], ["github", "issues"]),
    tool("github__create_pull_request", "Create a pull request in a GitHub repository", ["title", "head", "base"], ["github", "pulls"]),
    tool("gitlab__create_issue", "Create an issue in a GitLab project", ["title", "description"], ["gitlab", "issues"]),
    tool("slack__send_message", "Send a message to a Slack channel", ["channel", "text"], ["slack", "chat"]),
    tool("jira__create_ticket", "Create a ticket in a Jira project", ["summary", "project"], ["jira", "issues"]),
    tool("linear__create_issue", "Create an issue in Linear", ["title", "team"], ["linear", "issues"]),
  ];
  const r = rankBm25(catalog, "create a github issue", { limit: 5 });
  assert("catalogue: 'create a github issue' → github__create_issue #1", ids(r)[0] === "github__create_issue", `order=${ids(r)}`);
  assert("catalogue: github__list_issues outranks slack__send_message",
    scoreOf(r, "github__list_issues") > scoreOf(r, "slack__send_message"));

  const r2 = rankBm25(catalog, "send a slack message", { limit: 3 });
  assert("catalogue: 'send a slack message' → slack__send_message #1", ids(r2)[0] === "slack__send_message", `order=${ids(r2)}`);
}

// ── summary ──────────────────────────────────────────────────────────────────
const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
if (failed.length) console.log("FAILED:", failed.map((c) => c.name).join(", "));
process.exitCode = failed.length === 0 ? 0 : 1;
