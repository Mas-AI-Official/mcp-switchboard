// Deterministic oracle for the audit log + secret-safe I/O capture (src/audit.ts, with the
// injected-key seam from src/transforms.ts). The whole point of zero-custody is that a resolved
// vault/oauth secret NEVER lands on disk in cleartext — this oracle proves that property against
// the compiled dist/, computing every verdict itself (no server, no network, no model).
//
// It proves:
//   sanitizeForAudit (name heuristic) — keys matching /token|secret|password|api_key|authorization/
//                                       are masked; ordinary keys pass through.
//   sanitizeForAudit (injected seam)  — THE FIX: a secret injected under a BENIGN key name (e.g. `q`)
//                                       is redacted by EXACT name, so the secret VALUE never appears
//                                       in the serialized capture. The same call WITHOUT the seam
//                                       leaks it — that control proves the seam is load-bearing.
//   injectedArgKeys                   — server∪tool inject_args key union (tool merged in), name-agnostic.
//   end-to-end leak path              — applyArgTransforms → injectedArgKeys → sanitizeForAudit, the
//                                       exact wiring router.forward() uses, proven secret-free.
//   depth/size/uncapturable guards    — depth>6 cap, 4096-byte truncation marker, circular → "[uncapturable]".
//   audit/recentAudit/usageStats      — append-only write under an isolated SWITCHBOARD_HOME, newest-first
//                                       read, and allow/deny/approval + by_day/top_tools/by_server aggregation.
//   classifyOutcome + outcome tally   — OUTCOME (what happened) is kept distinct from DECISION (did we
//                                       allow it): an allowed-but-failed call counts as `error`, not a
//                                       win, and the SB_* error-code taxonomy is tallied. success+error===allow.
// Zero deps (node stdlib + the package's own compiled output). Run `npm run build` first.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Isolate the audit log into a throwaway home BEFORE importing — HOME_DIR is resolved at module load
// (vault.ts reads SWITCHBOARD_HOME there), so this redirects every write away from the real ~/.switchboard.
process.env.SWITCHBOARD_HOME = mkdtempSync(join(tmpdir(), "sb-audit-"));

const { sanitizeForAudit, audit, recentAudit, usageStats, classifyOutcome } = await import("../dist/audit.js");
const { injectedArgKeys, applyArgTransforms } = await import("../dist/transforms.js");

const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
};

// A distinctive sentinel: if this string ever appears in a serialized capture, a secret leaked.
const SECRET = "SUPERSECRET-7f3a";

// --- 1. name-heuristic redaction (pre-existing behavior, the control surface) ---------------------
{
  const out = sanitizeForAudit({
    api_key: SECRET,
    apiKey: SECRET,
    authorization: SECRET,
    access_token: SECRET,
    user_password: SECRET,
    client_secret: SECRET,
    normal: "keep-me",
    count: 7,
  });
  const s = JSON.stringify(out);
  assert("api_key (snake) masked by name", out.api_key === "[redacted]");
  assert("apiKey (camel) masked by name", out.apiKey === "[redacted]");
  assert("authorization masked by name", out.authorization === "[redacted]");
  assert("access_token masked by name", out.access_token === "[redacted]");
  assert("user_password masked by name", out.user_password === "[redacted]");
  assert("client_secret masked by name", out.client_secret === "[redacted]");
  assert("non-secret key passes through", out.normal === "keep-me" && out.count === 7);
  assert("no secret VALUE survives name-masking", !s.includes(SECRET), s.slice(0, 80));
}

// --- 2. THE FIX: a secret injected under a benign key name -----------------------------------------
{
  // The leak scenario: operator injects `${vault:apiToken}` under the innocuous param `q`. The name
  // heuristic alone would NOT mask `q`, so the resolved secret would hit the log in cleartext.
  const finalArgs = { q: SECRET, page: 2, note: "visible" };
  const injected = new Set(["q"]);

  // CONTROL — without the seam, the secret leaks. This proves the seam is doing real work.
  const leaked = JSON.stringify(sanitizeForAudit(finalArgs));
  assert("CONTROL: benign-key secret LEAKS without the seam", leaked.includes(SECRET), "expected leak reproduced");

  // FIX — with the injected-key set, `q` is redacted by exact name; the secret value is gone.
  const safe = sanitizeForAudit(finalArgs, injected);
  const safeStr = JSON.stringify(safe);
  assert("FIX: injected benign key is redacted", safe.q === "[redacted]");
  assert("FIX: secret VALUE absent from capture", !safeStr.includes(SECRET), safeStr);
  assert("FIX: non-injected args preserved", safe.page === 2 && safe.note === "visible");
}

// --- 3. injectedArgKeys: server ∪ tool union, tool merged in, name-agnostic ------------------------
{
  const serverCfg = { inject_args: { q: "${vault:a}", region: "${env:R}" } };
  const override = { inject_args: { id: "${oauth:gmail}" } };

  const merged = injectedArgKeys(serverCfg, override);
  assert("injectedArgKeys merges server keys", merged.has("q") && merged.has("region"));
  assert("injectedArgKeys merges tool-override keys", merged.has("id"));
  assert("injectedArgKeys size is the union (3)", merged.size === 3, `size=${merged.size}`);

  const serverOnly = injectedArgKeys(serverCfg, undefined);
  assert("injectedArgKeys works with no override", serverOnly.size === 2 && serverOnly.has("q"));

  const empty = injectedArgKeys({}, undefined);
  assert("injectedArgKeys on empty config is an empty set", empty.size === 0);

  // A key present in BOTH server and tool collapses to one entry (no double-count).
  const overlap = injectedArgKeys({ inject_args: { q: "${vault:a}" } }, { inject_args: { q: "${oauth:b}" } });
  assert("overlapping server+tool key collapses to one", overlap.size === 1 && overlap.has("q"));
}

// --- 4. end-to-end leak path: applyArgTransforms → injectedArgKeys → sanitizeForAudit --------------
{
  // Exactly the wiring router.forward() performs: transform agent args (injecting the resolved
  // secret), derive the redaction set from the SAME config, then sanitize for capture.
  const resolver = (ref) => {
    const map = { "${vault:apiToken}": SECRET, "${oauth:gmail}": `OAUTH-${SECRET}` };
    return map[ref] ?? ref;
  };
  const serverCfg = { inject_args: { q: "${vault:apiToken}" } };
  const override = { inject_args: { auth_id: "${oauth:gmail}" } };

  const finalArgs = applyArgTransforms({ q: "agent-typed", body: "hello" }, serverCfg, override, resolver);
  assert("transform injected the resolved vault secret under `q`", finalArgs.q === SECRET);
  assert("transform injected the resolved oauth secret under `auth_id`", finalArgs.auth_id === `OAUTH-${SECRET}`);
  assert("transform left a genuine agent arg intact", finalArgs.body === "hello");

  const keys = injectedArgKeys(serverCfg, override);
  const captured = sanitizeForAudit(finalArgs, keys);
  const capturedStr = JSON.stringify(captured);
  assert("end-to-end: vault secret redacted", captured.q === "[redacted]");
  assert("end-to-end: oauth secret redacted", captured.auth_id === "[redacted]");
  assert("end-to-end: NO secret value anywhere in capture", !capturedStr.includes(SECRET), capturedStr);
  assert("end-to-end: genuine agent arg still captured", captured.body === "hello");
}

// --- 5. nested injected values are reached when the secret-key set applies at the top level --------
{
  // Injected keys are always top-level finalArgs keys, so a whole injected OBJECT value is masked
  // wholesale (the key matches), regardless of what it nests.
  const finalArgs = { creds: { token: SECRET, deep: { also: SECRET } }, ok: 1 };
  const out = sanitizeForAudit(finalArgs, new Set(["creds"]));
  const s = JSON.stringify(out);
  assert("a whole injected object value is masked", out.creds === "[redacted]");
  assert("no secret leaks from a masked object's interior", !s.includes(SECRET), s);
  assert("sibling non-injected value preserved", out.ok === 1);
}

// --- 6. depth guard: recursion is bounded at depth 6 (a DoS/size guard, documented) ----------------
{
  // Build an object whose innermost `token` sits at depth 7 (beyond the cap). The cap returns it
  // as-is — this documents the BOUND. Injected secrets are never affected: they are top-level keys.
  let deep = { token: "deep-and-uncapped" };
  for (let i = 0; i < 7; i++) deep = { a: deep };
  const out = sanitizeForAudit(deep);
  // Walk down to the innermost object.
  let cur = out;
  for (let i = 0; i < 7; i++) cur = cur.a;
  assert("depth guard stops descending past 6 (bound documented)", cur.token === "deep-and-uncapped");

  // A secret WITHIN the cap is still masked.
  const shallow = sanitizeForAudit({ a: { b: { token: SECRET } } });
  assert("a secret inside the depth cap is masked", shallow.a.b.token === "[redacted]");
}

// --- 7. size cap: an over-cap value becomes a truncation marker, never the raw blob ----------------
{
  const big = { blob: "x".repeat(8000) };
  const out = sanitizeForAudit(big);
  assert("over-cap capture returns a _truncated marker", typeof out._truncated === "number" && out._truncated > 4096);
  assert("truncated preview is capped at 4096 bytes", out.preview.length === 4096, `len=${out.preview.length}`);

  const small = sanitizeForAudit({ a: 1 });
  assert("an under-cap value is returned whole (no marker)", small._truncated === undefined && small.a === 1);
}

// --- 8. uncapturable: a circular structure can't crash the logger ----------------------------------
{
  const circular = { name: "loop" };
  circular.self = circular;
  const out = sanitizeForAudit(circular);
  assert("a circular value yields [uncapturable], not a throw", out === "[uncapturable]");
}

// --- 9. append-only write + newest-first read under the isolated home ------------------------------
{
  audit({ server: "gmail", tool: "send", scope: "write", decision: "allow", reason: "ok" });
  audit({ server: "gmail", tool: "send", scope: "write", decision: "allow", reason: "ok" });
  audit({ server: "gmail", tool: "read", scope: "read", decision: "deny", reason: "policy" });
  audit({ server: "slack", tool: "post", scope: "write", decision: "approval_required", reason: "gate" });

  const recent = recentAudit(10);
  assert("recentAudit returns all written rows", recent.length === 4, `len=${recent.length}`);
  assert("recentAudit is newest-first", recent[0].tool === "post" && recent[0].decision === "approval_required");
  assert("audit rows carry an ISO timestamp", typeof recent[0].ts === "string" && recent[0].ts.includes("T"));
}

// --- 10. usageStats aggregation ---------------------------------------------------------------------
{
  const u = usageStats();
  assert("usageStats total counts every row", u.total === 4, `total=${u.total}`);
  assert("usageStats splits allow/deny/approval", u.allow === 2 && u.deny === 1 && u.approval_required === 1, `${u.allow}/${u.deny}/${u.approval_required}`);
  assert("usageStats by_day groups same-day rows", u.by_day.length === 1 && u.by_day[0].count === 4, JSON.stringify(u.by_day));

  const top = u.top_tools[0];
  assert("usageStats top_tools ranks the busiest tool", top.tool === "send" && top.server === "gmail" && top.count === 2, JSON.stringify(top));
  assert("usageStats top_tools splits server__tool keys cleanly", u.top_tools.every((t) => !t.tool.includes("__")));

  const srv = Object.fromEntries(u.by_server.map((s) => [s.server, s.count]));
  assert("usageStats by_server totals per server", srv.gmail === 3 && srv.slack === 1, JSON.stringify(srv));
  assert("usageStats by_server is descending", u.by_server[0].count >= u.by_server[u.by_server.length - 1].count);
}

// --- 11. OUTCOME vs DECISION: an allowed-but-failed call is NOT a success ---------------------------
{
  // classifyOutcome is a pure function of (decision, error, error_code) — pin every branch directly,
  // independent of any disk state. This is the contract usageStats relies on.
  assert("classify: deny → denied", classifyOutcome({ decision: "deny" }) === "denied");
  assert("classify: approval_required → approval_required", classifyOutcome({ decision: "approval_required" }) === "approval_required");
  assert("classify: clean allow → success", classifyOutcome({ decision: "allow" }) === "success");
  assert("classify: allow + error string → error", classifyOutcome({ decision: "allow", error: "boom" }) === "error");
  assert("classify: allow + error_code only → error", classifyOutcome({ decision: "allow", error_code: "SB_UPSTREAM_TIMEOUT" }) === "error");

  // Seed three MORE rows into the same isolated log: allowed calls that FAILED upstream. The decision
  // tally still counts them as `allow` (governance DID permit them) — the honesty is in the outcome split.
  const before = usageStats(); // { total:4, allow:2, ... } from sections 9–10
  audit({ server: "gmail", tool: "send", scope: "write", decision: "allow", reason: "permitted", error: "upstream 500", error_code: "SB_UPSTREAM_ERROR" });
  audit({ server: "gmail", tool: "send", scope: "write", decision: "allow", reason: "permitted", error_code: "SB_UPSTREAM_TIMEOUT" });
  audit({ server: "weather", tool: "get", scope: "read", decision: "allow", reason: "permitted", error: "nope", error_code: "SB_UPSTREAM_ERROR" });

  const u = usageStats();
  assert("decision tally still counts allowed-but-failed as allow", u.allow === before.allow + 3, `allow=${u.allow}`);
  assert("total grew by exactly the 3 new rows", u.total === before.total + 3, `total=${u.total}`);

  // The core invariant: outcomes partition the decisions. success+error === allow; the other two match 1:1.
  assert("outcomes.success + outcomes.error === allow", u.outcomes.success + u.outcomes.error === u.allow, JSON.stringify(u.outcomes));
  assert("outcomes.denied === deny", u.outcomes.denied === u.deny);
  assert("outcomes.approval_required === approval_required", u.outcomes.approval_required === u.approval_required);
  assert("every row lands in exactly one outcome bucket", u.outcomes.success + u.outcomes.error + u.outcomes.denied + u.outcomes.approval_required === u.total, JSON.stringify(u.outcomes));

  // The lie this fixes: the 2 clean sends stay `success`, the 3 failed allows become `error` (NOT counted as wins).
  assert("clean allows counted as success (the 2 from §9)", u.outcomes.success === 2, `success=${u.outcomes.success}`);
  assert("allowed-but-failed counted as error, not success", u.outcomes.error === 3, `error=${u.outcomes.error}`);

  // error_codes taxonomy is tallied and sorted descending; the deny row (no error_code) is absent.
  const codes = Object.fromEntries(u.error_codes.map((c) => [c.code, c.count]));
  assert("error_codes tallies SB_UPSTREAM_ERROR (×2)", codes.SB_UPSTREAM_ERROR === 2, JSON.stringify(u.error_codes));
  assert("error_codes tallies SB_UPSTREAM_TIMEOUT (×1)", codes.SB_UPSTREAM_TIMEOUT === 1, JSON.stringify(u.error_codes));
  assert("error_codes excludes rows with no code (the deny row)", u.error_codes.reduce((s, c) => s + c.count, 0) === u.outcomes.error, JSON.stringify(u.error_codes));
  assert("error_codes is sorted descending by count", u.error_codes[0].count >= u.error_codes[u.error_codes.length - 1].count, JSON.stringify(u.error_codes));
}

const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
process.exitCode = failed.length === 0 ? 0 : 1;
