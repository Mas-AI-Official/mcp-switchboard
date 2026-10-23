// Deterministic oracle for the keystone: src/router.ts — the governed call path every tool invocation
// flows through. verify-search already covers the pure BM25F ranker in isolation; this oracle covers
// what that one cannot: the Router's `callTool` entry point, its three exposure modes (namespaced /
// flat / search), the search-mode meta-tools (find_tools / call_tool / batch_call), and the FULL
// forward() governance pipeline — profile gate → scope ceiling → rate limit → circuit breaker →
// approval gate → arg-transform → upstream call → audit. It drives the REAL compiled Router over REAL
// in-memory upstream MCP Servers (mounted through the real Registry) and computes every verdict itself.
// ZERO network, ZERO model, ZERO native deps (node stdlib + the package's compiled output + bundled SDK).
//
// It proves, against the real `{ isError, content:[{ text }] }` result/error surface:
//   namespaced forward     — `alpha__echo` routes to the alpha upstream and returns its text, writing
//                            one allow audit row (server=alpha, tool=echo, scope=write).
//   HOME_DIR override       — that forwarded call wrote audit.log under the throwaway SWITCHBOARD_HOME
//                            (proves the env-before-import redirect took effect; router.ts exports no
//                            HOME_DIR, so the written log file is the observable proof).
//   flat collision          — in flat mode a bare `echo` owned by both alpha and beta resolves
//                            first-wins by mount order (alpha), never silently to the later mount.
//   search meta-tools       — find_tools returns a matches envelope, call_tool routes through the SAME
//                            governed forward, batch_call runs N calls where one bad entry fails IN
//                            PLACE without aborting the rest; each meta-tool's input validation returns
//                            a structured SB_BAD_REQUEST envelope.
//   every deny lever        — UNKNOWN_TOOL (no `__`), POLICY_DENY (active-profile exclusion AND scope
//                            over-ceiling), RATE_LIMITED (per_minute:1), UPSTREAM_UNAVAILABLE (breaker
//                            opens at threshold 1), APPROVAL_DENIED (gated read, fail-closed no-TTY),
//                            UPSTREAM_ERROR (upstream throw with resilience off) — each carries the
//                            exact SB_* code and its SB_HINTS hint.
//   secret redaction        — with capture_io on, an injected `${env:..}` secret landing under a benign
//                            key (`account`) is redacted by exact key name in the captured audit row,
//                            while a non-secret arg (`data`) is captured verbatim.
// Build first (this imports from dist/).
import { mkdtempSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Isolate the audit log into a throwaway home BEFORE importing — HOME_DIR is resolved at module load
// (vault.ts reads SWITCHBOARD_HOME there; audit.ts derives AUDIT_PATH = join(HOME_DIR,"audit.log")),
// so this redirects every write away from the real ~/.switchboard.
process.env.SWITCHBOARD_HOME = mkdtempSync(join(tmpdir(), "sb-router-"));
const HOME = process.env.SWITCHBOARD_HOME;

// Approval must FAIL CLOSED here, deterministically, without blocking on a human. Since design 3.3 a gated call
// never waits for a keystroke: it leaves a pending approval and returns SB_APPROVAL_PENDING at once, whatever the
// terminal looks like. Force no auto-approve (and keep the non-TTY streams, which the old in-band gate needed).
delete process.env.SWITCHBOARD_AUTO_APPROVE;
process.stdin.isTTY = false;
process.stdout.isTTY = false;

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  McpError,
  ErrorCode,
} from "@modelcontextprotocol/sdk/types.js";

const { Registry } = await import("../dist/registry.js");
const { Router } = await import("../dist/router.js");
const { Vault } = await import("../dist/vault.js");
const { recentAudit } = await import("../dist/audit.js");
const { SB_ERR, SB_HINTS } = await import("../dist/errors.js");

const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// --- a real in-memory upstream MCP Server exposing the named tools -----------------------------------
// echo  -> "<server>:echo:<msg>"          (write scope)
// boom  -> throws (transport failure)      (write scope)  — drives UPSTREAM_ERROR + breaker
// wipe_all -> text (never reached)         (full scope)   — drives scope POLICY_DENY
// get_secret -> text (never reached)       (read scope)   — drives APPROVAL_DENIED
// store -> "<server>:store:ok"             (write scope)  — drives injected-secret redaction
function makeToolServer(serverName, toolNames) {
  const server = new Server({ name: serverName, version: "0.0.0" }, { capabilities: { tools: {} } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: toolNames.map((t) => ({ name: t, inputSchema: { type: "object", properties: {} } })),
  }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const name = req.params.name;
    const a = req.params.arguments || {};
    switch (name) {
      case "echo":
        return { content: [{ type: "text", text: `${serverName}:echo:${a.msg ?? ""}` }] };
      case "boom":
        throw new Error("boom exploded");
      case "wipe_all":
        return { content: [{ type: "text", text: `${serverName}:wipe_all:done` }] };
      case "get_secret":
        return { content: [{ type: "text", text: `${serverName}:get_secret:${a.id ?? ""}` }] };
      case "store":
        return { content: [{ type: "text", text: `${serverName}:store:ok` }] };
      default:
        throw new McpError(ErrorCode.MethodNotFound, `no such tool ${name}`);
    }
  });
  return server;
}

// --- one shared registry; per-cfg behaviours (gov/breaker/profile/capture) come from each Router -----
const registry = new Registry(new Vault("env"));
await registry.mountLocal({ id: "alpha", source: "local", enabled: true, policy: "full" }, makeToolServer("alpha", ["echo", "boom"]));
await registry.mountLocal({ id: "beta", source: "local", enabled: true, policy: "full" }, makeToolServer("beta", ["echo"]));
await registry.mountLocal({ id: "capped", source: "local", enabled: true, policy: "read" }, makeToolServer("capped", ["wipe_all"]));
await registry.mountLocal({ id: "gated", source: "local", enabled: true, policy: "full", approval: { require_for: ["read"] } }, makeToolServer("gated", ["get_secret"]));
await registry.mountLocal(
  { id: "inj", source: "local", enabled: true, policy: "full", tools: { store: { inject_args: { account: "${env:SB_TEST_SECRET}" } } } },
  makeToolServer("inj", ["store"]),
);

const cfg = (exposure, settings = {}) => ({
  gateway: { default_policy: "full", tool_exposure: exposure },
  vault: { backend: "env" },
  servers: [],
  settings,
});
// Each Router gets its OWN Governor + Breaker (per-cfg isolation), so stateful levers can't bleed.
const router = new Router(registry, cfg("namespaced"), (ref) => ref);
const flatRouter = new Router(registry, cfg("flat"), (ref) => ref);
const searchRouter = new Router(registry, cfg("search"), (ref) => ref);
const profRouter = new Router(registry, cfg("namespaced", { active_profile: "p", profiles: { p: { exclude_tools: ["alpha__echo"] } } }), (ref) => ref);
const rateRouter = new Router(registry, cfg("namespaced", { limits: { per_minute: 1 } }), (ref) => ref);
const breakerRouter = new Router(registry, cfg("namespaced", { resilience: { enabled: true, failure_threshold: 1 } }), (ref) => ref);
const captureRouter = new Router(registry, cfg("namespaced", { logs: { capture_io: true } }), (ref) => ref);

const okText = (res) => res?.content?.[0]?.text;
const parseEnv = (res) => {
  try {
    return JSON.parse(res.content[0].text);
  } catch {
    return null;
  }
};

try {
  // --- A. happy-path namespaced forward + audit allow row -----------------------------------------
  const r1 = await router.callTool("alpha__echo", { msg: "hi" });
  assert("namespaced forward alpha__echo returns upstream text, no isError", okText(r1) === "alpha:echo:hi" && !r1.isError, okText(r1));
  let audit = recentAudit(300);
  const allowRow = audit.find((r) => r.server === "alpha" && r.tool === "echo" && r.decision === "allow");
  assert("audit allow row for alpha/echo at write scope", !!allowRow && allowRow.scope === "write" && allowRow.decision === "allow", allowRow ? `scope=${allowRow.scope}` : "missing");
  assert("forwarded call wrote audit.log under throwaway SWITCHBOARD_HOME (HOME_DIR override took effect)", existsSync(join(HOME, "audit.log")));

  // --- B. flat-mode collision: first-wins by mount order ------------------------------------------
  const rf = await flatRouter.callTool("echo", { msg: "hi" });
  assert("flat-mode bare 'echo' resolves first-wins to alpha (mount order, not beta)", okText(rf) === "alpha:echo:hi", okText(rf));

  // --- C. search-mode meta-tools -----------------------------------------------------------------
  const find = parseEnv(await searchRouter.callTool("find_tools", { query: "echo" }));
  assert("search find_tools returns a matches array", Array.isArray(find?.matches), JSON.stringify(find)?.slice(0, 80));
  assert("search find_tools surfaces an echo tool", (find?.matches ?? []).some((m) => /echo/.test(m.name)));

  const ct = await searchRouter.callTool("call_tool", { name: "alpha__echo", arguments: { msg: "via-meta" } });
  assert("search call_tool routes through the governed forward", okText(ct) === "alpha:echo:via-meta", okText(ct));

  const bc = parseEnv(
    await searchRouter.callTool("batch_call", {
      calls: [
        { name: "alpha__echo", arguments: { msg: "a" } },
        { name: "beta__echo", arguments: { msg: "b" } },
        { name: "", arguments: {} },
      ],
    }),
  );
  assert("search batch_call returns one result per call", Array.isArray(bc?.results) && bc.results.length === 3, `len=${bc?.results?.length}`);
  assert("batch result 0 = alpha echo", bc?.results?.[0]?.content?.[0]?.text === "alpha:echo:a");
  assert("batch result 1 = beta echo (both run)", bc?.results?.[1]?.content?.[0]?.text === "beta:echo:b");
  assert("batch entry missing name fails IN PLACE (isError) without aborting the batch", bc?.results?.[2]?.isError === true);

  // meta-tool input validation → structured SB_BAD_REQUEST
  const fEmpty = parseEnv(await searchRouter.callTool("find_tools", { query: "  " }));
  assert("find_tools empty query → SB_BAD_REQUEST + hint + message", fEmpty?.code === SB_ERR.BAD_REQUEST && fEmpty.hint === SB_HINTS[SB_ERR.BAD_REQUEST] && fEmpty.error.includes("non-empty 'query'"));
  const cNoName = parseEnv(await searchRouter.callTool("call_tool", {}));
  assert("call_tool no name → SB_BAD_REQUEST", cNoName?.code === SB_ERR.BAD_REQUEST && cNoName.error.includes("requires a 'name'"));
  const bNoArr = parseEnv(await searchRouter.callTool("batch_call", {}));
  assert("batch_call no calls array → SB_BAD_REQUEST", bNoArr?.code === SB_ERR.BAD_REQUEST && bNoArr.error.includes("requires a 'calls' array"));
  const bEmpty = parseEnv(await searchRouter.callTool("batch_call", { calls: [] }));
  assert("batch_call empty array → SB_BAD_REQUEST", bEmpty?.code === SB_ERR.BAD_REQUEST && bEmpty.error.includes("array is empty"));
  const bMax = parseEnv(await searchRouter.callTool("batch_call", { calls: Array.from({ length: 21 }, () => ({ name: "alpha__echo", arguments: {} })) }));
  assert("batch_call >20 → SB_BAD_REQUEST (MAX_BATCH_CALLS)", bMax?.code === SB_ERR.BAD_REQUEST && bMax.error.includes("at most 20 calls"));

  // --- D. UNKNOWN_TOOL (no `__` separator in namespaced mode) -------------------------------------
  const unkRaw = await router.callTool("nope", {});
  const unk = parseEnv(unkRaw);
  assert("governed denial result carries isError:true", unkRaw.isError === true);
  assert("unknown tool (no `__`) → SB_UNKNOWN_TOOL + hint + message", unk?.code === SB_ERR.UNKNOWN_TOOL && unk.hint === SB_HINTS[SB_ERR.UNKNOWN_TOOL] && unk.error.includes("unknown tool 'nope'"));
  assert("error envelope carries {error, code, hint} as strings", unk && typeof unk.error === "string" && typeof unk.code === "string" && typeof unk.hint === "string");

  // --- E. POLICY_DENY via active-profile exclusion (defense in depth) -----------------------------
  const pd = parseEnv(await profRouter.callTool("alpha__echo", {}));
  assert("profile-excluded tool → SB_POLICY_DENY (not available in active profile)", pd?.code === SB_ERR.POLICY_DENY && pd.error.includes("is not available in the active profile"));

  // --- F. POLICY_DENY via scope over-ceiling ------------------------------------------------------
  const sd = parseEnv(await router.callTool("capped__wipe_all", {}));
  assert("over-ceiling scope → SB_POLICY_DENY (needs 'full' but capped at 'read')", sd?.code === SB_ERR.POLICY_DENY && sd.error.includes("needs 'full'") && sd.error.includes("capped at 'read'"));

  // --- G. RATE_LIMITED (per_minute:1, dedicated Router so the bucket is isolated) ------------------
  await rateRouter.callTool("alpha__echo", { msg: "1" }); // consumes the single token
  const rl = parseEnv(await rateRouter.callTool("alpha__echo", { msg: "2" }));
  assert("2nd call over per_minute:1 → SB_RATE_LIMITED + hint", rl?.code === SB_ERR.RATE_LIMITED && rl.hint === SB_HINTS[SB_ERR.RATE_LIMITED] && rl.error.includes("rate limited"));

  // --- H. UPSTREAM_UNAVAILABLE (breaker opens at threshold 1) --------------------------------------
  await breakerRouter.callTool("alpha__boom", {}); // throws upstream → records failure → opens
  const open = parseEnv(await breakerRouter.callTool("alpha__echo", {}));
  assert("circuit open after threshold → SB_UPSTREAM_UNAVAILABLE + hint", open?.code === SB_ERR.UPSTREAM_UNAVAILABLE && open.hint === SB_HINTS[SB_ERR.UPSTREAM_UNAVAILABLE] && open.error.includes("circuit open"));

  // --- I. APPROVAL_PENDING (gated read: no in-band prompt, nothing executes until the owner approves) ----
  // Adapted for design 3.3: this check used to assert SB_APPROVAL_DENIED from the TTY gate failing closed when no
  // terminal was attached. The TTY gate is gone from the call path; a gated call now leaves a pending approval and
  // returns SB_APPROVAL_PENDING with a hint, an id and the owner instruction. Still fail closed: it did not run.
  const ap = parseEnv(await router.callTool("gated__get_secret", {}));
  assert("approval-gated read → SB_APPROVAL_PENDING (fail-closed, nothing executed) + hint + id + instruction", ap?.code === SB_ERR.APPROVAL_PENDING && ap.hint === SB_HINTS[SB_ERR.APPROVAL_PENDING] && ap.error.includes("approval required") && /^ap_[A-Z2-9]{8}$/.test(ap.approval_id ?? "") && /switchboard approvals approve ap_/.test(ap.instruction ?? ""));

  // --- J. UPSTREAM_ERROR (upstream throw, resilience OFF so the breaker never engages) -------------
  const ue = parseEnv(await router.callTool("alpha__boom", {}));
  assert("upstream throw (resilience off) → SB_UPSTREAM_ERROR (failed calling 'boom')", ue?.code === SB_ERR.UPSTREAM_ERROR && ue.hint === SB_HINTS[SB_ERR.UPSTREAM_ERROR] && ue.error.includes("failed calling 'boom'") && ue.error.includes("boom exploded"));

  // --- K. injected-secret-key redaction in the captured audit row ---------------------------------
  const st = await captureRouter.callTool("inj__store", { data: "x" });
  assert("inj__store forwards successfully under capture_io", okText(st) === "inj:store:ok", okText(st));
  audit = recentAudit(400);
  const storeRow = audit.find((r) => r.server === "inj" && r.tool === "store" && r.decision === "allow");
  assert("capture allow row exists for inj/store", !!storeRow);
  assert("injected secret key 'account' redacted in captured request (exact-name redaction)", storeRow?.request?.account === "[redacted]", JSON.stringify(storeRow?.request));
  assert("non-secret arg 'data' captured verbatim", storeRow?.request?.data === "x");
} finally {
  try {
    await registry.unmountAll();
  } catch {
    /* best effort */
  }
  await sleep(200); // Windows UV_HANDLE_CLOSING guard
}

const failed = checks.filter((c) => !c.ok);
if (failed.length) console.log("\nFAILED:", failed.map((c) => c.name).join(" | "));
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
process.exitCode = failed.length === 0 ? 0 : 1;
