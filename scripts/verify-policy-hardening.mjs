// Deterministic oracle for design vNext sections 3.5 (classifier), 3.6 (child environment), 3.8 (kill
// switch) and 3.10 (resources and prompts through policy). It drives the REAL compiled modules, a REAL
// stdio upstream process and REAL in-memory MCP servers, and computes every verdict itself. ZERO network
// beyond loopback, ZERO model. Build first (this imports from dist/).
//
// It proves:
//   classifier (3.5)        a table of tool names with expected scopes (browser_run_code, fetch_and_execute,
//                           query_execute, get_or_create_user, count_and_send_email, search_and_replace and
//                           the rest), the tokenizer, and generated name families: no name that has a write
//                           or exec token is ever read, a destructive token is always full. A negative
//                           control replays the 0.1.0 prefix regex over the same table and must misread some.
//   annotations (3.5)       destructiveHint:true raises to full; readOnlyHint never lowers; false and garbage
//                           never change anything; a per-tool policy override still wins. Proven on evaluate()
//                           AND through the real Router, where the upstream is never called on a deny.
//   child environment (3.6) a real stdio fixture reports its own environment: planted FAKE_SECRET_TOKEN,
//                           FOO_API_KEY and friends are absent, PATH and SYSTEMROOT (HOME off Windows) are
//                           present, nothing outside the allowlist crosses, env, credentials and
//                           env_passthrough arrive, a secret-looking passthrough needs env_passthrough_secrets.
//                           The config schema refuses the same mistakes before anything spawns.
//   kill switch (3.8)       the KILL file and gateway.kill_switch refuse tools/call (including the search
//                           meta-tools), resources/read and prompts/get with SB_KILL_SWITCH, per call, with
//                           no restart, from another process (the CLI), audited; listing stays allowed.
//                           /healthz, /api/health and /api/state report it.
//   resources, prompts (3.10) read scope through evaluate, the active profile, the kill switch and the
//                           governor: an unlisted URI is not broadcast (spies on every upstream), a template
//                           resolves to its declaring server only, and a disabled, hidden, capped, tool
//                           disabled or approval-gated read is refused, audited and never reaches the upstream.
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import net from "node:net";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURE = join(root, "scripts", "fixtures", "env-upstream.mjs");

// Never touch the operator's real state: every home, profile and app-data dir is a throwaway.
const tmp = mkdtempSync(join(tmpdir(), "sb-hardening-"));
const USER_HOME = join(tmp, "user");
const SB_HOME = join(USER_HOME, ".switchboard");
const APPDATA = join(tmp, "appdata");
const LOCALAPPDATA = join(tmp, "local");
for (const d of [USER_HOME, SB_HOME, APPDATA, LOCALAPPDATA]) mkdirSync(d, { recursive: true });
process.env.SWITCHBOARD_HOME = SB_HOME;
process.env.HOME = USER_HOME;
process.env.USERPROFILE = USER_HOME;
process.env.APPDATA = APPDATA;
process.env.LOCALAPPDATA = LOCALAPPDATA;
delete process.env.SWITCHBOARD_AUTO_APPROVE;
delete process.env.SWITCHBOARD_PROFILE;
// Approval must fail closed and never block on a human.
process.stdin.isTTY = false;
process.stdout.isTTY = false;

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ListResourceTemplatesRequestSchema,
  ReadResourceRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
  McpError,
  ErrorCode,
} from "@modelcontextprotocol/sdk/types.js";

const { inferScope, evaluate, resolveToolScope, tokenizeToolName } = await import("../dist/policy.js");
const { Registry } = await import("../dist/registry.js");
const { Router } = await import("../dist/router.js");
const { Vault } = await import("../dist/vault.js");
const { Gateway } = await import("../dist/gateway.js");
const { recentAudit } = await import("../dist/audit.js");
const { SB_ERR, SB_HINTS } = await import("../dist/errors.js");
const { loadConfig } = await import("../dist/config.js");
const { startDashboard } = await import("../dist/dashboard.js");
const { ownerSession } = await import("./lib/owner.mjs");
const ks = await import("../dist/killswitch.js");
const ce = await import("../dist/childenv.js");

const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  // Detail is for diagnosing a failure only. Passing lines stay clean so the runner's failure scan never
  // trips on text echoed from a CLI subprocess (it legitimately prints error lines for the negative cases).
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${!cond && detail ? ` | ${detail}` : ""}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const withTimeout = (p, ms, label) =>
  Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error(`timeout after ${ms}ms: ${label}`)), ms))]);
const freePort = () =>
  new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });

/** Parse a coded tool error: { error, code, hint } or null. */
const coded = (res) => {
  try {
    return res?.isError ? JSON.parse(res.content?.[0]?.text) : null;
  } catch {
    return null;
  }
};
/** Run fn(); return the thrown McpError (or null when it did not throw / threw something else). */
async function mcpError(fn) {
  try {
    await fn();
    return null;
  } catch (err) {
    return err instanceof McpError ? err : null;
  }
}
const refusedWith = (err, code) => !!err && err.code === ErrorCode.InvalidRequest && err.data?.code === code && String(err.message).includes(code);

const rows = (pred) => recentAudit(2000).filter(pred);

// =====================================================================================================
// 1. CLASSIFIER (design 3.5)
// =====================================================================================================
const TABLE = [
  // read: first token is a read verb and no token is a write or exec verb
  ["get_sum", "read"], ["list_voices", "read"], ["search_voices", "read"], ["getUserProfile", "read"], ["listFiles", "read"],
  ["get_file", "read"], ["read_file", "read"], ["fetch_url", "read"], ["find_user", "read"], ["query_database", "read"],
  ["describe_table", "read"], ["show_status", "read"], ["view_logs", "read"], ["count_items", "read"], ["head_object", "read"],
  ["lookup_user", "read"], ["browse_catalog", "read"], ["inspect_element", "read"], ["get-user-info", "read"], ["list.files", "read"],
  ["search/people", "read"], ["GetUserProfile", "read"], ["getHTTPResponse", "read"], ["list_dropbox_files", "read"],
  ["get_dropdown_options", "read"], ["get_settings", "read"], ["list_orders", "read"], ["get_posts", "read"], ["list_deployments", "read"],
  // write: not a read, or a read verb followed by a write or exec verb
  ["browser_click", "write"], ["browser_evaluate", "write"], ["browser_run_code", "write"], ["browser_file_upload", "write"],
  ["browser_navigate", "write"], ["fetch_and_execute", "write"], ["query_execute", "write"], ["get_or_create_user", "write"],
  ["count_and_send_email", "write"], ["search_and_replace", "write"], ["text_to_speech", "write"], ["upload_video", "write"],
  ["publish_post", "write"], ["create_issue", "write"], ["update_record", "write"], ["send_message", "write"], ["set_config", "write"],
  ["run_query", "write"], ["execute_sql", "write"], ["eval_js", "write"], ["push_commit", "write"], ["generate_image", "write"],
  ["clone_voice", "write"], ["design_voice", "write"], ["convert_audio", "write"], ["schedule_post", "write"],
  ["install_package", "write"], ["stop_server", "write"], ["kill_process", "write"], ["swipe_left", "write"],
  // write by design: a prefix match is no longer enough (0.1.0 called every one of these a read)
  ["readme", "write"], ["listen_events", "write"], ["header_info", "write"], ["getuser", "write"],
  // write by design, conservative: a noun that is also a write verb ("order", "post") keeps a read verb out of read
  ["get_order", "write"],
  // full: any destructive token, wherever it sits
  ["delete_video", "full"], ["remove_user", "full"], ["drop_table", "full"], ["purge_cache", "full"], ["wipe_disk", "full"],
  ["revoke_token", "full"], ["terminate_instance", "full"], ["deactivate_account", "full"], ["grant_access", "full"], ["sudo_run", "full"],
  ["list_admin_users", "full"], ["deleteFile", "full"], ["deletefile", "full"], ["removeAll", "full"], ["get_or_delete_user", "full"],
  ["read_and_delete", "full"], ["delete_and_send", "full"], ["bulk-deletion", "full"],
];
{
  const bad = TABLE.filter(([n, want]) => inferScope(n) !== want).map(([n, want]) => `${n}: want ${want} got ${inferScope(n)}`);
  assert(`classifier table: ${TABLE.length} tool names land on their expected scope`, TABLE.length >= 40 && bad.length === 0, bad.join(" | "));
  for (const must of [
    ["browser_click", "write"], ["browser_evaluate", "write"], ["browser_run_code", "write"], ["browser_file_upload", "write"],
    ["browser_navigate", "write"], ["fetch_and_execute", "write"], ["query_execute", "write"], ["get_or_create_user", "write"],
    ["count_and_send_email", "write"], ["search_and_replace", "write"], ["get_sum", "read"], ["list_voices", "read"],
    ["search_voices", "read"], ["text_to_speech", "write"], ["upload_video", "write"], ["publish_post", "write"],
    ["delete_video", "full"], ["getUserProfile", "read"], ["listFiles", "read"],
  ]) {
    assert(`required name ${must[0]} is ${must[1]}`, inferScope(must[0]) === must[1], `got ${inferScope(must[0])}`);
  }

  // The table has teeth: the 0.1.0 rule (bare prefix regex, then a substring destructive regex) misreads some of it.
  const LEGACY_READ = /^(get|list|read|search|fetch|find|query|describe|show|view|count|head|lookup|browse|inspect)[_A-Z]?/i;
  const LEGACY_FULL = /(delete|destroy|drop|remove|purge|wipe|revoke|terminate|deactivate|admin|grant|sudo)/i;
  const legacy = (n) => (LEGACY_FULL.test(n) ? "full" : LEGACY_READ.test(n) ? "read" : "write");
  const misread = TABLE.filter(([n, want]) => want !== "read" && legacy(n) === "read").map(([n]) => n);
  assert(`negative control: the 0.1.0 prefix rule calls ${misread.length} of these write/full names a read (need at least 8)`, misread.length >= 8, misread.join(", "));
  assert("negative control: 0.1.0 also misread browser-style exec names the new rule catches", misread.includes("fetch_and_execute") && misread.includes("query_execute") && misread.includes("count_and_send_email"));

  // Tokenizer
  const tk = (n) => tokenizeToolName(n).join(",");
  assert("tokenizer splits snake, kebab, dot, slash", tk("a_b-c.d/e") === "a,b,c,d,e", tk("a_b-c.d/e"));
  assert("tokenizer splits camelCase and PascalCase", tk("getUserProfile") === "get,user,profile" && tk("GetUserProfile") === "get,user,profile");
  assert("tokenizer keeps an acronym run together", tk("getHTTPResponse") === "get,http,response", tk("getHTTPResponse"));
  assert("tokenizer ignores separators at the edges and doubled (server__tool)", tk("__x__y__") === "x,y");
  assert("empty and separator-only names classify as write", inferScope("") === "write" && inferScope("___") === "write");

  // Generated families, written from the design's own verb lists.
  const READ = ["get", "list", "read", "search", "fetch", "find", "query", "describe", "show", "view", "count", "head", "lookup", "browse", "inspect"];
  const WRITE_EXEC = [
    "run", "exec", "execute", "eval", "evaluate", "click", "type", "press", "upload", "send", "post", "publish", "create", "update", "set",
    "write", "put", "patch", "mutate", "apply", "deploy", "push", "replace", "generate", "clone", "design", "remix", "convert", "transfer",
    "pay", "buy", "order", "submit", "schedule", "invite", "share", "import", "install", "start", "stop", "restart", "kill", "and", "then",
  ];
  const DESTRUCTIVE = ["delete", "destroy", "drop", "remove", "purge", "wipe", "revoke", "terminate", "deactivate", "admin", "grant", "sudo"];
  const shapes = (a, b) => [`${a}_${b}`, `${a}-${b}-thing`, `${a}Thing${b[0].toUpperCase()}${b.slice(1)}`, `${a}_x_${b}_y`];
  let n1 = 0, v1 = [];
  for (const r of READ) for (const w of WRITE_EXEC) for (const name of [...shapes(r, w), ...shapes(w, r)]) { n1++; if (inferScope(name) === "read") v1.push(name); }
  assert(`generated: no name with a write or exec token is ever read (${n1} names)`, v1.length === 0, v1.slice(0, 6).join(", "));
  let n2 = 0, v2 = [];
  for (const r of [...READ, ...WRITE_EXEC]) for (const d of DESTRUCTIVE) for (const name of shapes(r, d)) { n2++; if (inferScope(name) !== "full") v2.push(name); }
  assert(`generated: a destructive token always makes the name full (${n2} names)`, v2.length === 0, v2.slice(0, 6).join(", "));
  let n3 = 0, v3 = [];
  for (const r of READ) for (const noun of ["user", "file", "voices", "profile", "items", "status"]) for (const name of [`${r}_${noun}`, `${r}${noun[0].toUpperCase()}${noun.slice(1)}`]) { n3++; if (inferScope(name) !== "read") v3.push(name); }
  assert(`generated: read verb plus a plain noun is read (${n3} names)`, v3.length === 0, v3.slice(0, 6).join(", "));
}

// =====================================================================================================
// 2. ANNOTATIONS (design 3.5): tighten only
// =====================================================================================================
const baseCfg = {
  gateway: { transport: ["stdio"], http: { host: "127.0.0.1", port: 1, require_auth: "auto" }, tool_exposure: "namespaced", default_policy: "read" },
  vault: { backend: "env" },
  servers: [],
  settings: {},
};
const srv = (over = {}) => ({ id: "s", source: "npx", enabled: true, policy: "full", ...over });
{
  const sc = (name, ann, over, hint) => evaluate(srv(over), name, baseCfg, hint, undefined, ann).scope;
  assert("destructiveHint:true raises a read name to full", sc("get_item", { destructiveHint: true }) === "full");
  assert("destructiveHint:true raises a write name to full", sc("create_item", { destructiveHint: true }) === "full");
  assert("destructiveHint:true on an already-full name stays full", sc("delete_item", { destructiveHint: true }) === "full");
  assert("readOnlyHint:true does not lower a write name", sc("create_item", { readOnlyHint: true }) === "write");
  assert("readOnlyHint:true does not lower a full name", sc("delete_item", { readOnlyHint: true }) === "full");
  assert("readOnlyHint:true does not lower a name with a write token", sc("fetch_and_execute", { readOnlyHint: true }) === "write");
  assert("readOnlyHint:true leaves a read name read", sc("get_item", { readOnlyHint: true }) === "read");
  assert("contradictory hints (readOnly + destructive) still tighten to full", sc("get_item", { readOnlyHint: true, destructiveHint: true }) === "full");
  assert("destructiveHint:false does not lower anything", sc("delete_item", { destructiveHint: false }) === "full" && sc("create_item", { destructiveHint: false }) === "write");
  assert("destructiveHint:false and idempotent/openWorld hints do not change a read", sc("get_item", { destructiveHint: false, idempotentHint: true, openWorldHint: true }) === "read");
  for (const junk of [undefined, null, {}, "x", 7, [], { destructiveHint: "true" }, { destructiveHint: 1 }, { destructiveHint: "yes" }]) {
    assert(`annotations ${JSON.stringify(junk) ?? "undefined"} change nothing`, sc("get_item", junk) === "read");
  }
  assert("a scopeHint (app2mcp verb) is tightened by destructiveHint too", sc("findPets", { destructiveHint: true }, {}, "write") === "full");
  assert("a scopeHint is not lowered by readOnlyHint", sc("findPets", { readOnlyHint: true }, {}, "write") === "write");
  assert("a per-tool policy override wins over destructiveHint (operator authority)", sc("get_item", { destructiveHint: true }, { tools: { get_item: { policy: "read" } } }) === "read");
  assert("a per-tool policy override wins in the other direction too", sc("delete_item", { readOnlyHint: true }, { tools: { delete_item: { policy: "write" } } }) === "write");
  assert("inferScope(name, annotations) and resolveToolScope agree", inferScope("get_item", { destructiveHint: true }) === "full" && resolveToolScope("get_item", undefined, undefined, { destructiveHint: true }) === "full");

  const capped = evaluate(srv({ policy: "write" }), "get_item", baseCfg, undefined, undefined, { destructiveHint: true });
  assert("destructiveHint on a read name under a write ceiling is denied with scope full", capped.decision === "deny" && capped.scope === "full", capped.reason);
  const noRiskGate = { ...baseCfg, gateway: { ...baseCfg.gateway, approval: { require_for_risk: [] } } };
  const allowed = evaluate(srv({ policy: "full" }), "get_item", noRiskGate, undefined, undefined, { destructiveHint: true });
  assert("destructiveHint under a full ceiling is allowed at scope full", allowed.decision === "allow" && allowed.scope === "full");
  const byDefault = evaluate(srv({ policy: "full" }), "get_item", baseCfg, undefined, undefined, { destructiveHint: true });
  assert("under the default approval rule that same call needs approval (scope full is high risk), it is not denied", byDefault.decision === "approval_required" && byDefault.scope === "full" && byDefault.risk === "high");
  const gated = evaluate(srv({ policy: "full", approval: { require_for: ["full"] } }), "get_item", baseCfg, undefined, undefined, { destructiveHint: true });
  assert("destructiveHint raises into the full approval gate", gated.decision === "approval_required" && gated.scope === "full");
  const profiled = evaluate(srv({ policy: "full" }), "get_item", baseCfg, undefined, "write", { destructiveHint: true });
  assert("destructiveHint is capped by a write profile ceiling", profiled.decision === "deny" && profiled.scope === "full");
}

// ---- helper: a real in-memory upstream MCP server with spies on every surface ----------------------
function makeUpstream({ tools = [], resources = [], templates = [], reads = {}, prompts = [], caps }) {
  const spy = { tools: [], reads: [], prompts: [] };
  const hasRes = resources.length > 0 || templates.length > 0 || Object.keys(reads).length > 0;
  const server = new Server(
    { name: "upstream", version: "0.0.0" },
    { capabilities: caps ?? { tools: {}, ...(hasRes ? { resources: {} } : {}), ...(prompts.length ? { prompts: {} } : {}) } },
  );
  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: tools.map((t) => ({ name: t.name, description: t.name, inputSchema: { type: "object", properties: {} }, ...(t.annotations ? { annotations: t.annotations } : {}) })),
  }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    spy.tools.push(req.params.name);
    return { content: [{ type: "text", text: `ran:${req.params.name}` }] };
  });
  if (hasRes) {
    server.setRequestHandler(ListResourcesRequestSchema, async () => ({ resources }));
    server.setRequestHandler(ListResourceTemplatesRequestSchema, async () => ({ resourceTemplates: templates }));
    server.setRequestHandler(ReadResourceRequestSchema, async (req) => {
      spy.reads.push(req.params.uri);
      const text = reads[req.params.uri];
      if (text === undefined) throw new McpError(ErrorCode.InvalidParams, `no such resource ${req.params.uri}`);
      return { contents: [{ uri: req.params.uri, mimeType: "text/plain", text }] };
    });
  }
  if (prompts.length) {
    server.setRequestHandler(ListPromptsRequestSchema, async () => ({ prompts: prompts.map((p) => ({ name: p.name, description: p.name })) }));
    server.setRequestHandler(GetPromptRequestSchema, async (req) => {
      spy.prompts.push(req.params.name);
      const p = prompts.find((x) => x.name === req.params.name);
      if (!p) throw new McpError(ErrorCode.InvalidParams, `no such prompt ${req.params.name}`);
      return { messages: [{ role: "user", content: { type: "text", text: p.text } }] };
    });
  }
  return { server, spy };
}
// Adapted for design 3.4 (risk): a full-scope call is high risk and needs an out-of-band approval by default. This
// oracle measures scope classification, annotations and the read surfaces, not approvals, so its configs say that
// no risk needs one (`require_for_risk: []`). The scope-based gates it tests (`approval.require_for`) are untouched,
// and the default rule is asserted where the annotation block needs it (see "under the default approval rule").
const mkCfg = (over = {}) => ({
  gateway: { transport: ["stdio"], http: { host: "127.0.0.1", port: 1, require_auth: "auto" }, tool_exposure: "namespaced", default_policy: "full", approval: { require_for_risk: [] } },
  vault: { backend: "env" },
  servers: [],
  settings: {},
  ...over,
});
const text = (r) => r?.contents?.[0]?.text;
const pmsg = (r) => r?.messages?.[0]?.content?.text;

// =====================================================================================================
// 3. ANNOTATIONS through the real Router
// =====================================================================================================
{
  const mk = (id, policy) => {
    const up = makeUpstream({
      tools: [
        { name: "get_report", annotations: { destructiveHint: true } },
        { name: "get_status", annotations: { readOnlyHint: true } },
        { name: "delete_log", annotations: { readOnlyHint: true } },
        { name: "get_plain" },
      ],
    });
    return { up, config: { id, source: "council", enabled: true, policy } };
  };
  const strict = mk("annw", "write");
  const loose = mk("annf", "full");
  const registry = new Registry(new Vault("env"));
  await registry.mountLocal(strict.config, strict.up.server);
  await registry.mountLocal(loose.config, loose.up.server);
  const router = new Router(registry, mkCfg({ servers: [strict.config, loose.config] }), (r) => r);
  try {
    const r1 = await router.callTool("annw__get_report", {});
    assert("read-named tool annotated destructiveHint is denied under a write server (SB_POLICY_DENY)", coded(r1)?.code === SB_ERR.POLICY_DENY, r1.content?.[0]?.text);
    assert("...and the upstream was never called", !strict.up.spy.tools.includes("get_report"));
    const row = rows((e) => e.server === "annw" && e.tool === "get_report")[0];
    assert("...the audit row records scope full", row?.decision === "deny" && row?.scope === "full", JSON.stringify(row));
    const r2 = await router.callTool("annw__get_status", {});
    assert("readOnlyHint tool named get_* is allowed under a write server", !r2.isError && strict.up.spy.tools.includes("get_status"));
    const r3 = await router.callTool("annw__delete_log", {});
    assert("a delete_* tool with readOnlyHint:true is still denied (hint never lowers)", coded(r3)?.code === SB_ERR.POLICY_DENY && !strict.up.spy.tools.includes("delete_log"));
    const r4 = await router.callTool("annw__get_plain", {});
    assert("an unannotated get_* tool is unaffected", !r4.isError && strict.up.spy.tools.includes("get_plain"));
    const r5 = await router.callTool("annf__get_report", {});
    assert("under a full server the destructiveHint tool is allowed", !r5.isError && loose.up.spy.tools.includes("get_report"));
    const row5 = rows((e) => e.server === "annf" && e.tool === "get_report")[0];
    assert("...and is audited at scope full", row5?.decision === "allow" && row5?.scope === "full", JSON.stringify(row5));
    strict.config.tools = { get_report: { policy: "read" } };
    const r6 = await router.callTool("annw__get_report", {});
    assert("a per-tool policy override beats the upstream annotation through the Router", !r6.isError && strict.up.spy.tools.includes("get_report"));
    delete strict.config.tools;
  } finally {
    await registry.unmountAll();
  }
}

// =====================================================================================================
// 4. CHILD ENVIRONMENT (design 3.6)
// =====================================================================================================
const PLANTED = {
  FAKE_SECRET_TOKEN: "fake-secret-1",
  FOO_API_KEY: "fake-key-2",
  ANTHROPIC_API_KEY: "fake-key-3",
  OPENAI_API_KEY: "fake-key-4",
  GITHUB_TOKEN: "fake-token-5",
  AWS_SECRET_ACCESS_KEY: "fake-secret-6",
  NODE_OPTIONS: "--no-warnings",
  SB_TEST_LEAK: "leaked-if-seen",
  SB_TEST_PASSTHRU: "passthru-value",
  SB_TEST_CRED_SRC: "cred-value",
};
const savedEnv = Object.fromEntries(Object.keys(PLANTED).map((k) => [k, process.env[k]]));
Object.assign(process.env, PLANTED);
try {
  const WINDOWS_DESIGN = [
    "SYSTEMROOT", "WINDIR", "COMSPEC", "PATH", "PATHEXT", "TEMP", "TMP", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA",
    "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "NPM_CONFIG_CACHE", "NODE_EXTRA_CA_CERTS",
  ];
  assert("the Windows allowlist is exactly the one in design 3.6", JSON.stringify(ce.WINDOWS_ENV_ALLOWLIST) === JSON.stringify(WINDOWS_DESIGN));

  // Pure function first: nothing planted can appear in the base environment.
  const base = ce.baseChildEnv();
  const baseNames = Object.keys(base).map((n) => n.toUpperCase());
  assert("baseChildEnv carries PATH", baseNames.includes("PATH"));
  assert("baseChildEnv carries none of the planted secrets or odd names", !baseNames.some((n) => n in PLANTED || n.startsWith("SB_TEST_")));
  assert("baseChildEnv reads the CURRENT environment (USERPROFILE/HOME follow the sandbox)", process.platform === "win32" ? base.USERPROFILE === USER_HOME : base.HOME === USER_HOME, `${base.USERPROFILE ?? base.HOME}`);

  // isSecretEnvName
  for (const n of ["FAKE_SECRET_TOKEN", "FOO_API_KEY", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "DB_PASSWORD", "fooApiKey", "SSH_AUTH_SOCK", "MY_PASSPHRASE", "STRIPE_KEY"]) {
    assert(`isSecretEnvName flags ${n}`, ce.isSecretEnvName(n));
  }
  for (const n of ["PATH", "SB_TEST_PASSTHRU", "KEYBOARD_LAYOUT", "LANG", "HOME", "NODE_OPTIONS", "TMPDIR", "MONKEY_ID"]) {
    assert(`isSecretEnvName leaves ${n} alone`, !ce.isSecretEnvName(n));
  }
  assert("passthroughProblem: a secret-looking name needs the acknowledgement", /env_passthrough_secrets/.test(ce.passthroughProblem(["FOO_API_KEY"], []) ?? ""));
  assert("passthroughProblem: acknowledged in both lists is fine", ce.passthroughProblem(["FOO_API_KEY"], ["FOO_API_KEY"]) === undefined);
  assert("passthroughProblem: an acknowledgement without a passthrough entry is a typo", /must also be listed in env_passthrough/.test(ce.passthroughProblem([], ["FOO_API_KEY"]) ?? ""));

  async function probeEnv(id, extra = {}) {
    const reg = new Registry(new Vault("env"));
    try {
      const m = await withTimeout(reg.mount({ id, source: "binary", command: process.execPath, args: [FIXTURE], enabled: true, policy: "read", ...extra }), 25_000, `mount ${id}`);
      const res = await withTimeout(m.client.callTool({ name: "get_env", arguments: {} }), 15_000, `get_env ${id}`);
      const parsed = JSON.parse(res.content[0].text);
      return { ...parsed, upper: new Set(parsed.names.map((n) => n.toUpperCase())) };
    } finally {
      await reg.unmountAll();
    }
  }

  // --- the default: nothing planted crosses, the essentials do --------------------------------------
  const a = await probeEnv("env-default");
  assert("child: planted FAKE_SECRET_TOKEN is absent", !a.upper.has("FAKE_SECRET_TOKEN"));
  assert("child: planted FOO_API_KEY is absent", !a.upper.has("FOO_API_KEY"));
  assert("child: planted ANTHROPIC_API_KEY, OPENAI_API_KEY, GITHUB_TOKEN, AWS_SECRET_ACCESS_KEY are absent", ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY"].every((n) => !a.upper.has(n)));
  assert("child: a non-secret planted name (SB_TEST_LEAK) is absent too: this is an allowlist, not a name filter", !a.upper.has("SB_TEST_LEAK") && !a.upper.has("SB_TEST_PASSTHRU"));
  assert("child: NODE_OPTIONS from the gateway does not cross", !a.upper.has("NODE_OPTIONS"));
  assert("child: PATH is present", a.upper.has("PATH"));
  assert(process.platform === "win32" ? "child: SYSTEMROOT is present" : "child: HOME is present", process.platform === "win32" ? a.upper.has("SYSTEMROOT") : a.upper.has("HOME"));
  if (process.platform === "win32") {
    assert("child: COMSPEC, TEMP, USERPROFILE, APPDATA, LOCALAPPDATA are present", ["COMSPEC", "TEMP", "USERPROFILE", "APPDATA", "LOCALAPPDATA"].every((n) => a.upper.has(n)), [...a.upper].join(","));
  }
  const allowed = new Set(
    [...ce.WINDOWS_ENV_ALLOWLIST, ...ce.POSIX_ENV_ALLOWLIST, "HOME", "LOGNAME", "PATH", "SHELL", "TERM", "USER", "SYSTEMDRIVE", "USERNAME"].map((n) => n.toUpperCase()),
  );
  // Some variables are added by the OS to every process, whatever the parent passed (on Windows: LOGONSERVER,
  // USERDOMAIN and friends). Measure them with a bare child instead of guessing, so they are not mistaken for leaks.
  const bare = spawnSync(process.execPath, ["-e", "console.log(JSON.stringify(Object.keys(process.env)))"], {
    env: process.platform === "win32" ? { PATH: process.env.PATH, SYSTEMROOT: process.env.SYSTEMROOT } : { PATH: process.env.PATH },
    encoding: "utf8",
  });
  const osAdds = new Set(JSON.parse(bare.stdout || "[]").map((n) => n.toUpperCase()));
  const stray = [...a.upper].filter((n) => !allowed.has(n) && !osAdds.has(n));
  assert("child: closed world, every variable it sees is in the SDK defaults, the platform allowlist or added by the OS itself", stray.length === 0, `unexpected: ${stray.join(", ")}; OS adds: ${[...osAdds].join(",")}`);

  // --- env and credentials still arrive --------------------------------------------------------------
  const b = await probeEnv("env-cfg", { env: { SB_TEST_FROM_CFG: "cfg-literal" }, credentials: { SB_TEST_CRED: "${env:SB_TEST_CRED_SRC}" } });
  assert("child: the server's own env arrives", b.values.SB_TEST_FROM_CFG === "cfg-literal");
  assert("child: a credential resolved from ${env:..} arrives under its own name", b.values.SB_TEST_CRED === "cred-value");
  assert("child: the credential's SOURCE variable is not forwarded as a side effect", !b.upper.has("SB_TEST_CRED_SRC"));

  // --- env_passthrough --------------------------------------------------------------------------------
  const c = await probeEnv("env-pass", { env_passthrough: ["SB_TEST_PASSTHRU", "SB_TEST_NOT_SET_ANYWHERE"] });
  assert("env_passthrough delivers the listed name with its value", c.values.SB_TEST_PASSTHRU === "passthru-value");
  assert("env_passthrough does not open the door to anything else", !c.upper.has("SB_TEST_LEAK") && !c.upper.has("FAKE_SECRET_TOKEN") && !c.upper.has("FOO_API_KEY"));
  assert("a passthrough name the gateway does not have is simply absent (no error)", !c.upper.has("SB_TEST_NOT_SET_ANYWHERE"));
  const cfgOverride = await probeEnv("env-order", { env_passthrough: ["SB_TEST_PASSTHRU"], env: { SB_TEST_PASSTHRU: "explicit-env-wins" } });
  assert("the server's explicit env wins over a passthrough of the same name", cfgOverride.values.SB_TEST_PASSTHRU === "explicit-env-wins");

  // --- a secret-looking passthrough is refused unless acknowledged -----------------------------------
  let refused = "";
  try {
    await probeEnv("env-refuse", { env_passthrough: ["FOO_API_KEY"] });
  } catch (err) {
    refused = String(err.message);
  }
  assert("env_passthrough of FOO_API_KEY alone is refused at mount, naming env_passthrough_secrets", /env_passthrough_secrets/.test(refused) && /FOO_API_KEY/.test(refused), refused);
  let refused2 = "";
  try {
    await probeEnv("env-refuse2", { env_passthrough: ["FAKE_SECRET_TOKEN"], env_passthrough_secrets: ["FOO_API_KEY"] });
  } catch (err) {
    refused2 = String(err.message);
  }
  assert("acknowledging a DIFFERENT name does not unlock FAKE_SECRET_TOKEN", /FAKE_SECRET_TOKEN/.test(refused2), refused2);
  const d = await probeEnv("env-ack", { env_passthrough: ["FOO_API_KEY"], env_passthrough_secrets: ["FOO_API_KEY"] });
  assert("listed in both env_passthrough and env_passthrough_secrets, FOO_API_KEY is delivered", d.upper.has("FOO_API_KEY"));
  assert("...and FAKE_SECRET_TOKEN still is not", !d.upper.has("FAKE_SECRET_TOKEN"));

  // --- the config schema refuses the same mistakes before anything spawns ----------------------------
  const cfgDir = join(tmp, "cfg");
  mkdirSync(cfgDir, { recursive: true });
  let n = 0;
  const tryLoad = (serverYaml) => {
    const p = join(cfgDir, `c${n++}.yaml`);
    writeFileSync(p, `gateway:\n  transport: [stdio]\nservers:\n  - id: x\n    source: binary\n    command: node\n${serverYaml}`);
    try {
      return { cfg: loadConfig(p), err: "" };
    } catch (err) {
      return { cfg: null, err: String(err.message) };
    }
  };
  const l1 = tryLoad("    env_passthrough: [SB_TEST_PASSTHRU]\n");
  assert("config: env_passthrough with a plain name loads and is typed", !!l1.cfg && l1.cfg.servers[0].env_passthrough[0] === "SB_TEST_PASSTHRU", l1.err);
  const l2 = tryLoad("    env_passthrough: [FOO_API_KEY]\n");
  assert("config: a secret-looking env_passthrough without the acknowledgement is invalid", !l2.cfg && /env_passthrough_secrets/.test(l2.err), l2.err);
  const l3 = tryLoad("    env_passthrough: [FOO_API_KEY]\n    env_passthrough_secrets: [FOO_API_KEY]\n");
  assert("config: acknowledged in both lists loads", !!l3.cfg, l3.err);
  const l4 = tryLoad("    env_passthrough_secrets: [FOO_API_KEY]\n");
  assert("config: an acknowledgement with no matching env_passthrough entry is invalid", !l4.cfg && /must also be listed/.test(l4.err), l4.err);
  const l5 = tryLoad("    env_passthrough: ['A=B']\n");
  assert("config: a name containing = is invalid", !l5.cfg, l5.err);
  const l6 = tryLoad("    env_passthrough: [PATH]\n    env_passthrough_secrets: [PATH]\n");
  assert("config: acknowledging a non-secret name is allowed (harmless)", !!l6.cfg, l6.err);
} finally {
  for (const [k, v] of Object.entries(savedEnv)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
}

// =====================================================================================================
// 5. KILL SWITCH (design 3.8)
// =====================================================================================================
const KILL_PATH = join(SB_HOME, "KILL");
{
  const up = makeUpstream({
    tools: [{ name: "get_ping" }],
    resources: [{ uri: "kk://doc/1", name: "doc" }],
    reads: { "kk://doc/1": "KK-DOC" },
    prompts: [{ name: "hello", text: "KK-HELLO" }],
  });
  const config = { id: "kk", source: "council", enabled: true, policy: "full" };
  const registry = new Registry(new Vault("env"));
  await registry.mountLocal(config, up.server);
  const cfgK = mkCfg({ servers: [config] });
  const router = new Router(registry, cfgK, (r) => r);
  const searchCfg = mkCfg({ servers: [config], gateway: { ...mkCfg().gateway, tool_exposure: "search" } });
  const searchRouter = new Router(registry, searchCfg, (r) => r);
  const counts = () => `${up.spy.tools.length}/${up.spy.reads.length}/${up.spy.prompts.length}`;

  try {
    assert("kill switch is off at the start", !existsSync(KILL_PATH) && ks.killStatus(cfgK).active === false && ks.killStatus(cfgK).source === null);
    assert("baseline: tool call, resource read and prompt get all work", !(await router.callTool("kk__get_ping", {})).isError && text(await router.readResource("kk://doc/1")) === "KK-DOC" && pmsg(await router.getPrompt("kk__hello")) === "KK-HELLO");
    const before = counts();

    // ---- file switch, the same call the CLI makes -------------------------------------------------
    const turned = ks.setKillFile(true);
    assert("setKillFile(true) writes SWITCHBOARD_HOME/KILL and reports a change", turned.changed && existsSync(KILL_PATH));
    assert("killStatus reports file source and the since note", ks.killStatus(cfgK).source === "file" && typeof ks.killStatus(cfgK).since === "string");
    assert("setKillFile(true) twice is a no-op", ks.setKillFile(true).changed === false);

    const t1 = await router.callTool("kk__get_ping", {});
    const c1 = coded(t1);
    assert("tools/call is refused with SB_KILL_SWITCH", t1.isError === true && c1?.code === SB_ERR.KILL_SWITCH && c1?.hint === SB_HINTS[SB_ERR.KILL_SWITCH], t1.content?.[0]?.text);
    assert("the error code is the literal string SB_KILL_SWITCH", SB_ERR.KILL_SWITCH === "SB_KILL_SWITCH");
    const e2 = await mcpError(() => router.readResource("kk://doc/1"));
    assert("resources/read is refused with SB_KILL_SWITCH (McpError, data.code, message)", refusedWith(e2, "SB_KILL_SWITCH"), e2?.message);
    const e3 = await mcpError(() => router.getPrompt("kk__hello"));
    assert("prompts/get is refused with SB_KILL_SWITCH", refusedWith(e3, "SB_KILL_SWITCH"), e3?.message);
    const e3b = await mcpError(() => router.getPrompt("hello"));
    assert("prompts/get by bare name is refused too", refusedWith(e3b, "SB_KILL_SWITCH"));
    const e2b = await mcpError(() => router.readResource("nope://unknown"));
    assert("the kill switch answers before the URI is even resolved", refusedWith(e2b, "SB_KILL_SWITCH"));
    const t4 = await router.callTool("kk__does_not_exist", {});
    assert("an unknown tool name is refused with SB_KILL_SWITCH, not leaked as unknown", coded(t4)?.code === SB_ERR.KILL_SWITCH);
    assert("no upstream was reached by any refused call", counts() === before, `${before} -> ${counts()}`);
    assert("listing is not a call: tools, resources and prompts still list while the switch is on", router.listTools().length === 1 && (await router.listResources()).length === 1 && (await router.listPrompts()).length === 1);

    const killRows = rows((e) => e.error_code === "SB_KILL_SWITCH");
    assert("audit: tool refusal row (deny, server kk, tool get_ping, SB_KILL_SWITCH)", killRows.some((e) => e.decision === "deny" && e.server === "kk" && e.tool === "get_ping"));
    assert("audit: resources/read refusal row", killRows.some((e) => e.decision === "deny" && e.tool === "resources/read"));
    assert("audit: prompts/get refusal row", killRows.some((e) => e.decision === "deny" && e.tool === "prompts/get"));

    // ---- search mode: the meta-tools are calls too ---------------------------------------------------
    const f = await searchRouter.callTool("find_tools", { query: "ping" });
    const ct = await searchRouter.callTool("call_tool", { name: "kk__get_ping", arguments: {} });
    const bt = await searchRouter.callTool("batch_call", { calls: [{ name: "kk__get_ping" }] });
    assert("search mode: find_tools, call_tool and batch_call are all refused", [f, ct, bt].every((r) => coded(r)?.code === SB_ERR.KILL_SWITCH));
    assert("search mode: still no upstream call", counts() === before);

    // ---- a hand-made empty file and a directory also trip it -----------------------------------------
    ks.setKillFile(false);
    assert("setKillFile(false) removes the file", !existsSync(KILL_PATH) && ks.killStatus(cfgK).active === false);
    assert("...and calls work again on the SAME router, no restart", !(await router.callTool("kk__get_ping", {})).isError && text(await router.readResource("kk://doc/1")) === "KK-DOC" && pmsg(await router.getPrompt("kk__hello")) === "KK-HELLO");
    assert("setKillFile(false) twice is a no-op", ks.setKillFile(false).changed === false);
    writeFileSync(KILL_PATH, "");
    assert("an empty KILL file made with touch trips it", coded(await router.callTool("kk__get_ping", {}))?.code === SB_ERR.KILL_SWITCH && ks.killStatus(cfgK).source === "file");
    rmSync(KILL_PATH);
    mkdirSync(KILL_PATH);
    assert("anything at the KILL path trips it (fail closed)", coded(await router.callTool("kk__get_ping", {}))?.code === SB_ERR.KILL_SWITCH);
    rmSync(KILL_PATH, { recursive: true });
    // Adapted (design 3.15): a KILL file removed by hand no longer reopens the gateway. The first call that saw the switch
    // latched it, so only the owner-authorised clear (setKillFile(false), which the gateway calls after its presence
    // check) turns it off. The old check, "cleared again" right after the hand removal, described the file being the state.
    assert("a KILL file removed by hand is latched: the gateway keeps refusing (design 3.15)", coded(await router.callTool("kk__get_ping", {}))?.code === SB_ERR.KILL_SWITCH);
    ks.setKillFile(false);
    assert("cleared again by the owner-authorised clear", !(await router.callTool("kk__get_ping", {})).isError);

    // ---- config switch ---------------------------------------------------------------------------------
    cfgK.gateway.kill_switch = true;
    assert("gateway.kill_switch:true refuses tools/call", coded(await router.callTool("kk__get_ping", {}))?.code === SB_ERR.KILL_SWITCH);
    assert("gateway.kill_switch:true refuses resources/read and prompts/get", refusedWith(await mcpError(() => router.readResource("kk://doc/1")), "SB_KILL_SWITCH") && refusedWith(await mcpError(() => router.getPrompt("kk__hello")), "SB_KILL_SWITCH"));
    assert("killStatus names the config source", ks.killStatus(cfgK).source === "config" && ks.killStatus(cfgK).config === true && ks.killStatus(cfgK).file === false);
    ks.setKillFile(true);
    assert("file and config together report file+config", ks.killStatus(cfgK).source === "file+config");
    ks.setKillFile(false);
    assert("clearing the file does not clear the config switch", coded(await router.callTool("kk__get_ping", {}))?.code === SB_ERR.KILL_SWITCH);
    cfgK.gateway.kill_switch = false;
    assert("gateway.kill_switch:false lets calls through again", !(await router.callTool("kk__get_ping", {})).isError);
    delete cfgK.gateway.kill_switch;
    assert("an absent gateway.kill_switch is off", ks.isKilled(cfgK) === false);

    // ---- the CLI, a different process ------------------------------------------------------------------
    const cliDir = join(tmp, "cli");
    mkdirSync(cliDir, { recursive: true });
    const cfgOff = join(cliDir, "off.yaml");
    const cfgOn = join(cliDir, "on.yaml");
    writeFileSync(cfgOff, "gateway:\n  transport: [stdio]\nservers: []\n");
    writeFileSync(cfgOn, "gateway:\n  transport: [stdio]\n  kill_switch: true\nservers: []\n");
    const cli = (cfgFile, ...args) =>
      spawnSync(process.execPath, [join(root, "dist", "cli.js"), "-c", cfgFile, ...args], { cwd: cliDir, env: { ...process.env, NO_COLOR: "1" }, encoding: "utf8", timeout: 30_000 });
    const s0 = cli(cfgOff, "kill", "status");
    assert("CLI: kill status reports OFF with exit 0", s0.status === 0 && /kill switch: OFF/.test(s0.stdout), s0.stdout + s0.stderr);
    const on = cli(cfgOff, "kill", "on");
    assert("CLI: kill on exits 0 and creates the file in SWITCHBOARD_HOME", on.status === 0 && existsSync(KILL_PATH), on.stdout + on.stderr);
    assert("CLI: the file it wrote is JSON with a since timestamp", typeof JSON.parse(readFileSync(KILL_PATH, "utf8")).since === "string");
    assert("a gateway in THIS process refuses the very next call after the CLI turned it on", coded(await router.callTool("kk__get_ping", {}))?.code === SB_ERR.KILL_SWITCH && refusedWith(await mcpError(() => router.readResource("kk://doc/1")), "SB_KILL_SWITCH"));
    const s1 = cli(cfgOff, "kill", "status");
    assert("CLI: kill status reports ON, the file and its since note", s1.status === 0 && /kill switch: ON/.test(s1.stdout) && /present, since /.test(s1.stdout), s1.stdout);
    // Adapted (wave 2, design 3.8): `kill off` no longer deletes the file itself. It asks a RUNNING gateway, which checks
    // the owner is present first, so with no gateway answering it exits 1 and the switch stays on. The path with a live
    // gateway (presence granted, refused, already off) is proven in verify-hardening-2. Here the owner's presence-checked
    // clearing is done directly with setKillFile(false), because this oracle runs no HTTP gateway.
    const off = cli(cfgOff, "kill", "off");
    assert("CLI: kill off with no gateway answering exits 1, leaves the file and says why (it needs gateway-side owner presence)", off.status === 1 && existsSync(KILL_PATH) && /presence/.test(off.stderr), off.stdout + off.stderr);
    ks.setKillFile(false);
    assert("a gateway in THIS process works again after the switch is cleared", !(await router.callTool("kk__get_ping", {})).isError);
    const s2 = cli(cfgOn, "kill", "status");
    assert("CLI: status reports ON from gateway.kill_switch alone", s2.status === 0 && /kill switch: ON/.test(s2.stdout) && /gateway\.kill_switch is true/.test(s2.stdout), s2.stdout);
    const off2 = cli(cfgOn, "kill", "off");
    assert("CLI: kill off exits 1 and says so while gateway.kill_switch is still true", off2.status === 1 && /gateway\.kill_switch/.test(off2.stderr), off2.stdout + off2.stderr);
    const bad = cli(cfgOff, "kill", "maybe");
    assert("CLI: an unknown action exits 1", bad.status === 1 && /unknown action/.test(bad.stderr), bad.stderr);
    const noCfg = cli(join(cliDir, "missing.yaml"), "kill", "on");
    assert("CLI: kill on works with no readable config", noCfg.status === 0 && existsSync(KILL_PATH), noCfg.stdout + noCfg.stderr);
    ks.setKillFile(false); // adapted: `kill off` needs a running gateway (see above), so the harness clears its own file
    assert("CLI: cleaned up", !existsSync(KILL_PATH));

    // ---- health endpoints report it ----------------------------------------------------------------------
    const port = await freePort();
    const cfgH = {
      gateway: { transport: ["http"], http: { host: "127.0.0.1", port, require_auth: "auto" }, tool_exposure: "namespaced", default_policy: "read" },
      vault: { backend: "env" },
      servers: [],
      settings: {},
    };
    const gwH = new Gateway(cfgH);
    const handle = await startDashboard(gwH, cfgH, undefined);
    try {
      const base = `http://127.0.0.1:${port}`;
      const get = async (path, headers = {}) => {
        const r = await fetch(base + path, { headers });
        return { status: r.status, body: await r.json().catch(() => ({})) };
      };
      const h0 = await get("/healthz");
      assert("/healthz reports kill_switch:false when off", h0.status === 200 && h0.body.kill_switch === false && h0.body.status === "ok", JSON.stringify(h0.body));
      const a0 = await get("/api/health");
      assert("/api/health reports kill_switch.active:false when off", a0.status === 200 && a0.body.kill_switch?.active === false && a0.body.kill_switch?.source === null, JSON.stringify(a0.body.kill_switch));
      ks.setKillFile(true);
      const h1 = await get("/healthz");
      assert("/healthz reports kill_switch:true while on (liveness stays 200)", h1.status === 200 && h1.body.kill_switch === true && h1.body.status === "ok");
      const a1 = await get("/api/health");
      assert("/api/health reports the file source while on, and the server verdict is untouched", a1.body.kill_switch?.active === true && a1.body.kill_switch?.source === "file" && a1.body.status === "ok" && a1.status === 200, JSON.stringify(a1.body));
      // owner session for the gated state route (adapted: the gateway mints the code after its presence check, the session is a header)
      const owner = await ownerSession(port);
      const st = await get("/api/state", owner.hdr);
      assert("/api/state (owner session) reports the kill switch", st.status === 200 && st.body.kill_switch?.active === true, JSON.stringify(st.body.kill_switch));
      ks.setKillFile(false);
      cfgH.gateway.kill_switch = true;
      const h2 = await get("/healthz");
      const a2 = await get("/api/health");
      assert("health picks up gateway.kill_switch on the live config object", h2.body.kill_switch === true && a2.body.kill_switch?.source === "config");
      cfgH.gateway.kill_switch = false;
      const h3 = await get("/healthz");
      assert("...and clears again", h3.body.kill_switch === false);
    } finally {
      await handle.close();
      await gwH.shutdown();
      ks.setKillFile(false);
    }
  } finally {
    ks.setKillFile(false);
    await registry.unmountAll();
  }
}

// =====================================================================================================
// 6. RESOURCES AND PROMPTS THROUGH POLICY (design 3.10)
// =====================================================================================================
{
  const alpha = makeUpstream({
    tools: [{ name: "get_ping" }],
    resources: [{ uri: "alpha://doc/1", name: "A1" }],
    templates: [{ uriTemplate: "alpha://doc/{id}", name: "A by id" }],
    reads: { "alpha://doc/1": "ALPHA-1", "alpha://doc/99": "ALPHA-99" },
    prompts: [{ name: "summarize", text: "ALPHA-SUM" }],
  });
  const beta = makeUpstream({
    tools: [{ name: "get_ping" }],
    resources: [{ uri: "beta://file/a", name: "BA" }],
    reads: { "beta://file/a": "BETA-A", "beta://gen/xyz": "BETA-XYZ" },
    prompts: [{ name: "other", text: "BETA-OTHER" }],
  });
  const alphaCfg = { id: "alpha", source: "council", enabled: true, policy: "full" };
  const betaCfg = { id: "beta", source: "council", enabled: true, policy: "full" };
  const registry = new Registry(new Vault("env"));
  await registry.mountLocal(alphaCfg, alpha.server);
  await registry.mountLocal(betaCfg, beta.server);
  const cfgR = mkCfg({ servers: [alphaCfg, betaCfg], settings: { profiles: { only_beta: { servers: ["beta"] }, ro: { policy: "read" } } } });
  const router = new Router(registry, cfgR, (r) => r);
  const reads = () => `${alpha.spy.reads.length}/${beta.spy.reads.length}`;
  const promptCalls = () => `${alpha.spy.prompts.length}/${beta.spy.prompts.length}`;

  try {
    // ---- positive controls -----------------------------------------------------------------------------
    assert("listed resource reads from its owner", text(await router.readResource("alpha://doc/1")) === "ALPHA-1" && text(await router.readResource("beta://file/a")) === "BETA-A");
    assert("prompts read by namespaced and by bare name", pmsg(await router.getPrompt("alpha__summarize")) === "ALPHA-SUM" && pmsg(await router.getPrompt("other")) === "BETA-OTHER");
    const okRow = rows((e) => e.tool === "resources/read" && e.reason === "alpha://doc/1")[0];
    assert("an allowed read is audited at read scope with a duration", okRow?.decision === "allow" && okRow?.scope === "read" && typeof okRow?.duration_ms === "number");

    // ---- unlisted URIs are not broadcast ------------------------------------------------------------------
    await router.listResources();
    const r0 = reads();
    const eUnlisted = await mcpError(() => router.readResource("beta://gen/xyz"));
    assert("an unlisted URI (served only by beta) is unknown: McpError InvalidParams", !!eUnlisted && eUnlisted.code === ErrorCode.InvalidParams, eUnlisted?.message);
    assert("...and NO upstream was asked for it (spies on alpha and beta)", reads() === r0 && !alpha.spy.reads.includes("beta://gen/xyz") && !beta.spy.reads.includes("beta://gen/xyz"), `${r0} -> ${reads()}`);
    assert("a template-expanded URI resolves to the server that declared the template", text(await router.readResource("alpha://doc/99")) === "ALPHA-99");
    assert("...and only that server was asked", alpha.spy.reads.includes("alpha://doc/99") && !beta.spy.reads.includes("alpha://doc/99"));
    const eNear = await mcpError(() => router.readResource("alpha://other/1"));
    assert("a URI that does not fit the template is unknown and not broadcast", !!eNear && eNear.code === ErrorCode.InvalidParams && !alpha.spy.reads.includes("alpha://other/1") && !beta.spy.reads.includes("alpha://other/1"));
    const ePrompt = await mcpError(() => router.getPrompt("nonexistent"));
    assert("an unlisted bare prompt name is unknown: McpError InvalidParams", !!ePrompt && ePrompt.code === ErrorCode.InvalidParams);

    // ---- a disabled server (after it was listed) is refused ---------------------------------------------------
    await router.listResources();
    alphaCfg.enabled = false;
    const rd = reads();
    const pd = promptCalls();
    const eDis = await mcpError(() => router.readResource("alpha://doc/1"));
    assert("resources/read on a server disabled after listing is refused (SB_POLICY_DENY)", refusedWith(eDis, "SB_POLICY_DENY") && /disabled/.test(eDis.message), eDis?.message);
    const ePDis = await mcpError(() => router.getPrompt("alpha__summarize"));
    assert("prompts/get on a disabled server is refused (SB_POLICY_DENY)", refusedWith(ePDis, "SB_POLICY_DENY") && /disabled/.test(ePDis.message), ePDis?.message);
    assert("...neither reached the upstream", reads() === rd && promptCalls() === pd);
    const disRows = rows((e) => e.server === "alpha" && e.decision === "deny" && e.error_code === "SB_POLICY_DENY");
    assert("...both refusals are audited as deny rows with SB_POLICY_DENY", disRows.some((e) => e.tool === "resources/read" && /disabled/.test(e.reason)) && disRows.some((e) => e.tool === "prompts/get" && /disabled/.test(e.reason)));
    const eBare = await mcpError(() => router.getPrompt("summarize"));
    assert("a bare prompt name no longer resolves to a disabled server", !!eBare && eBare.code === ErrorCode.InvalidParams);
    alphaCfg.enabled = true;
    assert("re-enabled: both work again", text(await router.readResource("alpha://doc/1")) === "ALPHA-1" && pmsg(await router.getPrompt("alpha__summarize")) === "ALPHA-SUM");

    // ---- the active profile (switched after listing) ----------------------------------------------------------
    await router.listResources();
    cfgR.settings.active_profile = "only_beta";
    const eProf = await mcpError(() => router.readResource("alpha://doc/1"));
    assert("resources/read on a profile-hidden server is refused (SB_POLICY_DENY, active profile)", refusedWith(eProf, "SB_POLICY_DENY") && /active profile/.test(eProf.message), eProf?.message);
    const ePProf = await mcpError(() => router.getPrompt("alpha__summarize"));
    assert("prompts/get on a profile-hidden server is refused", refusedWith(ePProf, "SB_POLICY_DENY") && /active profile/.test(ePProf.message));
    assert("the profile's own server still reads", text(await router.readResource("beta://file/a")) === "BETA-A" && pmsg(await router.getPrompt("beta__other")) === "BETA-OTHER");
    cfgR.settings.active_profile = "ro";
    assert("a read-ceiling profile does not block read-scope surfaces", text(await router.readResource("alpha://doc/1")) === "ALPHA-1" && pmsg(await router.getPrompt("alpha__summarize")) === "ALPHA-SUM");
    delete cfgR.settings.active_profile;

    // ---- per-tool disable of the pseudo tools -------------------------------------------------------------------
    alphaCfg.tools = { "resources/read": { enabled: false }, "prompts/get": { enabled: false } };
    const eTd = await mcpError(() => router.readResource("alpha://doc/1"));
    const ePTd = await mcpError(() => router.getPrompt("alpha__summarize"));
    assert("tools['resources/read'].enabled:false refuses resources/read", refusedWith(eTd, "SB_POLICY_DENY") && /disabled in config/.test(eTd.message), eTd?.message);
    assert("tools['prompts/get'].enabled:false refuses prompts/get", refusedWith(ePTd, "SB_POLICY_DENY") && /disabled in config/.test(ePTd.message));
    assert("...while the same server's other surfaces and tools still work", !(await router.callTool("alpha__get_ping", {})).isError && text(await router.readResource("beta://file/a")) === "BETA-A");
    delete alphaCfg.tools;

    // ---- the approval gate runs on read scope -----------------------------------------------------------------------
    alphaCfg.approval = { require_for: ["read"] };
    const rg = reads();
    const eAp = await mcpError(() => router.readResource("alpha://doc/1"));
    // Adapted for design 3.3: the gate used to fail closed with SB_APPROVAL_DENIED (no terminal to ask). It now leaves a
    // pending approval and refuses with SB_APPROVAL_PENDING. Still fail closed: the upstream was not read.
    assert("a read-scope approval gate holds resources/read (fail closed, SB_APPROVAL_PENDING)", refusedWith(eAp, "SB_APPROVAL_PENDING") && reads() === rg, eAp?.message);
    const eAp2 = await mcpError(() => router.getPrompt("alpha__summarize"));
    assert("...and prompts/get", refusedWith(eAp2, "SB_APPROVAL_PENDING"));
    process.env.SWITCHBOARD_AUTO_APPROVE = "1";
    assert("with approval granted (test harness env) the gated read goes through", text(await router.readResource("alpha://doc/1")) === "ALPHA-1");
    delete process.env.SWITCHBOARD_AUTO_APPROVE;
    delete alphaCfg.approval;

    // ---- the governor: rate limits are shared across tools, resources and prompts ---------------------------------
    {
      const limited = new Router(registry, mkCfg({ servers: [alphaCfg, betaCfg], settings: { limits: { per_minute: 3 } } }), (r) => r);
      const t = await limited.callTool("alpha__get_ping", {});
      const rr = text(await limited.readResource("alpha://doc/1"));
      const pp = pmsg(await limited.getPrompt("alpha__summarize"));
      assert("global per_minute:3 admits a tool call, a resource read and a prompt get", !t.isError && rr === "ALPHA-1" && pp === "ALPHA-SUM");
      const before = reads();
      const eRate = await mcpError(() => limited.readResource("alpha://doc/1"));
      assert("the 4th draw (a resource read) is refused with SB_RATE_LIMITED: tools, resources and prompts share the bucket", refusedWith(eRate, "SB_RATE_LIMITED") && reads() === before, eRate?.message);
      const ePRate = await mcpError(() => limited.getPrompt("alpha__summarize"));
      assert("...a prompt get is refused the same way", refusedWith(ePRate, "SB_RATE_LIMITED"));
      assert("...and so is a tool call", coded(await limited.callTool("alpha__get_ping", {}))?.code === SB_ERR.RATE_LIMITED);
      assert("...audited as deny rows with SB_RATE_LIMITED", rows((e) => e.decision === "deny" && e.error_code === "SB_RATE_LIMITED" && e.tool === "resources/read").length >= 1 && rows((e) => e.decision === "deny" && e.error_code === "SB_RATE_LIMITED" && e.tool === "prompts/get").length >= 1);
    }
    {
      alphaCfg.limits = { per_minute: 1 };
      const serverLimited = new Router(registry, mkCfg({ servers: [alphaCfg, betaCfg] }), (r) => r);
      const first = text(await serverLimited.readResource("alpha://doc/1"));
      const eSrv = await mcpError(() => serverLimited.readResource("alpha://doc/1"));
      assert("a per-server cap (per_minute:1) refuses the second read on that server", first === "ALPHA-1" && refusedWith(eSrv, "SB_RATE_LIMITED"), eSrv?.message);
      assert("...another server is not capped", text(await serverLimited.readResource("beta://file/a")) === "BETA-A");
      delete alphaCfg.limits;
    }
    {
      alphaCfg.tools = { "prompts/get": { limits: { per_minute: 1 } } };
      const toolLimited = new Router(registry, mkCfg({ servers: [alphaCfg, betaCfg] }), (r) => r);
      const first = pmsg(await toolLimited.getPrompt("alpha__summarize"));
      const eT = await mcpError(() => toolLimited.getPrompt("alpha__summarize"));
      assert("a per-tool limit on 'prompts/get' caps prompt reads", first === "ALPHA-SUM" && refusedWith(eT, "SB_RATE_LIMITED"), eT?.message);
      assert("...without capping resources/read on the same server", text(await toolLimited.readResource("alpha://doc/1")) === "ALPHA-1");
      delete alphaCfg.tools;
    }

    // ---- everything still ordinary afterwards ------------------------------------------------------------------------
    assert("after all refusals the plain paths still work", text(await router.readResource("alpha://doc/1")) === "ALPHA-1" && pmsg(await router.getPrompt("alpha__summarize")) === "ALPHA-SUM");
  } finally {
    await registry.unmountAll();
  }
}

// ---- 6b. resource templates: which shapes resolve to the declaring server, and a backtracking guard ----
{
  const reads = {
    "t1://items/7": "ONE",
    "t2://a/b/c": "TWO",
    "t3://files/a/b": "THREE",
    "t4://doc.md": "FOUR",
    "t5://q?a=1&b=2": "FIVE",
    "t5://q": "FIVE-BARE",
  };
  const tpl = makeUpstream({
    templates: [
      { uriTemplate: "t1://items/{id}", name: "t1" },
      { uriTemplate: "t2://{+path}", name: "t2" },
      { uriTemplate: "t3://files{/dir}", name: "t3" },
      { uriTemplate: "t4://doc{.ext}", name: "t4" },
      { uriTemplate: "t5://q{?a,b}", name: "t5" },
    ],
    reads,
  });
  const other = makeUpstream({ templates: [{ uriTemplate: "o://x/{id}", name: "o" }], reads: { "o://x/1": "O" } });
  const tplCfg = { id: "tpl", source: "council", enabled: true, policy: "full" };
  const otherCfg = { id: "oth", source: "council", enabled: true, policy: "full" };
  const registry = new Registry(new Vault("env"));
  await registry.mountLocal(tplCfg, tpl.server);
  await registry.mountLocal(otherCfg, other.server);
  const router = new Router(registry, mkCfg({ servers: [tplCfg, otherCfg] }), (r) => r);
  try {
    for (const [uri, want] of Object.entries(reads)) {
      assert(`template shape resolves ${uri}`, text(await router.readResource(uri)) === want);
    }
    assert("every template read reached only the declaring server", other.spy.reads.length === 0 && tpl.spy.reads.length === Object.keys(reads).length);
    for (const uri of ["t1://items/7/8", "t1://items/", "t4://doc", "t3://files", "o://x/1/2", "t1://nothing"]) {
      const e = await mcpError(() => router.readResource(uri));
      assert(`non-matching ${uri} is unknown (not broadcast)`, !!e && e.code === ErrorCode.InvalidParams);
    }
    assert("an owner-declared template serves its own URI", text(await router.readResource("o://x/1")) === "O" && other.spy.reads.includes("o://x/1"));
    assert("...and the other server was not asked for the non-matching URIs", !other.spy.reads.some((u) => u.startsWith("t")) && !tpl.spy.reads.some((u) => u.includes("nothing") || u.endsWith("/8")));
    const hostile = "t4://doc" + ".a".repeat(2000) + "/x";
    const t0 = Date.now();
    const eH = await mcpError(() => router.readResource(hostile));
    const ms = Date.now() - t0;
    assert(`a hostile 4000-char URI against a {.ext} template is rejected quickly, no catastrophic backtracking (${ms} ms, limit 2000)`, !!eH && eH.code === ErrorCode.InvalidParams && ms < 2000, `${ms} ms`);
    const eL = await mcpError(() => router.readResource("t2://" + "a".repeat(9000)));
    assert("a URI over 8192 characters is never matched against a template", !!eL && eL.code === ErrorCode.InvalidParams && !tpl.spy.reads.some((u) => u.length > 8000));
  } finally {
    await registry.unmountAll();
  }
}

try {
  rmSync(tmp, { recursive: true, force: true });
} catch {
  /* leftovers in temp are harmless */
}
await sleep(200); // Windows UV_HANDLE_CLOSING guard
const failed = checks.filter((c) => !c.ok);
if (failed.length) console.log("\nFAILED:", failed.map((c) => c.name).join(" | "));
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
process.exitCode = failed.length === 0 ? 0 : 1;
