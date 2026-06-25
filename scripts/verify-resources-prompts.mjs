// Deterministic oracle for the MCP resources/* + prompts/* passthrough (src/router.ts listResources,
// listResourceTemplates, readResource, listPrompts, getPrompt — wired into the downstream Server by
// src/gateway.ts buildServer). These are the OTHER two MCP content surfaces beyond tools: a full MCP
// client (Claude Desktop, Cursor) discovers every governed upstream's resources + prompts through
// Switchboard's single endpoint, not just its tools. This oracle drives the real compiled Router over
// real in-memory upstream MCP Servers and computes every verdict itself — ZERO network, ZERO model.
//
// It proves:
//   resources aggregate   — resources from every visible, resource-capable upstream are merged
//                           (NOT namespaced — a URI is an opaque global identity passed back verbatim).
//   URI collision         — two upstreams exposing the same URI is first-wins + the loser is dropped,
//                           so a read of that URI resolves to the FIRST owner (never silently shadowed).
//   read routing + audit  — readResource(uri) routes to the owning server and writes a `resources/read`
//                           audit row at read scope.
//   template-expanded read — a URI that was never listed (expanded from a template) resolves via the
//                           try-each fallback, which SKIPS a server that throws and lands on the one
//                           that can serve it.
//   unknown resource      — an unresolvable URI throws McpError(InvalidParams) (result-or-error surface).
//   prompts aggregate     — prompts are namespaced `serverId__name` (a prompt name is short + collision
//                           -prone), so two upstreams' `summarize` coexist as distinct exposed names.
//   prompt routing + args — getPrompt("srv__name", args) strips the prefix, routes to the owner, forwards
//                           arguments, and writes a `prompts/get` audit row; a bare name falls back.
//   capability gating     — a tools-only upstream contributes ZERO resources and ZERO prompts.
//   visibility gating     — a DISABLED server and a server hidden by the active PROFILE contribute
//                           nothing, and their resources/prompts cannot be read even by exact URI/name.
//   gateway wiring        — Gateway.buildServer() registers all five resources/* + prompts/* handlers,
//                           which the SDK REFUSES unless the matching capability is declared (the negative
//                           control proves a tools-only Server rejects a resources/* handler).
// Zero deps (node stdlib + the package's own compiled output + its bundled MCP SDK). Build first.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Isolate the audit log into a throwaway home BEFORE importing — HOME_DIR is resolved at module load
// (vault.ts reads SWITCHBOARD_HOME there), so this redirects every write away from the real ~/.switchboard.
process.env.SWITCHBOARD_HOME = mkdtempSync(join(tmpdir(), "sb-respr-"));

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  ListToolsRequestSchema,
  ListResourcesRequestSchema,
  ListResourceTemplatesRequestSchema,
  ReadResourceRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
  McpError,
  ErrorCode,
} from "@modelcontextprotocol/sdk/types.js";

const { Registry } = await import("../dist/registry.js");
const { Router } = await import("../dist/router.js");
const { Vault } = await import("../dist/vault.js");
const { Gateway } = await import("../dist/gateway.js");
const { recentAudit } = await import("../dist/audit.js");

const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Did `fn()` throw an McpError carrying ErrorCode.InvalidParams? */
async function throwsInvalidParams(fn) {
  try {
    await fn();
    return false;
  } catch (err) {
    return err instanceof McpError && err.code === ErrorCode.InvalidParams;
  }
}

// --- build a real in-memory upstream MCP Server with the requested content surfaces ----------------
function makeUpstream({ caps, resources = [], templates = [], reads = {}, prompts = [] }) {
  const server = new Server({ name: "upstream", version: "0.0.0" }, { capabilities: caps });
  // mountLocal calls client.listTools(), so every upstream MUST answer tools/list (even if empty).
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [] }));

  if (caps.resources) {
    server.setRequestHandler(ListResourcesRequestSchema, async () => ({ resources }));
    server.setRequestHandler(ListResourceTemplatesRequestSchema, async () => ({ resourceTemplates: templates }));
    server.setRequestHandler(ReadResourceRequestSchema, async (req) => {
      const uri = req.params.uri;
      const text = reads[uri];
      if (text === undefined) throw new McpError(ErrorCode.InvalidParams, `no such resource ${uri}`);
      return { contents: [{ uri, mimeType: "text/plain", text }] };
    });
  }

  if (caps.prompts) {
    server.setRequestHandler(ListPromptsRequestSchema, async () => ({
      prompts: prompts.map((p) => ({
        name: p.name,
        description: p.description,
        ...(p.arguments ? { arguments: p.arguments } : {}),
      })),
    }));
    server.setRequestHandler(GetPromptRequestSchema, async (req) => {
      const p = prompts.find((x) => x.name === req.params.name);
      if (!p) throw new McpError(ErrorCode.InvalidParams, `no such prompt ${req.params.name}`);
      const text = p.render(req.params.arguments || {});
      return { description: p.description, messages: [{ role: "user", content: { type: "text", text } }] };
    });
  }

  return server;
}

const ALL = { tools: {}, resources: {}, prompts: {} };

// alpha — full content surface; owns alpha://doc/1 + alpha://doc/2 + an alpha://doc/{id} template.
const alpha = makeUpstream({
  caps: ALL,
  resources: [
    { uri: "alpha://doc/1", name: "Alpha One", mimeType: "text/plain" },
    { uri: "alpha://doc/2", name: "Alpha Two", mimeType: "text/plain" },
  ],
  templates: [{ uriTemplate: "alpha://doc/{id}", name: "Alpha doc by id" }],
  reads: { "alpha://doc/1": "ALPHA-DOC-1", "alpha://doc/2": "ALPHA-DOC-2", "alpha://doc/99": "ALPHA-DOC-99" },
  prompts: [
    {
      name: "summarize",
      description: "Alpha summarize",
      arguments: [{ name: "topic", required: false }],
      render: (a) => `ALPHA-SUMMARIZE topic=${a.topic ?? ""}`,
    },
    { name: "greet", description: "Alpha greet", render: () => "ALPHA-GREET" },
  ],
});

// beta — collides with alpha on alpha://doc/1 (must LOSE), owns beta://file/a, can serve an UNLISTED
// beta://gen/xyz only (proves the try-each fallback skips alpha's throw), and a 2nd `summarize` prompt.
const beta = makeUpstream({
  caps: ALL,
  resources: [
    { uri: "beta://file/a", name: "Beta A", mimeType: "text/plain" },
    { uri: "alpha://doc/1", name: "Beta shadow of alpha doc 1", mimeType: "text/plain" },
  ],
  reads: { "beta://file/a": "BETA-FILE-A", "beta://gen/xyz": "BETA-GEN-XYZ", "alpha://doc/1": "BETA-SHADOW" },
  prompts: [{ name: "summarize", description: "Beta summarize", render: () => "BETA-SUMMARIZE" }],
});

// gamma — tools ONLY. Must contribute zero resources + zero prompts (capability gating).
const gamma = makeUpstream({ caps: { tools: {} } });

// delta — full content surface but DISABLED at mount. Must contribute nothing (visibility gating).
const delta = makeUpstream({
  caps: ALL,
  resources: [{ uri: "delta://secret/1", name: "Delta secret", mimeType: "text/plain" }],
  reads: { "delta://secret/1": "DELTA-SECRET" },
  prompts: [{ name: "hidden", description: "Delta hidden", render: () => "DELTA-HIDDEN" }],
});

const registry = new Registry(new Vault("env"));
await registry.mountLocal({ id: "alpha", source: "local", enabled: true, policy: "full" }, alpha);
await registry.mountLocal({ id: "beta", source: "local", enabled: true, policy: "full" }, beta);
await registry.mountLocal({ id: "gamma", source: "local", enabled: true, policy: "full" }, gamma);
await registry.mountLocal({ id: "delta", source: "local", enabled: false, policy: "full" }, delta);

const baseCfg = {
  gateway: { default_policy: "full", tool_exposure: "namespaced" },
  vault: { backend: "env" },
  servers: [],
  settings: {},
};
const router = new Router(registry, baseCfg, (ref) => ref);

const text = (r) => r?.contents?.[0]?.text;
const msg = (r) => r?.messages?.[0]?.content?.text;

try {
  // --- A. resources aggregate across visible, resource-capable upstreams ---------------------------
  const res = await router.listResources();
  const uris = res.map((r) => r.uri);
  assert("resources aggregate to 3 (alpha:2 + beta:1, collision dropped)", res.length === 3, `got ${res.length}: ${uris.join(", ")}`);
  assert("resources include alpha://doc/1", uris.includes("alpha://doc/1"));
  assert("resources include alpha://doc/2", uris.includes("alpha://doc/2"));
  assert("resources include beta://file/a", uris.includes("beta://file/a"));
  assert("resources are NOT namespaced (raw URI, no `__` prefix)", uris.every((u) => !u.startsWith("alpha__") && !u.startsWith("beta__")));
  assert("disabled delta resource excluded", !uris.includes("delta://secret/1"));
  assert("tools-only gamma contributes no resources", !uris.some((u) => u.includes("gamma")));

  // --- B. resource templates aggregate ------------------------------------------------------------
  const tpls = await router.listResourceTemplates();
  assert("resource templates aggregate to 1", tpls.length === 1, `got ${tpls.length}`);
  assert("template is alpha://doc/{id}", tpls[0]?.uriTemplate === "alpha://doc/{id}");

  // --- C. readResource routing + URI-collision first-wins + audit ---------------------------------
  assert("readResource alpha://doc/1 routes to ALPHA (collision winner, not BETA-SHADOW)", text(await router.readResource("alpha://doc/1")) === "ALPHA-DOC-1");
  assert("readResource beta://file/a routes to BETA", text(await router.readResource("beta://file/a")) === "BETA-FILE-A");
  assert("readResource template-expanded alpha://doc/99 resolves via try-each", text(await router.readResource("alpha://doc/99")) === "ALPHA-DOC-99");
  assert("readResource unlisted beta://gen/xyz: fallback SKIPS alpha's throw, lands on beta", text(await router.readResource("beta://gen/xyz")) === "BETA-GEN-XYZ");
  assert("readResource unknown URI throws McpError(InvalidParams)", await throwsInvalidParams(() => router.readResource("nope://x")));

  let audit = recentAudit(200);
  const readRow = audit.find((r) => r.tool === "resources/read" && r.reason === "alpha://doc/1");
  assert("audit has a resources/read row at read scope (allow)", !!readRow && readRow.scope === "read" && readRow.decision === "allow");

  // --- D. prompts aggregate (namespaced) ----------------------------------------------------------
  const prompts = await router.listPrompts();
  const names = prompts.map((p) => p.name);
  assert("prompts aggregate to 3 (alpha:2 + beta:1)", prompts.length === 3, `got ${prompts.length}: ${names.join(", ")}`);
  assert("prompts ARE namespaced serverId__name", names.every((n) => n.includes("__")));
  assert("prompts include alpha__summarize", names.includes("alpha__summarize"));
  assert("prompts include alpha__greet", names.includes("alpha__greet"));
  assert("prompts include beta__summarize (name collision survives via namespacing)", names.includes("beta__summarize"));
  assert("tools-only gamma contributes no prompts", !names.some((n) => n.startsWith("gamma__")));
  assert("disabled delta prompt excluded", !names.includes("delta__hidden"));

  // --- E. getPrompt routing + arg passthrough + audit ---------------------------------------------
  assert("getPrompt alpha__summarize strips prefix, routes, FORWARDS args", msg(await router.getPrompt("alpha__summarize", { topic: "x" })) === "ALPHA-SUMMARIZE topic=x");
  assert("getPrompt beta__summarize routes to BETA despite name collision", msg(await router.getPrompt("beta__summarize")) === "BETA-SUMMARIZE");
  assert("getPrompt bare `greet` resolves via fallback", msg(await router.getPrompt("greet")) === "ALPHA-GREET");
  assert("getPrompt unknown-server prefix throws McpError(InvalidParams)", await throwsInvalidParams(() => router.getPrompt("zzz__nope")));
  assert("getPrompt bare unknown throws McpError(InvalidParams)", await throwsInvalidParams(() => router.getPrompt("nonexistent")));

  audit = recentAudit(200);
  const promptRow = audit.find((r) => r.tool === "prompts/get" && r.reason === "summarize");
  assert("audit has a prompts/get row at read scope (allow)", !!promptRow && promptRow.scope === "read" && promptRow.decision === "allow");

  // --- F. PROFILE visibility gating (alpha-only) — same registry, profile-restricted Router --------
  const profCfg = {
    gateway: { default_policy: "full", tool_exposure: "namespaced" },
    vault: { backend: "env" },
    servers: [],
    settings: { active_profile: "restricted", profiles: { restricted: { servers: ["alpha"] } } },
  };
  const profRouter = new Router(registry, profCfg, (ref) => ref);

  const pRes = (await profRouter.listResources()).map((r) => r.uri);
  assert("profile hides beta resources (only alpha visible)", !pRes.includes("beta://file/a") && pRes.includes("alpha://doc/1"), pRes.join(", "));
  const pPrompts = (await profRouter.listPrompts()).map((p) => p.name);
  assert("profile hides beta prompts (only alpha visible)", !pPrompts.includes("beta__summarize") && pPrompts.includes("alpha__summarize"), pPrompts.join(", "));
  assert("profile-hidden beta resource cannot be read even by exact URI", await throwsInvalidParams(() => profRouter.readResource("beta://file/a")));
  assert("profile-hidden beta prompt cannot be read even by namespaced name", await throwsInvalidParams(() => profRouter.getPrompt("beta__summarize")));

  // --- G. gateway wiring — buildServer registers all 5 handlers (cap declaration is load-bearing) --
  let built = null;
  let buildThrew = false;
  try {
    built = new Gateway({ ...baseCfg, vault: { backend: "env" } }).buildServer();
  } catch {
    buildThrew = true;
  }
  assert("Gateway.buildServer() registers resources/* + prompts/* handlers without throwing", !buildThrew && !!built);

  // negative control: the SDK refuses a resources/* handler on a Server that didn't declare the cap.
  // This proves gateway.ts declaring { resources:{}, prompts:{} } is what makes buildServer() legal.
  let refused = false;
  try {
    const barren = new Server({ name: "barren", version: "0" }, { capabilities: { tools: {} } });
    barren.setRequestHandler(ListResourcesRequestSchema, async () => ({ resources: [] }));
  } catch {
    refused = true;
  }
  assert("negative control: tools-only Server REFUSES a resources/* handler", refused);
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
