// Child process for scripts/verify-dos-hardening.mjs. It runs ONE timing case in isolation, so a
// catastrophic regression (a regex that never finishes) can only hang this process, which the parent
// kills on a deadline, never the oracle itself.
//
// Usage: node dos-child.mjs <case> <n>
//   template-router <n>   a hostile upstream declares mem://{a}{b}{c}{d}{e}{f}{g}x; the client reads a
//                         URI of about <n> characters through the real Router.readResource
//   redact-router <n>     a hostile upstream answers one tools/call with an isError text of <n> bytes
//                         (eyJa- repeated), once with capture_io off and once with it on
// Prints one line: RESULT <json>. SWITCHBOARD_HOME must point at a throwaway directory (the parent sets it).
import { Server } from "@modelcontextprotocol/server";

const [mode, nArg = "0"] = process.argv.slice(2);
const n = Number(nArg);

const { Registry } = await import("../../dist/registry.js");
const { Router } = await import("../../dist/router.js");
const { Vault } = await import("../../dist/vault.js");
const { recentAudit } = await import("../../dist/audit.js");

const cfg = (settings = {}) => ({ gateway: { default_policy: "full", tool_exposure: "namespaced" }, vault: { backend: "env" }, servers: [], settings });
const done = (obj) => {
  console.log(`RESULT ${JSON.stringify(obj)}`);
  process.exit(0);
};

if (mode === "template-router") {
  const hostile = new Server({ name: "hostile", version: "0.0.0" }, { capabilities: { tools: {}, resources: {} } });
  hostile.setRequestHandler("tools/list", async () => ({ tools: [] }));
  hostile.setRequestHandler("resources/list", async () => ({ resources: [] }));
  hostile.setRequestHandler("resources/templates/list", async () => ({ resourceTemplates: [{ uriTemplate: "mem://{a}{b}{c}{d}{e}{f}{g}x", name: "hostile" }] }));
  hostile.setRequestHandler("resources/read", async (req) => ({ contents: [{ uri: req.params.uri, text: "hostile-read" }] }));
  // A second, honest upstream: a legitimate template must keep working beside the hostile one.
  const honest = new Server({ name: "honest", version: "0.0.0" }, { capabilities: { tools: {}, resources: {} } });
  honest.setRequestHandler("tools/list", async () => ({ tools: [] }));
  honest.setRequestHandler("resources/list", async () => ({ resources: [] }));
  honest.setRequestHandler("resources/templates/list", async () => ({ resourceTemplates: [{ uriTemplate: "ok://doc/{id}", name: "ok" }] }));
  honest.setRequestHandler("resources/read", async (req) => ({ contents: [{ uri: req.params.uri, text: "honest-read" }] }));
  const registry = new Registry(new Vault("env"));
  await registry.mountLocal({ id: "hostile", source: "local", enabled: true, policy: "full" }, hostile);
  await registry.mountLocal({ id: "honest", source: "local", enabled: true, policy: "full" }, honest);
  const router = new Router(registry, cfg(), (ref) => ref);
  await router.listResources();
  const uri = `mem://${"ax".repeat(Math.max(0, Math.floor((n - 6) / 2)))}b`;
  const t0 = process.hrtime.bigint();
  let outcome = "read";
  try {
    await router.readResource(uri);
  } catch (err) {
    outcome = /unknown resource/.test(String(err?.message)) ? "unknown" : `error:${String(err?.message).slice(0, 80)}`;
  }
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  const honestRead = (await router.readResource("ok://doc/42")).contents?.[0]?.text;
  done({ uriLen: uri.length, ms, outcome, honestRead });
}

if (mode === "redact-router") {
  const hostile = new Server({ name: "hostile", version: "0.0.0" }, { capabilities: { tools: {} } });
  hostile.setRequestHandler("tools/list", async () => ({ tools: [{ name: "redos_error", description: "fails with a pathological error text", inputSchema: { type: "object", properties: {} } }] }));
  hostile.setRequestHandler("tools/call", async () => ({ isError: true, content: [{ type: "text", text: "eyJa-".repeat(Math.floor(n / 5)) }] }));
  const registry = new Registry(new Vault("env"));
  await registry.mountLocal({ id: "hostile", source: "local", enabled: true, policy: "full" }, hostile);
  const out = {};
  for (const [label, capture] of [["off", false], ["on", true]]) {
    const router = new Router(registry, cfg({ logs: { capture_io: capture } }), (ref) => ref);
    const t0 = process.hrtime.bigint();
    const res = await router.callTool("hostile__redos_error", {});
    out[`${label}_ms`] = Number(process.hrtime.bigint() - t0) / 1e6;
    out[`${label}_isError`] = res.isError === true;
  }
  // Result rows only: since wave 2 a write-scope call also writes an `attempt` row ahead of the upstream call (design 3.7).
  const rows = recentAudit(50).filter((r) => r.server === "hostile" && r.phase !== "attempt");
  out.rows = rows.length;
  out.maxErrorLen = Math.max(0, ...rows.map((r) => (typeof r.error === "string" ? r.error.length : 0)));
  done(out);
}

console.error(`unknown case ${mode}`);
process.exit(2);
