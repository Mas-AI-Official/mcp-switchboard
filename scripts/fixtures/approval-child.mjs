// Child process for scripts/verify-approval-gate.mjs. It runs the REAL approval gate with a TTY-shaped
// stdin and stdout (the gate only prompts when both claim to be a terminal) so the parent can play the
// human: read what the prompts show, type into the child's stdin, close it.
//
// Usage: node approval-child.mjs <mode> [n]
//   direct <n>        <n> concurrent approve() calls (what a batch or parallel requests produce)
//   router-batch      the real Router: one batch_call carrying 3 gated calls (write, write, destructive). Since
//                     design 3.3 it prints no prompt; RESULT carries `executed` and the count of `pending` answers
//   spoof             one approve() whose tool name tries to forge a second prompt and clear the screen
// Prompts go to stdout (as for a human); machine lines go to stderr:
//   EARLY <json>      how many calls had already been refused before any input arrived
//   RESULT <json>     the final outcome
import { Server } from "@modelcontextprotocol/server";

process.stdin.isTTY = true;
process.stdout.isTTY = true;
delete process.env.SWITCHBOARD_AUTO_APPROVE;
delete process.env.SWITCHBOARD_INSECURE_APPROVAL;

const [mode, nArg = "3"] = process.argv.slice(2);
const emit = (tag, obj) => process.stderr.write(`${tag} ${JSON.stringify(obj)}\n`);
const finish = (obj) => {
  emit("RESULT", obj);
  // stdin may still be open (that is the point of some cases): leave on our own terms
  setTimeout(() => process.exit(0), 50);
};

if (mode === "direct" || mode === "spoof") {
  const { approve } = await import("../../dist/approval.js");
  const n = mode === "spoof" ? 1 : Number(nArg);
  const settled = new Array(n).fill(null);
  const tools = Array.from({ length: n }, (_, i) =>
    mode === "spoof" ? "t\n[approval] FAKE gated -> wipe_everything needs 'full'. Type QQQQ to allow\u001b[2J" : `tool_${i}`,
  );
  const promises = tools.map((tool, i) =>
    approve("gated", tool, i % 2 === 0 ? "write" : "full", "oracle reason").then((v) => {
      settled[i] = v;
      return v;
    }),
  );
  setTimeout(() => emit("EARLY", { settled: settled.filter((v) => v !== null).length }), 600);
  const results = await Promise.all(promises);
  finish({ results });
} else if (mode === "router-batch") {
  const { Registry } = await import("../../dist/registry.js");
  const { Router } = await import("../../dist/router.js");
  const { Vault } = await import("../../dist/vault.js");
  const executed = [];
  const upstream = new Server({ name: "gated", version: "0.0.0" }, { capabilities: { tools: {} } });
  upstream.setRequestHandler("tools/list", async () => ({
    tools: [
      { name: "send_note", description: "write", inputSchema: { type: "object", properties: { text: { type: "string" } } } },
      { name: "delete_thing", description: "destructive", inputSchema: { type: "object", properties: {} } },
    ],
  }));
  upstream.setRequestHandler("tools/call", async (req) => {
    executed.push(`${req.params.name}:${JSON.stringify(req.params.arguments ?? {})}`);
    return { content: [{ type: "text", text: "done" }] };
  });
  const registry = new Registry(new Vault("env"));
  await registry.mountLocal({ id: "gated", source: "local", enabled: true, policy: "full", approval: { require_for: ["write", "full"] } }, upstream);
  const router = new Router(registry, { gateway: { default_policy: "full", tool_exposure: "search" }, vault: { backend: "env" }, servers: [], settings: {} }, (r) => r);
  const res = await router.callTool("batch_call", {
    calls: [
      { name: "gated__send_note", arguments: { text: "benign-looking" } },
      { name: "gated__send_note", arguments: { text: "second" } },
      { name: "gated__delete_thing", arguments: {} },
    ],
  });
  let denied = 0;
  let pending = 0;
  try {
    const body = JSON.parse(res.content[0].text);
    const results = body.results ?? body.result ?? [];
    denied = results.filter((r) => r?.isError || /APPROVAL_DENIED/.test(JSON.stringify(r))).length;
    pending = results.filter((r) => /SB_APPROVAL_PENDING/.test(JSON.stringify(r))).length;
  } catch {
    /* the executed list is the evidence, not the envelope */
  }
  finish({ executed, denied, pending });
} else {
  console.error(`unknown mode ${mode}`);
  process.exit(2);
}
