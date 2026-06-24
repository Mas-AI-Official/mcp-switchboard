// Deterministic oracle for poll-first triggers (settings.triggers). Drives the REAL
// TriggerManager.pollOnce() path against an in-process, MUTATING MCP server and proves the two
// governed actions stay distinct:
//   THE POLL  — a real router.callTool, so it runs policy → ceiling → audit like any agent call;
//   THE FIRE  — an observation, delivered as a `type:"switchboard.trigger"` webhook + recorded in
//               the local ring, and NEVER written as an AuditEntry.decision (so usageStats() can't
//               be inflated by fires).
// It proves: off-by-default (start() no-op while disabled) + running-flag honors enable/reload/stop;
// first poll only baselines (never floods the backlog); item-level fire on a NEW list key with a
// bounded sample; whole-response hash fire on any change; unchanged polls fire nothing; a denied
// (over-scope) poll is isError → no fire + last_error, yet IS audited as `deny`; unknown/disabled
// ids are skipped without polling; dual delivery (local ring + signed webhook) with the trigger
// payload bypassing the decision `events` filter; and the core invariant — a firing poll moves
// usageStats().total by exactly 1 (the poll), the fire adds nothing.
// Zero deps (node stdlib + global fetch + the package's own SDK). Run `npm run build` first.
// Uses an isolated SWITCHBOARD_HOME temp dir so the baseline assertions start from clean state.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHmac } from "node:crypto";
import { createServer } from "node:http";

process.env.SWITCHBOARD_HOME = mkdtempSync(join(tmpdir(), "sb-triggers-"));
process.env.SWITCHBOARD_AUTO_APPROVE = "1"; // defensive: no approval gate is configured, but never block on a TTY

const { Gateway } = await import("../dist/gateway.js");
const { recentAudit, usageStats } = await import("../dist/audit.js");
const { Server } = await import("@modelcontextprotocol/sdk/server/index.js");
const { CallToolRequestSchema, ListToolsRequestSchema } = await import("@modelcontextprotocol/sdk/types.js");

const SECRET = "s3cr3t-trigger-signing-key";
const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// --- local HTTP receiver: captures the RAW body (for HMAC) + headers of every delivery ---
const received = [];
const receiver = createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    let json = null;
    try { json = JSON.parse(body); } catch { /* keep raw only */ }
    received.push({ headers: req.headers, raw: body, json });
    res.writeHead(200);
    res.end("ok");
  });
});
const RECV_PORT = await new Promise((resolve) => {
  receiver.listen(0, "127.0.0.1", () => resolve(receiver.address().port));
});
const RECV_URL = `http://127.0.0.1:${RECV_PORT}/hook`;

// Trigger deliveries vs decision deliveries, isolated by payload type so a stray decision
// webhook can never skew a trigger count (and vice versa).
const trig = () => received.filter((d) => d.json?.type === "switchboard.trigger");
const dec = () => received.filter((d) => d.json?.type === "switchboard.decision");
// Wait until at least n trigger deliveries have landed (detached delivery → poll), or time out.
async function waitForTrig(n, ms = 2000) {
  const deadline = Date.now() + ms;
  while (trig().length < n && Date.now() < deadline) await sleep(15);
  return trig().length;
}
const clear = () => { received.length = 0; };
const sign = (raw) => "sha256=" + createHmac("sha256", SECRET).update(raw).digest("hex");

// --- in-process MUTATING MCP server: the poll re-reads these every call (args are fixed) ---
//   read_items → { items: [...] }   (item detection: item_path="items", item_key="id")
//   read_blob  → { blob: <string> } (hash detection: no item_path/item_key)
//   delete_item                      (full scope → denied by the `write` ceiling)
let items = [{ id: "i1" }, { id: "i2" }];
let blob = "v1";
const echo = new Server({ name: "echo", version: "0.0.0" }, { capabilities: { tools: {} } });
const TOOLS = [
  { name: "read_items", description: "list items", inputSchema: { type: "object", additionalProperties: true } },
  { name: "read_blob", description: "read blob", inputSchema: { type: "object", additionalProperties: true } },
  { name: "delete_item", description: "delete an item", inputSchema: { type: "object", additionalProperties: true } },
];
echo.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
echo.setRequestHandler(CallToolRequestSchema, async (req) => {
  const n = req.params.name;
  if (n === "read_items") return { content: [{ type: "text", text: JSON.stringify({ items }) }] };
  if (n === "read_blob") return { content: [{ type: "text", text: JSON.stringify({ blob }) }] };
  return { content: [{ type: "text", text: JSON.stringify({ ok: n }) }] };
});

// `cfg` is held by reference inside TriggerManager + Router; mutating cfg.settings between blocks
// takes effect on the next poll (defsById()/state() re-read cfg.settings.triggers every time).
const cfg = {
  gateway: { transport: ["http"], http: { host: "127.0.0.1", port: 0, require_auth: "auto" }, tool_exposure: "namespaced", default_policy: "read" },
  vault: { backend: "encrypted-file" },
  servers: [],
  settings: {
    logs: { capture_io: false },
    webhook: { enabled: false, url: RECV_URL, events: [], secret_ref: "" },
    triggers: {
      enabled: false,
      poll_interval_seconds: 60,
      definitions: [
        { id: "items", tool: "echo__read_items", item_path: "items", item_key: "id", enabled: true },
        { id: "blob", tool: "echo__read_blob", enabled: true },
        { id: "denied", tool: "echo__delete_item", enabled: true },
        { id: "disabledOne", tool: "echo__read_items", item_path: "items", item_key: "id", enabled: false },
      ],
    },
  },
};

// new Gateway() (NOT createGateway) so no poller auto-starts — we drive pollOnce() deterministically.
const gateway = new Gateway(cfg);
gateway.vault.set("trigger_secret", SECRET);
await gateway.registry.mountLocal({ id: "echo", source: "app2mcp", enabled: true, policy: "write" }, echo);
const t = gateway.triggers;

try {
  // A) OFF BY DEFAULT — start() is a no-op while triggers are disabled; reload/stop honor the flag.
  cfg.settings.triggers.enabled = false;
  t.start();
  assert("disabled: start() does not run any poller (running=false)", t.state().running === false);
  assert("disabled: state().enabled mirrors the config (false)", t.state().enabled === false);

  cfg.settings.triggers.enabled = true;
  t.reload();
  assert("enabled: reload() arms the pollers (running=true)", t.state().running === true);
  assert("enabled: state().enabled mirrors the config (true)", t.state().enabled === true);
  t.stop();
  assert("stop() halts the pollers (running=false)", t.state().running === false);
  // enabled stays true for the rest; we never rely on the interval timers — only explicit pollOnce().

  // Enable a signed webhook. events:["approval_required"] is a NON-EMPTY decision filter that NONE
  // of this test's polls match (they only ever produce allow/deny), so every DECISION webhook is
  // suppressed — yet trigger fires must still deliver, proving deliverTriggerWebhook ignores the
  // events filter entirely. (An EMPTY events list means "deliver every decision", not "suppress all",
  // so it would flood the receiver with decision noise — that is the trap this avoids.)
  cfg.settings.webhook = { enabled: true, url: RECV_URL, events: ["approval_required"], secret_ref: "${vault:trigger_secret}" };

  // B) BASELINE — the first poll of each trigger only seeds state and fires nothing (no backlog flood).
  clear();
  const bItems = await t.pollOnce("items");
  assert("items: first poll is a baseline, fires nothing", bItems.baseline === true && bItems.fired === false && bItems.ok === true && bItems.detection === "items", JSON.stringify(bItems));
  const bHash = await t.pollOnce("blob");
  assert("blob: first poll is a baseline, fires nothing", bHash.baseline === true && bHash.fired === false && bHash.ok === true && bHash.detection === "hash", JSON.stringify(bHash));
  await sleep(250);
  assert("baseline polls deliver no trigger webhook", trig().length === 0, `got ${trig().length}`);
  assert("baseline polls record no fire in the local ring", t.state().recent_fires.length === 0, `ring=${t.state().recent_fires.length}`);

  // C) ITEM-LEVEL FIRE — a new keyed element fires once, with a bounded sample of the new keys.
  items = [{ id: "i1" }, { id: "i2" }, { id: "i3" }];
  clear();
  const fItems = await t.pollOnce("items");
  await waitForTrig(1);
  assert("items: a new element fires (items detection, +1)", fItems.fired === true && fItems.detection === "items" && fItems.new_count === 1 && fItems.ok === true, JSON.stringify(fItems));
  {
    const d = trig()[0];
    assert("items: exactly one trigger webhook delivery", trig().length === 1, `got ${trig().length}`);
    assert("items: payload type=switchboard.trigger (NOT switchboard.decision)", d?.json?.type === "switchboard.trigger", d?.json?.type);
    assert("items: payload carries trigger_id/tool/detection/new_count", d?.json?.trigger_id === "items" && d?.json?.tool === "echo__read_items" && d?.json?.detection === "items" && d?.json?.new_count === 1, JSON.stringify(d?.json));
    assert("items: payload sample_keys is the new key only", Array.isArray(d?.json?.sample_keys) && d.json.sample_keys.length === 1 && d.json.sample_keys[0] === "i3", JSON.stringify(d?.json?.sample_keys));
    assert("items: delivery is HMAC-signed over the raw body", d?.headers?.["x-switchboard-signature"] === sign(d.raw), d?.headers?.["x-switchboard-signature"]);
  }
  assert("items: fire is recorded in the local ring (dual delivery)", t.state().recent_fires.some((r) => r.trigger_id === "items" && r.new_count === 1 && r.detection === "items"));
  assert("trigger fire delivered while the decision `events` filter suppressed the poll's own allow webhook", trig().length === 1 && dec().length === 0, `trig=${trig().length} dec=${dec().length}`);

  // C2) ITEM no-change — re-polling the same list fires nothing (snapshot semantics).
  clear();
  const fItems2 = await t.pollOnce("items");
  await sleep(250);
  assert("items: an unchanged poll fires nothing", fItems2.fired === false && fItems2.new_count === 0 && fItems2.baseline === false, JSON.stringify(fItems2));
  assert("items: unchanged poll delivers no trigger webhook", trig().length === 0, `got ${trig().length}`);

  // D) HASH FIRE — a changed whole response fires once with no sample_keys.
  blob = "v2";
  clear();
  const fHash = await t.pollOnce("blob");
  await waitForTrig(1);
  assert("blob: a changed response fires (hash detection, +1)", fHash.fired === true && fHash.detection === "hash" && fHash.new_count === 1, JSON.stringify(fHash));
  {
    const d = trig()[0];
    assert("blob: exactly one trigger webhook delivery, type=switchboard.trigger", trig().length === 1 && d?.json?.type === "switchboard.trigger", `len=${trig().length} type=${d?.json?.type}`);
    assert("blob: hash fire carries no sample_keys", d?.json?.sample_keys === undefined, JSON.stringify(d?.json?.sample_keys));
    assert("blob: delivery is HMAC-signed", d?.headers?.["x-switchboard-signature"] === sign(d.raw));
  }

  // D2) HASH no-change — an identical response fires nothing.
  clear();
  const fHash2 = await t.pollOnce("blob");
  await sleep(250);
  assert("blob: an identical response fires nothing", fHash2.fired === false && fHash2.new_count === 0 && trig().length === 0, `${JSON.stringify(fHash2)} len=${trig().length}`);

  // E) DENIED POLL — an over-scope poll is isError → no fire + last_error, but IS audited as deny.
  clear();
  const dn = await t.pollOnce("denied");
  await sleep(250);
  assert("denied: an isError poll does not fire", dn.fired === false && dn.ok === false && typeof dn.error === "string", JSON.stringify(dn));
  assert("denied: no trigger webhook for a non-firing poll", trig().length === 0, `got ${trig().length}`);
  {
    const st = t.state().triggers.find((x) => x.id === "denied");
    assert("denied: last_error is recorded on the trigger", st && typeof st.last_error === "string" && st.last_error.length > 0, st ? st.last_error : "(no trigger)");
  }

  // F) SKIPPED — unknown / disabled ids never poll (no audit row, no fire).
  const unk = await t.pollOnce("does-not-exist");
  assert("unknown id is skipped (not polled)", unk.skipped === "unknown trigger" && unk.fired === false && unk.ok === false, JSON.stringify(unk));
  const dis = await t.pollOnce("disabledOne");
  assert("disabled trigger is skipped (not polled)", dis.skipped === "disabled" && dis.fired === false && dis.ok === false, JSON.stringify(dis));

  // G) THE CORE INVARIANT — the poll is audited; the fire is NEVER an audit decision.
  {
    const echoRows = recentAudit(200).filter((e) => e.server === "echo");
    assert("the poll IS audited: read_items recorded as allow", echoRows.some((e) => e.tool === "read_items" && e.decision === "allow"));
    assert("the poll IS audited: read_blob recorded as allow", echoRows.some((e) => e.tool === "read_blob" && e.decision === "allow"));
    assert("the denied poll IS audited as deny", echoRows.some((e) => e.tool === "delete_item" && e.decision === "deny"));
    assert("no audit row carries a fire/trigger verdict (a fire is never a decision)", echoRows.every((e) => ["allow", "deny", "approval_required"].includes(e.decision)), `decisions=${[...new Set(echoRows.map((e) => e.decision))].join(",")}`);
  }

  // H) usageStats accounting — a FIRING poll moves the total by exactly 1 (the poll); the fire adds 0.
  clear();
  const before = usageStats().total;
  items = [{ id: "i1" }, { id: "i2" }, { id: "i3" }, { id: "i4" }];
  const fr = await t.pollOnce("items");
  await waitForTrig(1); // the fire's webhook lands (proving it really fired) but never touches the audit log
  const after = usageStats().total;
  assert("a firing poll fired (precondition for the accounting check)", fr.fired === true && fr.new_count === 1, JSON.stringify(fr));
  assert("the fire's webhook was delivered (dual delivery confirmed)", trig().length === 1 && trig()[0].json?.type === "switchboard.trigger");
  assert("a firing poll increments usageStats().total by exactly 1 — the poll, never the fire", after - before === 1, `before=${before} after=${after}`);
} finally {
  await gateway.shutdown();
  await new Promise((r) => receiver.close(r));
  // The product's fire() delivers its webhook detached (fire-and-forget), so global fetch (undici)
  // may still be finalizing an idle keep-alive socket here. Give it a tick to settle, then let the
  // loop drain on its own (undici unrefs idle sockets) — calling process.exit() mid-close trips a
  // libuv "UV_HANDLE_CLOSING" assertion on Windows that would abort with a non-zero code.
  await sleep(200);
}

const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
process.exitCode = failed.length === 0 ? 0 : 1;
