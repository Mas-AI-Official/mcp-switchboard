// Deterministic oracle for outbound webhook delivery (settings.webhook). Drives the REAL
// router decision path — scope inference → policy ceiling → approval gate → audit → webhook —
// against an in-process echo MCP server, and captures every delivery on a local HTTP receiver.
// It proves: off-by-default, per-decision delivery honoring `events`, valid HMAC-SHA256
// `x-switchboard-signature`, METADATA-ONLY payload (no request/response even with capture_io on),
// drop-on-unresolvable-secret (fail-closed authenticity), and non-blocking fail-open delivery.
// Zero deps (node stdlib + global fetch + the package's own SDK). Run `npm run build` first.
// Uses an isolated SWITCHBOARD_HOME temp dir and AUTO_APPROVE so it never blocks on a TTY prompt.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHmac } from "node:crypto";
import { createServer } from "node:http";

process.env.SWITCHBOARD_HOME = mkdtempSync(join(tmpdir(), "sb-webhook-"));
process.env.SWITCHBOARD_AUTO_APPROVE = "1"; // write_thing's approval gate resolves to allow, no TTY

const { Gateway } = await import("../dist/gateway.js");
const { recentAudit } = await import("../dist/audit.js");
const { verifyWebhook } = await import("../dist/webhook.js");
const { Server } = await import("@modelcontextprotocol/sdk/server/index.js");
const { CallToolRequestSchema, ListToolsRequestSchema } = await import("@modelcontextprotocol/sdk/types.js");

const SECRET = "s3cr3t-webhook-signing-key";
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
const DEAD_URL = "http://127.0.0.1:59999/dead"; // nothing listens here → ECONNREFUSED

// Wait until at least n deliveries have landed (detached delivery → poll), or time out.
async function waitFor(n, ms = 2000) {
  const deadline = Date.now() + ms;
  while (received.length < n && Date.now() < deadline) await sleep(15);
  return received.length;
}
const clear = () => { received.length = 0; };
const sign = (raw) => "sha256=" + createHmac("sha256", SECRET).update(raw).digest("hex");

// --- in-process echo MCP server: read_thing (allow), write_thing (approval), delete_thing (deny) ---
const echo = new Server({ name: "echo", version: "0.0.0" }, { capabilities: { tools: {} } });
const TOOLS = [
  { name: "read_thing", description: "read", inputSchema: { type: "object", additionalProperties: true } },
  { name: "write_thing", description: "write", inputSchema: { type: "object", additionalProperties: true } },
  { name: "delete_thing", description: "delete", inputSchema: { type: "object", additionalProperties: true } },
];
echo.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));
echo.setRequestHandler(CallToolRequestSchema, async (req) => ({
  content: [{ type: "text", text: JSON.stringify({ echoed: req.params.arguments ?? {} }) }],
}));

// `cfg` is held by reference inside the Router; mutating cfg.settings.webhook between blocks
// takes effect on the next call (deliverWebhook re-reads cfg.settings.webhook every time).
const cfg = {
  gateway: { transport: ["http"], http: { host: "127.0.0.1", port: 0, require_auth: "auto" }, tool_exposure: "namespaced", default_policy: "read" },
  vault: { backend: "encrypted-file" },
  servers: [],
  // The receiver listens on loopback; since the SSRF guard (src/netguard.ts) a loopback webhook target must be allowlisted.
  settings: { logs: { capture_io: false }, network: { allow_private: ["127.0.0.1"] }, webhook: { enabled: false, url: RECV_URL, events: [], secret_ref: "" } },
};

const gateway = new Gateway(cfg);
gateway.vault.set("webhook_secret", SECRET);
await gateway.registry.mountLocal(
  { id: "echo", source: "app2mcp", enabled: true, policy: "write", approval: { require_for: ["write"] } },
  echo,
);
const call = (name, args = {}) => gateway.router.callTool(name, args);

try {
  // 0) sanity: the three verdicts resolve as designed
  const denyRes = await call("echo__delete_thing", {});
  assert("delete_thing is denied by policy ceiling", denyRes.isError === true && /denied by policy/.test(denyRes.content?.[0]?.text ?? ""), denyRes.content?.[0]?.text ?? "");
  const allowRes = await call("echo__read_thing", {});
  assert("read_thing is allowed (not an error)", allowRes.isError !== true);

  // A) OFF BY DEFAULT — disabled webhook delivers nothing
  clear();
  cfg.settings.webhook = { enabled: false, url: RECV_URL, events: ["allow", "deny", "approval_required"], secret_ref: "${vault:webhook_secret}" };
  await call("echo__read_thing", {});
  await call("echo__delete_thing", {});
  await sleep(300);
  assert("disabled webhook delivers nothing", received.length === 0, `got ${received.length}`);

  // B) ENABLED + SIGNED + all events — one delivery per decision, signature valid, metadata only
  cfg.settings.webhook = { enabled: true, url: RECV_URL, events: ["allow", "deny", "approval_required"], secret_ref: "${vault:webhook_secret}" };

  clear();
  await call("echo__read_thing", {});
  await waitFor(1);
  {
    const d = received[0];
    assert("allow → exactly one delivery", received.length === 1, `got ${received.length}`);
    assert("allow payload decision=allow", d?.json?.decision === "allow", d?.json?.decision);
    assert("allow payload type=switchboard.decision", d?.json?.type === "switchboard.decision");
    assert("allow payload carries server/tool/scope", d?.json?.server === "echo" && d?.json?.tool === "read_thing" && d?.json?.scope === "read");
    assert("allow payload carries duration_ms", typeof d?.json?.duration_ms === "number");
    assert("allow signature verifies (HMAC-SHA256 over raw body)", d?.headers?.["x-switchboard-signature"] === sign(d.raw), d?.headers?.["x-switchboard-signature"]);

    // Standard Webhooks (standardwebhooks.com) triple is delivered ALONGSIDE the legacy header.
    assert("delivery carries a webhook-id (uuid)", typeof d?.headers?.["webhook-id"] === "string" && /^[0-9a-f-]{36}$/.test(d.headers["webhook-id"]), d?.headers?.["webhook-id"]);
    assert("delivery carries a numeric webhook-timestamp (unix seconds)", /^\d+$/.test(d?.headers?.["webhook-timestamp"] ?? ""), d?.headers?.["webhook-timestamp"]);
    assert("delivery carries a v1, webhook-signature", (d?.headers?.["webhook-signature"] ?? "").startsWith("v1,"), d?.headers?.["webhook-signature"]);

    // verifyWebhook round-trips the real delivery, and rejects every tamper.
    const wh = d.headers;
    assert(
      "verifyWebhook accepts a genuine delivery",
      verifyWebhook({ id: wh["webhook-id"], timestamp: wh["webhook-timestamp"], payload: d.raw, secret: SECRET, signature: wh["webhook-signature"] }) === true,
    );
    assert(
      "verifyWebhook rejects a tampered body",
      verifyWebhook({ id: wh["webhook-id"], timestamp: wh["webhook-timestamp"], payload: d.raw + " ", secret: SECRET, signature: wh["webhook-signature"] }) === false,
    );
    assert(
      "verifyWebhook rejects the wrong secret",
      verifyWebhook({ id: wh["webhook-id"], timestamp: wh["webhook-timestamp"], payload: d.raw, secret: "not-the-secret", signature: wh["webhook-signature"] }) === false,
    );
    assert(
      "verifyWebhook rejects a stale timestamp (replay window)",
      verifyWebhook({ id: wh["webhook-id"], timestamp: String(Number(wh["webhook-timestamp"]) - 3600), payload: d.raw, secret: SECRET, signature: wh["webhook-signature"], toleranceSec: 300 }) === false,
    );
    assert(
      "verifyWebhook rejects a mismatched id (id is part of the signed content)",
      verifyWebhook({ id: "00000000-0000-0000-0000-000000000000", timestamp: wh["webhook-timestamp"], payload: d.raw, secret: SECRET, signature: wh["webhook-signature"] }) === false,
    );
  }

  clear();
  await call("echo__delete_thing", {});
  await waitFor(1);
  {
    const d = received[0];
    assert("deny → exactly one delivery", received.length === 1, `got ${received.length}`);
    assert("deny payload decision=deny + reason", d?.json?.decision === "deny" && typeof d?.json?.reason === "string");
    assert("deny signature verifies", d?.headers?.["x-switchboard-signature"] === sign(d.raw));
  }

  clear();
  await call("echo__write_thing", {}); // approval_required notification (gate-open) THEN allow (post-exec)
  await waitFor(2);
  {
    const decisions = received.map((d) => d.json?.decision).sort();
    assert("write_thing delivers approval_required + allow", received.length === 2 && JSON.stringify(decisions) === JSON.stringify(["allow", "approval_required"]), JSON.stringify(decisions));
    const appr = received.find((d) => d.json?.decision === "approval_required");
    assert("approval_required carries no duration_ms (it is a pre-gate notification)", appr && appr.json.duration_ms === undefined);
    assert("every write_thing delivery is signed", received.every((d) => d.headers["x-switchboard-signature"] === sign(d.raw)));
  }

  // approval_required fired BEFORE the call executed → it is a notification, not an audit row.
  // The audit log must therefore hold an allow (and earlier a deny) for echo, but NO
  // approval_required row, so usage totals can't double-count. (forward() never audits the gate-open.)
  {
    const echoRows = recentAudit(100).filter((e) => e.server === "echo");
    assert("no approval_required row is written to the audit log", echoRows.every((e) => e.decision !== "approval_required"), `decisions=${[...new Set(echoRows.map((e) => e.decision))].join(",")}`);
  }

  // C) EVENT FILTERING — events:[deny] suppresses allow, still delivers deny
  cfg.settings.webhook = { enabled: true, url: RECV_URL, events: ["deny"], secret_ref: "${vault:webhook_secret}" };
  clear();
  await call("echo__read_thing", {});
  await sleep(300);
  assert("events:[deny] suppresses an allow delivery", received.length === 0, `got ${received.length}`);
  clear();
  await call("echo__delete_thing", {});
  await waitFor(1);
  assert("events:[deny] still delivers a deny", received.length === 1 && received[0].json?.decision === "deny", `got ${received.length}`);

  // D) UNSIGNED — no secret_ref → delivered, but no signature header
  cfg.settings.webhook = { enabled: true, url: RECV_URL, events: ["deny"], secret_ref: "" };
  clear();
  await call("echo__delete_thing", {});
  await waitFor(1);
  assert("unsigned delivery omits x-switchboard-signature", received.length === 1 && received[0].headers["x-switchboard-signature"] === undefined);

  // E) UNRESOLVABLE SECRET — a promised signature that can't be resolved → DROP (fail-closed)
  cfg.settings.webhook = { enabled: true, url: RECV_URL, events: ["deny"], secret_ref: "${vault:does_not_exist}" };
  clear();
  await call("echo__delete_thing", {});
  await sleep(300);
  assert("unresolvable secret_ref drops the delivery (no unsigned fallback)", received.length === 0, `got ${received.length}`);

  // F) METADATA ONLY even with capture_io ON — the payload must never carry request/response.
  // Use a non-secret-looking key so it would survive into the audit capture if leaked.
  const MARKER = "TOPSECRET-LEAK-MARKER";
  cfg.settings.logs = { capture_io: true };
  cfg.settings.webhook = { enabled: true, url: RECV_URL, events: ["allow"], secret_ref: "${vault:webhook_secret}" };
  clear();
  await call("echo__read_thing", { note: MARKER, payload: { deep: MARKER } });
  await waitFor(1);
  {
    const d = received[0];
    assert("capture_io=on: webhook body excludes the call I/O marker", !d.raw.includes(MARKER), "marker leaked into webhook body");
    assert("capture_io=on: webhook payload has no request/response keys", d.json && !("request" in d.json) && !("response" in d.json));
    // Prove capture_io was genuinely ON (so the strip above isn't vacuous): the audit row DID capture it.
    const row = recentAudit(20).find((e) => e.server === "echo" && e.tool === "read_thing" && e.decision === "allow" && e.request);
    assert("capture_io=on: the audit row DID store the request (strip is real, not vacuous)", row && JSON.stringify(row.request).includes(MARKER), row ? "marker absent from audit row" : "no captured audit row");
  }
  cfg.settings.logs = { capture_io: false };

  // G) NON-BLOCKING / FAIL-OPEN — a dead webhook URL must not delay or fail the decision
  cfg.settings.webhook = { enabled: true, url: DEAD_URL, events: ["allow"], secret_ref: "${vault:webhook_secret}" };
  const t0 = Date.now();
  const res = await call("echo__read_thing", {});
  const elapsed = Date.now() - t0;
  assert("dead webhook does not block the call (returns < 1s, well under the 8s timeout)", elapsed < 1000, `${elapsed}ms`);
  assert("dead webhook does not error the call (fail-open governance)", res.isError !== true);
} finally {
  await gateway.shutdown();
  await new Promise((r) => receiver.close(r));
}

const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
process.exit(failed.length === 0 ? 0 : 1);
