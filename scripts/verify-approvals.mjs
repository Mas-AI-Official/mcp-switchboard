// Deterministic oracle for out-of-band approvals and risk (design vNext 3.3 and 3.4), which replace the in-band
// TTY gate. Nothing here prompts, touches the operator's real state, or calls a real service.
//
//   A  the manager (src/approvals.ts) with a fake clock and a fake presence provider
//        the pending record and its canonical args hash; reuse; approve then consume once; a second identical
//        call needs a new approval; different args / principal / server / tool never match; expiry of pending and
//        approved records and the TTL bounds; forged, edited, rolled-back and pre-restart records are ignored and
//        logged; restart invalidates; a refused presence check approves nothing; deny needs no presence; prompts
//        are serialised; the flood caps; env-auto is recorded as such; a damaged store fails closed; the
//        waiting poll; the presence message (format, 120 character summary, no control characters)
//   B  the Router: risk derivation table, tool and server overrides, outward, require_for_risk OR-ed with the
//        server scopes, client max_risk, SB_APPROVAL_PENDING shape, approve then execute once, a second identical
//        call, different args and principal, the kill switch before and after an approval and across a wait,
//        wait_seconds, deny during a wait, resources/read, audit rows, the hash is taken before secret injection
//   C  the HTTP surfaces in-process: the dashboard routes (owner session + CSRF) and the control API (control
//        token) both go through the gateway's presence check; neither door opens the other; the kill switch toggle;
//        the clients API behind the Clients page
//   D  a real gateway process and the real CLI: pending, `approvals list|show|approve|deny`, one-use consumption,
//        a forged and a damaged approvals.json, restart invalidation, audit rows and an intact audit chain
//   E  config bounds   F  static facts (no readline on the call path, the dashboard pages, no em dash)
//
// Presence is NEVER real here: a provider is injected, or SWITCHBOARD_INSECURE_APPROVAL=1 selects presence "none".
// Isolated HOME / SWITCHBOARD_HOME, ephemeral ports (never 8088), every child is killed. Build first.
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import http from "node:http";
import net from "node:net";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dist = (f) => pathToFileURL(join(root, "dist", f)).href;
const FIXTURE_UP = join(root, "scripts", "fixtures", "approvals-upstream.mjs");
const CLI = join(root, "dist", "cli.js");

// ---- isolated environment (before any dist module is imported: HOME_DIR is read at import) ---------------------
const base = mkdtempSync(join(tmpdir(), "sb-approvals-"));
const dirs = { home: join(base, "home"), appdata: join(base, "appdata"), local: join(base, "local"), tmp: join(base, "tmp") };
for (const d of Object.values(dirs)) mkdirSync(d, { recursive: true });
const SBHOME = join(dirs.home, ".switchboard");
Object.assign(process.env, {
  HOME: dirs.home,
  USERPROFILE: dirs.home,
  APPDATA: dirs.appdata,
  LOCALAPPDATA: dirs.local,
  TEMP: dirs.tmp,
  TMP: dirs.tmp,
  SWITCHBOARD_HOME: SBHOME,
  NO_COLOR: "1",
});
const SCRUB = /(_API_KEY|_API_SECRET|TOKEN|SECRET|PASSWORD|CREDENTIALS)$|^SWITCHBOARD_(AUTO_APPROVE|PROFILE|TOKEN|KEY|INSECURE_APPROVAL)$/i;
for (const k of Object.keys(process.env)) if (SCRUB.test(k)) delete process.env[k];

const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond });
  const clean = String(detail).replace(/\x1b\[[0-9;]*[A-Za-z]/g, "").replace(/\s+/g, " ").trim();
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${!cond && clean ? `: ${clean.slice(0, 400)}` : ""}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const throwsMsg = (fn) => {
  try {
    fn();
    return "";
  } catch (e) {
    return `${e && e.name}: ${e && e.message}`;
  }
};

// Everything below runs against the compiled output.
const AP = await import(dist("approvals.js"));
const { Approvals, argsSha256, presenceMessage, summarizeArgs, ApprovalLimitError, APPROVAL_ID_RE } = AP;
const { Router } = await import(dist("router.js"));
const { Registry } = await import(dist("registry.js"));
const { Vault } = await import(dist("vault.js"));
const { Gateway } = await import(dist("gateway.js"));
const { startDashboard } = await import(dist("dashboard.js"));
const { evaluate, resolveRisk } = await import(dist("policy.js"));
const { recentAudit, canonicalJson } = await import(dist("audit.js"));
const { setKillFile, killFilePath } = await import(dist("killswitch.js"));
const { validateConfig } = await import(dist("config.js"));
const { verifyOwnerPresence } = await import(dist("presence.js"));
const { defaultPresence } = AP;
const CKEY = await import(dist("controlkey.js"));
const { isOsProtected } = await import(dist("oscrypt.js"));
const { LoginCodeStore } = await import(dist("httpsec.js"));
const { SB_ERR, SB_HINTS } = await import(dist("errors.js"));
const { Server } = await import("@modelcontextprotocol/sdk/server/index.js");
const { ListToolsRequestSchema, CallToolRequestSchema, ListResourcesRequestSchema, ReadResourceRequestSchema } = await import("@modelcontextprotocol/sdk/types.js");

// ---- independent reference for the canonical args hash (not the code under test) -----------------------------------
const refCanon = (v) =>
  v === null || typeof v !== "object"
    ? JSON.stringify(v)
    : Array.isArray(v)
      ? `[${v.map(refCanon).join(",")}]`
      : `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${refCanon(v[k])}`).join(",")}}`;
const refHash = (v) => createHash("sha256").update(refCanon(v), "utf8").digest("hex");

const T0 = Date.parse("2026-10-23T12:00:00.000Z");
const REASON = "approval gate: 'high' risk calls require confirmation (gateway.approval.require_for_risk)";
const baseReq = (o = {}) => ({
  principal: "apikey:k1",
  client: "codex",
  server: "voice",
  tool: "text_to_speech",
  args: { text: "hello", voice: "aria" },
  scope: "write",
  risk: "high",
  reason: REASON,
  ...o,
});

let fileSeq = 0;
/** A manager on its own store file, with a fake clock, a recording audit sink and a scriptable presence provider. */
function mk({ ok = true, path } = {}) {
  const p = path ?? join(SBHOME, `ap-${++fileSeq}.json`);
  const rows = [];
  const prompts = [];
  const st = { ok, active: 0, maxActive: 0, reason: "declined" };
  const clock = { t: T0 };
  const A = new Approvals({
    path: p,
    clock: () => clock.t,
    audit: (e) => rows.push(e),
    presence: async (message) => {
      prompts.push(message);
      st.active++;
      st.maxActive = Math.max(st.maxActive, st.active);
      await sleep(15);
      st.active--;
      return st.ok ? { ok: true, method: "none" } : { ok: false, method: "hello", reason: st.reason };
    },
  });
  return { A, rows, prompts, st, clock, path: p };
}
const readStore = (p) => JSON.parse(readFileSync(p, "utf8"));
const rowsFor = (rows, id) => rows.filter((r) => r.approval_id === id).map((r) => r.tool);

/** Capture what the code under test writes to stderr (its log lines) while `fn` runs. */
async function captureStderr(fn) {
  let text = "";
  const real = process.stderr.write.bind(process.stderr);
  process.stderr.write = (c) => ((text += String(c)), true);
  try {
    await fn();
  } finally {
    process.stderr.write = real;
  }
  return text.replace(/\x1b\[[0-9;]*m/g, "");
}

const children = new Set();
const handles = [];
const gateways = [];
function killTree(child) {
  try {
    if (process.platform === "win32") spawnSync("taskkill", ["/pid", String(child.pid), "/T", "/F"], { stdio: "ignore" });
    else child.kill("SIGKILL");
  } catch {
    /* already gone */
  }
}
const freePort = () =>
  new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });

/** Raw HTTP to a gateway. Never rejects: a hung request is status 0 so the check fails instead of the oracle. */
function raw(port, method, path, { cookie, headers = {}, body } = {}) {
  return new Promise((resolve) => {
    const h = { Host: `127.0.0.1:${port}`, ...headers };
    if (cookie) h.Cookie = cookie;
    let data;
    if (body !== undefined) {
      data = typeof body === "string" ? body : JSON.stringify(body);
      h["Content-Length"] = Buffer.byteLength(data);
      if (!Object.keys(h).some((k) => k.toLowerCase() === "content-type")) h["Content-Type"] = "application/json";
    }
    const req = http.request({ host: "127.0.0.1", port, method, path, headers: h, agent: false }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", (err) => resolve({ status: 0, headers: {}, body: "", error: String(err.message) }));
    req.setTimeout(30_000, () => req.destroy(new Error(`timeout ${method} ${path}`)));
    if (data !== undefined) req.write(data);
    req.end();
  });
}
const jsonOf = (r) => {
  try {
    return JSON.parse(r.body);
  } catch {
    return {};
  }
};

/** A stdio-free MCP upstream in-process: records every executed call; one resource behind a risk override. */
function makeUpstream(id, { resources = false } = {}) {
  const executed = [];
  const caps = { tools: {}, ...(resources ? { resources: {} } : {}) };
  const server = new Server({ name: id, version: "0.0.0" }, { capabilities: caps });
  const tool = (name) => ({ name, description: name, inputSchema: { type: "object", properties: { text: { type: "string" }, token: { type: "string" } } } });
  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: ["get_item", "send_note", "publish_post", "delete_thing"].map(tool) }));
  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    executed.push({ name: req.params.name, args: req.params.arguments ?? {} });
    return { content: [{ type: "text", text: `done:${req.params.name}` }] };
  });
  if (resources) {
    server.setRequestHandler(ListResourcesRequestSchema, async () => ({ resources: [{ uri: "res://secret/1", name: "secret" }] }));
    server.setRequestHandler(ReadResourceRequestSchema, async (req) => {
      executed.push({ name: "resources/read", args: { uri: req.params.uri } });
      return { contents: [{ uri: req.params.uri, text: "SECRET-BODY" }] };
    });
  }
  return { server, executed };
}

const parseSb = (res) => {
  try {
    return JSON.parse(res.content?.[0]?.text ?? "");
  } catch {
    return null;
  }
};
const INSTRUCTION = (id) => `approve in the Switchboard dashboard (Approvals) or run: switchboard approvals approve ${id}, then call the same tool again with the same arguments`;

try {
  // ===================================================================================================================
  // A. THE MANAGER
  // ===================================================================================================================
  {
    const { A, rows, prompts, path } = mk();
    const q = baseReq();
    const g = A.request(q, 900);
    const expected = refHash(q.args);
    assert("A1 a gated call creates a PENDING record", g.kind === "pending" && g.created === true && g.record.status === "pending");
    assert("A1 its id has the documented shape (ap_ plus 8 characters)", APPROVAL_ID_RE.test(g.record.id), g.record.id);
    assert("A1 args_sha256 is the SHA-256 of the canonical JSON of the arguments (independent reference)", g.record.args_sha256 === expected, `${g.record.args_sha256} vs ${expected}`);
    assert("A1 the canonical form is sorted keys, no whitespace (pinned bytes)", createHash("sha256").update('{"text":"hello","voice":"aria"}').digest("hex") === g.record.args_sha256);
    assert("A1 key order does not change the hash, at any depth", argsSha256({ b: 1, a: { d: 2, c: [3, { z: 1, y: 2 }] } }) === argsSha256({ a: { c: [3, { y: 2, z: 1 }], d: 2 }, b: 1 }) && argsSha256({ a: 1 }) !== argsSha256({ a: 2 }) && argsSha256({}) === argsSha256(undefined));
    assert("A1 the record carries principal, client, server, tool, scope, risk and a 900 s expiry", g.record.principal === "apikey:k1" && g.record.client === "codex" && g.record.server === "voice" && g.record.tool === "text_to_speech" && g.record.scope === "write" && g.record.risk === "high" && Date.parse(g.record.expires) - Date.parse(g.record.created) === 900_000);
    assert("A1 the preview is a redacted copy, not the raw object", same(g.record.args_preview, q.args));
    const disk = readStore(path);
    assert("A1 it is stored at the store path with an HMAC, and the key is not in the file", disk.approvals.length === 1 && disk.approvals[0].id === g.record.id && /^[0-9a-f]{64}$/.test(disk.approvals[0].mac) && disk.approvals[0].status === "pending");
    assert("A1 an approval_required audit row carries the approval id and risk", rows.some((r) => r.tool === "approval.approval_required" && r.approval_id === g.record.id && r.risk === "high" && r.decision === "approval_required"));
    const view = A.list().pending[0];
    assert("A1 the public view hides the HMAC and the instance", view && view.mac === undefined && view.instance === undefined);

    const again = A.request(q, 900);
    assert("A2 the same call again reuses the pending record (same id, created false, one record)", again.kind === "pending" && again.created === false && again.record.id === g.record.id && readStore(path).approvals.length === 1);
    assert("A2 a reuse writes no second approval_required row", rows.filter((r) => r.tool === "approval.approval_required").length === 1);

    const dec = await A.approve(g.record.id, "dashboard");
    assert("A3 approve succeeds after the presence check", dec.ok && dec.record.status === "approved" && dec.record.decided_via === "dashboard" && dec.record.presence === "none");
    assert("A3 presence was asked exactly once, with the exact action message", prompts.length === 1 && prompts[0] === 'Approve text_to_speech on voice for codex: text="hello", voice="aria"', JSON.stringify(prompts));
    assert("A3 an approved audit row names the owner channel, the id and the risk", rows.some((r) => r.tool === "approval.approved" && r.approval_id === g.record.id && r.principal === "owner:dashboard" && r.risk === "high"));

    const use = A.request(q, 900);
    assert("A4 the identical call consumes the approval (kind approved)", use.kind === "approved" && use.record.id === g.record.id && use.record.status === "consumed");
    assert("A4 the store now says consumed, and a consumed audit row exists", readStore(path).approvals.find((r) => r.id === g.record.id).status === "consumed" && rows.some((r) => r.tool === "approval.consumed" && r.approval_id === g.record.id));
    const second = A.request(q, 900);
    assert("A5 a second identical call needs a NEW approval (pending, different id)", second.kind === "pending" && second.created === true && second.record.id !== g.record.id);
    assert("A5 an approval cannot be consumed twice: the new pending one is not approved either", A.request(q, 900).kind === "pending");
  }

  {
    // matching is on (principal, server, tool, args hash) and nothing else
    const { A } = mk();
    const q = baseReq();
    const id = A.request(q).record.id;
    await A.approve(id, "cli");
    const others = [
      ["different arguments", baseReq({ args: { text: "hello!", voice: "aria" } })],
      ["a different principal", baseReq({ principal: "apikey:k2" })],
      ["a different server", baseReq({ server: "voice2" })],
      ["a different tool", baseReq({ tool: "text_to_speech2" })],
      ["a nested argument changed", baseReq({ args: { text: "hello", voice: "aria", opts: { speed: 2 } } })],
    ];
    for (const [label, r] of others) {
      const g = A.request(r);
      assert(`A6 ${label} does not match the approval (a new pending record)`, g.kind === "pending" && g.created === true && g.record.id !== id, g.kind);
    }
    assert("A6 the approval is still there for the exact call", A.request(q).kind === "approved");
    const key = baseReq({ client: "someone-else" }); // the client label is not part of the match, the principal is
    const id2 = A.request(baseReq({ args: { n: 1 } })).record.id;
    await A.approve(id2, "cli");
    assert("A6 the client name alone is not the identity (the principal is): same principal, other client label still matches", A.request({ ...key, args: { n: 1 } }).kind === "approved");
  }

  {
    // expiry
    const { A, rows, prompts, clock, path } = mk();
    const q = baseReq();
    const p1 = A.request(q, 60);
    assert("A7 the TTL is clamped up to 60 s", Date.parse(p1.record.expires) - Date.parse(p1.record.created) === 60_000);
    const pHuge = A.request(baseReq({ args: { big: 1 } }), 999_999);
    assert("A7 and down to 86400 s", Date.parse(pHuge.record.expires) - Date.parse(pHuge.record.created) === 86_400_000);
    clock.t = T0 + 59_000;
    assert("A7 one second before expiry the pending record is still reusable", A.request(q, 60).kind === "pending" && A.request(q, 60).record.id === p1.record.id);
    clock.t = T0 + 61_000;
    const n = prompts.length;
    const late = await A.approve(p1.record.id, "dashboard");
    assert("A7 an expired pending record cannot be approved, and no presence prompt is shown for it", !late.ok && (late.status === 409 || late.status === 404) && prompts.length === n, JSON.stringify(late));
    assert("A7 it is marked expired and an expired audit row is written", A.list().history.some((r) => r.id === p1.record.id && r.status === "expired") && rows.some((r) => r.tool === "approval.expired" && r.approval_id === p1.record.id));
    const fresh = A.request(q, 60);
    assert("A7 the same call after expiry gets a fresh pending record", fresh.kind === "pending" && fresh.created === true && fresh.record.id !== p1.record.id);
    await A.approve(fresh.record.id, "cli");
    clock.t += 61_000;
    const stale = A.request(q, 60);
    assert("A8 an approved record that is not used before its expiry is dead (pending again, old one expired)", stale.kind === "pending" && stale.record.id !== fresh.record.id && A.list().history.some((r) => r.id === fresh.record.id && r.status === "expired"));
    clock.t += 1000;
    assert("A8 the store file agrees: no approved record is left usable", readStore(path).approvals.every((r) => r.status !== "approved" || Date.parse(r.expires) > clock.t));
  }

  {
    // forged, edited, rolled-back and earlier-run records
    const { A, rows, path, prompts } = mk();
    const q = baseReq();
    const keep = A.request(q).record;
    await A.approve(keep.id, "cli");
    const store = readStore(path);
    const real = store.approvals.find((r) => r.id === keep.id);
    const fingerprintOf = (y) => ({ ...real, id: "ap_AAAAAAAA", args_sha256: refHash(y), args_preview: y, mac: "0".repeat(64) });

    // (i) a hand-made approved record for a call nobody asked about
    const Y = { text: "forged" };
    writeFileSync(path, JSON.stringify({ version: 1, approvals: [real, fingerprintOf(Y)] }));
    let gY;
    const err1 = await captureStderr(() => {
      gY = A.request(baseReq({ args: Y }));
    });
    assert("A9 a hand-made 'approved' record with a bogus HMAC does not approve its call (pending, new id)", gY.kind === "pending" && gY.created === true && gY.record.id !== "ap_AAAAAAAA");
    assert("A9 the forged record is logged on stderr and in the audit log", /ignored approval record ap_AAAAAAAA/.test(err1) && rows.some((r) => r.tool === "approval.ignored" && /ap_AAAAAAAA/.test(r.reason)), err1.slice(0, 200));
    assert("A9 the genuine approved record next to it still works", A.request(q).kind === "approved");

    // (ii) a pending record edited to 'approved' by hand
    const Z = { text: "edited" };
    const pz = A.request(baseReq({ args: Z })).record;
    const sz = readStore(path);
    sz.approvals.find((r) => r.id === pz.id).status = "approved";
    writeFileSync(path, JSON.stringify(sz));
    const gZ = A.request(baseReq({ args: Z }));
    assert("A9 a pending record flipped to 'approved' in the file does not approve (its HMAC no longer fits)", gZ.kind === "pending" && gZ.record.id !== pz.id);

    // (iii) an approved record whose expiry or arguments were edited
    const W = { text: "extend" };
    const pw = A.request(baseReq({ args: W })).record;
    await A.approve(pw.id, "cli");
    const sw = readStore(path);
    const rw = sw.approvals.find((r) => r.id === pw.id);
    rw.expires = "2099-01-01T00:00:00.000Z";
    writeFileSync(path, JSON.stringify(sw));
    assert("A9 an approved record with an edited expiry is ignored", A.request(baseReq({ args: W })).kind === "pending");
    const V = { text: "swapped-args" };
    const pv = A.request(baseReq({ args: V })).record;
    await A.approve(pv.id, "cli");
    const sv = readStore(path);
    const rv = sv.approvals.find((r) => r.id === pv.id);
    const other = { text: "something else entirely" };
    rv.args_sha256 = refHash(other);
    writeFileSync(path, JSON.stringify(sv));
    assert("A9 an approved record re-pointed at other arguments (edited hash) approves neither", A.request(baseReq({ args: other })).kind === "pending" && A.request(baseReq({ args: V })).kind === "pending");

    // (iv) an edited preview: what the owner would be shown is part of the signed record
    const U = { text: "preview" };
    const pu = A.request(baseReq({ args: U })).record;
    const su = readStore(path);
    su.approvals.find((r) => r.id === pu.id).args_preview = { text: "harmless" };
    writeFileSync(path, JSON.stringify(su));
    const before = prompts.length;
    const bad = await A.approve(pu.id, "dashboard");
    assert("A9 a record whose preview was edited cannot be approved, and no prompt is shown for it", !bad.ok && bad.status === 404 && prompts.length === before, JSON.stringify(bad));

    // (v) a record signed by ANOTHER manager (another run) pasted in
    const other2 = mk();
    const o = other2.A.request(baseReq({ args: { text: "from another run" } })).record;
    await other2.A.approve(o.id, "cli");
    const so = readStore(path);
    so.approvals.push(readStore(other2.path).approvals.find((r) => r.id === o.id));
    writeFileSync(path, JSON.stringify(so));
    assert("A9 a validly signed approved record from another gateway run is ignored", A.request(baseReq({ args: { text: "from another run" } })).kind === "pending");
  }

  {
    // rolled back: an already-used approval restored from an older copy of the file
    const { A, path } = mk();
    const q = baseReq({ args: { text: "replay" } });
    const id = A.request(q).record.id;
    await A.approve(id, "cli");
    const snapshot = readFileSync(path, "utf8"); // the approved record, validly signed, not yet used
    assert("A10 the approval works once", A.request(q).kind === "approved");
    writeFileSync(path, snapshot); // the file is rolled back: the record reads 'approved' again
    assert("A10 a restored copy of an already-consumed approval approves nothing (single use survives a rollback)", A.request(q).kind === "pending");
  }

  {
    // restart: the key is in memory only
    const { A, path } = mk();
    const q = baseReq({ args: { text: "restart" } });
    const id = A.request(q).record.id;
    await A.approve(id, "cli");
    const rowsB = [];
    const B = new Approvals({ path, clock: () => T0, audit: (e) => rowsB.push(e), presence: async () => ({ ok: true, method: "none" }) });
    let gB;
    const err = await captureStderr(() => {
      gB = B.request(q);
    });
    assert("A11 after a restart (a new manager on the same file) the approval is gone: the same call is pending", gB.kind === "pending" && gB.created === true && gB.record.id !== id);
    assert("A11 the earlier run's records are logged as ignored, not silently dropped", /earlier gateway run/.test(err) && rowsB.some((r) => r.tool === "approval.ignored" && /earlier gateway run/.test(r.reason)), err.slice(0, 200));
    const ap = await B.approve(id, "dashboard");
    assert("A11 the old id cannot be approved by the new run (unknown)", !ap.ok && ap.status === 404);
    assert("A11 the new run's file holds only its own records", readStore(path).approvals.every((r) => r.instance === B.instance));
  }

  {
    // a refused presence check, deny, serial prompts
    const { A, rows, prompts, st } = mk({ ok: false });
    const q = baseReq({ args: { text: "no presence" } });
    const id = A.request(q).record.id;
    const r = await A.approve(id, "dashboard");
    assert("A12 a refused presence check approves nothing (403 SB_PRESENCE_FAILED)", !r.ok && r.status === 403 && r.code === "SB_PRESENCE_FAILED" && /not verified/.test(r.error), JSON.stringify(r));
    assert("A12 the record is still pending, the call is still pending, and the refusal is audited", A.get(id).status === "pending" && A.request(q).kind === "pending" && rows.some((x) => x.tool === "approval.presence_failed" && x.approval_id === id) && !rows.some((x) => x.tool === "approval.approved"));

    const n = prompts.length;
    const d = A.deny(id, "cli");
    assert("A13 deny needs no presence check (no prompt) and marks the record denied", d.ok && d.record.status === "denied" && prompts.length === n && rows.some((x) => x.tool === "approval.denied" && x.approval_id === id && x.principal === "owner:cli" && x.decision === "deny"));
    const again = A.request(q);
    assert("A13 after a denial the same call gets a new pending record", again.kind === "pending" && again.created === true && again.record.id !== id);
    assert("A13 a denied record cannot be approved or denied again (409)", (await A.approve(id, "cli")).status === 409 && A.deny(id, "cli").status === 409);

    st.ok = true;
    const idW = A.request(baseReq({ args: { text: "withdraw" } })).record.id;
    await A.approve(idW, "cli");
    const w = A.deny(idW, "dashboard");
    assert("A13 an approved-but-unused approval can be withdrawn, after which the call is pending again", w.ok && w.record.status === "denied" && A.request(baseReq({ args: { text: "withdraw" } })).kind === "pending");
    assert("A13 deny of a malformed or unknown id is a clean refusal", A.deny("nope", "cli").status === 400 && A.deny("ap_ZZZZZZZZ", "cli").status === 404);
  }

  {
    const { A, st } = mk();
    const ids = [1, 2, 3, 4].map((i) => A.request(baseReq({ args: { i } })).record.id);
    const all = await Promise.all(ids.map((id) => A.approve(id, "dashboard")));
    assert("A14 four approvals started at once all succeed, one prompt at a time (never two dialogs overlapping)", all.every((x) => x.ok) && st.maxActive === 1, `max concurrent prompts ${st.maxActive}`);
  }

  {
    // flood caps
    const { A } = mk();
    for (let i = 0; i < 16; i++) A.request(baseReq({ args: { i } }));
    const msg = throwsMsg(() => A.request(baseReq({ args: { i: 99 } })));
    assert("A15 a caller with 16 undecided requests gets the 17th refused (ApprovalLimitError)", msg.startsWith("ApprovalLimitError"), msg);
    assert("A15 the SAME call still reuses its pending record under the cap", A.request(baseReq({ args: { i: 3 } })).created === false);
    assert("A15 another caller is not affected", A.request(baseReq({ principal: "apikey:k9", args: { i: 99 } })).created === true);
    for (const p of ["apikey:a", "apikey:b"]) for (let i = 0; i < 16; i++) A.request(baseReq({ principal: p, args: { i } }));
    for (let i = 0; i < 15; i++) A.request(baseReq({ principal: "apikey:c", args: { i } })); // 16 + 1 + 16 + 16 + 15 = 64
    const total = throwsMsg(() => A.request(baseReq({ principal: "apikey:z", args: { i: 1 } })));
    assert("A15 64 undecided requests in all: the 65th, from anyone, is refused", total.startsWith("ApprovalLimitError") && /64/.test(total), total);
    assert("A15 ApprovalLimitError is exported for embedders", typeof ApprovalLimitError === "function");
  }

  {
    // SWITCHBOARD_AUTO_APPROVE
    const warned = await captureStderr(() => {
      process.env.SWITCHBOARD_AUTO_APPROVE = "1";
      mk();
    });
    assert("A16 SWITCHBOARD_AUTO_APPROVE=1 prints a startup warning", /SWITCHBOARD_AUTO_APPROVE=1/.test(warned) && /test harnesses only/.test(warned), warned.slice(0, 200));
    const { A, rows, path } = mk();
    const g = A.request(baseReq({ args: { text: "auto" } }));
    delete process.env.SWITCHBOARD_AUTO_APPROVE;
    assert("A16 with the env switch a gated call is approved at once, recorded as decided_via env-auto", g.kind === "approved" && g.via === "env-auto" && g.record.decided_via === "env-auto");
    const rec = readStore(path).approvals[0];
    assert("A16 the store and the audit rows say env-auto", rec.decided_via === "env-auto" && rec.status === "consumed" && rows.some((r) => r.tool === "approval.approved" && /env-auto/.test(r.reason) && r.principal === "owner:env-auto") && rows.some((r) => r.tool === "approval.consumed"));
    const after = A.request(baseReq({ args: { text: "auto" } }));
    assert("A16 once the switch is off the same call needs a real approval again", after.kind === "pending");
  }

  {
    // a damaged store fails closed
    const { A, path } = mk();
    A.request(baseReq());
    writeFileSync(path, "{ this is not json");
    const msg = throwsMsg(() => A.request(baseReq({ args: { text: "x" } })));
    assert("A17 a damaged approvals.json makes a request throw (fail closed), naming the file", /StoreCorruptError/.test(msg) && msg.includes(path), msg.slice(0, 200));
    assert("A17 the damaged file was NOT replaced by an empty store", readFileSync(path, "utf8") === "{ this is not json");
    const ap = await A.approve("ap_ZZZZZZZZ", "cli");
    assert("A17 approve reports the store problem instead of pretending nothing is there (500 SB_APPROVAL_STORE)", !ap.ok && ap.status === 500 && ap.code === "SB_APPROVAL_STORE", JSON.stringify(ap));
  }

  {
    // waiting
    const { A } = mk();
    const id = A.request(baseReq({ args: { text: "wait" } })).record.id;
    setTimeout(() => void A.approve(id, "dashboard"), 300);
    const t0 = Date.now();
    const r = await A.waitForDecision(id, 5000);
    const dt = Date.now() - t0;
    assert("A18 waitForDecision returns as soon as the owner approves (not at the deadline)", r?.status === "approved" && dt >= 250 && dt < 3500, `${r?.status} after ${dt} ms`);
    const id2 = A.request(baseReq({ args: { text: "wait-timeout" } })).record.id;
    const t1 = Date.now();
    const r2 = await A.waitForDecision(id2, 400);
    const dt2 = Date.now() - t1;
    assert("A18 with nobody deciding it returns the still-pending record at the deadline", r2?.status === "pending" && dt2 >= 350 && dt2 < 3000, `${r2?.status} after ${dt2} ms`);
    assert("A18 an unknown id resolves undefined at once", (await A.waitForDecision("ap_ZZZZZZZZ", 2000)) === undefined);
  }

  {
    // the presence message
    const msg = presenceMessage({ tool: "text_to_speech", server: "voice", client: "codex", principal: "apikey:k1", args_preview: { text: "hi" } });
    assert("A19 the presence message is 'Approve <tool> on <server> for <client>: <summary>'", msg === 'Approve text_to_speech on voice for codex: text="hi"', msg);
    assert("A19 with no client the caller's principal is named", presenceMessage({ tool: "t", server: "s", client: null, principal: "loopback-anonymous:loopback", args_preview: {} }) === "Approve t on s for loopback-anonymous:loopback: (no arguments)");
    const hostile = presenceMessage({ tool: "t\n[approval] FAKE\u001b[2J", server: "s\r\nx", client: "c\u0007", principal: "p", args_preview: { text: "x".repeat(5000) } });
    assert("A19 control characters and newlines in names or arguments never reach the prompt", !/[\u0000-\u001f\u007f-\u009f]/.test(hostile), JSON.stringify(hostile.slice(0, 80)));
    const summary = hostile.slice(hostile.indexOf(": ") + 2);
    assert("A19 the argument summary is at most 120 characters and the whole message fits the 200 the prompt keeps", summary.length <= 120 && hostile.length <= 200, `summary ${summary.length}, total ${hostile.length}`);
    assert("A19 summarizeArgs flattens and cuts", summarizeArgs({ a: "x".repeat(300) }, 50).length === 50 && summarizeArgs({ a: "line1\nline2" }) === 'a="line1\\nline2"');
  }

  {
    // the presence seam and the gateway-console fallback
    const refused = await verifyOwnerPresence("none", "m", "ABCD");
    assert("A20 presence 'none' is refused unless SWITCHBOARD_INSECURE_APPROVAL=1", refused.ok === false && /SWITCHBOARD_INSECURE_APPROVAL/.test(refused.reason));
    process.env.SWITCHBOARD_INSECURE_APPROVAL = "1";
    let seam;
    const w = await captureStderr(async () => {
      seam = await defaultPresence(() => false)("m", "ABCD");
    });
    void w;
    delete process.env.SWITCHBOARD_INSECURE_APPROVAL;
    assert("A20 with the env switch the default provider selects presence 'none' (no prompt of any kind)", seam.ok === true && seam.method === "none");
    const warnedInsecure = await captureStderr(() => {
      process.env.SWITCHBOARD_INSECURE_APPROVAL = "1";
      mk();
      delete process.env.SWITCHBOARD_INSECURE_APPROVAL;
    });
    assert("A20 a gateway started with the seam on prints a startup warning", /SWITCHBOARD_INSECURE_APPROVAL=1/.test(warnedInsecure), warnedInsecure.slice(0, 200));

    // Windows Hello unavailable and no terminal attached to the gateway: the real TTY path (it never prompts when
    // stdin is not a terminal) must give a clear failure. This process's stdio is piped, so it is not a TTY.
    // Pin both streams to "not a terminal" for this block, so a run from an interactive shell can never block on a prompt.
    const tty = [process.stdin.isTTY, process.stdout.isTTY];
    process.stdin.isTTY = false;
    process.stdout.isTTY = false;
    const rows = [];
    const p = join(SBHOME, `ap-tty.json`);
    const A = new Approvals({ path: p, audit: (e) => rows.push(e), presence: (m, c) => verifyOwnerPresence("tty", m, c) });
    const id = A.request(baseReq({ args: { text: "tty" } })).record.id;
    const r = await A.approve(id, "cli");
    process.stdin.isTTY = tty[0];
    process.stdout.isTTY = tty[1];
    assert("A20 no Hello and no terminal on the gateway: approve fails with a clear message, nothing is approved", !r.ok && r.status === 403 && /Windows Hello/.test(r.error) && /terminal/.test(r.error) && A.get(id).status === "pending", JSON.stringify(r));
  }

  // ===================================================================================================================
  // B. THE ROUTER
  // ===================================================================================================================
  const srvCfg = (over = {}) => ({ id: "social", source: "npx", enabled: true, policy: "full", ...over });
  const gwCfg = (over = {}) => ({ default_policy: "full", tool_exposure: "namespaced", ...over });
  {
    const D = (server, tool, gateway = gwCfg(), more = []) => evaluate(server, tool, { gateway, vault: { backend: "env" }, servers: [] }, undefined, undefined, undefined, undefined, ...more);
    const table = [
      ["default read is low and allowed", srvCfg(), "get_item", "low", "allow"],
      ["default write is medium and allowed", srvCfg(), "send_note", "medium", "allow"],
      ["default full is high and needs approval", srvCfg(), "delete_thing", "high", "approval_required"],
      ["an outward server's write is high and needs approval", srvCfg({ outward: true }), "send_note", "high", "approval_required"],
      ["an outward server's read stays low and is allowed", srvCfg({ outward: true }), "get_item", "low", "allow"],
      ["an outward server's full is high", srvCfg({ outward: true }), "delete_thing", "high", "approval_required"],
      ["a tool risk override beats outward (the operator's word, downwards)", srvCfg({ outward: true, tools: { send_note: { risk: "low" } } }), "send_note", "low", "allow"],
      ["a tool risk override can also raise (a read pinned high)", srvCfg({ tools: { get_item: { risk: "high" } } }), "get_item", "high", "approval_required"],
      ["risk_defaults.write high makes writes need approval", srvCfg({ risk_defaults: { write: "high" } }), "send_note", "high", "approval_required"],
      ["risk_defaults.full low lets a destructive tool through (the operator's call)", srvCfg({ risk_defaults: { full: "low" } }), "delete_thing", "low", "allow"],
      ["outward raises a risk_defaults.write of low to high", srvCfg({ outward: true, risk_defaults: { write: "low" } }), "send_note", "high", "approval_required"],
      ["the server's scope rule (approval.require_for) still gates a low-risk call: the two are OR-ed", srvCfg({ approval: { require_for: ["write"] }, tools: { send_note: { risk: "low" } } }), "send_note", "low", "approval_required"],
    ];
    for (const [label, s, tool, risk, decision] of table) {
      const d = D(s, tool);
      assert(`B1 risk table: ${label}`, d.risk === risk && d.decision === decision, `${d.risk}/${d.decision}: ${d.reason}`);
    }
    const opt = (rr) => gwCfg({ approval: { require_for_risk: rr } });
    assert("B1 require_for_risk [medium, high] gates a write", D(srvCfg(), "send_note", opt(["medium", "high"])).decision === "approval_required");
    assert("B1 require_for_risk [] switches the risk rule off (a high-risk call is allowed)", D(srvCfg(), "delete_thing", opt([])).decision === "allow" && D(srvCfg(), "delete_thing", opt([])).risk === "high");
    assert("B1 a scope ceiling still denies first (server policy write, delete_thing)", D(srvCfg({ policy: "write" }), "delete_thing").decision === "deny");
    assert("B1 the client risk ceiling denies above max_risk and names it (SB_POLICY_DENY path)", (() => {
      const d = D(srvCfg(), "send_note", gwCfg(), [{ risk: "low", client: "c1" }]);
      return d.decision === "deny" && /max_risk/.test(d.reason) && /client 'c1'/.test(d.reason) && d.risk === "medium";
    })());
    assert("B1 ...and allows at or below it", D(srvCfg(), "get_item", gwCfg(), [{ risk: "low", client: "c1" }]).decision === "allow" && D(srvCfg(), "send_note", gwCfg(), [{ risk: "medium", client: "c1" }]).decision === "allow");
    assert("B1 ...a high-risk call at max_risk high still needs approval, one above max_risk medium is denied", D(srvCfg({ outward: true }), "send_note", gwCfg(), [{ risk: "high", client: "c1" }]).decision === "approval_required" && D(srvCfg({ outward: true }), "send_note", gwCfg(), [{ risk: "medium", client: "c1" }]).decision === "deny");
    assert("B1 resolveRisk is the pure function behind it", resolveRisk({}, "write") === "medium" && resolveRisk({ outward: true }, "read") === "low" && resolveRisk({ outward: true }, "write", { risk: "medium" }) === "medium");
  }

  // a Router over an outward server, a real Approvals with an injected presence provider
  async function rig({ server = {}, gateway = {}, clients, resources = false, approvalsOpts = {} } = {}) {
    const up = makeUpstream("social", { resources });
    const registry = new Registry(new Vault("env"));
    const scfg = srvCfg({ source: "local", outward: true, ...server });
    await registry.mountLocal(scfg, up.server);
    const st = { ok: true, prompts: [] };
    const approvals = new Approvals({
      path: join(SBHOME, `rig-${++fileSeq}.json`),
      presence: async (m) => {
        st.prompts.push(m);
        return st.ok ? { ok: true, method: "none" } : { ok: false, method: "hello", reason: "declined" };
      },
      ...approvalsOpts,
    });
    const cfg = { gateway: gwCfg(gateway), vault: { backend: "env" }, servers: [], settings: {}, ...(clients ? { clients } : {}) };
    const router = new Router(registry, cfg, (r) => r, approvals);
    return { router, approvals, executed: up.executed, cfg, scfg, st };
  }
  const P = (id, client = null) => ({ id, client, via: "apikey" });

  {
    const { router, approvals, executed } = await rig();
    const args = { text: "post this", token: "agent-supplied" };
    const r1 = await router.callTool("social__send_note", args, P("k1", null));
    const sb = parseSb(r1);
    assert("B2 a high-risk call returns isError with SB_APPROVAL_PENDING and executes nothing", r1.isError === true && sb?.code === SB_ERR.APPROVAL_PENDING && executed.length === 0, JSON.stringify(sb)?.slice(0, 300));
    assert("B2 it carries the approval id, the expiry, the risk and the hint", /^ap_[A-Z2-9]{8}$/.test(sb?.approval_id ?? "") && !Number.isNaN(Date.parse(sb?.expires)) && sb?.risk === "high" && sb?.hint === SB_HINTS[SB_ERR.APPROVAL_PENDING]);
    assert("B2 it carries the exact owner instruction (field and message)", sb?.instruction === INSTRUCTION(sb.approval_id) && sb.error.includes(INSTRUCTION(sb.approval_id)), sb?.error);
    assert("B2 the pending record is bound to the arguments exactly as the client sent them", approvals.get(sb.approval_id)?.args_sha256 === refHash(args));
    const id = sb.approval_id;

    const rA = await router.callTool("social__send_note", args, P("k1", null));
    assert("B2 repeating the call before approval returns the SAME id (idempotent for the client)", parseSb(rA)?.approval_id === id && executed.length === 0);
    const ap = await approvals.approve(id, "cli");
    assert("B2 the owner approves the record", ap.ok === true);
    const r2 = await router.callTool("social__send_note", args, P("k1", null));
    assert("B2 the identical call now executes, once", !r2.isError && executed.length === 1 && executed[0].name === "send_note" && same(executed[0].args, args), JSON.stringify(r2).slice(0, 200));
    const r3 = await router.callTool("social__send_note", args, P("k1", null));
    const sb3 = parseSb(r3);
    assert("B2 the third identical call needs a new approval and does not execute", sb3?.code === SB_ERR.APPROVAL_PENDING && sb3.approval_id !== id && executed.length === 1);
    await approvals.approve(sb3.approval_id, "cli");
    const rOther = await router.callTool("social__send_note", { ...args, text: "different" }, P("k1", null));
    assert("B2 an approval for one set of arguments does not cover other arguments", parseSb(rOther)?.code === SB_ERR.APPROVAL_PENDING && executed.length === 1);
    const rPrin = await router.callTool("social__send_note", args, P("k2", null));
    assert("B2 ...nor another principal calling with the same arguments", parseSb(rPrin)?.code === SB_ERR.APPROVAL_PENDING && executed.length === 1);
    const rIn = await router.callTool("social__send_note", args);
    assert("B2 ...nor an internal call (no principal)", parseSb(rIn)?.code === SB_ERR.APPROVAL_PENDING && executed.length === 1);
    const r4 = await router.callTool("social__send_note", args, P("k1", null));
    assert("B2 the first principal still holds its approval for the exact call", !r4.isError && executed.length === 2);

    const rows = recentAudit(3000);
    const forId = (aid) => rows.filter((r) => r.approval_id === aid).map((r) => `${r.tool}:${r.decision}`);
    const trail = forId(id);
    assert("B2 audit rows: approval_required, approved and consumed carry the approval id", ["approval.approval_required:approval_required", "approval.approved:allow", "approval.consumed:allow"].every((t) => trail.includes(t)), trail.join(","));
    const exec = rows.find((r) => r.server === "social" && r.tool === "send_note" && r.decision === "allow" && r.approval_id === id);
    assert("B2 the executed call's own row carries the approval id, risk high, the principal and reason approved", exec?.risk === "high" && exec?.principal === "apikey:k1" && exec?.reason === "approved", JSON.stringify(exec));
    const denied = rows.find((r) => r.tool === "approval.approved" && r.approval_id === id);
    assert("B2 the approved row names the owner channel and risk", denied?.principal === "owner:cli" && denied?.risk === "high");
  }

  {
    // the hash is taken before secret injection
    const { router, approvals, executed } = await rig({ server: { tools: { send_note: { inject_args: { token: "SECRET-INJECTED-VALUE-123" } } } } });
    const args = { text: "inject test" };
    const sb = parseSb(await router.callTool("social__send_note", args, P("k1")));
    const rec = approvals.get(sb.approval_id);
    assert("B3 the args hash is over the client's arguments, taken BEFORE secret injection", rec.args_sha256 === refHash(args));
    assert("B3 the injected secret appears nowhere in the stored record or its preview", !JSON.stringify(readStore(approvals.filePath)).includes("SECRET-INJECTED-VALUE-123") && !JSON.stringify(rec).includes("SECRET-INJECTED-VALUE-123"));
    await approvals.approve(sb.approval_id, "cli");
    const done = await router.callTool("social__send_note", args, P("k1"));
    assert("B3 after approval the call runs and the upstream receives the injected value (the approval matched the client's own arguments)", !done.isError && executed.length === 1 && executed[0].args.token === "SECRET-INJECTED-VALUE-123" && executed[0].args.text === "inject test");
  }

  {
    // client max_risk through the Router
    const clients = {
      lowc: { servers: ["*"], max_risk: "low" },
      medc: { servers: ["*"], max_risk: "medium" },
      highc: { servers: ["*"], max_risk: "high" },
      plain: { servers: ["*"] },
    };
    const { router, approvals, executed } = await rig({ clients });
    const pend = () => approvals.list().pending.length;
    const lowW = await router.callTool("social__send_note", { text: "a" }, P("kl", "lowc"));
    assert("B4 a client with max_risk low is refused a (here high-risk) write: SB_POLICY_DENY naming max_risk", parseSb(lowW)?.code === SB_ERR.POLICY_DENY && /max_risk/.test(parseSb(lowW).error) && /client 'lowc'/.test(parseSb(lowW).error));
    assert("B4 ...and no approval was created for it (a client cannot put a forbidden call in front of the owner)", pend() === 0 && executed.length === 0);
    const lowR = await router.callTool("social__get_item", {}, P("kl", "lowc"));
    assert("B4 the same client may still make low-risk calls", !lowR.isError && executed.length === 1);
    const medH = await router.callTool("social__send_note", { text: "b" }, P("km", "medc"));
    assert("B4 max_risk medium: the outward server's write is high risk, so denied", parseSb(medH)?.code === SB_ERR.POLICY_DENY && /max_risk/.test(parseSb(medH).error) && pend() === 0);
    const highH = await router.callTool("social__send_note", { text: "c" }, P("kh", "highc"));
    assert("B4 max_risk high: allowed to ask, and the call needs an approval (high still needs approval)", parseSb(highH)?.code === SB_ERR.APPROVAL_PENDING && pend() === 1);
    const plainH = await router.callTool("social__send_note", { text: "d" }, P("kp", "plain"));
    assert("B4 a client with no max_risk has no extra cap (high needs approval)", parseSb(plainH)?.code === SB_ERR.APPROVAL_PENDING && pend() === 2);
    const rowsB = recentAudit(500);
    assert("B4 the denial is audited with the client, the risk and SB_POLICY_DENY", rowsB.some((r) => r.client === "lowc" && r.decision === "deny" && r.error_code === "SB_POLICY_DENY" && r.risk === "high" && /max_risk/.test(r.reason)));
  }

  {
    // the kill switch, before and after an approval
    const { router, approvals, executed } = await rig();
    const args = { text: "kill test" };
    const id = parseSb(await router.callTool("social__send_note", args, P("k1"))).approval_id;
    await approvals.approve(id, "dashboard");
    setKillFile(true);
    const k = await router.callTool("social__send_note", args, P("k1"));
    assert("B5 an approved call is still refused while the kill switch is on (SB_KILL_SWITCH)", parseSb(k)?.code === SB_ERR.KILL_SWITCH && executed.length === 0);
    assert("B5 the refused call did not burn the approval", approvals.get(id).status === "approved");
    setKillFile(false);
    const ok = await router.callTool("social__send_note", args, P("k1"));
    assert("B5 once the switch is cleared the same approval is used", !ok.isError && executed.length === 1 && approvals.get(id).status === "consumed");
    setKillFile(true);
    const none = parseSb(await router.callTool("social__send_note", { text: "new" }, P("k1")));
    setKillFile(false);
    assert("B5 with the switch on, a call that needs approval creates no approval request", none?.code === SB_ERR.KILL_SWITCH && approvals.list().pending.length === 0);
  }

  {
    // wait_seconds
    const { router, approvals, executed } = await rig({ gateway: { approval: { wait_seconds: 3 } } });
    const args = { text: "wait path" };
    const t0 = Date.now();
    const pendingCall = router.callTool("social__send_note", args, P("k1"));
    await sleep(400);
    const id = approvals.list().pending[0]?.id;
    await approvals.approve(id, "dashboard");
    const res = await pendingCall;
    const dt = Date.now() - t0;
    assert("B6 with wait_seconds the call holds until the owner approves, then executes in the same call", !res.isError && executed.length === 1 && dt < 2500, `${dt} ms ${JSON.stringify(res).slice(0, 120)}`);

    const t1 = Date.now();
    const timedOut = await (async () => {
      const r = await rig({ gateway: { approval: { wait_seconds: 1 } } });
      const x = await r.router.callTool("social__send_note", { text: "nobody" }, P("k1"));
      return { x, executed: r.executed.length };
    })();
    const dt1 = Date.now() - t1;
    assert("B6 nobody decides: after wait_seconds it returns SB_APPROVAL_PENDING (and has waited about that long)", parseSb(timedOut.x)?.code === SB_ERR.APPROVAL_PENDING && timedOut.executed === 0 && dt1 >= 900 && dt1 < 4000, `${dt1} ms`);

    const r2 = await rig({ gateway: { approval: { wait_seconds: 3 } } });
    const call2 = r2.router.callTool("social__send_note", { text: "deny me" }, P("k1"));
    await sleep(300);
    r2.approvals.deny(r2.approvals.list().pending[0].id, "cli");
    const res2 = parseSb(await call2);
    assert("B6 denied while waiting: SB_APPROVAL_DENIED, nothing executes, a deny row is audited", res2?.code === SB_ERR.APPROVAL_DENIED && /denied by the owner/.test(res2.error) && r2.executed.length === 0 && res2.hint === SB_HINTS[SB_ERR.APPROVAL_DENIED]);

    const r3 = await rig({ gateway: { approval: { wait_seconds: 4 } } });
    const call3 = r3.router.callTool("social__send_note", { text: "kill during wait" }, P("k1"));
    await sleep(300);
    const id3 = r3.approvals.list().pending[0].id;
    setKillFile(true);
    await r3.approvals.approve(id3, "dashboard");
    const res3 = parseSb(await call3);
    setKillFile(false);
    assert("B6 the kill switch thrown while the call waits is re-checked after the wait: SB_KILL_SWITCH, nothing executes", res3?.code === SB_ERR.KILL_SWITCH && r3.executed.length === 0, JSON.stringify(res3)?.slice(0, 200));
    assert("B6 ...and the approval was not burned", r3.approvals.get(id3).status === "approved");
    const again = await r3.router.callTool("social__send_note", { text: "kill during wait" }, P("k1"));
    assert("B6 ...so after the switch is cleared the call executes", !again.isError && r3.executed.length === 1);
  }

  {
    // resources/read behind an approval gate (a risk override on the pseudo tool)
    const { router, approvals, executed } = await rig({ resources: true, server: { tools: { "resources/read": { risk: "high" } } } });
    let err1;
    try {
      await router.readResource("res://secret/1", P("k1"));
    } catch (e) {
      err1 = e;
    }
    assert("B7 resources/read of a high-risk surface is refused with SB_APPROVAL_PENDING carrying the id", err1?.data?.code === "SB_APPROVAL_PENDING" && /^ap_/.test(err1.data.approval_id ?? "") && executed.length === 0, String(err1?.message).slice(0, 200));
    await approvals.approve(err1.data.approval_id, "cli");
    const read = await router.readResource("res://secret/1", P("k1"));
    assert("B7 after approval the read goes through, once", read.contents?.[0]?.text === "SECRET-BODY" && executed.length === 1);
    let err2;
    try {
      await router.readResource("res://secret/1", P("k1"));
    } catch (e) {
      err2 = e;
    }
    assert("B7 and the next read needs a new approval", err2?.data?.code === "SB_APPROVAL_PENDING" && err2.data.approval_id !== err1.data.approval_id);
  }

  {
    // an unusable store refuses the call; the flood cap is a rate limit
    const { router, approvals, executed } = await rig();
    writeFileSync(approvals.filePath, "{ broken");
    const res = parseSb(await router.callTool("social__send_note", { text: "x" }, P("k1")));
    assert("B8 a damaged approvals.json refuses the call (SB_APPROVAL_DENIED, 'approval store'), it never reads as 'no approval needed'", res?.code === SB_ERR.APPROVAL_DENIED && /approval store/.test(res.error) && executed.length === 0, JSON.stringify(res)?.slice(0, 200));
    rmSync(approvals.filePath, { force: true });
    let last;
    for (let i = 0; i < 17; i++) last = parseSb(await router.callTool("social__send_note", { text: `flood ${i}` }, P("kf")));
    assert("B8 a caller flooding distinct requests is refused as SB_RATE_LIMITED after 16 undecided ones", last?.code === SB_ERR.RATE_LIMITED && executed.length === 0, JSON.stringify(last)?.slice(0, 160));
  }

  {
    // SWITCHBOARD_AUTO_APPROVE through the Router, and the notification webhook semantics are covered by verify-webhook
    process.env.SWITCHBOARD_AUTO_APPROVE = "1";
    let ran;
    let ex;
    try {
      const { router, executed } = await rig();
      ran = await router.callTool("social__send_note", { text: "auto" }, P("k1"));
      ex = executed.length;
    } finally {
      delete process.env.SWITCHBOARD_AUTO_APPROVE;
    }
    assert("B9 SWITCHBOARD_AUTO_APPROVE=1 keeps working for harnesses: the gated call executes at once", !ran.isError && ex === 1);
    assert("B9 ...and its audit row says env-auto", recentAudit(300).some((r) => r.tool === "approval.approved" && /env-auto/.test(r.reason)));
  }

  // ===================================================================================================================
  // C. THE HTTP SURFACES, IN-PROCESS
  // ===================================================================================================================
  {
    const port = await freePort();
    const prompts = [];
    const st = { ok: true };
    const approvals = new Approvals({
      path: join(SBHOME, "approvals.json"),
      presence: async (m) => {
        prompts.push(m);
        return st.ok ? { ok: true, method: "none" } : { ok: false, method: "hello", reason: "declined" };
      },
    });
    const scfg = srvCfg({ source: "local", outward: true });
    const cfg = {
      gateway: { transport: ["http"], http: { host: "127.0.0.1", port, require_auth: "auto" }, tool_exposure: "namespaced", default_policy: "full" },
      vault: { backend: "env" },
      servers: [scfg],
      settings: {},
      clients: { codex: { servers: ["*"] } },
    };
    const gw = new Gateway(cfg, { approvals });
    gateways.push(gw);
    const up = makeUpstream("social");
    await gw.registry.mountLocal(scfg, up.server);
    const dash = await startDashboard(gw, cfg);
    handles.push(dash);
    const login = async () => {
      const code = new LoginCodeStore().mint();
      const r = await raw(port, "POST", "/api/session", { body: { code } });
      const sid = /switchboard_session=([^;]+)/.exec(r.headers["set-cookie"]?.[0] ?? "")?.[1];
      return { cookie: `switchboard_session=${sid}`, csrf: jsonOf(r).csrf };
    };
    const sess = await login();
    const withS = { cookie: sess.cookie };
    const withC = { cookie: sess.cookie, headers: { "x-switchboard-csrf": sess.csrf } };
    const mkPending = async (text) => parseSb(await gw.router.callTool("social__send_note", { text }, P("kc", "codex"))).approval_id;

    const idA = await mkPending("via dashboard");
    const list = await raw(port, "GET", "/api/approvals", withS);
    const lj = jsonOf(list);
    const row = lj.pending?.find((a) => a.id === idA);
    assert("C1 GET /api/approvals lists the pending record with client, server, tool, risk, argument preview and expiry", list.status === 200 && row && row.client === "codex" && row.server === "social" && row.tool === "send_note" && row.risk === "high" && same(row.args_preview, { text: "via dashboard" }) && Date.parse(row.expires) > Date.parse(lj.now));
    assert("C1 the payload carries the TTL, the rule and the harness-switch flags, and never an HMAC", lj.ttl_seconds === 900 && same(lj.require_for_risk, ["high"]) && lj.auto_approve === false && lj.insecure_presence === false && !list.body.includes('"mac"'));
    assert("C1 an owner session is required to read it", (await raw(port, "GET", "/api/approvals")).status === 401);
    assert("C1 approving without the CSRF header is refused before any prompt", (await raw(port, "POST", `/api/approvals/${idA}/approve`, { ...withS, body: {} })).status === 403 && prompts.length === 0);

    st.ok = false;
    const noPresence = await raw(port, "POST", `/api/approvals/${idA}/approve`, { ...withC, body: {} });
    assert("C2 dashboard approve: a refused presence check leaves it pending (403 SB_PRESENCE_FAILED)", noPresence.status === 403 && jsonOf(noPresence).code === "SB_PRESENCE_FAILED" && gw.approvals.get(idA).status === "pending", noPresence.body.slice(0, 200));
    st.ok = true;
    const okD = await raw(port, "POST", `/api/approvals/${idA}/approve`, { ...withC, body: {} });
    assert("C2 dashboard approve routes through the gateway presence check (the injected provider ran, with the exact message)", okD.status === 200 && jsonOf(okD).approval?.status === "approved" && prompts.includes('Approve send_note on social for codex: text="via dashboard"'), `${okD.status} ${JSON.stringify(prompts)}`);

    const ctlToken = CKEY.readControlKey();
    const ctl = { headers: { authorization: `Bearer ${ctlToken}` } };
    assert("C3 the gateway wrote a control key at start, wrapped for the OS user", typeof ctlToken === "string" && ctlToken.startsWith("sbc_"));
    if (isOsProtected()) assert("C3 at rest the control key file is not the plaintext token", !readFileSync(CKEY.controlKeyPath()).includes(Buffer.from(ctlToken)));
    const idB = await mkPending("via control api");
    const before = prompts.length;
    assert("C3 the control API refuses no credential (401)", (await raw(port, "GET", "/api/control/approvals")).status === 401);
    assert("C3 ...an owner session alone does not open it (401)", (await raw(port, "GET", "/api/control/approvals", withC)).status === 401);
    assert("C3 ...a wrong token is refused (401), as is a malformed one", (await raw(port, "GET", "/api/control/approvals", { headers: { authorization: `Bearer ${CKEY.newControlToken()}` } })).status === 401 && (await raw(port, "GET", "/api/control/approvals", { headers: { authorization: "Bearer nope" } })).status === 401);
    assert("C3 ...a client API key is refused too", (await raw(port, "GET", "/api/control/approvals", { headers: { authorization: "Bearer sb_notakey" } })).status === 401);
    assert("C3 ...and the control token does not open the owner routes", (await raw(port, "GET", "/api/state", ctl)).status === 401 && (await raw(port, "POST", "/api/kill", { ...ctl, body: { on: true } })).status === 401);
    const cl = await raw(port, "GET", "/api/control/approvals", ctl);
    assert("C3 with the control token the pending list is readable", cl.status === 200 && jsonOf(cl).pending.some((a) => a.id === idB));
    st.ok = false;
    const ctlNo = await raw(port, "POST", `/api/control/approvals/${idB}/approve`, { ...ctl, body: {} });
    assert("C4 control API approve ALSO needs the gateway presence check: refused presence leaves it pending", ctlNo.status === 403 && jsonOf(ctlNo).code === "SB_PRESENCE_FAILED" && gw.approvals.get(idB).status === "pending" && prompts.length === before + 1);
    st.ok = true;
    const ctlOk = await raw(port, "POST", `/api/control/approvals/${idB}/approve`, { ...ctl, body: {} });
    assert("C4 ...and with presence it approves, through the same message", ctlOk.status === 200 && gw.approvals.get(idB).status === "approved" && gw.approvals.get(idB).decided_via === "cli" && prompts[prompts.length - 1] === 'Approve send_note on social for codex: text="via control api"', JSON.stringify(prompts.slice(-2)));
    assert("C4 and the dashboard approval was recorded as decided via the dashboard", gw.approvals.get(idA).decided_via === "dashboard");

    const idC = await mkPending("deny me");
    const pn = prompts.length;
    const ctlDeny = await raw(port, "POST", `/api/control/approvals/${idC}/deny`, { ...ctl, body: {} });
    assert("C5 deny through the control API needs no presence prompt", ctlDeny.status === 200 && gw.approvals.get(idC).status === "denied" && prompts.length === pn);
    const idD = await mkPending("deny from dashboard");
    const dDeny = await raw(port, "POST", `/api/approvals/${idD}/deny`, { ...withC, body: {} });
    assert("C5 deny through the dashboard likewise", dDeny.status === 200 && gw.approvals.get(idD).status === "denied" && prompts.length === pn);
    const again = await raw(port, "POST", `/api/approvals/${idD}/approve`, { ...withC, body: {} });
    assert("C5 approving a denied request is a 409 and shows no prompt", again.status === 409 && prompts.length === pn);
    assert("C5 an unknown or malformed id is a clean 404 / 400", (await raw(port, "POST", "/api/approvals/ap_ZZZZZZZZ/approve", { ...withC, body: {} })).status === 404 && (await raw(port, "POST", "/api/approvals/not-an-id/approve", { ...withC, body: {} })).status === 400);
    const st2 = await raw(port, "GET", "/api/state", withS);
    const tools = jsonOf(st2).servers?.find((s) => s.id === "social")?.tools ?? [];
    assert("C5 /api/state reports each tool's risk (outward write is high, read is low)", tools.find((t) => t.name === "send_note")?.risk === "high" && tools.find((t) => t.name === "get_item")?.risk === "low", JSON.stringify(tools).slice(0, 200));

    // a call after the dashboard approval executes through the same gateway
    const exec = await gw.router.callTool("social__send_note", { text: "via dashboard" }, P("kc", "codex"));
    assert("C6 the call approved on the dashboard executes through the gateway, once", !exec.isError && up.executed.length === 1);

    // kill switch from the dashboard
    const k0 = await raw(port, "GET", "/api/kill", withS);
    assert("C7 GET /api/kill reports the state", k0.status === 200 && jsonOf(k0).active === false);
    assert("C7 turning the kill switch ON needs only the session + CSRF", (await raw(port, "POST", "/api/kill", { ...withC, body: { on: true } })).status === 200 && existsSync(killFilePath()) && jsonOf(await raw(port, "GET", "/api/state", withS)).kill_switch?.active === true);
    const pk = prompts.length;
    st.ok = false;
    const off1 = await raw(port, "POST", "/api/kill", { ...withC, body: { on: false } });
    assert("C7 turning it OFF goes through gateway presence: refused presence keeps it on (403)", off1.status === 403 && existsSync(killFilePath()) && prompts.length === pk + 1 && /kill switch/i.test(prompts[prompts.length - 1]));
    st.ok = true;
    const off2 = await raw(port, "POST", "/api/kill", { ...withC, body: { on: false } });
    assert("C7 ...and with presence it turns off", off2.status === 200 && jsonOf(off2).active === false && !existsSync(killFilePath()));
    assert("C7 a non-boolean body is a 400", (await raw(port, "POST", "/api/kill", { ...withC, body: { on: "yes" } })).status === 400);
    const kr = recentAudit(400);
    assert("C7 the toggles are audited (kill.on, kill.off_refused, kill.off) as the dashboard owner", ["kill.on", "kill.off_refused", "kill.off"].every((t) => kr.some((r) => r.tool === t && r.principal === "owner:dashboard")));

    // the clients API behind the Clients page
    const mkc = await raw(port, "POST", "/api/clients", { ...withC, body: { id: "codex-test", servers: ["social"], max_scope: "write", max_risk: "medium", description: "oracle client" } });
    assert("C8 POST /api/clients creates a client and a key, and returns no token", mkc.status === 201 && jsonOf(mkc).client?.max_risk === "medium" && !/sb_[A-Za-z0-9_-]{20,}/.test(mkc.body), mkc.body.slice(0, 160));
    const put = await raw(port, "PUT", "/api/clients/codex-test", { ...withC, body: { servers: ["social", "voice"], max_risk: null, tools: ["social__*"] } });
    assert("C8 PUT edits the allowlist and clears a ceiling with null", put.status === 200 && same(jsonOf(put).client?.servers, ["social", "voice"]) && jsonOf(put).client?.max_risk === undefined);
    const rot = await raw(port, "POST", "/api/clients/codex-test/rotate", { ...withC, body: {} });
    assert("C8 rotate issues a new key (revoking the old) and returns no token", rot.status === 200 && jsonOf(rot).revoked === 1 && !/sb_[A-Za-z0-9_-]{20,}/.test(rot.body), rot.body.slice(0, 160));
    const rev = await raw(port, "DELETE", "/api/clients/codex-test?purge=0", { ...withC });
    const afterRev = jsonOf(await raw(port, "GET", "/api/clients", withS)).clients?.find((c) => c.id === "codex-test");
    assert("C8 DELETE ?purge=0 revokes the keys but keeps the client entry (the Revoke button)", rev.status === 200 && jsonOf(rev).purged === false && afterRev && afterRev.keys.length === 0);
    const rem = await raw(port, "DELETE", "/api/clients/codex-test", { ...withC });
    assert("C8 a plain DELETE removes the client entirely (the Remove button)", rem.status === 200 && jsonOf(rem).purged === true && !jsonOf(await raw(port, "GET", "/api/clients", withS)).clients?.some((c) => c.id === "codex-test"));

    const so = await raw(port, "DELETE", "/api/session", { ...withC });
    assert("C9 sign out drops the session server side (the Sign out button): the cookie stops working", so.status === 200 && (await raw(port, "GET", "/api/approvals", withS)).status === 401);

    await dash.close().catch(() => {});
    await gw.shutdown().catch(() => {});
    handles.splice(handles.indexOf(dash), 1);
    gateways.splice(gateways.indexOf(gw), 1);
  }

  // ===================================================================================================================
  // D. A REAL GATEWAY PROCESS AND THE REAL CLI
  // ===================================================================================================================
  {
    const homeD = join(base, "homeD");
    const sbD = join(homeD, ".switchboard");
    mkdirSync(sbD, { recursive: true });
    const stubLog = join(base, "stub.log");
    const port = await freePort();
    const cfgPath = join(base, "d.yaml");
    const q = (s) => `'${s.replace(/'/g, "''")}'`;
    writeFileSync(
      cfgPath,
      [
        "gateway:",
        "  transport: [http]",
        `  http: { host: 127.0.0.1, port: ${port}, require_auth: auto }`,
        "  tool_exposure: namespaced",
        "  default_policy: read",
        "  approval: { ttl_seconds: 120 }",
        "vault:",
        "  backend: env",
        "servers:",
        "  - id: social",
        "    source: binary",
        `    command: ${q(process.execPath)}`,
        `    args: [${q(FIXTURE_UP)}]`,
        "    enabled: true",
        "    policy: full",
        "    outward: true",
        "    env:",
        `      SB_STUB_LOG: ${q(stubLog)}`,
        "",
      ].join("\n"),
    );
    const childEnv = { ...process.env, SWITCHBOARD_HOME: sbD, HOME: homeD, USERPROFILE: homeD, NO_COLOR: "1", SWITCHBOARD_INSECURE_APPROVAL: "1" };
    const cliEnv = { ...process.env, SWITCHBOARD_HOME: sbD, HOME: homeD, USERPROFILE: homeD, NO_COLOR: "1" };
    delete cliEnv.SWITCHBOARD_INSECURE_APPROVAL;

    let gwProc;
    let gwLog = "";
    const startGateway = async () => {
      gwLog = "";
      gwProc = spawn(process.execPath, [CLI, "-c", cfgPath, "dashboard"], { env: childEnv, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
      children.add(gwProc);
      gwProc.stdout.on("data", (c) => (gwLog += c));
      gwProc.stderr.on("data", (c) => (gwLog += c));
      for (let i = 0; i < 150; i++) {
        const r = await raw(port, "GET", "/healthz");
        if (r.status === 200) return true;
        await sleep(200);
      }
      return false;
    };
    const stopGateway = async () => {
      if (gwProc) {
        killTree(gwProc);
        children.delete(gwProc);
        await sleep(400);
      }
    };
    const cli = (args, { timeoutMs = 90_000 } = {}) =>
      new Promise((resolve) => {
        const child = spawn(process.execPath, [CLI, "-c", cfgPath, ...args], { env: cliEnv, stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
        children.add(child);
        let stdout = "";
        let stderr = "";
        child.stdout.on("data", (c) => (stdout += c));
        child.stderr.on("data", (c) => (stderr += c));
        const timer = setTimeout(() => killTree(child), timeoutMs);
        child.on("close", (code) => {
          clearTimeout(timer);
          children.delete(child);
          resolve({ code, stdout: stdout.replace(/\x1b\[[0-9;]*m/g, ""), stderr: stderr.replace(/\x1b\[[0-9;]*m/g, "") });
        });
      });
    let rpcId = 100;
    const callTool = async (name, args) => {
      const r = await raw(port, "POST", "/mcp", {
        headers: { accept: "application/json, text/event-stream" },
        body: { jsonrpc: "2.0", id: ++rpcId, method: "tools/call", params: { name, arguments: args } },
      });
      let msg = null;
      if (/text\/event-stream/.test(r.headers["content-type"] ?? "")) {
        const line = r.body.split(/\r?\n/).find((l) => l.startsWith("data:"));
        try {
          msg = line ? JSON.parse(line.slice(5).trim()) : null;
        } catch {
          msg = null;
        }
      } else msg = jsonOf(r);
      const text = msg?.result?.content?.[0]?.text ?? "";
      let sb = null;
      try {
        sb = JSON.parse(text);
      } catch {
        sb = null;
      }
      return { status: r.status, isError: msg?.result?.isError === true, text, sb };
    };
    const executedCount = () => (existsSync(stubLog) ? readFileSync(stubLog, "utf8").split("\n").filter(Boolean).length : 0);
    const auditRows = () => (existsSync(join(sbD, "audit.log")) ? readFileSync(join(sbD, "audit.log"), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);

    const up = await startGateway();
    assert("D1 a real gateway process starts on an ephemeral port with the outward server mounted", up, gwLog.slice(0, 300));
    if (up) {
      const args = { text: "from the real gateway" };
      const c1 = await callTool("social__send_note", args);
      assert("D1 an HTTP /mcp tools/call of a high-risk tool returns SB_APPROVAL_PENDING and executes nothing", c1.isError && c1.sb?.code === "SB_APPROVAL_PENDING" && /^ap_/.test(c1.sb?.approval_id ?? "") && executedCount() === 0, c1.text.slice(0, 200));
      const id = c1.sb?.approval_id;

      const lst = await cli(["approvals", "list"]);
      assert("D2 `approvals list` shows the waiting call, its risk and a decide hint", lst.code === 0 && lst.stdout.includes(id) && /high/.test(lst.stdout) && /social__send_note/.test(lst.stdout) && /approvals approve/.test(lst.stdout), (lst.stdout + lst.stderr).slice(0, 300));
      const show = await cli(["approvals", "show", id]);
      assert("D2 `approvals show` prints the args hash and the arguments", show.code === 0 && show.stdout.includes(refHash(args)) && show.stdout.includes("from the real gateway"), (show.stdout + show.stderr).slice(0, 300));
      assert("D2 the CLI rejects a malformed id without calling the gateway", (await cli(["approvals", "approve", "nope"])).code === 1);

      const ap = await cli(["approvals", "approve", id]);
      assert("D3 `approvals approve` asks the running gateway, which verifies presence (seam: none) and approves", ap.code === 0 && /approved/.test(ap.stderr + ap.stdout) && /one use/.test(ap.stdout), (ap.stdout + ap.stderr).slice(0, 300));
      const c2 = await callTool("social__send_note", args);
      assert("D3 the identical call now executes, exactly once, through the real upstream process", !c2.isError && /^done:1$/.test(c2.text) && executedCount() === 1, c2.text.slice(0, 160));
      const c3 = await callTool("social__send_note", args);
      assert("D3 the next identical call needs a new approval", c3.sb?.code === "SB_APPROVAL_PENDING" && c3.sb.approval_id !== id && executedCount() === 1);

      const dn = await cli(["approvals", "deny", c3.sb.approval_id]);
      assert("D4 `approvals deny` denies (no presence needed)", dn.code === 0 && /denied/.test(dn.stderr + dn.stdout));
      const ap2 = await cli(["approvals", "approve", c3.sb.approval_id]);
      assert("D4 approving a denied request exits 1 and says so", ap2.code === 1 && /already denied/.test(ap2.stderr + ap2.stdout), (ap2.stdout + ap2.stderr).slice(0, 200));

      // an agent edits approvals.json while the gateway runs
      const storePath = join(sbD, "approvals.json");
      const fa = { text: "forged by an agent" };
      const pendingF = await callTool("social__send_note", fa);
      const live = JSON.parse(readFileSync(storePath, "utf8"));
      const forged = { ...live.approvals[0], id: "ap_FFFFFFFF", status: "approved", args_sha256: refHash({ text: "agent wants this" }), args_preview: { text: "agent wants this" }, principal: "loopback-anonymous:loopback", mac: "1".repeat(64) };
      live.approvals.push(forged);
      writeFileSync(storePath, JSON.stringify(live));
      const cf = await callTool("social__send_note", { text: "agent wants this" });
      assert("D5 a forged 'approved' record written into approvals.json does NOT let its call run", cf.sb?.code === "SB_APPROVAL_PENDING" && executedCount() === 1, cf.text.slice(0, 200));
      assert("D5 the gateway noticed and logged it", /ignored approval record ap_FFFFFFFF/.test(gwLog) && auditRows().some((r) => r.tool === "approval.ignored" && /ap_FFFFFFFF/.test(r.reason)), gwLog.slice(-300));
      // flipping a genuine pending record to approved by hand
      const live2 = JSON.parse(readFileSync(storePath, "utf8"));
      const target = live2.approvals.find((r) => r.id === pendingF.sb.approval_id);
      target.status = "approved";
      writeFileSync(storePath, JSON.stringify(live2));
      const cf2 = await callTool("social__send_note", fa);
      assert("D5 a genuine pending record flipped to approved by hand does not run either", cf2.sb?.code === "SB_APPROVAL_PENDING" && executedCount() === 1);
      writeFileSync(storePath, "{ damaged");
      const cd = await callTool("social__send_note", { text: "with a damaged store" });
      const hz = await raw(port, "GET", "/healthz");
      assert("D6 a damaged approvals.json refuses the gated call (SB_APPROVAL_DENIED) and the gateway stays up", cd.sb?.code === "SB_APPROVAL_DENIED" && /approval store/.test(cd.text) && hz.status === 200 && executedCount() === 1, cd.text.slice(0, 200));
      writeFileSync(storePath, JSON.stringify({ version: 1, approvals: [] }));

      // restart: approve a call, do not use it, restart the gateway
      const ra = { text: "survives a restart?" };
      const rid = (await callTool("social__send_note", ra)).sb.approval_id;
      const rap = await cli(["approvals", "approve", rid]);
      await stopGateway();
      const up2 = await startGateway();
      assert("D7 the gateway restarts on the same home", up2 && rap.code === 0, gwLog.slice(0, 200));
      const cr = await callTool("social__send_note", ra);
      assert("D7 an approval given before a restart does not survive it (the HMAC key lives in memory only)", cr.sb?.code === "SB_APPROVAL_PENDING" && cr.sb.approval_id !== rid && executedCount() === 1, cr.text.slice(0, 160));
      const oldId = await cli(["approvals", "approve", rid]);
      assert("D7 the old id cannot be approved after the restart (exit 1, unknown)", oldId.code === 1 && /no approval/.test(oldId.stderr + oldId.stdout), (oldId.stdout + oldId.stderr).slice(0, 200));
      assert("D7 the restart logged the ignored records from the earlier run", /earlier gateway run/.test(gwLog) || auditRows().some((r) => r.tool === "approval.ignored" && /earlier gateway run/.test(r.reason)), gwLog.slice(-200));

      const rows = auditRows();
      const byTool = (t) => rows.filter((r) => r.tool === t);
      assert("D8 the audit log has approval_required, approved, consumed and denied rows with approval ids and risk", ["approval.approval_required", "approval.approved", "approval.consumed", "approval.denied"].every((t) => byTool(t).length > 0 && byTool(t).every((r) => /^ap_/.test(r.approval_id ?? "") && r.risk)), JSON.stringify(rows.map((r) => r.tool)).slice(0, 300));
      assert("D8 the approved row came from the CLI channel", byTool("approval.approved").some((r) => r.principal === "owner:cli" && /decided_via cli/.test(r.reason)));
      // Adapted (wave 2, design 3.7): a write-scope call writes an `attempt` row ahead of the upstream call, and it carries the
      // approval id and risk too, so the RESULT row is the one that is not an attempt. The attempt row is asserted separately.
      const execRow = rows.find((r) => r.server === "social" && r.tool === "send_note" && r.decision === "allow" && r.approval_id === id && r.phase !== "attempt");
      assert("D8 the executed call's row carries the approval id and risk", execRow?.risk === "high" && execRow?.reason === "approved");
      const attemptRow = rows.find((r) => r.server === "social" && r.tool === "send_note" && r.phase === "attempt" && r.approval_id === id);
      assert("D8 ...and so does the attempt row written ahead of it, which the result row points back to", attemptRow?.risk === "high" && execRow?.attempt_seq === attemptRow?.seq && attemptRow?.seq < execRow?.seq);
      const av = await cli(["audit", "verify"]);
      assert("D8 the audit hash chain is intact with the new row types (`audit verify` exits 0)", av.code === 0 && /chain OK/.test(av.stdout), (av.stdout + av.stderr).slice(0, 200));
      const ctlFile = join(sbD, "control.key");
      const ctlBytes = existsSync(ctlFile) ? readFileSync(ctlFile) : Buffer.alloc(0);
      assert("D8 control.key exists in the home", ctlBytes.length > 0);
      if (isOsProtected()) assert("D8 and it is OS-wrapped (not a plaintext sbc_ token)", !ctlBytes.toString("latin1").includes("sbc_"));
    }
    await stopGateway();
    const noGw = await cli(["approvals", "list"], { timeoutMs: 30_000 });
    assert("D9 with no gateway running `approvals list` says so and labels the file view unverified", noGw.code === 0 && /not verified|NOT verified/.test(noGw.stderr + noGw.stdout) && /no gateway answered|no control key/.test(noGw.stderr + noGw.stdout), (noGw.stdout + noGw.stderr).slice(0, 300));
    const noGw2 = await cli(["approvals", "approve", "ap_ZZZZZZZZ"], { timeoutMs: 30_000 });
    assert("D9 with no gateway running `approvals approve` fails with a clear message (exit 1)", noGw2.code === 1 && /no gateway answered/.test(noGw2.stderr + noGw2.stdout), (noGw2.stdout + noGw2.stderr).slice(0, 300));
  }

  // ===================================================================================================================
  // E. CONFIG BOUNDS
  // ===================================================================================================================
  {
    const cfgWith = (gateway, extra = {}) => ({ gateway: { transport: ["http"], http: { host: "127.0.0.1", port: 1, require_auth: "auto" }, tool_exposure: "namespaced", default_policy: "read", ...gateway }, vault: { backend: "env" }, servers: [], ...extra });
    const ok = (g, e) => throwsMsg(() => validateConfig(cfgWith(g, e), "t")) === "";
    assert("E1 ttl_seconds: 60 and 86400 are accepted, 59 and 86401 are not", ok({ approval: { ttl_seconds: 60 } }) && ok({ approval: { ttl_seconds: 86400 } }) && !ok({ approval: { ttl_seconds: 59 } }) && !ok({ approval: { ttl_seconds: 86401 } }));
    assert("E1 wait_seconds: 0 and 50 are accepted, 51 and -1 are not", ok({ approval: { wait_seconds: 0 } }) && ok({ approval: { wait_seconds: 50 } }) && !ok({ approval: { wait_seconds: 51 } }) && !ok({ approval: { wait_seconds: -1 } }));
    assert("E1 require_for_risk takes low / medium / high only, and may be empty", ok({ approval: { require_for_risk: [] } }) && ok({ approval: { require_for_risk: ["medium", "high"] } }) && !ok({ approval: { require_for_risk: ["extreme"] } }));
    assert("E1 unknown keys under gateway.approval are refused", !ok({ approval: { ttl: 5 } }));
    const srv = (o) => ({ servers: [{ id: "s", source: "npx", package: "p", enabled: true, ...o }] });
    assert("E2 a tool 'risk' and a server 'outward' and 'risk_defaults' are accepted", ok({}, srv({ outward: true, risk_defaults: { read: "low", write: "high", full: "high" }, tools: { t: { risk: "low" } } })));
    assert("E2 a bad tool risk, a bad risk_defaults value and an unknown risk_defaults key are refused", !ok({}, srv({ tools: { t: { risk: "huge" } } })) && !ok({}, srv({ risk_defaults: { write: "huge" } })) && !ok({}, srv({ risk_defaults: { delete: "high" } })));
    assert("E2 default: no gateway.approval block is needed (every field is optional)", ok({}));
  }

  // ===================================================================================================================
  // F. STATIC FACTS
  // ===================================================================================================================
  {
    const strip = (s) => s.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
    const routerJs = strip(readFileSync(join(root, "dist", "router.js"), "utf8"));
    const gatewayJs = strip(readFileSync(join(root, "dist", "gateway.js"), "utf8"));
    const dashJs = strip(readFileSync(join(root, "dist", "dashboard.js"), "utf8"));
    assert("F1 the Router no longer imports the in-band gate (approval.js) or readline", !/from "\.\/approval\.js"/.test(routerJs) && !/readline/.test(routerJs) && /from "\.\/approvals\.js"/.test(routerJs));
    assert("F1 neither the Gateway nor the dashboard opens a readline interface on a call path", !/createInterface/.test(gatewayJs) && !/createInterface/.test(dashJs) && !/from "node:readline"/.test(dashJs));
    const approvalsJs = strip(readFileSync(join(root, "dist", "approvals.js"), "utf8"));
    assert("F2 the manager holds its HMAC key in memory: randomBytes in the class, never read from or written to disk", /randomBytes\(32\)/.test(approvalsJs) && !/writeFileSync|writeJsonAtomic\([^)]*key/i.test(approvalsJs));
    assert("F2 records are matched with a timing-safe comparison and written through the atomic watched store", /timingSafeEqual/.test(approvalsJs) && /WatchedJsonFile/.test(approvalsJs));

    const appJs = readFileSync(join(root, "public", "app.js"), "utf8");
    const indexHtml = readFileSync(join(root, "public", "index.html"), "utf8");
    const css = readFileSync(join(root, "public", "app.css"), "utf8");
    assert("F3 the dashboard has Approvals and Clients pages in the nav and the router", /href="#\/approvals"/.test(indexHtml) && /href="#\/clients"/.test(indexHtml) && /"\/approvals":\s*renderApprovals/.test(appJs) && /"\/clients":\s*renderClients/.test(appJs));
    assert("F3 the Approvals page reads /api/approvals, shows a countdown, and has Approve and Deny buttons", /\/api\/approvals/.test(appJs) && /countdown/.test(appJs) && /data-approve/.test(appJs) && /data-deny/.test(appJs) && /last \$\{history\.length\}|History/.test(appJs));
    assert("F3 the Clients page lists, adds, edits, rotates, revokes and removes", /renderClients/.test(appJs) && /method: "POST", body: JSON\.stringify\(body\)/.test(appJs) && /method: "PUT"/.test(appJs) && /\/rotate/.test(appJs) && /purge=0/.test(appJs) && /method: "DELETE"/.test(appJs));
    assert("F3 the kill switch has a banner and a toggle, and Sign out calls DELETE /api/session", /kill-banner/.test(appJs) && /id="kill-toggle"/.test(indexHtml) && /\/api\/kill/.test(appJs) && /id="sign-out"/.test(indexHtml) && /"\/api\/session", \{ method: "DELETE" \}/.test(appJs));
    assert("F3 the page keeps its one fetch wrapper, no inline handlers and no eval (CSP)", (appJs.match(/\bfetch\(/g) ?? []).length === 1 && !/\son(error|load|click|change|input|submit)\s*=\s*["'\\]/i.test(appJs) && !/\beval\(|new Function\(/.test(appJs));
    assert("F3 the styles for the new pages exist", /\.kill-banner/.test(css) && /\.countdown/.test(css) && /\.nav-count/.test(css));

    const EM = String.fromCharCode(0x2014);
    // The dashboard and design files predate this change and contain older dashes in untouched text; only the files
    // this change created are held to zero. The pages added here (the block between the two markers) are held too.
    const created = ["src/approvals.ts", "src/controlkey.ts", "scripts/verify-approvals.mjs", "scripts/fixtures/approvals-upstream.mjs"];
    const withDash = created.filter((f) => readFileSync(join(root, f), "utf8").includes(EM));
    assert("F4 no em dash in the files this change created", withDash.length === 0, withDash.join(","));
    const chunk = appJs.slice(appJs.indexOf("// Shared bits for the owner-decision pages"), appJs.search(/\/\/ Router\r?\n/));
    assert("F4 no em dash in the dashboard pages this change added", chunk.length > 1000 && !chunk.includes(EM));
  }
} catch (err) {
  assert("oracle ran to the end without throwing", false, err && err.stack ? err.stack.split("\n").slice(0, 4).join(" | ") : String(err));
} finally {
  for (const h of handles) await h.close().catch(() => {});
  for (const g of gateways) await g.shutdown().catch(() => {});
  for (const c of children) killTree(c);
  await sleep(300);
  try {
    rmSync(base, { recursive: true, force: true });
  } catch {
    /* leftovers in temp are harmless */
  }
}

const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
process.exit(failed.length === 0 ? 0 : 1);
