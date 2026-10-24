// Deterministic oracle: MCP Switchboard serves BOTH protocol eras from one /mcp endpoint and from stdio.
//   modern  = MCP 2026-07-28 (stateless, no initialize, server/discover, MCP-Protocol-Version + Mcp-Method +
//             Mcp-Name headers, per-request _meta envelope, resultType)
//   legacy  = handshake era (2025-11-25, 2025-06-18, 2025-03-26)
// It drives the REAL compiled gateway (dist/gateway.js, dist/router.js, dist/dashboard.js mountMcpEndpoint) and the
// REAL compiled CLI over stdio. No network beyond 127.0.0.1 ephemeral ports (never 8088), no provider calls,
// no model tokens. Sandboxed SWITCHBOARD_HOME. Build first.
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { createServer } from "node:net";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const tmp = mkdtempSync(join(tmpdir(), "sb-dualera-"));
process.env.SWITCHBOARD_HOME = join(tmp, "sbhome");
process.env.HOME = tmp;
process.env.USERPROFILE = tmp;
process.env.APPDATA = join(tmp, "appdata");
process.env.LOCALAPPDATA = join(tmp, "local");
for (const dir of [process.env.SWITCHBOARD_HOME, process.env.APPDATA, process.env.LOCALAPPDATA]) mkdirSync(dir, { recursive: true });
delete process.env.SWITCHBOARD_AUTO_APPROVE;

import { Server } from "@modelcontextprotocol/server";
import { Client as V2Client, StreamableHTTPClientTransport as V2Http } from "@modelcontextprotocol/client";
import { StdioClientTransport as V2Stdio, getDefaultEnvironment } from "@modelcontextprotocol/client/stdio";

const { Gateway } = await import("../dist/gateway.js");
const { startDashboard } = await import("../dist/dashboard.js");
const { startMcpListener } = await import("../dist/expose.js");
const { ApiKeyStore } = await import("../dist/apikeys.js");
const { readClientKey } = await import("../dist/clientkeys.js");
const { ownerSession, loopback } = await import("./lib/owner.mjs");

let V1 = null; // optional: a genuine SDK 1.x client, the strongest evidence for "handshake-era clients"
try {
  const c = await import("@modelcontextprotocol/sdk/client/index.js");
  const h = await import("@modelcontextprotocol/sdk/client/streamableHttp.js");
  const s = await import("@modelcontextprotocol/sdk/client/stdio.js");
  V1 = { Client: c.Client, Http: h.StreamableHTTPClientTransport, Stdio: s.StdioClientTransport };
} catch {
  /* 1.x SDK not installed: raw JSON-RPC covers the handshake era */
}

const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? `: ${detail}` : ""}`);
};
const freePort = () =>
  new Promise((res) => {
    const s = createServer();
    s.listen(0, "127.0.0.1", () => {
      const p = s.address().port;
      s.close(() => res(p));
    });
  });
const ENV = (v = "2026-07-28") => ({
  "io.modelcontextprotocol/protocolVersion": v,
  "io.modelcontextprotocol/clientInfo": { name: "verify-dualera", version: "0" },
  "io.modelcontextprotocol/clientCapabilities": {},
});
const unwrap = async (res) => {
  const text = await res.text();
  if (!text) return undefined;
  if ((res.headers.get("content-type") ?? "").includes("text/event-stream")) {
    const data = text.split("\n").find((l) => l.startsWith("data:"));
    return data ? JSON.parse(data.slice(5)) : undefined;
  }
  try { return JSON.parse(text); } catch { return { _raw: text.slice(0, 200) }; }
};
const post = async (url, body, headers = {}) => {
  const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", ...headers }, body: JSON.stringify(body) });
  return { status: res.status, ct: res.headers.get("content-type") ?? "", allow: res.headers.get("allow"), www: res.headers.get("www-authenticate"), msg: await unwrap(res) };
};
const jsonOf = (response) => {
  try { return JSON.parse(response.body); } catch { return {}; }
};

// ---- one real upstream, in-process, mounted exactly like council/app2mcp (registry.mountLocal) ----------------
function makeUpstream() {
  const s = new Server({ name: "up", version: "0.0.0" }, { capabilities: { tools: {} } });
  s.setRequestHandler("tools/list", async () => ({
    tools: [{ name: "get_sum", description: "sum", inputSchema: { type: "object", properties: { a: { type: "number" }, b: { type: "number" } }, required: ["a", "b"] } }],
  }));
  s.setRequestHandler("tools/call", async (req) => {
    const a = req.params.arguments ?? {};
    return { content: [{ type: "text", text: String(Number(a.a) + Number(a.b)) }] };
  });
  return s;
}
const portA = await freePort();
const portB = await freePort();
const cfg = { gateway: { transport: ["http"], http: { host: "127.0.0.1", port: portA, require_auth: "auto" }, tool_exposure: "namespaced", default_policy: "read" }, vault: { backend: "encrypted-file" }, servers: [], settings: {} };
const gateway = new Gateway(cfg);
await gateway.registry.mountLocal({ id: "up", source: "app2mcp", enabled: true, policy: "write" }, makeUpstream());
const TOOL = "up__get_sum";
assert("gateway exposes the namespaced upstream tool", gateway.router.listTools().some((t) => t.name === TOOL), gateway.router.listTools().map((t) => t.name).join(","));

// ---- endpoint A: the real dashboard boundary; endpoint B: the real JSON-only expose boundary -------------------
const dashA = await startDashboard(gateway, cfg);
const owner = await ownerSession(portA);
const added = await loopback(portA, "POST", "/api/clients", {
  headers: owner.hdrC,
  body: { id: "dualera", servers: ["up"], max_scope: "write" },
});
const token = readClientKey("dualera");
const apiKeys = new ApiKeyStore();
const listenerB = await startMcpListener(gateway, "127.0.0.1", portB, apiKeys, { clients: () => cfg.clients });
const A = `http://127.0.0.1:${portA}/mcp`;
const B = `http://127.0.0.1:${portB}/mcp`;

assert(
  "an owner session created a configured client and its bound key without returning plaintext",
  owner.status === 200 && added.status === 201 && typeof token === "string" && token.length > 10 && !jsonOf(added).token,
  JSON.stringify({ owner: owner.status, add: added.status }),
);
const auth = { authorization: `Bearer ${token}` };
const postA = (body, headers = {}) => post(A, body, { ...auth, ...headers });
const countedFetch = (counter) => async (input, init) => {
  const method = String(init?.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();
  if (method === "GET") counter.count += 1;
  return fetch(input, init);
};

try {
  // =========================================================================================== HTTP, modern
  {
    const rd = await postA({ jsonrpc: "2.0", id: 1, method: "server/discover", params: { _meta: ENV() } }, { "mcp-protocol-version": "2026-07-28", "mcp-method": "server/discover" });
    assert("modern: server/discover -> 200 listing 2026-07-28 with resultType=complete", rd.status === 200 && rd.msg?.result?.supportedVersions?.includes("2026-07-28") && rd.msg?.result?.resultType === "complete", JSON.stringify({ status: rd.status, v: rd.msg?.result?.supportedVersions }));
    assert("modern: server/discover advertises tools, resources and prompts capabilities", ["tools", "resources", "prompts"].every((k) => rd.msg?.result?.capabilities?.[k]), JSON.stringify(rd.msg?.result?.capabilities));
    assert("modern: server/discover names the gateway (serverInfo)", rd.msg?.result?._meta?.["io.modelcontextprotocol/serverInfo"]?.name === "switchboard", JSON.stringify(rd.msg?.result?._meta));

    const hdr = { "mcp-protocol-version": "2026-07-28", "mcp-method": "tools/call", "mcp-name": TOOL };
    const rc = await postA({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: TOOL, arguments: { a: 20, b: 22 }, _meta: ENV() } }, hdr);
    assert("modern: tools/call through the router -> 42 with resultType=complete", rc.msg?.result?.content?.[0]?.text === "42" && rc.msg?.result?.resultType === "complete", JSON.stringify(rc.msg));
    const rl = await postA({ jsonrpc: "2.0", id: 3, method: "tools/list", params: { _meta: ENV() } }, { "mcp-protocol-version": "2026-07-28", "mcp-method": "tools/list" });
    assert("modern: tools/list carries ttlMs and cacheScope", rl.msg?.result?.tools?.some((t) => t.name === TOOL) && typeof rl.msg?.result?.ttlMs === "number" && typeof rl.msg?.result?.cacheScope === "string", JSON.stringify({ ttl: rl.msg?.result?.ttlMs, scope: rl.msg?.result?.cacheScope }));
    const rr = await postA({ jsonrpc: "2.0", id: 4, method: "resources/list", params: { _meta: ENV() } }, { "mcp-protocol-version": "2026-07-28", "mcp-method": "resources/list" });
    assert("modern: resources/list answers (empty list, no error)", Array.isArray(rr.msg?.result?.resources), JSON.stringify(rr.msg));
    const rp = await postA({ jsonrpc: "2.0", id: 5, method: "prompts/list", params: { _meta: ENV() } }, { "mcp-protocol-version": "2026-07-28", "mcp-method": "prompts/list" });
    assert("modern: prompts/list answers (empty list, no error)", Array.isArray(rp.msg?.result?.prompts), JSON.stringify(rp.msg));
    assert("modern: result _meta names the gateway, never the upstream", rc.msg?.result?._meta?.["io.modelcontextprotocol/serverInfo"]?.name === "switchboard", JSON.stringify(rc.msg?.result?._meta));

    const noHdr = await postA({ jsonrpc: "2.0", id: 6, method: "tools/call", params: { name: TOOL, arguments: { a: 1, b: 1 }, _meta: ENV() } }, { "mcp-protocol-version": "2026-07-28" });
    assert("modern: missing Mcp-Method/Mcp-Name headers -> 400 with -32020", noHdr.status === 400 && noHdr.msg?.error?.code === -32020, JSON.stringify({ s: noHdr.status, c: noHdr.msg?.error?.code }));
    const badName = await postA({ jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: TOOL, arguments: { a: 1, b: 1 }, _meta: ENV() } }, { ...hdr, "mcp-name": "someone_elses_tool" });
    assert("modern: Mcp-Name header that disagrees with the body -> 400 with -32020 (policy cannot be bypassed via headers)", badName.status === 400 && badName.msg?.error?.code === -32020, JSON.stringify({ s: badName.status, c: badName.msg?.error?.code }));
    const badVer = await postA({ jsonrpc: "2.0", id: 8, method: "tools/call", params: { name: TOOL, arguments: {}, _meta: ENV("2099-01-01") } }, { ...hdr, "mcp-protocol-version": "2099-01-01" });
    assert("modern: unknown future version -> -32022 naming the supported versions", badVer.msg?.error?.code === -32022 && Array.isArray(badVer.msg?.error?.data?.supported), JSON.stringify(badVer.msg?.error));
  }

  // =========================================================================================== HTTP, legacy (handshake) eras
  for (const v of ["2025-11-25", "2025-06-18", "2025-03-26"]) {
    const init = await postA({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: v, capabilities: {}, clientInfo: { name: "raw", version: "0" } } });
    assert(`legacy ${v}: initialize echoes ${v}, no session id, no resultType`, init.msg?.result?.protocolVersion === v && init.msg?.result?.serverInfo?.name === "switchboard" && !("resultType" in (init.msg?.result ?? {})), JSON.stringify({ got: init.msg?.result?.protocolVersion }));
    const h = v === "2025-03-26" ? {} : { "mcp-protocol-version": v };
    const note = await postA({ jsonrpc: "2.0", method: "notifications/initialized" }, h);
    assert(`legacy ${v}: notifications/initialized -> 202`, note.status === 202, String(note.status));
    const rc = await postA({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: TOOL, arguments: { a: 4, b: 5 } } }, h);
    assert(`legacy ${v}: tools/call through the router -> 9, 2025 shape (no resultType, no reserved _meta)`, rc.msg?.result?.content?.[0]?.text === "9" && !("resultType" in rc.msg.result) && !Object.keys(rc.msg.result._meta ?? {}).some((k) => k.startsWith("io.modelcontextprotocol/")), JSON.stringify(rc.msg?.result));
  }
  {
    const g = await fetch(A, { method: "GET", headers: { ...auth, accept: "text/event-stream" } });
    const d = await fetch(A, { method: "DELETE", headers: auth });
    assert("legacy: GET and DELETE are answered 405 (stateless: no stream, no sessions)", g.status === 405 && d.status === 405, JSON.stringify({ get: g.status, del: d.status }));
  }

  // =========================================================================================== real SDK clients
  {
    const c = new V2Client({ name: "v2-pin", version: "2.3.1" }, { versionNegotiation: { mode: { pin: "2026-07-28" } } });
    await c.connect(new V2Http(new URL(A), { requestInit: { headers: auth } }));
    const r = await c.callTool({ name: TOOL, arguments: { a: 1, b: 2 } });
    assert("v2 SDK client pinned to 2026-07-28: era modern, add=3", c.getProtocolEra() === "modern" && r.content[0].text === "3", c.getProtocolEra());
    await c.close();
  }
  {
    const c = new V2Client({ name: "v2-auto", version: "2.3.1" }, { versionNegotiation: { mode: "auto" } });
    await c.connect(new V2Http(new URL(A), { requestInit: { headers: auth } }));
    const r = await c.callTool({ name: TOOL, arguments: { a: 2, b: 2 } });
    assert("v2 SDK client auto: negotiates modern against the gateway, add=4", c.getProtocolEra() === "modern" && r.content[0].text === "4", c.getProtocolEra());
    await c.close();
  }
  {
    const counter = { count: 0 };
    const c = new V2Client({ name: "v2-legacy", version: "2.3.1" });
    await c.connect(new V2Http(new URL(A), { requestInit: { headers: auth }, fetch: countedFetch(counter) }));
    const r = await c.callTool({ name: TOOL, arguments: { a: 3, b: 3 } });
    await new Promise((r2) => setTimeout(r2, 600));
    assert("v2 SDK client default (handshake): era legacy, add=6", c.getProtocolEra() === "legacy" && r.content[0].text === "6", c.getProtocolEra());
    assert("handshake clients do not reconnect-loop on the 405 GET (at most one GET)", counter.count <= 1, `GET count=${counter.count}`);
    await c.close();
  }
  if (V1) {
    const counter = { count: 0 };
    const c = new V1.Client({ name: "v1-sdk", version: "1.32.1" });
    await c.connect(new V1.Http(new URL(A), { requestInit: { headers: auth }, fetch: countedFetch(counter) }));
    const r = await c.callTool({ name: TOOL, arguments: { a: 8, b: 8 } });
    await new Promise((r2) => setTimeout(r2, 600));
    assert("genuine SDK 1.x client (initialize handshake): add=16", r.content[0].text === "16");
    assert("SDK 1.x client does not reconnect-loop on the 405 GET (at most one GET)", counter.count <= 1, `GET count=${counter.count}`);
    await c.close();
  } else {
    console.log("SKIP  genuine SDK 1.x client (package not installed)");
  }

  // =========================================================================================== JSON-only + auth-forced endpoint (expose shape)
  {
    const noAuth = await post(B, { jsonrpc: "2.0", id: 1, method: "tools/list" }, { "mcp-protocol-version": "2025-11-25" });
    assert("auth-forced endpoint: no key -> 401 with WWW-Authenticate, in both eras", noAuth.status === 401 && !!noAuth.www, JSON.stringify({ s: noAuth.status, www: noAuth.www }));
    const noAuthModern = await post(B, { jsonrpc: "2.0", id: 1, method: "tools/list", params: { _meta: ENV() } }, { "mcp-protocol-version": "2026-07-28", "mcp-method": "tools/list" });
    assert("auth-forced endpoint: modern request without key -> 401 too", noAuthModern.status === 401, String(noAuthModern.status));
    const li = await post(B, { jsonrpc: "2.0", id: 2, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "raw", version: "0" } } }, auth);
    assert("JSON-only endpoint: legacy initialize answers application/json (not SSE)", li.status === 200 && li.ct.includes("application/json") && li.msg?.result?.protocolVersion === "2025-11-25", li.ct);
    const lc = await post(B, { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: TOOL, arguments: { a: 1, b: 1 } } }, { ...auth, "mcp-protocol-version": "2025-11-25" });
    assert("JSON-only endpoint: legacy tools/call answers application/json, add=2", lc.ct.includes("application/json") && lc.msg?.result?.content?.[0]?.text === "2", lc.ct);
    const mc = await post(B, { jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: TOOL, arguments: { a: 5, b: 5 }, _meta: ENV() } }, { ...auth, "mcp-protocol-version": "2026-07-28", "mcp-method": "tools/call", "mcp-name": TOOL });
    assert("JSON-only endpoint: modern tools/call answers application/json, add=10", mc.ct.includes("application/json") && mc.msg?.result?.content?.[0]?.text === "10", mc.ct);
    const wrong = await post(B, { jsonrpc: "2.0", id: 5, method: "tools/list" }, { authorization: "Bearer not-a-real-key" });
    assert("auth-forced endpoint: a wrong key is refused", wrong.status === 401, String(wrong.status));
  }
} finally {
  await dashA.close().catch(() => {});
  await listenerB.close().catch(() => {});
  await gateway.shutdown();
}

// ======================================================================================= stdio, the real CLI, both eras
{
  const cfgPath = join(tmp, "stdio.config.yaml");
  const upstream = join(root, "scripts", "fixtures", "dualera-upstream.mjs");
  writeFileSync(
    cfgPath,
    [
      "gateway:",
      "  transport: [stdio]",
      "  http: { host: 127.0.0.1, port: 1, require_auth: auto }",
      "  tool_exposure: namespaced",
      "  default_policy: read",
      "vault: { backend: encrypted-file }",
      "servers:",
      "  - id: up",
      "    source: binary",
      "    enabled: true",
      "    policy: write",
      `    command: ${JSON.stringify(process.execPath)}`,
      `    args: [${JSON.stringify(upstream)}]`,
      "settings: {}",
      "",
    ].join("\n"),
  );
  const cli = join(root, "dist", "cli.js");
  const childEnv = { ...getDefaultEnvironment(), SWITCHBOARD_HOME: join(tmp, "sbhome2"), HOME: tmp, USERPROFILE: tmp, APPDATA: join(tmp, "appdata"), LOCALAPPDATA: join(tmp, "local"), NO_COLOR: "1" };

  const rawSession = (lines) =>
    new Promise((resolve) => {
      const child = spawn(process.execPath, [cli, "-c", cfgPath, "serve"], { env: childEnv, stdio: ["pipe", "pipe", "pipe"] });
      let out = "";
      child.stdout.on("data", (d) => (out += d));
      setTimeout(() => {
        for (const l of lines) child.stdin.write(JSON.stringify(l) + "\n");
        setTimeout(() => {
          child.stdin.end();
          setTimeout(() => {
            child.kill();
            resolve(out.split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return { _raw: l }; } }));
          }, 300);
        }, 2500);
      }, 2500); // allow the gateway to mount its upstream before the first request
    });

  const modern = await rawSession([
    { jsonrpc: "2.0", id: 1, method: "server/discover", params: { _meta: ENV() } },
    { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: TOOL, arguments: { a: 30, b: 12 }, _meta: ENV() } },
  ]);
  const d = modern.find((m) => m.id === 1);
  const c2 = modern.find((m) => m.id === 2);
  assert("stdio modern: server/discover lists 2026-07-28 and names the gateway", d?.result?.supportedVersions?.includes("2026-07-28") && d?.result?._meta?.["io.modelcontextprotocol/serverInfo"]?.name === "switchboard", JSON.stringify(d?.result?.supportedVersions));
  assert("stdio modern: tools/call through the router -> 42, resultType=complete", c2?.result?.content?.[0]?.text === "42" && c2?.result?.resultType === "complete", JSON.stringify(c2));

  for (const v of ["2025-11-25", "2025-06-18", "2025-03-26"]) {
    const msgs = await rawSession([
      { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: v, capabilities: {}, clientInfo: { name: "raw", version: "0" } } },
      { jsonrpc: "2.0", method: "notifications/initialized" },
      { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: TOOL, arguments: { a: 4, b: 5 } } },
    ]);
    const i = msgs.find((m) => m.id === 1);
    const t = msgs.find((m) => m.id === 2);
    assert(`stdio legacy ${v}: initialize echoes ${v}; tools/call -> 9 in 2025 shape`, i?.result?.protocolVersion === v && t?.result?.content?.[0]?.text === "9" && !("resultType" in (t?.result ?? {})), JSON.stringify({ got: i?.result?.protocolVersion }));
  }
  {
    const c = new V2Client({ name: "v2-stdio-auto", version: "2.3.1" }, { versionNegotiation: { mode: "auto" } });
    await c.connect(new V2Stdio({ command: process.execPath, args: [cli, "-c", cfgPath, "serve"], env: childEnv, stderr: "pipe" }), { timeout: 30000 });
    const r = await c.callTool({ name: TOOL, arguments: { a: 6, b: 6 } });
    assert("stdio: v2 SDK client auto -> modern against the real CLI, add=12", c.getProtocolEra() === "modern" && r.content[0].text === "12", c.getProtocolEra());
    await c.close();
  }
  {
    const c = new V2Client({ name: "v2-stdio-legacy", version: "2.3.1" });
    await c.connect(new V2Stdio({ command: process.execPath, args: [cli, "-c", cfgPath, "serve"], env: childEnv, stderr: "pipe" }), { timeout: 30000 });
    const r = await c.callTool({ name: TOOL, arguments: { a: 7, b: 7 } });
    assert("stdio: v2 SDK client default (handshake) -> legacy against the real CLI, add=14", c.getProtocolEra() === "legacy" && r.content[0].text === "14", c.getProtocolEra());
    await c.close();
  }
  if (V1) {
    const c = new V1.Client({ name: "v1-stdio", version: "1.32.1" });
    await c.connect(new V1.Stdio({ command: process.execPath, args: [cli, "-c", cfgPath, "serve"], env: childEnv, stderr: "pipe" }));
    const r = await c.callTool({ name: TOOL, arguments: { a: 9, b: 9 } });
    assert("stdio: genuine SDK 1.x client -> real CLI, add=18", r.content[0].text === "18");
    await c.close();
  }
}

const bad = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - bad.length}/${checks.length} checks passed`);
setTimeout(() => process.exit(bad.length ? 1 : 0), 300);
