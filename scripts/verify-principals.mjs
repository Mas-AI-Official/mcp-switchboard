// Deterministic oracle for principals and clients (design 3.1): the client profile, the per-client key, the
// filtered and gated Router, the /mcp front door, the clients admin API, `switchboard client ...` and the
// `serve --client` stdio principal. No model tokens, no network beyond loopback, no real client config.
//
// Halves, all against the compiled dist/:
//   A (in process, pure)  principal.ts: client id rule, glob matcher (and its work bound), gates, the /mcp
//        decision matrix (401 / 403 / ok), audit fields; config schema; policy ceiling (tightest wins);
//        governor client level; API key binding; the config watcher and the comment-preserving file edit.
//   B (real gateway, real HTTP, bearer keys)  two or more clients with different allowlists see different
//        tools; hidden is uncallable and never reaches the upstream; max_scope only lowers; per-client limits;
//        resources and prompts are filtered and gated; audit rows carry principal and client; a hot edit of the
//        config file is picked up and a bad one is ignored; the admin API (owner session + CSRF) never returns
//        a token and takes effect at once.
//   C (CLI end to end, no restart)  a gateway in legacy mode (no clients) is unchanged; `client add` then
//        `bridge --client` works against the running gateway; rotate invalidates the old key; rm / --purge.
//   D (stdio)  `serve --client` applies the filter and records via "stdio"; clients without --client is refused.
//   E (OAuth)  an OAuth token maps to a client only when the registered client name is a configured client id.
//   F (search and flat exposure)  the same filter and gate apply to find_tools, call_tool, batch_call and to flat names.
//
// Tests never touch the operator's state: SWITCHBOARD_HOME, HOME, USERPROFILE and APPDATA are temp dirs, ports
// are ephemeral, upstreams are this very file run with --upstream. Build first: npm run build && node scripts/verify-principals.mjs

import { spawn, spawnSync } from "node:child_process";
import http from "node:http";
import net from "node:net";
import { createHash, randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const SELF = fileURLToPath(import.meta.url);
const CLI = join(root, "dist", "cli.js");

// ---------------------------------------------------------------------------------------------------
// Mode 1: the stdio upstream fixture. Three servers with different tools, one resource and one prompt each.
// ---------------------------------------------------------------------------------------------------
const FIXTURES = {
  alpha: { tools: ["get_status", "get_info", "create_note", "delete_note"], resource: "alpha://readme", prompt: "hello_alpha" },
  beta: { tools: ["get_weather", "get_info", "send_message"], resource: "beta://secret", prompt: "hello_beta" },
  gamma: { tools: ["get_time", "ping"] },
};

async function runUpstream(id) {
  const { Server } = await import("@modelcontextprotocol/sdk/server/index.js");
  const { StdioServerTransport } = await import("@modelcontextprotocol/sdk/server/stdio.js");
  const T = await import("@modelcontextprotocol/sdk/types.js");
  const fx = FIXTURES[id];
  const caps = { tools: {}, ...(fx.resource ? { resources: {} } : {}), ...(fx.prompt ? { prompts: {} } : {}) };
  const server = new Server({ name: `principals-fixture-${id}`, version: "0.0.0" }, { capabilities: caps });
  server.setRequestHandler(T.ListToolsRequestSchema, async () => ({
    tools: fx.tools.map((name) => ({ name, description: `${id} ${name}`, inputSchema: { type: "object", properties: {} } })),
  }));
  server.setRequestHandler(T.CallToolRequestSchema, async (req) => {
    if (process.env.SB_FIXTURE_LOG) appendFileSync(process.env.SB_FIXTURE_LOG, `${id}:${req.params.name}\n`);
    return { content: [{ type: "text", text: `${id}:${req.params.name}` }] };
  });
  if (fx.resource) {
    server.setRequestHandler(T.ListResourcesRequestSchema, async () => ({ resources: [{ uri: fx.resource, name: `${id} resource` }] }));
    server.setRequestHandler(T.ReadResourceRequestSchema, async (req) => ({ contents: [{ uri: req.params.uri, mimeType: "text/plain", text: `${id} resource body` }] }));
  }
  if (fx.prompt) {
    server.setRequestHandler(T.ListPromptsRequestSchema, async () => ({ prompts: [{ name: fx.prompt, description: `${id} prompt` }] }));
    server.setRequestHandler(T.GetPromptRequestSchema, async () => ({ messages: [{ role: "user", content: { type: "text", text: `${id} prompt body` } }] }));
  }
  await server.connect(new StdioServerTransport());
}

if (process.argv.includes("--upstream")) {
  await runUpstream(process.argv[process.argv.indexOf("--upstream") + 1]);
} else {
  await main();
}

// ---------------------------------------------------------------------------------------------------
// Mode 2: the oracle.
// ---------------------------------------------------------------------------------------------------
async function main() {
  const checks = [];
  const assert = (name, cond, detail = "") => {
    checks.push({ name, ok: !!cond, detail });
    const clean = String(detail).replace(/\x1b\[[0-9;]*m/g, "").replace(new RegExp(`[${String.fromCharCode(0x2713, 0x2717)}]`, "g"), "").replace(/\s+/g, " ").trim();
    console.log(`${cond ? "PASS" : "FAIL"}  ${name}${clean ? ` - ${clean.slice(0, 220)}` : ""}`);
  };
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const sha256 = (s) => createHash("sha256").update(s).digest("hex");
  const throws = (fn) => {
    try {
      fn();
      return false;
    } catch {
      return true;
    }
  };
  const throwsMsg = (fn) => {
    try {
      fn();
      return "";
    } catch (e) {
      return String(e && e.message);
    }
  };

  // ---- isolated environment (before any dist module is imported: HOME_DIR is read at import) --------
  const base = mkdtempSync(join(tmpdir(), "sb-principals-"));
  const home = join(base, "home");
  const dirs = { home, appdata: join(base, "appdata"), local: join(base, "local"), tmp: join(base, "tmp") };
  for (const d of Object.values(dirs)) mkdirSync(d, { recursive: true });
  const SBHOME = join(home, ".switchboard");
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
  const childEnv = (extra = {}) => ({ ...process.env, NO_COLOR: "1", ...extra });

  const P = await import("../dist/principal.js");
  const { Gateway, createGateway } = await import("../dist/gateway.js");
  const { startDashboard } = await import("../dist/dashboard.js");
  const { ApiKeyStore } = await import("../dist/apikeys.js");
  const { loadConfig, writeConfig, validateConfig, parseClientEntry } = await import("../dist/config.js");
  const { evaluate } = await import("../dist/policy.js");
  const { Governor } = await import("../dist/governor.js");
  const { recentAudit, verifyAudit } = await import("../dist/audit.js");
  const { LoginCodeStore } = await import("../dist/httpsec.js");
  const CK = await import("../dist/clientkeys.js");
  const CC = await import("../dist/clientconfig.js");
  const { ClientAdmin, ClientAdminError } = await import("../dist/clientadmin.js");
  const { Router } = await import("../dist/router.js");
  const { startMcpListener } = await import("../dist/expose.js");

  const children = new Set();
  const handles = [];
  const gateways = [];
  /** Close one dashboard and its gateway now, and forget both so the final cleanup does not repeat it. */
  async function retire(dash, gw) {
    await dash.close().catch(() => {});
    await gw.shutdown().catch(() => {});
    handles.splice(handles.indexOf(dash), 1);
    gateways.splice(gateways.indexOf(gw), 1);
  }

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

  /** Raw HTTP to the gateway. Never rejects: a hung request is status 0 so the check fails instead of the oracle. */
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
      req.setTimeout(15_000, () => req.destroy(new Error(`timeout ${method} ${path}`)));
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

  /** One JSON-RPC request to /mcp (the answer may be SSE or JSON). */
  let rpcId = 100;
  async function mcp(port, token, method, params = {}) {
    const r = await raw(port, "POST", "/mcp", {
      headers: { accept: "application/json, text/event-stream", ...(token ? { authorization: `Bearer ${token}` } : {}) },
      body: { jsonrpc: "2.0", id: ++rpcId, method, params },
    });
    let msg = null;
    if (/text\/event-stream/.test(r.headers["content-type"] ?? "")) {
      const line = r.body.split(/\r?\n/).find((l) => l.startsWith("data:"));
      if (line) {
        try {
          msg = JSON.parse(line.slice(5).trim());
        } catch {
          msg = null;
        }
      }
    } else {
      msg = jsonOf(r);
    }
    return { status: r.status, headers: r.headers, body: r.body, msg, result: msg?.result, error: msg?.error };
  }
  const toolNames = async (port, token) => {
    const r = await mcp(port, token, "tools/list");
    return (r.result?.tools ?? []).map((t) => t.name).sort();
  };
  /** A tool call; `text` is the first content text, `sb` its parsed SB_* error body when there is one. */
  async function call(port, token, name, args = {}) {
    const r = await mcp(port, token, "tools/call", { name, arguments: args });
    const text = r.result?.content?.[0]?.text ?? "";
    let sb = null;
    try {
      sb = JSON.parse(text);
    } catch {
      sb = null;
    }
    return { ...r, isError: r.result?.isError === true, text, sb };
  }
  const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

  function cliRun(args, { env = {}, input, timeoutMs = 60_000 } = {}) {
    return new Promise((resolve) => {
      const child = spawn(process.execPath, [CLI, ...args], { env: childEnv(env), stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
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
      if (input !== undefined) child.stdin.write(input);
      child.stdin.end();
    });
  }

  /** Drive a stdio JSON-RPC child: write the lines, wait for `want` responses (by id), then end it. */
  function lineSession(args, messages, { want, env = {}, killAfter = false, timeoutMs = 40_000 } = {}) {
    return new Promise((resolve) => {
      const child = spawn(process.execPath, [CLI, ...args], { env: childEnv(env), stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
      children.add(child);
      let out = "";
      let err = "";
      const got = new Map();
      let finished = false;
      let exited = null;
      const finish = () => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        if (killAfter) killTree(child);
        else child.stdin.end();
        const waitExit = setTimeout(() => killTree(child), 8000);
        const done = () => {
          clearTimeout(waitExit);
          children.delete(child);
          resolve({ code: exited, out, err: err.replace(/\x1b\[[0-9;]*m/g, ""), msgs: [...got.values()], got });
        };
        if (exited !== null || killAfter) setTimeout(done, killAfter ? 300 : 0);
        else child.once("close", done);
      };
      const timer = setTimeout(finish, timeoutMs);
      child.stdout.on("data", (c) => {
        out += c;
        for (const line of out.split(/\r?\n/)) {
          if (!line.trim().startsWith("{")) continue;
          try {
            const m = JSON.parse(line);
            if (m.id !== undefined && (m.result !== undefined || m.error !== undefined)) got.set(m.id, m);
          } catch {
            /* partial line */
          }
        }
        if (got.size >= want) finish();
      });
      child.stderr.on("data", (c) => (err += c));
      child.on("close", (code) => {
        exited = code ?? -1;
        if (!finished) finish();
      });
      for (const m of messages) child.stdin.write(JSON.stringify(m) + "\n");
    });
  }

  const initMsg = (id) => ({ jsonrpc: "2.0", id, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "verify-principals", version: "0" } } });
  const toolsMsg = (id) => ({ jsonrpc: "2.0", id, method: "tools/list" });
  const callMsg = (id, name, args = {}) => ({ jsonrpc: "2.0", id, method: "tools/call", params: { name, arguments: args } });

  const q = JSON.stringify; // a JSON string is a valid double quoted YAML scalar
  const FIXLOG = join(base, "upstream-calls.log");
  const fixtureLines = () => (existsSync(FIXLOG) ? readFileSync(FIXLOG, "utf8").split("\n").filter(Boolean) : []);
  const POLICY = { alpha: "full", beta: "write", gamma: "read" };
  const serversYaml = (ids = ["alpha", "beta", "gamma"]) =>
    ids
      .map(
        (id) =>
          `  - id: ${id}\n    source: binary\n    command: ${q(process.execPath)}\n    args: [${q(SELF)}, "--upstream", ${q(id)}]\n    policy: ${POLICY[id]}\n    env:\n      SB_FIXTURE_LOG: ${q(FIXLOG)}`,
      )
      .join("\n");
  const configYaml = ({ port, transport = "[http]", exposure = "namespaced", clients = "", servers = ["alpha", "beta", "gamma"], extra = "" }) =>
    `# ORACLE-MARKER keep this comment\ngateway:\n  transport: ${transport}\n  http: { host: 127.0.0.1, port: ${port}, require_auth: auto }\n  tool_exposure: ${exposure}\n  default_policy: read\nvault:\n  backend: encrypted-file\nservers:\n${serversYaml(servers)}\nsettings:\n  logs:\n    capture_io: false\n${extra}${clients}`;

  const ALL = ["alpha__create_note", "alpha__delete_note", "alpha__get_info", "alpha__get_status", "beta__get_info", "beta__get_weather", "beta__send_message", "gamma__get_time", "gamma__ping"];

  try {
    // ===============================================================================================
    // HALF A: pure and in-process
    // ===============================================================================================
    // ---- client id ----
    for (const id of ["a", "claude-code", "local_model", "0abc", "x".repeat(64)]) assert(`client id '${id.length > 20 ? "x*64" : id}' is valid`, P.isValidClientId(id));
    for (const id of ["", "A", "-a", "_a", "a b", "a/b", "a..b", "x".repeat(65), "nul", "con", "com1", "lpt9", "aux", 7, null, String.fromCharCode(0xe9)]) {
      assert(`client id ${q(id)} is invalid`, !P.isValidClientId(id));
    }
    assert("CK.isValidClientId is the same rule (clientkeys re-exports it)", CK.isValidClientId === P.isValidClientId && CK.CLIENT_ID_RE === P.CLIENT_ID_RE);

    // ---- glob matcher ----
    const G = P.globMatch;
    const globCases = [
      ["*", "anything__at_all", true],
      ["*", "", true],
      ["alpha", "alpha", true],
      ["alpha", "alphA", false],
      ["alpha", "alpha2", false],
      ["alpha*", "alpha", true],
      ["alpha*", "alpha__get_status", true],
      ["alpha__get_*", "alpha__get_status", true],
      ["alpha__get_*", "alpha__create_note", false],
      ["*__delete_*", "alpha__delete_note", true],
      ["*__delete_*", "alpha__get_delete", false],
      ["a*b*c", "axxbxxc", true],
      ["a*b*c", "axxbxx", false],
      ["?lpha", "alpha", true],
      ["?lpha", "lpha", false],
      ["al?ha", "alpha", true],
      ["**", "x", true],
      ["a*", "*a", false],
      ["*", "*", true],
      ["", "", true],
      ["", "x", false],
      ["gam?a__*", "gamma__ping", true],
      ["a.c", "abc", false],
      ["a(b", "a(b", true],
    ];
    for (const [pat, text, want] of globCases) assert(`glob ${q(pat)} on ${q(text)} is ${want}`, G(pat, text) === want);
    assert("a pattern longer than the cap never matches", G("a".repeat(P.MAX_GLOB_LENGTH + 1), "a") === false && G("*".repeat(P.MAX_GLOB_LENGTH + 1), "a") === false);
    assert("a name longer than the cap never matches (even '*')", G("*", "a".repeat(P.MAX_GLOB_TEXT + 1)) === false);
    {
      const t0 = Date.now();
      const evil = "*a".repeat(60) + "*b";
      const hostile = "a".repeat(P.MAX_GLOB_TEXT);
      let r = true;
      for (let i = 0; i < 40; i++) r = G(evil, hostile);
      assert("a pathological pattern on a maximal name is bounded and false", r === false && Date.now() - t0 < 4000, `${Date.now() - t0} ms for 40 matches`);
    }
    assert("isValidGlob: printable, bounded, non empty", P.isValidGlob("a*") && !P.isValidGlob("") && !P.isValidGlob("a\u0000b") && !P.isValidGlob("a\nb") && !P.isValidGlob("x".repeat(P.MAX_GLOB_LENGTH + 1)) && !P.isValidGlob(5));

    // ---- gates ----
    const clientsA = {
      full: { servers: ["*"] },
      some: { servers: ["alpha", "be*"], tools: ["alpha__get_*", "beta__send_message"], exclude_tools: ["beta__send_*"], max_scope: "write" },
      none: { servers: [] },
      constructor: { servers: ["*"] },
    };
    const pk = (client, via = "apikey", id = "k1") => ({ id, client, via });
    assert("no principal: no gate (an internal caller is unfiltered)", P.resolveClientGate(clientsA, undefined) === undefined);
    assert("unbound principal while clients exist: deny-all gate", typeof P.resolveClientGate(clientsA, pk(null))?.deny === "string");
    assert("unbound principal with no clients: no gate (legacy)", P.resolveClientGate(undefined, pk(null)) === undefined && P.resolveClientGate({}, pk(null)) === undefined);
    assert("principal bound to an unconfigured client: deny-all, even with no clients", P.resolveClientGate(clientsA, pk("ghost"))?.deny?.includes("ghost") && typeof P.resolveClientGate(undefined, pk("ghost"))?.deny === "string");
    assert("Object.prototype names are not clients ('toString' is not configured)", typeof P.resolveClientGate(clientsA, pk("toString"))?.deny === "string");
    assert("a client literally named 'constructor' resolves to its own profile", P.resolveClientGate(clientsA, pk("constructor"))?.deny === null);
    const gSome = P.resolveClientGate(clientsA, pk("some"));
    assert("gate: server globs decide visibility", P.gateAllowsServer(gSome, "alpha") && P.gateAllowsServer(gSome, "beta") && P.gateAllowsServer(gSome, "bet") && P.gateAllowsServer(gSome, "be") && !P.gateAllowsServer(gSome, "b") && !P.gateAllowsServer(gSome, "gamma"));
    assert("gate: tool allowlist applies by exposed name", P.gateAllowsTool(gSome, "alpha__get_status") && !P.gateAllowsTool(gSome, "alpha__create_note"));
    assert("gate: exclude_tools beats the allowlist", !P.gateAllowsTool(gSome, "beta__send_message"));
    assert("gate: an over-long tool name is hidden, never matched", !P.gateAllowsTool(P.resolveClientGate(clientsA, pk("full")), "x".repeat(P.MAX_GLOB_TEXT + 1)));
    const gFull = P.resolveClientGate(clientsA, pk("full"));
    assert("gate: no tools list means every tool of the allowed servers", P.gateAllowsTool(gFull, "gamma__ping") && P.gateAllowsServer(gFull, "anything"));
    assert("gate: a client with no servers sees nothing", !P.gateAllowsServer(P.resolveClientGate(clientsA, pk("none")), "alpha"));
    assert("gate: deny-all gate allows nothing", !P.gateAllowsServer(P.resolveClientGate(clientsA, pk(null)), "alpha") && !P.gateAllowsTool(P.resolveClientGate(clientsA, pk(null)), "alpha__get_status"));
    assert("gateScopeCeiling: the client's max_scope with its id, none when unset", same(P.gateScopeCeiling(gSome), { scope: "write", client: "some" }) && P.gateScopeCeiling(gFull) === undefined && P.gateScopeCeiling(undefined) === undefined);
    assert("tighterScope picks the lower", P.tighterScope("write", "read") === "read" && P.tighterScope(undefined, "full") === "full" && P.tighterScope("full", undefined) === "full" && P.tighterScope("read", "full") === "read");
    assert("principalLabel and principalAudit", P.principalLabel(pk("c", "apikey", "abc")) === "apikey:abc" && same(P.principalAudit(pk("c", "stdio", "c")), { principal: "stdio:c", client: "c" }) && same(P.principalAudit(pk(null, "loopback-anonymous", "loopback")), { principal: "loopback-anonymous:loopback" }) && same(P.principalAudit(undefined), {}));

    // ---- the /mcp decision matrix ----
    const E = (o) => P.establishPrincipal({ clients: clientsA, apiKey: null, oauth: null, authRequired: false, ...o });
    {
      const d = E({});
      assert("clients configured, no credential: 401", d.ok === false && d.status === 401);
      const d2 = P.establishPrincipal({ clients: undefined, apiKey: null, oauth: null, authRequired: false });
      assert("no clients, no credential, auth not required: loopback-anonymous", d2.ok && d2.principal.via === "loopback-anonymous" && d2.principal.client === null);
      const d3 = P.establishPrincipal({ clients: undefined, apiKey: null, oauth: null, authRequired: true });
      assert("no clients, no credential, auth required: 401", d3.ok === false && d3.status === 401);
      const d4 = P.establishPrincipal({ clients: {}, apiKey: null, oauth: null, authRequired: false });
      assert("an empty clients map is legacy mode", d4.ok && d4.principal.via === "loopback-anonymous");
      const d5 = E({ apiKey: { id: "k1", client: "some" } });
      assert("a key bound to a configured client is a principal of that client", d5.ok && d5.principal.client === "some" && d5.principal.via === "apikey" && d5.principal.id === "k1");
      const d6 = E({ apiKey: { id: "k2" } });
      assert("clients configured, key bound to none: 403 SB_NO_CLIENT", d6.ok === false && d6.status === 403 && d6.code === "SB_NO_CLIENT");
      const d7 = E({ apiKey: { id: "k3", client: "ghost" } });
      assert("a key bound to an unconfigured client: 403 SB_UNKNOWN_CLIENT", d7.ok === false && d7.status === 403 && d7.code === "SB_UNKNOWN_CLIENT");
      const d8 = P.establishPrincipal({ clients: undefined, apiKey: { id: "k3", client: "ghost" }, oauth: null, authRequired: false });
      assert("a bound key whose client vanished is refused even when no client is configured", d8.ok === false && d8.status === 403);
      const d9 = P.establishPrincipal({ clients: undefined, apiKey: { id: "k4" }, oauth: null, authRequired: true });
      assert("legacy: an unbound key is the legacy caller only while no client is configured", d9.ok && d9.principal.client === null && d9.principal.via === "apikey");
      const o1 = E({ oauth: { clientId: "oc1", clientName: "some" } });
      assert("OAuth: the registered name equals a configured client id -> that client", o1.ok && o1.principal.client === "some" && o1.principal.via === "oauth" && o1.principal.id === "oc1");
      const o2 = E({ oauth: { clientId: "oc2", clientName: "stranger" } });
      assert("OAuth: an unmatched name has no client and is refused while clients exist", o2.ok === false && o2.status === 403 && o2.code === "SB_NO_CLIENT");
      const o3 = E({ oauth: { clientId: "oc3" } });
      assert("OAuth: no registered name -> refused while clients exist", o3.ok === false && o3.status === 403);
      const o4 = E({ oauth: { clientId: "oc4", clientName: "toString" } });
      assert("OAuth: Object.prototype names never map", o4.ok === false);
      const o5 = P.establishPrincipal({ clients: undefined, apiKey: null, oauth: { clientId: "oc5", clientName: "some" }, authRequired: true });
      assert("OAuth with no clients configured: a valid token is the legacy caller", o5.ok && o5.principal.client === null);
      const o6 = E({ apiKey: { id: "k5", client: "some" }, oauth: { clientId: "oc6", clientName: "full" } });
      assert("a verified key wins over an OAuth identity", o6.ok && o6.principal.via === "apikey" && o6.principal.client === "some");
    }

    // ---- config schema ----
    const baseCfg = { gateway: { transport: ["http"], http: { host: "127.0.0.1", port: 8088, require_auth: "auto" }, tool_exposure: "namespaced", default_policy: "read" }, vault: { backend: "encrypted-file" }, servers: [] };
    const tryCfg = (clients) => throwsMsg(() => validateConfig({ ...baseCfg, clients }, "t"));
    assert("config: a valid clients block parses and servers defaults to none", (() => {
      const c = validateConfig({ ...baseCfg, clients: { "claude-code": { description: "Claude Code CLI", servers: ["*"], tools: [], exclude_tools: ["x*"], max_scope: "full", max_risk: "high", limits: { per_minute: 60 } }, "local-model": { servers: ["voice", "youtube"], max_scope: "read", max_risk: "low" }, bare: {} }, }, "t");
      return c.clients["claude-code"].limits.per_minute === 60 && same(c.clients.bare.servers, []) && c.clients["local-model"].max_risk === "low";
    })());
    assert("config: a config without clients still parses (clients absent)", validateConfig(baseCfg, "t").clients === undefined);
    assert("config: a bare `clients:` key (null) is the same as no clients, not an error", validateConfig({ ...baseCfg, clients: null }, "t").clients === undefined);
    {
      const rt = join(base, "roundtrip.yaml");
      const cfgRT = validateConfig({ ...baseCfg, clients: { rt: { description: "round trip", servers: ["a*"], tools: ["a__b"], exclude_tools: ["x"], max_scope: "write", max_risk: "medium", limits: { per_minute: 5, cost_per_day: 2.5 } } } }, "t");
      writeConfig(rt, cfgRT);
      assert("config: writeConfig then loadConfig round-trips a client entry unchanged", same(loadConfig(rt).clients, cfgRT.clients));
    }
    assert("config: a bad client id is rejected, naming the rule", /invalid client id/.test(tryCfg({ "Bad Id": {} })) && /invalid client id/.test(tryCfg({ nul: {} })) && /invalid client id/.test(tryCfg({ "-x": {} })));
    assert("config: an unknown client field is rejected", tryCfg({ a: { servrs: ["*"] } }) !== "");
    assert("config: max_scope and max_risk are enums", tryCfg({ a: { max_scope: "root" } }) !== "" && tryCfg({ a: { max_risk: "extreme" } }) !== "");
    assert("config: glob patterns are bounded and printable", tryCfg({ a: { servers: ["x".repeat(200)] } }) !== "" && tryCfg({ a: { tools: [""] } }) !== "" && tryCfg({ a: { exclude_tools: ["a\u0001b"] } }) !== "");
    assert("config: a limits block must set a ceiling", tryCfg({ a: { limits: {} } }) !== "");
    assert("parseClientEntry validates one entry and rejects a bad id", parseClientEntry("ok", { servers: ["a"] }).servers[0] === "a" && throws(() => parseClientEntry("Bad", {})) && throws(() => parseClientEntry("ok", { max_scope: "z" })));

    // ---- policy: the client ceiling joins server and profile, tightest wins ----
    {
      const srv = (policy) => ({ id: "s", source: "npx", enabled: true, policy });
      const cfgP = { gateway: { default_policy: "read" } };
      const ev = (policy, tool, prof, client) => evaluate(srv(policy), tool, cfgP, undefined, prof, undefined, client ? { scope: client, client: "zed" } : undefined);
      const a = ev("full", "create_x", undefined, "read");
      assert("policy: a client ceiling of read denies a write tool and names the client", a.decision === "deny" && /client 'zed'/.test(a.reason) && /capped at 'read'/.test(a.reason), a.reason);
      assert("policy: the client ceiling cannot raise a server ceiling (server read, client full)", ev("read", "create_x", undefined, "full").decision === "deny" && /server 's'/.test(ev("read", "create_x", undefined, "full").reason));
      assert("policy: the tightest wins, profile tighter than client names the profile", /active profile/.test(ev("full", "create_x", "read", "write").reason));
      assert("policy: the tightest wins, client tighter than profile names the client", /client 'zed'/.test(ev("full", "delete_x", "write", "read").reason));
      assert("policy: equal ceilings keep the earlier attribution (server before profile before client)", /server 's'/.test(ev("read", "create_x", "read", "read").reason));
      assert("policy: a read tool passes a read ceiling, a write tool passes a write ceiling", ev("full", "get_x", undefined, "read").decision === "allow" && ev("full", "create_x", undefined, "write").decision === "allow");
      assert("policy: without a client ceiling nothing changed", ev("write", "create_x", undefined, undefined).decision === "allow" && ev("write", "delete_x", undefined, undefined).decision === "deny");
    }

    // ---- governor: a client level, read live ----
    {
      const gov = new Governor({ gateway: { default_policy: "read" }, servers: [] });
      const lim = { id: "dave", limits: { per_minute: 2 } };
      const r1 = gov.consume("alpha", "get_status", 1000, lim);
      const r2 = gov.consume("alpha", "get_status", 1001, lim);
      const r3 = gov.consume("alpha", "get_status", 1002, lim);
      assert("governor: a client limit allows its ceiling then denies, naming the client", r1.ok && r2.ok && !r3.ok && r3.level === "client" && /client 'dave'/.test(r3.reason), r3.reason);
      assert("governor: another client has its own bucket", gov.consume("alpha", "get_status", 1003, { id: "erin", limits: { per_minute: 2 } }).ok);
      assert("governor: a call with no client is not charged to it", gov.consume("alpha", "get_status", 1004).ok);
      assert("governor: the bucket refills with time", gov.consume("alpha", "get_status", 1000 + 61_000, lim).ok);
      const r4 = gov.consume("alpha", "get_status", 1005, { id: "dave", limits: { per_minute: 5 } });
      assert("governor: a changed limit (a reload) is a new bucket, not the old capacity", r4.ok);
      assert("governor: no limits anywhere is the fast path", new Governor({ gateway: { default_policy: "read" }, servers: [] }).consume("a", "b", 1, { id: "x" }).ok);
    }

    // ---- API keys bound to a client ----
    {
      const store = new ApiKeyStore({ home: join(base, "keystore-a"), lastUsedIntervalMs: 0 });
      const legacy = store.issue("legacy");
      const bound = store.issue("bound", { client: "alice" });
      assert("keys: a legacy key has no client, a bound key lists its client", legacy.record.client === undefined && bound.record.client === "alice" && store.list().find((k) => k.id === bound.record.id)?.client === "alice");
      assert("keys: authenticate returns the key id and its client", same(store.authenticate(bound.token), { id: bound.record.id, name: "bound", client: "alice" }) && same(store.authenticate(legacy.token), { id: legacy.record.id, name: "legacy" }));
      assert("keys: verify still answers true/false", store.verify(bound.token) === true && store.verify("sb_nope") === false && store.verify("") === false && store.authenticate("sb_nope") === null);
      assert("keys: inspect does not record a use", (() => {
        const s2 = new ApiKeyStore({ home: join(base, "keystore-b"), lastUsedIntervalMs: 0 });
        const k = s2.issue("x", { client: "c1" });
        const before = s2.list()[0].last_used;
        const hit = s2.inspect(k.token);
        return before === undefined && s2.list()[0].last_used === undefined && hit?.client === "c1" && s2.inspect("sb_nope") === null;
      })());
      assert("keys: an invalid client id is refused at issue", throws(() => store.issue("bad", { client: "Bad Id" })) && throws(() => store.issue("bad", { client: "../x" })));
      const rep = store.replaceClientKeys("alice", "client:alice");
      assert("keys: replaceClientKeys revokes the old keys of that client only, in one write", rep.revoked === 1 && store.verify(bound.token) === false && store.verify(rep.token) === true && store.verify(legacy.token) === true);
      assert("keys: the replacement is bound to the same client", store.authenticate(rep.token)?.client === "alice");
      assert("keys: revokeClientKeys removes just that client's keys", store.revokeClientKeys("alice") === 1 && store.verify(rep.token) === false && store.verify(legacy.token) === true && store.revokeClientKeys("alice") === 0);
      // a second store instance sees the first one's rotation (the CLI and a running gateway share the file)
      const s1 = new ApiKeyStore({ home: join(base, "keystore-c"), lastUsedIntervalMs: 0 });
      const s2 = new ApiKeyStore({ home: join(base, "keystore-c"), lastUsedIntervalMs: 0 });
      const k1 = s1.issue("k", { client: "zed" });
      assert("keys: a key issued by another store instance is valid at once", s2.verify(k1.token));
      const k2 = s1.replaceClientKeys("zed", "k2");
      assert("keys: a rotation by another store instance invalidates the old key at once", s2.verify(k1.token) === false && s2.verify(k2.token) === true);
      writeFileSync(join(base, "keystore-d.json"), "{}");
      mkdirSync(join(base, "keystore-d"), { recursive: true });
      writeFileSync(join(base, "keystore-d", "apikeys.json"), JSON.stringify({ keys: [{ id: "x", hash: "00", client: 5 }] }));
      assert("keys: a record with a non-string client is a corrupt store, not an empty one", throws(() => new ApiKeyStore({ home: join(base, "keystore-d") })));
    }

    // ---- file edit and watcher ----
    {
      const dir = join(base, "cfgedit");
      mkdirSync(dir, { recursive: true });
      const f = join(dir, "c.yaml");
      const original = `# top comment\ngateway:\n  transport: [http]\n  http: { host: 127.0.0.1, port: 8088, require_auth: auto }\n  tool_exposure: namespaced\n  default_policy: read\nvault:\n  backend: encrypted-file\nservers: []\n# trailing comment\n`;
      writeFileSync(f, original);
      const changed = CC.editConfigFile(f, (doc) => CC.writeClientEntry(doc, "alpha", { servers: ["*"], max_scope: "read" }));
      const after = readFileSync(f, "utf8");
      assert("edit: adds the client, keeps both comments and the other keys", changed && after.includes("# top comment") && after.includes("# trailing comment") && /clients:\s*\n\s+alpha:/.test(after) && after.includes("servers: []"), after.slice(-160));
      assert("edit: the result loads and holds the entry", same(loadConfig(f).clients.alpha, { servers: ["*"], max_scope: "read" }));
      assert("edit: a .bak of the previous file was kept", existsSync(`${f}.bak`) && readFileSync(`${f}.bak`, "utf8") === original);
      const before2 = readFileSync(f, "utf8");
      const bad = throws(() => CC.editConfigFile(f, (doc) => CC.writeClientEntry(doc, "beta", { servers: ["x".repeat(500)] })));
      assert("edit: an edit that makes the config invalid throws and writes nothing", bad && readFileSync(f, "utf8") === before2);
      CC.editConfigFile(f, (doc) => CC.writeClientEntry(doc, "alpha", { servers: ["a", "b"] }));
      assert("edit: updating an entry rewrites only the keys that changed (max_scope removed when absent)", same(loadConfig(f).clients.alpha, { servers: ["a", "b"] }));
      CC.editConfigFile(f, (doc) => CC.deleteClientEntry(doc, "alpha"));
      assert("edit: deleting the last client removes the clients key and keeps the comments", loadConfig(f).clients === undefined && !readFileSync(f, "utf8").includes("clients:") && readFileSync(f, "utf8").includes("# top comment"));
      writeFileSync(f, original.replace(/\n/g, "\r\n"));
      CC.editConfigFile(f, (doc) => CC.writeClientEntry(doc, "crlf", { servers: ["*"] }));
      const crlfOut = readFileSync(f, "utf8");
      assert("edit: a CRLF file stays CRLF (no mixed line endings)", crlfOut.includes("\r\n") && !/[^\r]\n/.test(crlfOut));
      writeFileSync(f, "gateway: [unclosed\n");
      assert("edit: a file that does not parse is refused, not overwritten", throws(() => CC.editConfigFile(f, () => {})) && readFileSync(f, "utf8") === "gateway: [unclosed\n");
      assert("edit: a missing file is an error that says so", /config not found/.test(throwsMsg(() => CC.editConfigFile(join(dir, "nope.yaml"), () => {}))));

      // the watcher
      const wf = join(dir, "w.yaml");
      writeFileSync(wf, original + `clients:\n  one:\n    servers: ["*"]\n`);
      const wcfg = loadConfig(wf);
      const watcher = new CC.ClientConfigWatcher(wcfg, wf);
      assert("watcher: the first sync reads the file, finds the same clients and changes nothing", watcher.sync() === false && same(Object.keys(wcfg.clients), ["one"]));
      assert("watcher: nothing changed, nothing done", watcher.sync() === false);
      writeFileSync(wf, original + `clients:\n  one:\n    servers: ["*"]\n  two:\n    servers: [alpha]\n`);
      assert("watcher: a new client in the file replaces the live map", watcher.sync() === true && same(Object.keys(wcfg.clients).sort(), ["one", "two"]));
      const live = wcfg.clients;
      writeFileSync(wf, "not: [valid");
      assert("watcher: a file that does not parse is ignored, the previous clients stay", watcher.sync() === false && wcfg.clients === live);
      writeFileSync(wf, original + `clients:\n  Bad_Id:\n    servers: ["*"]\n`);
      assert("watcher: a file that parses but is invalid is ignored too", watcher.sync() === false && wcfg.clients === live && same(Object.keys(wcfg.clients).sort(), ["one", "two"]));
      const gwBlock = JSON.stringify(wcfg.gateway);
      writeFileSync(wf, original.replace("port: 8088", "port: 9999") + `clients:\n  three:\n    servers: [beta]\n`);
      assert("watcher: only the clients section is reloaded (the gateway block keeps its startup value)", watcher.sync() === true && same(Object.keys(wcfg.clients), ["three"]) && JSON.stringify(wcfg.gateway) === gwBlock);
      writeFileSync(wf, original);
      assert("watcher: removing the clients section clears the live map", watcher.sync() === true && wcfg.clients === undefined);
      rmSync(wf);
      assert("watcher: a missing file keeps what is loaded", watcher.sync() === false);
      assert("watcher: without a path it does nothing", new CC.ClientConfigWatcher({ clients: { x: { servers: [] } } }, undefined).sync() === false);
    }

    // ---- ClientAdmin, in memory (no config file) ----
    {
      const cfgM = { gateway: baseCfg.gateway, vault: baseCfg.vault, servers: [] };
      const store = new ApiKeyStore({ home: join(base, "keystore-admin"), lastUsedIntervalMs: 0 });
      const admin = new ClientAdmin({ cfg: cfgM, apiKeys: store });
      const r = admin.add("mem1", { servers: ["alpha"] });
      assert("admin: add creates the client with least privilege defaults and issues a key", r.created && r.client.max_scope === "read" && r.client.max_risk === "low" && same(r.client.servers, ["alpha"]) && !!r.token && r.keyKept === false);
      assert("admin: the key is bound to the client and stored for the bridge", store.authenticate(r.token)?.client === "mem1" && CK.readClientKey("mem1") === r.token);
      assert("admin: the in-memory config now holds the client", cfgM.clients?.mem1?.servers[0] === "alpha");
      const r2 = admin.add("mem1", { max_scope: "write" });
      assert("admin: add again updates the field given and keeps the working key", r2.created === false && r2.keyKept === true && r2.token === undefined && r2.client.max_scope === "write" && same(r2.client.servers, ["alpha"]) && CK.readClientKey("mem1") === r.token);
      const fresh = admin.add("mem2", {});
      assert("admin: a new client with no flags gets every server, read, low", same(fresh.client.servers, ["*"]) && fresh.client.max_scope === "read" && fresh.client.max_risk === "low");
      const rot = admin.rotate("mem1");
      assert("admin: rotate replaces the key and revokes the old one", rot.revoked === 1 && store.verify(r.token) === false && store.verify(rot.token) === true && CK.readClientKey("mem1") === rot.token);
      assert("admin: rotate of an unknown client is a 404", (() => { try { admin.rotate("ghost"); return false; } catch (e) { return e instanceof ClientAdminError && e.status === 404; } })());
      assert("admin: an invalid id or field is a 400 and changes nothing", (() => { try { admin.add("Bad Id"); return false; } catch (e) { return e instanceof ClientAdminError && e.status === 400; } })() && (() => { try { admin.update("mem1", { max_scope: "root" }); return false; } catch (e) { return e instanceof ClientAdminError && e.status === 400; } })() && cfgM.clients.mem1.max_scope === "write");
      const up = admin.update("mem1", { servers: ["beta"], max_risk: null });
      assert("admin: update changes servers and null clears an optional field", same(up.servers, ["beta"]) && up.max_risk === undefined);
      const lst = admin.list();
      assert("admin: list has both clients with their keys and key file flags, no secrets", lst.clients.length === 2 && lst.clients.find((c) => c.id === "mem1").keys.length === 1 && lst.clients[0].key_file === true && !JSON.stringify(lst).includes(rot.token));
      const rm = admin.remove("mem1");
      assert("admin: remove revokes keys and deletes the key file but keeps the entry", rm.revokedKeys === 1 && rm.keyFileRemoved === true && rm.purged === false && cfgM.clients.mem1 !== undefined && CK.readClientKey("mem1") === null && store.verify(rot.token) === false);
      const rm2 = admin.remove("mem1", { purge: true });
      assert("admin: remove --purge also drops the entry", rm2.purged === true && cfgM.clients.mem1 === undefined && cfgM.clients.mem2 !== undefined);
      admin.remove("mem2", { purge: true });
      assert("admin: removing the last client clears cfg.clients (legacy mode again)", cfgM.clients === undefined);
      assert("admin: removing an unknown client with nothing to clean is a 404", (() => { try { admin.remove("mem1"); return false; } catch (e) { return e instanceof ClientAdminError && e.status === 404; } })());
    }

    // ===============================================================================================
    // HALF B: the real gateway over HTTP
    // ===============================================================================================
    const portB = await freePort();
    const cfgPathB = join(base, "main.yaml");
    const clientsB = `
clients:
  alice:
    description: Alice
    servers: [alpha, beta]
    exclude_tools: ["alpha__delete_*"]
  bob:
    servers: [alpha]
    max_scope: read
  carol:
    servers: ["*"]
    tools: ["gamma__*", "beta__get_*"]
  dave:
    servers: [alpha]
    limits: { per_minute: 2 }
  erin:
    servers: ["*"]
    max_scope: full
`;
    writeFileSync(cfgPathB, configYaml({ port: portB, clients: clientsB }));
    const cfgB = loadConfig(cfgPathB);
    const gwB = await createGateway(cfgB);
    gateways.push(gwB);
    const dashB = await startDashboard(gwB, cfgB, cfgPathB);
    handles.push(dashB);
    assert("gateway B is up on an ephemeral loopback port with five clients and require_auth auto", dashB.url === `http://127.0.0.1:${portB}` && Object.keys(cfgB.clients).length === 5);

    const keys = new ApiKeyStore();
    const K = {};
    for (const c of ["alice", "bob", "carol", "dave", "erin"]) K[c] = keys.issue(c, { client: c });
    const legacyKey = keys.issue("legacy-unbound");
    const ghostKey = keys.issue("ghost", { client: "ghost" });
    const allTokens = [...Object.values(K).map((k) => k.token), legacyKey.token, ghostKey.token];

    // ---- the front door ----
    {
      const none = await mcp(portB, null, "tools/list");
      assert("B: no credential while clients exist is 401, on a loopback bind with require_auth auto", none.status === 401 && /unauthorized/.test(none.body) && /Bearer/.test(none.headers["www-authenticate"] ?? ""));
      assert("B: a garbage bearer token is 401", (await mcp(portB, "sb_not_a_key", "tools/list")).status === 401);
      const lk = await mcp(portB, legacyKey.token, "tools/list");
      assert("B: a valid key bound to no client is 403 SB_NO_CLIENT while clients exist", lk.status === 403 && jsonOf(lk).code === "SB_NO_CLIENT" && /switchboard client add/.test(jsonOf(lk).hint ?? ""), lk.body.slice(0, 160));
      const gk = await mcp(portB, ghostKey.token, "tools/list");
      assert("B: a valid key bound to an unconfigured client is 403 SB_UNKNOWN_CLIENT", gk.status === 403 && jsonOf(gk).code === "SB_UNKNOWN_CLIENT");
      const viaHeader = await raw(portB, "POST", "/mcp", { headers: { accept: "application/json, text/event-stream", "x-api-key": K.alice.token }, body: { jsonrpc: "2.0", id: 1, method: "tools/list" } });
      assert("B: the x-api-key header authenticates a client key too", viaHeader.status === 200);
      assert("B: the 401 and 403 bodies never echo a token", ![none.body, lk.body, gk.body].some((b) => allTokens.some((t) => b.includes(t))));
    }

    // ---- filtered listing ----
    const tools = {};
    for (const c of ["alice", "bob", "carol", "dave", "erin"]) tools[c] = await toolNames(portB, K[c].token);
    assert("B: alice sees alpha and beta without the excluded delete tool and without gamma", same(tools.alice, ["alpha__create_note", "alpha__get_info", "alpha__get_status", "beta__get_info", "beta__get_weather", "beta__send_message"]), tools.alice.join(","));
    assert("B: bob sees only alpha (his max_scope read caps calls, not the listing)", same(tools.bob, ["alpha__create_note", "alpha__delete_note", "alpha__get_info", "alpha__get_status"]), tools.bob.join(","));
    assert("B: carol's tool allowlist cuts across servers (gamma__* and beta__get_*)", same(tools.carol, ["beta__get_info", "beta__get_weather", "gamma__get_time", "gamma__ping"]), tools.carol.join(","));
    assert("B: dave sees alpha", same(tools.dave, tools.bob));
    assert("B: erin (servers *) sees every tool", same(tools.erin, ALL), tools.erin.join(","));
    assert("B: two clients with different allowlists see different tools", !same(tools.alice, tools.bob) && !same(tools.bob, tools.carol) && !same(tools.alice, tools.carol));
    assert("B: the unfiltered Router surface (no principal) still lists everything", same(gwB.router.listTools().map((t) => t.name).sort(), ALL));

    // ---- calls: allowed, hidden, capped ----
    {
      const a1 = await call(portB, K.alice.token, "alpha__get_status");
      assert("B: alice calls an allowed tool", !a1.isError && a1.text === "alpha:get_status", a1.text);
      const aDel = await call(portB, K.alice.token, "alpha__delete_note");
      assert("B: alice's excluded tool is uncallable: SB_POLICY_DENY naming client 'alice'", aDel.isError && aDel.sb?.code === "SB_POLICY_DENY" && /client 'alice'/.test(aDel.sb?.error ?? ""), aDel.text.slice(0, 200));
      const aGam = await call(portB, K.alice.token, "gamma__ping");
      assert("B: a tool of a server outside the client's globs is uncallable", aGam.isError && aGam.sb?.code === "SB_POLICY_DENY" && /client 'alice'/.test(aGam.sb?.error ?? ""));
      const bHide = await call(portB, K.bob.token, "beta__get_weather");
      assert("B: bob cannot call beta (hidden = uncallable), client named", bHide.isError && bHide.sb?.code === "SB_POLICY_DENY" && /client 'bob'/.test(bHide.sb?.error ?? ""));
      const bRead = await call(portB, K.bob.token, "alpha__get_status");
      assert("B: bob can call a read tool under max_scope read", !bRead.isError && bRead.text === "alpha:get_status");
      const bWrite = await call(portB, K.bob.token, "alpha__create_note");
      assert("B: max_scope caps: bob's write call is denied, the client and ceiling are named", bWrite.isError && bWrite.sb?.code === "SB_POLICY_DENY" && /client 'bob'/.test(bWrite.sb?.error ?? "") && /capped at 'read'/.test(bWrite.sb?.error ?? ""), bWrite.sb?.error);
      const bFull = await call(portB, K.bob.token, "alpha__delete_note");
      assert("B: max_scope caps a full tool too", bFull.isError && /client 'bob'/.test(bFull.sb?.error ?? ""));
      const aWrite = await call(portB, K.alice.token, "alpha__create_note");
      assert("B: alice (no max_scope) may write where the server allows it", !aWrite.isError && aWrite.text === "alpha:create_note");
      const cGet = await call(portB, K.carol.token, "gamma__get_time");
      const cHide = await call(portB, K.carol.token, "beta__send_message");
      assert("B: carol's allowlist: an allowed tool works, a tool outside it is denied naming her", !cGet.isError && cGet.text === "gamma:get_time" && cHide.isError && /client 'carol'/.test(cHide.sb?.error ?? ""));
      const cPing = await call(portB, K.carol.token, "gamma__ping");
      assert("B: a client ceiling never raises a server ceiling: gamma is read, ping is a write, the SERVER caps it", cPing.isError && /server 'gamma'/.test(cPing.sb?.error ?? "") && !/client 'carol'/.test(cPing.sb?.error ?? ""), cPing.sb?.error);
      const ePing = await call(portB, K.erin.token, "gamma__ping");
      const eDel = await call(portB, K.erin.token, "alpha__delete_note");
      assert("B: erin (max_scope full) is still bound by the server ceiling, and may do what the server allows", ePing.isError && /server 'gamma'/.test(ePing.sb?.error ?? "") && !eDel.isError && eDel.text === "alpha:delete_note");
      const noSuchServer = await call(portB, K.alice.token, "nowhere__x");
      assert("B: an unknown server prefix is SB_UNKNOWN_TOOL", noSuchServer.isError && noSuchServer.sb?.code === "SB_UNKNOWN_TOOL");
    }
    {
      const log = fixtureLines();
      const count = (s) => log.filter((l) => l === s).length;
      assert("B: a hidden call never reached its upstream (gamma:ping 0, beta:send_message 0)", count("gamma:ping") === 0 && count("beta:send_message") === 0, log.join(","));
      assert("B: only erin's delete reached the upstream (alice's and bob's attempts did not)", count("alpha:delete_note") === 1 && count("alpha:create_note") === 1, `delete=${count("alpha:delete_note")} create=${count("alpha:create_note")}`);
    }

    // ---- per-client limits ----
    {
      const d1 = await call(portB, K.dave.token, "alpha__get_status");
      const d2 = await call(portB, K.dave.token, "alpha__get_status");
      const d3 = await call(portB, K.dave.token, "alpha__get_status");
      assert("B: dave's per_minute 2 allows two calls", !d1.isError && !d2.isError);
      assert("B: the third is SB_RATE_LIMITED naming client 'dave'", d3.isError && d3.sb?.code === "SB_RATE_LIMITED" && /client 'dave'/.test(d3.sb?.error ?? ""), d3.sb?.error);
      const a = await call(portB, K.alice.token, "alpha__get_status");
      assert("B: another client is unaffected by dave's budget", !a.isError);
    }

    // ---- resources and prompts ----
    {
      const rb = await mcp(portB, K.bob.token, "resources/list");
      const ra = await mcp(portB, K.alice.token, "resources/list");
      const uris = (r) => (r.result?.resources ?? []).map((x) => x.uri).sort();
      assert("B: resources/list is filtered by the client's servers", same(uris(rb), ["alpha://readme"]) && same(uris(ra), ["alpha://readme", "beta://secret"]), `${uris(rb)} | ${uris(ra)}`);
      const readOk = await mcp(portB, K.alice.token, "resources/read", { uri: "beta://secret" });
      assert("B: alice reads a resource of an allowed server", readOk.result?.contents?.[0]?.text === "beta resource body");
      const readHidden = await mcp(portB, K.bob.token, "resources/read", { uri: "beta://secret" });
      assert("B: bob cannot read a resource of a server he may not see: SB_POLICY_DENY naming client 'bob'", readHidden.error && /SB_POLICY_DENY/.test(readHidden.error.message) && /client 'bob'/.test(readHidden.error.message), readHidden.error?.message);
      const pb = await mcp(portB, K.bob.token, "prompts/list");
      const pa = await mcp(portB, K.alice.token, "prompts/list");
      const pnames = (r) => (r.result?.prompts ?? []).map((x) => x.name).sort();
      assert("B: prompts/list is filtered by the client's servers", same(pnames(pb), ["alpha__hello_alpha"]) && same(pnames(pa), ["alpha__hello_alpha", "beta__hello_beta"]), `${pnames(pb)} | ${pnames(pa)}`);
      const getOk = await mcp(portB, K.alice.token, "prompts/get", { name: "beta__hello_beta" });
      assert("B: alice gets a prompt of an allowed server", getOk.result?.messages?.[0]?.content?.text === "beta prompt body");
      const getHidden = await mcp(portB, K.bob.token, "prompts/get", { name: "beta__hello_beta" });
      assert("B: bob cannot get a prompt of a server he may not see, client named", getHidden.error && /SB_POLICY_DENY/.test(getHidden.error.message) && /client 'bob'/.test(getHidden.error.message), getHidden.error?.message);
      const getBare = await mcp(portB, K.bob.token, "prompts/get", { name: "hello_beta" });
      assert("B: a bare prompt name only matches the servers the client may see", getBare.error && /unknown prompt/.test(getBare.error.message), getBare.error?.message);
      const rt = await mcp(portB, K.bob.token, "resources/templates/list");
      assert("B: resources/templates/list answers for a client", rt.status === 200 && Array.isArray(rt.result?.resourceTemplates));
      const readUnknown = await mcp(portB, K.alice.token, "resources/read", { uri: "nowhere://x" });
      assert("B: an unlisted resource URI is unknown for everyone", readUnknown.error && /unknown resource/.test(readUnknown.error.message));
    }

    // ---- audit ----
    {
      const rows = recentAudit(1000);
      const aliceKeyId = K.alice.record.id;
      const okRow = rows.find((r) => r.server === "alpha" && r.tool === "get_status" && r.client === "alice" && r.decision === "allow");
      assert("B: an allowed call's row carries principal 'apikey:<key id>' and the client", okRow && okRow.principal === `apikey:${aliceKeyId}`, JSON.stringify(okRow));
      const denyRow = rows.find((r) => r.tool === "create_note" && r.client === "bob" && r.decision === "deny");
      assert("B: a denied call's row carries the client and SB_POLICY_DENY", denyRow && denyRow.error_code === "SB_POLICY_DENY" && denyRow.principal === `apikey:${K.bob.record.id}`, JSON.stringify(denyRow));
      const hiddenRow = rows.find((r) => r.tool === "get_weather" && r.client === "bob" && r.decision === "deny");
      assert("B: a hidden-from-client call is audited as a deny with the client in the reason", hiddenRow && /hidden from client 'bob'/.test(hiddenRow.reason ?? ""), JSON.stringify(hiddenRow));
      const rlRow = rows.find((r) => r.client === "dave" && r.error_code === "SB_RATE_LIMITED");
      assert("B: a rate limited call is audited with the client", !!rlRow);
      const resRow = rows.find((r) => r.tool === "resources/read" && r.client === "bob" && r.decision === "deny");
      const resOkRow = rows.find((r) => r.tool === "resources/read" && r.client === "alice" && r.decision === "allow");
      assert("B: resources/read rows (denied and allowed) carry the client", !!resRow && !!resOkRow);
      assert("B: the audit chain still verifies with the new fields", verifyAudit().ok === true, JSON.stringify(verifyAudit().break ?? ""));
    }

    // ---- hot edit of the config file (no admin API) ----
    {
      const text = readFileSync(cfgPathB, "utf8");
      writeFileSync(cfgPathB, text.replace(`exclude_tools: ["alpha__delete_*"]`, `exclude_tools: ["alpha__delete_*", "beta__send_*"]`));
      const t = await toolNames(portB, K.alice.token);
      assert("B: editing the config file changes alice's tools on the running gateway", !t.includes("beta__send_message") && t.includes("beta__get_weather"), t.join(","));
      const cl = await call(portB, K.alice.token, "beta__send_message");
      assert("B: and the newly excluded tool is uncallable at once", cl.isError && /client 'alice'/.test(cl.sb?.error ?? ""));
      const keep = JSON.stringify(cfgB.clients);
      writeFileSync(cfgPathB, "gateway: [broken\n");
      const t2 = await toolNames(portB, K.alice.token);
      assert("B: a broken config file is ignored, the previous clients stay in force", same(t2, t) && JSON.stringify(cfgB.clients) === keep);
      writeFileSync(cfgPathB, text.replace(`servers: [alpha, beta]\n    exclude_tools`, `servers: [alpha, beta, gamma]\n    exclude_tools`));
      const t3 = await toolNames(portB, K.alice.token);
      assert("B: a valid edit after a broken one is picked up", t3.includes("gamma__get_time"), t3.join(","));
      writeFileSync(cfgPathB, text);
      const t4 = await toolNames(portB, K.alice.token);
      assert("B: restoring the file restores the original view", same(t4, tools.alice));
    }

    // ---- admin API ----
    {
      const code = new LoginCodeStore().mint();
      const login = await raw(portB, "POST", "/api/session", { body: { code } });
      const sid = (login.headers["set-cookie"] ?? []).find((c) => c.startsWith("switchboard_session="))?.split(";")[0] ?? "";
      const csrf = jsonOf(login).csrf;
      assert("B: owner login for the admin API", login.status === 200 && !!sid && !!csrf);
      const corpus = [];
      const adm = async (method, path, body, { csrfOn = true, cookieOn = true, collect = true } = {}) => {
        const r = await raw(portB, method, path, { cookie: cookieOn ? sid : undefined, headers: csrfOn ? { "x-switchboard-csrf": csrf } : {}, body });
        if (collect) corpus.push(r.body);
        return r;
      };
      const noSession = await adm("GET", "/api/clients", undefined, { cookieOn: false, csrfOn: false });
      assert("B: GET /api/clients without an owner session is 401", noSession.status === 401);
      const bearer = await raw(portB, "GET", "/api/clients", { headers: { authorization: `Bearer ${K.alice.token}` } });
      assert("B: a client key is never accepted on the admin API", bearer.status === 401);
      const noCsrf = await adm("POST", "/api/clients", { id: "frank", servers: ["gamma"] }, { csrfOn: false });
      assert("B: POST /api/clients with a session but no CSRF is 403", noCsrf.status === 403 && !existsSync(CK.clientKeyPath("frank")));

      const list0 = await adm("GET", "/api/clients");
      const l0 = jsonOf(list0);
      assert("B: GET /api/clients lists the five clients with their keys and key file flags", list0.status === 200 && l0.clients?.length === 5 && l0.enforced === true && l0.clients.find((c) => c.id === "alice")?.keys?.length === 1 && l0.clients.find((c) => c.id === "alice")?.servers?.length === 2, list0.body.slice(0, 200));
      assert("B: the list reports keys bound to unconfigured clients", (l0.orphan_keys ?? []).some((k) => k.client === "ghost"));

      const add = await adm("POST", "/api/clients", { id: "frank", servers: ["gamma"], max_scope: "read", description: "Frank" });
      const addJ = jsonOf(add);
      assert("B: POST /api/clients creates the client: 201, a key record, no token", add.status === 201 && addJ.id === "frank" && addJ.key?.client === "frank" && addJ.token === undefined && !("token" in (addJ.key ?? {})), add.body.slice(0, 200));
      assert("B: the key went to the client key file only", existsSync(CK.clientKeyPath("frank")) && !!CK.readClientKey("frank"));
      const frank1 = CK.readClientKey("frank");
      const cfgText = readFileSync(cfgPathB, "utf8");
      assert("B: the config file gained the client and kept its comment", /frank:/.test(cfgText) && cfgText.includes("# ORACLE-MARKER keep this comment") && loadConfig(cfgPathB).clients.frank.servers[0] === "gamma");
      assert("B: the new client works on the running gateway at once", same(await toolNames(portB, frank1), ["gamma__get_time", "gamma__ping"]));
      const dup = await adm("POST", "/api/clients", { id: "frank" });
      assert("B: adding an existing id is 409", dup.status === 409);
      assert("B: an invalid id is 400", (await adm("POST", "/api/clients", { id: "Bad Id" })).status === 400 && (await adm("POST", "/api/clients", {})).status === 400);
      assert("B: an unknown field is 400 (nothing is guessed)", (await adm("POST", "/api/clients", { id: "gus", admin: true })).status === 400 && (await adm("PUT", "/api/clients/frank", { servrs: ["x"] })).status === 400);
      assert("B: an invalid value is 400 and creates nothing", (await adm("POST", "/api/clients", { id: "gus", max_scope: "root" })).status === 400 && !existsSync(CK.clientKeyPath("gus")) && loadConfig(cfgPathB).clients.gus === undefined);

      const put = await adm("PUT", "/api/clients/frank", { servers: ["alpha"], tools: ["alpha__get_*"], max_scope: "write", max_risk: "medium" });
      assert("B: PUT /api/clients/:id changes servers, tools, max_scope and max_risk", put.status === 200 && jsonOf(put).client?.max_risk === "medium" && same(jsonOf(put).client?.tools, ["alpha__get_*"]));
      assert("B: the change is live without a restart", same(await toolNames(portB, frank1), ["alpha__get_info", "alpha__get_status"]));
      assert("B: PUT of an unknown client is 404", (await adm("PUT", "/api/clients/nobody", { servers: ["*"] })).status === 404);

      const rot = await adm("POST", "/api/clients/frank/rotate");
      const frank2 = CK.readClientKey("frank");
      assert("B: POST /api/clients/:id/rotate returns nothing secret and writes a new key file", rot.status === 200 && jsonOf(rot).rotated === "frank" && jsonOf(rot).revoked === 1 && frank2 !== frank1 && !rot.body.includes(frank2), rot.body.slice(0, 160));
      assert("B: the old key is dead on the running gateway, the new one works", (await mcp(portB, frank1, "tools/list")).status === 401 && (await mcp(portB, frank2, "tools/list")).status === 200);
      assert("B: rotate of an unknown client is 404", (await adm("POST", "/api/clients/nobody/rotate")).status === 404);

      // The generic key route returns its token once, by design (it predates clients); it is not part of the no-token corpus.
      const bound = await adm("POST", "/api/apikeys", { name: "extra", client: "bob" }, { collect: false });
      assert("B: POST /api/apikeys can bind a key to a configured client", bound.status === 200 && jsonOf(bound).key?.client === "bob" && (await mcp(portB, jsonOf(bound).token, "tools/list")).status === 200);
      assert("B: binding a key to an unknown client is 400", (await adm("POST", "/api/apikeys", { name: "x", client: "nobody" }, { collect: false })).status === 400);
      const keysList = await adm("GET", "/api/apikeys", undefined, { collect: false });
      assert("B: GET /api/apikeys shows the client of each key", (jsonOf(keysList).keys ?? []).some((k) => k.client === "bob"));

      const del = await adm("DELETE", "/api/clients/frank");
      assert("B: DELETE /api/clients/:id removes the entry, revokes its keys and deletes the key file", del.status === 200 && jsonOf(del).revoked_keys === 1 && !existsSync(CK.clientKeyPath("frank")) && loadConfig(cfgPathB).clients.frank === undefined);
      assert("B: the deleted client's key no longer works", (await mcp(portB, frank2, "tools/list")).status === 401);
      assert("B: deleting an unknown client is 404", (await adm("DELETE", "/api/clients/frank")).status === 404);
      const finalCfg = readFileSync(cfgPathB, "utf8");
      assert("B: the config file still has its comment and the original five clients", finalCfg.includes("# ORACLE-MARKER keep this comment") && Object.keys(loadConfig(cfgPathB).clients).sort().join() === "alice,bob,carol,dave,erin");
      const adminRows = recentAudit(2000).filter((r) => r.tool.startsWith("client.") && r.principal === "owner:dashboard");
      assert("B: every admin change left an audit row (add, update, rotate, remove), attributed to the dashboard owner, naming the client", ["client.add", "client.update", "client.rotate", "client.remove"].every((t) => adminRows.some((r) => r.tool === t && /client 'frank'/.test(r.reason ?? "") && r.server === "switchboard" && r.decision === "allow")), adminRows.map((r) => r.tool).join(","));
      assert("B: the admin audit rows carry no token", !adminRows.some((r) => allTokens.some((t) => JSON.stringify(r).includes(t)) || JSON.stringify(r).includes(frank1) || JSON.stringify(r).includes(frank2)));
      const everything = corpus.join("\n");
      assert("B: no clients admin response ever contained a token, a token shape or a key hash", !allTokens.some((t) => everything.includes(t)) && !everything.includes(frank1) && !everything.includes(frank2) && !/sb_[A-Za-z0-9_-]{30,}/.test(everything) && !/"hash"/.test(everything), `${corpus.length} responses`);
    }

    await retire(dashB, gwB);

    // ===============================================================================================
    // HALF C: legacy mode, then the CLI end to end against a running gateway (no restart)
    // ===============================================================================================
    const portC = await freePort();
    const cfgPathC = join(base, "legacy.yaml");
    writeFileSync(cfgPathC, configYaml({ port: portC, servers: ["alpha", "gamma"] }));
    const cfgC = loadConfig(cfgPathC);
    const gwC = await createGateway(cfgC);
    gateways.push(gwC);
    const dashC = await startDashboard(gwC, cfgC, cfgPathC);
    handles.push(dashC);
    const urlC = `http://127.0.0.1:${portC}/mcp`;
    const cli = (args, opts) => cliRun(["--config", cfgPathC, ...args], opts);
    const secretShape = /sb_[A-Za-z0-9_-]{30,}/;

    {
      const t0 = await toolNames(portC, null);
      assert("C: legacy mode (no clients): no credential needed on loopback and every tool is listed", same(t0, ["alpha__create_note", "alpha__delete_note", "alpha__get_info", "alpha__get_status", "gamma__get_time", "gamma__ping"]), t0.join(","));
      const c0 = await call(portC, null, "gamma__get_time");
      assert("C: legacy mode: an anonymous call works as in 0.1.0", !c0.isError && c0.text === "gamma:get_time");
      const legacy = keys.issue("legacy-c");
      const lc = await call(portC, legacy.token, "alpha__get_status");
      assert("C: legacy mode: an unbound key works", !lc.isError && lc.text === "alpha:get_status");
      const rowsA = recentAudit(500);
      const anon = rowsA.find((r) => r.tool === "get_time" && r.server === "gamma" && r.principal === "loopback-anonymous:loopback");
      assert("C: legacy mode: an anonymous call is audited as loopback-anonymous with no client", !!anon && anon.client === undefined, JSON.stringify(anon));
      const keyed = rowsA.find((r) => r.tool === "get_status" && r.principal === `apikey:${legacy.record.id}`);
      assert("C: legacy mode: a key call is audited as the key, with no client", !!keyed && keyed.client === undefined);
      const badTok = await mcp(portC, "sb_garbage", "tools/list");
      assert("C: legacy mode: auth stays off on loopback (a stale token is ignored, as before)", badTok.status === 200);

      // --- client add (writes the config and the key file; prints no token) ---
      const cfgBefore = readFileSync(cfgPathC, "utf8");
      const add1 = await cli(["client", "add", "coder", "--servers", "alpha", "--max-scope", "read"]);
      assert("C: `client add coder` exits 0", add1.code === 0, add1.stderr.slice(0, 200));
      assert("C: it prints no token without --print", !secretShape.test(add1.stdout + add1.stderr), (add1.stdout + add1.stderr).slice(0, 200));
      assert("C: it says where the key went and how to use it", /key: issued and stored for the bridge/.test(add1.stdout) && /bridge --client coder/.test(add1.stdout));
      const cfgAfter = readFileSync(cfgPathC, "utf8");
      assert("C: the config file has the client and kept its comment and servers", /coder:/.test(cfgAfter) && cfgAfter.includes("# ORACLE-MARKER keep this comment") && cfgAfter.includes("id: alpha") && loadConfig(cfgPathC).clients.coder.max_scope === "read");
      assert("C: a .bak of the previous config was kept", existsSync(`${cfgPathC}.bak`) && readFileSync(`${cfgPathC}.bak`, "utf8") === cfgBefore);
      assert("C: the key file exists and holds a token the key store accepts for 'coder'", (() => { const t = CK.readClientKey("coder"); return !!t && new ApiKeyStore().inspect(t)?.client === "coder"; })());

      // --- the running gateway, no restart ---
      const t1 = CK.readClientKey("coder");
      const un = await mcp(portC, null, "tools/list");
      assert("C: with no restart the gateway now refuses an unauthenticated request (401)", un.status === 401);
      const lk = await mcp(portC, legacy.token, "tools/list");
      assert("C: and an unbound key is now 403 SB_NO_CLIENT", lk.status === 403 && jsonOf(lk).code === "SB_NO_CLIENT");
      assert("C: the new client's key lists only its servers", same(await toolNames(portC, t1), ["alpha__create_note", "alpha__delete_note", "alpha__get_info", "alpha__get_status"]));

      const bridge1 = await lineSession(["bridge", "--client", "coder", "--url", urlC], [initMsg(1), toolsMsg(2), callMsg(3, "alpha__get_status"), callMsg(4, "alpha__create_note"), callMsg(5, "gamma__get_time")], { want: 5 });
      const tl = (bridge1.got.get(2)?.result?.tools ?? []).map((t) => t.name).sort();
      const text3 = bridge1.got.get(3)?.result?.content?.[0]?.text;
      const text4 = bridge1.got.get(4)?.result?.content?.[0]?.text ?? "";
      const text5 = bridge1.got.get(5)?.result?.content?.[0]?.text ?? "";
      assert("C: `bridge --client coder` works end to end with no further step: initialize, filtered tools/list", !!bridge1.got.get(1)?.result?.serverInfo && same(tl, ["alpha__create_note", "alpha__delete_note", "alpha__get_info", "alpha__get_status"]), tl.join(","));
      assert("C: through the bridge an allowed call works, a write is capped by max_scope read, a hidden server is denied naming 'coder'", text3 === "alpha:get_status" && /capped at 'read'/.test(text4) && /client 'coder'/.test(text4) && /client 'coder'/.test(text5), `${text3} | ${text4.slice(0, 120)} | ${text5.slice(0, 120)}`);
      assert("C: the bridge never printed the token", !bridge1.out.includes(t1) && !bridge1.err.includes(t1));

      const rowsB = recentAudit(500);
      assert("C: the bridge's calls are audited with the client 'coder'", rowsB.some((r) => r.tool === "get_status" && r.client === "coder" && r.decision === "allow" && /^apikey:/.test(r.principal ?? "")));

      // --- client list: no secrets ---
      const lst = await cli(["client", "list"]);
      assert("C: `client list` shows the client, its servers and scope, and no secret", lst.code === 0 && /coder/.test(lst.stdout) && /servers: alpha/.test(lst.stdout) && /max_scope: read/.test(lst.stdout) && !secretShape.test(lst.stdout + lst.stderr) && !(lst.stdout + lst.stderr).includes(t1));

      // --- add again: update, keep the key ---
      const keyFileBytes = readFileSync(CK.clientKeyPath("coder"));
      const add2 = await cli(["client", "add", "coder", "--max-scope", "write", "--print"]);
      assert("C: `client add` on an existing client updates it and keeps the working key", add2.code === 0 && /updated/.test(add2.stderr) && /existing key is kept/.test(add2.stdout) && !secretShape.test(add2.stdout + add2.stderr), (add2.stdout + add2.stderr).slice(0, 240));
      assert("C: the key file was not rewritten and the servers list was kept", readFileSync(CK.clientKeyPath("coder")).equals(keyFileBytes) && loadConfig(cfgPathC).clients.coder.max_scope === "write" && loadConfig(cfgPathC).clients.coder.servers[0] === "alpha");
      const bridge2 = await lineSession(["bridge", "--client", "coder", "--url", urlC], [initMsg(1), callMsg(2, "alpha__create_note")], { want: 2 });
      assert("C: the update is live: the same bridge, no restart, may now write", bridge2.got.get(2)?.result?.content?.[0]?.text === "alpha:create_note", bridge2.got.get(2)?.result?.content?.[0]?.text);

      // --- rotate ---
      const rot = await cli(["client", "rotate", "coder", "--print"]);
      const t2 = CK.readClientKey("coder");
      assert("C: `client rotate --print` prints exactly the new token once (the one in the key file)", rot.code === 0 && rot.stdout.includes(t2) && t2 !== t1, rot.stdout.slice(0, 200));
      assert("C: rotate invalidates the old key on the running gateway (401), the new one works", (await mcp(portC, t1, "tools/list")).status === 401 && (await mcp(portC, t2, "tools/list")).status === 200);
      const bridge3 = await lineSession(["bridge", "--client", "coder", "--url", urlC], [initMsg(1), callMsg(2, "alpha__get_status")], { want: 2 });
      assert("C: the bridge picks the rotated key up from the key file with no change", bridge3.got.get(2)?.result?.content?.[0]?.text === "alpha:get_status");
      assert("C: `client rotate` without --print prints no token", !secretShape.test((await cli(["client", "rotate", "coder"])).stdout));
      const t3 = CK.readClientKey("coder");

      // --- rm without --purge ---
      const rm1 = await cli(["client", "rm", "coder"]);
      assert("C: `client rm` revokes the key, deletes the key file and keeps the config entry", rm1.code === 0 && /1 key\(s\) revoked/.test(rm1.stderr) && CK.readClientKey("coder") === null && loadConfig(cfgPathC).clients.coder !== undefined);
      assert("C: the revoked key is dead on the running gateway, and the gateway stays closed (clients still configured)", (await mcp(portC, t3, "tools/list")).status === 401 && (await mcp(portC, null, "tools/list")).status === 401);
      const bridge4 = await lineSession(["bridge", "--client", "coder", "--url", urlC], [initMsg(1)], { want: 1 });
      assert("C: the bridge for a removed client answers with a JSON-RPC error, not a crash", bridge4.got.get(1)?.error !== undefined && bridge4.code === 0, JSON.stringify(bridge4.got.get(1)).slice(0, 160));
      assert("C: `client list` flags the missing key file", /key file: missing/.test((await cli(["client", "list"])).stdout));

      // --- failures leave the config alone ---
      const snap = readFileSync(cfgPathC, "utf8");
      const f1 = await cli(["client", "add", "Bad_ID"]);
      const f2 = await cli(["client", "add", "okid", "--max-scope", "bogus"]);
      const f3 = await cli(["client", "add", "okid", "--max-risk", "bogus"]);
      const f4 = await cli(["client", "rotate", "nosuch"]);
      const f5 = await cli(["client", "rm", "nosuch"]);
      const f6 = await cli(["client", "add", "okid", "--servers", `${"x".repeat(200)}`]);
      assert("C: bad input exits 1 with one clear line each", [f1, f2, f3, f4, f5, f6].every((r) => r.code === 1 && r.stderr.trim().length > 0 && !/at .*\.js:\d+/.test(r.stderr)), [f1, f2, f3, f4, f5, f6].map((r) => r.code).join(","));
      assert("C: and none of them changed the config file or created a key", readFileSync(cfgPathC, "utf8") === snap && !existsSync(CK.clientKeyPath("okid")));
      const ak1 = await cli(["apikey", "new", "bound-key", "--client", "nosuch"]);
      assert("C: `apikey new --client` refuses an unconfigured client", ak1.code === 1 && /not configured/.test(ak1.stderr));
      const ak2 = await cli(["apikey", "new", "bound-key", "--client", "coder"]);
      const akTok = ak2.stdout.match(/sb_[A-Za-z0-9_-]{30,}/)?.[0];
      assert("C: `apikey new --client coder` issues a key bound to it (and `apikey list` shows the client)", ak2.code === 0 && !!akTok && (await mcp(portC, akTok, "tools/list")).status === 200 && /client coder/.test((await cli(["apikey", "list"])).stdout));

      // --- purge returns the gateway to legacy mode ---
      const rm2 = await cli(["client", "rm", "coder", "--purge"]);
      const cfgFinal = readFileSync(cfgPathC, "utf8");
      assert("C: `client rm --purge` removes the config entry and keeps the comment", rm2.code === 0 && /config entry removed/.test(rm2.stderr) && !cfgFinal.includes("clients:") && cfgFinal.includes("# ORACLE-MARKER keep this comment"));
      assert("C: removing the last client puts the running gateway back in legacy mode (no credential needed)", (await mcp(portC, null, "tools/list")).status === 200);
      assert("C: --purge also revoked the keys bound to the client (apikey list no longer shows it)", !/client coder/.test((await cli(["apikey", "list"])).stdout));
      assert("C: no client key file is left behind", !existsSync(CK.clientKeyPath("coder")));
      const cliRows = recentAudit(2000).filter((r) => r.tool.startsWith("client.") && r.principal === "owner:cli" && /client 'coder'/.test(r.reason ?? ""));
      assert("C: the CLI changes are audited as owner:cli (add, rotate, remove), naming the client", ["client.add", "client.rotate", "client.remove"].every((t) => cliRows.some((r) => r.tool === t)), cliRows.map((r) => r.tool).join(","));
      const rawLog = readdirSync(SBHOME).filter((n) => n.startsWith("audit.log")).map((n) => readFileSync(join(SBHOME, n), "utf8")).join("\n");
      assert("C: no client token ever reached the audit log (checked in the raw file)", ![t1, t2, t3, akTok].some((t) => rawLog.includes(t)) && rawLog.length > 1000);
      assert("C: the audit chain verifies after rows from the gateway and the CLI", verifyAudit().ok === true);
    }
    await retire(dashC, gwC);

    // ===============================================================================================
    // HALF D: stdio
    // ===============================================================================================
    {
      const cfgPathD = join(base, "stdio.yaml");
      writeFileSync(cfgPathD, configYaml({ port: 1, transport: "[stdio]", servers: ["alpha", "beta"], clients: `\nclients:\n  s1:\n    servers: [alpha]\n    max_scope: read\n  s2:\n    servers: [beta]\n` }));
      const run = (extra, msgs, want) => lineSession(["--config", cfgPathD, "serve", ...extra], msgs, { want, killAfter: true });
      const s1 = await run(["--client", "s1"], [initMsg(1), toolsMsg(2), callMsg(3, "alpha__get_status"), callMsg(4, "beta__get_weather"), callMsg(5, "alpha__create_note")], 5);
      const names = (s1.got.get(2)?.result?.tools ?? []).map((t) => t.name).sort();
      assert("D: `serve --client s1` lists only s1's servers", same(names, ["alpha__create_note", "alpha__delete_note", "alpha__get_info", "alpha__get_status"]), names.join(",") || s1.err.slice(0, 200));
      assert("D: an allowed call works, a hidden server is denied naming s1, max_scope read caps a write", s1.got.get(3)?.result?.content?.[0]?.text === "alpha:get_status" && /client 's1'/.test(s1.got.get(4)?.result?.content?.[0]?.text ?? "") && /capped at 'read'/.test(s1.got.get(5)?.result?.content?.[0]?.text ?? ""), JSON.stringify([s1.got.get(4)?.result?.content?.[0]?.text]));
      assert("D: stdout carried JSON-RPC lines only", s1.out.split(/\r?\n/).filter(Boolean).every((l) => l.startsWith("{")));
      await sleep(200);
      const rows = recentAudit(500);
      assert("D: the stdio calls are audited via 'stdio' with the client", rows.some((r) => r.tool === "get_status" && r.client === "s1" && r.principal === "stdio:s1" && r.decision === "allow") && rows.some((r) => r.tool === "get_weather" && r.client === "s1" && r.decision === "deny"));
      const s2 = await run(["--client", "s2"], [initMsg(1), toolsMsg(2)], 2);
      assert("D: a second client gets its own view over the same config", same((s2.got.get(2)?.result?.tools ?? []).map((t) => t.name).sort(), ["beta__get_info", "beta__get_weather", "beta__send_message"]));
      const noClient = await cliRun(["--config", cfgPathD, "serve"], { timeoutMs: 30_000 });
      assert("D: clients configured and stdio only: `serve` without --client refuses to start (exit 1) and says why", noClient.code === 1 && /--client/.test(noClient.stderr), noClient.stderr.slice(0, 200));
      const badClient = await cliRun(["--config", cfgPathD, "serve", "--client", "nosuch"], { timeoutMs: 30_000 });
      assert("D: `serve --client` for an unconfigured client exits 1", badClient.code === 1 && /not configured/.test(badClient.stderr));
      const badId = await cliRun(["--config", cfgPathD, "serve", "--client", "Bad Id"], { timeoutMs: 30_000 });
      assert("D: `serve --client` with an invalid id exits 1", badId.code === 1 && /invalid client id/.test(badId.stderr));
      {
        const portD2 = await freePort();
        const cfgPathD2 = join(base, "both.yaml");
        writeFileSync(cfgPathD2, configYaml({ port: portD2, transport: "[stdio, http]", servers: ["alpha"], clients: "\nclients:\n  s1:\n    servers: [alpha]\n" }));
        const child = spawn(process.execPath, [CLI, "--config", cfgPathD2, "serve"], { env: childEnv(), stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
        children.add(child);
        let errBuf = "";
        child.stderr.on("data", (c) => (errBuf += c));
        let up = false;
        for (let i = 0; i < 60 && !up; i++) {
          up = (await raw(portD2, "GET", "/healthz")).status === 200;
          if (!up) await sleep(500);
        }
        const noKey = up ? await raw(portD2, "POST", "/mcp", { headers: { accept: "application/json, text/event-stream" }, body: { jsonrpc: "2.0", id: 1, method: "tools/list" } }) : { status: 0 };
        killTree(child);
        children.delete(child);
        assert("D: clients with stdio and http configured, no --client: HTTP runs and demands a client key (401), stdio is skipped with a warning", up && noKey.status === 401 && /stdio transport is not served without --client/.test(errBuf), `up=${up} status=${noKey.status}`);
      }
    }

    // ===============================================================================================
    // HALF E: OAuth
    // ===============================================================================================
    {
      const portE = await freePort();
      const PUBLIC = `http://127.0.0.1:${portE}`;
      const cfgE = {
        gateway: { transport: ["http"], http: { host: "127.0.0.1", port: portE, require_auth: "auto" }, tool_exposure: "namespaced", default_policy: "read" },
        vault: { backend: "encrypted-file" },
        servers: [{ id: "alpha", source: "binary", command: process.execPath, args: [SELF, "--upstream", "alpha"], enabled: true, policy: "full", env: { SB_FIXTURE_LOG: FIXLOG } }, { id: "gamma", source: "binary", command: process.execPath, args: [SELF, "--upstream", "gamma"], enabled: true, policy: "read", env: { SB_FIXTURE_LOG: FIXLOG } }],
        settings: { oauth_server: { enabled: true, public_url: PUBLIC, consent: true, access_token_ttl: 3600, refresh_token_ttl: 1209600 } },
        clients: { oalice: { servers: ["alpha"], max_scope: "read" }, obob: { servers: ["gamma"] } },
      };
      const gwE = await createGateway(cfgE);
      gateways.push(gwE);
      const dashE = await startDashboard(gwE, cfgE);
      handles.push(dashE);
      const code = new LoginCodeStore().mint();
      const login = await raw(portE, "POST", "/api/session", { body: { code } });
      const sidE = (login.headers["set-cookie"] ?? []).find((c) => c.startsWith("switchboard_session="))?.split(";")[0] ?? "";
      const csrfE = jsonOf(login).csrf;
      const b64url = (b) => b.toString("base64url");
      const formHeaders = { "content-type": "application/x-www-form-urlencoded" };
      const form = (o) => new URLSearchParams(o).toString();
      async function oauthToken(clientName) {
        const meta = { client_name: clientName, redirect_uris: ["http://127.0.0.1:7777/callback"], token_endpoint_auth_method: "none", grant_types: ["authorization_code", "refresh_token"], response_types: ["code"] };
        const reg = jsonOf(await raw(portE, "POST", "/register", { body: meta }));
        const verifier = b64url(randomBytes(32));
        const challenge = b64url(createHash("sha256").update(verifier).digest());
        const auth = await raw(portE, "GET", `/authorize?response_type=code&client_id=${encodeURIComponent(reg.client_id)}&redirect_uri=${encodeURIComponent(meta.redirect_uris[0])}&code_challenge=${challenge}&code_challenge_method=S256&state=st&scope=read&resource=${encodeURIComponent(`${PUBLIC}/mcp`)}`, { cookie: sidE });
        const pending = auth.body.match(/name="pending_id"\s+value="([^"]+)"/)?.[1];
        const approve = await raw(portE, "POST", "/oauth/consent", { cookie: sidE, headers: { ...formHeaders, "x-switchboard-csrf": csrfE }, body: form({ pending_id: pending, decision: "approve" }) });
        const authCode = new URL(approve.headers.location ?? "http://x/", "http://x").searchParams.get("code");
        const tok = await raw(portE, "POST", "/token", { headers: formHeaders, body: form({ grant_type: "authorization_code", code: authCode, redirect_uri: meta.redirect_uris[0], client_id: reg.client_id, code_verifier: verifier, resource: `${PUBLIC}/mcp` }) });
        return { token: jsonOf(tok).access_token, clientId: reg.client_id };
      }
      const oa = await oauthToken("oalice");
      const ob = await oauthToken("obob");
      const os = await oauthToken("stranger");
      assert("E: three OAuth clients got owner-approved tokens", !!oa.token && !!ob.token && !!os.token);
      assert("E: an OAuth client named like a configured client id sees that client's tools", same(await toolNames(portE, oa.token), ["alpha__create_note", "alpha__delete_note", "alpha__get_info", "alpha__get_status"]) && same(await toolNames(portE, ob.token), ["gamma__get_time", "gamma__ping"]));
      const oRead = await call(portE, oa.token, "alpha__get_status");
      const oWrite = await call(portE, oa.token, "alpha__create_note");
      const oHidden = await call(portE, oa.token, "gamma__get_time");
      assert("E: the mapped client's filter and ceiling are enforced on OAuth calls", !oRead.isError && /client 'oalice'/.test(oWrite.sb?.error ?? "") && /capped at 'read'/.test(oWrite.sb?.error ?? "") && /client 'oalice'/.test(oHidden.sb?.error ?? ""));
      const st = await mcp(portE, os.token, "tools/list");
      assert("E: an OAuth client whose name matches no configured client is 403 SB_NO_CLIENT (clients are configured)", st.status === 403 && jsonOf(st).code === "SB_NO_CLIENT" && /client_name/.test(jsonOf(st).hint ?? ""));
      assert("E: no token at all is still 401 with the resource_metadata challenge", await (async () => { const r = await mcp(portE, null, "tools/list"); return r.status === 401 && /resource_metadata=/.test(r.headers["www-authenticate"] ?? ""); })());
      const rowsE = recentAudit(500);
      assert("E: OAuth calls are audited as 'oauth:<oauth client id>' with the mapped client", rowsE.some((r) => r.tool === "get_status" && r.client === "oalice" && r.principal === `oauth:${oa.clientId}`), JSON.stringify(rowsE.find((r) => r.client === "oalice")));
      const k = keys.issue("e-key", { client: "obob" });
      assert("E: an API key bound to a client works beside OAuth", same(await toolNames(portE, k.token), ["gamma__get_time", "gamma__ping"]));
      await retire(dashE, gwE);
    }

    // ===============================================================================================
    // HALF F: search and flat exposure
    // ===============================================================================================
    {
      const mkCfg = (port, exposure, clients, requireAuth = "auto") => ({
        gateway: { transport: ["http"], http: { host: "127.0.0.1", port, require_auth: requireAuth }, tool_exposure: exposure, default_policy: "read" },
        vault: { backend: "encrypted-file" },
        servers: ["alpha", "beta"].map((id) => ({ id, source: "binary", command: process.execPath, args: [SELF, "--upstream", id], enabled: true, policy: POLICY[id], env: { SB_FIXTURE_LOG: FIXLOG } })),
        clients,
      });
      // search mode
      const portS = await freePort();
      const cfgS = mkCfg(portS, "search", { sbob: { servers: ["alpha"], max_scope: "read" }, salice: { servers: ["*"] } });
      const gwS = await createGateway(cfgS);
      gateways.push(gwS);
      const dashS = await startDashboard(gwS, cfgS);
      handles.push(dashS);
      const sb = keys.issue("sb", { client: "sbob" });
      const sa = keys.issue("sa", { client: "salice" });
      const listS = await toolNames(portS, sb.token);
      assert("F: search mode lists the three meta tools for a client", same(listS, ["batch_call", "call_tool", "find_tools"]));
      const findB = await call(portS, sb.token, "find_tools", { query: "weather message status" });
      const matchesB = JSON.parse(findB.text).matches.map((m) => m.name);
      assert("F: find_tools returns only tools the client may see (no beta tool even for a beta query)", matchesB.length > 0 && matchesB.every((n) => n.startsWith("alpha__")), matchesB.join(","));
      const findA = await call(portS, sa.token, "find_tools", { query: "weather" });
      assert("F: and for a client that may see beta the same query finds it", JSON.parse(findA.text).matches.some((m) => m.name === "beta__get_weather"));
      const callHidden = await call(portS, sb.token, "call_tool", { name: "beta__get_weather", arguments: {} });
      assert("F: call_tool on a hidden tool is denied naming the client", callHidden.isError && /client 'sbob'/.test(callHidden.sb?.error ?? ""), callHidden.text.slice(0, 160));
      const callCap = await call(portS, sb.token, "call_tool", { name: "alpha__create_note", arguments: {} });
      assert("F: call_tool is capped by max_scope too", callCap.isError && /capped at 'read'/.test(callCap.sb?.error ?? ""));
      const batch = await call(portS, sb.token, "batch_call", { calls: [{ name: "alpha__get_status" }, { name: "beta__get_weather" }, { name: "alpha__create_note" }] });
      const bres = JSON.parse(batch.text).results;
      assert("F: batch_call gates every entry independently (ok, hidden, capped), in order", bres.length === 3 && bres[0].isError === false && bres[1].isError === true && /client 'sbob'/.test(bres[1].content[0].text) && bres[2].isError === true && /capped/.test(bres[2].content[0].text));
      const direct = await call(portS, sb.token, "beta__get_weather");
      assert("F: a direct namespaced call is gated in search mode as well", direct.isError && /client 'sbob'/.test(direct.sb?.error ?? ""));
      await retire(dashS, gwS);

      // flat mode: alpha and beta both define get_info; alpha claims it.
      const portF = await freePort();
      const cfgF = mkCfg(portF, "flat", { falpha: { servers: ["alpha"] }, fbeta: { servers: ["beta"] } }, "never");
      const gwF = await createGateway(cfgF);
      gateways.push(gwF);
      const dashF = await startDashboard(gwF, cfgF);
      handles.push(dashF);
      const fa = keys.issue("fa", { client: "falpha" });
      const fb = keys.issue("fb", { client: "fbeta" });
      const lA = await toolNames(portF, fa.token);
      const lB = await toolNames(portF, fb.token);
      assert("F: flat names: alpha's client lists the name alpha owns", lA.includes("get_info") && lA.includes("get_status"), lA.join(","));
      assert("F: flat names: beta's client does NOT list get_info (alpha claims it, so listing and calling agree)", !lB.includes("get_info") && same(lB, ["get_weather", "send_message"]), lB.join(","));
      const gi = await call(portF, fa.token, "get_info");
      const gb = await call(portF, fb.token, "get_info");
      assert("F: flat names: alpha's client calls get_info, beta's is denied naming it (never routed to beta's copy)", !gi.isError && gi.text === "alpha:get_info" && gb.isError && /client 'fbeta'/.test(gb.sb?.error ?? ""), gb.text.slice(0, 160));
      assert("F: require_auth never does not open the gateway once clients exist: no credential is 401", (await mcp(portF, null, "tools/list")).status === 401);
      {
        // the public tunnel listener (expose) applies the same rule to the same clients
        const portX = await freePort();
        const xl = await startMcpListener(gwF, "127.0.0.1", portX, new ApiKeyStore(), { clients: () => cfgF.clients });
        const legacyX = keys.issue("legacy-x");
        const xNone = await mcp(portX, null, "tools/list");
        const xLegacy = await mcp(portX, legacyX.token, "tools/list");
        const xBound = await mcp(portX, fa.token, "tools/list");
        await xl.close();
        assert("F: the expose listener: no key 401, an unbound key 403 SB_NO_CLIENT, a client key sees only its tools", xNone.status === 401 && xLegacy.status === 403 && jsonOf(xLegacy).code === "SB_NO_CLIENT" && xBound.status === 200 && (xBound.result?.tools ?? []).some((t) => t.name === "get_status") && !(xBound.result?.tools ?? []).some((t) => t.name === "get_weather"));
      }
      await retire(dashF, gwF);
    }

    // ---- the rule: no em dash character anywhere ----
    {
      const EM = String.fromCharCode(0x2014);
      const src = readFileSync(SELF, "utf8");
      assert("oracle source has no em dash", !src.includes(EM));
      // Older source files carry comment em dashes from before the rule; the files this step created must be clean.
      const created = ["principal.ts", "clientconfig.ts", "clientadmin.ts"].map((f) => readFileSync(join(root, "src", f), "utf8"));
      assert("the source files this step created have no em dash", created.every((t) => !t.includes(EM)));
    }
  } catch (err) {
    assert("oracle ran to the end without an unexpected error", false, String(err && err.stack ? err.stack : err).slice(0, 600));
  } finally {
    for (const h of handles) await h.close().catch(() => {});
    for (const g of gateways) await g.shutdown().catch(() => {});
    for (const c of children) killTree(c);
    await sleep(300);
    try {
      rmSync(base, { recursive: true, force: true });
    } catch {
      /* temp leftovers are harmless */
    }
  }

  const passed = checks.filter((c) => c.ok).length;
  console.log(`\n${passed}/${checks.length} checks passed`);
  process.exit(passed === checks.length ? 0 : 1);
}
