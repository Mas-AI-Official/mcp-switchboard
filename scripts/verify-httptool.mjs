// Deterministic oracle for the http-tool source (src/httptool.ts — hand-declared HTTP endpoints →
// a generated MCP server). Exercises buildHttpToolServer against the compiled dist/ through a real
// in-memory MCP Client, with the global `fetch` replaced by a capturing stub — so the full
// invocation contract is verified with ZERO network and ZERO model tokens. The oracle computes
// every verdict itself.
//
// It proves:
//   build-time validation — empty http_tools / missing method / duplicate name / relative-path-no-base
//                           all FAIL CLOSED (throw) rather than mounting a half-broken server.
//   scopeHints            — GET/HEAD→read, DELETE→full, else write; a per-tool `scope` only TIGHTENS
//                           (raises toward full), never relaxes a DELETE to read.
//   ListTools             — names/descriptions surface; inputSchema defaults to an open object when
//                           omitted and a custom inputSchema is preserved verbatim.
//   CallTool invocation   — `{name}` path segments fill from same-named args and are CONSUMED (not
//                           re-sent); query verbs put the rest in the query string, body verbs in a
//                           JSON body (content-type set); auth headers from resolveHeaders are sent;
//                           an absolute per-tool url is used as-is; a 4xx marks isError; a credential
//                           failure returns an isError result and NEVER calls fetch (fail closed).
// Zero deps (node stdlib + the package's own compiled output + its bundled MCP SDK). Build first.
import { buildHttpToolServer } from "../dist/httptool.js";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { useFetchStubForTests } from "../dist/netguard.js";

const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const deepEqual = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// --- a capturing fetch stub: records the last request, returns a scripted Response ----------------
let lastReq = null;
let nextResponse = () => new Response("ok", { status: 200, statusText: "OK" });
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init) => {
  lastReq = { url: url instanceof URL ? url : new URL(String(url)), init: init ?? {} };
  return nextResponse();
};
// Outbound HTTP now goes through the SSRF guard (src/netguard.ts) instead of calling fetch directly:
// route it to the capturing stub below and answer DNS with a public address, so no check here touches the network.
const restoreNet = useFetchStubForTests(() => globalThis.fetch);

/** Mount a config's http_tools and return a connected MCP client + the generated server's metadata. */
async function mount(config, resolveHeaders = async () => ({})) {
  const generated = await buildHttpToolServer(config, resolveHeaders);
  const [clientT, serverT] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "verify-httptool", version: "0.0.0" });
  await generated.server.connect(serverT);
  await client.connect(clientT);
  return { client, generated };
}

const clients = [];
async function open(config, resolveHeaders) {
  const m = await mount(config, resolveHeaders);
  clients.push(m.client);
  return m;
}

// --- 1. build-time validation FAILS CLOSED -------------------------------------------------------
{
  const threw = async (cfg) => {
    try {
      await buildHttpToolServer(cfg, async () => ({}));
      return false;
    } catch {
      return true;
    }
  };
  assert("empty http_tools throws", await threw({ id: "x", source: "http-tool", base_url: "https://api.test", http_tools: [] }));
  assert("missing method throws", await threw({ id: "x", source: "http-tool", base_url: "https://api.test", http_tools: [{ name: "a", path: "/a" }] }));
  assert(
    "duplicate tool name throws",
    await threw({
      id: "x",
      source: "http-tool",
      base_url: "https://api.test",
      http_tools: [
        { name: "a", method: "GET", path: "/a" },
        { name: "a", method: "GET", path: "/b" },
      ],
    }),
  );
  assert("relative path with no base_url throws", await threw({ id: "x", source: "http-tool", http_tools: [{ name: "a", method: "GET", path: "/a" }] }));
  assert(
    "absolute url needs no base_url (does NOT throw)",
    !(await threw({ id: "x", source: "http-tool", http_tools: [{ name: "a", method: "GET", url: "https://api.test/a" }] })),
  );
}

// --- 2. scopeHints: verb→scope, per-tool scope only TIGHTENS --------------------------------------
{
  const { generated } = await open({
    id: "scopes",
    source: "http-tool",
    base_url: "https://api.test",
    http_tools: [
      { name: "get_thing", method: "GET", path: "/t/{id}" },
      { name: "make_thing", method: "POST", path: "/t" },
      { name: "drop_thing", method: "DELETE", path: "/t/{id}" },
      { name: "danger_get", method: "GET", path: "/admin", scope: "full" }, // tighten read→full
      { name: "soft_delete", method: "DELETE", path: "/t/{id}", scope: "read" }, // must NOT relax full→read
    ],
  });
  const h = generated.scopeHints;
  assert("GET → read", h.get_thing === "read", h.get_thing);
  assert("POST → write", h.make_thing === "write", h.make_thing);
  assert("DELETE → full", h.drop_thing === "full", h.drop_thing);
  assert("per-tool scope tightens GET read→full", h.danger_get === "full", h.danger_get);
  assert("per-tool scope NEVER relaxes DELETE full→read", h.soft_delete === "full", h.soft_delete);
  assert("toolCount matches declared tools", generated.toolCount === 5, String(generated.toolCount));
}

// --- 3. ListTools: inputSchema default + custom preserved -----------------------------------------
{
  const customSchema = { type: "object", properties: { q: { type: "string" } }, required: ["q"] };
  const { client } = await open({
    id: "schemas",
    source: "http-tool",
    base_url: "https://api.test",
    http_tools: [
      { name: "no_schema", method: "GET", path: "/a" },
      { name: "with_schema", method: "POST", path: "/b", inputSchema: customSchema, description: "Custom." },
    ],
  });
  const { tools } = await client.listTools();
  const byName = Object.fromEntries(tools.map((t) => [t.name, t]));
  assert("omitted inputSchema defaults to an open object", deepEqual(byName.no_schema.inputSchema, { type: "object" }), JSON.stringify(byName.no_schema.inputSchema));
  assert("custom inputSchema is preserved verbatim", deepEqual(byName.with_schema.inputSchema, customSchema));
  assert("explicit description surfaces", byName.with_schema.description === "Custom.");
  assert("missing description is synthesized from method+path", byName.no_schema.description === "GET /a", byName.no_schema.description);
}

// --- 4. CallTool: path-fill consumes args; query verbs → query, body verbs → JSON body ------------
{
  const { client } = await open(
    {
      id: "invoke",
      source: "http-tool",
      base_url: "https://api.test/v1/",
      http_tools: [
        { name: "get_user", method: "GET", path: "/users/{id}" },
        { name: "create_user", method: "POST", path: "/users" },
        { name: "ext", method: "GET", url: "https://other.test/ping" },
      ],
    },
    async () => ({ Authorization: "Bearer T" }),
  );

  // GET with a path param + an extra arg → path filled & consumed, extra becomes a query param.
  nextResponse = () => new Response("{}", { status: 200, statusText: "OK" });
  await client.callTool({ name: "get_user", arguments: { id: "42", verbose: "yes" } });
  assert("base_url trailing slash + leading-slash path do not double up", lastReq.url.pathname === "/v1/users/42", lastReq.url.pathname);
  assert("path {id} consumed → not echoed in query", lastReq.url.searchParams.get("id") === null);
  assert("GET extra arg → query string", lastReq.url.searchParams.get("verbose") === "yes");
  assert("GET sends no body", lastReq.init.body === undefined);
  assert("auth header from resolveHeaders is sent", lastReq.init.headers.Authorization === "Bearer T");

  // POST → remaining args become a JSON body, content-type set, path param still consumed.
  await client.callTool({ name: "create_user", arguments: { name: "Ada", role: "admin" } });
  assert("POST sends a JSON body", deepEqual(JSON.parse(lastReq.init.body), { name: "Ada", role: "admin" }), lastReq.init.body);
  assert("POST sets content-type application/json", lastReq.init.headers["content-type"] === "application/json");

  // absolute per-tool url is used as-is (base_url ignored).
  await client.callTool({ name: "ext", arguments: {} });
  assert("absolute url is used verbatim", lastReq.url.href === "https://other.test/ping", lastReq.url.href);
}

// --- 5. error surfacing + fail-closed credential handling -----------------------------------------
{
  // A 404 from upstream marks the MCP result isError.
  const { client: c1 } = await open({ id: "err", source: "http-tool", base_url: "https://api.test", http_tools: [{ name: "g", method: "GET", path: "/x" }] });
  nextResponse = () => new Response("nope", { status: 404, statusText: "Not Found" });
  const r1 = await c1.callTool({ name: "g", arguments: {} });
  assert("upstream 4xx → isError result", r1.isError === true);
  assert("error result carries the HTTP status text", r1.content[0].text.includes("HTTP 404"));

  // resolveHeaders throwing (e.g. missing credential) → isError, and fetch is NEVER called.
  const before = lastReq;
  const { client: c2 } = await open(
    { id: "failclosed", source: "http-tool", base_url: "https://api.test", http_tools: [{ name: "g", method: "GET", path: "/x" }] },
    async () => {
      throw new Error("vault locked");
    },
  );
  const r2 = await c2.callTool({ name: "g", arguments: {} });
  assert("credential failure → isError result", r2.isError === true);
  assert("credential failure message surfaces", r2.content[0].text.includes("credential error") && r2.content[0].text.includes("vault locked"), r2.content[0].text);
  assert("fail-closed: fetch is NOT called when credentials fail", lastReq === before);
}

// --- 6. response cap ------------------------------------------------------------------------------
{
  const { client } = await open({ id: "cap", source: "http-tool", base_url: "https://api.test", http_tools: [{ name: "big", method: "GET", path: "/big" }] });
  const huge = "z".repeat(60_000);
  nextResponse = () => new Response(huge, { status: 200, statusText: "OK" });
  const r = await client.callTool({ name: "big", arguments: {} });
  assert("oversized response is truncated with a marker", r.content[0].text.includes("[truncated") && r.content[0].text.length < 55_000, String(r.content[0].text.length));
}

globalThis.fetch = realFetch;
restoreNet();
for (const c of clients) {
  try {
    await c.close();
  } catch {
    /* already closed */
  }
}
await sleep(200); // let libuv settle before exit (Windows UV_HANDLE_CLOSING guard)

const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
process.exitCode = failed.length === 0 ? 0 : 1;
