// Deterministic oracle for the app2mcp source (src/openapi.ts — an OpenAPI 3.x / Swagger 2.0 spec →
// a generated in-process MCP server). Exercises buildOpenApiServer against the compiled dist/ through
// a real in-memory MCP Client, with specs written to temp files (so loadSpec uses readFileSync, never
// the network) and the global `fetch` replaced by a capturing stub (so invokeOperation is verified
// with ZERO network and ZERO model tokens). The oracle computes every verdict itself.
//
// It proves:
//   tool generation     — one operation (path × method) → one tool; operationId / x-mcp-tool-name /
//                         derived `${method}_${path}` naming; sanitization to [a-z0-9_-]; collisions
//                         get a `_2` suffix; an empty/non-3.x/non-2.0/zero-op spec FAILS CLOSED (throws).
//   scope inference     — GET/HEAD/OPTIONS → read, POST/PUT/PATCH → write, DELETE → full, surfaced
//                         per-tool in scopeHints for the policy engine to classify by verb.
//   schema flattening   — path/query/header params → inputSchema.properties + a `required` list;
//                         $ref (3.x #/components, 2.0 #/definitions) is dereferenced; an object body
//                         is MERGED to the top level, a non-object body or a name collision is NESTED
//                         under a `body` key.
//   base-url derivation — explicit base_url wins; else servers[0].url with {var} defaults; else the
//                         Swagger scheme+host+basePath; a relative / missing host FAILS CLOSED (throws).
//   invocation contract — `{name}` path segments fill from same-named args and are URL-encoded; query
//                         verbs put scalars/arrays in the query string; body verbs send a JSON (or
//                         form-urlencoded) body with the content-type set; auth headers from
//                         resolveHeaders are merged in; a >=400 status marks isError; an oversized
//                         response is truncated; a credential failure returns isError and NEVER fetches.
// Zero deps (node stdlib + the package's own compiled output + its bundled MCP SDK). Build first.
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildOpenApiServer } from "../dist/openapi.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const deepEqual = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// --- specs live on disk so loadSpec() reads them with readFileSync (never the network) -------------
const TMP = mkdtempSync(join(tmpdir(), "sb-openapi-"));
let specSeq = 0;
const specFile = (obj) => {
  const p = join(TMP, `spec-${specSeq++}.json`);
  writeFileSync(p, JSON.stringify(obj));
  return p;
};

// --- a capturing fetch stub: records the last request, returns a scripted Response -----------------
let lastReq = null;
let nextResponse = () => new Response("{}", { status: 200, statusText: "OK" });
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init) => {
  lastReq = { url: url instanceof URL ? url : new URL(String(url)), init: init ?? {} };
  return nextResponse();
};

const clients = [];
/** Build a server from a spec object + config overrides and return a connected MCP client + metadata. */
async function open(spec, overrides = {}, resolveHeaders = async () => ({})) {
  const config = { id: "t", source: "app2mcp", openapi: specFile(spec), ...overrides };
  const generated = await buildOpenApiServer(config, resolveHeaders);
  const [clientT, serverT] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "verify-openapi", version: "0.0.0" });
  await generated.server.connect(serverT);
  await client.connect(clientT);
  clients.push(client);
  return { client, generated };
}
/** True iff buildOpenApiServer rejects for this spec/config (fail-closed assertions). */
async function rejects(spec, overrides = {}) {
  try {
    await buildOpenApiServer({ id: "t", source: "app2mcp", openapi: spec === null ? undefined : specFile(spec), ...overrides }, async () => ({}));
    return false;
  } catch {
    return true;
  }
}

// =================================================================================================
// 1. OpenAPI 3.x — tool generation, scope hints, schema flattening, $ref + body merge
// =================================================================================================
const oas3 = {
  openapi: "3.0.0",
  info: { title: "Pet", version: "1.0" },
  servers: [{ url: "https://api.pet.test/v1" }],
  components: {
    schemas: { Order: { type: "object", properties: { sku: { type: "string" }, qty: { type: "integer" } }, required: ["sku"] } },
  },
  paths: {
    "/pet/{petId}": {
      get: {
        operationId: "getpetbyid",
        parameters: [
          { name: "petId", in: "path", required: true, schema: { type: "string" } },
          { name: "verbose", in: "query", required: false, schema: { type: "boolean" } },
          { name: "tags", in: "query", schema: { type: "array", items: { type: "string" } } },
        ],
      },
      delete: { operationId: "deletepet", parameters: [{ name: "petId", in: "path", required: true, schema: { type: "string" } }] },
      head: { operationId: "headpet", parameters: [{ name: "petId", in: "path", required: true, schema: { type: "string" } }] },
    },
    "/pet": {
      put: { operationId: "replacepet", requestBody: { content: { "application/json": { schema: { type: "object", properties: { name: { type: "string" } } } } } } },
      post: {
        operationId: "addpet",
        requestBody: { required: true, content: { "application/json": { schema: { type: "object", properties: { name: { type: "string" }, tag: { type: "string" } }, required: ["name"] } } } },
      },
      options: { operationId: "optpet" },
    },
    "/store/order": {
      post: { operationId: "placeorder", requestBody: { required: true, content: { "application/json": { schema: { $ref: "#/components/schemas/Order" } } } } },
    },
  },
};
{
  const { client, generated } = await open(oas3, {}, async () => ({ Authorization: "Bearer T" }));
  const h = generated.scopeHints;
  assert("toolCount counts every path×method operation", generated.toolCount === 7, String(generated.toolCount));
  assert("scope GET → read", h.getpetbyid === "read", h.getpetbyid);
  assert("scope DELETE → full", h.deletepet === "full", h.deletepet);
  assert("scope HEAD → read", h.headpet === "read", h.headpet);
  assert("scope OPTIONS → read", h.optpet === "read", h.optpet);
  assert("scope PUT → write", h.replacepet === "write", h.replacepet);
  assert("scope POST → write", h.addpet === "write", h.addpet);

  const { tools } = await client.listTools();
  const byName = Object.fromEntries(tools.map((t) => [t.name, t]));
  assert("operationId becomes the tool name", Boolean(byName.getpetbyid && byName.addpet && byName.placeorder));
  // getpetbyid: path + query params flattened; only petId required.
  const get = byName.getpetbyid.inputSchema;
  assert("path + query params surface as properties", "petId" in get.properties && "verbose" in get.properties && "tags" in get.properties);
  assert("required carries the required path param only", deepEqual(get.required, ["petId"]), JSON.stringify(get.required));
  assert("array query param keeps its array schema", get.properties.tags.type === "array" && get.properties.tags.items.type === "string");
  // addpet: object body MERGED to the top level.
  const add = byName.addpet.inputSchema;
  assert("object request body is merged to top-level properties", "name" in add.properties && "tag" in add.properties);
  assert("merged body's required field is hoisted to required", add.required.includes("name"), JSON.stringify(add.required));
  // placeorder: $ref body dereferenced then merged.
  const order = byName.placeorder.inputSchema;
  assert("$ref body is dereferenced before flattening", "sku" in order.properties && "qty" in order.properties, JSON.stringify(Object.keys(order.properties)));
  assert("dereferenced body required is preserved", order.required.includes("sku"));
  assert("description falls back to METHOD path when absent", byName.optpet.description.includes("/pet"), byName.optpet.description);
}

// =================================================================================================
// 2. Body modes — non-object body NESTED; param/body name collision NESTED under `body`
// =================================================================================================
const bodyModes = {
  openapi: "3.0.0",
  info: { title: "B", version: "1" },
  servers: [{ url: "https://b.test" }],
  paths: {
    "/raw": { post: { operationId: "putraw", requestBody: { content: { "application/json": { schema: { type: "array", items: { type: "string" } } } } } } },
    "/items/{id}": {
      post: {
        operationId: "updateitem",
        parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
        requestBody: { content: { "application/json": { schema: { type: "object", properties: { id: { type: "string" }, value: { type: "string" } } } } } },
      },
    },
  },
};
{
  const { client } = await open(bodyModes);
  const { tools } = await client.listTools();
  const byName = Object.fromEntries(tools.map((t) => [t.name, t]));
  const raw = byName.putraw.inputSchema;
  assert("non-object body is nested under a `body` key", "body" in raw.properties && raw.properties.body.type === "array", JSON.stringify(Object.keys(raw.properties)));
  const upd = byName.updateitem.inputSchema;
  assert("path param + body field name collision keeps the path param", upd.properties.id.type === "string");
  assert("collision nests the body object under `body` (no clobber)", "body" in upd.properties && upd.properties.body.type === "object", JSON.stringify(Object.keys(upd.properties)));
}

// =================================================================================================
// 3. Invocation — path fill + encode, query scalars/arrays, JSON body, auth headers, response shape
// =================================================================================================
{
  const { client } = await open(oas3, {}, async () => ({ Authorization: "Bearer T" }));

  // GET: path {petId} filled & consumed; query scalar + array; auth header; no body.
  nextResponse = () => new Response("hello", { status: 200, statusText: "OK" });
  await client.callTool({ name: "getpetbyid", arguments: { petId: "7", verbose: true, tags: ["a", "b"] } });
  assert("base_url from servers[0].url + path → correct pathname", lastReq.url.pathname === "/v1/pet/7", lastReq.url.pathname);
  assert("path param consumed → not echoed as a query param", lastReq.url.searchParams.get("petId") === null);
  assert("scalar query param serialized", lastReq.url.searchParams.get("verbose") === "true", lastReq.url.searchParams.get("verbose"));
  assert("array query param → repeated pairs", deepEqual(lastReq.url.searchParams.getAll("tags"), ["a", "b"]), lastReq.url.searchParams.getAll("tags").join());
  assert("GET method is set", lastReq.init.method === "GET", lastReq.init.method);
  assert("GET sends no body", lastReq.init.body === undefined);
  assert("auth header from resolveHeaders is merged in", lastReq.init.headers.Authorization === "Bearer T");
  const okResult = await client.callTool({ name: "getpetbyid", arguments: { petId: "1" } });
  assert("2xx body is surfaced verbatim with status line", okResult.content[0].text.includes("HTTP 200") && okResult.content[0].text.includes("hello"), okResult.content[0].text.slice(0, 40));
  assert("2xx is not isError", okResult.isError !== true);

  // array path param → comma-joined then URL-encoded.
  await client.callTool({ name: "getpetbyid", arguments: { petId: ["7", "8"] } });
  assert("array path param is comma-joined and percent-encoded", lastReq.url.pathname === "/v1/pet/7%2C8", lastReq.url.pathname);

  // POST merged body → JSON body, content-type set, DELETE → method + path only.
  await client.callTool({ name: "addpet", arguments: { name: "Rex", tag: "dog" } });
  assert("merged object body is sent as JSON", deepEqual(JSON.parse(lastReq.init.body), { name: "Rex", tag: "dog" }), String(lastReq.init.body));
  assert("JSON body sets content-type application/json", lastReq.init.headers["content-type"] === "application/json");
  assert("POST method is set", lastReq.init.method === "POST");

  await client.callTool({ name: "deletepet", arguments: { petId: "9" } });
  assert("DELETE fills its path and sends no body", lastReq.url.pathname === "/v1/pet/9" && lastReq.init.method === "DELETE" && lastReq.init.body === undefined, lastReq.url.pathname);

  // nested body invocation: the whole `body` arg is sent as the request body.
  const { client: bc } = await open(bodyModes);
  await bc.callTool({ name: "putraw", arguments: { body: ["x", "y"] } });
  assert("nested `body` arg is sent as the whole request body", deepEqual(JSON.parse(lastReq.init.body), ["x", "y"]), String(lastReq.init.body));
  await bc.callTool({ name: "updateitem", arguments: { id: "5", body: { id: "inner", value: "v" } } });
  assert("collision: path id fills the path, body object is the JSON body", lastReq.url.pathname === "/items/5" && deepEqual(JSON.parse(lastReq.init.body), { id: "inner", value: "v" }), lastReq.url.pathname);
}

// =================================================================================================
// 4. form-urlencoded body (OpenAPI 3.x content type) → URLSearchParams body + form content-type
// =================================================================================================
{
  const formSpec = {
    openapi: "3.0.0",
    info: { title: "F", version: "1" },
    servers: [{ url: "https://f.test" }],
    paths: {
      "/login": {
        post: { operationId: "login", requestBody: { content: { "application/x-www-form-urlencoded": { schema: { type: "object", properties: { user: { type: "string" }, code: { type: "string" } } } } } } },
      },
    },
  };
  const { client } = await open(formSpec);
  await client.callTool({ name: "login", arguments: { user: "ada", code: "42" } });
  assert("form body is URL-encoded, not JSON", typeof lastReq.init.body === "string" && lastReq.init.body.includes("user=ada") && lastReq.init.body.includes("code=42"), String(lastReq.init.body));
  assert("form body sets content-type x-www-form-urlencoded", lastReq.init.headers["content-type"] === "application/x-www-form-urlencoded", lastReq.init.headers["content-type"]);
}

// =================================================================================================
// 5. Swagger 2.0 — scheme+host+basePath base URL, inline param typing, in:body $ref, in:formData
// =================================================================================================
const swagger2 = {
  swagger: "2.0",
  info: { title: "S", version: "1.0" },
  host: "api.s.test",
  basePath: "/v2",
  schemes: ["https"],
  definitions: { Widget: { type: "object", properties: { color: { type: "string" } }, required: ["color"] } },
  paths: {
    "/widget/{wid}": {
      get: { operationId: "getwidget", parameters: [{ name: "wid", in: "path", required: true, type: "string" }, { name: "limit", in: "query", type: "integer" }] },
      delete: { operationId: "delwidget", parameters: [{ name: "wid", in: "path", required: true, type: "string" }] },
    },
    "/widget": {
      post: { operationId: "makewidget", parameters: [{ name: "body", in: "body", required: true, schema: { $ref: "#/definitions/Widget" } }] },
    },
    "/upload": {
      post: { operationId: "uploadform", consumes: ["application/x-www-form-urlencoded"], parameters: [{ name: "field1", in: "formData", required: true, type: "string" }, { name: "field2", in: "formData", type: "string" }] },
    },
  },
};
{
  const { client, generated } = await open(swagger2);
  const h = generated.scopeHints;
  assert("swagger 2.0 GET → read", h.getwidget === "read", h.getwidget);
  assert("swagger 2.0 DELETE → full", h.delwidget === "full", h.delwidget);
  assert("swagger 2.0 POST → write", h.makewidget === "write" && h.uploadform === "write");

  const { tools } = await client.listTools();
  const byName = Object.fromEntries(tools.map((t) => [t.name, t]));
  const gw = byName.getwidget.inputSchema;
  assert("swagger inline param typing → property type", gw.properties.wid.type === "string" && gw.properties.limit.type === "integer", JSON.stringify(gw.properties));
  assert("swagger required path param surfaces in required", deepEqual(gw.required, ["wid"]), JSON.stringify(gw.required));
  const mw = byName.makewidget.inputSchema;
  assert("swagger in:body $ref dereferenced + merged", "color" in mw.properties && mw.required.includes("color"), JSON.stringify(mw.properties));
  const uf = byName.uploadform.inputSchema;
  assert("swagger in:formData params surface", "field1" in uf.properties && "field2" in uf.properties && uf.required.includes("field1"), JSON.stringify(uf.required));

  // base URL = scheme + host + basePath; formData → form body.
  await client.callTool({ name: "getwidget", arguments: { wid: "9", limit: 5 } });
  assert("swagger base URL is scheme+host+basePath", lastReq.url.href.startsWith("https://api.s.test/v2/widget/9"), lastReq.url.href);
  assert("swagger query param serialized", lastReq.url.searchParams.get("limit") === "5");
  await client.callTool({ name: "uploadform", arguments: { field1: "a", field2: "b" } });
  assert("swagger formData → form-urlencoded body", typeof lastReq.init.body === "string" && lastReq.init.body.includes("field1=a"), String(lastReq.init.body));
}

// =================================================================================================
// 6. base-url derivation — explicit override, {var} substitution, fail-closed on relative/no-host
// =================================================================================================
{
  // explicit base_url wins over servers[0].url.
  const { client } = await open(oas3, { base_url: "https://override.test/api" });
  await client.callTool({ name: "getpetbyid", arguments: { petId: "3" } });
  assert("explicit config.base_url overrides servers[0].url", lastReq.url.href.startsWith("https://override.test/api/pet/3"), lastReq.url.href);

  // servers[0].url {var} defaults substituted.
  const varSpec = {
    openapi: "3.0.0",
    info: { title: "V", version: "1" },
    servers: [{ url: "https://{stage}.api.test/{ver}", variables: { stage: { default: "prod" }, ver: { default: "v3" } } }],
    paths: { "/ping": { get: { operationId: "ping" } } },
  };
  const { client: vc } = await open(varSpec);
  await vc.callTool({ name: "ping", arguments: {} });
  assert("servers[0].url {var} defaults are substituted", lastReq.url.href === "https://prod.api.test/v3/ping", lastReq.url.href);

  // relative servers[0].url → fail closed.
  assert(
    "relative servers[0].url fails closed (throws)",
    await rejects({ openapi: "3.0.0", info: { title: "R", version: "1" }, servers: [{ url: "/relative" }], paths: { "/a": { get: { operationId: "a" } } } }),
  );
  // Swagger 2.0 with no host and no base_url → fail closed.
  assert(
    "swagger 2.0 with no host fails closed (throws)",
    await rejects({ swagger: "2.0", info: { title: "R", version: "1" }, paths: { "/a": { get: { operationId: "a" } } } }),
  );
}

// =================================================================================================
// 7. naming — sanitization, collision suffix, derived name, x-mcp-tool-name override
// =================================================================================================
{
  const nameSpec = {
    openapi: "3.0.0",
    info: { title: "N", version: "1" },
    servers: [{ url: "https://n.test" }],
    paths: {
      "/a": { get: { operationId: "Get Thing!! V2" } },
      "/b": { get: { operationId: "Get/Thing/V2" } },
      "/c": { get: {} },
      "/d": { get: { operationId: "ignored", "x-mcp-tool-name": "custom_name" } },
    },
  };
  const { client } = await open(nameSpec);
  const { tools } = await client.listTools();
  const names = tools.map((t) => t.name);
  assert("operationId sanitized to [a-z0-9_-]", names.includes("get_thing_v2"), names.join());
  assert("name collision gets a _2 suffix", names.includes("get_thing_v2_2"), names.join());
  assert("missing operationId → derived method_path name", names.includes("get_c"), names.join());
  assert("x-mcp-tool-name overrides operationId", names.includes("custom_name") && !names.includes("ignored"), names.join());
  assert("every generated name matches the MCP tool-name charset", names.every((n) => /^[a-z0-9_-]{1,64}$/.test(n)), names.join());
}

// =================================================================================================
// 8. response shaping + fail-closed credential handling + unknown tool
// =================================================================================================
{
  const { client } = await open(oas3, {}, async () => ({ Authorization: "Bearer T" }));

  // >=400 status → isError, status line carried.
  nextResponse = () => new Response("not found", { status: 404, statusText: "Not Found" });
  const r404 = await client.callTool({ name: "getpetbyid", arguments: { petId: "1" } });
  assert("upstream >=400 → isError result", r404.isError === true);
  assert("error result carries the HTTP status", r404.content[0].text.includes("HTTP 404"));

  // oversized response truncated with a marker.
  nextResponse = () => new Response("z".repeat(60_000), { status: 200, statusText: "OK" });
  const big = await client.callTool({ name: "getpetbyid", arguments: { petId: "1" } });
  assert("oversized response is truncated with a marker", big.content[0].text.includes("[truncated") && big.content[0].text.length < 55_000, String(big.content[0].text.length));

  // unknown tool → isError, fetch not relevant.
  nextResponse = () => new Response("{}", { status: 200, statusText: "OK" });
  const unk = await client.callTool({ name: "no_such_tool", arguments: {} });
  assert("unknown tool name → isError result", unk.isError === true && unk.content[0].text.includes("unknown tool"), unk.content[0].text);

  // credential failure → isError, fetch NEVER called.
  const before = lastReq;
  const { client: fc } = await open(oas3, {}, async () => {
    throw new Error("vault locked");
  });
  const cred = await fc.callTool({ name: "getpetbyid", arguments: { petId: "1" } });
  assert("credential failure → isError result", cred.isError === true);
  assert("credential failure message surfaces", cred.content[0].text.includes("credential error") && cred.content[0].text.includes("vault locked"), cred.content[0].text);
  assert("fail-closed: fetch is NOT called when credentials fail", lastReq === before);
}

// =================================================================================================
// 9. build-time validation fails closed
// =================================================================================================
{
  assert("missing openapi config → throws", await rejects(null));
  assert("spec that is neither 3.x nor 2.0 → throws", await rejects({ info: { title: "X", version: "1" }, paths: { "/a": { get: { operationId: "a" } } } }));
  assert("spec with zero callable operations → throws", await rejects({ openapi: "3.0.0", info: { title: "X", version: "1" }, servers: [{ url: "https://x.test" }], paths: {} }));
}

// --- teardown -------------------------------------------------------------------------------------
globalThis.fetch = realFetch;
for (const c of clients) {
  try {
    await c.close();
  } catch {
    /* already closed */
  }
}
await sleep(200); // let libuv settle before exit (Windows UV_HANDLE_CLOSING guard)

const failed = checks.filter((c) => !c.ok);
if (failed.length) console.log("\nFAILED:", failed.map((c) => c.name).join(", "));
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
process.exitCode = failed.length === 0 ? 0 : 1;
