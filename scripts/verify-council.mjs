// Deterministic oracle for the council relay (src/council.ts) with a focus on the LOCAL provider —
// an OpenAI-compatible model server (Ollama / LM Studio / llama.cpp / vLLM) that lets the whole
// council run offline against a downloaded model. Exercises buildCouncilServer against compiled
// dist/ through a real in-memory MCP Client, with global `fetch` replaced by a capturing stub that
// emulates a local chat-completions endpoint. ZERO network, ZERO model tokens — the oracle computes
// every verdict itself.
//
// It proves:
//   provider enumeration  — `local` joins the council, appears in the `provider` tool enum, and is
//                           ordered after the cloud providers (anthropic, openai, local).
//   local routing         — a consult to `local` POSTs to `${base_url}/chat/completions` (the base
//                           already carries `/v1`, so it is NEVER doubled), OpenAI Chat-Completions
//                           wire shape (model = default_model, messages, max_tokens = token_budget),
//                           and the reply + usage tokens are parsed back.
//   zero-key by default   — no `api_key_ref` ⇒ NO Authorization header (most local servers need none);
//                           a configured `${env:..}` ref ⇒ a Bearer header resolved at call time.
//   system + model param  — a `system` arg becomes a system message; a per-call `model` overrides the
//                           configured default.
//   errors fail loud      — a non-2xx local response surfaces as an isError result; consulting a
//                           provider that is not configured is an isError result.
//   debate with local     — local is a valid debate participant; a 1-round openai+local debate makes
//                           exactly rounds*participants + 1 (synthesis) calls and names both speakers;
//                           a debate with only one configured provider fails (needs ≥2).
// Zero deps (node stdlib + the package's own compiled output + its bundled MCP SDK). Build first.
import { buildCouncilServer, COUNCIL_SERVER_ID } from "../dist/council.js";
import { Vault } from "../dist/vault.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";

const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const deepEqual = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// --- a capturing fetch stub: records every request, emulates chat-completions + anthropic shapes ---
let reqs = [];
let nextStatus = 200;
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init) => {
  const u = url instanceof URL ? url : new URL(String(url));
  const headers = (init && init.headers) || {};
  const body = init && init.body ? JSON.parse(init.body) : {};
  reqs.push({ url: u, href: u.href, headers, body });
  if (nextStatus !== 200) {
    return new Response("upstream is unhappy", { status: nextStatus, statusText: "ServerError" });
  }
  // Anthropic Messages shape vs OpenAI/local Chat-Completions shape, keyed by path.
  if (u.pathname.endsWith("/v1/messages")) {
    const payload = { content: [{ type: "text", text: `REPLY[${body.model}]` }], usage: { input_tokens: 5, output_tokens: 9 } };
    return new Response(JSON.stringify(payload), { status: 200, statusText: "OK" });
  }
  const payload = {
    choices: [{ message: { content: `REPLY[${body.model}]` } }],
    usage: { prompt_tokens: 7, completion_tokens: 11 },
  };
  return new Response(JSON.stringify(payload), { status: 200, statusText: "OK" });
};

const vault = new Vault("env"); // resolves ${env:NAME} from process.env, no filesystem
const clients = [];
async function mount(council) {
  const built = buildCouncilServer(council, vault);
  const [clientT, serverT] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "verify-council", version: "0.0.0" });
  await built.server.connect(serverT);
  await client.connect(clientT);
  clients.push(client);
  return { client, built };
}
const reset = () => {
  reqs = [];
  nextStatus = 200;
};

const LOCAL_BASE = "http://127.0.0.1:11434/v1"; // Ollama-style base — already carries /v1

// --- 1. provider enumeration: local joins, ordered after the cloud providers ----------------------
{
  const { client, built } = await mount({
    enabled: true,
    providers: { local: { base_url: LOCAL_BASE, default_model: "llama3.1" } },
    token_budget: 256,
  });
  assert("synthetic server id is 'council'", COUNCIL_SERVER_ID === "council", COUNCIL_SERVER_ID);
  assert("two tools are exposed", built.toolCount === 2, String(built.toolCount));
  assert("both tools are write-scoped (governed + audited)", built.scopeHints.council_consult === "write" && built.scopeHints.council_debate === "write");
  const { tools } = await client.listTools();
  const consult = tools.find((t) => t.name === "council_consult");
  assert("council_consult is listed", !!consult);
  assert("local-only config ⇒ provider enum is exactly ['local']", deepEqual(consult.inputSchema.properties.provider.enum, ["local"]), JSON.stringify(consult?.inputSchema?.properties?.provider?.enum));
}
{
  const { client } = await mount({
    enabled: true,
    providers: {
      anthropic: { api_key_ref: "${env:ANTHROPIC_KEY}", default_model: "claude" },
      openai: { api_key_ref: "${env:OPENAI_KEY}", default_model: "gpt" },
      local: { base_url: LOCAL_BASE, default_model: "llama3.1" },
    },
  });
  const { tools } = await client.listTools();
  const consult = tools.find((t) => t.name === "council_consult");
  assert("all-three config ⇒ provider enum order is [anthropic, openai, local]", deepEqual(consult.inputSchema.properties.provider.enum, ["anthropic", "openai", "local"]), JSON.stringify(consult.inputSchema.properties.provider.enum));
}

// --- 2. local routing: correct URL, wire shape, parsed reply + usage -------------------------------
{
  reset();
  const { client } = await mount({
    enabled: true,
    providers: { local: { base_url: LOCAL_BASE, default_model: "llama3.1" } },
    token_budget: 256,
  });
  const r = await client.callTool({ name: "council_consult", arguments: { provider: "local", prompt: "ping" } });
  assert("local consult is not an error", r.isError !== true, JSON.stringify(r.content));
  assert("exactly one fetch was made", reqs.length === 1, String(reqs.length));
  assert("URL is base + /chat/completions (the /v1 is NOT doubled)", reqs[0].href === `${LOCAL_BASE}/chat/completions`, reqs[0].href);
  assert("body.model defaults to the configured default_model", reqs[0].body.model === "llama3.1", reqs[0].body.model);
  assert("body.max_tokens is the token_budget", reqs[0].body.max_tokens === 256, String(reqs[0].body.max_tokens));
  assert("no system arg ⇒ a single user message", reqs[0].body.messages.length === 1 && reqs[0].body.messages[0].role === "user" && reqs[0].body.messages[0].content === "ping", JSON.stringify(reqs[0].body.messages));
  const text = r.content[0].text;
  assert("reply is tagged with the provider", text.startsWith("[local]\n"), text.slice(0, 24));
  assert("the parsed model reply is surfaced", text.includes("REPLY[llama3.1]"), text);
  assert("the usage footer reports the local token counts", text.includes("1 model call, 7 in / 11 out tokens"), text);
}

// --- 3. zero-key by default; bearer only when api_key_ref is configured ----------------------------
{
  reset();
  const { client } = await mount({
    enabled: true,
    providers: { local: { base_url: LOCAL_BASE, default_model: "llama3.1" } },
  });
  await client.callTool({ name: "council_consult", arguments: { provider: "local", prompt: "ping" } });
  assert("no api_key_ref ⇒ NO authorization header is sent", reqs[0].headers.authorization === undefined && reqs[0].headers.Authorization === undefined, JSON.stringify(reqs[0].headers));
  assert("content-type is application/json", reqs[0].headers["content-type"] === "application/json");
}
{
  reset();
  process.env.LOCAL_TOKEN = "tok-abc-123";
  const { client } = await mount({
    enabled: true,
    providers: { local: { base_url: LOCAL_BASE, default_model: "llama3.1", api_key_ref: "${env:LOCAL_TOKEN}" } },
  });
  await client.callTool({ name: "council_consult", arguments: { provider: "local", prompt: "ping" } });
  assert("configured api_key_ref ⇒ Bearer header resolved from the vault at call time", reqs[0].headers.authorization === "Bearer tok-abc-123", reqs[0].headers.authorization);
}

// --- 4. system message + per-call model override --------------------------------------------------
{
  reset();
  const { client } = await mount({
    enabled: true,
    providers: { local: { base_url: LOCAL_BASE, default_model: "llama3.1" } },
  });
  const r = await client.callTool({ name: "council_consult", arguments: { provider: "local", prompt: "ping", system: "be terse", model: "qwen2.5-coder" } });
  assert("system arg ⇒ messages are [system, user] in order", reqs[0].body.messages.length === 2 && reqs[0].body.messages[0].role === "system" && reqs[0].body.messages[0].content === "be terse" && reqs[0].body.messages[1].role === "user", JSON.stringify(reqs[0].body.messages));
  assert("per-call model overrides the default", reqs[0].body.model === "qwen2.5-coder", reqs[0].body.model);
  assert("override reply surfaces the overridden model", r.content[0].text.includes("REPLY[qwen2.5-coder]"), r.content[0].text);
}

// --- 5. errors fail loud: non-2xx local response + unconfigured provider ---------------------------
{
  reset();
  nextStatus = 500;
  const { client } = await mount({
    enabled: true,
    providers: { local: { base_url: LOCAL_BASE, default_model: "llama3.1" } },
  });
  const r = await client.callTool({ name: "council_consult", arguments: { provider: "local", prompt: "ping" } });
  assert("a non-2xx local response ⇒ isError result", r.isError === true, JSON.stringify(r));
  assert("the error names the local status", r.content[0].text.includes("local 500"), r.content[0].text);
}
{
  reset();
  const { client } = await mount({
    enabled: true,
    providers: { openai: { api_key_ref: "${env:OPENAI_KEY}", default_model: "gpt" } },
  });
  const r = await client.callTool({ name: "council_consult", arguments: { provider: "local", prompt: "ping" } });
  assert("consulting an unconfigured 'local' ⇒ isError", r.isError === true);
  assert("the error says local is not configured", r.content[0].text.includes("'local' is not configured"), r.content[0].text);
  assert("fail-closed: no fetch is made for an unconfigured provider", reqs.length === 0, String(reqs.length));
}

// --- 6. debate with local as a participant --------------------------------------------------------
{
  reset();
  process.env.OPENAI_KEY = "sk-test";
  const { client } = await mount({
    enabled: true,
    providers: {
      openai: { api_key_ref: "${env:OPENAI_KEY}", default_model: "gpt" },
      local: { base_url: LOCAL_BASE, default_model: "llama3.1" },
    },
    max_rounds: 3,
  });
  const r = await client.callTool({ name: "council_debate", arguments: { topic: "tabs vs spaces", rounds: 1 } });
  assert("debate with openai+local is not an error", r.isError !== true, JSON.stringify(r.content));
  // rounds(1) * participants(2) + 1 synthesis = 3 model calls.
  assert("1-round 2-party debate makes exactly 3 model calls", reqs.length === 3, String(reqs.length));
  // The local participant POSTed to its own base; at least one request hit the local endpoint.
  assert("the local participant was actually polled at its base_url", reqs.some((q) => q.href === `${LOCAL_BASE}/chat/completions`), reqs.map((q) => q.href).join(", "));
  const text = r.content[0].text;
  assert("both speakers appear in the transcript", text.includes("### openai — round 1") && text.includes("### local — round 1"), text.slice(0, 200));
  assert("the moderator (first participant) is named", text.includes("Synthesis (moderator: openai)"), text.slice(0, 200));
}
{
  reset();
  const { client } = await mount({
    enabled: true,
    providers: { local: { base_url: LOCAL_BASE, default_model: "llama3.1" } },
  });
  const r = await client.callTool({ name: "council_debate", arguments: { topic: "solo" } });
  assert("a debate with only one configured provider ⇒ isError (needs ≥2)", r.isError === true);
  assert("the error explains the two-provider minimum", r.content[0].text.includes("at least two configured providers"), r.content[0].text);
  assert("fail-closed: no fetch is made for an under-provisioned debate", reqs.length === 0, String(reqs.length));
}

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
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
process.exitCode = failed.length === 0 ? 0 : 1;
