// End-user smoke for Codex -> MCP Switchboard over Streamable HTTP.
//
// This proves the "one endpoint, many tools" path without touching real credentials:
//   1. Codex global config contains [mcp_servers.switchboard] -> http://127.0.0.1:8088/mcp.
//   2. Switchboard starts on that exact loopback endpoint.
//   3. A real MCP client connects over Streamable HTTP, lists tools, and calls tools from two
//      mounted servers: one app2mcp OpenAPI server and one hand-declared http-tool server.
//   4. Both calls are audited as allowed.
//
// Build first: npm run build && npm run smoke:codex

import { createServer } from "node:http";
import { mkdtempSync, writeFileSync, readFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";

const PORT = 8088;
process.env.SWITCHBOARD_HOME = mkdtempSync(join(tmpdir(), "sb-codex-smoke-"));

const { createGateway } = await import("../dist/gateway.js");
const { startDashboard } = await import("../dist/dashboard.js");
const { recentAudit } = await import("../dist/audit.js");
const { Client, StreamableHTTPClientTransport } = await import("@modelcontextprotocol/client");

const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? ` - ${detail}` : ""}`);
};

const closeServer = (server) =>
  new Promise((resolve) => {
    if (!server.listening) {
      resolve();
      return;
    }
    server.close(() => resolve());
  });

const upstream = createServer((req, res) => {
  const url = new URL(req.url ?? "/", "http://127.0.0.1");
  res.setHeader("content-type", "application/json");
  if (req.method === "GET" && url.pathname.startsWith("/pet/")) {
    const petId = decodeURIComponent(url.pathname.slice("/pet/".length));
    res.end(JSON.stringify({ source: "openapi", petId, name: "Fido" }));
    return;
  }
  if (req.method === "GET" && url.pathname.startsWith("/http/ping/")) {
    const name = decodeURIComponent(url.pathname.slice("/http/ping/".length));
    res.end(JSON.stringify({ source: "http-tool", hello: name }));
    return;
  }
  res.statusCode = 404;
  res.end(JSON.stringify({ error: "not found", path: url.pathname }));
});

await new Promise((resolve) => upstream.listen(0, "127.0.0.1", resolve));
const upstreamPort = upstream.address().port;
const upstreamBase = `http://127.0.0.1:${upstreamPort}`;

const openapiPath = join(process.env.SWITCHBOARD_HOME, "openapi.json");
writeFileSync(
  openapiPath,
  JSON.stringify(
    {
      openapi: "3.0.0",
      info: { title: "Switchboard Smoke API", version: "1.0.0" },
      servers: [{ url: upstreamBase }],
      paths: {
        "/pet/{petId}": {
          get: {
            operationId: "getPetById",
            parameters: [
              { name: "petId", in: "path", required: true, schema: { type: "string" } },
            ],
            responses: {
              "200": {
                description: "ok",
                content: { "application/json": { schema: { type: "object" } } },
              },
            },
          },
        },
      },
    },
    null,
    2,
  ),
  "utf8",
);

const cfg = {
  gateway: {
    transport: ["http"],
    http: { host: "127.0.0.1", port: PORT, require_auth: "auto" },
    tool_exposure: "namespaced",
    default_policy: "read",
  },
  vault: { backend: "encrypted-file" },
  servers: [
    {
      id: "demoapi",
      source: "app2mcp",
      openapi: openapiPath,
      base_url: upstreamBase,
      enabled: true,
      policy: "read",
    },
    {
      id: "manualhttp",
      source: "http-tool",
      base_url: upstreamBase,
      enabled: true,
      policy: "read",
      http_tools: [
        {
          name: "ping",
          description: "Return a greeting from the smoke upstream.",
          method: "GET",
          path: "/http/ping/{name}",
          inputSchema: {
            type: "object",
            properties: { name: { type: "string" } },
            required: ["name"],
          },
        },
      ],
    },
  ],
  settings: { general: { organization_name: "Smoke", project_name: "codex" }, logs: { capture_io: true } },
};

let gateway;
let handle;
let client;

try {
  const codexConfigPath = join(homedir(), ".codex", "config.toml");
  const codexConfig = readFileSync(codexConfigPath, "utf8");
  assert("Codex config has switchboard MCP table", codexConfig.includes("[mcp_servers.switchboard]"), codexConfigPath);
  assert("Codex switchboard URL points at loopback /mcp", codexConfig.includes(`url = "http://127.0.0.1:${PORT}/mcp"`));

  gateway = await createGateway(cfg);
  handle = await startDashboard(gateway, cfg);
  assert("Switchboard dashboard started on Codex endpoint", handle.url === `http://127.0.0.1:${PORT}`, handle.url);

  const health = await (await fetch(`${handle.url}/api/health`)).json();
  assert("health endpoint reports both test servers mounted", health.status === "ok" && health.servers?.length === 2, JSON.stringify(health));

  const transport = new StreamableHTTPClientTransport(new URL(`${handle.url}/mcp`));
  client = new Client({ name: "codex-switchboard-smoke", version: "0.0.0" });
  await client.connect(transport);

  const listed = await client.listTools();
  const names = listed.tools.map((t) => t.name).sort();
  const openapiTool = names.find((n) => n === "demoapi__getpetbyid");
  const httpTool = names.find((n) => n === "manualhttp__ping");
  assert("MCP tools/list includes app2mcp tool", Boolean(openapiTool), names.join(","));
  assert("MCP tools/list includes http-tool tool", Boolean(httpTool), names.join(","));

  const pet = await client.callTool({ name: openapiTool, arguments: { petId: "7" } });
  const petText = pet.content?.[0]?.text ?? "";
  assert("app2mcp tool call returns upstream data", !pet.isError && petText.includes('"petId":"7"') && petText.includes('"Fido"'), petText.slice(0, 160));

  const ping = await client.callTool({ name: httpTool, arguments: { name: "Masoud" } });
  const pingText = ping.content?.[0]?.text ?? "";
  assert("http-tool call returns upstream data", !ping.isError && pingText.includes('"hello":"Masoud"'), pingText.slice(0, 160));

  const audit = recentAudit(20);
  assert("audit records allowed app2mcp call", audit.some((r) => r.server === "demoapi" && r.tool === "getpetbyid" && r.decision === "allow"));
  assert("audit records allowed http-tool call", audit.some((r) => r.server === "manualhttp" && r.tool === "ping" && r.decision === "allow"));
} finally {
  if (client) await client.close().catch(() => {});
  if (handle) await handle.close().catch(() => {});
  if (gateway) await gateway.shutdown().catch(() => {});
  await closeServer(upstream);
}

const failed = checks.filter((c) => !c.ok);
if (failed.length) console.log("\nFAILED:", failed.map((c) => c.name).join(" | "));
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
process.exitCode = failed.length === 0 ? 0 : 1;
