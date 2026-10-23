// A real stdio MCP upstream whose only job is to report the environment it was started with. The
// policy-hardening oracle mounts it through the real Registry, so what comes back is exactly what a
// stdio upstream of a real config would see. It returns variable NAMES for everything, and the VALUE
// only for names that start with SB_TEST_ (oracle-planted, obviously fake): a real secret is never
// echoed even if the filter under test were broken.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const server = new Server({ name: "env-upstream", version: "0.0.0" }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "get_env",
      description: "Report the names (and SB_TEST_ values) of this process's environment.",
      inputSchema: { type: "object", properties: {} },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async () => {
  const names = Object.keys(process.env);
  const values = {};
  for (const name of names) if (name.startsWith("SB_TEST_")) values[name] = process.env[name];
  return { content: [{ type: "text", text: JSON.stringify({ platform: process.platform, names, values }) }] };
});

await server.connect(new StdioServerTransport());
