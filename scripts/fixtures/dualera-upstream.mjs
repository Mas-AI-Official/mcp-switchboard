// A real stdio MCP upstream built on SDK 1.x. The dual-era oracle mounts it through the real CLI (`switchboard serve`),
// so it proves that the v2 gateway still mounts the 1.x servers most local MCP servers are, over stdio. One tool,
// get_sum(a, b), answers the sum as text.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const server = new Server({ name: "dualera-upstream", version: "0.0.0" }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "get_sum",
      description: "Add two numbers.",
      inputSchema: { type: "object", properties: { a: { type: "number" }, b: { type: "number" } }, required: ["a", "b"] },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const a = req.params.arguments ?? {};
  return { content: [{ type: "text", text: String(Number(a.a) + Number(a.b)) }] };
});

await server.connect(new StdioServerTransport());
