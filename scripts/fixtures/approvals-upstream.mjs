// A real stdio MCP upstream for scripts/verify-approvals.mjs. Every tool call is appended to the file named by
// SB_STUB_LOG (one JSON line: tool and arguments), so the oracle can prove from outside the gateway process that a
// call was executed exactly once, or not at all. It returns "done:<n>" where n counts the calls so far.
import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { ListToolsRequestSchema, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const log = process.env.SB_STUB_LOG;
const server = new Server({ name: "approvals-upstream", version: "0.0.0" }, { capabilities: { tools: {} } });

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    { name: "get_item", description: "a read", inputSchema: { type: "object", properties: { id: { type: "string" } } } },
    { name: "send_note", description: "a write", inputSchema: { type: "object", properties: { text: { type: "string" } } } },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  if (log) appendFileSync(log, JSON.stringify({ tool: req.params.name, args: req.params.arguments ?? {} }) + "\n");
  const n = log && existsSync(log) ? readFileSync(log, "utf8").split("\n").filter(Boolean).length : 0;
  return { content: [{ type: "text", text: `done:${n}` }] };
});

await server.connect(new StdioServerTransport());
