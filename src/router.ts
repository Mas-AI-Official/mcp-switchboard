/**
 * Router — turns the set of mounted upstream servers into one governed tool
 * surface, and routes calls back to the right upstream after a policy check.
 *
 * Tool naming (`tool_exposure`):
 *   - namespaced (default): `serverId__toolName` — collision-free, the safe default.
 *   - flat:                 bare `toolName` — first server to claim a name wins; later
 *                           collisions are dropped (and logged) so we never silently
 *                           shadow a tool with a different one.
 *   - search:               the gateway exposes just two meta-tools — `find_tools` and
 *                           `call_tool` — instead of every upstream tool. The agent
 *                           searches for what it needs, then invokes it by name. This
 *                           keeps the context window flat no matter how many servers are
 *                           mounted (dozens of MCP servers = thousands of tokens of tool
 *                           schemas otherwise; accuracy degrades sharply past ~30-50 tools).
 *
 * Every real tool call runs the policy engine first. Disabled tools and over-scope calls
 * are denied before the upstream is ever contacted; approval-gated calls block on a
 * human confirm. Every verdict is written to the audit log.
 */

import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import type { Registry, MountedServer } from "./registry.js";
import type { SwitchboardConfig } from "./types.js";
import { evaluate } from "./policy.js";
import { approve } from "./approval.js";
import { audit, sanitizeForAudit } from "./audit.js";
import { log } from "./logger.js";

const SEP = "__";

/** Meta-tool names exposed in `search` mode. Bare names — they cannot collide with a
 *  namespaced upstream tool, which always contains the `__` separator. */
const FIND_TOOLS = "find_tools";
const CALL_TOOL = "call_tool";
const DEFAULT_SEARCH_LIMIT = 10;
const MAX_SEARCH_LIMIT = 50;

interface ExposedTool {
  /** Name as the downstream client sees it. */
  exposedName: string;
  server: MountedServer;
  tool: Tool;
}

export class Router {
  constructor(
    private readonly registry: Registry,
    private readonly cfg: SwitchboardConfig,
  ) {}

  private get mode(): "namespaced" | "flat" | "search" {
    return this.cfg.gateway.tool_exposure;
  }

  /** Build the governed tool list exposed to downstream clients. */
  listTools(): Tool[] {
    if (this.mode === "search") return this.metaTools();
    return this.exposed().map(({ exposedName, tool }) => ({ ...tool, name: exposedName }));
  }

  /** The two meta-tools presented in `search` mode. */
  private metaTools(): Tool[] {
    return [
      {
        name: FIND_TOOLS,
        description:
          "Search across every connected tool by keyword and return the best matches " +
          "with their names, descriptions, and input schemas. Call this first to discover " +
          "which tool to use, then invoke it with `call_tool`. Use this instead of guessing.",
        inputSchema: {
          type: "object",
          properties: {
            query: {
              type: "string",
              description: "What you want to do, e.g. 'create a github issue' or 'send slack message'.",
            },
            limit: {
              type: "number",
              description: `Max results to return (default ${DEFAULT_SEARCH_LIMIT}, max ${MAX_SEARCH_LIMIT}).`,
            },
          },
          required: ["query"],
        },
      },
      {
        name: CALL_TOOL,
        description:
          "Invoke a tool discovered via `find_tools`, by its exact `name` (e.g. " +
          "'github__create_issue'). The call is governed by Switchboard's policy and audit log.",
        inputSchema: {
          type: "object",
          properties: {
            name: { type: "string", description: "Exact tool name from find_tools." },
            arguments: {
              type: "object",
              description: "Arguments object for the target tool.",
              additionalProperties: true,
            },
          },
          required: ["name"],
        },
      },
    ];
  }

  private exposed(): ExposedTool[] {
    // `search` mode still namespaces internally so `call_tool` / `find_tools` can resolve
    // a unique name back to its upstream; only `flat` collapses to bare tool names.
    const flat = this.mode === "flat";
    const out: ExposedTool[] = [];
    const claimed = new Set<string>();

    for (const server of this.registry.list()) {
      if (server.config.enabled === false) continue;
      for (const tool of server.tools) {
        // A tool explicitly disabled in config is never exposed at all.
        if (server.config.tools?.[tool.name]?.enabled === false) continue;

        const exposedName = flat ? tool.name : `${server.config.id}${SEP}${tool.name}`;
        if (claimed.has(exposedName)) {
          log.warn(`tool name collision on '${exposedName}' — dropping the copy from '${server.id}'`);
          continue;
        }
        claimed.add(exposedName);
        out.push({ exposedName, server, tool });
      }
    }
    return out;
  }

  /** Rank the exposed tools against a free-text query. Dependency-free keyword scoring. */
  private search(query: string, limit: number): Tool[] {
    const tokens = query.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
    const scored = this.exposed().map(({ exposedName, tool }) => {
      const name = exposedName.toLowerCase();
      const desc = (tool.description ?? "").toLowerCase();
      let score = 0;
      for (const t of tokens) {
        if (name.includes(t)) score += 3;
        if (desc.includes(t)) score += 1;
      }
      // Phrase bonus: the whole query landing in the description is a strong signal.
      if (tokens.length > 1 && desc.includes(query.toLowerCase())) score += 2;
      return { score, tool: { ...tool, name: exposedName } as Tool };
    });

    const ranked = scored.filter((s) => s.score > 0).sort((a, b) => b.score - a.score);
    // No keyword hits → fall back to the first N tools so the agent still gets a catalogue.
    const pool = ranked.length > 0 ? ranked.map((s) => s.tool) : scored.map((s) => s.tool);
    return pool.slice(0, limit);
  }

  /** Resolve a downstream tool name back to its upstream (server, realToolName). */
  private resolve(exposedName: string): { server: MountedServer; toolName: string } | undefined {
    if (this.mode !== "flat") {
      const idx = exposedName.indexOf(SEP);
      if (idx === -1) return undefined;
      const serverId = exposedName.slice(0, idx);
      const toolName = exposedName.slice(idx + SEP.length);
      const server = this.registry.get(serverId);
      return server ? { server, toolName } : undefined;
    }
    // flat mode: find the first server that owns this tool name.
    for (const server of this.registry.list()) {
      if (server.tools.some((t) => t.name === exposedName)) return { server, toolName: exposedName };
    }
    return undefined;
  }

  /** Entry point for a downstream tool call. In `search` mode this also services the
   *  `find_tools` / `call_tool` meta-tools; otherwise it forwards directly. */
  async callTool(exposedName: string, args: Record<string, unknown>): Promise<CallToolResult> {
    if (this.mode === "search") {
      if (exposedName === FIND_TOOLS) return this.handleFind(args);
      if (exposedName === CALL_TOOL) return this.handleCall(args);
      // Direct call by namespaced name still works as a convenience.
    }
    return this.forward(exposedName, args);
  }

  /** `find_tools` meta-tool — discovery only, never touches an upstream. */
  private handleFind(args: Record<string, unknown>): CallToolResult {
    const query = typeof args.query === "string" ? args.query : "";
    if (!query.trim()) return this.error("find_tools requires a non-empty 'query'");
    const rawLimit = typeof args.limit === "number" ? args.limit : DEFAULT_SEARCH_LIMIT;
    const limit = Math.max(1, Math.min(MAX_SEARCH_LIMIT, Math.floor(rawLimit)));

    const matches = this.search(query, limit).map((t) => ({
      name: t.name,
      description: t.description ?? "",
      inputSchema: t.inputSchema,
    }));
    audit({ server: "switchboard", tool: FIND_TOOLS, scope: "read", decision: "allow", reason: `query=${query}` });
    return { content: [{ type: "text", text: JSON.stringify({ matches }, null, 2) }] };
  }

  /** `call_tool` meta-tool — unwrap the target and route it through the governed path. */
  private handleCall(args: Record<string, unknown>): Promise<CallToolResult> {
    const name = typeof args.name === "string" ? args.name : "";
    if (!name) return Promise.resolve(this.error("call_tool requires a 'name'"));
    const inner =
      args.arguments && typeof args.arguments === "object"
        ? (args.arguments as Record<string, unknown>)
        : {};
    return this.forward(name, inner);
  }

  /** Govern, then forward, a real tool call to its upstream server. */
  private async forward(exposedName: string, args: Record<string, unknown>): Promise<CallToolResult> {
    const target = this.resolve(exposedName);
    if (!target) return this.error(`unknown tool '${exposedName}'`);

    const { server, toolName } = target;
    const verdict = evaluate(server.config, toolName, this.cfg, server.scopeHints?.[toolName]);

    if (verdict.decision === "deny") {
      audit({ server: server.id, tool: toolName, scope: verdict.scope, decision: "deny", reason: verdict.reason });
      return this.error(`denied by policy: ${verdict.reason}`);
    }

    // Settle the approval gate before executing. A denied approval is the only path that
    // audits without an execution; everything allowed audits ONCE after the call so the row
    // can carry timing and (opt-in) request/response.
    let reason = verdict.reason;
    if (verdict.decision === "approval_required") {
      const allowed = await approve(server.id, toolName, verdict.scope, verdict.reason);
      if (!allowed) {
        audit({ server: server.id, tool: toolName, scope: verdict.scope, decision: "deny", reason: "approval denied/unavailable" });
        return this.error(`approval required and not granted for '${exposedName}'`);
      }
      reason = "approved";
    }

    const capture = this.cfg.settings?.logs?.capture_io === true;
    const start = Date.now();
    try {
      const result = (await server.client.callTool({ name: toolName, arguments: args })) as CallToolResult;
      audit({
        server: server.id,
        tool: toolName,
        scope: verdict.scope,
        decision: "allow",
        reason,
        duration_ms: Date.now() - start,
        ...(capture ? { request: sanitizeForAudit(args), response: sanitizeForAudit(result) } : {}),
        ...(result.isError ? { error: this.resultErrorText(result) } : {}),
      });
      return result;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      audit({
        server: server.id,
        tool: toolName,
        scope: verdict.scope,
        decision: "allow",
        reason,
        duration_ms: Date.now() - start,
        ...(capture ? { request: sanitizeForAudit(args) } : {}),
        error: msg,
      });
      return this.error(`upstream '${server.id}' failed calling '${toolName}': ${msg}`);
    }
  }

  /** Best-effort extraction of an upstream error-result's text content for the audit row. */
  private resultErrorText(result: CallToolResult): string {
    const parts: string[] = [];
    for (const c of result.content ?? []) {
      if (c && typeof c === "object" && (c as { type?: string }).type === "text") {
        const t = (c as { text?: unknown }).text;
        if (typeof t === "string") parts.push(t);
      }
    }
    return parts.join(" ").trim() || "upstream returned an error result";
  }

  private error(message: string): CallToolResult {
    return { isError: true, content: [{ type: "text", text: `[switchboard] ${message}` }] };
  }
}
