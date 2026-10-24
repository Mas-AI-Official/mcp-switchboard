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

import { ProtocolError, ProtocolErrorCode, SdkError, SdkErrorCode } from "@modelcontextprotocol/server";
import type {
  CallToolResult,
  Tool,
  Resource,
  ResourceTemplateType,
  Prompt,
  ReadResourceResult,
  GetPromptResult,
} from "@modelcontextprotocol/server";
import type { Registry, MountedServer } from "./registry.js";
import type { LimitSpec, Risk, Scope, SwitchboardConfig } from "./types.js";
import { evaluate, resolveToolScope } from "./policy.js";
import {
  gateAllowsServer,
  gateAllowsTool,
  gateLabel,
  gateRiskCeiling,
  gateScopeCeiling,
  principalAudit,
  principalLabel,
  resolveClientGate,
  type ClientGate,
  type Principal,
} from "./principal.js";
import { isKilled, killStatus } from "./killswitch.js";
import {
  getActiveProfile,
  profileAllowsServer,
  profileAllowsTool,
  profileScopeCeiling,
} from "./profiles.js";
import {
  Approvals,
  ApprovalLimitError,
  DEFAULT_TTL_SECONDS,
  INTERNAL_PRINCIPAL,
  MAX_WAIT_SECONDS,
  type ApprovalRequest,
} from "./approvals.js";
import { audit, redactSecretShapes, sanitizeForAudit, type AuditInput } from "./audit.js";
import { safeText } from "./safetext.js";
import { deliverWebhook, type SecretResolver, type WebhookEvent } from "./webhook.js";
import {
  shapeExposedTool,
  applyArgTransforms,
  ArgCollisionError,
  assertNoArgCollision,
  applyResponseRedaction,
  removedRequiredNotInjected,
  injectedArgKeys,
} from "./transforms.js";
import { SB_ERR, SB_HINTS, type SbErrorCode } from "./errors.js";
import { rankBm25, type RankDoc } from "./search-index.js";
import { Governor } from "./governor.js";
import { Breaker } from "./breaker.js";
import { DEFAULT_STEP_BUDGET, templateMatches, type StepBudget } from "./uritemplate.js";
import { log } from "./logger.js";
import { APPROVED_META_KEY, AUDIT_META_KEY, CLIENT_META_KEY, TOOL_META_KEY, type ConnectorPlanView } from "./connectors/mcpserver.js";
import { isConnectorError, type ConnectorError } from "./connectors/errors.js";

const SEP = "__";
const RESERVED_META_PREFIX = "io.modelcontextprotocol/";

/** Never relay an upstream SDK's reserved identity metadata as if it described this gateway. */
function stripUpstreamReservedMeta<T extends { _meta?: Record<string, unknown> }>(value: T): T {
  if (!value._meta || !Object.keys(value._meta).some((key) => key.startsWith(RESERVED_META_PREFIX))) return value;
  const meta = Object.fromEntries(Object.entries(value._meta).filter(([key]) => !key.startsWith(RESERVED_META_PREFIX)));
  if (Object.keys(meta).length === 0) {
    const { _meta: _removed, ...rest } = value;
    return rest as T;
  }
  return { ...value, _meta: meta };
}

/**
 * Per-field weights + length-normalization for the BM25F tool ranker (see search-index.ts).
 * Intent: a query term landing in the tool *name* outranks the same term in a *tag*, which
 * outranks an input *property*, which outranks a mention deep in the *description*. Keyword-ish
 * fields (name/tags/props) use b=0 (length is meaningless for a 2-word name or a tag list);
 * the prose description uses full length normalization so a terse, on-point description isn't
 * beaten by a sprawling one that merely happens to contain the term.
 */
const SEARCH_FIELDS = {
  name: { weight: 6, b: 0 },
  tags: { weight: 4, b: 0 },
  props: { weight: 2, b: 0 },
  description: { weight: 1, b: 0.75 },
} as const;
/** Multiplier applied to an operator-flagged (`important`) tool's BM25F score. */
const IMPORTANT_BOOST = 1.5;

/** Meta-tool names exposed in `search` mode. Bare names — they cannot collide with a
 *  namespaced upstream tool, which always contains the `__` separator. */
const FIND_TOOLS = "find_tools";
const CALL_TOOL = "call_tool";
const BATCH_CALL = "batch_call";
const DEFAULT_SEARCH_LIMIT = 10;
const MAX_SEARCH_LIMIT = 50;
/** Cap on tool calls per `batch_call` request — a runaway guard, not a quota. */
const MAX_BATCH_CALLS = 20;
/** The two read-scope content surfaces that run through policy like a tool call (design 3.10). */
type ReadSurface = "resources/read" | "prompts/get";

/** The four MCP annotation hints that can be used as `find_tools` tag filters. */
const ANNOTATION_TAGS = ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"] as const;

interface ExposedTool {
  /** Name as the downstream client sees it. */
  exposedName: string;
  server: MountedServer;
  tool: Tool;
}

/**
 * Who is calling, resolved once per Router entry: the principal (absent for an internal call such as the
 * owner's playground or a trigger poll, which no client filter applies to), the gate its client imposes
 * (design 3.1), and the audit fields every row of this call carries.
 */
interface Caller {
  principal?: Principal;
  gate?: ClientGate;
  attr: { principal?: string; client?: string };
}

/** What settling an approval gate came to: go on, stop for the kill switch, or stop with a coded refusal. */
type Settled =
  | { go: true; approvalId: string }
  | { go: false; killed: true }
  | { go: false; killed?: false; code: SbErrorCode; message: string; auditReason: string; extra?: Record<string, unknown> };

export class Router {
  /** Rate-limit + spend-budget enforcement, built once from the immutable config for this Router. */
  private readonly governor: Governor;
  /** Per-server circuit breaker — fails fast on a wedged/dead upstream instead of hanging. */
  private readonly breaker: Breaker;
  /** Out-of-band approvals (design 3.3). The gateway passes the one its dashboard decides on; a Router built alone gets its own. */
  private readonly approvals: Approvals;

  constructor(
    private readonly registry: Registry,
    private readonly cfg: SwitchboardConfig,
    private readonly resolveSecret: SecretResolver,
    approvals?: Approvals,
  ) {
    this.governor = new Governor(cfg);
    this.breaker = new Breaker(cfg);
    this.approvals = approvals ?? new Approvals();
  }

  /** Read-only health of every server's circuit breaker — for an observability endpoint/dashboard. */
  serverHealth() {
    return this.breaker.snapshot(Date.now());
  }

  /** Tool keys we've already warned about (shaping removed a required param with no injected
   *  value). Deduped for this Router's lifetime so a per-listTools call can't spam the log. */
  private readonly warned = new Set<string>();

  private get mode(): "namespaced" | "flat" | "search" {
    return this.cfg.gateway.tool_exposure;
  }

  private warnOnce(key: string, message: string): void {
    if (this.warned.has(key)) return;
    this.warned.add(key);
    log.warn(message);
  }

  /** Property names declared on a tool's input schema (empty when none). */
  private schemaPropNames(tool: Tool): string[] {
    const schema = tool.inputSchema as { properties?: Record<string, unknown> } | undefined;
    const props = schema?.properties;
    return props && typeof props === "object" ? Object.keys(props) : [];
  }

  /** Coerce an arbitrary value into a non-empty Set of strings, or undefined. */
  private stringSet(value: unknown): Set<string> | undefined {
    if (!Array.isArray(value)) return undefined;
    const items = value.filter((v): v is string => typeof v === "string" && v.length > 0);
    return items.length ? new Set(items) : undefined;
  }

  /** Resolve the caller of a Router entry. The clients map is read live, so a reload takes effect on the next call. */
  private callerOf(principal?: Principal): Caller {
    return { principal, gate: resolveClientGate(this.cfg.clients, principal), attr: principalAudit(principal) };
  }

  /** Build the governed tool list exposed to downstream clients, filtered by the caller's client (design 3.1). */
  listTools(principal?: Principal): Tool[] {
    const gate = this.callerOf(principal).gate;
    if (gate && gate.deny !== null) return [];
    if (this.mode === "search") return this.metaTools();
    const tools = this.exposed(gate).map(({ exposedName, tool }) => ({ ...tool, name: exposedName }));
    // A connector toolkit lists only its important set. While any toolkit THIS caller may see holds unlisted actions,
    // the two discovery tools are listed too, so the rest are reachable (ADR local-composio 6.7).
    if (this.hasUnlisted(gate)) tools.push(...this.metaTools().filter((t) => t.name === FIND_TOOLS || t.name === CALL_TOOL));
    return tools;
  }

  /** True while a server the caller may see holds callable-but-unlisted tools (a connector toolkit's long tail). */
  private hasUnlisted(gate?: ClientGate): boolean {
    const active = getActiveProfile(this.cfg)?.profile;
    return this.registry.list().some((s) => this.isVisible(s, active) && (!gate || gateAllowsServer(gate, s.id)) && (s.unlisted?.length ?? 0) > 0);
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
            servers: {
              type: "array",
              items: { type: "string" },
              description:
                "Optional: restrict the search to these server ids (e.g. ['github','slack']). " +
                "Omit to search every connected server.",
            },
            tags: {
              type: "array",
              items: { type: "string", enum: [...ANNOTATION_TAGS] },
              description:
                "Optional: only return tools whose annotations assert ALL of these hints — e.g. " +
                "['readOnlyHint'] for safe read-only tools, ['destructiveHint'] for mutating ones.",
            },
          },
          required: ["query"],
        },
      },
      {
        name: CALL_TOOL,
        description:
          "Invoke a tool discovered via `find_tools`, by its exact `name` (e.g. " +
          "'github__create_issue'). The call is governed by MCP Switchboard's policy and audit log.",
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
      {
        name: BATCH_CALL,
        description:
          "Invoke several tools in one request. Each entry is governed, approval-gated, and " +
          "audited independently — exactly as if called via `call_tool`. Returns a `results` " +
          `array in the same order; a failure in one call never aborts the others. Up to ${MAX_BATCH_CALLS} calls.`,
        inputSchema: {
          type: "object",
          properties: {
            calls: {
              type: "array",
              description: "Tool calls to run, each `{ name, arguments? }`.",
              items: {
                type: "object",
                properties: {
                  name: { type: "string", description: "Exact tool name (e.g. 'github__create_issue')." },
                  arguments: {
                    type: "object",
                    description: "Arguments object for that tool.",
                    additionalProperties: true,
                  },
                },
                required: ["name"],
              },
            },
          },
          required: ["calls"],
        },
      },
    ];
  }

  /**
   * `gate`: the caller's client, which may hide whole servers and individual tools. `includeUnlisted`: also the tools a
   * server keeps out of its listing (search and calls use them; listing never does).
   */
  private exposed(gate?: ClientGate, includeUnlisted = false): ExposedTool[] {
    // `search` mode still namespaces internally so `call_tool` / `find_tools` can resolve
    // a unique name back to its upstream; only `flat` collapses to bare tool names.
    const flat = this.mode === "flat";
    const out: ExposedTool[] = [];
    const claimed = new Set<string>();
    // The active profile (if any) is a VIEW: it can only HIDE servers/tools, never reveal a
    // disabled one. Resolved once here so listTools()/search() inherit the same filter for free.
    const active = getActiveProfile(this.cfg)?.profile;

    for (const server of this.registry.list()) {
      if (server.config.enabled === false) continue;
      // A profile's server allowlist hides whole servers before we ever shape their tools.
      if (!profileAllowsServer(active, server.config.id)) continue;
      // The caller's client may hide a server too. Its tools still claim their names below, so a flat-mode
      // name resolves to the same owner here as in resolve() whoever is asking.
      const serverHidden = gate !== undefined && !gateAllowsServer(gate, server.config.id);
      for (const tool of includeUnlisted && server.unlisted?.length ? [...server.tools, ...server.unlisted] : server.tools) {
        const override = server.config.tools?.[tool.name];
        // A tool explicitly disabled in config is never exposed at all.
        if (override?.enabled === false) continue;

        const exposedName = flat ? tool.name : `${server.config.id}${SEP}${tool.name}`;
        // A profile's tool allow/deny list hides individual tools by their EXPOSED name.
        if (!profileAllowsTool(active, exposedName)) continue;
        if (claimed.has(exposedName)) {
          log.warn(`tool name collision on '${safeText(exposedName)}': dropping the copy from '${server.id}'`);
          continue;
        }
        claimed.add(exposedName);
        // The caller's client: its server globs (above) and its tool allowlist and denylist, by exposed name.
        if (gate && (serverHidden || !gateAllowsTool(gate, exposedName))) continue;

        // If shaping removes a required param without injecting a value, agents can't satisfy
        // the upstream call — warn once so the misconfiguration is visible (the tool is still
        // exposed; the upstream remains the source of truth for what it will accept).
        const orphaned = removedRequiredNotInjected(tool, server.config, override);
        if (orphaned.length) {
          this.warnOnce(
            `${exposedName}:${orphaned.join(",")}`,
            `tool '${safeText(exposedName)}' hides/drops required param(s) [${safeText(orphaned.join(", "), 200)}] with no inject_args value: calls may fail upstream`,
          );
        }

        // Shape the tool AS AGENTS SEE IT (description/params/schema). forward() still resolves
        // the RAW upstream name + transforms args, so shaping only affects the exposed surface.
        out.push({ exposedName, server, tool: shapeExposedTool(tool, server.config, override) });
      }
    }
    return out;
  }

  /** Rank the exposed tools against a free-text query with BM25F (see search-index.ts), with
   *  optional pre-filtering by server id and by annotation tag. A tool passes the tag filter
   *  only if it POSITIVELY asserts every requested hint (`annotations[tag] === true`). */
  private search(
    query: string,
    limit: number,
    serverFilter?: Set<string>,
    tagFilter?: Set<string>,
    gate?: ClientGate,
  ): Tool[] {
    const lcQuery = query.trim().toLowerCase();

    let pool = this.exposed(gate, true);
    if (serverFilter && serverFilter.size) pool = pool.filter((e) => serverFilter.has(e.server.id));
    if (tagFilter && tagFilter.size) {
      pool = pool.filter((e) => {
        const ann = e.tool.annotations as Record<string, unknown> | undefined;
        return Array.from(tagFilter).every((tag) => ann?.[tag] === true);
      });
    }

    // Build one BM25F document per exposed tool: name / tags / input-property names / description.
    const docs: RankDoc[] = pool.map(({ exposedName, server, tool }) => {
      const override = server.config.tools?.[tool.name];
      // A connector action carries its own tags. Its `important` flag decides what is LISTED, not how it ranks:
      // find_tools exists to reach the long tail, so the listed set gets no boost over it.
      const meta = server.config.source === "connector" ? (tool._meta?.[TOOL_META_KEY] as { tags?: unknown } | undefined) : undefined;
      const metaTags = Array.isArray(meta?.tags) ? (meta!.tags as unknown[]).filter((t): t is string => typeof t === "string") : [];
      return {
        id: exposedName,
        boost: override?.important ? IMPORTANT_BOOST : 1,
        exact: exposedName.toLowerCase() === lcQuery,
        fields: [
          { key: "name", text: exposedName, weight: SEARCH_FIELDS.name.weight, b: SEARCH_FIELDS.name.b },
          { key: "tags", text: [...(override?.tags ?? []), ...metaTags].join(" "), weight: SEARCH_FIELDS.tags.weight, b: SEARCH_FIELDS.tags.b },
          { key: "props", text: this.schemaPropNames(tool).join(" "), weight: SEARCH_FIELDS.props.weight, b: SEARCH_FIELDS.props.b },
          { key: "description", text: tool.description ?? "", weight: SEARCH_FIELDS.description.weight, b: SEARCH_FIELDS.description.b },
        ],
      };
    });

    const ranked = rankBm25(docs, query, { limit });
    if (ranked.length > 0) {
      const byId = new Map(pool.map((e) => [e.exposedName, e.tool]));
      return ranked.map((r) => ({ ...byId.get(r.id)!, name: r.id }) as Tool);
    }
    // No term matched → fall back to the first N tools (already server/tag-filtered) so the
    // agent still gets a catalogue narrowed to what it asked for.
    return pool.slice(0, limit).map(({ exposedName, tool }) => ({ ...tool, name: exposedName }) as Tool);
  }

  /** The mounted server a namespaced name points at (`serverId__...`), whether or not that server lists the tool. */
  private namespaceOwner(exposedName: string): { server: MountedServer; toolName: string } | undefined {
    if (this.mode === "flat") return undefined;
    const idx = exposedName.indexOf(SEP);
    if (idx === -1) return undefined;
    const server = this.registry.get(exposedName.slice(0, idx));
    return server ? { server, toolName: exposedName.slice(idx + SEP.length) } : undefined;
  }

  /**
   * Resolve a downstream tool name back to its upstream (server, realToolName). A namespaced name resolves only to a
   * tool the upstream LISTED: 0.1.0 split `serverId__anything` and forwarded the rest, so a client could call a
   * tool its upstream never advertised (a hidden admin tool, a debug handler) and every listing-based control
   * (profiles, client globs, per-tool overrides) was bypassed by naming it directly.
   */
  private resolve(exposedName: string): { server: MountedServer; toolName: string } | undefined {
    if (this.mode !== "flat") {
      const owner = this.namespaceOwner(exposedName);
      return owner && this.lists(owner.server, owner.toolName) ? owner : undefined;
    }
    // flat mode: find the first server that owns this tool name.
    for (const server of this.registry.list()) {
      if (this.lists(server, exposedName)) return { server, toolName: exposedName };
    }
    return undefined;
  }

  /**
   * Does this server LIST the tool, or hold it as a callable-but-unlisted one (a connector toolkit's long tail, found
   * with `find_tools`)? Both are tools the upstream declared at mount. A name the upstream never declared is neither.
   * Callable is not the same as allowed: every client, profile and policy gate in forward() still applies.
   */
  private lists(server: MountedServer, toolName: string): boolean {
    return server.tools.some((t) => t.name === toolName) || server.unlisted?.some((t) => t.name === toolName) === true;
  }

  /** Entry point for a downstream tool call. In `search` mode this also services the
   *  `find_tools` / `call_tool` meta-tools; otherwise it forwards directly. */
  async callTool(exposedName: string, args: Record<string, unknown>, principal?: Principal): Promise<CallToolResult> {
    const caller = this.callerOf(principal);
    // Kill switch first (design 3.8): it stops the discovery meta-tools too, not just upstream calls.
    const killed = this.refuseIfKilled(exposedName, caller);
    if (killed) return killed;
    if (this.mode === "search") {
      if (exposedName === FIND_TOOLS) return this.handleFind(args, caller);
      if (exposedName === CALL_TOOL) return this.handleCall(args, caller);
      if (exposedName === BATCH_CALL) return this.handleBatch(args, caller);
      // Direct call by namespaced name still works as a convenience.
    } else if ((exposedName === FIND_TOOLS || exposedName === CALL_TOOL) && this.hasUnlisted(caller.gate)) {
      return exposedName === FIND_TOOLS ? this.handleFind(args, caller) : this.handleCall(args, caller);
    }
    return this.forward(exposedName, args, caller);
  }

  /** `find_tools` meta-tool — discovery only, never touches an upstream. */
  private handleFind(args: Record<string, unknown>, caller: Caller): CallToolResult {
    const query = typeof args.query === "string" ? args.query : "";
    if (!query.trim()) return this.error("find_tools requires a non-empty 'query'", SB_ERR.BAD_REQUEST);
    const rawLimit = typeof args.limit === "number" ? args.limit : DEFAULT_SEARCH_LIMIT;
    const limit = Math.max(1, Math.min(MAX_SEARCH_LIMIT, Math.floor(rawLimit)));
    const serverFilter = this.stringSet(args.servers);
    const tagFilter = this.stringSet(args.tags);

    const matches = this.search(query, limit, serverFilter, tagFilter, caller.gate).map((t) => ({
      name: t.name,
      description: t.description ?? "",
      inputSchema: t.inputSchema,
    }));
    this.safeAudit({ server: "switchboard", tool: FIND_TOOLS, scope: "read", decision: "allow", reason: `query=${query}`, ...caller.attr });
    return { content: [{ type: "text", text: JSON.stringify({ matches }, null, 2) }] };
  }

  /** `call_tool` meta-tool — unwrap the target and route it through the governed path. */
  private handleCall(args: Record<string, unknown>, caller: Caller): Promise<CallToolResult> {
    const name = typeof args.name === "string" ? args.name : "";
    if (!name) return Promise.resolve(this.error("call_tool requires a 'name'", SB_ERR.BAD_REQUEST));
    const inner =
      args.arguments && typeof args.arguments === "object"
        ? (args.arguments as Record<string, unknown>)
        : {};
    return this.forward(name, inner, caller);
  }

  /** `batch_call` meta-tool — run several governed calls in one request. Each entry goes through
   *  the SAME forward() path (policy → approval → audit), so a batch is just a convenience over N
   *  call_tool invocations: one failing call never aborts the rest. */
  private async handleBatch(args: Record<string, unknown>, caller: Caller): Promise<CallToolResult> {
    const calls = Array.isArray(args.calls) ? args.calls : null;
    if (!calls) return this.error("batch_call requires a 'calls' array", SB_ERR.BAD_REQUEST);
    if (calls.length === 0) return this.error("batch_call 'calls' array is empty", SB_ERR.BAD_REQUEST);
    if (calls.length > MAX_BATCH_CALLS) {
      return this.error(`batch_call accepts at most ${MAX_BATCH_CALLS} calls per request`, SB_ERR.BAD_REQUEST);
    }

    const results = await Promise.all(
      calls.map(async (raw) => {
        const entry = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
        const name = typeof entry.name === "string" ? entry.name : "";
        if (!name) {
          const errored = this.error("batch entry missing 'name'", SB_ERR.BAD_REQUEST);
          return { name: "", isError: true, content: errored.content };
        }
        const inner =
          entry.arguments && typeof entry.arguments === "object"
            ? (entry.arguments as Record<string, unknown>)
            : {};
        const res = await this.forward(name, inner, caller);
        return { name, isError: res.isError === true, content: res.content };
      }),
    );
    return { content: [{ type: "text", text: JSON.stringify({ results }, null, 2) }] };
  }

  /** Govern, then forward, a real tool call to its upstream server. */
  private async forward(exposedName: string, args: Record<string, unknown>, caller: Caller): Promise<CallToolResult> {
    // Every audit row of this call carries the caller's principal and client, its risk (once known) and the
    // approval it ran under (once consumed).
    let risk: Risk | undefined;
    let approvalId: string | undefined;
    let attemptSeq: number | undefined;
    const rec = (e: AuditInput): void =>
      this.record(
        {
          ...(risk ? { risk } : {}),
          ...(approvalId ? { approval_id: approvalId } : {}),
          ...(attemptSeq !== undefined ? { attempt_seq: attemptSeq } : {}),
          ...e,
        },
        caller,
      );
    const gate = caller.gate;
    // Checked again here, not only in callTool(): each entry of a batch_call is its own call, and the
    // switch can be thrown between two of them.
    const killed = this.refuseIfKilled(exposedName, caller);
    if (killed) return killed;

    const target = this.resolve(exposedName);
    if (!target) {
      // A name that points at a real server but at a tool it never listed is a probe worth a row; a name that points
      // at nothing is noise and stays unaudited (as before), so a flood of junk names cannot grow the log.
      const owner = this.namespaceOwner(exposedName);
      if (owner) {
        rec({
          server: owner.server.id,
          tool: safeText(owner.toolName, 128),
          scope: "read",
          decision: "deny",
          reason: "the upstream does not list this tool",
          error_code: SB_ERR.UNKNOWN_TOOL,
        });
      }
      return this.error(`unknown tool '${exposedName}'`, SB_ERR.UNKNOWN_TOOL);
    }

    const { server, toolName } = target;
    const override = server.config.tools?.[toolName];
    const active = getActiveProfile(this.cfg)?.profile;
    // The upstream's own annotations ride along: they can only tighten the scope (design 3.5).
    const verdict = evaluate(
      server.config,
      toolName,
      this.cfg,
      server.scopeHints?.[toolName],
      profileScopeCeiling(active),
      this.annotationsOf(server, toolName),
      gateScopeCeiling(gate),
      gateRiskCeiling(gate),
      // A connector action carries its own risk, outward and approval facts: they raise the risk and force an approval, never lower either.
      server.connector?.hints[toolName],
    );
    risk = verdict.risk;

    // Defense in depth: a tool hidden by the active profile must also be UNCALLABLE, not merely
    // absent from the listing. resolve() works off raw upstream names, so a client that names a
    // hidden tool directly would otherwise bypass the view. Deny it with the same audit trail.
    const exposedForProfile = this.mode === "flat" ? toolName : `${server.config.id}${SEP}${toolName}`;
    if (!profileAllowsServer(active, server.config.id) || !profileAllowsTool(active, exposedForProfile)) {
      rec({ server: server.id, tool: toolName, scope: verdict.scope, decision: "deny", reason: "hidden by active profile", error_code: SB_ERR.POLICY_DENY });
      return this.error(`denied by policy: '${exposedName}' is not available in the active profile`, SB_ERR.POLICY_DENY);
    }

    // The same for the caller's client (design 3.1): hidden must also be uncallable, and the client is named.
    if (gate && (gate.deny !== null || !gateAllowsServer(gate, server.config.id) || !gateAllowsTool(gate, exposedForProfile))) {
      const why = gate.deny ?? `hidden from ${gateLabel(gate)}`;
      rec({ server: server.id, tool: toolName, scope: verdict.scope, decision: "deny", reason: why, error_code: SB_ERR.POLICY_DENY });
      return this.error(
        gate.deny !== null ? `denied by policy: ${gate.deny}` : `denied by policy: '${exposedName}' is not available to ${gateLabel(gate)}`,
        SB_ERR.POLICY_DENY,
      );
    }

    if (verdict.decision === "deny") {
      rec({ server: server.id, tool: toolName, scope: verdict.scope, decision: "deny", reason: verdict.reason, error_code: SB_ERR.POLICY_DENY });
      return this.error(`denied by policy: ${verdict.reason}`, SB_ERR.POLICY_DENY);
    }

    // Ambiguous arguments (design 3.15): an exposed name and the upstream name it replaces, both sent, would reach
    // the upstream as ONE parameter whose value depended on key order, while the approval hash does not. Refused
    // here, before a governor token, an approval request or an approval is spent on it.
    try {
      assertNoArgCollision(args, server.config, override);
    } catch (err) {
      if (!(err instanceof ArgCollisionError)) throw err;
      rec({ server: server.id, tool: toolName, scope: verdict.scope, decision: "deny", reason: `ambiguous arguments: ${err.message}`, error_code: SB_ERR.BAD_REQUEST });
      return this.error(`could not prepare arguments for '${exposedName}': ${err.message}`, SB_ERR.BAD_REQUEST);
    }

    // Rate limits + spend budgets — charged BEFORE the approval gate so a throttled call never wakes
    // a human, and conservatively (a denied call still counts) so a runaway loop is capped, not billed
    // precisely. Fails closed: any exceeded ceiling (global/server/tool) stops the call here.
    const gov = this.governor.consume(server.id, toolName, Date.now(), this.clientLimitsOf(gate));
    if (!gov.ok) {
      rec({ server: server.id, tool: toolName, scope: verdict.scope, decision: "deny", reason: gov.reason, error_code: SB_ERR.RATE_LIMITED });
      const retry = gov.retryAfterMs && isFinite(gov.retryAfterMs) ? ` (retry after ~${Math.ceil(gov.retryAfterMs / 1000)}s)` : "";
      return this.error(`rate limited: ${gov.reason}${retry}`, SB_ERR.RATE_LIMITED);
    }

    // Circuit breaker — an AVAILABILITY check after the security controls (policy/scope/limits) and
    // before the approval gate, so a call to a known-dead upstream fails fast instead of paying the
    // full call timeout AND never wakes a human for a server that can't answer. Opt-in via
    // settings.resilience / server.resilience; inert (constant-true) when unconfigured.
    const health = this.breaker.allow(server.id, Date.now());
    if (!health.ok) {
      rec({ server: server.id, tool: toolName, scope: verdict.scope, decision: "deny", reason: health.reason, error_code: SB_ERR.UPSTREAM_UNAVAILABLE });
      const retry = health.retryAfterMs && isFinite(health.retryAfterMs) ? ` (retry after ~${Math.ceil(health.retryAfterMs / 1000)}s)` : "";
      return this.error(`upstream '${server.id}' is unavailable (circuit open)${retry}: ${health.reason}`, SB_ERR.UPSTREAM_UNAVAILABLE);
    }

    // Settle the approval gate before executing (design 3.3). The gate no longer waits for a keystroke: a gated call
    // either consumes an approval the owner already gave for exactly these arguments, or leaves a pending request
    // and tells the caller how the owner approves it. A denied or unusable approval is the only path that audits
    // without an execution; everything allowed audits ONCE after the call so the row can carry timing and (opt-in)
    // request/response.
    let reason = verdict.reason;
    let plan: ConnectorPlanView | undefined;
    if (verdict.decision === "approval_required") {
      // The hash is taken over the arguments as the client sent them: BEFORE applyArgTransforms below injects a secret.
      let bound: unknown = args;
      if (server.connector) {
        // A connector call is approved for an ACCOUNT and a REQUEST, not just for arguments: another account, host,
        // path, method, body or file must be another approval. The call is resolved here exactly as the toolkit will
        // resolve it (the final arguments, the authenticated client), without sending anything, and what it resolves
        // to is bound beside the arguments. A refusal at this point (the account argument, a pin, an unknown account, a
        // bad argument) comes before any approval exists, so nothing is put in front of the owner that cannot run.
        let planArgs: Record<string, unknown>;
        try {
          planArgs = applyArgTransforms(args, server.config, override, this.resolveSecret);
        } catch (err) {
          const msg = err instanceof Error ? err.message : String(err);
          rec({ server: server.id, tool: toolName, scope: verdict.scope, decision: "deny", reason: `arg transform failed: ${msg}`, error_code: SB_ERR.BAD_REQUEST });
          return this.error(`could not prepare arguments for '${exposedName}': ${msg}`, SB_ERR.BAD_REQUEST);
        }
        try {
          plan = await server.connector.plan(toolName, planArgs, caller.principal?.client ?? undefined);
        } catch (err) {
          if (!isConnectorError(err)) {
            // Anything else that goes wrong while resolving a call is a refusal too: nothing was approved, nothing is sent.
            const msg = safeText(err instanceof Error ? err.message : String(err), 300);
            rec({ server: server.id, tool: toolName, scope: verdict.scope, decision: "deny", reason: `could not resolve the call: ${msg}`, error_code: SB_ERR.BAD_REQUEST });
            return this.error(`could not prepare '${exposedName}': ${msg}`, SB_ERR.BAD_REQUEST);
          }
          rec({ server: server.id, tool: toolName, scope: verdict.scope, decision: "deny", reason: safeText(err.message, 300), error_code: err.code });
          return this.connectorRefusal(err, exposedName);
        }
        if (plan) bound = { account: plan.account, request: plan.request, arguments: args, connector: plan.binding };
      }
      const settled = await this.settleApproval(server, toolName, exposedName, bound, verdict, caller, () => isKilled(this.cfg));
      if (!settled.go) {
        // The switch can be thrown while we waited for the owner. The approval stays unused for when it is cleared.
        if (settled.killed) return this.refuseIfKilled(exposedName, caller) ?? this.error("kill switch is on", SB_ERR.KILL_SWITCH);
        // A pending request already wrote its own approval_required row when it was created.
        if (settled.code !== SB_ERR.APPROVAL_PENDING) {
          rec({ server: server.id, tool: toolName, scope: verdict.scope, decision: "deny", reason: settled.auditReason, error_code: settled.code });
        }
        return this.error(settled.message, settled.code, settled.extra);
      }
      approvalId = settled.approvalId;
      reason = "approved";
    }

    // Reverse renamed params and overlay injected/pinned values — this is what is actually sent
    // upstream, and what the audit row records (so the log shows the real call, not the agent's
    // pre-transform args). A malformed transform is a BAD_REQUEST, not an upstream failure.
    let finalArgs: Record<string, unknown>;
    try {
      finalArgs = applyArgTransforms(args, server.config, override, this.resolveSecret);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      rec({ server: server.id, tool: toolName, scope: verdict.scope, decision: "deny", reason: `arg transform failed: ${msg}`, error_code: SB_ERR.BAD_REQUEST });
      return this.error(`could not prepare arguments for '${exposedName}': ${msg}`, SB_ERR.BAD_REQUEST);
    }

    // The names applyArgTransforms injected a value under — these hold resolved secrets even when the
    // operator chose a benign key (`q`, `id`), which the SECRET_KEY name regex would miss. Redact them
    // by exact name in every capture below so a vault/oauth secret never lands in audit.log cleartext.
    const injectedKeys = injectedArgKeys(server.config, override);

    // Native per-call timeout (ms): the SDK throws an SdkError with RequestTimeout
    // when it elapses, which we map to a distinct SB_UPSTREAM_TIMEOUT below.
    const timeoutMs = this.cfg.settings?.call_timeout_ms;
    const callOpts = typeof timeoutMs === "number" ? { timeout: timeoutMs } : undefined;

    const capture = this.cfg.settings?.logs?.capture_io === true;

    // Write-ahead (design 3.7): a write or full scope call is recorded BEFORE the upstream is contacted. After-call
    // logging alone leaves nothing behind when the process dies or hangs in the middle of a mutating call, and lets
    // a full disk turn into mutations nobody recorded. If the row cannot be written the call is refused (fail
    // closed); the owner's approval, if one was consumed, is spent and the call must be approved again. Read scope
    // keeps after-call logging: it changes nothing, and a broken log must not take the read surface down with it.
    // The attempt row is written with audit() directly, not record(): it is not a verdict, so it is not a webhook event.
    if (verdict.scope !== "read") {
      try {
        attemptSeq = audit({
          server: server.id,
          tool: toolName,
          scope: verdict.scope,
          decision: "allow",
          reason: "attempt: written before the upstream call",
          phase: "attempt",
          ...caller.attr,
          ...(risk ? { risk } : {}),
          ...(approvalId ? { approval_id: approvalId } : {}),
          ...(capture ? { request: sanitizeForAudit(finalArgs, injectedKeys) } : {}),
        });
      } catch (err) {
        log.error(
          `audit write-ahead failed for ${server.id}/${safeText(toolName, 128)}: ${safeText(err instanceof Error ? err.message : String(err), 300)}; the ${verdict.scope} scope call is refused`,
        );
        return this.error(
          `the audit log cannot be written, so this ${verdict.scope} scope call is refused rather than run unrecorded (the reason is in the gateway log)`,
          SB_ERR.AUDIT_FAILED,
        );
      }
    }

    const start = Date.now();
    try {
      // A connector server is told who is calling (from the authenticated principal, never from an argument) and, when
      // an approval was consumed for a planned call, the digest of what was approved: it rebuilds the call and refuses
      // one that hashes to anything else (another account, another request).
      const callMeta = server.connector ? this.connectorMeta(caller, plan, approvalId) : undefined;
      const upstream = (await server.client.callTool(
        { name: toolName, arguments: finalArgs, ...(callMeta ? { _meta: callMeta } : {}) },
        callOpts,
      )) as CallToolResult;
      const raw = stripUpstreamReservedMeta(upstream);
      // The server responded — transport is healthy even if the tool returned an error *result*
      // (a logical "not found" is not an outage). Closes the breaker / clears the failure count.
      this.breaker.record(server.id, true, Date.now());
      // Redact configured top-level response fields before the agent (or the audit row) sees them.
      const result = applyResponseRedaction(raw, server.config, override);
      rec({
        server: server.id,
        tool: toolName,
        scope: verdict.scope,
        decision: "allow",
        reason,
        duration_ms: Date.now() - start,
        ...(capture ? { request: sanitizeForAudit(finalArgs, injectedKeys), response: sanitizeForAudit(result) } : {}),
        ...(result.isError ? { error: this.resultErrorText(result), error_code: SB_ERR.UPSTREAM_ERROR } : {}),
        ...this.connectorAudit(server, raw),
      });
      return this.normalizeConnectorRefusal(server, raw, result);
    } catch (err) {
      // A throw or timeout is a TRANSPORT failure — count it toward opening the breaker so a
      // wedged/dead upstream trips fast after N in a row, rather than every call hanging.
      this.breaker.record(server.id, false, Date.now());
      const timedOut = SdkError.isInstance(err) && err.code === SdkErrorCode.RequestTimeout;
      const code: SbErrorCode = timedOut ? SB_ERR.UPSTREAM_TIMEOUT : SB_ERR.UPSTREAM_ERROR;
      const msg = err instanceof Error ? err.message : String(err);
      rec({
        server: server.id,
        tool: toolName,
        scope: verdict.scope,
        decision: "allow",
        reason,
        duration_ms: Date.now() - start,
        ...(capture ? { request: sanitizeForAudit(finalArgs, injectedKeys) } : {}),
        error: msg,
        error_code: code,
      });
      const verb = timedOut ? `timed out after ${timeoutMs}ms calling` : `failed calling`;
      return this.error(`upstream '${server.id}' ${verb} '${toolName}': ${msg}`, code);
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Resources & prompts passthrough — the other two MCP content surfaces, aggregated across every
  // visible upstream so a full MCP client (Claude Desktop, Cursor) sees them through the one
  // endpoint, not just tools. Profiles + the per-server `enabled` flag gate visibility exactly as
  // for tools; read access is audited. (Subscriptions are intentionally out of scope — no
  // `subscribe` capability is advertised; an operator hides sensitive data by disabling the server.)
  // ---------------------------------------------------------------------------------------------

  /** The per-client limits to charge for this caller: its client id and the limits its profile sets right now. */
  private clientLimitsOf(gate: ClientGate | undefined): { id: string; limits?: LimitSpec } | undefined {
    return gate?.profile && gate.client ? { id: gate.client, limits: gate.profile.limits } : undefined;
  }

  /** A server is visible iff it is enabled AND not hidden by the active profile (profiles can only
   *  HIDE — never reveal a disabled server). `active` is threaded in so a sweep resolves it once. */
  private isVisible(server: MountedServer, active = getActiveProfile(this.cfg)?.profile): boolean {
    return server.config.enabled !== false && profileAllowsServer(active, server.config.id);
  }

  /** Every mounted server that is enabled and not hidden by the active profile, and, when a caller's gate is
   *  given, by that caller's client. */
  private visibleServers(gate?: ClientGate): MountedServer[] {
    const active = getActiveProfile(this.cfg)?.profile;
    return this.registry.list().filter((s) => this.isVisible(s, active) && (!gate || gateAllowsServer(gate, s.id)));
  }

  /** URI → owning serverId, rebuilt on every listResources() so readResource() routes correctly.
   *  Resources are NOT namespaced: a URI is an opaque, globally-meaningful identity the agent
   *  passes back verbatim, so we can't rewrite it the way we namespace tool/prompt names. */
  private readonly resourceOwner = new Map<string, string>();

  /** Aggregate resources across every visible, resource-capable server. Rebuilds the URI→owner
   *  map; a URI collision is first-wins + logged (we never silently shadow one resource with
   *  another). A per-server list failure is isolated — it never sinks the whole aggregation. */
  async listResources(principal?: Principal): Promise<Resource[]> {
    const gate = this.callerOf(principal).gate;
    // The owner map is the same whoever asks (it routes reads; the caller's client is checked at read time),
    // so it is always rebuilt over every visible server. Only the answer is narrowed to the caller's client.
    this.resourceOwner.clear();
    const out: Resource[] = [];
    for (const server of this.visibleServers()) {
      if (!server.client.getServerCapabilities()?.resources) continue;
      try {
        const { resources } = await server.client.listResources();
        for (const resource of resources ?? []) {
          if (this.resourceOwner.has(resource.uri)) {
            log.warn(
              `resource URI collision on '${safeText(resource.uri, 200)}': keeping '${this.resourceOwner.get(resource.uri)}', dropping the copy from '${server.id}'`,
            );
            continue;
          }
          this.resourceOwner.set(resource.uri, server.id);
          if (gate && !gateAllowsServer(gate, server.id)) continue;
          out.push(resource);
        }
      } catch (err) {
        log.warn(`listResources failed for '${server.id}': ${safeText(err instanceof Error ? err.message : String(err), 300)}`);
      }
    }
    return out;
  }

  /** Aggregate resource templates across every visible, resource-capable server. Templates are
   *  parameterized URIs (never concrete identities), so there is no owner map to maintain — a read
   *  of a template-expanded URI resolves via readResource()'s try-each fallback. */
  async listResourceTemplates(principal?: Principal): Promise<ResourceTemplateType[]> {
    const out: ResourceTemplateType[] = [];
    for (const server of this.visibleServers(this.callerOf(principal).gate)) {
      if (!server.client.getServerCapabilities()?.resources) continue;
      try {
        const { resourceTemplates } = await server.client.listResourceTemplates();
        for (const tpl of resourceTemplates ?? []) out.push(tpl);
      } catch (err) {
        log.warn(`listResourceTemplates failed for '${server.id}': ${safeText(err instanceof Error ? err.message : String(err), 300)}`);
      }
    }
    return out;
  }

  /**
   * Read a resource by URI, routing to the server that listed it. The owner is resolved from what
   * servers LIST: the exact-URI map first (rebuilt once when cold or stale), then the resource
   * templates a server declared. A URI nobody listed or declared is NOT tried against every server
   * (0.1.0 broadcast it): it is "unknown", a ProtocolError(InvalidParams). The owner then goes through the
   * same gates as a tool call, at read scope: kill switch, visibility (enabled + active profile),
   * policy, the governor and the approval gate (see governRead). resources/read is result-or-error,
   * so every refusal is a thrown ProtocolError carrying the SB_* code in `data.code`.
   */
  async readResource(uri: string, principal?: Principal): Promise<ReadResourceResult> {
    const caller = this.callerOf(principal);
    const rec = (e: AuditInput): void => this.record(e, caller);
    this.assertNotKilled("resources/read", uri, caller);
    let ownerId = this.resourceOwner.get(uri);
    if (!ownerId) {
      await this.listResources();
      ownerId = this.resourceOwner.get(uri);
    }
    ownerId ??= await this.templateOwner(uri);
    const server = ownerId ? this.registry.get(ownerId) : undefined;
    if (!server) throw new ProtocolError(ProtocolErrorCode.InvalidParams, `[switchboard] unknown resource '${uri}'`);

    await this.governRead(server, "resources/read", uri, caller);
    const start = Date.now();
    try {
      const result = stripUpstreamReservedMeta((await server.client.readResource({ uri })) as ReadResourceResult);
      rec({ server: server.id, tool: "resources/read", scope: "read", decision: "allow", reason: uri, duration_ms: Date.now() - start });
      return result;
    } catch (err) {
      rec({
        server: server.id,
        tool: "resources/read",
        scope: "read",
        decision: "allow",
        reason: uri,
        duration_ms: Date.now() - start,
        error: err instanceof Error ? err.message : String(err),
        error_code: SB_ERR.UPSTREAM_ERROR,
      });
      throw err;
    }
  }

  /** The visible server that DECLARED a resource template matching `uri`, if any (first wins). Only
   *  the declaring server is ever asked to read it. */
  private async templateOwner(uri: string): Promise<string | undefined> {
    // One work budget for the whole lookup: the templates are chosen by the upstreams, so a server
    // that declares hundreds of hostile ones must not be able to add the cost up (see uritemplate.ts).
    const budget: StepBudget = { steps: DEFAULT_STEP_BUDGET };
    for (const server of this.visibleServers()) {
      if (!server.client.getServerCapabilities()?.resources) continue;
      try {
        const { resourceTemplates } = await server.client.listResourceTemplates();
        if ((resourceTemplates ?? []).some((t) => templateMatches(t.uriTemplate, uri, budget))) return server.id;
      } catch (err) {
        log.warn(`listResourceTemplates failed for '${server.id}': ${safeText(err instanceof Error ? err.message : String(err), 300)}`);
      }
      if (budget.steps <= 0) {
        log.warn("resource template matching hit its work limit; treating the URI as unknown");
        break;
      }
    }
    return undefined;
  }

  /** Aggregate prompts across every visible, prompt-capable server, namespaced `serverId__name`.
   *  Prompts ARE namespaced (like tools) because a prompt name is a short, collision-prone label
   *  (many servers expose a "summarize"); getPrompt() strips the prefix before routing. */
  async listPrompts(principal?: Principal): Promise<Prompt[]> {
    const out: Prompt[] = [];
    for (const server of this.visibleServers(this.callerOf(principal).gate)) {
      if (!server.client.getServerCapabilities()?.prompts) continue;
      try {
        const { prompts } = await server.client.listPrompts();
        for (const prompt of prompts ?? []) {
          out.push({ ...prompt, name: `${server.config.id}${SEP}${prompt.name}` });
        }
      } catch (err) {
        log.warn(`listPrompts failed for '${server.id}': ${safeText(err instanceof Error ? err.message : String(err), 300)}`);
      }
    }
    return out;
  }

  /** Get a prompt by its exposed (namespaced) name, stripping the `serverId__` prefix before
   *  routing. A bare (un-prefixed) name is matched against the prompts each visible server LISTS and
   *  only the server that lists it is asked. Same gates as resources/read (see governRead); an
   *  unresolved name throws ProtocolError(InvalidParams), a refused one ProtocolError(InvalidRequest). */
  async getPrompt(name: string, args?: Record<string, string>, principal?: Principal): Promise<GetPromptResult> {
    const caller = this.callerOf(principal);
    this.assertNotKilled("prompts/get", name, caller);
    const idx = name.indexOf(SEP);
    if (idx !== -1) {
      const serverId = name.slice(0, idx);
      const promptName = name.slice(idx + SEP.length);
      const server = this.registry.get(serverId);
      if (server && server.client.getServerCapabilities()?.prompts) {
        await this.governRead(server, "prompts/get", promptName, caller, { name: promptName, arguments: args ?? {} });
        return this.fetchPrompt(server, promptName, args, caller);
      }
    }
    // Fallback: treat `name` as a bare prompt name and find the first visible server that lists it. Only the
    // servers the caller's client may see are asked, so it never matches (or is refused for) another client's server.
    for (const server of this.visibleServers(caller.gate)) {
      if (!server.client.getServerCapabilities()?.prompts) continue;
      let listed: string[];
      try {
        const { prompts } = await server.client.listPrompts();
        listed = (prompts ?? []).map((p) => p.name);
      } catch {
        continue; // not this server
      }
      if (!listed.includes(name)) continue;
      await this.governRead(server, "prompts/get", name, caller, { name, arguments: args ?? {} });
      return this.fetchPrompt(server, name, args, caller);
    }
    throw new ProtocolError(ProtocolErrorCode.InvalidParams, `[switchboard] unknown prompt '${name}'`);
  }

  /** The upstream half of prompts/get: call it, audit the outcome, rethrow an upstream failure. */
  private async fetchPrompt(server: MountedServer, promptName: string, args: Record<string, string> | undefined, caller: Caller): Promise<GetPromptResult> {
    const rec = (e: AuditInput): void => this.record(e, caller);
    const start = Date.now();
    try {
      const result = stripUpstreamReservedMeta((await server.client.getPrompt({
        name: promptName,
        ...(args ? { arguments: args } : {}),
      })) as GetPromptResult);
      rec({ server: server.id, tool: "prompts/get", scope: "read", decision: "allow", reason: promptName, duration_ms: Date.now() - start });
      return result;
    } catch (err) {
      rec({
        server: server.id,
        tool: "prompts/get",
        scope: "read",
        decision: "allow",
        reason: promptName,
        duration_ms: Date.now() - start,
        error: err instanceof Error ? err.message : String(err),
        error_code: SB_ERR.UPSTREAM_ERROR,
      });
      throw err;
    }
  }

  /**
   * Settle every gate a resources/read or prompts/get must pass before it reaches an upstream, in the
   * order a tool call meets them: visibility (a disabled server, or one the active profile hides),
   * policy via evaluate() at READ scope (so a per-tool `enabled: false` on "resources/read" or
   * "prompts/get" and the profile ceiling apply), the governor (the same global, server and tool
   * buckets a tool call draws from), then the approval gate. Every refusal is audited and thrown as an
   * ProtocolError(InvalidRequest) with the SB_* code in `data.code`.
   */
  private async governRead(server: MountedServer, tool: ReadSurface, detail: string, caller: Caller, bound: unknown = { detail }): Promise<void> {
    const gate = caller.gate;
    const deny = (code: SbErrorCode, why: string, message: string): never => {
      this.record({ server: server.id, tool, scope: "read", decision: "deny", reason: `${why}: ${detail}`, error_code: code }, caller);
      throw this.refusal(code, message);
    };
    const active = getActiveProfile(this.cfg)?.profile;
    if (server.config.enabled === false) {
      return deny(SB_ERR.POLICY_DENY, "server is disabled", `denied by policy: server '${server.id}' is disabled`);
    }
    if (!profileAllowsServer(active, server.id)) {
      return deny(SB_ERR.POLICY_DENY, "hidden by active profile", `denied by policy: '${server.id}' is not available in the active profile`);
    }
    // The caller's client (design 3.1): resources and prompts follow its server globs; its tool lists do not apply.
    if (gate && (gate.deny !== null || !gateAllowsServer(gate, server.id))) {
      return deny(
        SB_ERR.POLICY_DENY,
        gate.deny ?? `server hidden from ${gateLabel(gate)}`,
        gate.deny !== null ? `denied by policy: ${gate.deny}` : `denied by policy: '${server.id}' is not available to ${gateLabel(gate)}`,
      );
    }
    const verdict = evaluate(server.config, tool, this.cfg, "read", profileScopeCeiling(active), undefined, gateScopeCeiling(gate), gateRiskCeiling(gate));
    if (verdict.decision === "deny") {
      return deny(SB_ERR.POLICY_DENY, verdict.reason, `denied by policy: ${verdict.reason}`);
    }
    const gov = this.governor.consume(server.id, tool, Date.now(), this.clientLimitsOf(gate));
    if (!gov.ok) {
      const retry = gov.retryAfterMs && isFinite(gov.retryAfterMs) ? ` (retry after ~${Math.ceil(gov.retryAfterMs / 1000)}s)` : "";
      return deny(SB_ERR.RATE_LIMITED, gov.reason ?? "limit exceeded", `rate limited: ${gov.reason ?? "limit exceeded"}${retry}`);
    }
    if (verdict.decision === "approval_required") {
      const settled = await this.settleApproval(server, tool, `${tool} ${detail}`, bound, verdict, caller, () => isKilled(this.cfg));
      if (!settled.go) {
        if (settled.killed) {
          this.assertNotKilled(tool, detail, caller);
          return deny(SB_ERR.KILL_SWITCH, "kill switch is on", "kill switch is on");
        }
        if (settled.code === SB_ERR.APPROVAL_PENDING) throw this.refusal(settled.code, settled.message, settled.extra);
        return deny(settled.code, settled.auditReason, settled.message);
      }
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Kill switch (design 3.8). Checked on every tools/call, resources/read and prompts/get.
  // ---------------------------------------------------------------------------------------------

  /** If the kill switch is on, audit a deny row and return the refusal result for a tool call. */
  private refuseIfKilled(exposedName: string, caller: Caller): CallToolResult | undefined {
    if (!isKilled(this.cfg)) return undefined;
    const reason = `kill switch is on (${killStatus(this.cfg).source})`;
    // Attribution only: the target is resolved to name the server in the audit row, never called.
    const target = this.resolve(exposedName);
    this.record({
      server: target?.server.id ?? "switchboard",
      tool: target?.toolName ?? exposedName,
      scope: target ? this.scopeOf(target.server, target.toolName) : "read",
      decision: "deny",
      reason,
      error_code: SB_ERR.KILL_SWITCH,
    }, caller);
    return this.error(`${reason}: refusing '${exposedName}'`, SB_ERR.KILL_SWITCH);
  }

  /** The resources/read and prompts/get form of the kill switch: audit, then throw. */
  private assertNotKilled(tool: ReadSurface, detail: string, caller: Caller): void {
    if (!isKilled(this.cfg)) return;
    const reason = `kill switch is on (${killStatus(this.cfg).source})`;
    this.record({ server: "switchboard", tool, scope: "read", decision: "deny", reason: `${reason}: ${detail}`, error_code: SB_ERR.KILL_SWITCH }, caller);
    throw this.refusal(SB_ERR.KILL_SWITCH, `${reason}: refusing ${tool}`);
  }

  /** A governed refusal on a result-or-error surface: the code travels in the message and in `data`. */
  private refusal(code: SbErrorCode, message: string, extra?: Record<string, unknown>): ProtocolError {
    return new ProtocolError(ProtocolErrorCode.InvalidRequest, `[switchboard] ${code}: ${message}`, { code, hint: SB_HINTS[code], ...extra });
  }

  // ---------------------------------------------------------------------------------------------
  // Approvals (design 3.3). One settle step shared by tool calls, resources/read and prompts/get.
  // ---------------------------------------------------------------------------------------------

  /**
   * A gated call has reached the approval gate. Consume the approval the owner gave for exactly this call
   * (principal, server, tool, canonical arguments), or leave a pending request and say how to approve it.
   * With `gateway.approval.wait_seconds` above 0 the call first waits that long for a decision; the kill
   * switch is looked at again after any wait, because it can be thrown while nobody is watching the call.
   * A store that cannot be used refuses the call (fail closed); it never reads as "no approvals needed".
   */
  private async settleApproval(
    server: MountedServer,
    toolName: string,
    label: string,
    bound: unknown,
    verdict: { scope: Scope; risk: Risk; reason: string },
    caller: Caller,
    killed: () => boolean,
  ): Promise<Settled> {
    const conf = this.cfg.gateway.approval;
    const ttl = conf?.ttl_seconds ?? DEFAULT_TTL_SECONDS;
    const waitMs = Math.min(MAX_WAIT_SECONDS, Math.max(0, conf?.wait_seconds ?? 0)) * 1000;
    const req: ApprovalRequest = {
      principal: caller.principal ? principalLabel(caller.principal) : INTERNAL_PRINCIPAL,
      client: caller.principal?.client ?? null,
      server: server.id,
      tool: toolName,
      args: bound,
      scope: verdict.scope,
      risk: verdict.risk,
      reason: verdict.reason,
    };
    const unusable = (err: unknown): Settled => {
      if (err instanceof ApprovalLimitError) {
        return { go: false, code: SB_ERR.RATE_LIMITED, message: `rate limited: ${err.message}`, auditReason: err.message };
      }
      const msg = err instanceof Error ? err.message : String(err);
      return {
        go: false,
        code: SB_ERR.APPROVAL_DENIED,
        message: `approval required for '${label}' and the approval store cannot be used, so the call is refused: ${msg}`,
        auditReason: `approval store unusable: ${msg}`.slice(0, 500),
      };
    };

    let gate;
    try {
      gate = this.approvals.request(req, ttl);
    } catch (err) {
      return unusable(err);
    }
    // A NOTIFICATION only, once per request (a client repeating the call must not fire it again).
    if ((gate.kind === "pending" && gate.created) || (gate.kind === "approved" && gate.via === "env-auto")) {
      this.fireWebhook({ decision: "approval_required", server: server.id, tool: toolName, scope: verdict.scope, reason: verdict.reason });
    }

    if (gate.kind === "pending" && waitMs > 0) {
      let decided;
      try {
        decided = await this.approvals.waitForDecision(gate.record.id, waitMs);
      } catch (err) {
        return unusable(err);
      }
      if (killed()) return { go: false, killed: true };
      if (decided?.status === "denied" || decided?.status === "expired") {
        return {
          go: false,
          code: SB_ERR.APPROVAL_DENIED,
          message: `approval ${decided.id} for '${label}' was ${decided.status === "denied" ? "denied by the owner" : "not decided before it expired"}`,
          auditReason: `approval ${decided.id} ${decided.status}`,
        };
      }
      if (decided?.status === "approved") {
        try {
          gate = this.approvals.request(req, ttl); // consume it
        } catch (err) {
          return unusable(err);
        }
      }
    }

    if (gate.kind === "approved") return { go: true, approvalId: gate.record.id };

    const id = gate.record.id;
    const instruction = `approve in the Switchboard dashboard (Approvals) or run: switchboard approvals approve ${id}, then call the same tool again with the same arguments`;
    return {
      go: false,
      code: SB_ERR.APPROVAL_PENDING,
      message: `approval required for '${label}' (${gate.record.risk} risk). Approval ${id} is waiting for the owner and is valid until ${gate.record.expires}. To proceed: ${instruction}`,
      auditReason: `approval ${id} pending`,
      extra: { approval_id: id, expires: gate.record.expires, risk: gate.record.risk, instruction },
    };
  }

  /** The upstream's annotations for a tool, from the tool list the registry cached at mount. */
  private annotationsOf(server: MountedServer, toolName: string): Tool["annotations"] {
    return (server.tools.find((t) => t.name === toolName) ?? server.unlisted?.find((t) => t.name === toolName))?.annotations;
  }

  /** The scope a tool resolves to (override, hint, name, annotations), for audit attribution. */
  private scopeOf(server: MountedServer, toolName: string): Scope {
    return resolveToolScope(toolName, server.config.tools?.[toolName], server.scopeHints?.[toolName], this.annotationsOf(server, toolName));
  }

  /** Append an audit row without ever throwing: by the time most rows are written the upstream call has
   *  already happened, so a full disk, a locked file or a read-only home must cost the audit row (logged
   *  loudly), never the result the caller is about to receive. */
  private safeAudit(entry: AuditInput): void {
    try {
      audit(entry);
    } catch (err) {
      log.error(`audit write failed for ${entry.server}/${entry.tool} (${entry.decision}): ${safeText(err instanceof Error ? err.message : String(err), 300)}`);
    }
  }

  /** Write one finalized verdict to the audit log AND notify the webhook. Every terminal
   *  decision in forward() goes through here so a delivered event always mirrors an audited
   *  row. The webhook carries decision metadata only — `record` never forwards request/response
   *  to it, even when `capture_io` stored them on the audit row. */
  private record(entry: AuditInput, caller?: Caller): void {
    this.safeAudit(caller ? { ...entry, ...caller.attr } : entry);
    this.fireWebhook({
      decision: entry.decision,
      server: entry.server,
      tool: entry.tool,
      scope: entry.scope,
      ...(entry.reason ? { reason: entry.reason } : {}),
      ...(typeof entry.duration_ms === "number" ? { duration_ms: entry.duration_ms } : {}),
      // An upstream chooses its error text and it can echo a credential: the audit row scrubs it, so does the webhook.
      ...(entry.error ? { error: redactSecretShapes(entry.error) } : {}),
    });
  }

  /** Fire-and-forget webhook delivery — never blocks, never throws into the call path. */
  private fireWebhook(event: WebhookEvent): void {
    deliverWebhook(this.cfg, event, this.resolveSecret);
  }

  /** The request `_meta` for a call into a connector server: the caller's client and, after an approval, what was approved. */
  private connectorMeta(caller: Caller, plan: ConnectorPlanView | undefined, approvalId: string | undefined): Record<string, unknown> {
    return {
      ...(caller.principal?.client ? { [CLIENT_META_KEY]: caller.principal.client } : {}),
      ...(plan && approvalId ? { [APPROVED_META_KEY]: { digest: plan.digest, approval_id: approvalId } } : {}),
    };
  }

  /**
   * A refusal the connector pipeline makes itself (an account a client may not use, a digest that no longer matches
   * the approval, the kill switch) reaches the agent in the gateway's own refusal shape, the one the router gives for
   * the same reason before the call: `{ error, code, hint }`. Every other connector result keeps the toolkit's shape.
   * The audit row was already written from the connector's own `_meta`.
   */
  private normalizeConnectorRefusal(server: MountedServer, raw: CallToolResult, result: CallToolResult): CallToolResult {
    if (server.config.source !== "connector" || raw.isError !== true) return result;
    const meta = (raw._meta as Record<string, unknown> | undefined)?.[AUDIT_META_KEY] as Record<string, unknown> | undefined;
    const code = meta && typeof meta.error_code === "string" ? meta.error_code : undefined;
    if (code !== SB_ERR.POLICY_DENY && code !== SB_ERR.APPROVAL_DENIED && code !== SB_ERR.KILL_SWITCH) return result;
    let message = "";
    try {
      const body = JSON.parse(this.resultErrorText(raw)) as { error?: { message?: unknown } };
      if (typeof body.error?.message === "string") message = body.error.message;
    } catch {
      /* not the toolkit's shape: leave the result as it is */
    }
    if (!message) return result;
    return this.error(code === SB_ERR.POLICY_DENY ? `denied by policy: ${message}` : message, code);
  }

  /** A connector refusal before the call as a governed result: a policy denial in the gateway's own form, any other code with its fix. */
  private connectorRefusal(err: ConnectorError, exposedName: string): CallToolResult {
    if (err.code === SB_ERR.POLICY_DENY) return this.error(`denied by policy: ${err.message}`, SB_ERR.POLICY_DENY);
    const text = JSON.stringify({
      error: `[switchboard] could not prepare '${exposedName}': ${err.message}`,
      code: err.code,
      ...(err.detail.hint ? { hint: err.detail.hint } : {}),
      ...(err.detail.reconnect ? { reconnect: err.detail.reconnect } : {}),
    });
    return { isError: true, content: [{ type: "text", text }] };
  }

  /**
   * The connector fields of an audit row (ADR local-composio 6.4): toolkit, its version, the account id, the
   * client, the risk. They come from the connector server's own result `_meta`, and ONLY from a server whose
   * source is `connector`: any other upstream could otherwise write whatever it liked into the audit log.
   * Every value is checked against a strict shape; a call the connector refused before sending is a `deny`.
   */
  private connectorAudit(server: MountedServer, result: CallToolResult): Partial<AuditInput> {
    if (server.config.source !== "connector") return {};
    const m = (result._meta as Record<string, unknown> | undefined)?.[AUDIT_META_KEY];
    if (!m || typeof m !== "object") return {};
    const a = m as Record<string, unknown>;
    const str = (v: unknown, re: RegExp, max: number): string | undefined => (typeof v === "string" && v.length <= max && re.test(v) ? v : undefined);
    const out: Partial<AuditInput> = {};
    const toolkit = str(a.toolkit, /^[a-z][a-z0-9-]*$/, 40);
    const version = str(a.toolkit_version, /^[A-Za-z0-9_.-]+$/, 24);
    const account = str(a.account, /^ca_[A-Za-z0-9]+$/, 40);
    const client = str(a.client, /^[A-Za-z0-9][A-Za-z0-9._-]*$/, 48);
    const runId = str(a.run_id, /^[A-Za-z0-9_-]+$/, 64);
    const code = str(a.error_code, /^SB_[A-Z_]+$/, 48);
    if (toolkit) out.toolkit = toolkit;
    if (version) out.toolkit_version = version;
    if (account) out.account = account;
    if (client) out.client = client;
    if (runId) out.run_id = runId;
    if (a.risk === "low" || a.risk === "medium" || a.risk === "high") out.risk = a.risk;
    if (typeof a.outward === "boolean") out.outward = a.outward;
    if (code && result.isError) out.error_code = code;
    if (a.decision === "deny" && result.isError) out.decision = "deny";
    return out;
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

  /** Build an error result. When a `SB_*` code is supplied, the text is structured JSON carrying
   *  the message, the stable code, and a one-line actionable hint — so an agent gets a fixable
   *  failure instead of an opaque string. Without a code it stays plain text (back-compat). */
  private error(message: string, code?: SbErrorCode, extra?: Record<string, unknown>): CallToolResult {
    const text =
      code === undefined
        ? `[switchboard] ${message}`
        : JSON.stringify({ error: `[switchboard] ${message}`, code, hint: SB_HINTS[code], ...extra });
    return { isError: true, content: [{ type: "text", text }] };
  }
}
