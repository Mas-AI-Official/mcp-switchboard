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

import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import type { Registry, MountedServer } from "./registry.js";
import type { SwitchboardConfig } from "./types.js";
import { evaluate } from "./policy.js";
import {
  getActiveProfile,
  profileAllowsServer,
  profileAllowsTool,
  profileScopeCeiling,
} from "./profiles.js";
import { approve } from "./approval.js";
import { audit, sanitizeForAudit, type AuditEntry } from "./audit.js";
import { deliverWebhook, type SecretResolver, type WebhookEvent } from "./webhook.js";
import {
  shapeExposedTool,
  applyArgTransforms,
  applyResponseRedaction,
  removedRequiredNotInjected,
  injectedArgKeys,
} from "./transforms.js";
import { SB_ERR, SB_HINTS, type SbErrorCode } from "./errors.js";
import { rankBm25, type RankDoc } from "./search-index.js";
import { Governor } from "./governor.js";
import { Breaker } from "./breaker.js";
import { log } from "./logger.js";

const SEP = "__";

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
/** The four MCP annotation hints that can be used as `find_tools` tag filters. */
const ANNOTATION_TAGS = ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"] as const;

interface ExposedTool {
  /** Name as the downstream client sees it. */
  exposedName: string;
  server: MountedServer;
  tool: Tool;
}

export class Router {
  /** Rate-limit + spend-budget enforcement, built once from the immutable config for this Router. */
  private readonly governor: Governor;
  /** Per-server circuit breaker — fails fast on a wedged/dead upstream instead of hanging. */
  private readonly breaker: Breaker;

  constructor(
    private readonly registry: Registry,
    private readonly cfg: SwitchboardConfig,
    private readonly resolveSecret: SecretResolver,
  ) {
    this.governor = new Governor(cfg);
    this.breaker = new Breaker(cfg);
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

  private exposed(): ExposedTool[] {
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
      for (const tool of server.tools) {
        const override = server.config.tools?.[tool.name];
        // A tool explicitly disabled in config is never exposed at all.
        if (override?.enabled === false) continue;

        const exposedName = flat ? tool.name : `${server.config.id}${SEP}${tool.name}`;
        // A profile's tool allow/deny list hides individual tools by their EXPOSED name.
        if (!profileAllowsTool(active, exposedName)) continue;
        if (claimed.has(exposedName)) {
          log.warn(`tool name collision on '${exposedName}' — dropping the copy from '${server.id}'`);
          continue;
        }
        claimed.add(exposedName);

        // If shaping removes a required param without injecting a value, agents can't satisfy
        // the upstream call — warn once so the misconfiguration is visible (the tool is still
        // exposed; the upstream remains the source of truth for what it will accept).
        const orphaned = removedRequiredNotInjected(tool, server.config, override);
        if (orphaned.length) {
          this.warnOnce(
            `${exposedName}:${orphaned.join(",")}`,
            `tool '${exposedName}' hides/drops required param(s) [${orphaned.join(", ")}] with no inject_args value — calls may fail upstream`,
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
  ): Tool[] {
    const lcQuery = query.trim().toLowerCase();

    let pool = this.exposed();
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
      return {
        id: exposedName,
        boost: override?.important ? IMPORTANT_BOOST : 1,
        exact: exposedName.toLowerCase() === lcQuery,
        fields: [
          { key: "name", text: exposedName, weight: SEARCH_FIELDS.name.weight, b: SEARCH_FIELDS.name.b },
          { key: "tags", text: (override?.tags ?? []).join(" "), weight: SEARCH_FIELDS.tags.weight, b: SEARCH_FIELDS.tags.b },
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
      if (exposedName === BATCH_CALL) return this.handleBatch(args);
      // Direct call by namespaced name still works as a convenience.
    }
    return this.forward(exposedName, args);
  }

  /** `find_tools` meta-tool — discovery only, never touches an upstream. */
  private handleFind(args: Record<string, unknown>): CallToolResult {
    const query = typeof args.query === "string" ? args.query : "";
    if (!query.trim()) return this.error("find_tools requires a non-empty 'query'", SB_ERR.BAD_REQUEST);
    const rawLimit = typeof args.limit === "number" ? args.limit : DEFAULT_SEARCH_LIMIT;
    const limit = Math.max(1, Math.min(MAX_SEARCH_LIMIT, Math.floor(rawLimit)));
    const serverFilter = this.stringSet(args.servers);
    const tagFilter = this.stringSet(args.tags);

    const matches = this.search(query, limit, serverFilter, tagFilter).map((t) => ({
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
    if (!name) return Promise.resolve(this.error("call_tool requires a 'name'", SB_ERR.BAD_REQUEST));
    const inner =
      args.arguments && typeof args.arguments === "object"
        ? (args.arguments as Record<string, unknown>)
        : {};
    return this.forward(name, inner);
  }

  /** `batch_call` meta-tool — run several governed calls in one request. Each entry goes through
   *  the SAME forward() path (policy → approval → audit), so a batch is just a convenience over N
   *  call_tool invocations: one failing call never aborts the rest. */
  private async handleBatch(args: Record<string, unknown>): Promise<CallToolResult> {
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
        const res = await this.forward(name, inner);
        return { name, isError: res.isError === true, content: res.content };
      }),
    );
    return { content: [{ type: "text", text: JSON.stringify({ results }, null, 2) }] };
  }

  /** Govern, then forward, a real tool call to its upstream server. */
  private async forward(exposedName: string, args: Record<string, unknown>): Promise<CallToolResult> {
    const target = this.resolve(exposedName);
    if (!target) return this.error(`unknown tool '${exposedName}'`, SB_ERR.UNKNOWN_TOOL);

    const { server, toolName } = target;
    const override = server.config.tools?.[toolName];
    const active = getActiveProfile(this.cfg)?.profile;
    const verdict = evaluate(server.config, toolName, this.cfg, server.scopeHints?.[toolName], profileScopeCeiling(active));

    // Defense in depth: a tool hidden by the active profile must also be UNCALLABLE, not merely
    // absent from the listing. resolve() works off raw upstream names, so a client that names a
    // hidden tool directly would otherwise bypass the view. Deny it with the same audit trail.
    const exposedForProfile = this.mode === "flat" ? toolName : `${server.config.id}${SEP}${toolName}`;
    if (!profileAllowsServer(active, server.config.id) || !profileAllowsTool(active, exposedForProfile)) {
      this.record({ server: server.id, tool: toolName, scope: verdict.scope, decision: "deny", reason: "hidden by active profile", error_code: SB_ERR.POLICY_DENY });
      return this.error(`denied by policy: '${exposedName}' is not available in the active profile`, SB_ERR.POLICY_DENY);
    }

    if (verdict.decision === "deny") {
      this.record({ server: server.id, tool: toolName, scope: verdict.scope, decision: "deny", reason: verdict.reason, error_code: SB_ERR.POLICY_DENY });
      return this.error(`denied by policy: ${verdict.reason}`, SB_ERR.POLICY_DENY);
    }

    // Rate limits + spend budgets — charged BEFORE the approval gate so a throttled call never wakes
    // a human, and conservatively (a denied call still counts) so a runaway loop is capped, not billed
    // precisely. Fails closed: any exceeded ceiling (global/server/tool) stops the call here.
    const gov = this.governor.consume(server.id, toolName, Date.now());
    if (!gov.ok) {
      this.record({ server: server.id, tool: toolName, scope: verdict.scope, decision: "deny", reason: gov.reason, error_code: SB_ERR.RATE_LIMITED });
      const retry = gov.retryAfterMs && isFinite(gov.retryAfterMs) ? ` (retry after ~${Math.ceil(gov.retryAfterMs / 1000)}s)` : "";
      return this.error(`rate limited: ${gov.reason}${retry}`, SB_ERR.RATE_LIMITED);
    }

    // Circuit breaker — an AVAILABILITY check after the security controls (policy/scope/limits) and
    // before the approval gate, so a call to a known-dead upstream fails fast instead of paying the
    // full call timeout AND never wakes a human for a server that can't answer. Opt-in via
    // settings.resilience / server.resilience; inert (constant-true) when unconfigured.
    const health = this.breaker.allow(server.id, Date.now());
    if (!health.ok) {
      this.record({ server: server.id, tool: toolName, scope: verdict.scope, decision: "deny", reason: health.reason, error_code: SB_ERR.UPSTREAM_UNAVAILABLE });
      const retry = health.retryAfterMs && isFinite(health.retryAfterMs) ? ` (retry after ~${Math.ceil(health.retryAfterMs / 1000)}s)` : "";
      return this.error(`upstream '${server.id}' is unavailable (circuit open)${retry}: ${health.reason}`, SB_ERR.UPSTREAM_UNAVAILABLE);
    }

    // Settle the approval gate before executing. A denied approval is the only path that
    // audits without an execution; everything allowed audits ONCE after the call so the row
    // can carry timing and (opt-in) request/response.
    let reason = verdict.reason;
    if (verdict.decision === "approval_required") {
      // Notify the webhook that a call is waiting for a human decision. This is a NOTIFICATION
      // only — it writes NO audit row, so it can never double-count against usage totals; the
      // audit log records the eventual allow/deny once the gate is settled below.
      this.fireWebhook({ decision: "approval_required", server: server.id, tool: toolName, scope: verdict.scope, reason: verdict.reason });
      const allowed = await approve(server.id, toolName, verdict.scope, verdict.reason);
      if (!allowed) {
        this.record({ server: server.id, tool: toolName, scope: verdict.scope, decision: "deny", reason: "approval denied/unavailable", error_code: SB_ERR.APPROVAL_DENIED });
        return this.error(`approval required and not granted for '${exposedName}'`, SB_ERR.APPROVAL_DENIED);
      }
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
      this.record({ server: server.id, tool: toolName, scope: verdict.scope, decision: "deny", reason: `arg transform failed: ${msg}`, error_code: SB_ERR.BAD_REQUEST });
      return this.error(`could not prepare arguments for '${exposedName}': ${msg}`, SB_ERR.BAD_REQUEST);
    }

    // The names applyArgTransforms injected a value under — these hold resolved secrets even when the
    // operator chose a benign key (`q`, `id`), which the SECRET_KEY name regex would miss. Redact them
    // by exact name in every capture below so a vault/oauth secret never lands in audit.log cleartext.
    const injectedKeys = injectedArgKeys(server.config, override);

    // Native per-call timeout (ms) — the SDK throws an McpError with ErrorCode.RequestTimeout
    // when it elapses, which we map to a distinct SB_UPSTREAM_TIMEOUT below.
    const timeoutMs = this.cfg.settings?.call_timeout_ms;
    const callOpts = typeof timeoutMs === "number" ? { timeout: timeoutMs } : undefined;

    const capture = this.cfg.settings?.logs?.capture_io === true;
    const start = Date.now();
    try {
      const raw = (await server.client.callTool({ name: toolName, arguments: finalArgs }, undefined, callOpts)) as CallToolResult;
      // The server responded — transport is healthy even if the tool returned an error *result*
      // (a logical "not found" is not an outage). Closes the breaker / clears the failure count.
      this.breaker.record(server.id, true, Date.now());
      // Redact configured top-level response fields before the agent (or the audit row) sees them.
      const result = applyResponseRedaction(raw, server.config, override);
      this.record({
        server: server.id,
        tool: toolName,
        scope: verdict.scope,
        decision: "allow",
        reason,
        duration_ms: Date.now() - start,
        ...(capture ? { request: sanitizeForAudit(finalArgs, injectedKeys), response: sanitizeForAudit(result) } : {}),
        ...(result.isError ? { error: this.resultErrorText(result), error_code: SB_ERR.UPSTREAM_ERROR } : {}),
      });
      return result;
    } catch (err) {
      // A throw or timeout is a TRANSPORT failure — count it toward opening the breaker so a
      // wedged/dead upstream trips fast after N in a row, rather than every call hanging.
      this.breaker.record(server.id, false, Date.now());
      const timedOut = err instanceof McpError && err.code === ErrorCode.RequestTimeout;
      const code: SbErrorCode = timedOut ? SB_ERR.UPSTREAM_TIMEOUT : SB_ERR.UPSTREAM_ERROR;
      const msg = err instanceof Error ? err.message : String(err);
      this.record({
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

  /** Write one finalized verdict to the audit log AND notify the webhook. Every terminal
   *  decision in forward() goes through here so a delivered event always mirrors an audited
   *  row. The webhook carries decision metadata only — `record` never forwards request/response
   *  to it, even when `capture_io` stored them on the audit row. */
  private record(entry: Omit<AuditEntry, "ts">): void {
    audit(entry);
    this.fireWebhook({
      decision: entry.decision,
      server: entry.server,
      tool: entry.tool,
      scope: entry.scope,
      ...(entry.reason ? { reason: entry.reason } : {}),
      ...(typeof entry.duration_ms === "number" ? { duration_ms: entry.duration_ms } : {}),
      ...(entry.error ? { error: entry.error } : {}),
    });
  }

  /** Fire-and-forget webhook delivery — never blocks, never throws into the call path. */
  private fireWebhook(event: WebhookEvent): void {
    deliverWebhook(this.cfg, event, this.resolveSecret);
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
  private error(message: string, code?: SbErrorCode): CallToolResult {
    const text =
      code === undefined
        ? `[switchboard] ${message}`
        : JSON.stringify({ error: `[switchboard] ${message}`, code, hint: SB_HINTS[code] });
    return { isError: true, content: [{ type: "text", text }] };
  }
}
