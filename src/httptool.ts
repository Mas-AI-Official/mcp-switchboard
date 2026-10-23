/**
 * http-tool — hand-declared HTTP endpoints → a generated MCP server.
 *
 * The lighter sibling of `app2mcp` (openapi.ts): instead of parsing a whole OpenAPI spec, the
 * operator lists a handful of endpoints in `http_tools`, and each becomes one governed MCP tool.
 * Tool calls execute through the SSRF guard (`guardedFetch`, src/netguard.ts), **zero deps**: private,
 * loopback and metadata targets are refused unless the exact host is in `settings.network.allow_private`,
 * redirects are re-validated hop by hop and never carry the injected credentials to another origin, and
 * the call has a deadline and a response-size cap.
 *
 * The invocation contract is deliberately simple and predictable for a hand-written tool:
 *   - `{name}` segments in the `path` are filled from same-named args (URL-encoded) and consumed.
 *   - any args NOT consumed by the path become the JSON body for body verbs (POST/PUT/PATCH/DELETE)
 *     or query-string params for query verbs (GET/HEAD/OPTIONS).
 * Scope follows the project rule (GET/HEAD→read, DELETE→full, else write); a per-tool `scope` may
 * only TIGHTEN that classification (raise toward `full`), never relax a dangerous verb to `read`.
 * The generated server does NOT enforce scope — the gateway's Router/Policy engine governs every
 * call first — but it surfaces a per-tool `scopeHints` map so the policy engine classifies by verb.
 *
 * Auth is injected per call via `resolveHeaders()` (so OAuth tokens refresh) and fails closed: a
 * missing/expired credential returns an error result rather than silently sending an unauthed call.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import type { HttpToolDef, Scope, ServerConfig } from "./types.js";
import { guardedFetch, type NetworkSource } from "./netguard.js";
import { dotSegmentProblem, pathParamProblem, rawPathOf } from "./pathparam.js";

const MAX_RESPONSE_CHARS = 50_000;
const BODY_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const SCOPE_RANK: Record<Scope, number> = { read: 0, write: 1, full: 2 };

export interface HttpToolServer {
  server: Server;
  scopeHints: Record<string, Scope>;
  toolCount: number;
}

/** GET/HEAD/OPTIONS → read, DELETE → full, everything else → write. */
function scopeForMethod(method: string): Scope {
  const m = method.toUpperCase();
  if (m === "GET" || m === "HEAD" || m === "OPTIONS") return "read";
  if (m === "DELETE") return "full";
  return "write";
}

/** A per-tool scope may only raise the verb-derived classification (toward `full`), never lower it. */
function tightenScope(verb: Scope, override?: Scope): Scope {
  if (!override) return verb;
  return SCOPE_RANK[override] >= SCOPE_RANK[verb] ? override : verb;
}

/** One resolved plan for a declared endpoint. */
interface HttpToolPlan {
  method: string;
  /** Absolute `url` wins; otherwise `base + path`. Validated at build time so we never call relative. */
  base: string; // absolute base URL with no trailing slash, or "" when `path` already carries an absolute url
  path: string; // path template with `{name}` segments, or "" when using an absolute url base
  absolute?: string; // an absolute per-tool url, used as-is (after `{name}` substitution)
  scope: Scope;
}

/**
 * Replace `{name}` segments from same-named args; returns the filled string, the consumed keys and, when a value
 * would move the request out of the declared path (`.` or `..`, which a URL parser reads as navigation), the reason.
 */
function fillPath(template: string, args: Record<string, unknown>): { filled: string; consumed: Set<string>; refused?: string } {
  const consumed = new Set<string>();
  let refused: string | undefined;
  const filled = template.replace(/\{([^}]+)\}/g, (whole, name: string) => {
    if (Object.prototype.hasOwnProperty.call(args, name) && args[name] !== undefined && args[name] !== null) {
      consumed.add(name);
      const text = String(args[name]);
      const bad = pathParamProblem(text);
      if (bad && refused === undefined) refused = `path parameter '${name}': ${bad}`;
      return encodeURIComponent(text);
    }
    return whole; // leave an unfilled placeholder visible rather than silently dropping it
  });
  // Two values can form a dot segment only together (`{a}{b}`), and a template can carry one: check the whole path too.
  if (refused === undefined) {
    const dot = dotSegmentProblem(rawPathOf(filled));
    if (dot) refused = `path parameter substitution: ${dot}`;
  }
  return { filled, consumed, refused };
}

/** Execute one declared endpoint as an HTTP request and shape the MCP result. */
async function invoke(
  plan: HttpToolPlan,
  args: Record<string, unknown>,
  authHeaders: Record<string, string>,
  network: NetworkSource,
): Promise<CallToolResult> {
  const template = plan.absolute ?? plan.base + plan.path;
  const { filled, consumed, refused } = fillPath(template, args);
  if (refused) return { content: [{ type: "text", text: `refusing request: ${refused}` }], isError: true };

  const url = new URL(filled);
  const headers: Record<string, string> = { accept: "application/json", ...authHeaders };
  const rest: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(args)) {
    if (!consumed.has(k) && v !== undefined) rest[k] = v;
  }

  let body: string | undefined;
  if (BODY_METHODS.has(plan.method)) {
    if (Object.keys(rest).length) {
      body = JSON.stringify(rest);
      headers["content-type"] = "application/json";
    }
  } else {
    // query verbs: remaining args become query-string params.
    for (const [k, v] of Object.entries(rest)) {
      if (Array.isArray(v)) for (const item of v) url.searchParams.append(k, String(item));
      else url.searchParams.append(k, String(v));
    }
  }

  let resp: Awaited<ReturnType<typeof guardedFetch>>;
  try {
    resp = await guardedFetch(url, { method: plan.method, headers, body, credentialHeaders: Object.keys(authHeaders) }, network);
  } catch (err) {
    return {
      content: [{ type: "text", text: `request to ${plan.method} ${url.pathname} failed: ${(err as Error).message}` }],
      isError: true,
    };
  }

  const text = await resp.text();
  const shown =
    text.length > MAX_RESPONSE_CHARS
      ? `${text.slice(0, MAX_RESPONSE_CHARS)}\n…[truncated ${text.length - MAX_RESPONSE_CHARS} chars]`
      : text;
  return {
    content: [{ type: "text", text: `HTTP ${resp.status} ${resp.statusText}\n\n${shown}` }],
    isError: resp.status >= 400,
  };
}

/**
 * Build an in-process MCP `Server` from a config's `http_tools`. The registry links it to a real
 * SDK `Client` over an in-memory transport, so the rest of the gateway treats it like any mounted
 * server. Validates every endpoint up front (fail closed) — a relative path with no `base_url`, a
 * missing method, or a duplicate name throws rather than mounting a half-broken server.
 *
 * @param resolveHeaders called per tool-call to produce auth headers — async so OAuth tokens refresh.
 * @param network the live `settings.network` (or a thunk returning it) for the SSRF guard.
 */
export async function buildHttpToolServer(
  config: ServerConfig,
  resolveHeaders: () => Promise<Record<string, string>>,
  network?: NetworkSource,
): Promise<HttpToolServer> {
  const defs: HttpToolDef[] = config.http_tools ?? [];
  if (!defs.length) {
    throw new Error(`server '${config.id}': source 'http-tool' requires a non-empty 'http_tools' list`);
  }

  const base = config.base_url ? config.base_url.replace(/\/$/, "") : "";
  const tools: Tool[] = [];
  const plans = new Map<string, HttpToolPlan>();
  const scopeHints: Record<string, Scope> = {};

  for (const def of defs) {
    if (!def.name) throw new Error(`server '${config.id}': an http_tool is missing 'name'`);
    if (plans.has(def.name)) throw new Error(`server '${config.id}': duplicate http_tool name '${def.name}'`);
    if (!def.method) throw new Error(`server '${config.id}': http_tool '${def.name}' is missing 'method'`);

    const hasAbsolute = typeof def.url === "string" && /^https?:\/\//i.test(def.url);
    if (!hasAbsolute) {
      if (!def.path) {
        throw new Error(`server '${config.id}': http_tool '${def.name}' needs an absolute 'url' or a 'path'`);
      }
      if (!base) {
        throw new Error(`server '${config.id}': http_tool '${def.name}' has a relative 'path' but no 'base_url' is set`);
      }
    }

    const method = def.method.toUpperCase();
    const scope = tightenScope(scopeForMethod(method), def.scope);
    const plan: HttpToolPlan = {
      method,
      base,
      path: hasAbsolute ? "" : (def.path ?? ""),
      absolute: hasAbsolute ? def.url : undefined,
      scope,
    };
    plans.set(def.name, plan);
    scopeHints[def.name] = scope;

    const inputSchema =
      def.inputSchema && typeof def.inputSchema === "object"
        ? (def.inputSchema as Tool["inputSchema"])
        : ({ type: "object" } as Tool["inputSchema"]);
    tools.push({
      name: def.name,
      description: def.description ?? `${method} ${plan.absolute ?? plan.path}`,
      inputSchema,
    });
  }

  const server = new Server(
    { name: `switchboard-httptool:${config.id}`, version: "0.1.0" },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
  server.setRequestHandler(CallToolRequestSchema, async (request): Promise<CallToolResult> => {
    const plan = plans.get(request.params.name);
    if (!plan) {
      return { content: [{ type: "text", text: `unknown tool '${request.params.name}'` }], isError: true };
    }
    const args = (request.params.arguments ?? {}) as Record<string, unknown>;
    let authHeaders: Record<string, string>;
    try {
      authHeaders = await resolveHeaders();
    } catch (err) {
      // Fail closed: a missing/expired credential must not silently send an unauthenticated call.
      return { content: [{ type: "text", text: `credential error: ${(err as Error).message}` }], isError: true };
    }
    return invoke(plan, args, authHeaders, network);
  });

  return { server, scopeHints, toolCount: tools.length };
}
