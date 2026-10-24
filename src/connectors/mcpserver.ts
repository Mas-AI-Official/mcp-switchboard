/**
 * One in-process MCP server per toolkit (ADR local-composio, sections 6.1 and 6.7).
 *
 * `source: connector` in the config names a toolkit (and optionally an account). The registry builds the
 * server here and links it to a client over an in-memory transport, exactly like `app2mcp` and `http-tool`,
 * so on/off, scope ceilings, per-tool overrides, profiles, limits, the breaker, audit and approvals all
 * apply with no new concept. The server id is the toolkit's on/off switch.
 *
 * Exposure:
 *   - `tools/list` is the toolkit's `important` set, capped so the whole list (with the two meta tools)
 *     never passes MAX_LISTED_TOOLS = 30. The rest of the actions are returned as `unlisted`: the router
 *     searches them with `find_tools` and calls them with `call_tool`, but never lists them. GitHub's
 *     1,242 operations or X's 239 are never listed raw.
 *   - `manage_connections` (read, low): which accounts this toolkit's provider has, their status, expiry,
 *     last probe and which one this client uses. It never returns a credential.
 *   - `proxy_request` (full, high, approval ALWAYS): a raw call with the account's credential injected,
 *     host locked to the provider. It exists for the rare endpoint no action covers.
 *
 * Fail closed: a toolkit cannot be mounted until its provider has an ACTIVE account that passed its identity
 * probe (and, when the server config names an account, that account). The mount error says how to connect.
 *
 * Caller identity: this server never trusts an argument for it. The router puts the authenticated principal's
 * client id in the MCP request `_meta` (`io.mcpswitchboard/client`); a request with no such field is the owner's
 * own unscoped path (a CLI run, the playground), and a field that is present but malformed is REFUSED, never read
 * as "no client". The client's access, ceilings and account come from the gateway's `clients:` config (access.ts):
 * there is no separate link table. The same `_meta` filters `tools/list`.
 *
 * Approval: the router decides every approval, out of band, and binds it to the digest `plan()` returns (the
 * resolved account and the built request). It passes that digest back in `_meta["io.mcpswitchboard/approved"]`;
 * the call is then rebuilt here and refused if it hashes to something else (exec.ts).
 *
 * What goes back to the router besides the result: `_meta["io.mcpswitchboard/audit"]`, the toolkit, its
 * version, the account id, the client, the risk, so the router's single audit row carries them (the router
 * only honours this field from a `connector` server).
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import type { Scope, ServerConfig } from "../types.js";
import { CONNECTOR_ERR, ConnectorError } from "./errors.js";
import type { ConnectorKit } from "./kit.js";
import type { Action } from "./toolkits.js";
import { withinCaps } from "./access.js";
import type { CallBinding, ExecResult } from "./exec.js";
import { isValidClientId } from "../principal.js";

export const CLIENT_META_KEY = "io.mcpswitchboard/client";
/** Set by the router only: the digest of the call the owner approved (and the approval's id for the audit row). */
export const APPROVED_META_KEY = "io.mcpswitchboard/approved";
export const AUDIT_META_KEY = "io.mcpswitchboard/audit";
export const TOOL_META_KEY = "io.mcpswitchboard/connector";
export const MAX_LISTED_TOOLS = 30;
const META_TOOLS = 2;
export const MAX_IMPORTANT = MAX_LISTED_TOOLS - META_TOOLS;
const DESCRIPTION_MAX = 500;

/** What the router needs to know about one action to classify a call by what it is, not by what it is named. */
export interface ActionHint {
  risk: "low" | "medium" | "high";
  /** Visible to others (a post, a send, a publish): raises write and full to high risk. */
  outward: boolean;
  /** `always`: the action needs a human decision whatever the gateway's approval settings say (proxy_request). */
  approval?: "always";
}

/** A planned call as the router sees it: what to bind an approval to. */
export interface ConnectorPlanView {
  /** sha256 over the canonical JSON of `binding`. */
  digest: string;
  /** The resolved account and the request in one line each, shown to the owner first. */
  account: string;
  request: string;
  binding: CallBinding;
}

/** The router's handle on a connector server: per-action facts and the pre-approval plan. */
export interface ConnectorHooks {
  hints: Record<string, ActionHint>;
  /**
   * Resolve a call without sending anything: the account (client binding, server pin, `account` argument rules) and the
   * built request. Throws a ConnectorError for a refusal (SB_POLICY_DENY, SB_ACCOUNT_NOT_FOUND, SB_BAD_REQUEST, ...).
   * `undefined`: nothing to bind (an action that calls no provider).
   */
  plan(tool: string, args: Record<string, unknown>, client: string | undefined): Promise<ConnectorPlanView | undefined>;
}

export interface ConnectorServerBuild {
  server: Server;
  /** Scope hint for every tool, listed or not, so the router classifies by the action and not by its name. */
  scopeHints: Record<string, Scope>;
  /** Risk, outward and approval facts for every action, listed or not, and the pre-approval plan. */
  hooks: ConnectorHooks;
  /** Tools reachable through find_tools / call_tool but absent from tools/list. */
  unlisted: Tool[];
  toolCount: number;
  listedCount: number;
}

const ACCOUNT_PROP = {
  type: "string",
  description: "Connected account to use: a ca_... id, provider/label, or a label. Omit for this client's bound account, else the provider default. A client may name only its own account unless its accounts entry is \"*\", and a server pinned to an account cannot be overridden.",
};

function toolFor(action: Action, toolkit: string, version: string, important: boolean): Tool {
  const schema = JSON.parse(JSON.stringify(action.input_schema)) as { type?: string; properties?: Record<string, unknown>; [k: string]: unknown };
  schema.type = "object";
  schema.properties = { ...(schema.properties ?? {}) };
  if (!("account" in schema.properties)) schema.properties.account = ACCOUNT_PROP;
  const desc = action.description.startsWith(action.title) ? action.description : `${action.title}: ${action.description}`;
  return {
    name: action.slug,
    description: `${action.deprecated ? "[deprecated] " : ""}${desc}`.slice(0, DESCRIPTION_MAX),
    inputSchema: schema as Tool["inputSchema"],
    annotations: {
      title: action.title,
      readOnlyHint: action.scope === "read",
      destructiveHint: action.scope === "full",
      idempotentHint: action.idempotent,
      openWorldHint: true,
    },
    _meta: {
      [TOOL_META_KEY]: { toolkit, version, scope: action.scope, risk: action.risk, outward: action.outward, important, tags: action.tags, verification: action.verification },
    },
  };
}

function manageAction(): Action {
  return {
    slug: "manage_connections",
    title: "Manage connections",
    description: "Show which accounts are connected for this toolkit's provider: status, identity, scopes, expiry, last probe, and which one this client uses. Read only; never returns a credential.",
    input_schema: { type: "object", properties: {} },
    scopes: [],
    scope: "read",
    risk: "low",
    outward: false,
    idempotent: true,
    important: true,
    tags: ["accounts", "status", "connect"],
    deprecated: false,
    verification: "mapped",
  };
}

function proxyAction(toolkit: string): Action {
  return {
    slug: "proxy_request",
    title: "Proxy request",
    description: `A raw HTTP call to ${toolkit}'s API with the connected account's credential injected, for an endpoint no action covers. Host locked to the provider. Needs a human decision on every call.`,
    input_schema: {
      type: "object",
      properties: {
        method: { type: "string", enum: ["GET", "POST", "PUT", "PATCH", "DELETE"], description: "HTTP method" },
        path: { type: "string", description: "Path relative to the toolkit's API base, for example /v1/me. Give this or url." },
        url: { type: "string", description: "Absolute URL; its host must be one of the provider's API hosts. Give this or path." },
        query: { type: "object", additionalProperties: true, description: "Query parameters" },
        headers: { type: "object", additionalProperties: { type: "string" }, description: "Extra headers (the credential header cannot be replaced)" },
        body: { description: "Request body: an object is sent as JSON, a string as text" },
      },
      required: ["method"],
    },
    scopes: [],
    scope: "full",
    risk: "high",
    outward: false,
    idempotent: false,
    important: true,
    tags: ["raw", "http", "request"],
    deprecated: false,
    approval: "always",
    proxy: true,
    verification: "mapped",
  };
}

/**
 * The caller named by the router in the request `_meta`. Absent: the owner's unscoped path. Present but not a valid
 * client id: `bad`, which the handlers REFUSE; reading it as "no client" would hand an unscoped call to whoever got a
 * malformed value through (a client id has the same shape everywhere: principal.ts).
 */
function callerOf(meta: unknown): { client?: string; bad?: true } {
  const m = meta && typeof meta === "object" ? (meta as Record<string, unknown>) : undefined;
  if (!m || !(CLIENT_META_KEY in m)) return {};
  const v = m[CLIENT_META_KEY];
  return isValidClientId(v) ? { client: v } : { bad: true };
}

function boundOf(meta: unknown): { digest: string; approval_id?: string } | undefined {
  const v = meta && typeof meta === "object" ? (meta as Record<string, unknown>)[APPROVED_META_KEY] : undefined;
  if (!v || typeof v !== "object") return undefined;
  const o = v as Record<string, unknown>;
  if (typeof o.digest !== "string" || !/^[0-9a-f]{64}$/.test(o.digest)) return undefined;
  return { digest: o.digest, ...(typeof o.approval_id === "string" && /^ap_[A-Za-z0-9]{1,16}$/.test(o.approval_id) ? { approval_id: o.approval_id } : {}) };
}

const BAD_CALLER = (): CallToolResult =>
  textResult({ successful: false, error: { code: CONNECTOR_ERR.POLICY_DENY, message: "the caller's client id is not a valid client id, so the call is refused rather than run as the owner's own" } }, true);

function textResult(payload: unknown, isError: boolean, audit?: unknown): CallToolResult {
  return {
    content: [{ type: "text", text: JSON.stringify(payload) }],
    ...(isError ? { isError: true } : {}),
    ...(audit ? { _meta: { [AUDIT_META_KEY]: audit } } : {}),
  };
}

function fromExec(r: ExecResult): CallToolResult {
  const audit = { ...r.audit, decision: r.decision };
  if (r.ok) return textResult({ successful: true, data: r.data ?? null, ...(r.files ? { files: r.files } : {}), run_id: r.run_id }, false, audit);
  return textResult({ successful: false, error: r.error, run_id: r.run_id }, true, audit);
}

export async function buildConnectorServer(kit: ConnectorKit, config: ServerConfig): Promise<ConnectorServerBuild> {
  const slug = config.toolkit;
  if (!slug) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `server '${config.id}': source 'connector' requires a 'toolkit'`);
  const tk = kit.toolkits.load(slug);
  if (!tk) throw new ConnectorError(CONNECTOR_ERR.TOOLKIT_NOT_FOUND, `server '${config.id}': toolkit '${slug}' has no definition here`, { hint: `run \`switchboard toolkits sync ${slug}\`` });
  const provider = kit.connectors.providers.providerForToolkit(slug) ?? kit.connectors.providers.get(tk.provider);
  if (!provider) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `server '${config.id}': no provider definition backs toolkit '${slug}'`);

  // Fail closed: at least one ACTIVE account that passed its identity probe.
  const accounts = kit.connectors.accounts;
  const candidates = config.account ? [accounts.find(config.account.includes("/") || config.account.startsWith("ca_") ? config.account : `${provider.slug}/${config.account}`)].filter((a): a is NonNullable<typeof a> => Boolean(a && a.provider === provider.slug)) : accounts.list({ provider: provider.slug });
  const usable = candidates.some((a) => a.status === "ACTIVE" && (provider.identity_probe ? Boolean(a.last_probe_at) && !a.last_error : true));
  if (!usable) {
    const connect = `switchboard connect ${provider.slug}`;
    throw new ConnectorError(
      CONNECTOR_ERR.ACCOUNT_NOT_ACTIVE,
      `toolkit '${slug}' is not enabled: ${config.account ? `account '${config.account}'` : `${provider.name}`} has no ACTIVE account that passed its identity probe. Connect one: ${connect}`,
      { provider: provider.slug, reconnect: connect },
    );
  }

  const all = tk.actions;
  const importantFirst = all.filter((a) => a.important && !a.deprecated);
  const picked = importantFirst.length ? importantFirst : all.filter((a) => a.scope === "read" && !a.deprecated);
  const listedActions = picked.slice(0, MAX_IMPORTANT);
  const listedSet = new Set(listedActions.map((a) => a.slug));
  const manage = manageAction();
  const proxy = proxyAction(slug);

  const tools = new Map<string, Tool>();
  for (const a of all) tools.set(a.slug, toolFor(a, slug, tk.version, listedSet.has(a.slug)));
  const metaTools = [toolFor(manage, slug, tk.version, true), toolFor(proxy, slug, tk.version, true)];
  const listed: Tool[] = [...listedActions.map((a) => tools.get(a.slug)!), ...metaTools];
  const unlisted: Tool[] = all.filter((a) => !listedSet.has(a.slug)).map((a) => tools.get(a.slug)!);
  const scopeHints: Record<string, Scope> = {};
  for (const a of all) scopeHints[a.slug] = a.scope;
  scopeHints[manage.slug] = manage.scope;
  scopeHints[proxy.slug] = proxy.scope;
  const byAction = new Map<string, Action>([...all.map((a) => [a.slug, a] as const), [manage.slug, manage], [proxy.slug, proxy]]);

  const server = new Server({ name: `switchboard-connector:${config.id}`, version: "0.1.0" }, { capabilities: { tools: {} } });

  server.setRequestHandler(ListToolsRequestSchema, async (request) => {
    const caller = callerOf(request.params?._meta);
    if (caller.bad) return { tools: [] };
    const access = kit.access.check(caller.client, config.id);
    if (!access.allowed) return { tools: [] };
    return {
      tools: listed.filter((t) => {
        const a = byAction.get(t.name);
        return a ? withinCaps(access.profile, a.scope, a.risk).ok : true;
      }),
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request): Promise<CallToolResult> => {
    const name = request.params.name;
    const args = (request.params.arguments ?? {}) as Record<string, unknown>;
    const caller = callerOf(request.params._meta);
    if (caller.bad) return BAD_CALLER();
    const client = caller.client;
    const bound = boundOf(request.params._meta);
    const base = { toolkit: slug, server: config.id, ...(client ? { client } : {}), ...(config.account ? { serverAccount: config.account } : {}), ...(bound ? { bound } : {}) };
    if (name === manage.slug) {
      const access = kit.access.check(client, config.id);
      if (!access.allowed) return textResult({ successful: false, error: { code: CONNECTOR_ERR.CLIENT_NOT_LINKED, message: access.reason } }, true);
      return textResult({ successful: true, data: kit.connectionStatus(slug, client), run_id: "status" }, false, { toolkit: slug, toolkit_version: tk.version, ...(client ? { client } : {}), risk: "low", outward: false, run_id: "status" });
    }
    if (name === proxy.slug) return fromExec(await kit.exec.run({ ...base, action: proxy.slug, args, synthetic: proxy }));
    if (!byAction.has(name)) {
      return textResult({ successful: false, error: { code: CONNECTOR_ERR.ACTION_NOT_FOUND, message: `toolkit '${slug}' has no action '${name}'` } }, true);
    }
    return fromExec(await kit.exec.run({ ...base, action: name, args }));
  });

  const hints: Record<string, ActionHint> = {};
  for (const a of byAction.values()) hints[a.slug] = { risk: a.risk, outward: a.outward, ...(a.approval === "always" ? { approval: "always" as const } : {}) };
  const hooks: ConnectorHooks = {
    hints,
    async plan(tool, args, client) {
      const planInput = { toolkit: slug, server: config.id, args, ...(client ? { client } : {}), ...(config.account ? { serverAccount: config.account } : {}) };
      let planned;
      if (tool === manage.slug) return undefined;
      if (tool === proxy.slug) planned = await kit.exec.plan({ ...planInput, action: proxy.slug, synthetic: proxy });
      else if (byAction.has(tool)) planned = await kit.exec.plan({ ...planInput, action: tool });
      else return undefined;
      return { digest: planned.digest, account: planned.summary.account, request: planned.summary.request, binding: planned.binding };
    },
  };

  return { server, scopeHints, hooks, unlisted, toolCount: all.length + META_TOOLS, listedCount: listed.length };
}
