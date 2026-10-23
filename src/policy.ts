/**
 * Policy engine — the governance layer.
 *
 * Every tool call is classified into a scope (read < write < full) and checked against:
 *   1. per-tool `enabled: false`  -> hard deny
 *   2. the server's scope ceiling -> deny if the tool needs more than the server allows
 *   3. approval gates             -> require a human confirm for the configured scopes
 *
 * Scope is inferred from the tool name (design vNext 3.5), overridable per tool. The classifier is
 * token based, not a prefix match: a name is `read` only when its FIRST token is a read verb and NO
 * token is a write or exec verb, so `browser_run_code`, `fetch_and_execute` and `count_and_send_email`
 * are never mistaken for reads. Anything with a destructive token is `full`; everything else is `write`.
 * Upstream annotations can only TIGHTEN the result (`destructiveHint: true` raises to `full`); a
 * `readOnlyHint` is a claim by the upstream and never lowers a scope.
 *
 * Scope is the CEILING check. A second axis, risk (design 3.4), decides APPROVAL: read is low, write is
 * medium, full is high by default; a tool's own `risk`, the server's `risk_defaults` and `outward: true`
 * (which raises write and full to high) refine it. Calls whose risk is listed in
 * `gateway.approval.require_for_risk` (default high) need an out-of-band approval, OR-ed with the server's
 * `approval.require_for` scopes. A client's `max_risk` is a ceiling like `max_scope`: above it, the call is refused.
 */

import type { Risk, Scope, ServerConfig, SwitchboardConfig, ToolOverride } from "./types.js";

const SCOPE_RANK: Record<Scope, number> = { read: 0, write: 1, full: 2 };

export const RISK_RANK: Record<Risk, number> = { low: 0, medium: 1, high: 2 };

/** Risk of a call by scope when nothing says otherwise (design 3.4). */
export const DEFAULT_RISK_BY_SCOPE: Readonly<Record<Scope, Risk>> = { read: "low", write: "medium", full: "high" };

/** Risks that need an approval when `gateway.approval.require_for_risk` is not set. */
export const DEFAULT_REQUIRE_FOR_RISK: readonly Risk[] = ["high"];

/**
 * The risk of a call at `scope` on `server` (design 3.4). Precedence: the tool's own `risk` (the operator's
 * explicit word, in both directions) > the server's `risk_defaults` for that scope > the built-in default.
 * `outward: true` then raises write and full to high; it never lowers anything and never touches read.
 */
export function resolveRisk(server: Pick<ServerConfig, "risk_defaults" | "outward">, scope: Scope, override?: Pick<ToolOverride, "risk">): Risk {
  if (override?.risk) return override.risk;
  let risk: Risk = server.risk_defaults?.[scope] ?? DEFAULT_RISK_BY_SCOPE[scope];
  if (server.outward === true && scope !== "read" && RISK_RANK[risk] < RISK_RANK.high) risk = "high";
  return risk;
}

/**
 * Tool annotations as an upstream reports them (MCP `Tool.annotations`). Structural on purpose, so a
 * hostile or sloppy upstream can send anything: only an explicit boolean `true` is ever honoured.
 */
export type ToolAnnotationsLike = { readonly [key: string]: unknown } | null | undefined;

/** First-token verbs that mark a tool as a pure read. */
const READ_VERBS: ReadonlySet<string> = new Set([
  "get", "list", "read", "search", "fetch", "find", "query", "describe", "show", "view", "count", "head", "lookup", "browse", "inspect",
]);

/** Any token in this set removes a name from `read`, wherever it sits (design 3.5). */
const WRITE_EXEC_VERBS: ReadonlySet<string> = new Set([
  "run", "exec", "execute", "eval", "evaluate", "click", "type", "press", "upload", "send", "post", "publish", "create", "update",
  "set", "write", "put", "patch", "mutate", "apply", "deploy", "push", "replace", "generate", "clone", "design", "remix", "convert",
  "transfer", "pay", "buy", "order", "submit", "schedule", "invite", "share", "import", "install", "start", "stop", "restart", "kill",
  "and", "then",
]);

/**
 * Destructive or privileged verbs (the 0.1.0 list), matched as whole tokens with their common
 * inflections. Whole-token matching means `dropdown`, `dropbox` and `swipe` are no longer full.
 */
const DESTRUCTIVE_TOKEN =
  /^(?:delet(?:e|es|ed|ing|ion)|destroy(?:s|ed|ing)?|drop(?:s|ped|ping)?|remov(?:e|es|ed|ing|al)|purg(?:e|es|ed|ing)|wip(?:e|es|ed|ing)|revok(?:e|es|ed|ing)|terminat(?:e|es|ed|ing|ion)|deactivat(?:e|es|ed|ing|ion)|admin(?:s|istrators?|istration)?|grant(?:s|ed|ing)?|sudo)$/;

/**
 * Names glued together without a separator (`deletefile`, `removeall`) have no token boundary to
 * match. The 0.1.0 substring rule caught them, so keep it for the stems that have no benign
 * collision. `drop`, `wipe`, `grant` and `admin` are excluded here: they collide with `dropdown`,
 * `swipe`, `migrant` and `badminton`.
 */
const GLUED_DESTRUCTIVE = /delete|destroy|purge|revoke|terminate|deactivate|remove/;

/**
 * Split a tool name into lowercase tokens on every non letter/digit (`_ - . /` and friends) and on
 * camelCase boundaries (`getUserProfile` -> get, user, profile; `getHTTPResponse` -> get, http, response).
 */
export function tokenizeToolName(name: string): string[] {
  return name
    .replace(/(\p{Ll}|\p{N})(\p{Lu})/gu, "$1 $2")
    .replace(/(\p{Lu}+)(\p{Lu}\p{Ll})/gu, "$1 $2")
    .split(/[^\p{L}\p{N}]+/u)
    .filter(Boolean)
    .map((t) => t.toLowerCase());
}

/** Name-only classification (no annotations): `full` > `read` > `write`, per design 3.5. */
function classifyName(toolName: string): Scope {
  const tokens = tokenizeToolName(toolName);
  if (tokens.some((t) => DESTRUCTIVE_TOKEN.test(t) || GLUED_DESTRUCTIVE.test(t))) return "full";
  if (tokens.length > 0 && READ_VERBS.has(tokens[0]!) && !tokens.some((t) => WRITE_EXEC_VERBS.has(t))) return "read";
  return "write";
}

/**
 * Apply upstream annotations to a scope. They may only tighten: an explicit `destructiveHint: true`
 * raises the scope to `full`. `readOnlyHint` is deliberately ignored, because an upstream (or a
 * compromised one) must not be able to talk its own `delete_*` down to a read.
 */
export function tightenWithAnnotations(scope: Scope, annotations: ToolAnnotationsLike): Scope {
  if (annotations && typeof annotations === "object" && annotations.destructiveHint === true) return "full";
  return scope;
}

/** Infer the scope a tool needs from its name, tightened by its annotations. Overridable via config. */
export function inferScope(toolName: string, annotations?: ToolAnnotationsLike): Scope {
  return tightenWithAnnotations(classifyName(toolName), annotations);
}

/**
 * The scope a tool call runs at. Precedence: explicit per-tool `policy` override (the operator always
 * wins, in both directions) > generator-supplied verb hint (app2mcp / http-tool) > name inference;
 * annotations then tighten whatever the hint or the name produced. Shared by `evaluate`, the dashboard
 * and `switchboard list` so what is displayed is what is enforced.
 */
export function resolveToolScope(
  toolName: string,
  override?: ToolOverride,
  scopeHint?: Scope,
  annotations?: ToolAnnotationsLike,
): Scope {
  if (override?.policy) return override.policy;
  return tightenWithAnnotations(scopeHint ?? classifyName(toolName), annotations);
}

export interface PolicyDecision {
  decision: "allow" | "deny" | "approval_required";
  scope: Scope;
  /** Risk of the call (design 3.4); it decides approval, scope decides the ceiling. */
  risk: Risk;
  reason: string;
}

/** A caller's client and the scope ceiling its profile sets (design 3.1); an extra cap beside the server and the profile. */
export interface ClientCeiling {
  scope: Scope;
  client: string;
}

/** A caller's client and the highest risk it may request (`max_risk`, design 3.4). */
export interface ClientRiskCeiling {
  risk: Risk;
  client: string;
}

export function evaluate(
  server: ServerConfig,
  toolName: string,
  cfg: SwitchboardConfig,
  scopeHint?: Scope,
  profileCeiling?: Scope,
  annotations?: ToolAnnotationsLike,
  clientCeiling?: ClientCeiling,
  clientRiskCeiling?: ClientRiskCeiling,
): PolicyDecision {
  const override = server.tools?.[toolName];

  if (override?.enabled === false) {
    return { decision: "deny", scope: "read", risk: "low", reason: `tool '${toolName}' is disabled in config` };
  }

  // Precedence: explicit per-tool override > generator-supplied verb→scope hint (app2mcp) >
  // name-based inference, then upstream annotations tighten (never loosen) the result. The hint lets
  // OpenAPI HTTP verbs drive scope when the tool name alone (e.g. `findPetsByStatus`) would be misread.
  const scope: Scope = resolveToolScope(toolName, override, scopeHint, annotations);
  const risk: Risk = resolveRisk(server, scope, override);
  // The effective ceiling is the TIGHTEST of the server/gateway cap, the active profile's cap and the
  // calling client's cap. A profile or a client can only ever LOWER the ceiling (read < write < full),
  // never raise it, so a `read` profile forces read-only even on a server configured for `full`.
  const serverCeiling: Scope = server.policy ?? cfg.gateway.default_policy;
  let ceiling: Scope = serverCeiling;
  let cappedBy = `server '${server.id}'`;
  if (profileCeiling !== undefined && SCOPE_RANK[profileCeiling] < SCOPE_RANK[ceiling]) {
    ceiling = profileCeiling;
    cappedBy = "active profile";
  }
  if (clientCeiling !== undefined && SCOPE_RANK[clientCeiling.scope] < SCOPE_RANK[ceiling]) {
    ceiling = clientCeiling.scope;
    cappedBy = `client '${clientCeiling.client}'`;
  }

  if (SCOPE_RANK[scope] > SCOPE_RANK[ceiling]) {
    return {
      decision: "deny",
      scope,
      risk,
      reason: `'${toolName}' needs '${scope}' but ${cappedBy} is capped at '${ceiling}'`,
    };
  }

  // The client's risk ceiling (design 3.4): refused before any approval exists, so a client that may not ask for
  // a high-risk call can never put one in front of the owner.
  if (clientRiskCeiling !== undefined && RISK_RANK[risk] > RISK_RANK[clientRiskCeiling.risk]) {
    return {
      decision: "deny",
      scope,
      risk,
      reason: `'${toolName}' is '${risk}' risk but client '${clientRiskCeiling.client}' may request at most '${clientRiskCeiling.risk}' (max_risk)`,
    };
  }

  // Two independent triggers, OR-ed (design 3.4): the server's scopes and the gateway's risks.
  const requireFor = server.approval?.require_for ?? [];
  const requireForRisk = cfg.gateway.approval?.require_for_risk ?? DEFAULT_REQUIRE_FOR_RISK;
  const byScope = requireFor.includes(scope);
  const byRisk = requireForRisk.includes(risk);
  if (byScope || byRisk) {
    return {
      decision: "approval_required",
      scope,
      risk,
      reason: byScope
        ? `approval gate: '${scope}' calls on '${server.id}' require confirmation${byRisk ? ` (and '${risk}' risk calls do)` : ""}`
        : `approval gate: '${risk}' risk calls require confirmation (gateway.approval.require_for_risk)`,
    };
  }

  return { decision: "allow", scope, risk, reason: "ok" };
}
