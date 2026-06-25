/**
 * Policy engine — the governance layer.
 *
 * Every tool call is classified into a scope (read < write < full) and checked against:
 *   1. per-tool `enabled: false`  -> hard deny
 *   2. the server's scope ceiling -> deny if the tool needs more than the server allows
 *   3. approval gates             -> require a human confirm for the configured scopes
 *
 * Scope is inferred from the tool name by verb heuristic, overridable per tool. The
 * inference is deliberately conservative: anything that isn't clearly a read and isn't
 * clearly destructive is treated as `write`.
 */

import type { Scope, ServerConfig, SwitchboardConfig } from "./types.js";

const SCOPE_RANK: Record<Scope, number> = { read: 0, write: 1, full: 2 };

/** Names that clearly only read. */
const READ_RE = /^(get|list|read|search|fetch|find|query|describe|show|view|count|head|lookup|browse|inspect)[_A-Z]?/i;
/** Names that are destructive / privileged -> demand the top scope. */
const FULL_RE = /(delete|destroy|drop|remove|purge|wipe|revoke|terminate|deactivate|admin|grant|sudo)/i;

/** Infer the scope a tool needs from its name. Overridable via config. */
export function inferScope(toolName: string): Scope {
  if (FULL_RE.test(toolName)) return "full";
  if (READ_RE.test(toolName)) return "read";
  return "write";
}

export interface PolicyDecision {
  decision: "allow" | "deny" | "approval_required";
  scope: Scope;
  reason: string;
}

export function evaluate(
  server: ServerConfig,
  toolName: string,
  cfg: SwitchboardConfig,
  scopeHint?: Scope,
  profileCeiling?: Scope,
): PolicyDecision {
  const override = server.tools?.[toolName];

  if (override?.enabled === false) {
    return { decision: "deny", scope: "read", reason: `tool '${toolName}' is disabled in config` };
  }

  // Precedence: explicit per-tool override > generator-supplied verb→scope hint (app2mcp) >
  // name-based inference. The hint lets OpenAPI HTTP verbs drive scope when the tool name alone
  // (e.g. `findPetsByStatus`) would otherwise be misread.
  const scope: Scope = override?.policy ?? scopeHint ?? inferScope(toolName);
  // The effective ceiling is the TIGHTEST of the server/gateway cap and the active profile's cap.
  // A profile can only ever LOWER the ceiling (read < write < full), never raise it — so a
  // `read` profile forces read-only even on a server configured for `full`.
  const serverCeiling: Scope = server.policy ?? cfg.gateway.default_policy;
  const ceiling: Scope =
    profileCeiling !== undefined && SCOPE_RANK[profileCeiling] < SCOPE_RANK[serverCeiling]
      ? profileCeiling
      : serverCeiling;

  if (SCOPE_RANK[scope] > SCOPE_RANK[ceiling]) {
    const cappedBy = ceiling === profileCeiling && ceiling !== serverCeiling ? "active profile" : `server '${server.id}'`;
    return {
      decision: "deny",
      scope,
      reason: `'${toolName}' needs '${scope}' but ${cappedBy} is capped at '${ceiling}'`,
    };
  }

  const requireFor = server.approval?.require_for ?? [];
  if (requireFor.includes(scope)) {
    return {
      decision: "approval_required",
      scope,
      reason: `approval gate: '${scope}' calls on '${server.id}' require confirmation`,
    };
  }

  return { decision: "allow", scope, reason: "ok" };
}
