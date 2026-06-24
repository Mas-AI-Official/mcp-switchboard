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

export function evaluate(server: ServerConfig, toolName: string, cfg: SwitchboardConfig): PolicyDecision {
  const override = server.tools?.[toolName];

  if (override?.enabled === false) {
    return { decision: "deny", scope: "read", reason: `tool '${toolName}' is disabled in config` };
  }

  const scope: Scope = override?.policy ?? inferScope(toolName);
  const ceiling: Scope = server.policy ?? cfg.gateway.default_policy;

  if (SCOPE_RANK[scope] > SCOPE_RANK[ceiling]) {
    return {
      decision: "deny",
      scope,
      reason: `'${toolName}' needs '${scope}' but server '${server.id}' is capped at '${ceiling}'`,
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
