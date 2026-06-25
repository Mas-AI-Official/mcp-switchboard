/**
 * Switchboard error taxonomy.
 *
 * Every governed failure carries a stable `SB_*` code plus a one-line, actionable hint — so an
 * agent (or a human reading the Logs page) gets a fixable message instead of an opaque stack.
 * This mirrors Composio's namespaced-code + possible-fixes idea, deliberately kept minimal and
 * dependency-free. Codes are also written to the audit row (`error_code`) for after-the-fact triage.
 */

export const SB_ERR = {
  /** No exposed tool by that name (disabled, never mounted, or a typo). */
  UNKNOWN_TOOL: "SB_UNKNOWN_TOOL",
  /** The call's scope exceeds the server/tool policy ceiling. */
  POLICY_DENY: "SB_POLICY_DENY",
  /** A human declined the approval gate (or it was not approved in time). */
  APPROVAL_DENIED: "SB_APPROVAL_DENIED",
  /** The upstream MCP server returned an error. */
  UPSTREAM_ERROR: "SB_UPSTREAM_ERROR",
  /** The upstream call exceeded `settings.call_timeout_ms`. */
  UPSTREAM_TIMEOUT: "SB_UPSTREAM_TIMEOUT",
  /** The server's circuit breaker is open after repeated failures — failing fast instead of hanging. */
  UPSTREAM_UNAVAILABLE: "SB_UPSTREAM_UNAVAILABLE",
  /** The request itself was malformed (bad/missing arguments). */
  BAD_REQUEST: "SB_BAD_REQUEST",
  /** The call hit a configured rate limit or spend budget (global/server/tool). Fails closed. */
  RATE_LIMITED: "SB_RATE_LIMITED",
} as const;

export type SbErrorCode = (typeof SB_ERR)[keyof typeof SB_ERR];

/** One actionable next step per code. Surfaced alongside the error so failures are self-explaining. */
export const SB_HINTS: Record<SbErrorCode, string> = {
  [SB_ERR.UNKNOWN_TOOL]:
    "No tool by that name is exposed. Call find_tools (or list tools) to see current names — the server may be disabled or the tool dropped.",
  [SB_ERR.POLICY_DENY]:
    "This tool's scope exceeds the server policy ceiling. Raise the server `policy` (read < write < full) or pin the tool's `policy` in config — least privilege is the default.",
  [SB_ERR.APPROVAL_DENIED]:
    "A human declined (or did not approve in time) the approval gate. Re-issue the call and approve it in the dashboard, or relax `approval.require_for`.",
  [SB_ERR.UPSTREAM_ERROR]:
    "The upstream MCP server returned an error. Check that server's credentials and the Logs page for the underlying message.",
  [SB_ERR.UPSTREAM_TIMEOUT]:
    "The upstream call exceeded settings.call_timeout_ms. Raise the timeout, or check whether the upstream server is reachable and responsive.",
  [SB_ERR.UPSTREAM_UNAVAILABLE]:
    "This server's circuit breaker is open after repeated transport failures — Switchboard is failing fast instead of hanging on a dead upstream. Wait for the retry window, then it auto-probes; check the upstream server's health and credentials in the meantime. Tune via settings.resilience / server.resilience.",
  [SB_ERR.BAD_REQUEST]:
    "The request was malformed. Check the tool's input schema and that all required arguments are present.",
  [SB_ERR.RATE_LIMITED]:
    "This call hit a configured rate limit or spend budget (settings.limits / server.limits / tool.limits). Wait for the window to refill, raise the limit, or lower the tool's `cost`. Limits fail closed to cap runaway loops and API spend.",
};
