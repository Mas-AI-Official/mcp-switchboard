/**
 * MCP Switchboard error taxonomy.
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
  /** The call needs an out-of-band approval that has not been given yet. Approve it, then repeat the identical call. */
  APPROVAL_PENDING: "SB_APPROVAL_PENDING",
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
  /** The kill switch is on: every tool call, resource read and prompt get is refused until it is cleared. */
  KILL_SWITCH: "SB_KILL_SWITCH",
  /** The audit log cannot be written, so a write or full scope call is refused rather than run unrecorded. */
  AUDIT_FAILED: "SB_AUDIT_FAILED",
} as const;

export type SbErrorCode = (typeof SB_ERR)[keyof typeof SB_ERR];

/** One actionable next step per code. Surfaced alongside the error so failures are self-explaining. */
export const SB_HINTS: Record<SbErrorCode, string> = {
  [SB_ERR.UNKNOWN_TOOL]:
    "No tool by that name is exposed. Call find_tools (or list tools) to see current names — the server may be disabled or the tool dropped.",
  [SB_ERR.POLICY_DENY]:
    "This tool's scope exceeds a ceiling (the server `policy`, the active profile, or the calling client's `max_scope`), its risk is above the calling client's `max_risk`, or it is hidden from the calling client. Raise the server `policy` (read < write < full), pin the tool's `policy`, or change the client's servers, tools, max_scope and max_risk (`switchboard client list`) in config. Least privilege is the default.",
  [SB_ERR.APPROVAL_DENIED]:
    "The approval was declined, it expired before it was used, or the approval store could not be used. Make the call again to create a new approval request, or relax `approval.require_for` / `gateway.approval.require_for_risk` in config.",
  [SB_ERR.APPROVAL_PENDING]:
    "This call needs the owner's approval, bound to these exact arguments. The owner approves it in the Switchboard dashboard (Approvals) or with `switchboard approvals approve <id>` on the machine that runs the gateway; then repeat the same call with the same arguments. An approval works once and expires.",
  [SB_ERR.UPSTREAM_ERROR]:
    "The upstream MCP server returned an error. Check that server's credentials and the Logs page for the underlying message.",
  [SB_ERR.UPSTREAM_TIMEOUT]:
    "The upstream call exceeded settings.call_timeout_ms. Raise the timeout, or check whether the upstream server is reachable and responsive.",
  [SB_ERR.UPSTREAM_UNAVAILABLE]:
    "This server's circuit breaker is open after repeated transport failures — MCP Switchboard is failing fast instead of hanging on a dead upstream. Wait for the retry window, then it auto-probes; check the upstream server's health and credentials in the meantime. Tune via settings.resilience / server.resilience.",
  [SB_ERR.BAD_REQUEST]:
    "The request was malformed. Check the tool's input schema and that all required arguments are present.",
  [SB_ERR.RATE_LIMITED]:
    "This call hit a configured rate limit or spend budget (settings.limits / server.limits / tool.limits). Wait for the window to refill, raise the limit, or lower the tool's `cost`. Limits fail closed to cap runaway loops and API spend.",
  [SB_ERR.KILL_SWITCH]:
    "The operator turned the kill switch on (the SWITCHBOARD_HOME/KILL file or gateway.kill_switch). Every tool call, resource read and prompt get is refused until it is cleared: run `switchboard kill off` and make sure gateway.kill_switch is not true. The file takes effect on the next call; the config flag is read at startup.",
  [SB_ERR.AUDIT_FAILED]:
    "A write or full scope call is recorded in the audit log BEFORE it runs, and the log could not be written (disk full, read-only home, a locked or damaged audit.log), so the call was refused instead of running unrecorded. Fix the audit log (see the gateway's stderr for the reason) and repeat the call. Read scope calls are not affected.",
};
