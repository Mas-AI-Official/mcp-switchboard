/**
 * Connector error taxonomy (ADR local-composio, section 6.3 and 6.4).
 *
 * These codes sit beside the gateway's `SB_ERR` set (errors.ts) rather than inside it: the connector
 * layer lands first and the router wiring that surfaces them as tool results comes with the execution
 * pipeline (phase P2), so keeping them here avoids touching the shared file twice. Every code is a
 * stable `SB_*` string with a one-line fix, exactly like the gateway's codes.
 */

export const CONNECTOR_ERR = {
  /** The provider refused the refresh token (`invalid_grant`) or the token expired with no way to renew it. */
  ACCOUNT_EXPIRED: "SB_ACCOUNT_EXPIRED",
  /** The account was disabled by the owner; its tokens are kept but unusable until `accounts enable`. */
  ACCOUNT_DISABLED: "SB_ACCOUNT_DISABLED",
  /** The account was revoked; its tokens were deleted. */
  ACCOUNT_REVOKED: "SB_ACCOUNT_REVOKED",
  /** No such account, or none connected for the provider. */
  ACCOUNT_NOT_FOUND: "SB_ACCOUNT_NOT_FOUND",
  /** The account exists but is not usable yet (a flow that never completed). */
  ACCOUNT_NOT_ACTIVE: "SB_ACCOUNT_NOT_ACTIVE",
  /** A request tried to send a provider token to a host outside the provider's `api_hosts`. */
  HOST_NOT_ALLOWED: "SB_HOST_NOT_ALLOWED",
  /** The provider answered a token, probe or revoke call with an error. */
  PROVIDER_ERROR: "SB_PROVIDER_ERROR",
  /** A connect flow could not finish (bad state, expired pending flow, refused redirect, probe failed). */
  CONNECT_FAILED: "SB_CONNECT_FAILED",
  /** The connector configuration is unusable (unknown provider, missing auth config, bad definition). */
  CONNECTOR_CONFIG: "SB_CONNECTOR_CONFIG",

  // ── execution (phase P2) ──────────────────────────────────────────────────────────────────────────
  /** No such toolkit, or it has not been synced and has no recipes. */
  TOOLKIT_NOT_FOUND: "SB_TOOLKIT_NOT_FOUND",
  /** The toolkit exists but has no such action. */
  ACTION_NOT_FOUND: "SB_ACTION_NOT_FOUND",
  /** The calling client is not linked to this toolkit. */
  CLIENT_NOT_LINKED: "SB_CLIENT_NOT_LINKED",
  /** The call needs more scope or risk than the client's link allows. */
  POLICY_DENY: "SB_POLICY_DENY",
  /** The arguments do not match the action's input schema. */
  BAD_REQUEST: "SB_BAD_REQUEST",
  /** A human decision was required and not given. */
  APPROVAL_DENIED: "SB_APPROVAL_DENIED",
  /** The kill switch is on. */
  KILL_SWITCH: "SB_KILL_SWITCH",
  /** An upload was refused: outside the allowlist, a sensitive path, a symlink escape, not a file. */
  FILE_REFUSED: "SB_FILE_REFUSED",
  /** A file or response is over its size cap. */
  FILE_TOO_LARGE: "SB_FILE_TOO_LARGE",
  /** Media staging is not configured, so a platform that must fetch the file cannot be served. */
  MEDIA_NOT_CONFIGURED: "SB_MEDIA_NOT_CONFIGURED",
  /** The request left and the connection failed before an answer: it may or may not have taken effect. Never retried. */
  OUTCOME_UNKNOWN: "SB_OUTCOME_UNKNOWN",
  /** The provider could not be reached before the request was sent (refused, DNS), so nothing happened. */
  PROVIDER_UNREACHABLE: "SB_PROVIDER_UNREACHABLE",
  PROVIDER_BAD_REQUEST: "SB_PROVIDER_BAD_REQUEST",
  PROVIDER_UNAUTHORIZED: "SB_PROVIDER_UNAUTHORIZED",
  PROVIDER_FORBIDDEN: "SB_PROVIDER_FORBIDDEN",
  PROVIDER_NOT_FOUND: "SB_PROVIDER_NOT_FOUND",
  PROVIDER_CONFLICT: "SB_PROVIDER_CONFLICT",
  /** HTTP 429. The account is paused until the provider's Retry-After passes. */
  PROVIDER_RATE_LIMITED: "SB_PROVIDER_RATE_LIMITED",
  PROVIDER_UNAVAILABLE: "SB_PROVIDER_UNAVAILABLE",
  /** Any other provider failure. */
  PROVIDER_FAILED: "SB_PROVIDER_FAILED",
  /** A recipe stopped: an assert failed, a poll timed out, a step was refused, a limit was hit. */
  RECIPE_FAILED: "SB_RECIPE_FAILED",
} as const;

export type ConnectorErrorCode = (typeof CONNECTOR_ERR)[keyof typeof CONNECTOR_ERR];

export interface ConnectorErrorDetail {
  /** The exact command that fixes the problem, when there is one (printed verbatim to the operator). */
  reconnect?: string;
  provider?: string;
  account?: string;
  /** One actionable sentence. */
  hint?: string;
  /** The connect needs a registered OAuth app first; the CLI prints the provider's owner setup steps. */
  needsApp?: boolean;
}

/** A governed connector failure: a stable code, an operator-readable message, and the fix command. */
export class ConnectorError extends Error {
  readonly code: ConnectorErrorCode;
  readonly detail: ConnectorErrorDetail;
  constructor(code: ConnectorErrorCode, message: string, detail: ConnectorErrorDetail = {}) {
    super(message);
    this.name = "ConnectorError";
    this.code = code;
    this.detail = detail;
  }

  /** The shape the router will return to an agent once connectors are wired into tools/call (P2). */
  toToolResult(): { isError: true; content: { type: "text"; text: string }[]; structuredContent: Record<string, unknown> } {
    return {
      isError: true,
      content: [{ type: "text", text: `${this.code}: ${this.message}` }],
      structuredContent: { code: this.code, ...this.detail },
    };
  }
}

export function isConnectorError(err: unknown): err is ConnectorError {
  return err instanceof ConnectorError;
}

/** The command that reconnects an account, with the label quoted only when it needs it. */
export function reconnectCommand(provider: string, label: string): string {
  const arg = /^[A-Za-z0-9._-]+$/.test(label) ? label : JSON.stringify(label);
  return `switchboard connect ${provider} --account ${arg}`;
}
