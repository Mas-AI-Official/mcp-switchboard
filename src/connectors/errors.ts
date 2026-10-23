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
