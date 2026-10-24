/**
 * controlclient.ts: how a CLI process talks to the RUNNING gateway's control API (design 3.3 and 3.15).
 *
 * The CLI never decides anything an owner must decide. `approve`, `kill off`, `dashboard login`, and the grant of
 * a client (`client add`, `client rotate`, `install`) are requests to the gateway, which performs the owner
 * presence check itself (Windows Hello, or a challenge at its own console) and only then acts. The control token
 * that authenticates the request is read from `<SWITCHBOARD_HOME>/control.key`; it keeps stray local callers out
 * and proves only "a process of this OS user", which is exactly what an agent with a shell is, so it is a
 * convenience and never the boundary.
 *
 * The token is never logged and never put in an error message.
 */

import { readControlKey } from "./controlkey.js";
import { guardedFetch } from "./netguard.js";
import { HOME_DIR } from "./vault.js";

/**
 * Why the gateway could not be asked:
 *  - no-key: no usable control key file, so no gateway started here (or its key is unreadable);
 *  - no-gateway: a key exists but nothing answered on the port (a stale key, or the gateway is down);
 *  - rejected: a gateway answered and refused the token (it restarted since the key was read, or two gateways
 *    share this SWITCHBOARD_HOME). A gateway IS there, so a caller must never fall back to editing files.
 */
export type ControlFailure = "no-key" | "no-gateway" | "rejected";

export class ControlError extends Error {
  constructor(
    readonly kind: ControlFailure,
    message: string,
  ) {
    super(message);
    this.name = "ControlError";
  }
}

export interface ControlResponse {
  status: number;
  body: Record<string, unknown>;
}

/** One request to the control API of the gateway on `127.0.0.1:<port>`. Throws {@link ControlError}. */
export async function controlRequest(
  port: number,
  method: "GET" | "POST",
  path: string,
  timeoutMs: number,
  body?: unknown,
): Promise<ControlResponse> {
  let token: string | null;
  try {
    token = readControlKey();
  } catch (err) {
    throw new ControlError("no-key", err instanceof Error ? err.message : String(err));
  }
  if (token === null) {
    throw new ControlError("no-key", `no control key in ${HOME_DIR}: no gateway has started here. Start one with \`switchboard dashboard\` or \`switchboard serve\`.`);
  }
  let res;
  try {
    // Explicit local call to our own gateway: loopback is permitted for this one request, nothing else.
    res = await guardedFetch(`http://127.0.0.1:${port}/api/control${path}`, {
      method,
      headers: { authorization: `Bearer ${token}`, ...(body !== undefined ? { "content-type": "application/json" } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      timeoutMs,
      allowLoopback: true,
    });
  } catch {
    throw new ControlError("no-gateway", `no gateway answered on 127.0.0.1:${port} (or the request timed out). Is it running?`);
  }
  let parsed: Record<string, unknown> = {};
  try {
    parsed = (await res.json()) as Record<string, unknown>;
  } catch {
    /* an empty or non-JSON body is reported by status */
  }
  if (res.status === 401) {
    throw new ControlError("rejected", "the gateway rejected the control token: it was restarted since the key was read, or another gateway shares this SWITCHBOARD_HOME. Run the command again.");
  }
  return { status: res.status, body: parsed };
}

/**
 * Like {@link controlRequest}, but `null` when there is no gateway to ask (no key, or nothing answering). A rejected
 * token is still an error: a gateway is running, and the caller must not go around it.
 */
export async function askGateway(port: number, method: "GET" | "POST", path: string, timeoutMs: number, body?: unknown): Promise<ControlResponse | null> {
  try {
    return await controlRequest(port, method, path, timeoutMs, body);
  } catch (err) {
    if (err instanceof ControlError && err.kind !== "rejected") return null;
    throw err;
  }
}
