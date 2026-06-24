/**
 * Approval gate handler. Fail-closed by design.
 *
 * When a tool call hits an approval gate we need a human "yes". The only safe
 * synchronous channel is an interactive TTY prompt — and only when the stdio MCP
 * transport is NOT using stdin (in stdio mode stdin is the JSON-RPC channel, so
 * prompting there would corrupt the protocol).
 *
 * Resolution order:
 *   - SWITCHBOARD_AUTO_APPROVE=1  -> auto-allow (logged loudly; opt-in only)
 *   - stdio transport active, or no TTY -> deny (fail-closed)
 *   - otherwise -> prompt y/N on the terminal
 */

import { createInterface } from "node:readline";
import type { Scope } from "./types.js";
import { log } from "./logger.js";

let stdioActive = false;

/** Called by the gateway when the stdio transport connects, so we never read stdin. */
export function setStdioActive(active: boolean): void {
  stdioActive = active;
}

export async function approve(server: string, tool: string, scope: Scope, reason: string): Promise<boolean> {
  if (process.env.SWITCHBOARD_AUTO_APPROVE === "1") {
    log.warn(`auto-approved ${server}__${tool} (SWITCHBOARD_AUTO_APPROVE=1)`);
    return true;
  }

  if (stdioActive || !process.stdin.isTTY || !process.stdout.isTTY) {
    log.warn(
      `approval required for ${server}__${tool} (${reason}) — no interactive TTY, denying (fail-closed). ` +
        `Relax the policy or set SWITCHBOARD_AUTO_APPROVE=1 to allow.`,
    );
    return false;
  }

  const rl = createInterface({ input: process.stdin, output: process.stdout });
  try {
    const answer = await new Promise<string>((resolve) =>
      rl.question(`\n[approval] ${server} → ${tool} needs '${scope}'. ${reason}\nAllow this call? [y/N] `, resolve),
    );
    return /^y(es)?$/i.test(answer.trim());
  } finally {
    rl.close();
  }
}
