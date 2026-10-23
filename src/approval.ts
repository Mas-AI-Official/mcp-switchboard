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
 *   - stdio transport active, no TTY, or stdin already at EOF -> deny (fail-closed)
 *   - too many prompts already waiting -> deny (fail-closed)
 *   - otherwise -> queue a prompt; the owner must type that prompt's code
 *
 * One prompt at a time, one code per prompt. 0.1.0 opened a readline interface on the shared stdin for
 * EVERY pending call, and every interface received the same input line, so one typed "y" approved a whole
 * batch_call (two writes and a destructive call) at once. Now every pending call waits in one queue behind
 * one interface, only the head prompt is shown, and it is approved only by typing its own random code (the
 * same base32 challenge the owner-presence check uses). A bare "y", a wrong code, a line typed before the
 * prompt existed and EOF all deny, so one typed line can resolve at most one call and never by accident.
 *
 * This is still the in-band channel the design (3.3) replaces with out-of-band approvals bound to the call's
 * arguments; until those land it is the only human gate, so it must not be fooled by concurrency.
 */

import { createInterface, type Interface } from "node:readline";
import type { Scope } from "./types.js";
import { log } from "./logger.js";
import { randomChallenge } from "./presence.js";

let stdioActive = false;

/** Called by the gateway when the stdio transport connects, so we never read stdin. */
export function setStdioActive(active: boolean): void {
  stdioActive = active;
}

/** Calls waiting for a human decision (the open prompt plus the queue) beyond which new ones are refused at once. */
export const MAX_PENDING_PROMPTS = 16;

interface Prompt {
  header: string;
  code: string;
  resolve: (approved: boolean) => void;
}

/** The prompt the owner is looking at, and the ones queued behind it. */
let open: Prompt | undefined;
const waiting: Prompt[] = [];
let rl: Interface | undefined;

/** Server, tool and reason come from upstream servers and clients: no control characters may reach the terminal. */
function printable(s: string): string {
  const t = s.replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g, "?");
  return t.length > 160 ? `${t.slice(0, 157)}...` : t;
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

  if (process.stdin.readableEnded || process.stdin.destroyed) {
    log.warn(`approval required for ${server}__${tool} but stdin is closed, denying (fail-closed).`);
    return false;
  }

  if (waiting.length + (open ? 1 : 0) >= MAX_PENDING_PROMPTS) {
    log.warn(`approval required for ${server}__${tool} but ${MAX_PENDING_PROMPTS} approvals are already waiting, denying (fail-closed).`);
    return false;
  }

  return new Promise<boolean>((resolve) => {
    waiting.push({
      header: `[approval] ${printable(server)} → ${printable(tool)} needs '${scope}'. ${printable(reason)}`,
      code: randomChallenge(4),
      resolve,
    });
    next();
  });
}

/** Show the next prompt if none is open; close the interface when nothing is left. */
function next(): void {
  if (open) return;
  const p = waiting.shift();
  if (!p) {
    const r = rl;
    rl = undefined;
    r?.close();
    return;
  }
  open = p;
  if (!rl) {
    rl = createInterface({ input: process.stdin, output: process.stdout });
    rl.on("line", onLine);
    rl.on("close", onEnd);
  }
  const more = waiting.length;
  process.stdout.write(`\n${p.header}\n${more > 0 ? `(${more} more waiting; each needs its own code)\n` : ""}`);
  rl.setPrompt(`Type ${p.code} to allow this call (anything else denies): `);
  rl.prompt();
}

/** One typed line answers the open prompt, and only that one. With no prompt open the line is dropped. */
function onLine(line: string): void {
  const p = open;
  if (!p) return;
  open = undefined;
  const ok = line.trim().toUpperCase() === p.code;
  p.resolve(ok);
  next();
}

/** stdin ended or the terminal was closed: nobody can answer the calls still waiting, so they are denied. */
function onEnd(): void {
  rl = undefined;
  const pending = open ? [open, ...waiting] : [...waiting];
  open = undefined;
  waiting.length = 0;
  for (const p of pending) p.resolve(false);
}
