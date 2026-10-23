/**
 * Tiny logger. Critically: info/warn/error all write to **stderr**, never stdout —
 * in stdio transport mode stdout is the JSON-RPC channel and any stray byte corrupts
 * the MCP protocol. `plain` (stdout) is only used by one-shot commands (list/doctor/vault)
 * that never run while the stdio transport is connected.
 *
 * Every message passes through `stripControl` (safetext.ts): many messages echo a string somebody else
 * chose (an OAuth client's registered name, an upstream's tool name or error text, a provider's model
 * list), and a raw escape sequence in one of them could rewrite earlier lines, retitle the window or
 * write to the clipboard. Newlines and tabs are kept; the logger's own colour codes are added after.
 */

import { stripControl } from "./safetext.js";

const C = {
  reset: "\x1b[0m",
  gray: "\x1b[90m",
  red: "\x1b[31m",
  yellow: "\x1b[33m",
  cyan: "\x1b[36m",
  green: "\x1b[32m",
};

function ts(): string {
  return new Date().toISOString().slice(11, 19);
}

export const log = {
  info: (m: string) => process.stderr.write(`${C.gray}${ts()}${C.reset} ${C.cyan}›${C.reset} ${stripControl(m)}\n`),
  ok: (m: string) => process.stderr.write(`${C.gray}${ts()}${C.reset} ${C.green}✓${C.reset} ${stripControl(m)}\n`),
  warn: (m: string) => process.stderr.write(`${C.gray}${ts()}${C.reset} ${C.yellow}!${C.reset} ${stripControl(m)}\n`),
  error: (m: string) => process.stderr.write(`${C.gray}${ts()}${C.reset} ${C.red}✗${C.reset} ${stripControl(m)}\n`),
  /** stdout — only for human-facing command output, never during stdio serving. */
  plain: (m: string) => process.stdout.write(stripControl(m) + "\n"),
};

/** Convenience alias for human-facing one-shot command output (stdout). */
export const out = (m: string): void => {
  log.plain(m);
};
