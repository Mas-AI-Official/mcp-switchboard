/**
 * Tiny logger. Critically: info/warn/error all write to **stderr**, never stdout —
 * in stdio transport mode stdout is the JSON-RPC channel and any stray byte corrupts
 * the MCP protocol. `plain` (stdout) is only used by one-shot commands (list/doctor/vault)
 * that never run while the stdio transport is connected.
 */

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
  info: (m: string) => process.stderr.write(`${C.gray}${ts()}${C.reset} ${C.cyan}›${C.reset} ${m}\n`),
  ok: (m: string) => process.stderr.write(`${C.gray}${ts()}${C.reset} ${C.green}✓${C.reset} ${m}\n`),
  warn: (m: string) => process.stderr.write(`${C.gray}${ts()}${C.reset} ${C.yellow}!${C.reset} ${m}\n`),
  error: (m: string) => process.stderr.write(`${C.gray}${ts()}${C.reset} ${C.red}✗${C.reset} ${m}\n`),
  /** stdout — only for human-facing command output, never during stdio serving. */
  plain: (m: string) => process.stdout.write(m + "\n"),
};

/** Convenience alias for human-facing one-shot command output (stdout). */
export const out = (m: string): void => {
  log.plain(m);
};
