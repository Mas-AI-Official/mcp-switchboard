/**
 * Text that was chosen by somebody else and is about to be echoed to a terminal or a log.
 *
 * A DCR `client_name`, a tool or resource name an upstream lists, an error message an upstream returns, a
 * model name a local server reports: all of it is attacker-influenced. Printed raw, an ESC sequence can
 * rewrite earlier lines, retitle the window or write to the clipboard (OSC 52), a carriage return can paint
 * over the line that precedes it, and a bidi override can reorder what the operator reads. Two helpers:
 *
 *   stripControl(text)   removes ANSI escape sequences and every control or invisible formatting character
 *                        EXCEPT newline and tab. The logger applies it to every message, so no caller can forget.
 *   safeText(value, max) the form for one value inside a message: stripControl, then every whitespace run
 *                        (newlines included) becomes one space, then the text is capped at `max` characters.
 *
 * Both are linear in their input: the patterns have no nested quantifiers and `safeText` looks at no more than
 * SCAN_LIMIT characters.
 */

/** The most input `safeText` reads; an escape sequence is never longer than this in practice. */
const SCAN_LIMIT = 4096;
export const DEFAULT_TEXT_MAX = 120;

const range = (a: number, b: number): string => `${String.fromCharCode(a)}-${String.fromCharCode(b)}`;

/** Complete escape sequences first, so `ESC [ 2 J` leaves nothing behind (CSI, OSC up to BEL or ST, two-character forms). */
const ANSI = new RegExp(
  [
    `${String.fromCharCode(27)}\\[[0-?]*[ -/]*[@-~]`,
    `${String.fromCharCode(27)}\\][^${String.fromCharCode(7)}${String.fromCharCode(27)}]*(?:${String.fromCharCode(7)}|${String.fromCharCode(27)}\\\\)`,
    `${String.fromCharCode(27)}[@-_]`,
  ].join("|"),
  "g",
);

/**
 * What remains after the sequences are gone: C0 (but not tab and newline), DEL, C1, zero-width and bidi
 * formatting characters, line and paragraph separators, word joiners and the byte order mark.
 */
const KEEP = new Set([9, 10]);
const CONTROL = new RegExp(
  `[${range(0, 31)}${range(127, 159)}${range(0x200b, 0x200f)}${range(0x2028, 0x202e)}${range(0x2060, 0x2069)}${String.fromCharCode(0xfeff)}]`,
  "g",
);

/** Remove escape sequences and control characters from `text`, keeping newline and tab. */
export function stripControl(text: string): string {
  return text.replace(ANSI, "").replace(CONTROL, (c) => (KEEP.has(c.charCodeAt(0)) ? c : ""));
}

/** One value for a log line or a terminal: no control characters, no line breaks, at most `max` characters. */
export function safeText(value: unknown, max: number = DEFAULT_TEXT_MAX): string {
  if (value === undefined || value === null) return "";
  const full = String(value);
  const head = full.length > SCAN_LIMIT ? full.slice(0, SCAN_LIMIT) : full;
  // Line and paragraph separators and NEL read as whitespace, so they become a space rather than vanish.
  const spaced = head.replace(ANSI, "").replace(new RegExp(`[${String.fromCharCode(0x85)}${range(0x2028, 0x2029)}]`, "g"), " ");
  const flat = stripControl(spaced.replace(/[\t\r\n]+/g, " ")).replace(/ {2,}/g, " ").trim();
  return flat.length > max || full.length > SCAN_LIMIT ? `${flat.slice(0, max)}...` : flat;
}
