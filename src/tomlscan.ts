/**
 * tomlscan.ts: a small TOML 1.0 syntax scanner (design 3.13).
 *
 * `switchboard install codex` must not edit a `config.toml` it cannot read: a file that does not parse is
 * refused, never rewritten. The project has no TOML dependency, so this module checks syntax and reports where
 * every table header and every key/value statement sits. That is all the installer needs: it locates the one
 * `[mcp_servers.<name>]` table (and its sub-tables) by line range and replaces or removes exactly those lines.
 *
 * It validates structure (tables, dotted and quoted keys, basic and literal strings, multi-line strings, numbers,
 * booleans, date-times, arrays, inline tables, comments, line ends). It does not evaluate values and does not
 * detect duplicate keys or tables; the owning client does that when it loads the file. It is deliberately a bit
 * lenient where TOML 1.1 relaxed 1.0 (newlines inside inline tables, `\e` and `\xHH` escapes), because a refusal of
 * a file the client accepts would be a false alarm, while the reverse never leads to a write the client rejects
 * (the installer only touches lines it located itself).
 *
 * Linear in the input: one pass, no backtracking, no RegExp built from file text.
 */

export interface TomlHeader {
  /** Key path of the table, unquoted: `[mcp_servers."a b"]` gives `["mcp_servers", "a b"]`. */
  path: string[];
  /** True for an array-of-tables header `[[x]]`. */
  array: boolean;
  /** Zero-based index of the header's line. */
  line: number;
}

export interface TomlAssign {
  /** Path of the table the statement sits in (empty at the top level). */
  table: string[];
  /** The statement's own (possibly dotted) key. */
  key: string[];
  /** Zero-based index of the statement's first line. */
  line: number;
}

export type TomlScan =
  | { ok: true; headers: TomlHeader[]; assigns: TomlAssign[]; lineCount: number }
  | { ok: false; error: string; line: number };

class TomlSyntaxError extends Error {
  constructor(
    message: string,
    readonly line: number,
  ) {
    super(message);
  }
}

const BARE_KEY = /[A-Za-z0-9_-]/;
const INT_RE = /^[+-]?(0|[1-9](_?[0-9])*)$/;
const HEX_RE = /^0x[0-9a-fA-F](_?[0-9a-fA-F])*$/;
const OCT_RE = /^0o[0-7](_?[0-7])*$/;
const BIN_RE = /^0b[01](_?[01])*$/;
const FLOAT_RE = /^[+-]?(0|[1-9](_?[0-9])*)(\.[0-9](_?[0-9])*)?([eE][+-]?[0-9](_?[0-9])*)?$/;
const SPECIAL_FLOAT_RE = /^[+-]?(inf|nan)$/;
const DATETIME_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}([Tt ][0-9]{2}:[0-9]{2}(:[0-9]{2}(\.[0-9]+)?)?([Zz]|[+-][0-9]{2}:[0-9]{2})?)?/;
const TIME_RE = /^[0-9]{2}:[0-9]{2}(:[0-9]{2}(\.[0-9]+)?)?$/;

class Scanner {
  i = 0;
  line = 0;
  readonly headers: TomlHeader[] = [];
  readonly assigns: TomlAssign[] = [];
  private table: string[] = [];

  constructor(private readonly s: string) {}

  private fail(message: string): never {
    throw new TomlSyntaxError(message, this.line);
  }

  private peek(offset = 0): string | undefined {
    return this.s[this.i + offset];
  }

  private adv(): string {
    const c = this.s[this.i++]!;
    if (c === "\n") this.line++;
    return c;
  }

  private skipWs(): void {
    while (this.peek() === " " || this.peek() === "\t") this.i++;
  }

  private skipToEol(): void {
    while (this.i < this.s.length && this.peek() !== "\n") this.i++;
  }

  /** Whitespace, newlines and comments (inside arrays and inline tables). */
  private skipWsNl(): void {
    for (;;) {
      const c = this.peek();
      if (c === " " || c === "\t" || c === "\n") this.adv();
      else if (c === "\r" && this.peek(1) === "\n") this.i++;
      else if (c === "#") this.skipToEol();
      else return;
    }
  }

  private expectEol(): void {
    this.skipWs();
    if (this.peek() === "#") this.skipToEol();
    const c = this.peek();
    if (c === undefined) return;
    if (c === "\n") {
      this.adv();
      return;
    }
    if (c === "\r" && this.peek(1) === "\n") {
      this.i++;
      this.adv();
      return;
    }
    this.fail("unexpected characters after the value or table header");
  }

  run(): void {
    for (;;) {
      this.skipWs();
      const c = this.peek();
      if (c === undefined) return;
      if (c === "\n") {
        this.adv();
        continue;
      }
      if (c === "\r" && this.peek(1) === "\n") {
        this.i++;
        continue;
      }
      if (c === "#") {
        this.skipToEol();
        continue;
      }
      if (c === "[") this.header();
      else this.keyval();
    }
  }

  private header(): void {
    const line = this.line;
    this.adv(); // [
    const array = this.peek() === "[";
    if (array) this.adv();
    const path = this.key();
    this.skipWs();
    if (this.peek() !== "]") this.fail("a table header must end with ]");
    this.adv();
    if (array) {
      if (this.peek() !== "]") this.fail("an array-of-tables header must end with ]]");
      this.adv();
    }
    this.expectEol();
    this.table = path;
    this.headers.push({ path, array, line });
  }

  private keyval(): void {
    const line = this.line;
    const key = this.key();
    this.skipWs();
    if (this.peek() !== "=") this.fail("expected = after the key");
    this.adv();
    this.skipWs();
    this.value();
    this.expectEol();
    this.assigns.push({ table: this.table, key, line });
  }

  private key(): string[] {
    const parts: string[] = [];
    for (;;) {
      this.skipWs();
      parts.push(this.simpleKey());
      this.skipWs();
      if (this.peek() === ".") {
        this.adv();
        continue;
      }
      return parts;
    }
  }

  private simpleKey(): string {
    const c = this.peek();
    if (c === '"') return this.basicString();
    if (c === "'") return this.literalString();
    let out = "";
    while (this.peek() !== undefined && BARE_KEY.test(this.peek()!)) out += this.adv();
    if (out === "") this.fail("expected a key");
    return out;
  }

  /** Single-line basic string; returns its (unescaped for the simple escapes) text. */
  private basicString(): string {
    this.adv(); // opening quote
    let out = "";
    for (;;) {
      const c = this.peek();
      if (c === undefined || c === "\n" || (c === "\r" && this.peek(1) === "\n")) this.fail("unterminated string");
      if (c === '"') {
        this.adv();
        return out;
      }
      if (c === "\\") {
        out += this.escape();
        continue;
      }
      if (this.isControl(c!)) this.fail("a control character inside a string");
      out += this.adv();
    }
  }

  private isControl(c: string): boolean {
    const code = c.charCodeAt(0);
    return (code < 0x20 && c !== "\t") || code === 0x7f;
  }

  private escape(): string {
    this.adv(); // backslash
    const e = this.peek();
    if (e === undefined) this.fail("unterminated escape sequence");
    this.adv();
    switch (e) {
      case "b":
        return "\b";
      case "t":
        return "\t";
      case "n":
        return "\n";
      case "f":
        return "\f";
      case "r":
        return "\r";
      case "e":
        return "\x1b";
      case '"':
        return '"';
      case "\\":
        return "\\";
      case "u":
        return this.hexEscape(4);
      case "U":
        return this.hexEscape(8);
      case "x":
        return this.hexEscape(2);
      default:
        return this.fail(`invalid escape sequence \\${e}`);
    }
  }

  private hexEscape(n: number): string {
    let hex = "";
    for (let k = 0; k < n; k++) {
      const h = this.peek();
      if (h === undefined || !/[0-9a-fA-F]/.test(h)) this.fail("invalid unicode escape");
      hex += this.adv();
    }
    const cp = parseInt(hex, 16);
    if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) this.fail("invalid unicode escape");
    return String.fromCodePoint(cp);
  }

  private literalString(): string {
    this.adv();
    let out = "";
    for (;;) {
      const c = this.peek();
      if (c === undefined || c === "\n" || (c === "\r" && this.peek(1) === "\n")) this.fail("unterminated literal string");
      if (c === "'") {
        this.adv();
        return out;
      }
      if (this.isControl(c!)) this.fail("a control character inside a string");
      out += this.adv();
    }
  }

  private multiBasic(): void {
    this.i += 3;
    if (this.peek() === "\n") this.adv();
    else if (this.peek() === "\r" && this.peek(1) === "\n") {
      this.i++;
      this.adv();
    }
    for (;;) {
      const c = this.peek();
      if (c === undefined) this.fail("unterminated multi-line string");
      if (c === "\\") {
        const n = this.peek(1);
        if (n === " " || n === "\t" || n === "\n" || n === "\r") {
          this.adv(); // line-ending backslash: swallow it and the whitespace that follows
          while (this.peek() === " " || this.peek() === "\t" || this.peek() === "\n" || this.peek() === "\r") this.adv();
        } else this.escape();
        continue;
      }
      if (c === '"') {
        if (this.closeTriple('"')) return;
        continue;
      }
      if (this.isControl(c) && c !== "\n" && c !== "\r") this.fail("a control character inside a string");
      this.adv();
    }
  }

  private multiLiteral(): void {
    this.i += 3;
    if (this.peek() === "\n") this.adv();
    else if (this.peek() === "\r" && this.peek(1) === "\n") {
      this.i++;
      this.adv();
    }
    for (;;) {
      const c = this.peek();
      if (c === undefined) this.fail("unterminated multi-line literal string");
      if (c === "'") {
        if (this.closeTriple("'")) return;
        continue;
      }
      if (this.isControl(c) && c !== "\n" && c !== "\r") this.fail("a control character inside a string");
      this.adv();
    }
  }

  /** At a quote inside a multi-line string: consume the run of quotes; true when it closes the string (3 to 5 quotes). */
  private closeTriple(q: string): boolean {
    let run = 0;
    while (this.peek(run) === q) run++;
    this.i += run;
    if (run < 3) return false;
    if (run > 5) this.fail("too many quotes at the end of a multi-line string");
    return true;
  }

  private value(): void {
    const c = this.peek();
    if (c === undefined || c === "\n" || c === "\r") this.fail("expected a value");
    if (c === '"') {
      if (this.peek(1) === '"' && this.peek(2) === '"') this.multiBasic();
      else this.basicString();
      return;
    }
    if (c === "'") {
      if (this.peek(1) === "'" && this.peek(2) === "'") this.multiLiteral();
      else this.literalString();
      return;
    }
    if (c === "[") return this.array();
    if (c === "{") return this.inlineTable();
    this.bareValue();
  }

  private array(): void {
    this.adv();
    for (;;) {
      this.skipWsNl();
      if (this.peek() === "]") {
        this.adv();
        return;
      }
      this.value();
      this.skipWsNl();
      if (this.peek() === ",") {
        this.adv();
        continue;
      }
      if (this.peek() === "]") {
        this.adv();
        return;
      }
      this.fail("expected , or ] in an array");
    }
  }

  private inlineTable(): void {
    this.adv();
    for (;;) {
      this.skipWsNl();
      if (this.peek() === "}") {
        this.adv();
        return;
      }
      this.key();
      this.skipWs();
      if (this.peek() !== "=") this.fail("expected = in an inline table");
      this.adv();
      this.skipWs();
      this.value();
      this.skipWsNl();
      if (this.peek() === ",") {
        this.adv();
        continue;
      }
      if (this.peek() === "}") {
        this.adv();
        return;
      }
      this.fail("expected , or } in an inline table");
    }
  }

  private bareValue(): void {
    // A date-time may contain a space (`1979-05-27 07:32:00Z`): try it on the rest of the line first.
    let eol = this.i;
    while (eol < this.s.length && this.s[eol] !== "\n") eol++;
    const m = DATETIME_RE.exec(this.s.slice(this.i, Math.min(eol, this.i + 40)));
    if (m) {
      const after = this.s[this.i + m[0].length];
      if (after === undefined || " \t\r\n,]}#".includes(after)) {
        this.i += m[0].length;
        return;
      }
    }
    let tok = "";
    for (;;) {
      const c = this.peek();
      if (c === undefined || " \t\r\n,]}#".includes(c)) break;
      tok += this.adv();
    }
    if (tok === "") this.fail("expected a value");
    if (tok === "true" || tok === "false") return;
    if (INT_RE.test(tok) || HEX_RE.test(tok) || OCT_RE.test(tok) || BIN_RE.test(tok) || SPECIAL_FLOAT_RE.test(tok) || TIME_RE.test(tok)) return;
    if (FLOAT_RE.test(tok) && /[.eE]/.test(tok)) return;
    this.fail(`invalid value '${tok.length > 24 ? tok.slice(0, 24) + "..." : tok}'`);
  }
}

/** Scan TOML text. Never throws: a syntax error comes back as `{ ok: false, error, line }` (line is 1-based). */
export function scanToml(text: string): TomlScan {
  const src = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  const sc = new Scanner(src);
  try {
    sc.run();
  } catch (err) {
    if (err instanceof TomlSyntaxError) return { ok: false, error: err.message, line: err.line + 1 };
    throw err;
  }
  return { ok: true, headers: sc.headers, assigns: sc.assigns, lineCount: src.split("\n").length };
}

/** Parse the key path of a `[a.b."c d"]` header string (for callers that name a table by its header text). */
export function headerPath(header: string): string[] | null {
  const scan = scanToml(header.trim() + "\n");
  if (!scan.ok || scan.headers.length !== 1 || scan.headers[0]!.array) return null;
  return scan.headers[0]!.path;
}

export const pathStartsWith = (path: string[], prefix: string[]): boolean => prefix.length <= path.length && prefix.every((p, k) => path[k] === p);
