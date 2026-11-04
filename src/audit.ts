/**
 * Append-only, hash-chained audit log (design vNext 3.7). Every policy verdict (allow / deny /
 * approval) is one JSON line in `~/.switchboard/audit.log`. The dashboard tails it.
 *
 * Tamper evidence: every row carries `seq` (1, 2, 3, ... across rotations), `prev_hash` (the hash of
 * the row before it) and `hash` (SHA-256 hex over the canonical JSON of the row without `hash`, keys
 * sorted). `switchboard audit verify [--all]` walks the chain and reports the first break with its seq.
 * Rotation at 20 MB renames the file to `audit.log.<timestamp>` and the new file's first row carries
 * the last hash over, so the chain survives it.
 *
 * What the chain does and does not prove: it detects an edited row, a removed or inserted row and a
 * reordered row, because each row commits to the one before it. It cannot detect the newest rows being
 * cut off the end, or an attacker who can rewrite the whole file and recompute every hash after the
 * edit: there is no secret in the chain. Anchor the latest `hash` somewhere the log writer cannot
 * reach if that matters.
 *
 * Writers are serialised across processes by a lock on the file, so the CLI and the gateway can both
 * append and the chain still has no forks.
 */

import { appendFileSync, closeSync, existsSync, fstatSync, openSync, readFileSync, readSync, readdirSync, renameSync, statSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { ensureDir, fileStamp, withFileLock } from "./atomicfile.js";
import { HOME_DIR } from "./vault.js";

/** Rotate `audit.log` once it reaches this size. */
export const AUDIT_ROTATE_BYTES = 20 * 1024 * 1024;
/** `prev_hash` of the first row of a chain. */
export const GENESIS_HASH = "0".repeat(64);

export interface AuditEntry {
  ts: string;
  /** Position in the hash chain, starting at 1 and continuing across rotations. Absent on rows written before the chain existed. */
  seq?: number;
  /** `hash` of the previous row (GENESIS_HASH for the first). Absent on pre-chain rows. */
  prev_hash?: string;
  /** SHA-256 hex over the canonical JSON of this row without `hash`. Absent on pre-chain rows. */
  hash?: string;
  server: string;
  tool: string;
  scope: string;
  decision: "allow" | "deny" | "approval_required";
  reason?: string;
  /** Who called (design 3.1): `<via>:<id>`. Optional until principals land. */
  principal?: string;
  /** Client profile id of the caller. Optional until principals land. */
  client?: string;
  /** Risk of the call (design 3.4). Optional until risk lands. */
  risk?: "low" | "medium" | "high";
  /** Approval record this call consumed or created (design 3.3). Optional until approvals land. */
  approval_id?: string;
  /** Connector calls (ADR local-composio 6.4): the toolkit, the exact definition version, the connected account (`ca_...`, never a token), whether the call is visible to others, and the run id that names any files it saved. */
  toolkit?: string;
  toolkit_version?: string;
  account?: string;
  outward?: boolean;
  run_id?: string;
  /** Wall-clock duration of the upstream call, milliseconds. Allowed executions only. */
  duration_ms?: number;
  /** Captured call arguments (opt-in via settings.logs.capture_io, redacted + size-capped). */
  request?: unknown;
  /** Captured upstream result (opt-in via settings.logs.capture_io, redacted + size-capped). */
  response?: unknown;
  /** Upstream error message when an allowed call threw. */
  error?: string;
  /** Stable `SB_*` taxonomy code for a failure row (deny / approval-denied / upstream error/timeout). */
  error_code?: string;
  /**
   * `"attempt"` marks the write-ahead row of a write or full scope call: it is appended BEFORE the upstream is
   * called, so a crash or a hang in the middle of a mutating call still leaves a record that it started. It is not
   * a verdict: usage stats skip it, and the call's own result row follows and points back at it with `attempt_seq`.
   */
  phase?: "attempt";
  /** On a result row: the `seq` of the attempt row written ahead of this call. */
  attempt_seq?: number;
}

/** What a caller hands to `audit()`: the chain fields and the timestamp are added by the log. */
export type AuditInput = Omit<AuditEntry, "ts" | "seq" | "prev_hash" | "hash">;

// ── canonical form and hashing ───────────────────────────────────────────────────────────────────

/** JSON with object keys sorted at every depth and no insignificant whitespace: the hashed form of a row. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map((v) => canonicalJson(v)).join(",")}]`;
  const o = value as Record<string, unknown>;
  const keys = Object.keys(o)
    .filter((k) => o[k] !== undefined)
    .sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`).join(",")}}`;
}

const sha256hex = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");

/** The hash a row must carry: SHA-256 over its canonical JSON without the `hash` field. */
export function rowHash(row: Record<string, unknown>): string {
  const rest = { ...row };
  delete rest.hash;
  return sha256hex(canonicalJson(rest));
}

// ── secret scrubbing ─────────────────────────────────────────────────────────────────────────────

/** Key names whose values are masked before anything is written to disk. */
const SECRET_KEY = /token|secret|password|api[_-]?key|authorization/i;
/** Hard ceiling on a captured value's serialized size, so a big payload can't bloat the log. */
const CAPTURE_CAP_BYTES = 4096;
/** Captured structures nested deeper than this are replaced, not copied (a size guard, never a leak). */
const MAX_CAPTURE_DEPTH = 64;

/**
 * A shape is a RegExp, or a hand-written scanner where the RegExp cannot be made linear (the JWT shape).
 * Every shape must be linear in the text it scans: the text is chosen by an upstream server or a client.
 */
type Shape = { kind: string; re: RegExp } | { kind: string; scan: (text: string) => string };

/**
 * `\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*` in linear time. As a RegExp it is quadratic:
 * on `eyJa-eyJa-eyJa-...` every `eyJ` is a legal start, and each start scans the whole base64url run before
 * failing for want of a `.`, so 80 KB of it blocked the gateway for 6 seconds and 200 KB for a minute.
 *
 * The scanner walks maximal base64url runs once. A match is: a run `[a, b)` followed by `.`, a second run of
 * at least 4 characters followed by `.`, then a third run of any length. Its start is the LEFTMOST `eyJ` in the
 * first run that leaves at least 4 characters before `b` and sits at a word boundary (the run start, or right
 * after a `-`, the only non-word character a run can contain). Both the greedy runs and the leftmost-start
 * rule are exactly what the RegExp did; an oracle compares the two on random strings.
 */
function redactJwts(text: string): string {
  const n = text.length;
  const isB64 = (c: number): boolean => (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 45 || c === 95;
  let out = "";
  let copied = 0;
  let pos = 0;
  while (pos < n) {
    while (pos < n && !isB64(text.charCodeAt(pos))) pos++;
    if (pos >= n) break;
    const a = pos;
    let b = a;
    while (b < n && isB64(text.charCodeAt(b))) b++;
    pos = b;
    if (text.charCodeAt(b) !== 46 /* . */ || b - a < 7) continue;
    const c = b + 1;
    let d = c;
    while (d < n && isB64(text.charCodeAt(d))) d++;
    if (d - c < 4 || text.charCodeAt(d) !== 46) continue;
    let start = -1;
    for (let i = a; i <= b - 7; i++) {
      if (text.charCodeAt(i) === 101 && text.charCodeAt(i + 1) === 121 && text.charCodeAt(i + 2) === 74 /* eyJ */ && (i === a || text.charCodeAt(i - 1) === 45)) {
        start = i;
        break;
      }
    }
    if (start < 0) continue;
    let e = d + 1;
    while (e < n && isB64(text.charCodeAt(e))) e++;
    out += text.slice(copied, start) + "[redacted:jwt]";
    copied = e;
    pos = e;
  }
  return copied === 0 ? text : out + text.slice(copied);
}

/** Provider-specific and structural secret shapes. Order matters: wide structures first. */
const SHAPES: Shape[] = [
  { kind: "pem-block", re: /-----BEGIN [A-Z0-9 ]{1,40}-----[\s\S]*?(?:-----END [A-Z0-9 ]{1,40}-----|$)/g },
  { kind: "bearer", re: /\b[Bb]earer\s+[A-Za-z0-9._~+/=-]{8,}/g },
  { kind: "jwt", scan: redactJwts },
  { kind: "sk-key", re: /(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{16,}/g },
  { kind: "google-api-key", re: /(?<![A-Za-z0-9_-])AIza[A-Za-z0-9_-]{30,}/g },
  { kind: "github-token", re: /(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})/g },
  { kind: "slack-token", re: /(?<![A-Za-z0-9_-])xox[abpr]-[A-Za-z0-9-]{8,}/g },
  { kind: "huggingface-token", re: /(?<![A-Za-z0-9_])hf_[A-Za-z0-9]{20,}/g },
  { kind: "aws-access-key", re: /(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])/g },
];

/** A 32+ character hex or base64url run right after a key / token / secret word (`api_key=...`, `"token": "..."`). */
const GENERIC_TOKEN = /((?:key|token|secret)[A-Za-z_]{0,12}(?:\s+is)?[^A-Za-z0-9\r\n]{1,8})([A-Za-z0-9_-]{32,})(?![A-Za-z0-9_-])/gi;

/**
 * The most text one scrub will look at. Anything longer is cut here before any pattern runs, and the cut is
 * marked `[truncated:<original length>]`. An audit row never needs more (captured values are capped at
 * CAPTURE_CAP_BYTES anyway, an error message is a diagnostic), and it bounds the work an upstream can make
 * us do with one answer, whatever a pattern does.
 */
export const REDACT_MAX_CHARS = 8192;

/** Characters that can be part of a token-shaped secret (provider keys, bearer values, JWTs, base64, hex). */
const isTokenChar = (c: number): boolean => (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 45 || c === 95 || c === 46 || c === 126 || c === 43 || c === 47 || c === 61;

/**
 * The first REDACT_MAX_CHARS characters of `text`, backed off to a token boundary. A secret that straddles the
 * cut would otherwise leave its first characters behind (too short for its pattern to match), so a token that
 * is cut in half is dropped whole. A multi-line PEM block cut in the middle is still caught: its BEGIN line is
 * in the kept part and the pattern redacts an unterminated block to the end of the text.
 */
function cutForScan(text: string): string {
  let end = REDACT_MAX_CHARS;
  if (isTokenChar(text.charCodeAt(end))) {
    while (end > 0 && isTokenChar(text.charCodeAt(end - 1))) end--;
  }
  return text.slice(0, end);
}

/**
 * Replace every secret-shaped substring of `text` with `[redacted:<kind>]`: provider keys (sk-, sk-proj-,
 * AIza, ghp_/gho_/github_pat_, xox[abpr]-, hf_, AWS AKIA), Bearer tokens, JWTs, PEM blocks, and long
 * hex or base64url tokens adjacent to key / token / secret words. Over-redacting is the accepted
 * failure direction for a log. Linear in the input (every shape is: see Shape, and the oracle times each
 * one on adversarial input), and the input is capped at REDACT_MAX_CHARS first.
 */
export function redactSecretShapes(text: string): string {
  return scrubText(text);
}

/** Set by a scrub when it had to cut a text, so a caller that reports sizes can say the value was longer. */
interface ScrubState {
  cut: boolean;
}

function scrubText(text: string, state?: ScrubState): string {
  if (text.length < 8) return text;
  const over = text.length > REDACT_MAX_CHARS;
  if (over && state) state.cut = true;
  let out = over ? cutForScan(text) : text;
  for (const shape of SHAPES) out = "scan" in shape ? shape.scan(out) : out.replace(shape.re, `[redacted:${shape.kind}]`);
  out = out.replace(GENERIC_TOKEN, (_m, lead: string, token: string) => `${lead}[redacted:${/^[0-9a-fA-F]+$/.test(token) ? "hex-token" : "b64url-token"}]`);
  return over ? `${out}[truncated:${text.length}]` : out;
}

/**
 * Prepare a value for opt-in I/O capture: normalise to plain JSON, mask values under secret-looking key
 * names, scan EVERY string value (at any depth) for secret shapes, then cap the serialized size.
 * Returns a truncation marker rather than a giant blob when over cap. Capture is OFF by default; this
 * only runs when the operator sets settings.logs.capture_io.
 *
 * `secretKeys` is an exact-match set of key names that MUST be redacted regardless of how they
 * look — the router passes the injected-arg key names so a `${vault:..}`/`${oauth:..}` secret that
 * was injected under an innocuous param name (e.g. `q`) never reaches the log in cleartext. The
 * name-pattern heuristic (SECRET_KEY) and the value-shape scan still cover everything else.
 */
export function sanitizeForAudit(value: unknown, secretKeys?: ReadonlySet<string>): unknown {
  let plain: unknown;
  let originalSize = 0;
  try {
    const text = JSON.stringify(value);
    if (text === undefined) return undefined; // nothing serializable (undefined, a function)
    originalSize = text.length;
    plain = JSON.parse(text); // normalises toJSON/Date/undefined and throws on a circular structure
  } catch {
    return "[uncapturable]";
  }
  const state: ScrubState = { cut: false };
  const redacted = redactTree(plain, 0, secretKeys, state);
  let serialized: string;
  try {
    serialized = JSON.stringify(redacted);
  } catch {
    return "[uncapturable]";
  }
  // A string longer than REDACT_MAX_CHARS was cut before scanning, so the redacted tree can be much shorter
  // than the value that was captured: it still counts as over cap and reports the size it really had.
  if (serialized !== undefined && (state.cut || serialized.length > CAPTURE_CAP_BYTES)) {
    return { _truncated: state.cut ? Math.max(originalSize, serialized.length) : serialized.length, preview: serialized.slice(0, CAPTURE_CAP_BYTES) };
  }
  return redacted;
}

function redactTree(value: unknown, depth: number, secretKeys: ReadonlySet<string> | undefined, state: ScrubState): unknown {
  if (typeof value === "string") return scrubText(value, state);
  if (value === null || typeof value !== "object") return value;
  if (depth >= MAX_CAPTURE_DEPTH) return "[truncated:depth]";
  if (Array.isArray(value)) return value.map((v) => redactTree(v, depth + 1, secretKeys, state));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[scrubText(k, state)] = SECRET_KEY.test(k) || secretKeys?.has(k) ? "[redacted]" : redactTree(v, depth + 1, secretKeys, state);
  }
  return out;
}

/**
 * The OUTCOME of a row, distinct from its governance `decision`.
 *
 * `decision` answers "did governance allow it?"; `outcome` answers "what actually happened?".
 * They are NOT the same: an allowed call can still fail upstream (an error result, a throw, a
 * timeout). Counting every `allow` as a success — which the raw decision tally does — overstates
 * health, so the Usage aggregation derives outcome here instead. Outcome is computed, never
 * persisted, so it can never drift from the `error`/`error_code` already on the row (the single
 * source of truth). Both the aggregator and any row-level consumer call this one function.
 */
export type AuditOutcome = "success" | "error" | "denied" | "approval_required";

export function classifyOutcome(entry: Pick<AuditEntry, "decision" | "error" | "error_code">): AuditOutcome {
  if (entry.decision === "deny") return "denied";
  if (entry.decision === "approval_required") return "approval_required";
  // decision === "allow": governance permitted it — but the call itself may have failed.
  return entry.error || entry.error_code ? "error" : "success";
}

// ── reading a file from the back ─────────────────────────────────────────────────────────────────

/** Lines of a file, last first, reading 64 KB blocks from the end. Blank lines are skipped. */
function* linesBackward(path: string): Generator<string> {
  const fd = openSync(path, "r");
  try {
    let pos = fstatSync(fd).size;
    let pieces: Buffer[] = []; // bytes of the line being assembled, in file order
    while (pos > 0) {
      const n = Math.min(64 * 1024, pos);
      pos -= n;
      const chunk = Buffer.allocUnsafe(n);
      readSync(fd, chunk, 0, n, pos);
      let end = chunk.length;
      for (let i = chunk.lastIndexOf(10, end - 1); i >= 0; i = i > 0 ? chunk.lastIndexOf(10, i - 1) : -1) {
        const head = chunk.subarray(i + 1, end);
        const parts = head.length ? [head, ...pieces] : pieces;
        pieces = [];
        end = i;
        if (parts.length) {
          const line = (parts.length === 1 ? parts[0]! : Buffer.concat(parts)).toString("utf8");
          if (line.trim()) yield line;
        }
      }
      if (end > 0) pieces = [chunk.subarray(0, end), ...pieces];
    }
    if (pieces.length) {
      const line = Buffer.concat(pieces).toString("utf8");
      if (line.trim()) yield line;
    }
  } finally {
    closeSync(fd);
  }
}

function endsWithNewline(path: string): boolean {
  const fd = openSync(path, "r");
  try {
    const size = fstatSync(fd).size;
    if (size === 0) return true;
    const b = Buffer.alloc(1);
    readSync(fd, b, 0, 1, size - 1);
    return b[0] === 10;
  } finally {
    closeSync(fd);
  }
}

const ROTATED_RE = /^audit\.log\.\d{8}T\d{9}Z(?:-\d+)?$/;

// ── the log ──────────────────────────────────────────────────────────────────────────────────────

export interface AuditBreak {
  /** The chain position that failed: the row's seq, or the seq that was expected there. */
  seq: number;
  file: string;
  /** 1-based line within `file`. */
  line: number;
  reason: string;
}

export interface AuditVerifyResult {
  ok: boolean;
  /** File names walked, oldest first. */
  files: string[];
  /** Chained rows verified before the break (or all of them). */
  rows: number;
  /** Rows from before the chain existed (a prefix of the oldest file); not verifiable. */
  legacy_rows: number;
  first_seq?: number;
  last_seq?: number;
  last_hash?: string;
  /** Things worth knowing that are not breaks (an unverifiable legacy prefix, an absent earlier segment). */
  notes: string[];
  break?: AuditBreak;
}

interface ChainState {
  seq: number;
  hash: string;
  /** The current file ends in a partial line (a crash mid-append). */
  torn: boolean;
}

export class AuditLog {
  readonly path: string;
  private cache: { stamp: string; seq: number; hash: string } | null = null;

  constructor(readonly home: string = HOME_DIR) {
    this.path = join(home, "audit.log");
  }

  /** Rotated segments, oldest first. */
  rotatedFiles(): string[] {
    try {
      return readdirSync(this.home)
        .filter((n) => ROTATED_RE.test(n))
        .sort()
        .map((n) => join(this.home, n));
    } catch {
      return [];
    }
  }

  /** Append one row to the chain and return its `seq`. Throws on a disk or lock failure (the router decides what that costs). */
  append(entry: AuditInput): number {
    ensureDir(this.home);
    // An upstream error message can echo a credential; scrub it whether or not capture_io is on.
    const input = typeof entry.error === "string" ? { ...entry, error: redactSecretShapes(entry.error) } : entry;
    const {
      ts: _ts,
      seq: _seq,
      prev_hash: _prev,
      hash: _hash,
      ...fields
    } = input as Record<string, unknown>;
    return withFileLock(this.path, () => {
      const state = this.tail();
      let torn = state.torn;
      if ((statSync(this.path, { throwIfNoEntry: false })?.size ?? 0) >= AUDIT_ROTATE_BYTES) {
        this.rotate();
        torn = false;
      }
      // Normalise through JSON so the hashed form is exactly what a verifier will parse back.
      const base = JSON.parse(JSON.stringify({ ts: new Date().toISOString(), seq: state.seq + 1, ...fields, prev_hash: state.hash })) as Record<string, unknown>;
      const hash = rowHash(base);
      appendFileSync(this.path, `${torn ? "\n" : ""}${JSON.stringify({ ...base, hash })}\n`, { mode: 0o600 });
      const stamp = fileStamp(this.path);
      this.cache = stamp ? { stamp, seq: state.seq + 1, hash } : null;
      return state.seq + 1;
    });
  }

  private rotate(): void {
    const stamp = new Date().toISOString().replace(/[-:.]/g, "");
    let name = `audit.log.${stamp}`;
    for (let n = 1; existsSync(join(this.home, name)); n++) name = `audit.log.${stamp}-${n}`;
    renameSync(this.path, join(this.home, name));
    this.cache = null;
  }

  /** The seq and hash the next row must follow, found at the end of the newest file that has a chained row. */
  private tail(): ChainState {
    const stamp = fileStamp(this.path);
    if (stamp && this.cache && this.cache.stamp === stamp) return { seq: this.cache.seq, hash: this.cache.hash, torn: false };
    const torn = stamp ? !endsWithNewline(this.path) : false;
    const sources = [...(stamp ? [this.path] : []), ...this.rotatedFiles().reverse()];
    for (const source of sources) {
      for (const line of linesBackward(source)) {
        let row: Partial<AuditEntry>;
        try {
          row = JSON.parse(line) as Partial<AuditEntry>;
        } catch {
          continue; // a torn fragment: keep looking for the last whole row
        }
        if (typeof row.hash === "string" && Number.isSafeInteger(row.seq)) return { seq: row.seq as number, hash: row.hash, torn };
        return { seq: 0, hash: GENESIS_HASH, torn }; // a pre-chain row: the chain starts after it
      }
    }
    return { seq: 0, hash: GENESIS_HASH, torn };
  }

  /** The most recent rows, newest first, reading back through rotated segments when needed. */
  recent(limit = 100): AuditEntry[] {
    const out: AuditEntry[] = [];
    for (const line of this.linesNewestFirst(limit)) {
      try {
        out.push(JSON.parse(line) as AuditEntry);
      } catch {
        /* an unreadable line is skipped for display; `audit verify` reports it */
      }
    }
    return out;
  }

  /** Up to `cap` raw lines, newest first, across the current file and rotated segments. */
  *linesNewestFirst(cap: number): Generator<string> {
    let n = 0;
    for (const file of [this.path, ...this.rotatedFiles().reverse()]) {
      if (!existsSync(file)) continue;
      for (const line of linesBackward(file)) {
        if (n++ >= cap) return;
        yield line;
      }
    }
  }

  /**
   * Walk the chain. By default the current file only (its link to the newest rotated segment is still
   * checked); `all` walks every rotated segment first. Stops at the first break.
   */
  verify(opts: { all?: boolean } = {}): AuditVerifyResult {
    const rotated = this.rotatedFiles();
    const files = [...(opts.all ? rotated : []), ...(existsSync(this.path) ? [this.path] : [])];
    const result: AuditVerifyResult = { ok: true, files: files.map((f) => f.slice(this.home.length + 1)), rows: 0, legacy_rows: 0, notes: [] };
    let prev: { seq: number; hash: string } | null = null;
    // Without --all the first row of the current file is checked against the end of the newest segment.
    if (!opts.all && rotated.length) {
      for (const line of linesBackward(rotated[rotated.length - 1]!)) {
        try {
          const r = JSON.parse(line) as Partial<AuditEntry>;
          if (typeof r.hash === "string" && Number.isSafeInteger(r.seq)) prev = { seq: r.seq as number, hash: r.hash };
          break;
        } catch {
          /* skip a torn line */
        }
      }
    }
    let chained = prev !== null; // a chained row precedes this one

    for (const file of files) {
      const name = file.slice(this.home.length + 1);
      const lines = readFileSync(file, "utf8").split("\n");
      for (let i = 0; i < lines.length; i++) {
        const text = lines[i]!;
        if (!text.trim()) continue;
        const lineNo = i + 1;
        const fail = (seq: number, reason: string): AuditVerifyResult => {
          result.ok = false;
          result.break = { seq, file: name, line: lineNo, reason };
          return result;
        };
        const expected = prev ? prev.seq + 1 : 1;
        let row: Record<string, unknown>;
        try {
          const parsed = JSON.parse(text) as unknown;
          if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not an object");
          row = parsed as Record<string, unknown>;
        } catch {
          return fail(expected, "unreadable row (not valid JSON): the row was damaged, or cut short by a crash");
        }
        if (typeof row.hash !== "string") {
          if (chained) return fail(expected, "a row without a hash appears after the chain began (inserted or rewritten row)");
          result.legacy_rows++;
          continue;
        }
        const seq = row.seq;
        if (typeof seq !== "number" || !Number.isSafeInteger(seq) || seq < 1) {
          return fail(expected, "the row has no valid seq");
        }
        if (rowHash(row) !== row.hash) {
          return fail(prev ? expected : seq, `hash mismatch: the content of row ${prev ? expected : seq} was altered after it was written`);
        }
        if (prev) {
          if (seq !== prev.seq + 1) {
            return fail(expected, `seq ${seq} follows seq ${prev.seq}: ${seq > prev.seq + 1 ? `row(s) ${expected} to ${seq - 1} are missing` : "rows are duplicated or out of order"}`);
          }
          if (row.prev_hash !== prev.hash) {
            return fail(seq, `prev_hash does not match the hash of seq ${prev.seq}: a row before this one was altered, removed or inserted`);
          }
        } else if (row.prev_hash !== GENESIS_HASH) {
          result.notes.push(`the chain in view starts at seq ${seq} and continues from an earlier segment that is not part of this check`);
        }
        if (result.first_seq === undefined) result.first_seq = seq;
        result.last_seq = seq;
        result.last_hash = row.hash;
        result.rows++;
        prev = { seq, hash: row.hash };
        chained = true;
      }
    }
    if (result.legacy_rows) result.notes.push(`${result.legacy_rows} row(s) written before the hash chain existed are not verifiable`);
    return result;
  }
}

const defaultLog = new AuditLog(HOME_DIR);

/** Append one row to the process-wide audit log (`<SWITCHBOARD_HOME>/audit.log`) and return its `seq`. */
export function audit(entry: AuditInput): number {
  return defaultLog.append(entry);
}

/** Verify the process-wide audit log. */
export function verifyAudit(opts: { all?: boolean } = {}): AuditVerifyResult {
  return defaultLog.verify(opts);
}

/** Most recent entries first. */
export function recentAudit(limit = 100): AuditEntry[] {
  return defaultLog.recent(limit);
}

/** Aggregated tool-call usage for the Usage page. Composio meters on tool calls; so do we. */
export interface UsageStats {
  total: number;
  /** Governance-decision tally (did we allow / deny / hold it?). `allow` = success + error. */
  allow: number;
  deny: number;
  approval_required: number;
  /** OUTCOME tally — what actually happened — so an allowed-but-failed call isn't counted as a
   *  win. `success + error === allow`; `denied === deny`; `approval_required` matches the decision. */
  outcomes: { success: number; error: number; denied: number; approval_required: number };
  /** Why failures happened: `SB_*` error-code counts, descending. Empty when nothing failed. */
  error_codes: { code: string; count: number }[];
  /** Tool-call counts per UTC day (YYYY-MM-DD), oldest first. */
  by_day: { day: string; count: number }[];
  /** Busiest tools, descending, capped. */
  top_tools: { tool: string; server: string; count: number }[];
  /** Per-server totals, descending. */
  by_server: { server: string; count: number }[];
}

/**
 * Aggregate the most recent `cap` rows (reading back through rotated segments). Local scale (a personal
 * log) makes this cheap; the cap is a runaway guard.
 */
export function usageStats(cap = 50_000): UsageStats {
  const empty: UsageStats = {
    total: 0, allow: 0, deny: 0, approval_required: 0,
    outcomes: { success: 0, error: 0, denied: 0, approval_required: 0 },
    error_codes: [], by_day: [], top_tools: [], by_server: [],
  };
  if (!existsSync(defaultLog.path) && defaultLog.rotatedFiles().length === 0) return empty;

  let allow = 0,
    deny = 0,
    approval = 0;
  const outcomes = { success: 0, error: 0, denied: 0, approval_required: 0 };
  const byDay = new Map<string, number>();
  const byTool = new Map<string, { server: string; count: number }>();
  const byServer = new Map<string, number>();
  const byErrorCode = new Map<string, number>();

  for (const line of defaultLog.linesNewestFirst(cap)) {
    let e: AuditEntry;
    try {
      e = JSON.parse(line) as AuditEntry;
    } catch {
      continue;
    }
    // A write-ahead attempt row is the announcement of a call, not a verdict: its result row is the one that counts.
    if (e.phase === "attempt") continue;
    if (e.decision === "allow") allow++;
    else if (e.decision === "deny") deny++;
    else if (e.decision === "approval_required") approval++;

    // Outcome is derived (decision + error), so an allowed-but-failed call lands in `error`, not `success`.
    outcomes[classifyOutcome(e)]++;
    if (e.error_code) byErrorCode.set(e.error_code, (byErrorCode.get(e.error_code) ?? 0) + 1);

    const day = (e.ts || "").slice(0, 10);
    if (day) byDay.set(day, (byDay.get(day) ?? 0) + 1);

    const toolKey = `${e.server}__${e.tool}`;
    const prev = byTool.get(toolKey);
    byTool.set(toolKey, { server: e.server, count: (prev?.count ?? 0) + 1 });

    if (e.server) byServer.set(e.server, (byServer.get(e.server) ?? 0) + 1);
  }

  return {
    total: allow + deny + approval,
    allow,
    deny,
    approval_required: approval,
    outcomes,
    error_codes: [...byErrorCode.entries()].map(([code, count]) => ({ code, count })).sort((a, b) => b.count - a.count),
    by_day: [...byDay.entries()].map(([day, count]) => ({ day, count })).sort((a, b) => a.day.localeCompare(b.day)),
    top_tools: [...byTool.entries()]
      .map(([key, v]) => ({ tool: key.includes("__") ? key.slice(key.indexOf("__") + 2) : key, server: v.server, count: v.count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 15),
    by_server: [...byServer.entries()].map(([server, count]) => ({ server, count })).sort((a, b) => b.count - a.count),
  };
}
