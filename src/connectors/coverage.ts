/**
 * Coverage (ADR local-composio, section 6.8): honest counts.
 *
 * "8,472 actions" and "1,600+ toolkits" are REGISTERED counts. Ours must mean connected and probed. So every
 * row of the R1 research checklists (one row per Composio action, 1,740 of them) is imported into a state:
 *
 *   unmapped             no reviewed endpoint mapping for it (an unreviewed fuzzy match counts as unmapped)
 *   mapped               the researcher mapped it to a provider endpoint (a coverage map, not a spec)
 *   mock_tested          our mock contract suite exercised it
 *   live_verified        an owner-run probe passed against the real provider, with a date and an account
 *   blocked_by_platform  the platform gates it (TikTok audit, Meta Live mode, X paid tier): never counted
 *   declined             we chose not to build it
 *   deprecated           Composio marks it deprecated (31 rows): excluded from the addressable total by name
 *
 * Only `live_verified` ever prints as "working". The state of a row is its base state from the import,
 * overridden by the newest line for it in the append-only `connectors/verification.ndjson`. A
 * `live_verified` line that has no account id or no date is ignored when counting, so a hand edit cannot
 * inflate the number, and a deprecated row cannot be promoted.
 *
 * The rows themselves are a local snapshot (`connectors/coverage-rows.json`) read from the checklist CSVs,
 * which carry identifiers only; they are not committed.
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { atomicWriteFileSync } from "../atomicfile.js";
import { VERIFICATION_STATES, type VerificationState } from "./toolkits.js";

/** R1 checklist toolkit name -> our toolkit slug, where they differ. */
export const R1_TOOLKIT_SLUG: Record<string, string> = { googledrive: "drive", twitter: "x" };

export const DEFAULT_CHECKLIST_DIR = "D:/agents/wiki/reference/mcp-switchboard-rea/checklists";

export interface CoverageRow {
  /** The R1 toolkit name (`googledrive`). */
  toolkit: string;
  /** Our toolkit slug (`drive`). */
  our_toolkit: string;
  /** The row's action identifier from the checklist. */
  slug: string;
  method: string;
  endpoint: string;
  basis: string;
  base_state: VerificationState;
  deprecated: boolean;
}

export interface LedgerLine {
  ts: string;
  /** A row slug. */
  id: string;
  toolkit: string;
  state: VerificationState;
  account?: string;
  note?: string;
}

export interface ImportReport {
  dir: string;
  files: number;
  rows: number;
  deprecated: number;
  by_basis: Record<string, number>;
  problems: string[];
}

export interface ToolkitCoverage {
  toolkit: string;
  our_toolkit: string;
  rows: number;
  counts: Record<VerificationState, number>;
  /** live_verified rows. The only number that is called working. */
  working: number;
  /** Rows that can be worked on: everything except deprecated. */
  addressable: number;
}

export interface CoverageReport {
  generated_at: string;
  toolkits: ToolkitCoverage[];
  total: ToolkitCoverage;
  deprecated_rows: string[];
  ignored_lines: string[];
}

const emptyCounts = (): Record<VerificationState, number> => Object.fromEntries(VERIFICATION_STATES.map((s) => [s, 0])) as Record<VerificationState, number>;

/** RFC 4180: quoted fields may hold commas, doubled quotes and newlines. */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  const src = text.replace(/^\uFEFF/, "");
  for (let i = 0; i < src.length; i++) {
    const ch = src[i]!;
    if (quoted) {
      if (ch === '"') {
        if (src[i + 1] === '"') {
          field += '"';
          i++;
        } else quoted = false;
      } else field += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ",") {
      row.push(field);
      field = "";
    } else if (ch === "\n" || ch === "\r") {
      if (ch === "\r" && src[i + 1] === "\n") i++;
      row.push(field);
      field = "";
      if (row.length > 1 || row[0] !== "") rows.push(row);
      row = [];
    } else field += ch;
  }
  if (field !== "" || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

/** Base state of one checklist row. */
export function baseState(r: { basis: string; method: string; endpoint: string; notes: string }): VerificationState {
  if (/^\s*deprecated action/i.test(r.notes)) return "deprecated";
  if (!r.method.trim() || !r.endpoint.trim()) return "unmapped";
  return r.basis === "A" || r.basis === "B" || r.basis === "R" ? "mapped" : "unmapped";
}

export class Coverage {
  private readonly rowsFile: string;
  private readonly ledgerFile: string;

  constructor(
    private readonly home: string,
    private readonly now: () => number = Date.now,
  ) {
    this.rowsFile = join(home, "connectors", "coverage-rows.json");
    this.ledgerFile = join(home, "connectors", "verification.ndjson");
  }

  /** Read every `<toolkit>.csv` (not the `_triggers` ones) in `dir` and keep them as the local row snapshot. */
  importCsv(dir: string): ImportReport {
    const report: ImportReport = { dir, files: 0, rows: 0, deprecated: 0, by_basis: {}, problems: [] };
    if (!existsSync(dir)) {
      report.problems.push(`checklist directory not found: ${dir}`);
      return report;
    }
    const rows: CoverageRow[] = [];
    for (const name of readdirSync(dir).sort()) {
      if (!name.endsWith(".csv") || name.endsWith("_triggers.csv")) continue;
      const parsed = parseCsv(readFileSync(join(dir, name), "utf8"));
      const header = parsed[0];
      if (!header) {
        report.problems.push(`${name}: empty`);
        continue;
      }
      const col = (n: string): number => header.indexOf(n);
      const need = ["toolkit", "action_slug", "http_method", "endpoint", "basis", "notes"].filter((n) => col(n) === -1);
      if (need.length) {
        report.problems.push(`${name}: missing column(s) ${need.join(", ")}`);
        continue;
      }
      report.files += 1;
      for (const r of parsed.slice(1)) {
        const get = (n: string): string => (r[col(n)] ?? "").trim();
        const slug = get("action_slug");
        if (!slug) {
          report.problems.push(`${name}: a row has no action_slug`);
          continue;
        }
        const toolkit = get("toolkit") || name.replace(/\.csv$/, "");
        const base = baseState({ basis: get("basis"), method: get("http_method"), endpoint: get("endpoint"), notes: get("notes") });
        rows.push({ toolkit, our_toolkit: R1_TOOLKIT_SLUG[toolkit] ?? toolkit, slug, method: get("http_method").toUpperCase(), endpoint: get("endpoint"), basis: get("basis"), base_state: base, deprecated: base === "deprecated" });
        report.by_basis[get("basis") || "-"] = (report.by_basis[get("basis") || "-"] ?? 0) + 1;
      }
    }
    const seen = new Set<string>();
    for (const r of rows) {
      const k = `${r.toolkit}:${r.slug}`;
      if (seen.has(k)) report.problems.push(`duplicate row ${k}`);
      seen.add(k);
    }
    report.rows = rows.length;
    report.deprecated = rows.filter((r) => r.deprecated).length;
    mkdirSync(join(this.home, "connectors"), { recursive: true });
    atomicWriteFileSync(this.rowsFile, JSON.stringify({ imported_at: new Date(this.now()).toISOString(), source_dir: dir, rows }), { mode: 0o600 });
    return report;
  }

  rows(): CoverageRow[] {
    try {
      return (JSON.parse(readFileSync(this.rowsFile, "utf8")) as { rows: CoverageRow[] }).rows;
    } catch {
      return [];
    }
  }

  ledger(): LedgerLine[] {
    if (!existsSync(this.ledgerFile)) return [];
    const out: LedgerLine[] = [];
    for (const line of readFileSync(this.ledgerFile, "utf8").split("\n")) {
      if (!line.trim()) continue;
      try {
        out.push(JSON.parse(line) as LedgerLine);
      } catch {
        /* a torn line is skipped, never fatal */
      }
    }
    return out;
  }

  /** Append one state line. `live_verified` needs a connected account id; it is dated by the clock. */
  mark(id: string, state: VerificationState, opts: { toolkit?: string; account?: string; note?: string } = {}): LedgerLine {
    if (!(VERIFICATION_STATES as readonly string[]).includes(state)) throw new Error(`'${state}' is not a verification state (${VERIFICATION_STATES.join(", ")})`);
    const row = this.rows().find((r) => r.slug.toLowerCase() === id.toLowerCase());
    if (!row) throw new Error(`no checklist row '${id}': run \`switchboard coverage import\` first, or check the name`);
    if (state === "live_verified" && !/^ca_[A-Za-z0-9]+$/.test(opts.account ?? "")) throw new Error("live_verified needs --account <ca_...>: a row counts as working only with the account that proved it");
    if (row.deprecated && state !== "deprecated") throw new Error(`'${row.slug}' is deprecated and cannot be marked ${state}`);
    const line: LedgerLine = { ts: new Date(this.now()).toISOString(), id: row.slug, toolkit: row.toolkit, state, ...(opts.account ? { account: opts.account } : {}), ...(opts.note ? { note: opts.note.slice(0, 200) } : {}) };
    mkdirSync(join(this.home, "connectors"), { recursive: true });
    appendFileSync(this.ledgerFile, `${JSON.stringify(line)}\n`, { mode: 0o600 });
    return line;
  }

  /** The state of every row now: base state overridden by its newest valid ledger line. */
  states(): { row: CoverageRow; state: VerificationState; line?: LedgerLine }[] {
    const latest = new Map<string, LedgerLine>();
    const ignored: string[] = [];
    for (const l of this.ledger()) {
      const key = String(l.id).toLowerCase();
      if (!(VERIFICATION_STATES as readonly string[]).includes(l.state)) continue;
      if (l.state === "live_verified" && (!l.account || !l.ts || Number.isNaN(Date.parse(l.ts)))) {
        ignored.push(l.id);
        continue;
      }
      latest.set(key, l);
    }
    this.lastIgnored = ignored;
    return this.rows().map((row) => {
      const l = latest.get(row.slug.toLowerCase());
      if (row.deprecated) return { row, state: "deprecated" as const };
      return l ? { row, state: l.state, line: l } : { row, state: row.base_state };
    });
  }

  private lastIgnored: string[] = [];

  report(only?: string): CoverageReport {
    const states = this.states();
    const byToolkit = new Map<string, ToolkitCoverage>();
    const total: ToolkitCoverage = { toolkit: "total", our_toolkit: "total", rows: 0, counts: emptyCounts(), working: 0, addressable: 0 };
    const keep = (r: CoverageRow): boolean => !only || r.toolkit === only || r.our_toolkit === only;
    for (const { row, state } of states) {
      if (!keep(row)) continue;
      let t = byToolkit.get(row.toolkit);
      if (!t) {
        t = { toolkit: row.toolkit, our_toolkit: row.our_toolkit, rows: 0, counts: emptyCounts(), working: 0, addressable: 0 };
        byToolkit.set(row.toolkit, t);
      }
      for (const bag of [t, total]) {
        bag.rows += 1;
        bag.counts[state] += 1;
        if (state === "live_verified") bag.working += 1;
        if (state !== "deprecated") bag.addressable += 1;
      }
    }
    return {
      generated_at: new Date(this.now()).toISOString(),
      toolkits: [...byToolkit.values()].sort((a, b) => a.toolkit.localeCompare(b.toolkit)),
      total,
      deprecated_rows: states.filter((s) => keep(s.row) && s.row.deprecated).map((s) => s.row.slug).sort(),
      ignored_lines: [...new Set(this.lastIgnored)],
    };
  }

  /** The verification summary of one of our toolkits (rows grouped by our slug). */
  summary(ourToolkit: string): Record<VerificationState, number> {
    const counts = emptyCounts();
    for (const { row, state } of this.states()) if (row.our_toolkit === ourToolkit) counts[state] += 1;
    return counts;
  }
}

/** The text `switchboard coverage` prints. The word "working" appears only beside the live_verified count. */
export function formatReport(r: CoverageReport): string {
  const head = ["toolkit", "rows", "unmapped", "mapped", "mock_tested", "live_verified", "blocked", "declined", "deprecated", "working"];
  const line = (t: ToolkitCoverage): string[] => [
    t.our_toolkit === t.toolkit || t.toolkit === "total" ? t.toolkit : `${t.toolkit} (${t.our_toolkit})`,
    String(t.rows),
    String(t.counts.unmapped),
    String(t.counts.mapped),
    String(t.counts.mock_tested),
    String(t.counts.live_verified),
    String(t.counts.blocked_by_platform),
    String(t.counts.declined),
    String(t.counts.deprecated),
    `${t.working} of ${t.addressable}`,
  ];
  const rows = [head, ...r.toolkits.map(line), line(r.total)];
  const widths = head.map((_, i) => Math.max(...rows.map((x) => x[i]!.length)));
  const lines = rows.map((x) => x.map((c, i) => (i === 0 ? c.padEnd(widths[i]!) : c.padStart(widths[i]!))).join("  "));
  const tail = [
    "",
    `working = rows proven live by an owner-run probe (live_verified): ${r.total.working} of ${r.total.addressable} addressable rows.`,
    "Registered or mapped rows are not working rows. mock_tested means a mock passed, not the real provider.",
  ];
  if (r.ignored_lines.length) tail.push(`ignored ${r.ignored_lines.length} live_verified line(s) with no account or no date: ${r.ignored_lines.slice(0, 5).join(", ")}`);
  return [...lines, ...tail].join("\n");
}
