/**
 * Append-only audit log. Every policy verdict (allow / deny / approval) is written
 * as one JSON line to `~/.switchboard/audit.log`. The dashboard tails it.
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { HOME_DIR } from "./vault.js";

const AUDIT_PATH = join(HOME_DIR, "audit.log");

export interface AuditEntry {
  ts: string;
  server: string;
  tool: string;
  scope: string;
  decision: "allow" | "deny" | "approval_required";
  reason?: string;
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
}

export function audit(entry: Omit<AuditEntry, "ts">): void {
  if (!existsSync(HOME_DIR)) mkdirSync(HOME_DIR, { recursive: true });
  const row: AuditEntry = { ts: new Date().toISOString(), ...entry };
  appendFileSync(AUDIT_PATH, JSON.stringify(row) + "\n");
}

/** Key names whose values are masked before anything is written to disk. */
const SECRET_KEY = /token|secret|password|api[_-]?key|authorization/i;
/** Hard ceiling on a captured value's serialized size, so a big payload can't bloat the log. */
const CAPTURE_CAP_BYTES = 4096;

/**
 * Prepare a value for opt-in I/O capture: deep-clone with secret-looking keys masked, then
 * cap the serialized size. Returns a truncation marker rather than a giant blob when over cap.
 * Capture is OFF by default; this only runs when the operator sets settings.logs.capture_io.
 *
 * `secretKeys` is an exact-match set of key names that MUST be redacted regardless of how they
 * look — the router passes the injected-arg key names so a `${vault:..}`/`${oauth:..}` secret that
 * was injected under an innocuous param name (e.g. `q`) never reaches the log in cleartext. The
 * name-pattern heuristic (SECRET_KEY) still covers conventionally-named secrets in untouched args.
 */
export function sanitizeForAudit(value: unknown, secretKeys?: ReadonlySet<string>): unknown {
  const redacted = redact(value, 0, secretKeys);
  let serialized: string;
  try {
    serialized = JSON.stringify(redacted);
  } catch {
    return "[uncapturable]";
  }
  if (serialized !== undefined && serialized.length > CAPTURE_CAP_BYTES) {
    return { _truncated: serialized.length, preview: serialized.slice(0, CAPTURE_CAP_BYTES) };
  }
  return redacted;
}

function redact(value: unknown, depth: number, secretKeys?: ReadonlySet<string>): unknown {
  if (depth > 6 || value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1, secretKeys));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[k] = SECRET_KEY.test(k) || secretKeys?.has(k) ? "[redacted]" : redact(v, depth + 1, secretKeys);
  }
  return out;
}

/** Most recent entries first. */
export function recentAudit(limit = 100): AuditEntry[] {
  if (!existsSync(AUDIT_PATH)) return [];
  const lines = readFileSync(AUDIT_PATH, "utf8").trim().split("\n").filter(Boolean);
  return lines
    .slice(-limit)
    .map((line) => {
      try {
        return JSON.parse(line) as AuditEntry;
      } catch {
        return null;
      }
    })
    .filter((e): e is AuditEntry => e !== null)
    .reverse();
}

/** Aggregated tool-call usage for the Usage page. Composio meters on tool calls; so do we. */
export interface UsageStats {
  total: number;
  allow: number;
  deny: number;
  approval_required: number;
  /** Tool-call counts per UTC day (YYYY-MM-DD), oldest first. */
  by_day: { day: string; count: number }[];
  /** Busiest tools, descending, capped. */
  top_tools: { tool: string; server: string; count: number }[];
  /** Per-server totals, descending. */
  by_server: { server: string; count: number }[];
}

/**
 * Read the whole audit log and aggregate it. Local scale (a personal log) makes a
 * full read cheap; we cap the scan to the last `cap` lines as a runaway guard.
 */
export function usageStats(cap = 50_000): UsageStats {
  const empty: UsageStats = { total: 0, allow: 0, deny: 0, approval_required: 0, by_day: [], top_tools: [], by_server: [] };
  if (!existsSync(AUDIT_PATH)) return empty;
  const lines = readFileSync(AUDIT_PATH, "utf8").trim().split("\n").filter(Boolean).slice(-cap);

  let allow = 0,
    deny = 0,
    approval = 0;
  const byDay = new Map<string, number>();
  const byTool = new Map<string, { server: string; count: number }>();
  const byServer = new Map<string, number>();

  for (const line of lines) {
    let e: AuditEntry;
    try {
      e = JSON.parse(line) as AuditEntry;
    } catch {
      continue;
    }
    if (e.decision === "allow") allow++;
    else if (e.decision === "deny") deny++;
    else if (e.decision === "approval_required") approval++;

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
    by_day: [...byDay.entries()].map(([day, count]) => ({ day, count })).sort((a, b) => a.day.localeCompare(b.day)),
    top_tools: [...byTool.entries()]
      .map(([key, v]) => ({ tool: key.includes("__") ? key.slice(key.indexOf("__") + 2) : key, server: v.server, count: v.count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 15),
    by_server: [...byServer.entries()].map(([server, count]) => ({ server, count })).sort((a, b) => b.count - a.count),
  };
}
