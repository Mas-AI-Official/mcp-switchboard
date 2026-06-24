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
}

export function audit(entry: Omit<AuditEntry, "ts">): void {
  if (!existsSync(HOME_DIR)) mkdirSync(HOME_DIR, { recursive: true });
  const row: AuditEntry = { ts: new Date().toISOString(), ...entry };
  appendFileSync(AUDIT_PATH, JSON.stringify(row) + "\n");
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
