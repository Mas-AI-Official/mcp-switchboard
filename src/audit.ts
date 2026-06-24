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
