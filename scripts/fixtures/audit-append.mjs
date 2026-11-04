// A worker process for verify-audit-chain.mjs: appends N rows to the audit log of a shared home through
// its own AuditLog instance, so several of these prove that the cross-process lock keeps one chain.
//
// argv: <home> <label> <count>
import { AuditLog } from "../../dist/audit.js";

const [home, label, count] = process.argv.slice(2);
const log = new AuditLog(home);
let errors = 0;
for (let i = 0; i < Number(count); i++) {
  try {
    log.append({ server: "worker", tool: `${label}_${i}`, scope: "read", decision: "allow" });
  } catch {
    errors++;
  }
}
console.log(JSON.stringify({ label, errors }));
