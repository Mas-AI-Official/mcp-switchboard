/**
 * Public library surface. Most users run the `switchboard` CLI, but the gateway is
 * also embeddable — import these to mount Switchboard inside another Node process.
 */

export { Gateway, createGateway } from "./gateway.js";
export { Registry, type MountedServer } from "./registry.js";
export { Router } from "./router.js";
export { Vault, HOME_DIR } from "./vault.js";
export { loadConfig, writeConfig, starterConfig } from "./config.js";
export { evaluate, inferScope, type PolicyDecision } from "./policy.js";
export { approve, setStdioActive } from "./approval.js";
export { audit, recentAudit, type AuditEntry } from "./audit.js";
export { startDashboard, type DashboardHandle } from "./dashboard.js";
export { dashboardHtml } from "./console.js";
export type * from "./types.js";
