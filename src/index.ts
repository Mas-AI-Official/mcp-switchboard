/**
 * Public library surface. Most users run the `switchboard` CLI, but the gateway is
 * also embeddable — import these to mount MCP Switchboard inside another Node process.
 */

export { Gateway, createGateway } from "./gateway.js";
export { Registry, type MountedServer } from "./registry.js";
export { Router } from "./router.js";
export { Vault, HOME_DIR } from "./vault.js";
export { OAuthStore, type ProviderStatus } from "./oauth.js";
export { buildOpenApiServer, type OpenApiServer } from "./openapi.js";
export { loadConfig, writeConfig, starterConfig } from "./config.js";
export { evaluate, inferScope, type PolicyDecision } from "./policy.js";
export { approve, setStdioActive } from "./approval.js";
export { audit, recentAudit, type AuditEntry } from "./audit.js";
export { startDashboard, type DashboardHandle } from "./dashboard.js";
export {
  loadCatalog,
  writeCatalog,
  ingestCatalog,
  ingestCatalogVerbose,
  queryCatalog,
  defaultCatalogPath,
  type Toolkit,
  type ToolkitMount,
  type CatalogSnapshot,
} from "./catalog.js";
export type * from "./types.js";
