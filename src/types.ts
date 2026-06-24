/**
 * Shared types for Switchboard.
 *
 * The shapes here mirror `switchboard.config.yaml` 1:1. `config.ts` validates the
 * raw YAML against a zod schema and returns `SwitchboardConfig`; everything else
 * in the gateway consumes these typed structures.
 */

/** Access level a tool is allowed to operate at. Ordered: read < write < full. */
export type Scope = "read" | "write" | "full";

/** Per-tool override inside a server block. */
export interface ToolOverride {
  /** `false` hard-blocks the tool — it never reaches the agent or the upstream. */
  enabled?: boolean;
  /** Pin the scope for this tool instead of inferring it from the name. */
  policy?: Scope;
}

/** Approval-gate config for a server. */
export interface ApprovalConfig {
  /** Calls whose scope is in this list require a human confirm before forwarding. */
  require_for?: Scope[];
}

/** How an upstream MCP server is sourced. */
export type ServerSource = "npx" | "binary" | "remote" | "app2mcp";

/** One mounted (or mountable) upstream MCP server. */
export interface ServerConfig {
  /** Stable id; becomes the tool namespace, e.g. `github__create_issue`. */
  id: string;
  source: ServerSource;
  /** Whether this server is mounted at startup. Toggled live from the dashboard. */
  enabled: boolean;
  /** Scope ceiling for the whole server. Falls back to `gateway.default_policy` when omitted. */
  policy?: Scope;

  // --- stdio sources (npx | binary) ---
  /** npm package to run via `npx -y <package>` (source: npx). */
  package?: string;
  /** Executable to launch (source: binary). */
  command?: string;
  /** Extra args appended to the launch command. */
  args?: string[];

  // --- remote source ---
  /** Streamable HTTP endpoint of a hosted MCP server (source: remote). */
  url?: string;
  /** Auth strategy for a remote server. */
  auth?: "none" | "oauth" | "bearer";

  // --- app2mcp source (roadmap) ---
  /** Path to an OpenAPI/Swagger spec to generate an MCP server from. */
  openapi?: string;
  /** Base URL the generated server calls. */
  base_url?: string;

  // --- shared ---
  /** Secrets injected into the upstream env. Values may use `${vault:..}`/`${env:..}`. */
  credentials?: Record<string, string>;
  /** Plain env vars injected into the upstream process (also supports refs). */
  env?: Record<string, string>;
  /** Per-tool enable/scope overrides keyed by the upstream tool name. */
  tools?: Record<string, ToolOverride>;
  /** Approval gates for this server. */
  approval?: ApprovalConfig;
}

export interface GatewayConfig {
  /** Which transports the gateway exposes to agent clients. */
  transport: ("stdio" | "http")[];
  http: {
    host: string;
    port: number;
    /**
     * Whether the `/mcp` endpoint requires a bearer API key.
     * - `auto` (default): require iff `host` is not a loopback address.
     * - `always`: require even on localhost.
     * - `never`: serve without auth (only safe behind another gate).
     */
    require_auth: "auto" | "always" | "never";
  };
  /** How upstream tools are presented to agents. */
  tool_exposure: "namespaced" | "flat" | "search";
  /** Scope ceiling applied to any server that omits its own `policy`. */
  default_policy: Scope;
}

export interface VaultConfig {
  /** `encrypted-file` = AES-256-GCM blob in ~/.switchboard. `env` = read from process env only. */
  backend: "encrypted-file" | "env";
}

/** Dashboard-editable presentation/integration settings (the Composio "Settings" pages). */
export interface SettingsConfig {
  /** `/settings/general` — naming shown across the dashboard. Cosmetic; no effect on routing. */
  general?: {
    organization_name?: string;
    project_name?: string;
  };
  /** `/settings/auth-screen` — branding for the OAuth consent/callback landing page. */
  auth_screen?: {
    title?: string;
    subtitle?: string;
    logo_url?: string;
    /** Hex accent color, e.g. `#2dd4bf`. */
    accent_color?: string;
    support_url?: string;
  };
  /** `/settings/webhook` — optional outbound notifications when a tool call is decided. */
  webhook?: {
    enabled?: boolean;
    /** HTTPS endpoint to POST audit events to. */
    url?: string;
    /** Which audit decisions to deliver. Empty/omitted = all. */
    events?: ("allow" | "deny" | "approval_required")[];
    /** `${vault:..}` reference to an HMAC-SHA256 signing secret (sent as `X-Switchboard-Signature`). */
    secret_ref?: string;
  };
}

export interface SwitchboardConfig {
  gateway: GatewayConfig;
  vault: VaultConfig;
  servers: ServerConfig[];
  /** Dashboard-editable settings. Optional so pre-existing configs remain valid. */
  settings?: SettingsConfig;
}
