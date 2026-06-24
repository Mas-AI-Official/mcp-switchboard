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

/** How an upstream MCP server is sourced. `council` is synthetic — built in-process from
 *  `settings.council`, never declared in the user's `servers:` array. */
export type ServerSource = "npx" | "binary" | "remote" | "app2mcp" | "council";

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
  /** `/settings/usage` (Logs) — audit-capture controls. */
  logs?: {
    /** Capture (redacted, size-capped) request args + responses for allowed calls. Off by default. */
    capture_io?: boolean;
  };
  /** Cross-provider "council" relay tools (`council_consult` / `council_debate`). Off by default. */
  council?: CouncilConfig;
  /**
   * Built-in OAuth 2.1 + PKCE Authorization Server for the `/mcp` endpoint. Off by default.
   * Required for hosted MCP clients (e.g. claude.ai web) that can only reach Switchboard
   * through a public HTTPS tunnel and refuse to connect without OAuth + DCR.
   */
  oauth_server?: OAuthServerConfig;
}

/**
 * Turns the dashboard's own `/mcp` endpoint into an OAuth 2.1 Authorization + Resource
 * Server (RFC 8414/9728 metadata, RFC 7591 dynamic client registration, mandatory PKCE,
 * RFC 8707 resource binding). Off by default; fails closed if `public_url` is missing.
 */
export interface OAuthServerConfig {
  /** Master switch. When false (default) no OAuth routes are mounted. */
  enabled?: boolean;
  /**
   * Public HTTPS origin the tunnel exposes (e.g. `https://abc.trycloudflare.com`). Becomes
   * the OAuth issuer and the base of the canonical `/mcp` audience. REQUIRED when enabled —
   * the loopback address can't be the issuer for a cloud client.
   */
  public_url?: string;
  /** Access-token lifetime in seconds. Default 3600 (1h). */
  access_token_ttl?: number;
  /** Refresh-token lifetime in seconds. Default 14 days. 0 disables refresh-token issuance. */
  refresh_token_ttl?: number;
  /** Show the human consent screen on every authorization. Default true (governance-first). */
  consent?: boolean;
}

/** One LLM provider the council can relay to. */
export interface CouncilProviderConfig {
  /**
   * `${vault:..}`/`${env:..}` reference to the provider API key. MUST be a reference,
   * never a literal key — Switchboard never custodies plaintext secrets.
   */
  api_key_ref: string;
  /** Default model id used when a call omits `model`. Config-driven to avoid hardcoded staleness. */
  default_model: string;
  /** Optional base URL override (e.g. a proxy or Azure/OpenAI-compatible gateway). */
  base_url?: string;
}

/**
 * `council_consult` proxies one prompt to the *other* provider and returns the reply;
 * `council_debate` runs a bounded multi-round exchange between both and synthesizes.
 * Both flow through the normal policy → approval → audit path as a synthetic in-process
 * MCP server. Outbound + metered, so it is off by default and approval-gateable.
 */
export interface CouncilConfig {
  /** Master switch. When false (default) no council tools are mounted. */
  enabled?: boolean;
  /** Providers the council may relay to. `council_debate` needs at least two configured. */
  providers?: {
    anthropic?: CouncilProviderConfig;
    openai?: CouncilProviderConfig;
  };
  /** Hard ceiling on `council_debate` rounds (loop guard). Default 3, max 10. */
  max_rounds?: number;
  /** `max_tokens` cap applied to every provider call (cost/loop guard). Default 2048. */
  token_budget?: number;
  /** Require an approval confirm for every council call. Default false (off-by-default feature already opts in). */
  require_approval?: boolean;
}

export interface SwitchboardConfig {
  gateway: GatewayConfig;
  vault: VaultConfig;
  servers: ServerConfig[];
  /** Dashboard-editable settings. Optional so pre-existing configs remain valid. */
  settings?: SettingsConfig;
}
