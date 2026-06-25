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
  /** Replace the description agents see for this tool (the upstream call is unaffected). */
  description_override?: string;
  /** Parameters dropped from the exposed input schema; also filtered out of `required`. */
  drop_params?: string[];
  /** Hide/rename params + trim description on the exposed schema. Overrides the server-level
   *  modifier per field (lists union, `trim_description` takes the tool value). */
  schema_modifiers?: SchemaModifier;
  /** Force argument values before forwarding. Values may be `${vault:..}`/`${env:..}` refs or
   *  literals; the resolved value always wins over an agent-supplied one. Keys are UPSTREAM
   *  parameter names (apply after any rename). */
  inject_args?: Record<string, string>;
  /** Redact top-level JSON fields from this tool's response before it reaches the agent. */
  redact_response?: ResponseRedaction;
  /** Free-text tags that boost this tool in `find_tools` keyword ranking. */
  tags?: string[];
  /** Mark this tool important so it ranks higher in `find_tools` search. */
  important?: boolean;
  /** Per-tool rate limits + spend budgets. Stacks with `server.limits` and `settings.limits` —
   *  a call must pass all three. The tightest binding limit is reported when a call is denied. */
  limits?: LimitSpec;
  /** Abstract per-call cost charged against any `cost_per_*` budget at every level. Unitless —
   *  use it to weight pricier tools (a council fan-out, a paid API) more heavily. Default 0. */
  cost?: number;
}

/**
 * Rate limits and spend budgets for one level (global / server / tool). Every field is an optional
 * ceiling; only the windows you set are enforced. `per_*` cap call COUNT; `cost_per_*` cap the sum of
 * each call's tool `cost`. Limits fail closed and stack across levels so a runaway agent loop or a
 * pricey cross-provider council can't quietly drain your API budget.
 */
export interface LimitSpec {
  /** Max calls per rolling minute. */
  per_minute?: number;
  /** Max calls per rolling hour. */
  per_hour?: number;
  /** Max calls per rolling day. */
  per_day?: number;
  /** Max summed tool `cost` per rolling minute. */
  cost_per_minute?: number;
  /** Max summed tool `cost` per rolling hour. */
  cost_per_hour?: number;
  /** Max summed tool `cost` per rolling day. */
  cost_per_day?: number;
}

/**
 * Per-server circuit-breaker tuning. A reliability control that watches each upstream's TRANSPORT
 * health (timeouts/throws, NOT well-formed tool error results) and, after repeated failures, fails
 * fast with an honest `SB_UPSTREAM_UNAVAILABLE` instead of paying a full `call_timeout_ms` on every
 * call to a dead server. Opt-in: set at `settings.resilience` for a gateway-wide default and/or per
 * `server.resilience` to override or disable. Off unless `enabled` resolves true.
 */
export interface ResilienceConfig {
  /** Master switch. At `settings.resilience` it defaults the whole gateway; per server it overrides
   *  (set `false` to exempt one server from a global default). */
  enabled?: boolean;
  /** Consecutive transport failures before the breaker opens. Default 5. */
  failure_threshold?: number;
  /** Seconds the breaker stays open before it releases one probe call. Default 30. */
  cooldown_seconds?: number;
}

/**
 * Self-healing mount policy. When an upstream fails to mount at boot, the Gateway retries it in
 * the background on a capped exponential backoff (computed in `retry.ts`) rather than leaving it
 * dead until restart. Opt-out via `enabled: false`; every field defaults (see `DEFAULT_MOUNT_RETRY`).
 */
export interface MountRetryConfig {
  /** Master switch. Default true — a failed mount self-heals unless explicitly disabled. */
  enabled?: boolean;
  /** Total background attempts after the initial failure. 0 disables retry. Default 5. */
  max_attempts?: number;
  /** Delay before the first retry, in ms. Default 1000. */
  base_ms?: number;
  /** Multiplier applied to the delay each subsequent attempt. Default 2. */
  factor?: number;
  /** Ceiling on any single delay, in ms — backoff never grows past this. Default 30000. */
  max_ms?: number;
}

/** Schema-shaping rules applied to a tool's exposed input schema before agents see it. */
export interface SchemaModifier {
  /** Parameters removed from the exposed schema (and from `required`). */
  hide_params?: string[];
  /**
   * Rename exposed parameters, e.g. `{ owner: "org" }` shows `org` to the agent. The gateway
   * reverse-maps the renamed key back to the upstream name before forwarding, so the upstream
   * keeps receiving its real parameter name.
   */
  rename_params?: Record<string, string>;
  /** Truncate the tool description to at most N characters. */
  trim_description?: number;
}

/** Top-level response-field redaction applied after a successful tool call. */
export interface ResponseRedaction {
  /** Top-level JSON keys to remove (or mask) in the tool's text result. */
  fields?: string[];
  /** When set, replace each field's value with this string; when omitted, the key is deleted. */
  replace_with?: string;
}

/**
 * Declarative auth injection for a server. Resolved per call so OAuth/vault values stay fresh,
 * then mapped to the right HTTP header (remote/app2mcp/http-tool) or env var (stdio). All `*_ref`
 * fields accept `${vault:..}`/`${env:..}` references — Switchboard never custodies a plaintext key.
 */
export type AuthScheme =
  | { kind: "bearer"; ref: string }
  | { kind: "api_key"; ref: string; header?: string; query?: string }
  | { kind: "basic"; username_ref: string; password_ref: string }
  | { kind: "header"; name: string; ref: string };

/** One hand-declared HTTP endpoint exposed as a governed MCP tool (`source: http-tool`). */
export interface HttpToolDef {
  /** Tool name as agents see it (namespaced under the server id). */
  name: string;
  /** Human description shown to agents. */
  description?: string;
  /** HTTP method; also derives the scope ceiling (GET/HEAD→read, DELETE→full, else write). */
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD" | "OPTIONS";
  /** Path appended to the server `base_url` (e.g. `/v1/items/{id}`). `{name}` segments are filled
   *  from same-named args. Provide this OR an absolute `url`. */
  path?: string;
  /** Absolute URL to call instead of `base_url` + `path`. */
  url?: string;
  /** JSON Schema for the tool's arguments. Defaults to an open object when omitted. */
  inputSchema?: Record<string, unknown>;
  /** Per-tool scope ceiling. Only TIGHTENS the verb-derived scope; never relaxes a DELETE to read. */
  scope?: Scope;
}

/** Approval-gate config for a server. */
export interface ApprovalConfig {
  /** Calls whose scope is in this list require a human confirm before forwarding. */
  require_for?: Scope[];
}

/** How an upstream MCP server is sourced. `council` is synthetic — built in-process from
 *  `settings.council`, never declared in the user's `servers:` array. */
export type ServerSource =
  | "npx"
  | "binary"
  | "remote"
  | "app2mcp"
  | "http-tool"
  | "council";

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

  // --- app2mcp source ---
  /** Path to an OpenAPI/Swagger spec to generate an MCP server from. */
  openapi?: string;
  /** Base URL the generated server calls (also the base for `http-tool` relative paths). */
  base_url?: string;

  // --- http-tool source ---
  /** Hand-declared HTTP endpoints exposed as governed MCP tools (source: http-tool). */
  http_tools?: HttpToolDef[];

  // --- auth + schema shaping (any source) ---
  /**
   * Declarative auth injection resolved per call and mapped to a header (remote/app2mcp/http-tool)
   * or env var (stdio). Higher-level alternative to hand-writing `credentials`/`env` entries.
   */
  auth_scheme?: AuthScheme;
  /** `full` (default) exposes every input property; `required_only` slims schemas to required params. */
  schema_mode?: "full" | "required_only";
  /** Server-wide schema shaping (hide/rename params, trim descriptions); merged with per-tool modifiers. */
  schema_modifiers?: SchemaModifier;
  /** Server-wide forced args (upstream-named keys); per-tool `inject_args` overrides on key collision. */
  inject_args?: Record<string, string>;
  /** Server-wide response-field redaction; a per-tool `redact_response` overrides it. */
  redact_response?: ResponseRedaction;

  // --- shared ---
  /** Secrets injected into the upstream env. Values may use `${vault:..}`/`${env:..}`. */
  credentials?: Record<string, string>;
  /** Plain env vars injected into the upstream process (also supports refs). */
  env?: Record<string, string>;
  /** Per-tool enable/scope overrides keyed by the upstream tool name. */
  tools?: Record<string, ToolOverride>;
  /** Approval gates for this server. */
  approval?: ApprovalConfig;
  /** Server-wide rate limits + spend budgets. Stacks under `settings.limits` and over each tool's
   *  `limits` — a call must pass the tool, server, and global ceilings it touches. */
  limits?: LimitSpec;
  /** Per-server circuit-breaker override. Overrides (or, with `enabled:false`, opts out of) the
   *  gateway-wide `settings.resilience` default for this server only. */
  resilience?: ResilienceConfig;
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
  /**
   * Poll-first triggers: periodically call a read-scoped tool and fire a local + (optional)
   * webhook event when its result changes. NAT-friendly (outbound poll, no inbound port). Off
   * by default. See `TriggersConfig`.
   */
  triggers?: TriggersConfig;
  /**
   * Hard wall-clock timeout (ms) applied to every upstream tool call. A slow or hung upstream is
   * cut off and surfaced as an `SB_UPSTREAM_TIMEOUT` error instead of blocking the agent forever.
   * Omitted = no Switchboard-imposed timeout (the transport's own default applies).
   */
  call_timeout_ms?: number;
  /**
   * Named, switchable VIEWS over the configured servers/tools. A profile is NOT a new server —
   * it narrows which already-configured tools are exposed (e.g. a "read-only" profile, a
   * "coding" profile that hides email tools) and can cap the maximum scope every tool runs at.
   * Switch with the `SWITCHBOARD_PROFILE` env var or `active_profile`; omit both = no profile
   * (every enabled tool is exposed, fully backward compatible). See `ProfileConfig`.
   */
  profiles?: Record<string, ProfileConfig>;
  /**
   * The profile applied when `SWITCHBOARD_PROFILE` is unset. Must name a key in `profiles`.
   * Omitted = no profile is active. The env var always wins over this.
   */
  active_profile?: string;
  /**
   * Global rate limits + spend budgets applied to EVERY tool call across all servers. The outermost
   * of the three stacking levels (global > server > tool): a call must pass this ceiling plus any
   * server- and tool-level limit it touches. Fail-closed; denied/failed calls still count. Use it as
   * a blast-radius cap on a runaway agent loop or total cross-provider council spend.
   */
  limits?: LimitSpec;
  /**
   * Gateway-wide circuit-breaker default. Set `enabled: true` to give every upstream a per-server
   * breaker that fails fast (with `SB_UPSTREAM_UNAVAILABLE`) after repeated transport failures
   * instead of hanging on a dead server. Override or exempt individual servers via `server.resilience`.
   */
  resilience?: ResilienceConfig;
  /**
   * Self-healing mounts. When a server fails to mount at boot (transient DNS, an upstream still
   * warming up, a stdio-child race), Switchboard retries it in the background on a capped
   * exponential backoff instead of leaving it dead until restart. On by default; set
   * `enabled: false` to disable, or tune the schedule. See `MountRetryConfig`.
   */
  mount_retry?: MountRetryConfig;
}

/**
 * A profile is a named filter over the already-configured servers/tools — a saved "view" the
 * operator can switch between without editing server blocks. It controls visibility (which
 * servers/tools are exposed) and an optional scope ceiling (the hardest scope any tool may run
 * at while this profile is active). It never grants access a server block didn't already allow:
 * a profile can only ever HIDE tools and LOWER scope, never reveal a disabled tool or raise a
 * server's policy. Resolution order for the active profile: `SWITCHBOARD_PROFILE` env var, then
 * `settings.active_profile`, then none.
 */
export interface ProfileConfig {
  /** Human-readable note shown in `switchboard profile list` and the dashboard. */
  description?: string;
  /**
   * Server-id allowlist. When present, ONLY these servers are exposed (others are hidden
   * wholesale). Omitted/empty = every enabled server is in scope (subject to `tools`).
   */
  servers?: string[];
  /**
   * Exposed-tool allowlist, matched against the EXPOSED name (`serverId__toolName` in
   * namespaced mode, the bare tool name in flat mode). When present, ONLY tools whose exposed
   * name is listed are visible. Omitted/empty = all tools of the in-scope servers are visible.
   */
  tools?: string[];
  /**
   * Exposed-tool denylist. Tools whose exposed name is listed are hidden even if `tools`/`servers`
   * would otherwise expose them. Denylist beats allowlist.
   */
  exclude_tools?: string[];
  /**
   * Scope ceiling for this profile. Every tool runs at the TIGHTER of its server ceiling and
   * this value, so a `read` profile forces read-only across the board regardless of server policy.
   * Omitted = no extra cap (the server/gateway ceiling stands).
   */
  policy?: Scope;
}

/**
 * Poll-first triggers. Each enabled definition is polled on its own interval by calling a
 * read-scoped tool through the SAME policy → approval → audit path as any agent call; when the
 * result changes (a new list item, or a changed whole-response hash) a `switchboard.trigger`
 * event is recorded locally and, if `settings.webhook` is enabled, delivered to the operator's
 * webhook. Local-first by design: the poll is an outbound call, so no inbound port or public
 * tunnel is ever required (unlike inbound webhooks from a provider).
 */
export interface TriggersConfig {
  /** Master switch. When false (default) no polling loop runs. */
  enabled?: boolean;
  /** Default seconds between polls for definitions that omit their own `interval_seconds`. Default 60. */
  poll_interval_seconds?: number;
  /** The triggers to evaluate. */
  definitions?: TriggerDefinition[];
}

/** One poll-first trigger. The polled tool SHOULD be read-scoped — the policy engine still governs it. */
export interface TriggerDefinition {
  /** Stable id; namespaces the persisted seen-state and the fired-event log. */
  id: string;
  /** Human label shown in the dashboard. */
  name?: string;
  /** Exposed tool name to poll (e.g. `github__list_issues`). Called at its inferred/configured scope. */
  tool: string;
  /** Arguments passed to the polled tool on every call. */
  args?: Record<string, unknown>;
  /** Per-trigger interval override in seconds. Falls back to `poll_interval_seconds`. */
  interval_seconds?: number;
  /**
   * Dot-path to an array inside the tool's JSON result (e.g. `items` or `data.issues`). When set
   * AND `item_key` resolves a unique field per element, change detection is ITEM-LEVEL: new keys
   * fire. When omitted (or the path doesn't resolve to an array), detection falls back to a hash
   * of the whole response — a fire on any change.
   */
  item_path?: string;
  /** Field on each array element that uniquely identifies it (e.g. `id`, `number`, `url`). */
  item_key?: string;
  /** Whether this definition is polled. Default true (the master switch already gates the loop). */
  enabled?: boolean;
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
 * A LOCAL, OpenAI-compatible model server (Ollama, LM Studio, llama.cpp, vLLM, …). The headline
 * "zero-cloud, zero-key" path: point `base_url` at the local server and the council/playground run
 * entirely offline. `api_key_ref` is OPTIONAL — most local servers need no token — but when present
 * it must still be a `${vault:..}`/`${env:..}` reference (Switchboard never custodies a plaintext key).
 */
export interface LocalProviderConfig {
  /** OpenAI-compatible base URL, e.g. `http://127.0.0.1:11434/v1` (Ollama) or `http://127.0.0.1:1234/v1` (LM Studio). */
  base_url: string;
  /** Default model id served locally (e.g. `llama3.1`, `qwen2.5-coder`, `mistral`). */
  default_model: string;
  /** Optional `${vault:..}`/`${env:..}` reference if the local server enforces a bearer token. */
  api_key_ref?: string;
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
    /** A local OpenAI-compatible model server — the zero-cloud, zero-key option. */
    local?: LocalProviderConfig;
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
