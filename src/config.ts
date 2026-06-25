/**
 * Config loading + validation. The on-disk contract is `switchboard.config.yaml`;
 * this module is the single place where that YAML is parsed, zod-validated, and
 * turned into the typed `SwitchboardConfig` the rest of the app consumes.
 *
 * Validation is strict and fail-fast: a malformed config aborts startup with a
 * readable error rather than silently mounting a half-configured server.
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { parse, stringify } from "yaml";
import { z } from "zod";
import type { SwitchboardConfig, TriggersConfig } from "./types.js";

const scope = z.enum(["read", "write", "full"]);

// Schema-shaping rules applied to a tool's exposed input schema before agents see it.
const schemaModifier = z
  .object({
    hide_params: z.array(z.string()).optional(),
    rename_params: z.record(z.string(), z.string()).optional(),
    trim_description: z.number().int().positive().optional(),
  })
  .strict();

// Top-level response-field redaction applied after a successful tool call.
const responseRedaction = z
  .object({
    fields: z.array(z.string()).optional(),
    replace_with: z.string().optional(),
  })
  .strict();

// Declarative auth injection, discriminated on `kind`. All ref fields are vault/env references.
const authScheme = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("bearer"), ref: z.string().min(1) }).strict(),
  z
    .object({
      kind: z.literal("api_key"),
      ref: z.string().min(1),
      header: z.string().optional(),
      query: z.string().optional(),
    })
    .strict(),
  z
    .object({
      kind: z.literal("basic"),
      username_ref: z.string().min(1),
      password_ref: z.string().min(1),
    })
    .strict(),
  z.object({ kind: z.literal("header"), name: z.string().min(1), ref: z.string().min(1) }).strict(),
]);

// One hand-declared HTTP endpoint exposed as a governed MCP tool (source: http-tool).
const httpToolDef = z
  .object({
    name: z.string().min(1),
    description: z.string().optional(),
    method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]),
    path: z.string().optional(),
    url: z.url().optional(),
    inputSchema: z.record(z.string(), z.unknown()).optional(),
    scope: scope.optional(),
  })
  .strict()
  .refine((v) => !!v.path || !!v.url, {
    message: "each http_tools entry needs a `path` (joined to base_url) or an absolute `url`",
  });

// Rate limits + spend budgets for one level (global / server / tool). Counts (`per_*`) must be
// positive integers; cost budgets (`cost_per_*`) may be fractional but positive. `.refine` rejects
// an all-empty block so a typo'd field name can't silently disable the limit it was meant to set.
const limitSpec = z
  .object({
    per_minute: z.number().int().positive().optional(),
    per_hour: z.number().int().positive().optional(),
    per_day: z.number().int().positive().optional(),
    cost_per_minute: z.number().positive().optional(),
    cost_per_hour: z.number().positive().optional(),
    cost_per_day: z.number().positive().optional(),
  })
  .strict()
  .refine((v) => Object.values(v).some((n) => typeof n === "number"), {
    message: "a limits block must set at least one ceiling (per_minute/per_hour/per_day or cost_per_*)",
  });

const resilience = z
  .object({
    enabled: z.boolean().optional(),
    failure_threshold: z.number().int().positive().max(1000).optional(),
    cooldown_seconds: z.number().int().positive().max(86400).optional(),
  })
  .strict();

const mountRetry = z
  .object({
    enabled: z.boolean().optional(),
    // 0 disables retry; cap the count so a misconfig can't schedule an unbounded chain.
    max_attempts: z.number().int().min(0).max(100).optional(),
    base_ms: z.number().int().positive().max(3600000).optional(),
    factor: z.number().positive().max(60).optional(),
    max_ms: z.number().int().positive().max(3600000).optional(),
  })
  .strict();

const toolOverride = z
  .object({
    enabled: z.boolean().optional(),
    policy: scope.optional(),
    description_override: z.string().optional(),
    drop_params: z.array(z.string()).optional(),
    schema_modifiers: schemaModifier.optional(),
    inject_args: z.record(z.string(), z.string()).optional(),
    redact_response: responseRedaction.optional(),
    tags: z.array(z.string()).optional(),
    important: z.boolean().optional(),
    limits: limitSpec.optional(),
    cost: z.number().nonnegative().optional(),
  })
  .strict();

const approval = z
  .object({
    require_for: z.array(scope).optional(),
  })
  .strict();

const serverConfig = z
  .object({
    id: z.string().min(1),
    source: z.enum(["npx", "binary", "remote", "app2mcp", "http-tool"]),
    enabled: z.boolean().default(true),
    policy: scope.optional(),
    package: z.string().optional(),
    command: z.string().optional(),
    args: z.array(z.string()).optional(),
    url: z.url().optional(),
    auth: z.enum(["none", "oauth", "bearer"]).optional(),
    openapi: z.string().optional(),
    base_url: z.string().optional(),
    http_tools: z.array(httpToolDef).optional(),
    auth_scheme: authScheme.optional(),
    schema_mode: z.enum(["full", "required_only"]).optional(),
    schema_modifiers: schemaModifier.optional(),
    inject_args: z.record(z.string(), z.string()).optional(),
    redact_response: responseRedaction.optional(),
    credentials: z.record(z.string(), z.string()).optional(),
    env: z.record(z.string(), z.string()).optional(),
    tools: z.record(z.string(), toolOverride).optional(),
    approval: approval.optional(),
    limits: limitSpec.optional(),
    resilience: resilience.optional(),
  })
  .strict();

const gateway = z
  .object({
    transport: z.array(z.enum(["stdio", "http"])).default(["stdio"]),
    http: z
      .object({
        host: z.string().default("127.0.0.1"),
        port: z.number().int().positive().default(8088),
        // When the `/mcp` endpoint requires a bearer API key. "auto" (the default)
        // requires one whenever the bind host is NOT loopback — zero friction on
        // localhost, fails closed the instant you expose to the network or a tunnel.
        require_auth: z.enum(["auto", "always", "never"]).default("auto"),
      })
      .strict()
      .default({ host: "127.0.0.1", port: 8088, require_auth: "auto" }),
    tool_exposure: z.enum(["namespaced", "flat", "search"]).default("namespaced"),
    default_policy: scope.default("read"),
  })
  .strict()
  .default({
    transport: ["stdio"],
    http: { host: "127.0.0.1", port: 8088, require_auth: "auto" },
    tool_exposure: "namespaced",
    default_policy: "read",
  });

const vault = z
  .object({
    backend: z.enum(["encrypted-file", "env"]).default("encrypted-file"),
  })
  .strict()
  .default({ backend: "encrypted-file" });

// A council provider's API key MUST be a vault/env reference — never a literal secret in
// source (NEVER #1). This refine fails the config fast if someone pastes a raw key.
const councilKeyRef = z
  .string()
  .min(1)
  .refine((s) => /^\$\{(vault|env):[^}]+\}$/.test(s.trim()), {
    message: "must be a ${vault:NAME} or ${env:NAME} reference, never a literal API key",
  });

const councilProvider = z
  .object({
    api_key_ref: councilKeyRef,
    default_model: z.string().min(1),
    base_url: z.url().optional(),
  })
  .strict();

// A local OpenAI-compatible server (Ollama / LM Studio / llama.cpp). `base_url` is REQUIRED so the
// call has a concrete target; `api_key_ref` is OPTIONAL (most local servers need no token) but when
// present must still be a vault/env reference — never a literal secret in source (NEVER #1).
const localProvider = z
  .object({
    base_url: z.url(),
    default_model: z.string().min(1),
    api_key_ref: councilKeyRef.optional(),
  })
  .strict();

const council = z
  .object({
    enabled: z.boolean().default(false),
    providers: z
      .object({
        anthropic: councilProvider.optional(),
        openai: councilProvider.optional(),
        local: localProvider.optional(),
      })
      .strict()
      .optional(),
    max_rounds: z.number().int().positive().max(10).default(3),
    token_budget: z.number().int().positive().max(32768).default(2048),
    require_approval: z.boolean().default(false),
  })
  .strict();

const triggerDefinition = z
  .object({
    id: z.string().min(1),
    name: z.string().optional(),
    tool: z.string().min(1),
    args: z.record(z.string(), z.unknown()).optional(),
    interval_seconds: z.number().int().positive().max(86400).optional(),
    item_path: z.string().optional(),
    item_key: z.string().optional(),
    enabled: z.boolean().default(true),
  })
  .strict();

const triggers = z
  .object({
    enabled: z.boolean().default(false),
    poll_interval_seconds: z.number().int().positive().max(86400).default(60),
    definitions: z.array(triggerDefinition).default([]),
  })
  .strict();

const profile = z
  .object({
    description: z.string().optional(),
    servers: z.array(z.string()).optional(),
    tools: z.array(z.string()).optional(),
    exclude_tools: z.array(z.string()).optional(),
    policy: scope.optional(),
  })
  .strict();

const settings = z
  .object({
    general: z
      .object({
        organization_name: z.string().optional(),
        project_name: z.string().optional(),
      })
      .strict()
      .optional(),
    auth_screen: z
      .object({
        title: z.string().optional(),
        subtitle: z.string().optional(),
        logo_url: z.string().optional(),
        accent_color: z.string().optional(),
        support_url: z.string().optional(),
      })
      .strict()
      .optional(),
    webhook: z
      .object({
        enabled: z.boolean().optional(),
        url: z.string().optional(),
        events: z.array(z.enum(["allow", "deny", "approval_required"])).optional(),
        secret_ref: z.string().optional(),
      })
      .strict()
      .optional(),
    logs: z
      .object({
        // When true, allowed executions also record (redacted, size-capped) request args and
        // upstream responses in the audit log. Off by default — duration is always recorded.
        capture_io: z.boolean().optional(),
      })
      .strict()
      .optional(),
    council: council.optional(),
    oauth_server: z
      .object({
        enabled: z.boolean().default(false),
        public_url: z.url().optional(),
        access_token_ttl: z.number().int().positive().optional(),
        refresh_token_ttl: z.number().int().min(0).optional(),
        consent: z.boolean().optional(),
      })
      .strict()
      .refine((v) => !v.enabled || !!v.public_url, {
        message: "settings.oauth_server.public_url is required when oauth_server.enabled is true",
      })
      .optional(),
    triggers: triggers.optional(),
    // Hard wall-clock timeout (ms) applied to every upstream tool call. Cap at 10 min.
    call_timeout_ms: z.number().int().positive().max(600000).optional(),
    // Named switchable views over the configured servers/tools (visibility + optional scope cap).
    profiles: z.record(z.string(), profile).optional(),
    active_profile: z.string().optional(),
    // Global rate limits + spend budgets applied to every tool call across all servers.
    limits: limitSpec.optional(),
    // Gateway-wide circuit-breaker default; per-server override via server.resilience.
    resilience: resilience.optional(),
    // Self-healing mounts: retry a server that fails to mount at boot, on a capped backoff.
    mount_retry: mountRetry.optional(),
  })
  .strict()
  .refine((s) => !s.active_profile || (s.profiles !== undefined && s.active_profile in s.profiles), {
    message: "settings.active_profile must name a profile defined in settings.profiles",
    path: ["active_profile"],
  })
  .optional();

const configSchema = z
  .object({
    gateway,
    vault,
    servers: z.array(serverConfig).default([]),
    settings,
  })
  .strict();

/** Parse + validate a YAML config file into a typed config. Throws on any error. */
export function loadConfig(path: string): SwitchboardConfig {
  if (!existsSync(path)) {
    throw new Error(`config not found: ${path} — run \`switchboard init\` to create one`);
  }
  const raw = parse(readFileSync(path, "utf8")) ?? {};
  const result = configSchema.safeParse(raw);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  - ${i.path.join(".") || "(root)"}: ${i.message}`)
      .join("\n");
    throw new Error(`invalid config (${path}):\n${issues}`);
  }
  return result.data as SwitchboardConfig;
}

/** Serialize a config back to YAML on disk. */
export function writeConfig(path: string, cfg: SwitchboardConfig): void {
  writeFileSync(path, stringify(cfg));
}

/**
 * Validate a raw triggers settings object (as sent by the dashboard's `/api/triggers` PUT)
 * against the same strict schema used at startup, applying defaults. Throws a readable error
 * on any violation so the HTTP layer can answer 400 instead of persisting a bad config.
 */
export function parseTriggersConfig(raw: unknown): TriggersConfig {
  const result = triggers.safeParse(raw ?? {});
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`)
      .join("; ");
    throw new Error(issues);
  }
  return result.data as TriggersConfig;
}

/** The config written by `switchboard init`. Intentionally minimal but runnable. */
export function starterConfig(): SwitchboardConfig {
  return {
    gateway: {
      transport: ["stdio", "http"],
      http: { host: "127.0.0.1", port: 8088, require_auth: "auto" },
      tool_exposure: "namespaced",
      default_policy: "read",
    },
    vault: { backend: "encrypted-file" },
    servers: [
      {
        id: "everything",
        source: "npx",
        package: "@modelcontextprotocol/server-everything",
        enabled: true,
        policy: "read",
      },
    ],
  };
}
