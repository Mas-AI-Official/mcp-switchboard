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
import type { SwitchboardConfig } from "./types.js";

const scope = z.enum(["read", "write", "full"]);

const toolOverride = z
  .object({
    enabled: z.boolean().optional(),
    policy: scope.optional(),
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
    source: z.enum(["npx", "binary", "remote", "app2mcp"]),
    enabled: z.boolean().default(true),
    policy: scope.optional(),
    package: z.string().optional(),
    command: z.string().optional(),
    args: z.array(z.string()).optional(),
    url: z.url().optional(),
    auth: z.enum(["none", "oauth", "bearer"]).optional(),
    openapi: z.string().optional(),
    base_url: z.string().optional(),
    credentials: z.record(z.string(), z.string()).optional(),
    env: z.record(z.string(), z.string()).optional(),
    tools: z.record(z.string(), toolOverride).optional(),
    approval: approval.optional(),
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

const council = z
  .object({
    enabled: z.boolean().default(false),
    providers: z
      .object({
        anthropic: councilProvider.optional(),
        openai: councilProvider.optional(),
      })
      .strict()
      .optional(),
    max_rounds: z.number().int().positive().max(10).default(3),
    token_budget: z.number().int().positive().max(32768).default(2048),
    require_approval: z.boolean().default(false),
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
  })
  .strict()
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
