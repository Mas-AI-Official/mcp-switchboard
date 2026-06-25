/**
 * profiles.ts — named, switchable VIEWS over the configured servers/tools.
 *
 * A profile is NOT a new server. It is a saved filter the operator switches between (a "coding"
 * profile that hides email tools, a "read-only" profile that caps everything at read scope, a
 * "support" profile that exposes only three servers). It can only ever HIDE tools and LOWER
 * scope — never reveal a disabled tool or raise a server's policy. This keeps profiles safe by
 * construction: switching to any profile can only ever reduce what an agent can reach.
 *
 * Resolution order for the ACTIVE profile name (highest precedence first):
 *   1. the `SWITCHBOARD_PROFILE` environment variable
 *   2. `settings.active_profile` in the config file
 *   3. none (every enabled tool is exposed — fully backward compatible)
 *
 * The env override is folded into the config ONCE at the CLI boot boundary
 * (`applyProfileEnvOverride`), so the Router and policy engine only ever read `cfg` and never
 * touch `process.env` — that keeps them pure and makes the dashboard's `/api/state` report the
 * effective active profile. Every function here is pure (env is an explicit parameter) so the
 * deterministic oracle can prove the resolution + filter logic with no network and no boot.
 */

import type { ProfileConfig, Scope, SwitchboardConfig } from "./types.js";

const SCOPE_RANK: Record<Scope, number> = { read: 0, write: 1, full: 2 };

/** A defensive deep clone — keeps `applyProfileEnvOverride` non-mutating like `withLocalProvider`. */
function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

/**
 * The active profile name as resolved from config alone (the env var is folded in beforehand by
 * `applyProfileEnvOverride`). Returns `undefined` when no profile is active.
 */
export function activeProfileName(cfg: SwitchboardConfig): string | undefined {
  return cfg.settings?.active_profile;
}

/**
 * Resolve the active profile to its config block. Returns `undefined` when no profile is active
 * OR when `active_profile` names a profile that isn't defined (the loader's schema refine prevents
 * the latter for file-set names, but an env-set name is validated by `applyProfileEnvOverride`).
 */
export function getActiveProfile(cfg: SwitchboardConfig): { name: string; profile: ProfileConfig } | undefined {
  const name = cfg.settings?.active_profile;
  if (!name) return undefined;
  const profile = cfg.settings?.profiles?.[name];
  return profile ? { name, profile } : undefined;
}

/**
 * Does the active profile expose this server at all? `servers` (when non-empty) is an allowlist —
 * a server not on it is hidden wholesale. No active profile / no `servers` list ⇒ allowed.
 */
export function profileAllowsServer(profile: ProfileConfig | undefined, serverId: string): boolean {
  if (!profile) return true;
  const allow = profile.servers;
  if (allow && allow.length > 0 && !allow.includes(serverId)) return false;
  return true;
}

/**
 * Does the active profile expose this EXPOSED tool name (`serverId__toolName` namespaced, or the
 * bare name in flat mode)? Denylist beats allowlist: an `exclude_tools` hit is hidden even if a
 * `tools` allowlist would include it. No active profile ⇒ allowed.
 */
export function profileAllowsTool(profile: ProfileConfig | undefined, exposedName: string): boolean {
  if (!profile) return true;
  if (profile.exclude_tools && profile.exclude_tools.includes(exposedName)) return false;
  const allow = profile.tools;
  if (allow && allow.length > 0 && !allow.includes(exposedName)) return false;
  return true;
}

/** The profile's scope ceiling, if any. `evaluate()` takes the tighter of this and the server cap. */
export function profileScopeCeiling(profile: ProfileConfig | undefined): Scope | undefined {
  return profile?.policy;
}

/** Result of folding `SWITCHBOARD_PROFILE` into a config. The input is never mutated. */
export interface ProfileOverrideResult {
  /** The config to boot with (a NEW object when the env changed the active profile). */
  config: SwitchboardConfig;
  /** The resolved active profile name after the override (undefined = none). */
  active?: string;
  /** Advisory to surface (e.g. the env named an unknown profile and was ignored). */
  note?: string;
}

/** The reserved env value that explicitly disables profiles for one run (unless a profile is literally named "none"). */
const DISABLE_VALUE = "none";

/**
 * Fold the `SWITCHBOARD_PROFILE` env var into `settings.active_profile`, returning a config the
 * Router/policy can read without ever touching the environment. Behaviour:
 *   - unset            → no change (the file's `active_profile`, if any, stands)
 *   - empty / `none`   → explicitly disable any active profile for this run
 *   - a defined profile→ activate it
 *   - an unknown name  → ignore it (keep the file's profile) and return an advisory `note`
 * An unknown env value is never fatal: a typo in an env var must not stop the server from booting.
 */
export function applyProfileEnvOverride(
  cfg: SwitchboardConfig,
  env: NodeJS.ProcessEnv = process.env,
): ProfileOverrideResult {
  const raw = env.SWITCHBOARD_PROFILE;
  if (raw === undefined) {
    return { config: cfg, active: cfg.settings?.active_profile };
  }
  const name = raw.trim();
  const profiles = cfg.settings?.profiles ?? {};

  // Explicit disable: empty string, or the reserved word "none" when nothing is literally named "none".
  if (name === "" || (name.toLowerCase() === DISABLE_VALUE && !(name in profiles))) {
    if (cfg.settings?.active_profile === undefined) return { config: cfg, active: undefined };
    const next = clone(cfg);
    if (next.settings) delete next.settings.active_profile;
    return { config: next, active: undefined, note: "SWITCHBOARD_PROFILE cleared the active profile for this run" };
  }

  if (!(name in profiles)) {
    const defined = Object.keys(profiles);
    return {
      config: cfg,
      active: cfg.settings?.active_profile,
      note: `SWITCHBOARD_PROFILE='${name}' names no defined profile — ignoring (defined: ${defined.length ? defined.join(", ") : "none"})`,
    };
  }

  if (cfg.settings?.active_profile === name) return { config: cfg, active: name };
  const next = clone(cfg);
  next.settings ??= {};
  next.settings.active_profile = name;
  return { config: next, active: name };
}

/** A one-line, human-readable summary of a profile's effect (for `switchboard profile list/show`). */
export function describeProfile(name: string, profile: ProfileConfig): string {
  const parts: string[] = [];
  if (profile.servers && profile.servers.length) parts.push(`servers: ${profile.servers.join(", ")}`);
  if (profile.tools && profile.tools.length) parts.push(`only tools: ${profile.tools.length}`);
  if (profile.exclude_tools && profile.exclude_tools.length) parts.push(`hides: ${profile.exclude_tools.length}`);
  if (profile.policy) parts.push(`scope ≤ ${profile.policy}`);
  const summary = parts.length ? parts.join(" · ") : "no restrictions";
  return profile.description ? `${name} — ${profile.description} (${summary})` : `${name} — ${summary}`;
}

/**
 * Set/clear the active profile in a config, returning a NEW config (input untouched). `undefined`
 * clears it. Throws if `name` names no defined profile — the CLI surfaces that as a usage error.
 */
export function withActiveProfile(cfg: SwitchboardConfig, name: string | undefined): SwitchboardConfig {
  const next = clone(cfg);
  next.settings ??= {};
  if (name === undefined) {
    delete next.settings.active_profile;
    return next;
  }
  const profiles = next.settings.profiles ?? {};
  if (!(name in profiles)) {
    const defined = Object.keys(profiles);
    throw new Error(`no profile named '${name}' (defined: ${defined.length ? defined.join(", ") : "none"})`);
  }
  next.settings.active_profile = name;
  return next;
}

/** Re-export for callers that compute their own scope math against a profile ceiling. */
export { SCOPE_RANK };
