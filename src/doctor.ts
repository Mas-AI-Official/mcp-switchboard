/**
 * Doctor — pre-flight diagnosis of a MCP Switchboard install, computed as DATA.
 *
 * `switchboard doctor` renders this report; the oracle asserts on it. Keeping the
 * checks in one pure function — no console, no process.exit, no live gateway — makes
 * the whole diagnosis testable to the row, and lets every front-end (CLI, a future
 * dashboard panel) share one source of truth for "is this install healthy?".
 *
 * It catches the config mistakes that otherwise only surface as a confusing runtime
 * failure: a node older than the engines floor, two servers sharing an id (namespace
 * collision), a secret ref that won't resolve, a `${oauth:..}` ref whose provider has
 * no client id (a call-time auth failure), and a per-tool policy trap (a tool denied by
 * its own server's scope ceiling). Pure aside from the injected `resolve` callback.
 */

import type { ServerConfig, SwitchboardConfig, Scope } from "./types.js";
import { evaluate } from "./policy.js";

/** Minimum Node that the runtime relies on (global `fetch`, stable ESM). Mirrors package.json `engines.node`. */
export const NODE_FLOOR = "18.18.0";

/** `${oauth:provider}` reference — resolved by the OAuth store at call time, not the vault. */
const OAUTH_REF = /\$\{oauth:([^}]+)\}/g;

export interface DoctorServerFinding {
  id: string;
  source: ServerConfig["source"];
  policy: Scope;
  enabled: boolean;
  /** Secret refs (`${vault:..}`/`${env:..}`) that fail to resolve — the fail-closed message each gave. */
  unresolved: string[];
  /** Per-tool policy traps: an explicitly-configured tool its own server ceiling would deny. */
  policyTraps: { tool: string; reason: string }[];
  /** `${oauth:provider}` refs whose provider has no stored client id, so the call can't authenticate. */
  oauthUnconfigured: string[];
  /** True when this id repeats an earlier server's id — the tool namespace would collide. */
  duplicateId: boolean;
}

export interface DoctorReport {
  node: { version: string; floor: string; ok: boolean };
  vaultBackend: string;
  transports: string[];
  endpoint: string;
  servers: DoctorServerFinding[];
  /** Flat, human-readable list of everything actionable — the CLI tail and the oracle both read this. */
  problems: string[];
  /** True when nothing actionable was found. */
  ok: boolean;
}

export interface DoctorInputs {
  cfg: SwitchboardConfig;
  /** Resolve a config value's `${vault:..}`/`${env:..}` refs; MUST throw (fail-closed) on a missing one. */
  resolve: (value: string) => string;
  /** Providers that have a stored OAuth client id. When supplied, a `${oauth:..}` ref to a provider
   *  absent from this set is flagged. Omit to skip the OAuth-config check entirely. */
  oauthClientIds?: ReadonlySet<string>;
  /** Override the running node version (defaults to `process.version`) — lets the oracle pin both branches. */
  nodeVersion?: string;
}

/** Parse a `vX.Y.Z` / `X.Y.Z` string into a numeric triple, tolerating noise (never throws). */
function parseVer(v: string): [number, number, number] {
  const parts = v.replace(/^v/, "").split(".");
  const n = (s?: string) => {
    const x = parseInt(s ?? "0", 10);
    return Number.isFinite(x) ? x : 0;
  };
  return [n(parts[0]), n(parts[1]), n(parts[2])];
}

/** True when `version` is at least `floor` (semver-lite major→minor→patch; zero-dep, total). */
export function meetsNodeFloor(version: string, floor: string): boolean {
  const [a, b, c] = parseVer(version);
  const [x, y, z] = parseVer(floor);
  if (a !== x) return a > x;
  if (b !== y) return b > y;
  return c >= z;
}

/** Every `${oauth:provider}` provider named in a server's secret-bearing value maps. */
function oauthProvidersOf(server: ServerConfig): string[] {
  const out = new Set<string>();
  const maps = [server.env, server.credentials, server.inject_args];
  for (const map of maps) {
    for (const value of Object.values(map ?? {})) {
      if (typeof value !== "string") continue;
      for (const m of value.matchAll(OAUTH_REF)) out.add(m[1]);
    }
  }
  return [...out];
}

/** Diagnose a config without mounting anything. Pure aside from the injected `resolve`. */
export function buildDoctorReport(inputs: DoctorInputs): DoctorReport {
  const { cfg, resolve, oauthClientIds } = inputs;
  const version = inputs.nodeVersion ?? process.version;
  const nodeOk = meetsNodeFloor(version, NODE_FLOOR);

  const problems: string[] = [];
  if (!nodeOk) problems.push(`node ${version} is below the supported floor ${NODE_FLOOR}`);

  const seenIds = new Set<string>();
  const servers: DoctorServerFinding[] = cfg.servers.map((s) => {
    const policy: Scope = s.policy ?? cfg.gateway.default_policy;
    const enabled = s.enabled !== false;

    const duplicateId = seenIds.has(s.id);
    if (duplicateId) problems.push(`server '${s.id}' id is declared more than once — tool namespace collision`);
    seenIds.add(s.id);

    // Secret refs must resolve now; a fail-closed throw becomes a problem instead of a startup crash.
    const unresolved: string[] = [];
    for (const value of Object.values({ ...(s.env ?? {}), ...(s.credentials ?? {}) })) {
      if (typeof value !== "string") continue;
      try {
        resolve(value);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        unresolved.push(msg);
        problems.push(`server '${s.id}': ${msg}`);
      }
    }

    // `${oauth:..}` refs aren't resolved by the vault — verify the provider can actually authenticate.
    const oauthUnconfigured: string[] = [];
    if (oauthClientIds) {
      for (const provider of oauthProvidersOf(s)) {
        if (!oauthClientIds.has(provider)) {
          oauthUnconfigured.push(provider);
          problems.push(`server '${s.id}': OAuth provider '${provider}' has no client id — run \`switchboard connect ${provider}\``);
        }
      }
    }

    // A tool the operator explicitly configured but its own server ceiling would deny is a silent trap.
    const policyTraps: { tool: string; reason: string }[] = [];
    for (const tool of Object.keys(s.tools ?? {})) {
      const d = evaluate(s, tool, cfg);
      if (d.decision === "deny") {
        policyTraps.push({ tool, reason: d.reason });
        problems.push(`server '${s.id}': ${d.reason}`);
      }
    }

    return { id: s.id, source: s.source, policy, enabled, unresolved, policyTraps, oauthUnconfigured, duplicateId };
  });

  return {
    node: { version, floor: NODE_FLOOR, ok: nodeOk },
    vaultBackend: cfg.vault.backend,
    transports: cfg.gateway.transport,
    endpoint: `http://${cfg.gateway.http.host}:${cfg.gateway.http.port}/mcp`,
    servers,
    problems,
    ok: problems.length === 0,
  };
}
