/**
 * Per-server circuit breaker — the upstream-resilience control a hosted router gives you for free.
 *
 * MCP Switchboard proxies upstream MCP servers that can crash, wedge, or go unreachable. Without a
 * breaker, every call to a dead server pays the full `settings.call_timeout_ms` before failing, and
 * the agent rediscovers the outage one slow call at a time. The breaker watches each server's
 * TRANSPORT health — thrown errors and timeouts, NOT well-formed tool *error results* (a tool that
 * answers "file not found" means the server is alive and responding) — and after N consecutive
 * failures it OPENS: further calls fail fast with an honest "server X is unavailable, retry in ~Ts"
 * instead of hanging. After a cooldown it permits ONE probe (HALF-OPEN); a success CLOSES it (back
 * to normal), a failure re-opens it for another cooldown.
 *
 * This is an AVAILABILITY signal layered UNDER the security controls — policy, scope, and rate
 * limits all run first; the breaker only decides whether attempting the upstream is worth it at all.
 * It sits before the approval gate so a call to a known-dead server never wakes a human. `allow()`
 * may mutate (it re-arms the cooldown when it releases a probe) so concurrent calls don't stampede
 * a recovering server; the only unpaired case — a probe released then blocked by a denied approval —
 * self-heals after one more cooldown, never a stuck-open leak.
 *
 * Deterministic by construction: every method takes the current time (`now`, ms since epoch).
 * Production passes `Date.now()`; the verifier passes synthetic timestamps to drive the state machine
 * without a wall clock. Zero dependencies, O(1) per call, O(servers-seen) memory.
 *
 * Opt-in (off by default, like triggers/council): set `settings.resilience.enabled: true` for a
 * gateway-wide default and/or `server.resilience` to override (or disable) per server.
 */

import type { ResilienceConfig, SwitchboardConfig } from "./types.js";

const DEFAULT_FAILURE_THRESHOLD = 5;
const DEFAULT_COOLDOWN_SECONDS = 30;

/** Breaker state for one server. `half_open` = a single probe has been released / is in flight. */
export type BreakerState = "closed" | "open" | "half_open";

/** Outcome of a `Breaker.allow` check. `ok:false` short-circuits the call before the upstream. */
export interface BreakerDecision {
  ok: boolean;
  state: BreakerState;
  /** When denied: ms until the breaker would next release a probe (always finite — cooldown-bounded). */
  retryAfterMs?: number;
  /** When denied: a one-line, actionable explanation of the open circuit. */
  reason?: string;
}

/** Read-only view of one server's breaker, for observability (dashboard / health endpoint). */
export interface BreakerHealth {
  server: string;
  state: BreakerState;
  consecutiveFailures: number;
  /** ms until the next probe is permitted (0 unless currently open). */
  retryAfterMs: number;
}

/** Resolved, defaults-applied tuning for one server (null = breaker inactive for that server). */
interface Effective {
  threshold: number;
  cooldownMs: number;
}

interface Entry {
  state: BreakerState;
  /** Consecutive transport failures since the last success. */
  failures: number;
  /** When the breaker last opened or released a probe (ms). Cooldown is measured from here. */
  openedAt: number;
}

export class Breaker {
  private readonly entries = new Map<string, Entry>();
  private readonly globalCfg?: ResilienceConfig;
  private readonly serverCfg = new Map<string, ResilienceConfig>();
  /** Fast path: when resilience is enabled nowhere, `allow` is constant and `record` is a no-op. */
  private readonly active: boolean;

  constructor(cfg: SwitchboardConfig) {
    this.globalCfg = cfg.settings?.resilience;
    for (const server of cfg.servers ?? []) {
      if (server.resilience) this.serverCfg.set(server.id, server.resilience);
    }
    this.active =
      this.globalCfg?.enabled === true ||
      Array.from(this.serverCfg.values()).some((r) => r.enabled === true);
  }

  /**
   * Resolve the effective tuning for a server, or null when the breaker is inactive for it. A
   * per-server `enabled` (true/false) overrides the global default; thresholds/cooldowns fall back
   * server → global → built-in default. Synthetic servers (e.g. `council`) have no override and
   * simply inherit the global default.
   */
  private effectiveFor(serverId: string): Effective | null {
    const s = this.serverCfg.get(serverId);
    const enabled = s?.enabled ?? this.globalCfg?.enabled === true;
    if (!enabled) return null;
    const threshold = s?.failure_threshold ?? this.globalCfg?.failure_threshold ?? DEFAULT_FAILURE_THRESHOLD;
    const cooldownSeconds =
      s?.cooldown_seconds ?? this.globalCfg?.cooldown_seconds ?? DEFAULT_COOLDOWN_SECONDS;
    return { threshold, cooldownMs: cooldownSeconds * 1000 };
  }

  /**
   * Decide whether to attempt the upstream now. Closed → always ok. Open → fail fast until the
   * cooldown elapses, then release exactly one probe (transition to half_open, re-arm the cooldown
   * so concurrent calls don't stampede). Half_open → block additional calls until the probe records
   * or, if it never does, another cooldown frees a fresh probe.
   */
  allow(serverId: string, now: number): BreakerDecision {
    if (!this.active) return { ok: true, state: "closed" };
    const eff = this.effectiveFor(serverId);
    if (!eff) return { ok: true, state: "closed" };

    const e = this.entries.get(serverId);
    if (!e || e.state === "closed") return { ok: true, state: "closed" };

    const elapsed = now - e.openedAt;
    if (elapsed >= eff.cooldownMs) {
      // Cooldown elapsed (from either an open circuit or a stale in-flight probe) → release one
      // probe and re-arm so a burst of concurrent calls is gated to a single attempt.
      e.state = "half_open";
      e.openedAt = now;
      return { ok: true, state: "half_open" };
    }
    return {
      ok: false,
      state: e.state,
      retryAfterMs: eff.cooldownMs - elapsed,
      reason: this.reason(serverId, e, eff, now),
    };
  }

  /**
   * Record the transport outcome of an attempted upstream call. `ok:true` (the server responded,
   * even with an error *result*) closes the breaker and clears the failure count; `ok:false` (a
   * throw/timeout) increments it and opens the breaker once it reaches the threshold. The caller
   * records exactly once per released attempt.
   */
  record(serverId: string, ok: boolean, now: number): void {
    if (!this.active) return;
    const eff = this.effectiveFor(serverId);
    if (!eff) return;

    let e = this.entries.get(serverId);
    if (!e) {
      e = { state: "closed", failures: 0, openedAt: 0 };
      this.entries.set(serverId, e);
    }

    if (ok) {
      e.state = "closed";
      e.failures = 0;
      e.openedAt = 0;
      return;
    }

    e.failures += 1;
    if (e.failures >= eff.threshold) {
      e.state = "open";
      e.openedAt = now;
    }
  }

  /** Read-only health of one server's breaker. Never mutates — safe for a dashboard poll. */
  health(serverId: string, now: number): BreakerHealth {
    const e = this.entries.get(serverId);
    if (!e) return { server: serverId, state: "closed", consecutiveFailures: 0, retryAfterMs: 0 };
    const eff = this.effectiveFor(serverId);
    const retryAfterMs =
      e.state === "open" && eff ? Math.max(0, eff.cooldownMs - (now - e.openedAt)) : 0;
    return { server: serverId, state: e.state, consecutiveFailures: e.failures, retryAfterMs };
  }

  /** Read-only health of every server the breaker has observed. For an observability endpoint. */
  snapshot(now: number): BreakerHealth[] {
    return Array.from(this.entries.keys()).map((id) => this.health(id, now));
  }

  private reason(serverId: string, e: Entry, eff: Effective, now: number): string {
    const retrySec = Math.ceil(Math.max(0, eff.cooldownMs - (now - e.openedAt)) / 1000);
    return `server '${serverId}' circuit is open after ${e.failures} consecutive failures — failing fast for ~${retrySec}s`;
  }
}
