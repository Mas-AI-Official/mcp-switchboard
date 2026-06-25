/**
 * Mount-retry backoff — the pure math behind self-healing upstream mounts.
 *
 * A server that fails to mount at boot (transient DNS, an upstream still warming up, a
 * race on a freshly-spawned stdio child) was previously dead until the operator restarted
 * Switchboard. This module computes a capped exponential backoff schedule; the Gateway uses
 * it to retry a failed mount in the background until it succeeds or the attempts are spent.
 *
 * Everything here is deterministic and side-effect-free (no timers, no I/O, no clock, no
 * randomness) so the schedule can be unit-tested exactly. The Gateway owns the one impure
 * part — a single `setTimeout(...).unref()` per scheduled attempt — and nothing else.
 *
 * No jitter on purpose: Switchboard reconnects a handful of named upstreams from ONE process,
 * not a fleet of thousands hammering a shared backend, so the thundering-herd problem jitter
 * solves does not apply here — and a deterministic schedule is testable to the millisecond.
 */

import type { MountRetryConfig } from "./types.js";

export type { MountRetryConfig };

/** All-fields-present policy after defaults are folded in. */
export type ResolvedMountRetry = Required<MountRetryConfig>;

export const DEFAULT_MOUNT_RETRY: ResolvedMountRetry = {
  enabled: true,
  max_attempts: 5,
  base_ms: 1000,
  factor: 2,
  max_ms: 30000,
};

/** Fold an optional, partial policy over the defaults. The single source of truth for both the
 *  Gateway scheduler and the verifier, so they can never drift. */
export function resolveMountRetry(cfg?: MountRetryConfig): ResolvedMountRetry {
  return {
    enabled: cfg?.enabled ?? DEFAULT_MOUNT_RETRY.enabled,
    max_attempts: cfg?.max_attempts ?? DEFAULT_MOUNT_RETRY.max_attempts,
    base_ms: cfg?.base_ms ?? DEFAULT_MOUNT_RETRY.base_ms,
    factor: cfg?.factor ?? DEFAULT_MOUNT_RETRY.factor,
    max_ms: cfg?.max_ms ?? DEFAULT_MOUNT_RETRY.max_ms,
  };
}

/**
 * Delay (ms) before the `attempt`-th retry, or `null` when no retry should happen.
 *
 * `attempt` is 1-based: 1 = the first retry after the initial mount failed. Returns `null`
 * — the give-up signal the scheduler stops on — when retry is disabled, when `max_attempts`
 * is 0, when `attempt` falls outside `[1, max_attempts]`, or when the policy is degenerate
 * (non-finite / non-positive base or factor). Otherwise: `min(base_ms · factor^(attempt-1),
 * max_ms)`, rounded to a whole millisecond.
 */
export function retryDelay(attempt: number, cfg?: MountRetryConfig): number | null {
  const p = resolveMountRetry(cfg);
  if (!p.enabled || p.max_attempts <= 0) return null;
  if (!Number.isInteger(attempt) || attempt < 1 || attempt > p.max_attempts) return null;
  if (!Number.isFinite(p.base_ms) || p.base_ms <= 0) return null;
  if (!Number.isFinite(p.factor) || p.factor <= 0) return null;
  const raw = p.base_ms * Math.pow(p.factor, attempt - 1);
  const capped = Math.min(raw, p.max_ms);
  return Math.round(capped);
}
