/**
 * Rate limits + spend budgets — the protective inverse of a hosted router's billing meter.
 *
 * Hosted aggregators meter your calls to bill you. MCP Switchboard runs on YOUR machine, so the same
 * accounting becomes a governance control instead: cap how fast (and how expensively) an autonomous
 * agent may hit a tool, so a runaway loop or a pricey cross-provider council can't quietly burn your
 * API budget. Limits stack across three levels — global (`settings.limits`), per-server
 * (`server.limits`), and per-tool (`server.tools[name].limits`) — and a call must satisfy EVERY
 * level it touches. Denials fail CLOSED and are conservative: a call that is denied or fails upstream
 * still counts against its limit (we never under-count), because the goal is to bound blast radius,
 * not to bill precisely.
 *
 * Deterministic by construction: every method takes the current time as a parameter (`now`, ms since
 * epoch). Production passes `Date.now()`; the verifier passes synthetic timestamps to drive refill
 * without a wall clock. Zero dependencies, O(buckets-touched) per call, O(1) memory per active limit.
 */

import type { LimitSpec, SwitchboardConfig } from "./types.js";

/**
 * A classic token bucket. Capacity is the maximum burst (= the configured limit for its window);
 * tokens refill continuously at `limit / window` per ms, capped at capacity. `take` is the only
 * mutating success path. Refill is idempotent for a fixed `now`, so peeking then taking at the same
 * instant is atomic — the basis for the Governor's all-or-nothing multi-bucket commit.
 */
export class TokenBucket {
  private tokens: number;
  private lastRefillMs: number;

  constructor(
    /** Maximum tokens the bucket can hold — the configured limit for this window. */
    readonly capacity: number,
    /** Tokens regained per millisecond (= capacity / windowMs). */
    readonly refillPerMs: number,
    now: number,
  ) {
    this.tokens = capacity;
    this.lastRefillMs = now;
  }

  /** Add tokens for elapsed time since the last refill, capped at capacity. Idempotent at fixed `now`. */
  private refill(now: number): void {
    if (now <= this.lastRefillMs) return;
    const gained = (now - this.lastRefillMs) * this.refillPerMs;
    this.tokens = Math.min(this.capacity, this.tokens + gained);
    this.lastRefillMs = now;
  }

  /** Tokens available right now (after refill), without consuming any. */
  peek(now: number): number {
    this.refill(now);
    return this.tokens;
  }

  /** Remove `need` tokens if available. Returns true (and mutates) on success, false (no change) otherwise. */
  take(need: number, now: number): boolean {
    this.refill(now);
    if (this.tokens + 1e-9 >= need) {
      this.tokens -= need;
      return true;
    }
    return false;
  }

  /** Milliseconds until `need` tokens would be available — 0 if available now, Infinity if unreachable. */
  retryAfterMs(need: number, now: number): number {
    this.refill(now);
    if (this.tokens + 1e-9 >= need) return 0;
    if (need > this.capacity || this.refillPerMs <= 0) return Infinity;
    return Math.ceil((need - this.tokens) / this.refillPerMs);
  }
}

/** The level a limit was attached to — surfaced in the denial so the operator knows what to raise. */
export type LimitLevel = "global" | "server" | "tool";
/** Which rolling window a limit governs. */
export type LimitWindow = "minute" | "hour" | "day";
/** Whether the binding limit counted calls (`rate`) or summed `cost` (`cost`). */
export type LimitKind = "rate" | "cost";

/** Outcome of a `Governor.consume` decision. `ok:false` means the call must be denied, fail-closed. */
export interface GovernorDecision {
  ok: boolean;
  /** When denied: ms until the binding bucket would admit the call (Infinity = unsatisfiable as configured). */
  retryAfterMs?: number;
  /** When denied: a one-line, actionable explanation of the binding limit. */
  reason?: string;
  level?: LimitLevel;
  window?: LimitWindow;
  kind?: LimitKind;
}

interface WindowSpec {
  key: LimitWindow;
  ms: number;
  countField: keyof LimitSpec;
  costField: keyof LimitSpec;
}

const WINDOWS: readonly WindowSpec[] = [
  { key: "minute", ms: 60_000, countField: "per_minute", costField: "cost_per_minute" },
  { key: "hour", ms: 3_600_000, countField: "per_hour", costField: "cost_per_hour" },
  { key: "day", ms: 86_400_000, countField: "per_day", costField: "cost_per_day" },
];

// Composite map keys are built with JSON.stringify of a tuple, so they are unambiguous regardless of
// what characters appear in server ids or tool names — no separator char to collide (server "a" +
// tool "b__c" serializes differently from server "a__b" + tool "c").
function tupleKey(parts: readonly string[]): string {
  return JSON.stringify(parts);
}

/** One bucket draw resolved for a single call: the bucket, how much to take, and how to describe it. */
interface Draw {
  bucket: TokenBucket;
  need: number;
  level: LimitLevel;
  window: LimitWindow;
  kind: LimitKind;
}

/**
 * Enforces the configured rate limits and spend budgets. One instance per Router (per loaded
 * config); its buckets persist across calls for the Router's lifetime. Config is immutable for that
 * lifetime, so a reload builds a fresh Router (and Governor) — buckets never need re-keying.
 */
export class Governor {
  private readonly buckets = new Map<string, TokenBucket>();
  private readonly globalLimits?: LimitSpec;
  private readonly serverLimits = new Map<string, LimitSpec>();
  private readonly toolLimits = new Map<string, LimitSpec>();
  private readonly toolCost = new Map<string, number>();
  /** Fast path: when no limits are configured anywhere, `consume` returns immediately. */
  private readonly active: boolean;

  constructor(cfg: SwitchboardConfig) {
    this.globalLimits = hasAny(cfg.settings?.limits) ? cfg.settings!.limits : undefined;
    for (const server of cfg.servers ?? []) {
      if (hasAny(server.limits)) this.serverLimits.set(server.id, server.limits!);
      for (const [toolName, ov] of Object.entries(server.tools ?? {})) {
        const tk = tupleKey([server.id, toolName]);
        if (hasAny(ov.limits)) this.toolLimits.set(tk, ov.limits!);
        if (typeof ov.cost === "number" && ov.cost > 0) this.toolCost.set(tk, ov.cost);
      }
    }
    this.active =
      this.globalLimits !== undefined || this.serverLimits.size > 0 || this.toolLimits.size > 0;
  }

  /** Find-or-create a bucket. Capacity/refill are fixed at first touch (config is immutable here). */
  private bucketFor(key: string, capacity: number, windowMs: number, now: number): TokenBucket {
    let b = this.buckets.get(key);
    if (!b) {
      b = new TokenBucket(capacity, capacity / windowMs, now);
      this.buckets.set(key, b);
    }
    return b;
  }

  /**
   * Atomically charge one call against every limit that applies to (serverId, toolName) at `now`.
   * All-or-nothing: if ANY bucket would be exceeded, nothing is deducted and the call is denied with
   * the binding limit. On success, every applicable bucket is debited (1 call, plus the tool's `cost`
   * against any cost budget). The caller must NOT refund on a later upstream failure — limits count
   * attempts, conservatively, to bound runaway loops.
   */
  consume(serverId: string, toolName: string, now: number): GovernorDecision {
    if (!this.active) return { ok: true };

    const tk = tupleKey([serverId, toolName]);
    const cost = this.toolCost.get(tk) ?? 0;

    // Most-specific level first, so the reported denial names the tightest binding limit.
    const levels: ReadonlyArray<[LimitLevel, readonly string[], LimitSpec | undefined]> = [
      ["tool", ["tool", serverId, toolName], this.toolLimits.get(tk)],
      ["server", ["server", serverId], this.serverLimits.get(serverId)],
      ["global", ["global"], this.globalLimits],
    ];

    const draws: Draw[] = [];
    for (const [level, keyParts, spec] of levels) {
      if (!spec) continue;
      for (const w of WINDOWS) {
        const countLimit = spec[w.countField];
        if (typeof countLimit === "number") {
          const bucket = this.bucketFor(tupleKey([...keyParts, "rate", w.key]), countLimit, w.ms, now);
          draws.push({ bucket, need: 1, level, window: w.key, kind: "rate" });
        }
        const costLimit = spec[w.costField];
        if (typeof costLimit === "number" && cost > 0) {
          const bucket = this.bucketFor(tupleKey([...keyParts, "cost", w.key]), costLimit, w.ms, now);
          draws.push({ bucket, need: cost, level, window: w.key, kind: "cost" });
        }
      }
    }

    if (draws.length === 0) return { ok: true };

    // Phase 1 — check every bucket without committing. First binding limit (most specific level,
    // shortest window) is the one reported. Refill inside peek is idempotent at this `now`.
    for (const d of draws) {
      if (d.need > d.bucket.capacity) {
        return {
          ok: false,
          retryAfterMs: Infinity,
          reason: misconfigReason(d, serverId, toolName),
          level: d.level,
          window: d.window,
          kind: d.kind,
        };
      }
      if (d.bucket.peek(now) < d.need) {
        return {
          ok: false,
          retryAfterMs: d.bucket.retryAfterMs(d.need, now),
          reason: denyReason(d, serverId, toolName),
          level: d.level,
          window: d.window,
          kind: d.kind,
        };
      }
    }

    // Phase 2 — commit. Pre-checked at this same `now`, so every take() succeeds.
    for (const d of draws) d.bucket.take(d.need, now);
    return { ok: true };
  }
}

/** True when a LimitSpec has at least one numeric ceiling set. */
function hasAny(spec: LimitSpec | undefined): boolean {
  if (!spec) return false;
  return (
    typeof spec.per_minute === "number" ||
    typeof spec.per_hour === "number" ||
    typeof spec.per_day === "number" ||
    typeof spec.cost_per_minute === "number" ||
    typeof spec.cost_per_hour === "number" ||
    typeof spec.cost_per_day === "number"
  );
}

/** "global" | "server 'github'" | "tool 'github__create_issue'" — the subject of the limit. */
function subject(level: LimitLevel, serverId: string, toolName: string): string {
  if (level === "global") return "global";
  if (level === "server") return `server '${serverId}'`;
  return `tool '${serverId}__${toolName}'`;
}

function denyReason(d: Draw, serverId: string, toolName: string): string {
  const who = subject(d.level, serverId, toolName);
  const unit = d.kind === "cost" ? `${d.bucket.capacity} cost` : `${d.bucket.capacity} calls`;
  return `${who} exceeded its ${unit}/${d.window} ${d.kind === "cost" ? "budget" : "rate limit"}`;
}

function misconfigReason(d: Draw, serverId: string, toolName: string): string {
  const who = subject(d.level, serverId, toolName);
  return `${who} call cost ${d.need} exceeds its ${d.bucket.capacity} cost/${d.window} budget — the call can never pass`;
}
