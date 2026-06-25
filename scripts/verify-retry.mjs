/**
 * verify-retry.mjs — deterministic oracle for the self-healing mount-retry backoff (Gap 9).
 *
 * Two halves, zero dependencies:
 *   1. PURE MATH — import retryDelay / resolveMountRetry / DEFAULT_MOUNT_RETRY from dist/ and
 *      pin every branch: the give-up signals (disabled, max_attempts:0, out-of-range, degenerate
 *      policy), the exact exponential schedule, the max_ms cap, custom base/factor, rounding,
 *      and default-folding. The module is side-effect-free (no timers, no clock) so the schedule
 *      is testable to the millisecond.
 *   2. STATIC SCAN — read dist/gateway.js and prove the impure scheduler is wired correctly:
 *      retryDelay is consulted, the failure path schedules a remount, the timer is `.unref()`'d
 *      (so a pending retry can't hang the process), the timer is tracked, and shutdown cancels
 *      every pending timer (so a dead server can't resurrect after teardown).
 *
 * Run: node scripts/verify-retry.mjs   (exits non-zero on any FAIL)
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { retryDelay, resolveMountRetry, DEFAULT_MOUNT_RETRY } from "../dist/retry.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const checks = [];
function assert(name, cond, detail = "") {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? `  — ${detail}` : ""}`);
}

// ── 1. defaults are exactly the documented self-healing schedule ───────────────────────────
assert("DEFAULT enabled", DEFAULT_MOUNT_RETRY.enabled === true);
assert("DEFAULT max_attempts=5", DEFAULT_MOUNT_RETRY.max_attempts === 5);
assert("DEFAULT base_ms=1000", DEFAULT_MOUNT_RETRY.base_ms === 1000);
assert("DEFAULT factor=2", DEFAULT_MOUNT_RETRY.factor === 2);
assert("DEFAULT max_ms=30000", DEFAULT_MOUNT_RETRY.max_ms === 30000);

// ── 2. default schedule: 1s, 2s, 4s, 8s, 16s then give up ──────────────────────────────────
assert("attempt 1 → 1000ms", retryDelay(1) === 1000);
assert("attempt 2 → 2000ms", retryDelay(2) === 2000);
assert("attempt 3 → 4000ms", retryDelay(3) === 4000);
assert("attempt 4 → 8000ms", retryDelay(4) === 8000);
assert("attempt 5 → 16000ms", retryDelay(5) === 16000);
assert("attempt 6 → null (spent)", retryDelay(6) === null);
const total = [1, 2, 3, 4, 5].reduce((s, a) => s + retryDelay(a), 0);
assert("default budget ≈ 31s", total === 31000, `${total}ms over 5 retries`);

// ── 3. out-of-range / non-integer attempts give up (never throw, never NaN) ────────────────
assert("attempt 0 → null", retryDelay(0) === null);
assert("attempt -1 → null", retryDelay(-1) === null);
assert("attempt 1.5 → null", retryDelay(1.5) === null);
assert("attempt NaN → null", retryDelay(NaN) === null);
assert("attempt Infinity → null", retryDelay(Infinity) === null);

// ── 4. disabled / zeroed policy never schedules ────────────────────────────────────────────
assert("disabled → null", retryDelay(1, { enabled: false }) === null);
assert("max_attempts:0 → null", retryDelay(1, { max_attempts: 0 }) === null);
assert("max_attempts:0 at any attempt → null", retryDelay(3, { max_attempts: 0 }) === null);

// ── 5. degenerate policy is rejected (no NaN/negative delay can reach a setTimeout) ─────────
assert("base_ms:0 → null", retryDelay(1, { base_ms: 0 }) === null);
assert("base_ms negative → null", retryDelay(1, { base_ms: -5 }) === null);
assert("factor:0 → null", retryDelay(1, { factor: 0 }) === null);
assert("factor negative → null", retryDelay(1, { factor: -2 }) === null);

// ── 6. max_ms cap clamps the tail of the curve ─────────────────────────────────────────────
// base 1000, factor 10, cap 5000: 1000, 5000(capped from 10000), 5000(capped), …
assert("cap: attempt 1 uncapped", retryDelay(1, { factor: 10, max_ms: 5000, max_attempts: 5 }) === 1000);
assert("cap: attempt 2 capped", retryDelay(2, { factor: 10, max_ms: 5000, max_attempts: 5 }) === 5000);
assert("cap: attempt 3 stays capped", retryDelay(3, { factor: 10, max_ms: 5000, max_attempts: 5 }) === 5000);
assert(
  "cap: max_ms below base clamps immediately",
  retryDelay(1, { base_ms: 9000, max_ms: 500, max_attempts: 3 }) === 500,
);

// ── 7. custom base/factor compute the right curve, rounded to whole ms ──────────────────────
assert("custom base 250 factor 3 → a1", retryDelay(1, { base_ms: 250, factor: 3, max_attempts: 4 }) === 250);
assert("custom base 250 factor 3 → a2", retryDelay(2, { base_ms: 250, factor: 3, max_attempts: 4 }) === 750);
assert("custom base 250 factor 3 → a3", retryDelay(3, { base_ms: 250, factor: 3, max_attempts: 4 }) === 2250);
assert(
  "fractional factor rounds to whole ms",
  retryDelay(2, { base_ms: 100, factor: 1.5, max_attempts: 5 }) === 150,
);
assert(
  "fractional product rounds (Math.round, not floor)",
  // base 100, factor 1.25, attempt 4 → 100*1.953125 = 195.3125 → 195
  retryDelay(4, { base_ms: 100, factor: 1.25, max_attempts: 6 }) === 195,
);

// ── 8. resolveMountRetry folds partial policy over defaults (single source of truth) ───────
const folded = resolveMountRetry({ base_ms: 500 });
assert("resolve: override base_ms", folded.base_ms === 500);
assert("resolve: keep default factor", folded.factor === 2);
assert("resolve: keep default max_attempts", folded.max_attempts === 5);
assert("resolve: keep default enabled", folded.enabled === true);
assert("resolve: keep default max_ms", folded.max_ms === 30000);
const foldedEmpty = resolveMountRetry();
assert(
  "resolve: undefined → exact defaults",
  JSON.stringify(foldedEmpty) === JSON.stringify(DEFAULT_MOUNT_RETRY),
);
// passing an already-resolved policy back in is idempotent (gateway does this)
assert(
  "resolve idempotent on resolved policy",
  JSON.stringify(resolveMountRetry(folded)) === JSON.stringify(folded),
);
assert("retryDelay accepts resolved policy", retryDelay(2, folded) === 1000);

// ── 9. static scan of dist/gateway.js — the impure scheduler is wired correctly ─────────────
const gw = readFileSync(join(__dirname, "..", "dist", "gateway.js"), "utf8");
assert("gateway imports retryDelay", /retryDelay/.test(gw) && /resolveMountRetry/.test(gw));
assert("gateway has scheduleRemount", /scheduleRemount\s*\(/.test(gw));
assert("gateway has attemptRemount", /attemptRemount\s*\(/.test(gw));
assert("scheduleRemount is called from the mount-failure path", /this\.scheduleRemount\(\s*server\s*,\s*1\s*\)/.test(gw));
assert("scheduler consults retryDelay", /retryDelay\(\s*attempt/.test(gw));
assert("timer is unref()'d (cannot hang the process)", /\.unref\(\)/.test(gw));
assert("pending timers are tracked in a Set", /pendingRetries/.test(gw) && /\.add\(\s*timer\s*\)/.test(gw));
assert("shutdown cancels pending timers", /clearTimeout\(\s*timer\s*\)/.test(gw) && /pendingRetries\.clear\(\)/.test(gw));
assert("shutdown sets the shuttingDown guard", /this\.shuttingDown\s*=\s*true/.test(gw));
assert("scheduler bails when shutting down", /if\s*\(\s*this\.shuttingDown\s*\)\s*return/.test(gw));
// ordering: the shuttingDown guard + timer cancel must precede unmountAll in shutdown
const shutdownIdx = gw.indexOf("shutdown");
const clearIdx = gw.indexOf("pendingRetries.clear()");
const unmountIdx = gw.indexOf("unmountAll", shutdownIdx);
assert(
  "shutdown clears timers BEFORE unmountAll",
  clearIdx > -1 && unmountIdx > -1 && clearIdx < unmountIdx,
  `clear=${clearIdx} unmountAll=${unmountIdx}`,
);

// ── 10. config-schema scan — mount_retry is a validated, strict settings field ──────────────
const cfgSrc = readFileSync(join(__dirname, "..", "dist", "config.js"), "utf8");
assert("config validates mount_retry", /mount_retry/.test(cfgSrc));
assert("mountRetry schema is strict", /mountRetry[\s\S]{0,400}\.strict\(\)/.test(cfgSrc));

// ── footer ──────────────────────────────────────────────────────────────────────────────────
const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
process.exitCode = failed.length === 0 ? 0 : 1;
