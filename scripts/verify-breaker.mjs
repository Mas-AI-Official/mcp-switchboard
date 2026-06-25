/**
 * verify-breaker.mjs — deterministic oracle for the per-server circuit breaker (Feature: Breaker).
 *
 * A hosted aggregator absorbs upstream outages for you; a self-hosted proxy must do it itself or
 * every call to a dead server pays the full `call_timeout_ms` and the agent rediscovers the outage
 * one slow call at a time. The breaker watches each server's TRANSPORT health (throws/timeouts, NOT
 * well-formed tool error *results*) and, after N consecutive failures, OPENS — failing fast with an
 * honest "unavailable, retry in ~Ts" — then auto-probes after a cooldown.
 *
 * This proves the state machine with a synthetic clock (no wall time, no network, no boot):
 *   • Fast path — unconfigured (or opt-in-not-enabled) ⇒ allow is constant-true, record is a no-op.
 *   • Threshold — closed until the Nth consecutive failure, then open; denies carry a finite,
 *     positive retryAfterMs and a self-explaining reason; siblings are independent.
 *   • Cooldown → half_open — one probe released at the boundary, re-armed so concurrent calls don't
 *     stampede a recovering server; success closes, failure re-opens for a fresh cooldown.
 *   • Streak reset — a success between failures clears the count (CONSECUTIVE, not cumulative).
 *   • Layering — per-server threshold override, per-server enabled:false exempt under a global ON,
 *     per-server enabled:true active under a global OFF (others then exempt).
 *   • Units — cooldown_seconds*1000 = retryAfterMs, decaying linearly to the probe boundary.
 *   • health()/snapshot() — pure reads that never flip state (safe for a dashboard poll).
 *   • Round-trip — settings/server resilience survive writeConfig→loadConfig through zod and drive a
 *     live Breaker; malformed tuning (0 / negative / fractional / unknown field) is REJECTED.
 *
 * Run: node scripts/verify-breaker.mjs   (exit 0 = all green, 1 = a check failed)
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Breaker } from "../dist/breaker.js";
import { starterConfig, writeConfig, loadConfig } from "../dist/config.js";

const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "ok  " : "FAIL"} ${name}${detail ? ` — ${detail}` : ""}`);
};
const throws = (fn) => {
  try {
    fn();
    return false;
  } catch {
    return true;
  }
};

// Global-enabled config factory: threshold 3, cooldown 30s, two servers. `over` tweaks the tuning.
const G = (over = {}) => ({
  settings: { resilience: { enabled: true, failure_threshold: 3, cooldown_seconds: 30, ...over } },
  servers: [{ id: "a" }, { id: "b" }],
});

const root = mkdtempSync(join(tmpdir(), "sb-breaker-"));
try {
  // ---- Fast path: inert when resilience is enabled nowhere -----------------
  {
    const b = new Breaker({ servers: [{ id: "a" }] }); // no resilience anywhere
    const d = b.allow("a", 0);
    assert("fastpath: allow ok + closed when unconfigured", d.ok === true && d.state === "closed");
    for (let i = 0; i < 100; i++) b.record("a", false, 0);
    assert("fastpath: record is a no-op (never opens)", b.allow("a", 0).ok === true);
    assert("fastpath: snapshot empty (no buckets allocated)", b.snapshot(0).length === 0);
  }
  {
    // Opt-in semantics: a resilience block WITHOUT enabled:true is still inert.
    const b = new Breaker({ settings: { resilience: { failure_threshold: 2 } }, servers: [{ id: "a" }] });
    for (let i = 0; i < 10; i++) b.record("a", false, 0);
    assert("optin: resilience without enabled:true stays inert", b.allow("a", 0).ok === true);
  }

  // ---- Threshold: closed → open at the Nth consecutive failure -------------
  {
    const b = new Breaker(G());
    b.record("a", false, 0);
    b.record("a", false, 0);
    const pre = b.allow("a", 0);
    assert("trip: still closed before the threshold", pre.ok === true && pre.state === "closed");
    b.record("a", false, 0); // 3rd consecutive failure ⇒ open
    const d = b.allow("a", 0);
    assert("trip: opens exactly at the threshold", d.ok === false && d.state === "open");
    assert("trip: deny carries a finite, positive retryAfterMs", Number.isFinite(d.retryAfterMs) && d.retryAfterMs === 30000);
    assert(
      "trip: deny reason is self-explaining",
      /circuit is open/.test(d.reason) && /'a'/.test(d.reason) && /3 consecutive/.test(d.reason),
      d.reason,
    );
    assert("trip: a different server is unaffected", b.allow("b", 0).ok === true);
  }

  // ---- Cooldown → single half_open probe (stampede gate) -------------------
  {
    const b = new Breaker(G());
    for (let i = 0; i < 3; i++) b.record("a", false, 0); // open at openedAt=0
    assert("cooldown: denied 1ms before the window", b.allow("a", 29999).ok === false);
    const probe = b.allow("a", 30000);
    assert("cooldown: half_open probe released at the window", probe.ok === true && probe.state === "half_open");
    // releasing the probe re-armed the cooldown ⇒ a concurrent call is gated to ONE attempt.
    assert("cooldown: concurrent call blocked while the probe is in flight", b.allow("a", 30000).ok === false);
    assert("cooldown: still blocked moments later", b.allow("a", 30050).ok === false);
  }

  // ---- Recovery: probe success closes, probe failure re-opens --------------
  {
    const b = new Breaker(G());
    for (let i = 0; i < 3; i++) b.record("a", false, 0);
    b.allow("a", 30000); // half_open
    b.record("a", true, 30010); // probe success
    const d = b.allow("a", 30010);
    assert("recover: a probe success closes the circuit", d.ok === true && d.state === "closed");
  }
  {
    const b = new Breaker(G());
    for (let i = 0; i < 3; i++) b.record("a", false, 0);
    b.allow("a", 30000); // half_open, openedAt re-armed to 30000, failures still 3
    b.record("a", false, 30010); // probe fails ⇒ failures=4 ≥ 3 ⇒ re-open at 30010
    const d = b.allow("a", 30010);
    assert("recover: a probe failure re-opens", d.ok === false && d.state === "open");
    assert("recover: re-open re-arms the cooldown from the probe time", d.retryAfterMs === 30000);
    const probe2 = b.allow("a", 60010);
    assert("recover: another cooldown frees a fresh probe", probe2.state === "half_open");
  }

  // ---- Streak reset: failures are CONSECUTIVE, not cumulative --------------
  {
    const b = new Breaker(G());
    b.record("a", false, 0); // 1
    b.record("a", true, 0); // success ⇒ reset to 0
    b.record("a", false, 0); // 1 (not 2) ⇒ still closed
    assert("reset: a success between failures clears the streak", b.allow("a", 0).ok === true);
    assert("reset: health reflects only the current streak", b.health("a", 0).consecutiveFailures === 1);
  }

  // ---- Per-server threshold override --------------------------------------
  {
    const cfg = {
      settings: { resilience: { enabled: true, failure_threshold: 5 } },
      servers: [{ id: "a", resilience: { failure_threshold: 2 } }, { id: "b" }],
    };
    const b = new Breaker(cfg);
    b.record("a", false, 0);
    b.record("a", false, 0); // 2 ⇒ open (override is tighter)
    assert("override: per-server threshold trips earlier", b.allow("a", 0).ok === false);
    for (let i = 0; i < 4; i++) b.record("b", false, 0); // 4 < global 5 ⇒ closed
    assert("override: an inheriting server uses the global threshold", b.allow("b", 0).ok === true);
    b.record("b", false, 0); // 5 ⇒ open
    assert("override: the inheriting server opens at the global threshold", b.allow("b", 0).ok === false);
  }

  // ---- Per-server enabled:false exempt, under a global ON ------------------
  {
    const cfg = {
      settings: { resilience: { enabled: true, failure_threshold: 2 } },
      servers: [{ id: "a", resilience: { enabled: false } }, { id: "b" }],
    };
    const b = new Breaker(cfg);
    for (let i = 0; i < 50; i++) b.record("a", false, 0);
    assert("exempt: a server with enabled:false never opens", b.allow("a", 0).ok === true);
    assert("exempt: an exempt server creates no entry", b.snapshot(0).some((s) => s.server === "a") === false);
    b.record("b", false, 0);
    b.record("b", false, 0);
    assert("exempt: a non-exempt sibling still trips", b.allow("b", 0).ok === false);
  }

  // ---- Per-server enabled:true under a global OFF -------------------------
  {
    const cfg = {
      servers: [{ id: "a", resilience: { enabled: true, failure_threshold: 2 } }, { id: "b" }],
    };
    const b = new Breaker(cfg);
    assert("local-on: a single opt-in activates the breaker", b.allow("a", 0).state === "closed");
    b.record("a", false, 0);
    b.record("a", false, 0);
    assert("local-on: the opted-in server opens with the global off", b.allow("a", 0).ok === false);
    for (let i = 0; i < 100; i++) b.record("b", false, 0);
    assert("local-on: a non-opted server stays exempt with the global off", b.allow("b", 0).ok === true);
  }

  // ---- Units: cooldown_seconds → ms, retryAfterMs decay -------------------
  {
    const b = new Breaker(G({ failure_threshold: 1, cooldown_seconds: 30 }));
    b.record("a", false, 0); // open at 0
    assert("units: cooldown_seconds*1000 = retryAfterMs at open", b.allow("a", 0).retryAfterMs === 30000);
    assert("units: retryAfterMs decays linearly", b.allow("a", 10000).retryAfterMs === 20000);
    assert("units: the probe fires exactly at the boundary", b.allow("a", 30000).state === "half_open");
  }

  // ---- health()/snapshot() are pure reads (never mutate state) ------------
  {
    const b = new Breaker(G({ failure_threshold: 1 }));
    b.record("a", false, 0); // open at 0
    const h1 = b.health("a", 0);
    assert("health: reports open with the failure count and retry window", h1.state === "open" && h1.consecutiveFailures === 1 && h1.retryAfterMs === 30000);
    // Past the cooldown, health must NOT transition to half_open (that's allow()'s job).
    const h2 = b.health("a", 30000);
    assert("health: at/after the cooldown still reports open, never half_open", h2.state === "open" && h2.retryAfterMs === 0);
    // Because health didn't consume it, allow() at the boundary still releases the probe.
    assert("health: did not consume the transition", b.allow("a", 30000).state === "half_open");
  }
  {
    const cfg = {
      settings: { resilience: { enabled: true, failure_threshold: 2 } },
      servers: [{ id: "a" }, { id: "b" }, { id: "c", resilience: { enabled: false } }],
    };
    const b = new Breaker(cfg);
    b.record("a", false, 0);
    b.record("a", false, 0); // a ⇒ open
    b.record("b", false, 0); // b ⇒ one failure, closed
    b.record("c", false, 0); // exempt ⇒ no entry
    const byId = Object.fromEntries(b.snapshot(0).map((s) => [s.server, s]));
    assert("snapshot: lists only observed, non-exempt servers", Object.keys(byId).length === 2 && byId.a && byId.b && !byId.c);
    assert("snapshot: a is open with two failures", byId.a.state === "open" && byId.a.consecutiveFailures === 2);
    assert("snapshot: b is closed with one failure", byId.b.state === "closed" && byId.b.consecutiveFailures === 1);
  }

  // ---- Real config round-trip: resilience survives the zod schema ---------
  {
    const cfg = starterConfig();
    cfg.settings = { resilience: { enabled: true, failure_threshold: 4, cooldown_seconds: 45 } };
    cfg.servers[0].resilience = { enabled: false };
    const p = join(root, "switchboard.config.yaml");
    writeConfig(p, cfg);
    const r = loadConfig(p); // throws if any resilience field is schema-invalid
    assert(
      "roundtrip: settings.resilience survives",
      r.settings.resilience.enabled === true && r.settings.resilience.failure_threshold === 4 && r.settings.resilience.cooldown_seconds === 45,
    );
    assert("roundtrip: server.resilience survives", r.servers[0].resilience.enabled === false);
    // the reloaded config drives a live Breaker identically.
    const b = new Breaker(r);
    for (let i = 0; i < 20; i++) b.record(r.servers[0].id, false, 0);
    assert("roundtrip: reloaded exempt server stays closed", b.allow(r.servers[0].id, 0).ok === true);
    for (let i = 0; i < 4; i++) b.record("synthetic", false, 0); // inherits global threshold 4
    assert("roundtrip: reloaded global default opens an inheriting server at 4", b.allow("synthetic", 0).ok === false);
    assert("roundtrip: reloaded cooldown is 45s", b.allow("synthetic", 0).retryAfterMs === 45000);
  }

  // ---- zod: malformed tuning is REJECTED, valid minimal block ACCEPTED ----
  {
    const mk = (res) => {
      const c = starterConfig();
      c.settings = { resilience: res };
      return c;
    };
    const wr = (c, name) => {
      const p = join(root, name);
      writeConfig(p, c);
      return p;
    };
    assert("zod: failure_threshold 0 rejected (must be positive)", throws(() => loadConfig(wr(mk({ enabled: true, failure_threshold: 0 }), "bz0.yaml"))));
    assert("zod: negative failure_threshold rejected", throws(() => loadConfig(wr(mk({ enabled: true, failure_threshold: -1 }), "bzn.yaml"))));
    assert("zod: fractional cooldown_seconds rejected (must be int)", throws(() => loadConfig(wr(mk({ enabled: true, cooldown_seconds: 1.5 }), "bzf.yaml"))));
    assert("zod: unknown resilience field rejected (strict)", throws(() => loadConfig(wr(mk({ enabled: true, half_life: 5 }), "bzu.yaml"))));
    assert("zod: a valid minimal resilience block loads", !throws(() => loadConfig(wr(mk({ enabled: true }), "okmin.yaml"))));
  }
} finally {
  rmSync(root, { recursive: true, force: true });
}

const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
if (failed.length) console.log("FAILED:", failed.map((c) => c.name).join(", "));
process.exitCode = failed.length === 0 ? 0 : 1;
