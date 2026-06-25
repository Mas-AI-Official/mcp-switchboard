/**
 * verify-doctor.mjs — deterministic oracle for the pre-flight `doctor` diagnosis (Gap 5+13).
 *
 * The diagnosis is computed by a single pure function, `buildDoctorReport`, so it is testable to
 * the row without spawning a process, mounting a server, or touching disk. Two halves, zero deps:
 *
 *   1. PURE LOGIC — pin every branch of the report:
 *        • meetsNodeFloor: the semver-lite comparator across major/minor/patch, v-prefix, and noise.
 *        • a healthy config produces ok:true with an empty problems list.
 *        • each defect surfaces exactly one finding and flips ok:false — an unresolvable secret ref,
 *          a `${oauth:..}` ref to a provider with no client id, a duplicate server id, and a per-tool
 *          policy trap (a write tool under a read ceiling). The oauth check is skipped when no
 *          client-id set is supplied (so the CLI can run it offline).
 *        • ok === (problems.length === 0) holds — the summary verdict can't drift from the detail.
 *   2. STATIC SCAN — read dist/cli.js and prove the CLI renders FROM the report (one source of
 *      truth), not a second hand-rolled copy of the checks.
 *
 * Run: node scripts/verify-doctor.mjs   (exits non-zero on any FAIL)
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { buildDoctorReport, meetsNodeFloor, NODE_FLOOR } from "../dist/doctor.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const checks = [];
function assert(name, cond, detail = "") {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${detail ? `  — ${detail}` : ""}`);
}

// A minimal config the report can read. buildDoctorReport only touches servers, the default policy,
// transport, the http host/port, and the vault backend — so a plain literal is enough (no zod).
function mkCfg(servers) {
  return {
    vault: { backend: "file" },
    gateway: { default_policy: "read", transport: ["http"], http: { host: "127.0.0.1", port: 8787 } },
    servers,
  };
}
// A resolver that mimics Vault.resolve: throws fail-closed on a missing ref, echoes otherwise.
const resolve = (v) => {
  if (typeof v === "string" && v.includes("MISSING")) throw new Error(`vault secret 'MISSING' is not set`);
  return v;
};

// ── 1. meetsNodeFloor — semver-lite, total, never throws ─────────────────────────────────────
assert("NODE_FLOOR is 18.18.0", NODE_FLOOR === "18.18.0");
assert("equal version meets floor", meetsNodeFloor("18.18.0", "18.18.0") === true);
assert("higher patch meets floor", meetsNodeFloor("18.18.1", "18.18.0") === true);
assert("lower patch fails floor", meetsNodeFloor("18.18.0", "18.18.1") === false);
assert("lower minor fails floor", meetsNodeFloor("18.17.9", "18.18.0") === false);
assert("higher minor meets floor", meetsNodeFloor("18.19.0", "18.18.0") === true);
assert("lower major fails floor", meetsNodeFloor("17.99.99", "18.18.0") === false);
assert("higher major meets floor", meetsNodeFloor("22.10.5", "18.18.0") === true);
assert("v-prefix is tolerated", meetsNodeFloor("v22.10.5", "18.18.0") === true);
assert("missing patch segment defaults to 0", meetsNodeFloor("18.18", "18.18.0") === true);
assert("garbage parses low, fails floor (no throw)", meetsNodeFloor("garbage", "18.18.0") === false);

// ── 2. a healthy config: ok, no problems, node passes ────────────────────────────────────────
{
  const cfg = mkCfg([
    { id: "weather", source: "npx", policy: "read", tools: { get_forecast: {} } },
    { id: "github", source: "remote", policy: "write", credentials: { token: "${oauth:github}" } },
  ]);
  const r = buildDoctorReport({ cfg, resolve, oauthClientIds: new Set(["github"]), nodeVersion: "22.10.5" });
  assert("healthy: ok true", r.ok === true);
  assert("healthy: zero problems", r.problems.length === 0, JSON.stringify(r.problems));
  assert("healthy: node.ok true", r.node.ok === true);
  assert("healthy: node version echoed", r.node.version === "22.10.5");
  assert("healthy: endpoint composed from host:port", r.endpoint === "http://127.0.0.1:8787/mcp", r.endpoint);
  assert("healthy: vault backend echoed", r.vaultBackend === "file");
  assert("healthy: transports echoed", JSON.stringify(r.transports) === JSON.stringify(["http"]));
  assert("healthy: server count preserved", r.servers.length === 2);
  assert("healthy: no per-server findings", r.servers.every((s) => !s.unresolved.length && !s.policyTraps.length && !s.oauthUnconfigured.length && !s.duplicateId));
  assert("healthy: configured oauth provider with a client id is NOT flagged", r.servers[1].oauthUnconfigured.length === 0);
}

// ── 3. unresolvable secret ref is surfaced, fail-closed ──────────────────────────────────────
{
  const cfg = mkCfg([{ id: "db", source: "npx", policy: "read", env: { DSN: "${vault:MISSING}" } }]);
  const r = buildDoctorReport({ cfg, resolve, nodeVersion: "22.10.5" });
  assert("unresolved: ok false", r.ok === false);
  assert("unresolved: one finding on the server", r.servers[0].unresolved.length === 1, JSON.stringify(r.servers[0].unresolved));
  assert("unresolved: problem mentions the server id", r.problems.some((p) => p.includes("db")), JSON.stringify(r.problems));
  assert("unresolved: carries the fail-closed message", r.servers[0].unresolved[0].includes("MISSING"));
}

// ── 4. ${oauth:..} ref to a provider with no client id ───────────────────────────────────────
{
  const cfg = mkCfg([
    { id: "slackbot", source: "remote", policy: "write", credentials: { token: "${oauth:slack}" } },
    { id: "notiontool", source: "http-tool", policy: "read", inject_args: { auth: "${oauth:notion}" } },
  ]);
  const withSet = buildDoctorReport({ cfg, resolve, oauthClientIds: new Set(["github"]), nodeVersion: "22.10.5" });
  assert("oauth: slack flagged (no client id)", withSet.servers[0].oauthUnconfigured.includes("slack"));
  assert("oauth: notion flagged from inject_args (3rd value map scanned)", withSet.servers[1].oauthUnconfigured.includes("notion"));
  assert("oauth: ok false when a provider is unconfigured", withSet.ok === false);
  assert("oauth: problem names the provider + remedy", withSet.problems.some((p) => p.includes("slack") && p.includes("connect")));
  // When no client-id set is supplied, the oauth check is skipped entirely (offline-safe).
  const noSet = buildDoctorReport({ cfg, resolve, nodeVersion: "22.10.5" });
  assert("oauth: skipped when no client-id set passed", noSet.servers.every((s) => s.oauthUnconfigured.length === 0));
  assert("oauth: ok true when the check is skipped and nothing else is wrong", noSet.ok === true);
}

// ── 5. duplicate server id (tool namespace collision) ────────────────────────────────────────
{
  const cfg = mkCfg([
    { id: "tools", source: "npx", policy: "read" },
    { id: "tools", source: "remote", policy: "read" },
  ]);
  const r = buildDoctorReport({ cfg, resolve, nodeVersion: "22.10.5" });
  assert("dup: first occurrence not flagged", r.servers[0].duplicateId === false);
  assert("dup: second occurrence flagged", r.servers[1].duplicateId === true);
  assert("dup: ok false", r.ok === false);
  assert("dup: problem mentions namespace collision", r.problems.some((p) => p.includes("collision")));
}

// ── 6. policy trap: a write tool under a read ceiling ────────────────────────────────────────
{
  const cfg = mkCfg([
    { id: "capped", source: "npx", policy: "read", tools: { push: { policy: "write" } } },
    { id: "open", source: "npx", policy: "full", tools: { push: { policy: "write" } } },
  ]);
  const r = buildDoctorReport({ cfg, resolve, nodeVersion: "22.10.5" });
  assert("trap: write tool denied under read ceiling", r.servers[0].policyTraps.length === 1, JSON.stringify(r.servers[0].policyTraps));
  assert("trap: reason names the tool and the cap", r.servers[0].policyTraps[0].reason.includes("push") && r.servers[0].policyTraps[0].reason.includes("read"));
  assert("trap: same tool fine under a full ceiling (no false positive)", r.servers[1].policyTraps.length === 0);
  assert("trap: ok false", r.ok === false);
}

// ── 7. node below the floor is a problem ─────────────────────────────────────────────────────
{
  const cfg = mkCfg([{ id: "x", source: "npx", policy: "read" }]);
  const r = buildDoctorReport({ cfg, resolve, nodeVersion: "16.0.0" });
  assert("oldnode: node.ok false", r.node.ok === false);
  assert("oldnode: floor recorded on the report", r.node.floor === NODE_FLOOR);
  assert("oldnode: problem lists the version and floor", r.problems.some((p) => p.includes("16.0.0") && p.includes(NODE_FLOOR)));
  assert("oldnode: ok false even with otherwise-clean servers", r.ok === false);
}

// ── 8. the verdict can't drift from the detail ───────────────────────────────────────────────
for (const [label, inputs] of [
  ["clean", { cfg: mkCfg([{ id: "a", source: "npx", policy: "read" }]), resolve, nodeVersion: "22.10.5" }],
  ["dirty", { cfg: mkCfg([{ id: "a", source: "npx", policy: "read", env: { K: "${vault:MISSING}" } }]), resolve, nodeVersion: "22.10.5" }],
]) {
  const r = buildDoctorReport(inputs);
  assert(`invariant: ok === (problems empty) [${label}]`, r.ok === (r.problems.length === 0), `ok=${r.ok} problems=${r.problems.length}`);
}

// ── 9. static scan — the CLI renders FROM the report, not a second copy of the checks ─────────
const cli = readFileSync(join(__dirname, "..", "dist", "cli.js"), "utf8");
assert("cli imports buildDoctorReport", /buildDoctorReport/.test(cli));
assert("cli builds the report in the doctor command", /buildDoctorReport\(\s*\{/.test(cli));
assert("cli passes the vault resolver into the report", /resolve:\s*\(v\)\s*=>\s*vault\.resolve\(v\)/.test(cli));
assert("cli feeds oauth client ids from the store", /oauthClientIds/.test(cli) && /hasClientId/.test(cli));
assert("cli renders report.servers (not a re-derived loop)", /report\.servers/.test(cli));
assert("cli exit code tracks report.ok", /report\.ok\s*\?\s*0\s*:\s*1/.test(cli));

// ── footer ──────────────────────────────────────────────────────────────────────────────────
const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
process.exitCode = failed.length === 0 ? 0 : 1;
