#!/usr/bin/env node
/**
 * Run every deterministic oracle named in package.json's `verify` chain, one by one, sandboxed.
 *
 * Unlike `npm run verify` (which stops at the first failure), this runs them all and prints one table:
 * script, exit code, checks passed/total (parsed from each script's own "N/N checks passed" line),
 * seconds. Each script gets a fresh HOME / USERPROFILE / APPDATA / LOCALAPPDATA / SWITCHBOARD_HOME so
 * nothing touches the operator's real state, and provider keys are scrubbed from its environment.
 *
 * Usage: node scripts/run-oracles.mjs [--only name1,name2] [--json out.json]
 * Exit code: 0 only when every selected oracle exits 0. Requires a prior `npm run build`.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const chain = String(pkg.scripts.verify ?? "")
  .split("&&")
  .map((s) => s.trim())
  .filter((s) => s.startsWith("npm run verify:"))
  .map((s) => s.slice("npm run ".length));

const args = process.argv.slice(2);
const onlyIdx = args.indexOf("--only");
const only = onlyIdx >= 0 ? new Set(String(args[onlyIdx + 1] ?? "").split(",").filter(Boolean)) : null;
const jsonIdx = args.indexOf("--json");
const jsonOut = jsonIdx >= 0 ? args[jsonIdx + 1] : null;

const SCRUB = /(_API_KEY|_API_SECRET|TOKEN|SECRET|PASSWORD|CREDENTIALS)$|^SWITCHBOARD_(AUTO_APPROVE|PROFILE|TOKEN|INSECURE_APPROVAL)$/i;

const rows = [];
for (const name of chain) {
  const short = name.replace(/^verify:/, "");
  if (only && !only.has(short) && !only.has(name)) continue;
  const cmd = String(pkg.scripts[name] ?? "");
  const m = cmd.match(/^node\s+(\S+)/);
  if (!m) {
    rows.push({ name, exit: -1, passed: null, total: null, secs: 0, note: `unrunnable script: ${cmd}` });
    continue;
  }
  const base = mkdtempSync(join(tmpdir(), "sb-oracle-"));
  const dirs = { home: join(base, "home"), appdata: join(base, "appdata"), local: join(base, "local"), tmp: join(base, "tmp") };
  for (const d of Object.values(dirs)) mkdirSync(d, { recursive: true });
  const env = {};
  for (const [k, v] of Object.entries(process.env)) if (!SCRUB.test(k)) env[k] = v;
  Object.assign(env, {
    HOME: dirs.home,
    USERPROFILE: dirs.home,
    APPDATA: dirs.appdata,
    LOCALAPPDATA: dirs.local,
    TEMP: dirs.tmp,
    TMP: dirs.tmp,
    SWITCHBOARD_HOME: join(dirs.home, ".switchboard"),
    NO_COLOR: "1",
  });
  const t0 = Date.now();
  const r = spawnSync(process.execPath, [m[1]], { cwd: root, env, encoding: "utf8", timeout: 300_000, maxBuffer: 64 << 20 });
  const secs = (Date.now() - t0) / 1000;
  const out = `${r.stdout ?? ""}\n${r.stderr ?? ""}`;
  const counts = [...out.matchAll(/(\d+)\s*\/\s*(\d+)\s+checks?\s+passed/gi)].pop();
  const failLines = out.split(/\r?\n/).filter((l) => /\bFAIL\b|BREACHED|✗/.test(l)).slice(0, 8);
  rows.push({
    name: short,
    exit: r.status ?? (r.signal ? `signal ${r.signal}` : -1),
    passed: counts ? Number(counts[1]) : null,
    total: counts ? Number(counts[2]) : null,
    secs: Number(secs.toFixed(1)),
    note: r.error ? String(r.error.message) : failLines.join(" | "),
  });
  try {
    rmSync(base, { recursive: true, force: true });
  } catch {
    /* leftovers in temp are harmless */
  }
}

const pad = (s, n) => String(s).padEnd(n);
console.log(`${pad("oracle", 26)}${pad("exit", 6)}${pad("checks", 12)}${pad("secs", 7)}notes`);
for (const r of rows) {
  const checks = r.passed === null ? "n/a" : `${r.passed}/${r.total}`;
  console.log(`${pad(r.name, 26)}${pad(r.exit, 6)}${pad(checks, 12)}${pad(r.secs, 7)}${r.note ?? ""}`);
}
const failed = rows.filter((r) => r.exit !== 0);
const passed = rows.reduce((a, r) => a + (r.passed ?? 0), 0);
const total = rows.reduce((a, r) => a + (r.total ?? 0), 0);
console.log(`\noracles: ${rows.length - failed.length}/${rows.length} exit 0; checks: ${passed}/${total}`);
if (jsonOut) writeFileSync(jsonOut, JSON.stringify({ rows, passed, total, failed: failed.map((r) => r.name) }, null, 2));
process.exit(failed.length ? 1 : 0);
