/**
 * verify-install.mjs — deterministic oracle for `switchboard install <client>` (src/clients.ts).
 *
 * No client, no network: it imports the pure config-writer from dist/ and asserts the properties
 * that make `install` safe and correct — per-client transport/format/path resolution (OS-pinned so
 * the oracle is platform-independent), the loopback/auth URL logic, the JSON entry shape each client
 * actually accepts, a non-destructive MERGE that preserves every pre-existing server, the idempotent
 * fixpoint (running twice is a no-op), and a real temp-dir round-trip for both JSON and TOML clients.
 */
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  SUPPORTED_CLIENTS,
  resolveTarget,
  mcpUrl,
  authRequired,
  buildJsonEntry,
  mergeJsonConfig,
  upsertTomlTable,
  buildPlan,
  writePlan,
} from "../dist/clients.js";

const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "ok  " : "FAIL"} ${name}${detail ? `  — ${detail}` : ""}`);
};
const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// Pin OS-specific resolution so the oracle gives the same verdict on win/mac/linux CI.
const ENV = { platform: "win32", home: "C:\\Users\\dev", appData: "C:\\Users\\dev\\AppData\\Roaming" };
const HOST_LOOPBACK = { host: "127.0.0.1", port: 8088, requireAuth: "auto" };

// ── supported set ──────────────────────────────────────────────────────────────
assert("five clients supported", eq([...SUPPORTED_CLIENTS], ["claude-desktop", "claude-code", "cursor", "vscode", "codex"]));

// ── resolveTarget: transport/format/key per client ──────────────────────────────
{
  const t = resolveTarget("claude-desktop", ENV);
  assert("claude-desktop: stdio/json/mcpServers", t.transport === "stdio" && t.format === "json" && t.jsonKey === "mcpServers");
  assert("claude-desktop: AppData\\Claude path", t.path === "C:\\Users\\dev\\AppData\\Roaming\\Claude\\claude_desktop_config.json", t.path);
}
{
  const proj = resolveTarget("claude-code", { ...ENV, baseDir: "C:\\proj" });
  const glob = resolveTarget("claude-code", { ...ENV, global: true });
  assert("claude-code: http/json/mcpServers", proj.transport === "http" && proj.format === "json" && proj.jsonKey === "mcpServers");
  assert("claude-code project → <base>/.mcp.json", proj.path === "C:\\proj\\.mcp.json", proj.path);
  assert("claude-code global → ~/.claude.json", glob.path === "C:\\Users\\dev\\.claude.json", glob.path);
}
{
  const proj = resolveTarget("cursor", { ...ENV, baseDir: "C:\\proj" });
  const glob = resolveTarget("cursor", { ...ENV, global: true });
  assert("cursor: http/json/mcpServers", proj.transport === "http" && proj.format === "json" && proj.jsonKey === "mcpServers");
  assert("cursor project → <base>/.cursor/mcp.json", proj.path === "C:\\proj\\.cursor\\mcp.json", proj.path);
  assert("cursor global → ~/.cursor/mcp.json", glob.path === "C:\\Users\\dev\\.cursor\\mcp.json", glob.path);
}
{
  const proj = resolveTarget("vscode", { ...ENV, baseDir: "C:\\proj" });
  const glob = resolveTarget("vscode", { ...ENV, global: true });
  assert("vscode: http/json/servers key", proj.transport === "http" && proj.format === "json" && proj.jsonKey === "servers");
  assert("vscode project → <base>/.vscode/mcp.json", proj.path === "C:\\proj\\.vscode\\mcp.json", proj.path);
  assert("vscode global → AppData\\Code\\User\\mcp.json", glob.path === "C:\\Users\\dev\\AppData\\Roaming\\Code\\User\\mcp.json", glob.path);
}
{
  const proj = resolveTarget("codex", { ...ENV, baseDir: "C:\\proj" });
  const glob = resolveTarget("codex", { ...ENV, global: true });
  assert("codex: http/toml", proj.transport === "http" && proj.format === "toml");
  assert("codex project → <base>/.codex/config.toml", proj.path === "C:\\proj\\.codex\\config.toml", proj.path);
  assert("codex global → ~/.codex/config.toml", glob.path === "C:\\Users\\dev\\.codex\\config.toml", glob.path);
}

// ── mcpUrl: loopback + wildcard collapse to a reachable 127.0.0.1 ─────────────────
assert("mcpUrl loopback → 127.0.0.1", mcpUrl({ host: "127.0.0.1", port: 8088 }) === "http://127.0.0.1:8088/mcp");
assert("mcpUrl localhost → 127.0.0.1", mcpUrl({ host: "localhost", port: 8088 }) === "http://127.0.0.1:8088/mcp");
assert("mcpUrl 0.0.0.0 → 127.0.0.1", mcpUrl({ host: "0.0.0.0", port: 9000 }) === "http://127.0.0.1:9000/mcp");
assert("mcpUrl LAN host preserved", mcpUrl({ host: "192.168.1.5", port: 8088 }) === "http://192.168.1.5:8088/mcp");

// ── authRequired: mirrors the gateway's require_auth logic ────────────────────────
assert("auth always → true", authRequired({ host: "127.0.0.1", port: 1, requireAuth: "always" }) === true);
assert("auth never → false", authRequired({ host: "10.0.0.1", port: 1, requireAuth: "never" }) === false);
assert("auth auto + loopback → false", authRequired({ host: "127.0.0.1", port: 1, requireAuth: "auto" }) === false);
assert("auth auto + LAN → true", authRequired({ host: "192.168.1.5", port: 1, requireAuth: "auto" }) === true);

// ── buildJsonEntry: the exact shape each client accepts ──────────────────────────
{
  const stdioTarget = resolveTarget("claude-desktop", ENV);
  const e = buildJsonEntry(stdioTarget, {
    url: "http://127.0.0.1:8088/mcp",
    launcher: { command: "node", cliPath: "C:\\sb\\dist\\cli.js", configPath: "C:\\sb\\switchboard.config.yaml" },
  });
  assert("stdio entry: command=node", e.command === "node");
  assert("stdio entry: args = [cli, --config, cfg, serve]",
    eq(e.args, ["C:\\sb\\dist\\cli.js", "--config", "C:\\sb\\switchboard.config.yaml", "serve"]), JSON.stringify(e.args));
  assert("stdio entry: no url/type", e.url === undefined && e.type === undefined);
}
{
  const httpTarget = resolveTarget("claude-code", ENV);
  const e = buildJsonEntry(httpTarget, { url: "http://127.0.0.1:8088/mcp", launcher: {} });
  assert("http entry: type=http", e.type === "http");
  assert("http entry: url set", e.url === "http://127.0.0.1:8088/mcp");
  assert("http entry: no headers when auth not needed", e.headers === undefined);
}
{
  const cursorTarget = resolveTarget("cursor", ENV);
  const e = buildJsonEntry(cursorTarget, { url: "http://127.0.0.1:8088/mcp", launcher: {}, authHeader: "Bearer X" });
  assert("cursor entry: NO type (transport inferred)", e.type === undefined);
  assert("cursor entry: url set", e.url === "http://127.0.0.1:8088/mcp");
  assert("cursor entry: headers carry auth", eq(e.headers, { Authorization: "Bearer X" }));
}

// ── mergeJsonConfig: preserve everything, set our one entry, trailing newline ─────
{
  const existing = JSON.stringify({ mcpServers: { other: { url: "http://x" } }, unrelatedTopKey: 42 }, null, 2);
  const merged = mergeJsonConfig(existing, "mcpServers", "switchboard", { type: "http", url: "u" });
  const parsed = JSON.parse(merged);
  assert("merge: preserves sibling server", eq(parsed.mcpServers.other, { url: "http://x" }));
  assert("merge: preserves unrelated top-level key", parsed.unrelatedTopKey === 42);
  assert("merge: adds our entry", eq(parsed.mcpServers.switchboard, { type: "http", url: "u" }));
  assert("merge: trailing newline", merged.endsWith("\n"));
}
{
  const fromNull = mergeJsonConfig(null, "mcpServers", "switchboard", { url: "u" });
  assert("merge null → fresh config", eq(JSON.parse(fromNull), { mcpServers: { switchboard: { url: "u" } } }));
  let threw = false;
  try {
    mergeJsonConfig("{ not json", "mcpServers", "switchboard", { url: "u" });
  } catch {
    threw = true;
  }
  assert("merge: refuses to overwrite invalid JSON", threw);
}
{
  // VS Code uses the `servers` key — merge must honor whatever key the target declares.
  const merged = mergeJsonConfig(null, "servers", "switchboard", { type: "http", url: "u" });
  assert("merge: respects non-default key (servers)", eq(JSON.parse(merged), { servers: { switchboard: { type: "http", url: "u" } } }));
}

// ── upsertTomlTable: insert, append-preserving, replace, fixpoint ─────────────────
{
  const inserted = upsertTomlTable("", "[mcp_servers.switchboard]", ['url = "http://127.0.0.1:8088/mcp"']);
  assert("toml insert into empty", inserted === '[mcp_servers.switchboard]\nurl = "http://127.0.0.1:8088/mcp"\n', JSON.stringify(inserted));

  const withOther = '[mcp_servers.other]\nurl = "http://other"\n';
  const appended = upsertTomlTable(withOther, "[mcp_servers.switchboard]", ['url = "u"']);
  assert("toml append: preserves existing table", appended.includes("[mcp_servers.other]") && appended.includes('url = "http://other"'));
  assert("toml append: adds our table", appended.includes("[mcp_servers.switchboard]"));

  // Replacing our table must NOT duplicate it and must keep the trailing unrelated table intact.
  const doc = '[mcp_servers.switchboard]\nurl = "http://old"\n\n[other]\nx = 1\n';
  const replaced = upsertTomlTable(doc, "[mcp_servers.switchboard]", ['url = "http://new"']);
  assert("toml replace: single switchboard table", (replaced.match(/\[mcp_servers\.switchboard\]/g) || []).length === 1);
  assert("toml replace: new value present, old gone", replaced.includes('url = "http://new"') && !replaced.includes('url = "http://old"'));
  assert("toml replace: trailing [other] preserved", replaced.includes("[other]") && replaced.includes("x = 1"));

  // Fixpoint: applying the identical upsert again changes nothing.
  const again = upsertTomlTable(replaced, "[mcp_servers.switchboard]", ['url = "http://new"']);
  assert("toml upsert is a fixpoint", again === replaced);
}

// ── full buildPlan + writePlan round-trip in a real temp dir ──────────────────────
const root = mkdtempSync(join(tmpdir(), "sb-install-"));
try {
  // JSON client (claude-code, project-local): write, then re-plan ⇒ no change.
  {
    const ctx = { endpoint: HOST_LOOPBACK, launcher: { command: "node", cliPath: "C:\\sb\\dist\\cli.js", configPath: "C:\\sb\\cfg.yaml" }, baseDir: root };
    const p1 = buildPlan("claude-code", ctx);
    assert("plan(claude-code): not existed yet", p1.existed === false && p1.changed === true);
    writePlan(p1);
    const onDisk = readFileSync(p1.target.path, "utf8");
    assert("plan(claude-code): file written verbatim", onDisk === p1.content);
    assert("plan(claude-code): loopback ⇒ no auth header", !onDisk.includes("Authorization"));
    const p2 = buildPlan("claude-code", ctx);
    assert("plan(claude-code): second run is a no-op (idempotent)", p2.existed === true && p2.changed === false);
  }

  // TOML client (codex, project-local): write, then re-plan ⇒ no change.
  {
    const ctx = { endpoint: HOST_LOOPBACK, launcher: { command: "node", cliPath: "x", configPath: "y" }, baseDir: root };
    const p1 = buildPlan("codex", ctx);
    writePlan(p1);
    assert("plan(codex): wrote a [mcp_servers.switchboard] table", readFileSync(p1.target.path, "utf8").includes("[mcp_servers.switchboard]"));
    const p2 = buildPlan("codex", ctx);
    assert("plan(codex): second run is a no-op (idempotent)", p2.changed === false);
  }

  // Merge safety: a pre-existing unrelated server in the SAME file must survive install.
  {
    const dir = join(root, "merge");
    mkdirSync(join(dir, ".cursor"), { recursive: true });
    const cursorPath = join(dir, ".cursor", "mcp.json");
    writeFileSync(cursorPath, JSON.stringify({ mcpServers: { github: { url: "http://gh" } } }, null, 2), "utf8");
    const p = buildPlan("cursor", { endpoint: HOST_LOOPBACK, launcher: {}, baseDir: dir });
    writePlan(p);
    const after = JSON.parse(readFileSync(cursorPath, "utf8"));
    assert("merge round-trip: existing 'github' server preserved", eq(after.mcpServers.github, { url: "http://gh" }));
    assert("merge round-trip: 'switchboard' server added", after.mcpServers.switchboard?.url === "http://127.0.0.1:8088/mcp");
  }

  // Non-loopback endpoint ⇒ auth header / bearer env var must appear.
  {
    const lanEp = { host: "0.0.0.0", port: 8088, requireAuth: "auto" };
    const jsonPlan = buildPlan("claude-code", { endpoint: lanEp, launcher: {}, baseDir: join(root, "lan") });
    assert("plan(LAN, json): writes Authorization bearer env placeholder", jsonPlan.content.includes("Bearer ${env:SWITCHBOARD_TOKEN}"));
    assert("plan(LAN, json): notes flag auth required", jsonPlan.notes.some((n) => n.toLowerCase().includes("bearer token")));
    const tomlPlan = buildPlan("codex", { endpoint: { host: "192.168.0.9", port: 8088, requireAuth: "auto" }, launcher: {}, baseDir: join(root, "lan2") });
    assert("plan(LAN, toml): writes bearer_token_env_var", tomlPlan.content.includes('bearer_token_env_var = "SWITCHBOARD_TOKEN"'));
  }
} finally {
  rmSync(root, { recursive: true, force: true });
}

// ── summary ──────────────────────────────────────────────────────────────────
const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
if (failed.length) console.log("FAILED:", failed.map((c) => c.name).join(", "));
process.exitCode = failed.length === 0 ? 0 : 1;
