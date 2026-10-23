// Deterministic oracle for client registration (design 3.13): `switchboard install <client>` and
// `switchboard uninstall <client>` for claude-code, claude-desktop, codex, gemini, antigravity, dsh, cursor, vscode.
// No model tokens, no real client, no real config, no network beyond an ephemeral loopback stub gateway.
//
// Everything runs against the compiled dist/ in fake homes: HOME, USERPROFILE, APPDATA, LOCALAPPDATA and TEMP are
// temp dirs, the in-process SWITCHBOARD_HOME is a scratch dir, CODEX_HOME / DSH_HOME are unset, gateway ports are
// ephemeral (never 8088), and PATH has the real claude/codex/agy/dsh directories filtered out. Where a client's own
// CLI matters, stub executables on a temp PATH record their argv (and emulate the client's config file).
//
//   1. pure units: the TOML scanner, TOML table surgery, the dsh patch block, executable resolution and the cmd.exe
//      shim quoting, target resolution for all eight clients, plan shapes (bridge entry, --url rule, http entries).
//   2. every client, file route, through runInstall/runUninstall: entry shape, other servers kept, timestamped
//      backup, idempotent re-install, uninstall removes only our entry, project scope, http mode and its refusals,
//      name validation; the real `client add` equivalent (defaults, existing settings kept); and a handful of real
//      CLI processes for flags, stdin confirmation, exit codes and a real registration with a real key.
//   3. the CLI route with stub claude/codex/agy: exact argv (through a real .cmd shim on Windows), record or backup
//      before the write, probe commands, idempotence, project scope, uninstall.
//   4. refusal: an unparseable file (JSON, TOML, YAML, dsh markers, foreign forms) is never touched and nothing is
//      registered; dry-run writes nothing for every client.
//   5. probe and rollback: a failing `get`, a failing add, a gateway that answers 500, restore byte for byte or
//      remove what the install created, the previous CLI entry put back; a working gateway proves the bridge entry
//      with the client's real key.
//   6. guards: a file edited while the owner reads the preview is never overwritten; the bridge probe itself.
//
// Build first: npm run build && node scripts/verify-installers.mjs

import { spawnSync } from "node:child_process";
import { createServer } from "node:http";
import { createServer as createNetServer } from "node:net";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parse as parseYaml } from "yaml";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const CLI = join(root, "dist", "cli.js");
const WIN = process.platform === "win32";
const SCRATCH = mkdtempSync(join(tmpdir(), "sb-installers-"));
// Modules loaded in this process read SWITCHBOARD_HOME once at import: point it at scratch before any dist import,
// so nothing in-process can ever resolve to the operator's real ~/.switchboard.
process.env.SWITCHBOARD_HOME = join(SCRATCH, "inproc-sbhome");

// Section headers carry the elapsed time, so a slow section is visible in the oracle's own output.
const T0 = Date.now();
const rawLog = console.log.bind(console);
console.log = (...a) => {
  if (typeof a[0] === "string" && a[0].startsWith("\n== ")) a[0] += ` [t+${Math.round((Date.now() - T0) / 1000)}s]`;
  rawLog(...a);
};

const checks = [];
const assert = (name, cond, detail = "") => {
  checks.push({ name, ok: !!cond });
  console.log(`${cond ? "ok  " : "FAIL"} ${name}${detail && !cond ? `  : ${String(detail).slice(0, 600)}` : ""}`);
};
const eq = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const read = (p) => readFileSync(p, "utf8");
const readJson = (p) => JSON.parse(read(p));
const lf = (s) => s.replace(/\r\n/g, "\n");
const clean = (s) => String(s ?? "").replace(/\x1b\[[0-9;]*m/g, "");

const dist = (m) => import(pathToFileURL(join(root, "dist", m)).href);

// ── fixtures ────────────────────────────────────────────────────────────────────────────────────

function freePort() {
  return new Promise((res, rej) => {
    const s = createNetServer();
    s.once("error", rej);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => res(port));
    });
  });
}

const STUB_JS = String.raw`
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
const [tool, ...argv] = process.argv.slice(2);
const home = process.env.USERPROFILE || process.env.HOME;
if (process.env.STUB_LOG) appendFileSync(process.env.STUB_LOG, JSON.stringify({ tool, argv, cwd: process.cwd() }) + "\n");
const die = (code, msg) => { process.stderr.write(msg + "\n"); process.exit(code); };
const readJson = (p) => (existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) : {});
const writeJson = (p, v) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, JSON.stringify(v, null, 2) + "\n"); };
const flag = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i + 1] : undefined; };
const exitFor = (name) => { if (process.env[name]) die(Number(process.env[name]), "stub: " + name + " forced"); };

if (tool === "claude") {
  const [mcp, sub, name] = argv;
  if (mcp !== "mcp") die(2, "stub claude: expected mcp");
  const scope = flag("--scope") || "local";
  const fileOf = (s) => (s === "user" ? join(home, ".claude.json") : join(process.cwd(), ".mcp.json"));
  if (sub === "add-json") {
    exitFor("STUB_ADD_EXIT");
    const f = fileOf(scope);
    const j = readJson(f);
    j.mcpServers = j.mcpServers || {};
    if (j.mcpServers[name]) die(1, "MCP server " + name + " already exists in " + scope + " config");
    j.mcpServers[name] = JSON.parse(argv[3]);
    writeJson(f, j);
    console.log("Added MCP server " + name + " to " + scope + " config");
  } else if (sub === "remove") {
    const f = fileOf(scope);
    const j = readJson(f);
    if (!j.mcpServers || !j.mcpServers[name]) die(1, "No " + scope + "-scoped MCP server found with name: " + name);
    delete j.mcpServers[name];
    writeJson(f, j);
    console.log("Removed MCP server " + name);
  } else if (sub === "get") {
    exitFor("STUB_GET_EXIT");
    const e = (readJson(fileOf("user")).mcpServers || {})[name] || (readJson(fileOf("project")).mcpServers || {})[name];
    if (!e) die(1, 'No MCP server named "' + name + '"');
    console.log(name + ":\n  Scope: stub\n  Status: Failed to connect\n  Type: " + (e.type || "stdio") + "\n  Command: " + e.command + "\n  Args: " + (e.args || []).join(" "));
  } else die(2, "stub claude: unknown subcommand " + sub);
} else if (tool === "codex") {
  const [mcp, sub, name] = argv;
  if (mcp !== "mcp") die(2, "stub codex: expected mcp");
  const dir = process.env.CODEX_HOME || join(home, ".codex");
  const f = join(dir, "config.toml");
  const text = () => (existsSync(f) ? readFileSync(f, "utf8") : "");
  const header = "[mcp_servers." + name + "]";
  const strip = (t) => {
    const lines = t.split(/\r?\n/);
    const out = [];
    let skip = false;
    for (const l of lines) {
      if (/^\s*\[/.test(l)) skip = l.trim() === header || l.trim().startsWith("[mcp_servers." + name + ".");
      if (!skip) out.push(l);
    }
    return out.join("\n").replace(/\s+$/, "");
  };
  if (sub === "add") {
    exitFor("STUB_ADD_EXIT");
    if (process.env.STUB_ADD_REFUSES_EXISTING && text().includes(header)) die(1, "MCP server " + name + " already exists");
    const dd = argv.indexOf("--");
    let block;
    if (dd >= 0) block = [header, "command = " + JSON.stringify(argv[dd + 1]), "args = " + JSON.stringify(argv.slice(dd + 2))].join("\n");
    else block = [header, "url = " + JSON.stringify(flag("--url")), ...(flag("--bearer-token-env-var") ? ["bearer_token_env_var = " + JSON.stringify(flag("--bearer-token-env-var"))] : [])].join("\n");
    const base = strip(text());
    mkdirSync(dir, { recursive: true });
    writeFileSync(f, (base ? base + "\n\n" : "") + block + "\n");
    console.log("Added global MCP server '" + name + "'.");
  } else if (sub === "remove") {
    if (!text().includes(header)) die(1, "No MCP server named '" + name + "' found.");
    writeFileSync(f, strip(text()) + "\n");
    console.log("Removed global MCP server '" + name + "'.");
  } else if (sub === "get") {
    exitFor("STUB_GET_EXIT");
    const t = text();
    const i = t.indexOf(header);
    if (i < 0) die(1, "No MCP server named '" + name + "' found.");
    const rest = t.slice(i + header.length);
    const cmd = /^command = (".*")$/m.exec(rest);
    const args = /^args = (\[.*\])$/m.exec(rest);
    console.log(JSON.stringify({ name, enabled: true, transport: { type: "stdio", command: cmd ? JSON.parse(cmd[1]) : "", args: args ? JSON.parse(args[1]) : [], env: null, env_vars: [], cwd: null } }));
  } else die(2, "stub codex: unknown subcommand " + sub);
} else if (tool === "agy") {
  const [mcp, sub] = argv;
  if (mcp !== "mcp") die(2, "stub agy: expected mcp");
  const f = join(home, ".gemini", "config", "mcp_config.json");
  const j = readJson(f);
  j.mcpServers = j.mcpServers || {};
  if (sub === "add") {
    exitFor("STUB_ADD_EXIT");
    const dd = argv.indexOf("--");
    if (dd < 1) die(2, "stub agy: expected -- before the command");
    const name = argv[dd - 1];
    j.mcpServers[name] = { command: argv[dd + 1], args: argv.slice(dd + 2) };
    writeJson(f, j);
    console.log("Added " + name);
  } else if (sub === "remove") {
    const name = argv[2];
    if (!j.mcpServers[name]) die(1, "no server " + name);
    delete j.mcpServers[name];
    writeJson(f, j);
    console.log("Removed " + name);
  } else if (sub === "list") {
    exitFor("STUB_LIST_EXIT");
    console.log("NAME        TYPE   STATUS   COMMAND/URL");
    for (const [n, e] of Object.entries(j.mcpServers)) console.log(n.padEnd(11) + " stdio  enabled  " + (e.command || e.serverUrl || "") + " " + (e.args || []).join(" "));
  } else die(2, "stub agy: unknown subcommand " + sub);
} else die(2, "stub: unknown tool " + tool);
`;

/** A directory with stub claude, codex and agy (a .cmd shim each on Windows, a shell script elsewhere). */
function makeStubBin() {
  const dir = join(SCRATCH, "stub-bin");
  mkdirSync(dir, { recursive: true });
  const js = join(dir, "stub-cli.mjs");
  writeFileSync(js, STUB_JS);
  for (const tool of ["claude", "codex", "agy"]) {
    if (WIN) writeFileSync(join(dir, `${tool}.cmd`), `@echo off\r\n"${process.execPath}" "${js}" ${tool} %*\r\n`);
    else {
      const p = join(dir, tool);
      writeFileSync(p, `#!/bin/sh\nexec "${process.execPath}" "${js}" ${tool} "$@"\n`);
      chmodSync(p, 0o755);
    }
  }
  return dir;
}
const STUB_BIN = makeStubBin();

/** PATH entries of this machine that hold none of the real clients (so a real claude/codex/agy/dsh can never run). */
function cleanPathDirs() {
  const exts = WIN ? ["", ".exe", ".cmd", ".bat", ".ps1"] : [""];
  return String(process.env.PATH ?? "")
    .split(delimiter)
    .filter(Boolean)
    .filter((d) => !["claude", "codex", "agy", "dsh"].some((n) => exts.some((e) => existsSync(join(d, n + e)))));
}
const CLEAN_DIRS = cleanPathDirs();

let scenarioCount = 0;
const scenarioPorts = [];
/** A fake home with a config file, a project dir and an env for child processes. */
function scenario(label, { port, clients, stubs = false } = {}) {
  const dir = join(SCRATCH, `${String(++scenarioCount).padStart(2, "0")}-${label}`);
  const home = join(dir, "home");
  const appdata = join(home, "AppData", "Roaming");
  const local = join(home, "AppData", "Local");
  const proj = join(dir, "proj");
  const tmp = join(dir, "tmp");
  for (const d of [home, appdata, local, proj, tmp]) mkdirSync(d, { recursive: true });
  const cfg = join(dir, "switchboard.config.yaml");
  const S = { dir, home, appdata, local, proj, tmp, cfg, stubs, log: join(dir, "stub.log"), port: port ?? 0 };
  S.writeConfig = (p = S.port, extraYaml = clients ?? "") => {
    S.port = p;
    scenarioPorts.push(p);
    writeFileSync(
      cfg,
      [
        "gateway:",
        "  transport: [http]",
        `  http: { host: 127.0.0.1, port: ${p}, require_auth: auto }`,
        "  tool_exposure: namespaced",
        "  default_policy: read",
        "vault: { backend: encrypted-file }",
        "servers:",
        '  - { id: fixture, source: binary, command: node, args: ["-e", "0"], enabled: true, policy: read }',
        extraYaml,
        "",
      ].join("\n"),
    );
  };
  return S;
}

const SECRET_ENV = /(_API_KEY|_API_SECRET|TOKEN|SECRET|PASSWORD|CREDENTIALS)$|^SWITCHBOARD_|^CODEX_HOME$|^DSH_HOME$|^NODE_OPTIONS$|^CLAUDE_CONFIG_DIR$/i;

function envFor(S, extra = {}, { stubs } = {}) {
  const e = {};
  for (const [k, v] of Object.entries(process.env)) if (!SECRET_ENV.test(k)) e[k] = v;
  const useStubs = stubs ?? S.stubs;
  const pathDirs = useStubs ? [STUB_BIN, ...CLEAN_DIRS] : CLEAN_DIRS;
  Object.assign(e, { HOME: S.home, USERPROFILE: S.home, APPDATA: S.appdata, LOCALAPPDATA: S.local, TEMP: S.tmp, TMP: S.tmp, PATH: pathDirs.join(delimiter), STUB_LOG: S.log, NO_COLOR: "1" });
  if (WIN) e.Path = e.PATH;
  Object.assign(e, extra);
  return e;
}

/** Run `node dist/cli.js --config <cfg> <args>` in the scenario's project dir. */
function run(S, args, { input = "", env = {}, stubs, cwd } = {}) {
  const r = spawnSync(process.execPath, [CLI, "--config", S.cfg, ...args], { cwd: cwd ?? S.proj, env: envFor(S, env, { stubs }), input, encoding: "utf8", timeout: 180_000, windowsHide: true });
  return { status: r.status, out: clean(r.stdout), err: clean(r.stderr), all: clean(`${r.stdout}\n${r.stderr}`) };
}

const stubLog = (S) => (existsSync(S.log) ? read(S.log).split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
const stubCalls = (S, tool) => stubLog(S).filter((c) => c.tool === tool);
const MUTATING = (c) => (c.tool === "claude" && ["add-json", "remove"].includes(c.argv[1])) || (c.tool === "codex" && ["add", "remove"].includes(c.argv[1])) || (c.tool === "agy" && ["add", "remove"].includes(c.argv[1]));

function listTree(dir) {
  const out = [];
  const walk = (d) => {
    for (const n of readdirSync(d)) {
      const p = join(d, n);
      const st = statSync(p);
      if (st.isDirectory()) walk(p);
      else out.push(`${p.slice(dir.length)}:${st.size}`);
    }
  };
  if (existsSync(dir)) walk(dir);
  return out.sort();
}

const backupsOf = (path) => readdirSync(dirname(path)).filter((n) => n.startsWith(`${path.split(/[\\/]/).pop()}.bak-switchboard-`)).map((n) => join(dirname(path), n));
const tmpLeftovers = (dirPath) => (existsSync(dirPath) ? readdirSync(dirPath).filter((n) => n.endsWith(".tmp")) : []);
const BACKUP_NAME = /\.bak-switchboard-\d{8}T\d{6}Z(-\d+)?$/;

/** The client's token, unwrapped for this OS user (to prove it is never written into a client file). */
async function tokenOf(S, id) {
  const { unprotectForUser } = await dist("oscrypt.js");
  const f = join(S.home, ".switchboard", "clients", `${id}.key`);
  return existsSync(f) ? unprotectForUser(readFileSync(f)).toString("utf8").trim() : null;
}

const sbConfigClients = async (S) => {
  const { loadConfig } = await dist("config.js");
  return loadConfig(S.cfg).clients ?? {};
};

// ── expected values ─────────────────────────────────────────────────────────────────────────────

const urlFor = (port) => `http://127.0.0.1:${port}/mcp`;
const bridgeArgsFor = (id, port) => [CLI, "bridge", "--client", id, "--url", urlFor(port)];

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// 1. pure units
// ═══════════════════════════════════════════════════════════════════════════════════════════════

const { scanToml, headerPath } = await dist("tomlscan.js");
const clientsMod = await dist("clients.js");
const dsh = await dist("dshpatch.js");
const inst = await dist("installer.js");
const cliexec = await dist("cliexec.js");
const { SUPPORTED_CLIENTS, resolveTarget, buildPlan, buildJsonEntry, upsertTomlTable, removeTomlTable, readTomlTable, checkTomlConfig, bridgeArgs, writePlan, backupFile, InstallRefusal } = clientsMod;

console.log("\n== 1a. TOML scanner ==");
{
  const valid = {
    "empty file": "",
    "comments and blank lines": "# a\n\n   # b\n",
    "table and keys": '[a]\nx = 1\ny = "two"\nz = \'lit\'\n',
    "dotted and quoted keys": 'a.b.c = 1\n"q k" = 2\n[x."y z".w]\nk = true\n',
    "multi-line array with comments and trailing comma": 'args = [\n  "a",  # one\n  "b",\n]\n',
    "nested arrays and inline tables": 'v = [[1, 2], [3]]\nt = { a = 1, b = { c = "d" } }\n',
    "multi-line basic string holding a table-looking line": 's = """\n[not_a_table]\nx\\\n   y"""\n[real]\nk = 1\n',
    "multi-line literal string": "s = '''\n[also_not]\n'''\n",
    "numbers, floats, specials": "a = 0\nb = -17\nc = 1_000\nd = 0xDEAD_beef\ne = 0o17\nf = 0b101\ng = 3.14\nh = 1e10\ni = -2.5E-3\nj = inf\nk = -nan\n",
    "dates and times": "d = 1979-05-27\nt = 07:32:00\ndt = 1979-05-27T07:32:00Z\ndt2 = 1979-05-27 07:32:00-08:00\n",
    "windows paths in strings": "p = 'C:\\Users\\dev'\nq = \"C:\\\\Program Files\\\\nodejs\\\\node.exe\"\n",
    "CRLF line ends": '[a]\r\nx = 1\r\n# c\r\ny = [\r\n  1,\r\n  2\r\n]\r\n',
    "array of tables": "[[p]]\nn = 1\n[[p]]\nn = 2\n",
    "no trailing newline": "k = 1",
    "BOM": "\uFEFFk = 1\n",
  };
  for (const [name, text] of Object.entries(valid)) {
    const r = scanToml(text);
    assert(`toml scan accepts: ${name}`, r.ok, r.ok ? "" : `${r.error} at line ${r.line}`);
  }
  const invalid = {
    "unterminated string": 'k = "abc\n',
    "unterminated multi-line string": 's = """\nabc\n',
    "bare word value": "k = hello\n",
    "missing value": "k =\n",
    "missing equals": "k 1\n",
    "unclosed table header": "[a\nk = 1\n",
    "unclosed array": "a = [1, 2\nb = 3\n",
    "garbage after value": "k = 1 2\n",
    "invalid escape": 'k = "a\\qb"\n',
    "two values in an array without a comma": "a = [1 2]\n",
    "unclosed inline table": "t = { a = 1\n",
    "binary garbage": "\u0000\u0001\u0002 = ?\n",
    "empty key": " = 1\n",
    "leading zero integer": "n = 012\n",
  };
  for (const [name, text] of Object.entries(invalid)) {
    const r = scanToml(text);
    assert(`toml scan rejects: ${name}`, !r.ok);
  }
  const line = scanToml("a = 1\nb = 2\nc = oops\n");
  assert("toml scan reports the 1-based line of the error", !line.ok && line.line === 3, JSON.stringify(line));
  assert("headerPath parses a header string", eq(headerPath('[mcp_servers."a b".c]'), ["mcp_servers", "a b", "c"]) && headerPath("not a header") === null);
}

console.log("\n== 1b. TOML table surgery ==");
{
  const seed = [
    "# my codex config",
    'model = "x"',
    "",
    "[mcp_servers.context7]",
    'command = "node"',
    'args = [',
    '  "a",',
    '  ["nested"],',
    "]",
    "",
    "[mcp_servers.context7.env]",
    'K = "v"',
    "",
    "[features]",
    "multi_agent = true",
    "",
  ].join("\n");
  const H = "[mcp_servers.switchboard]";
  const body = ['command = "node"', 'args = ["cli.js", "bridge"]'];
  const added = upsertTomlTable(seed, H, body);
  assert("toml upsert appends after existing tables and keeps them", added.startsWith(seed.trimEnd()) && added.includes(`${H}\ncommand = "node"`), added);
  assert("toml upsert is a fixpoint", upsertTomlTable(added, H, body) === added);
  const removed = removeTomlTable(added, "switchboard");
  assert("toml remove restores the original text exactly", removed.removed && removed.text === seed, JSON.stringify(removed.text));
  const alt = '# top\n[ mcp_servers . "switchboard" ]\ncommand = "old"\n\n[mcp_servers.switchboard.env]\nA = "1"\n\n[other]\nx = 1\n';
  const replaced = upsertTomlTable(alt, H, body);
  assert("toml upsert matches a table by key path (quoted, spaced header) and does not duplicate it", (replaced.match(/switchboard/g) || []).length === 1 && !replaced.includes('"old"'), replaced);
  assert("toml upsert drops the entry's own sub-table with the entry and keeps [other]", !replaced.includes("A = ") && replaced.includes("[other]") && replaced.startsWith("# top\n"), replaced);
  assert("toml remove takes the sub-table too", removeTomlTable(alt, "switchboard").text === "# top\n\n[other]\nx = 1\n" || removeTomlTable(alt, "switchboard").text === "# top\n[other]\nx = 1\n", JSON.stringify(removeTomlTable(alt, "switchboard").text));
  const crlf = seed.replace(/\n/g, "\r\n");
  const crlfAdded = upsertTomlTable(crlf, H, body);
  assert("toml upsert keeps CRLF line ends", crlfAdded.includes("\r\n") && !/[^\r]\n/.test(crlfAdded), JSON.stringify(crlfAdded.slice(-80)));
  assert("toml remove on CRLF restores the CRLF original", removeTomlTable(crlfAdded, "switchboard").text === crlf);
  assert("a table-looking line inside a multi-line string is not a table", readTomlTable('[mcp_servers.switchboard]\ns = """\n[mcp_servers.other]\n"""\nk = 1\n', "other") === undefined);
  const dotted = 'mcp_servers.switchboard.command = "x"\n';
  let msg = "";
  try {
    checkTomlConfig(dotted, "switchboard", "f.toml");
  } catch (e) {
    msg = e instanceof InstallRefusal ? e.message : "wrong error";
  }
  assert("toml: an entry written with dotted keys is refused, not duplicated", msg.includes("dotted keys") && msg.includes("f.toml"), msg);
  msg = "";
  try {
    checkTomlConfig('[mcp_servers]\nswitchboard = { command = "x" }\n', "switchboard");
  } catch (e) {
    msg = e instanceof InstallRefusal ? e.message : "wrong error";
  }
  assert("toml: an entry written as an inline table is refused", msg.includes("inline table"), msg);
  msg = "";
  try {
    checkTomlConfig('k = "unterminated\n', "switchboard", "g.toml");
  } catch (e) {
    msg = e instanceof InstallRefusal ? e.message : "wrong error";
  }
  assert("toml: a file that does not parse is refused with its path and line", msg.includes("g.toml") && msg.includes("line 1") && msg.includes("Refusing"), msg);
  assert("toml upsert into empty text matches the 0.1.0 output", upsertTomlTable("", H, ['url = "u"']) === `${H}\nurl = "u"\n`);
}

console.log("\n== 1c. dsh patch block ==");
const GEN = [
  "# Your patch layer for this dsh profile, applied after every bundle layer:",
  "# a top-level YAML array of loader patch entries (id-targeted config",
  "# overrides, disables, and insert lists; `!!js` expressions allowed).",
  "",
  "# BEGIN local-llama (generated by D:/Ideas/llama.cpp/dsh_local_setup.py; edit the script, not this block)",
  "- id: llm-pi-ai",
  "  config:",
  "    providers:",
  "      llama:",
  "        baseURL: http://127.0.0.1:8080/v1",
  "        apiKeyEnv: LLAMA_KEY",
  "- id: agent-default-model",
  "  config:",
  "    provider: llama",
  "    k: !!js process.env.HOME",
  "",
  "# END local-llama",
  "",
].join("\n");
{
  const spec = { name: "switchboard", mode: "bridge", command: "C:\\Program Files\\nodejs\\node.exe", args: ["D:\\x\\dist\\cli.js", "bridge", "--client", "dsh"], url: "http://127.0.0.1:9/mcp" };
  const r = dsh.upsertDshPatch(GEN, spec);
  assert("dsh: the generated block is byte for byte unchanged", r.text.startsWith(GEN.slice(0, GEN.indexOf("# END local-llama") + "# END local-llama".length)));
  const lay = dsh.dshLayout(r.text);
  assert("dsh: our block sits after the generated block's END line", lay.ours && lay.generated.length === 1 && lay.ours.start > lay.generated[0].end, JSON.stringify([lay.ours, lay.generated]));
  const doc = parseYaml(r.text);
  const row = doc.find((x) => x.insert)?.insert?.[0];
  assert("dsh: the row is { id, name: @deepseek-ai/dsh-mcp-client, config: { serverName, transport: stdio, command, args } }", row && row.id === "switchboard" && row.name === "@deepseek-ai/dsh-mcp-client" && row.config.serverName === "switchboard" && row.config.transport === "stdio" && row.config.command === spec.command && eq(row.config.args, spec.args), JSON.stringify(row));
  assert("dsh: the row is an `insert` entry in the root list", Array.isArray(doc) && doc.some((x) => Array.isArray(x.insert)));
  assert("dsh: verify accepts what was written", dsh.verifyDshPatch(r.text, spec).ok);
  const r2 = dsh.upsertDshPatch(r.text, spec);
  assert("dsh: upsert is a fixpoint", r2.text === r.text && r2.changed === false);
  const gone = dsh.removeDshPatch(r.text, "switchboard");
  assert("dsh: remove restores the original file exactly", gone.removed && gone.text === GEN, JSON.stringify(gone.text.slice(-120)));
  const crlf = GEN.replace(/\n/g, "\r\n");
  const rc = dsh.upsertDshPatch(crlf, spec);
  assert("dsh: CRLF file stays CRLF and removal restores it", /\r\n/.test(rc.text) && !/[^\r]\n/.test(rc.text) && dsh.removeDshPatch(rc.text, "switchboard").text === crlf);
  const httpSpec = { ...spec, mode: "http" };
  const rh = dsh.upsertDshPatch(GEN, httpSpec);
  const hrow = parseYaml(rh.text).find((x) => x.insert).insert[0];
  assert("dsh: http mode is transport streamable-http with url and an environment-referenced Authorization header", hrow.config.transport === "streamable-http" && hrow.config.url === spec.url && String(hrow.config.headers.Authorization).includes("SWITCHBOARD_TOKEN") && rh.text.includes("!!js"), JSON.stringify(hrow));
  const empty = dsh.upsertDshPatch(null, spec);
  assert("dsh: a new file is created with the block", dsh.verifyDshPatch(empty.text, spec).ok);
  const flowEmpty = dsh.upsertDshPatch("# c\n[]\n", spec);
  assert("dsh: an empty flow list is turned into a block list", dsh.verifyDshPatch(flowEmpty.text, spec).ok && !flowEmpty.text.includes("[]"), flowEmpty.text);
  const refusals = {
    "BEGIN without END": GEN.replace("# END local-llama", "# end of file"),
    "END without BEGIN": GEN.replace(/# BEGIN local-llama[^\n]*\n/, ""),
    "mismatched END": GEN.replace("# END local-llama", "# END other"),
    "unmarked row with our id": GEN + "- id: switchboard\n  name: x\n",
    "row with our id inside a generated block": GEN.replace("# END local-llama", "- id: switchboard\n# END local-llama"),
    "invalid YAML": GEN + "- [unclosed\n",
    "root is a map": "a: 1\n",
    "non-empty flow list": "[{id: a}]\n",
    "our marker inside a generated block": GEN.replace("  config:\n    provider: llama", "# switchboard:begin id=switchboard\n  config:\n    provider: llama"),
  };
  for (const [name, text] of Object.entries(refusals)) {
    let m = "";
    try {
      dsh.upsertDshPatch(text, spec);
    } catch (e) {
      m = e instanceof InstallRefusal ? e.message : `wrong error: ${e}`;
    }
    assert(`dsh refuses: ${name}`, m !== "" && !m.startsWith("wrong error"), m);
  }
}

console.log("\n== 1d. executables: lookup and the .cmd shim ==");
{
  const bin = join(SCRATCH, "resolve");
  const rel = join(SCRATCH, "resolve-rel");
  mkdirSync(bin, { recursive: true });
  mkdirSync(rel, { recursive: true });
  const ext = WIN ? ".cmd" : "";
  writeFileSync(join(bin, `tool${ext}`), "x");
  if (!WIN) chmodSync(join(bin, "tool"), 0o755);
  writeFileSync(join(rel, `trap${ext}`), "x");
  const env = { PATH: [bin].join(delimiter), PATHEXT: ".COM;.EXE;.BAT;.CMD" };
  const r = cliexec.resolveExecutable("tool", env);
  assert("resolveExecutable finds a tool in an absolute PATH entry", r && r.path.toLowerCase().includes("tool") && (WIN ? r.kind === "shim" : r.kind === "direct"), JSON.stringify(r));
  assert("resolveExecutable returns null for a missing tool", cliexec.resolveExecutable("nope", env) === null);
  const here2 = process.cwd();
  process.chdir(rel);
  const trap = cliexec.resolveExecutable("trap", { PATH: ["." , "", "relative-dir"].join(delimiter), PATHEXT: ".CMD" });
  process.chdir(here2);
  assert("resolveExecutable never looks in the working directory or at relative PATH entries", trap === null, JSON.stringify(trap));
  assert("shimUnsafeReason refuses cmd.exe syntax and passes plain arguments", cliexec.shimUnsafeReason(["a&b"]) !== null && cliexec.shimUnsafeReason(["50%"]) !== null && cliexec.shimUnsafeReason(["a|b", "x"]) !== null && cliexec.shimUnsafeReason(["^"]) !== null && cliexec.shimUnsafeReason(["C:\\Program Files\\nodejs\\node.exe", '{"a":"b\\\\c"}', "--scope", "user"]) === null);
  assert("quoteCrtArg follows the C runtime rules", cliexec.quoteCrtArg("a b") === '"a b"' && cliexec.quoteCrtArg('say "hi"') === '"say \\"hi\\""' && cliexec.quoteCrtArg("C:\\dir with space\\") === '"C:\\dir with space\\\\"' && cliexec.quoteCrtArg("plain") === "plain" && cliexec.quoteCrtArg("plain", true) === '"plain"' && cliexec.quoteCrtArg("") === '""');

  // Round trip through a real process: the child must receive exactly the argument vector we sent.
  const echo = join(SCRATCH, "echo-argv.mjs");
  writeFileSync(echo, "process.stdout.write(JSON.stringify(process.argv.slice(2)));");
  const tricky = ["plain", "has space", 'quote " inside', "C:\\Program Files\\nodejs\\node.exe", '{"type":"stdio","command":"C:\\\\Program Files\\\\n.exe","args":["a b","--x"]}', "trailing backslash\\", "", "--", "-x"];
  const direct = cliexec.runExecutable({ path: process.execPath, kind: "direct" }, [echo, ...tricky]);
  assert("direct run passes the arguments exactly (spaces, quotes, JSON, backslashes, empty)", direct.ok && eq(JSON.parse(direct.stdout), tricky), direct.stdout + direct.error);
  const accented = ["C:\\Users\\Jos\u00e9 \u4e2d\\AppData\\node.exe", 'say "caf\u00e9"'];
  const directU = cliexec.runExecutable({ path: process.execPath, kind: "direct" }, [echo, ...accented]);
  assert("direct run passes non-ASCII arguments (an accented profile name) exactly", directU.ok && eq(JSON.parse(directU.stdout), accented), directU.stdout + directU.error);
  if (WIN) {
    const shim = join(SCRATCH, "echo-shim.cmd");
    writeFileSync(shim, `@echo off\r\n"${process.execPath}" "${echo}" %*\r\n`);
    const viaShim = cliexec.runExecutable({ path: shim, kind: "shim" }, tricky);
    assert("a .cmd shim receives the same arguments exactly through the quoted cmd.exe line", viaShim.ok && eq(JSON.parse(viaShim.stdout), tricky), `${viaShim.stdout} ${viaShim.error} ${viaShim.stderr}`);
    const viaShimU = cliexec.runExecutable({ path: shim, kind: "shim" }, accented);
    assert("a .cmd shim receives non-ASCII arguments (an accented profile name) exactly", viaShimU.ok && eq(JSON.parse(viaShimU.stdout), accented), `${viaShimU.stdout} ${viaShimU.error} ${viaShimU.stderr}`);
    const evil = join(SCRATCH, "pwned.txt");
    const bad = cliexec.runExecutable({ path: shim, kind: "shim" }, [`x & echo pwned > "${evil}"`]);
    assert("a shim argument with cmd.exe syntax is refused and nothing runs", bad.unsafe === true && bad.ok === false && !existsSync(evil), JSON.stringify(bad));
    const pct = cliexec.runExecutable({ path: shim, kind: "shim" }, ["%COMSPEC%"]);
    assert("a % in a shim argument is refused (cmd.exe would expand it even inside quotes)", pct.unsafe === true);
  } else {
    assert("(Windows-only shim checks skipped on this platform)", true);
  }
}

console.log("\n== 1e. targets for all eight clients ==");
{
  assert("the supported clients are exactly the eight of design 3.13", eq([...SUPPORTED_CLIENTS], ["claude-code", "claude-desktop", "codex", "gemini", "antigravity", "dsh", "cursor", "vscode"]));
  const W = { platform: "win32", home: "C:\\Users\\dev", appData: "C:\\Users\\dev\\AppData\\Roaming", baseDir: "C:\\proj" };
  const t = (c, o = {}) => resolveTarget(c, { ...W, ...o });
  assert("claude-code user -> ~/.claude.json, project -> <dir>/.mcp.json", t("claude-code", { scope: "user" }).path === "C:\\Users\\dev\\.claude.json" && t("claude-code", { scope: "project" }).path === "C:\\proj\\.mcp.json" && t("claude-code", { scope: "user" }).cli === "claude");
  assert("claude-desktop -> %APPDATA%/Claude/claude_desktop_config.json (mcpServers), no CLI", t("claude-desktop", { scope: "user" }).path === "C:\\Users\\dev\\AppData\\Roaming\\Claude\\claude_desktop_config.json" && t("claude-desktop").jsonKey === "mcpServers" && !t("claude-desktop").cli);
  assert("codex user -> ~/.codex/config.toml with the codex CLI; project -> <dir>/.codex/config.toml without it", t("codex", { scope: "user" }).path === "C:\\Users\\dev\\.codex\\config.toml" && t("codex", { scope: "user" }).cli === "codex" && t("codex", { scope: "project" }).path === "C:\\proj\\.codex\\config.toml" && !t("codex", { scope: "project" }).cli);
  assert("codex honours CODEX_HOME (and ignores it when the env is not passed)", t("codex", { scope: "user", env: { CODEX_HOME: "D:\\ch" } }).path === "D:\\ch\\config.toml" && t("codex", { scope: "user" }).path === "C:\\Users\\dev\\.codex\\config.toml");
  assert("gemini user -> ~/.gemini/settings.json, project -> <dir>/.gemini/settings.json", t("gemini", { scope: "user" }).path === "C:\\Users\\dev\\.gemini\\settings.json" && t("gemini", { scope: "project" }).path === "C:\\proj\\.gemini\\settings.json");
  assert("cursor user -> ~/.cursor/mcp.json, project -> <dir>/.cursor/mcp.json", t("cursor", { scope: "user" }).path === "C:\\Users\\dev\\.cursor\\mcp.json" && t("cursor", { scope: "project" }).path === "C:\\proj\\.cursor\\mcp.json");
  assert("vscode user -> %APPDATA%/Code/User/mcp.json with the `servers` key, project -> <dir>/.vscode/mcp.json", t("vscode", { scope: "user" }).path === "C:\\Users\\dev\\AppData\\Roaming\\Code\\User\\mcp.json" && t("vscode").jsonKey === "servers" && t("vscode", { scope: "project" }).path === "C:\\proj\\.vscode\\mcp.json");
  assert("dsh -> ~/.dsh/profiles/<profile>/cordis.patch.yml, default profile web, DSH_HOME honoured", t("dsh", { scope: "user" }).path === "C:\\Users\\dev\\.dsh\\profiles\\web\\cordis.patch.yml" && t("dsh", { scope: "user", dshProfile: "headless" }).path.endsWith("profiles\\headless\\cordis.patch.yml") && t("dsh", { env: { DSH_HOME: "D:\\d" } }).path === "D:\\d\\profiles\\web\\cordis.patch.yml");
  for (const [c, why] of [["claude-desktop", "project"], ["antigravity", "project"], ["dsh", "project"]]) {
    let m = "";
    try {
      t(c, { scope: why });
    } catch (e) {
      m = e instanceof InstallRefusal ? e.message : "wrong";
    }
    assert(`${c} has no project scope: refused`, m.includes("no project scope"), m);
  }
  let badProfile = "";
  try {
    t("dsh", { dshProfile: "../x" });
  } catch (e) {
    badProfile = e.message;
  }
  assert("a dsh profile name cannot escape the profiles directory", badProfile.includes("invalid --dsh-profile"), badProfile);

  // Antigravity: agy 1.4.5 reads ~/.gemini/config/mcp_config.json; the older file is used only on a machine that never migrated.
  const ah = join(SCRATCH, "agy-paths");
  const cur = join(ah, ".gemini", "config", "mcp_config.json");
  const leg = join(ah, ".gemini", "antigravity", "mcp_config.json");
  const ap = () => resolveTarget("antigravity", { scope: "user", home: ah }).path;
  mkdirSync(ah, { recursive: true });
  assert("antigravity on a fresh machine -> ~/.gemini/config/mcp_config.json", ap() === cur, ap());
  mkdirSync(dirname(leg), { recursive: true });
  writeFileSync(leg, "{}");
  assert("antigravity with only the older file and no migration marker -> the older file", ap() === leg, ap());
  mkdirSync(dirname(cur), { recursive: true });
  writeFileSync(join(dirname(cur), ".migrated"), "");
  assert("antigravity with the migration marker -> the new file (the older one is stale)", ap() === cur, ap());
  rmSync(join(dirname(cur), ".migrated"));
  writeFileSync(cur, "{}");
  assert("antigravity with both files -> the new file", ap() === cur, ap());
}

console.log("\n== 1f. plan shapes (no files written) ==");
{
  const NODE = process.execPath;
  const launcher = { command: NODE, cliPath: CLI };
  const home = join(SCRATCH, "plan-home");
  mkdirSync(home, { recursive: true });
  const base = { launcher, scope: "user", home, appData: join(home, "AppData", "Roaming"), baseDir: join(SCRATCH, "plan-proj"), env: {} };
  const ep = (port, host = "127.0.0.1") => ({ host, port, requireAuth: "auto" });
  // The CLI always passes the mode (default bridge); `buildPlan` without one keeps its 0.1.0 meaning (http where the client can dial a URL).
  const plan = (c, o = {}) => buildPlan(c, { ...base, mode: "bridge", endpoint: ep(8088), ...o });
  for (const c of SUPPORTED_CLIENTS) {
    const p = plan(c, { clientsConfigured: true });
    const e = p.entry;
    assert(`${c}: the default (bridge) entry is node + [cli.js, bridge, --client, ${c}]`, p.mode === "bridge" && e.kind === "stdio" && e.command === NODE && eq(e.args, [CLI, "bridge", "--client", c]), JSON.stringify(e));
  }
  assert("bridge args add --url only when the gateway URL is not the default http://127.0.0.1:8088/mcp", eq(bridgeArgs(CLI, "x", "http://127.0.0.1:8088/mcp"), [CLI, "bridge", "--client", "x"]) && eq(bridgeArgs(CLI, "x", "http://127.0.0.1:9000/mcp"), [CLI, "bridge", "--client", "x", "--url", "http://127.0.0.1:9000/mcp"]));
  assert("a LAN bind on port 8088 also gets --url (the default URL would not reach it)", eq(plan("cursor", { endpoint: ep(8088, "192.168.1.5") }).entry.args.slice(-2), ["--url", "http://192.168.1.5:8088/mcp"]));
  assert("a gateway on another port gets --url in every JSON client", ["claude-code", "claude-desktop", "gemini", "antigravity", "cursor", "vscode"].every((c) => plan(c, { endpoint: ep(9123) }).entry.args.slice(-2).join(" ") === "--url http://127.0.0.1:9123/mcp"));
  const typed = Object.fromEntries(["claude-code", "claude-desktop", "gemini", "antigravity", "cursor", "vscode"].map((c) => [c, plan(c).jsonEntry]));
  assert("JSON entries: type stdio only where the client's docs show it (claude-code, cursor, vscode)", typed["claude-code"].type === "stdio" && typed.cursor.type === "stdio" && typed.vscode.type === "stdio" && typed["claude-desktop"].type === undefined && typed.gemini.type === undefined && typed.antigravity.type === undefined);
  assert("JSON entries carry command and args and nothing else but the optional type", Object.keys(typed.gemini).sort().join() === "args,command" && Object.keys(typed.cursor).sort().join() === "args,command,type");
  const tomlP = plan("codex");
  const tomlArgs = (list) => `args = [${list.map((a) => JSON.stringify(a)).join(", ")}]`;
  assert("codex bridge entry is a [mcp_servers.switchboard] table with command and args", tomlP.content.includes("[mcp_servers.switchboard]") && tomlP.content.includes(`command = ${JSON.stringify(NODE)}`) && tomlP.content.includes(tomlArgs([CLI, "bridge", "--client", "codex"])), tomlP.content);
  const dshP = plan("dsh");
  assert("dsh plan carries the insert row", dshP.content.includes("- insert:") && dshP.content.includes("@deepseek-ai/dsh-mcp-client") && dshP.dshSpec.name === "switchboard");
  // http mode
  const hc = (c, o = {}) => plan(c, { mode: "http", clientsConfigured: true, ...o });
  assert("http mode: claude-code uses type http, the URL and Claude Code's ${VAR} expansion", eq(hc("claude-code").jsonEntry, { type: "http", url: urlFor(8088), headers: { Authorization: "Bearer ${SWITCHBOARD_TOKEN}" } }), JSON.stringify(hc("claude-code").jsonEntry));
  assert("http mode: cursor has no type and uses ${env:VAR}; vscode has type http", eq(hc("cursor").jsonEntry, { url: urlFor(8088), headers: { Authorization: "Bearer ${env:SWITCHBOARD_TOKEN}" } }) && hc("vscode").jsonEntry.type === "http");
  assert("http mode: codex is url + bearer_token_env_var", hc("codex").content.includes(`url = "${urlFor(8088)}"`) && hc("codex").content.includes('bearer_token_env_var = "SWITCHBOARD_TOKEN"'));
  for (const c of ["claude-desktop", "gemini", "antigravity"]) {
    let m = "";
    try {
      hc(c);
    } catch (e) {
      m = e instanceof InstallRefusal ? e.message : "wrong";
    }
    assert(`http mode is refused for ${c} (no way to name the token by environment reference)`, m.includes("--mode http") && m.includes("bridge"), m);
  }
  assert("a server name that is unsafe in TOML, YAML or a command line is refused", (() => {
    for (const bad of ["a b", "a.b", "x;y", "-x", "", "a".repeat(33), "q\"r"]) {
      try {
        plan("cursor", { name: bad });
        return false;
      } catch (e) {
        if (!(e instanceof InstallRefusal)) return false;
      }
    }
    return true;
  })());
}

console.log("\n== 1g. atomic write and backup helpers ==");
{
  const d = join(SCRATCH, "atomic");
  mkdirSync(d, { recursive: true });
  const f = join(d, "c.json");
  writeFileSync(f, '{"keep":1}\n');
  const p = buildPlan("cursor", { launcher: { command: process.execPath, cliPath: CLI }, endpoint: { host: "127.0.0.1", port: 9, requireAuth: "auto" }, scope: "project", baseDir: d, env: {} });
  assert("writePlan target for a project cursor config is <dir>/.cursor/mcp.json", p.target.path === join(d, ".cursor", "mcp.json"));
  const r = writePlan(p, { backup: true });
  assert("writePlan creates parent directories and leaves no temp file", existsSync(p.target.path) && tmpLeftovers(dirname(p.target.path)).length === 0 && r.backupPath === undefined);
  const r2 = writePlan({ ...p, content: p.content + " " }, { backup: true });
  assert("writePlan with backup keeps a byte-identical timestamped copy", r2.backupPath && BACKUP_NAME.test(r2.backupPath) && read(r2.backupPath) === p.content, r2.backupPath);
  const r3 = writePlan({ ...p, content: p.content + "  " });
  assert("writePlan backs up an existing file by default (0.1.0 overwrote in place with no copy)", r3.backupPath && BACKUP_NAME.test(r3.backupPath) && read(r3.backupPath) === p.content + " ", r3.backupPath);
  const r4 = writePlan({ ...p, content: p.content }, { backup: false });
  assert("writePlan with backup:false makes no copy", r4.backupPath === undefined);
  const b1 = backupFile(f, new Date("2026-10-23T10:00:00Z"));
  const b2 = backupFile(f, new Date("2026-10-23T10:00:00Z"));
  assert("two backups in the same second get distinct names", b1 !== b2 && b1.endsWith("bak-switchboard-20261023T100000Z") && b2.endsWith("20261023T100000Z-2") && read(b1) === read(f) && read(b2) === read(f), `${b1} ${b2}`);
  if (!WIN) {
    const target = join(d, "real.json");
    writeFileSync(target, '{"a":1}\n');
    try {
      const { symlinkSync, lstatSync } = await import("node:fs");
      symlinkSync(target, join(d, "link.json"));
      clientsMod.writeFileAtomic(join(d, "link.json"), '{"a":2}\n');
      assert("a write through a symlink updates the link's target and keeps the link", lstatSync(join(d, "link.json")).isSymbolicLink() && read(target) === '{"a":2}\n');
    } catch {
      assert("(symlink check skipped: cannot create a symlink here)", true);
    }
  }
}
// ═══════════════════════════════════════════════════════════════════════════════════════════════
// The flows below run in process through runInstall / runUninstall (the CLI's own entry points) with the real file
// writers, real stub CLIs and a counted client-registration stub: loading the CLI costs about two seconds per
// process here, so a spawn is spent only where the CLI wiring itself (flags, stdin, exit code) is the thing tested.
// ═══════════════════════════════════════════════════════════════════════════════════════════════

const cfgFor = (S) => ({ gateway: { transport: ["http"], http: { host: "127.0.0.1", port: S.port, require_auth: "auto" } } });

/** Run install or uninstall in process against a scenario. `ensure` records the clients it was asked to register. */
async function api(S, kind, client, o = {}) {
  const lines = [];
  const cap = (l) => lines.push(clean(l));
  const ensureCalls = [];
  const common = {
    client,
    scope: o.scope ?? "user",
    name: o.name ?? "switchboard",
    dir: o.dir ?? S.proj,
    dshProfile: o.dsh ?? "web",
    yes: o.yes ?? true,
    dryRun: o.dry ?? false,
    cfg: cfgFor(S),
    cfgPath: S.cfg,
    env: envFor(S, o.env ?? {}, { stubs: o.stubs }),
    platform: process.platform,
    home: S.home,
    appData: S.appdata,
    io: { out: cap, ok: cap, warn: cap, error: cap, confirm: o.confirm ?? (async () => true) },
    ...(o.probeTimeoutMs ? { probeTimeoutMs: o.probeTimeoutMs } : {}),
  };
  const res =
    kind === "install"
      ? await inst.runInstall({ ...common, mode: o.mode ?? "bridge", nodePath: process.execPath, cliPath: CLI, ensureClient: o.ensure ?? ((cfg, p, id) => (ensureCalls.push(id), { created: true, keyIssued: true })) })
      : await inst.runUninstall(common);
  return { o: res, text: lines.join("\n"), ensureCalls };
}
const installed = (r) => r.o.status === "installed" && r.o.exitCode === 0;

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// 2. every client, file route (no client CLI on PATH)
// ═══════════════════════════════════════════════════════════════════════════════════════════════

console.log("\n== 2. every client, file route ==");
const F = scenario("files", { port: await freePort() });
F.writeConfig();
const seeds = {};
const seedFile = (path, text) => {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text);
  seeds[path] = text;
  return path;
};
const paths = {
  cursor: join(F.home, ".cursor", "mcp.json"),
  vscode: join(F.appdata, "Code", "User", "mcp.json"),
  gemini: join(F.home, ".gemini", "settings.json"),
  "claude-desktop": join(F.appdata, "Claude", "claude_desktop_config.json"),
  "claude-code": join(F.home, ".claude.json"),
  antigravity: join(F.home, ".gemini", "config", "mcp_config.json"),
  antigravityLegacy: join(F.home, ".gemini", "antigravity", "mcp_config.json"),
  codex: join(F.home, ".codex", "config.toml"),
  dsh: join(F.home, ".dsh", "profiles", "web", "cordis.patch.yml"),
};
seedFile(paths.cursor, JSON.stringify({ mcpServers: { github: { url: "http://gh" } }, other: 1 }, null, 2));
seedFile(paths.vscode, JSON.stringify({ servers: { fs: { type: "stdio", command: "npx", args: ["-y", "x"] } }, inputs: [] }, null, 2));
seedFile(paths.gemini, JSON.stringify({ security: { auth: "oauth" }, mcpServers: { ragx: { command: "py", args: ["-m", "ragx"], env: { A: "b" } } }, general: {} }, null, 2));
seedFile(paths["claude-desktop"], JSON.stringify({ mcpServers: { fs: { command: "npx", args: ["-y", "fs"] } }, isUsingBuiltInNodeForMcp: true }, null, 2));
seedFile(paths["claude-code"], JSON.stringify({ numStartups: 5, projects: { "C:/p": { allowedTools: [] } }, mcpServers: { ctx: { type: "stdio", command: "node", args: ["x"] } } }, null, 2));
seedFile(paths.antigravity, JSON.stringify({ mcpServers: { masai: { command: "py", args: ["s.py"], disabled: false, disabledTools: ["gmail_search"] } } }, null, 2));
seedFile(paths.antigravityLegacy, JSON.stringify({ mcpServers: { stale: { command: "x" } } }, null, 2));
const CODEX_SEED = ["# Codex config (seed)", 'model = "gpt-x"', "", "[projects.'C:\\Users\\dev\\proj']", 'trust_level = "trusted"', "", "[mcp_servers.context7]", 'command = "C:\\\\Program Files\\\\nodejs\\\\node.exe"', "args = [", '  "D:\\\\mcp\\\\index.js",', '  "--flag",  # note', "]", "startup_timeout_sec = 30", 'notes = """', "[mcp_servers.fake]", '"""', "", "[mcp_servers.context7.env]", 'TOKEN_NAME = "v"', "", "[features]", "multi_agent = true", ""].join("\n");
seedFile(paths.codex, CODEX_SEED);
seedFile(paths.dsh, GEN);

for (const c of ["cursor", "vscode", "gemini", "claude-desktop", "claude-code", "antigravity"]) {
  const key = c === "vscode" ? "servers" : "mcpServers";
  const r = await api(F, "install", c);
  assert(`${c}: install succeeds by editing the file (no client CLI on PATH)`, installed(r) && r.o.route === "file", r.text.slice(-500));
  assert(`${c}: the client was registered under its own id (once)`, eq(r.ensureCalls, [c]));
  const now = readJson(paths[c]);
  const before = JSON.parse(seeds[paths[c]]);
  const ours = now[key]?.switchboard;
  const typed = ["claude-code", "cursor", "vscode"].includes(c);
  assert(`${c}: the entry is { ${typed ? "type: stdio, " : ""}command: node, args: [cli.js, bridge, --client, ${c}, --url] }`, eq(ours, { ...(typed ? { type: "stdio" } : {}), command: process.execPath, args: bridgeArgsFor(c, F.port) }), JSON.stringify(ours));
  const rest = JSON.parse(JSON.stringify(now));
  delete rest[key].switchboard;
  assert(`${c}: every other key and server is preserved`, eq(rest, before), JSON.stringify(rest));
  const baks = backupsOf(paths[c]);
  assert(`${c}: a timestamped backup of the original exists and is byte-identical`, baks.length === 1 && BACKUP_NAME.test(baks[0]) && read(baks[0]) === seeds[paths[c]], baks.join());
  assert(`${c}: no temp files left beside the target`, tmpLeftovers(dirname(paths[c])).length === 0);
  assert(`${c}: the preview named the file and the entry`, r.text.includes(paths[c]) && r.text.includes("bridge"));
}
assert("antigravity: the stale ~/.gemini/antigravity/mcp_config.json was left byte for byte alone", read(paths.antigravityLegacy) === seeds[paths.antigravityLegacy]);

{
  const r = await api(F, "install", "codex");
  assert("codex: install succeeds by editing config.toml (no codex CLI on PATH)", installed(r) && r.o.route === "file", r.text.slice(-500));
  const text = read(paths.codex);
  assert("codex: the [mcp_servers.switchboard] table has command and args", text.includes("[mcp_servers.switchboard]") && text.includes(`command = ${JSON.stringify(process.execPath)}`) && text.includes(`args = [${bridgeArgsFor("codex", F.port).map((a) => JSON.stringify(a)).join(", ")}]`), text.slice(-400));
  assert("codex: everything before our table is the original text, byte for byte", text.startsWith(CODEX_SEED.trimEnd()), text.slice(0, 200));
  assert("codex: the file still scans as TOML", scanToml(text).ok);
  const baks = backupsOf(paths.codex);
  assert("codex: backup byte-identical", baks.length === 1 && read(baks[0]) === CODEX_SEED);
}

{
  const r = await api(F, "install", "dsh");
  assert("dsh: install succeeds", installed(r), r.text.slice(-500));
  const text = read(paths.dsh);
  const generatedEnd = GEN.indexOf("# END local-llama") + "# END local-llama".length;
  assert("dsh: the generated local-llama block is byte for byte unchanged", text.startsWith(GEN.slice(0, generatedEnd)));
  const lay = dsh.dshLayout(text);
  assert("dsh: our block lands outside the generated markers (after # END local-llama)", lay.generated.length === 1 && lay.ours && lay.ours.start > lay.generated[0].end, JSON.stringify([lay.ours, lay.generated]));
  const row = parseYaml(text).find((x) => x.insert).insert[0];
  assert("dsh: the row is the documented dsh-mcp-client entry running the bridge", row.id === "switchboard" && row.name === "@deepseek-ai/dsh-mcp-client" && row.config.transport === "stdio" && row.config.command === process.execPath && eq(row.config.args, bridgeArgsFor("dsh", F.port)), JSON.stringify(row));
  assert("dsh: backup byte-identical", backupsOf(paths.dsh).length === 1 && read(backupsOf(paths.dsh)[0]) === GEN);
}

console.log("\n== 2b. idempotent re-install ==");
{
  const files = ["cursor", "vscode", "gemini", "claude-desktop", "claude-code", "antigravity", "codex", "dsh"];
  const before = Object.fromEntries(files.map((c) => [c, [read(paths[c]), backupsOf(paths[c]).length]]));
  for (const c of files) {
    const r = await api(F, "install", c);
    assert(`${c}: a second install reports it is already configured (status unchanged, exit 0)`, r.o.status === "unchanged" && r.o.exitCode === 0 && /identical/i.test(r.text), r.text.slice(-300));
    assert(`${c}: a second install changes no byte and makes no new backup`, read(paths[c]) === before[c][0] && backupsOf(paths[c]).length === before[c][1]);
  }
}

console.log("\n== 2c. uninstall removes only our entry ==");
{
  for (const c of ["cursor", "vscode", "gemini", "claude-desktop", "claude-code", "antigravity"]) {
    const key = c === "vscode" ? "servers" : "mcpServers";
    const nBak = backupsOf(paths[c]).length;
    const r = await api(F, "uninstall", c);
    assert(`${c}: uninstall succeeds`, r.o.status === "removed" && r.o.exitCode === 0, r.text.slice(-400));
    const after = readJson(paths[c]);
    assert(`${c}: afterwards the file equals the original (only our entry went)`, eq(after, JSON.parse(seeds[paths[c]])), JSON.stringify(after));
    assert(`${c}: a backup was taken first (one more than before)`, backupsOf(paths[c]).length === nBak + 1);
    assert(`${c}: the entry is gone`, after[key]?.switchboard === undefined);
  }
  let r = await api(F, "uninstall", "codex");
  assert("codex: uninstall succeeds and the file is the original text again, byte for byte", r.o.status === "removed" && read(paths.codex) === CODEX_SEED, JSON.stringify(read(paths.codex).slice(-200)));
  r = await api(F, "uninstall", "dsh");
  assert("dsh: uninstall succeeds and the file is the original again, generated block untouched", r.o.status === "removed" && read(paths.dsh) === GEN, JSON.stringify(read(paths.dsh).slice(-200)));
  const again = await api(F, "uninstall", "cursor");
  assert("uninstalling what is not installed succeeds and changes nothing", again.o.status === "absent" && again.o.exitCode === 0 && /nothing to remove/i.test(again.text) && eq(readJson(paths.cursor), JSON.parse(seeds[paths.cursor])));
  const noFile = await api(F, "uninstall", "gemini", { scope: "project" });
  assert("uninstall with no file at all succeeds (nothing to remove)", noFile.o.status === "absent" && /nothing to remove/i.test(noFile.text));
}

console.log("\n== 2d. project scope, custom name, http mode (file route) ==");
{
  const P = scenario("scope", { port: await freePort() });
  P.writeConfig();
  const proj = P.proj;
  const exp = {
    cursor: [join(proj, ".cursor", "mcp.json"), "mcpServers"],
    vscode: [join(proj, ".vscode", "mcp.json"), "servers"],
    gemini: [join(proj, ".gemini", "settings.json"), "mcpServers"],
    "claude-code": [join(proj, ".mcp.json"), "mcpServers"],
  };
  for (const [c, [p, key]] of Object.entries(exp)) {
    const r = await api(P, "install", c, { scope: "project", dir: proj });
    assert(`${c}: --scope project writes ${p.slice(proj.length + 1)} in the project`, installed(r) && existsSync(p) && readJson(p)[key]?.switchboard?.args?.includes(c), r.text.slice(-300));
    assert(`${c}: --scope project did not touch the user-level file`, !existsSync(join(P.home, ".cursor", "mcp.json")) && !existsSync(join(P.home, ".claude.json")));
  }
  let r = await api(P, "install", "codex", { scope: "project", dir: proj });
  assert("codex: --scope project writes <dir>/.codex/config.toml", installed(r) && read(join(proj, ".codex", "config.toml")).includes("[mcp_servers.switchboard]") && !existsSync(join(P.home, ".codex", "config.toml")), r.text.slice(-300));
  for (const c of ["claude-desktop", "antigravity", "dsh"]) {
    r = await api(P, "install", c, { scope: "project", dir: proj });
    assert(`${c}: --scope project is refused`, r.o.status === "refused" && /no project scope/.test(r.text), r.text.slice(-300));
  }
  r = await api(P, "install", "cursor", { scope: "project", dir: join(P.dir, "no-such-project") });
  assert("--scope project with a project directory that does not exist is refused (a typo must not create a tree)", r.o.status === "refused" && /does not exist/.test(r.text) && !existsSync(join(P.dir, "no-such-project")), r.text.slice(-200));
  r = await api(P, "install", "cursor", { name: "sb2" });
  const cur = join(P.home, ".cursor", "mcp.json");
  assert("--name registers the entry under that name", installed(r) && readJson(cur).mcpServers.sb2?.args?.includes("cursor"), r.text.slice(-200));
  r = await api(P, "uninstall", "cursor", { name: "sb2" });
  assert("uninstall --name removes that entry", r.o.status === "removed" && readJson(cur).mcpServers.sb2 === undefined);
  for (const bad of ["a b", "a.b", "x;y"]) {
    r = await api(P, "install", "cursor", { name: bad, dry: true });
    assert(`--name '${bad}' is refused`, r.o.status === "refused" && /invalid --name/.test(r.text), r.text.slice(-200));
  }

  // http mode
  const H = scenario("http", { port: await freePort() });
  H.writeConfig();
  const hp = {
    cursor: join(H.home, ".cursor", "mcp.json"),
    vscode: join(H.appdata, "Code", "User", "mcp.json"),
    "claude-code": join(H.home, ".claude.json"),
    codex: join(H.home, ".codex", "config.toml"),
    dsh: join(H.home, ".dsh", "profiles", "web", "cordis.patch.yml"),
  };
  for (const c of ["cursor", "vscode", "claude-code", "codex", "dsh"]) {
    r = await api(H, "install", c, { mode: "http" });
    assert(`${c}: --mode http succeeds`, installed(r), r.text.slice(-300));
  }
  const url = urlFor(H.port);
  assert("http cursor: { url, headers } with ${env:SWITCHBOARD_TOKEN}", eq(readJson(hp.cursor).mcpServers.switchboard, { url, headers: { Authorization: "Bearer ${env:SWITCHBOARD_TOKEN}" } }), JSON.stringify(readJson(hp.cursor)));
  assert("http vscode: { type: http, url, headers }", eq(readJson(hp.vscode).servers.switchboard, { type: "http", url, headers: { Authorization: "Bearer ${env:SWITCHBOARD_TOKEN}" } }));
  assert("http claude-code: { type: http, url, headers } with ${SWITCHBOARD_TOKEN}", eq(readJson(hp["claude-code"]).mcpServers.switchboard, { type: "http", url, headers: { Authorization: "Bearer ${SWITCHBOARD_TOKEN}" } }));
  assert("http codex: url and bearer_token_env_var", read(hp.codex).includes(`url = "${url}"`) && read(hp.codex).includes('bearer_token_env_var = "SWITCHBOARD_TOKEN"'));
  const hd = parseYaml(read(hp.dsh)).find((x) => x.insert).insert[0];
  assert("http dsh: streamable-http with url and headers", hd.config.transport === "streamable-http" && hd.config.url === url);
  assert("http mode writes the token's NAME as an environment reference, never a token value", ["cursor", "vscode", "claude-code", "codex", "dsh"].every((c) => !/Bearer (?!\$\{)/.test(read(hp[c])) && !/sb_[A-Za-z0-9_-]{8,}/.test(read(hp[c]))));
  for (const c of ["claude-desktop", "gemini", "antigravity"]) {
    r = await api(H, "install", c, { mode: "http" });
    assert(`${c}: --mode http is refused with a reason and writes nothing`, r.o.status === "refused" && /--mode http/.test(r.text) && /bridge/.test(r.text), r.text.slice(-300));
  }
}

console.log("\n== 2e. client registration (the real `client add` equivalent) ==");
{
  const { loadConfig } = await dist("config.js");
  const C = scenario("register", { port: await freePort(), clients: "clients:\n  vscode:\n    servers: [only-this]\n    max_scope: read\n    max_risk: low" });
  C.writeConfig();
  const keyFile = (id) => join(process.env.SWITCHBOARD_HOME, "clients", `${id}.key`);
  let cfg = loadConfig(C.cfg);
  const e1 = inst.ensureClientRegistered(cfg, C.cfg, "cursor");
  const after1 = loadConfig(C.cfg).clients;
  assert("an unconfigured client is created with the design's defaults: all servers, max_scope write, max_risk high", e1.created === true && e1.keyIssued === true && eq(after1.cursor.servers, ["*"]) && after1.cursor.max_scope === "write" && after1.cursor.max_risk === "high", JSON.stringify(after1));
  assert("... and gets a key in the client key store", existsSync(keyFile("cursor")));
  const e2 = inst.ensureClientRegistered(loadConfig(C.cfg), C.cfg, "vscode");
  const after2 = loadConfig(C.cfg).clients;
  assert("an already configured client keeps its settings (servers, max_scope, max_risk) and only gets a key", e2.created === false && e2.keyIssued === true && eq(after2.vscode.servers, ["only-this"]) && after2.vscode.max_scope === "read" && after2.vscode.max_risk === "low" && existsSync(keyFile("vscode")), JSON.stringify(after2));
  const before = read(C.cfg);
  const e3 = inst.ensureClientRegistered(loadConfig(C.cfg), C.cfg, "cursor");
  assert("a configured client with a working key is left completely alone (config file not rewritten)", e3.created === false && e3.keyIssued === false && read(C.cfg) === before);
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// 2f. the CLI itself: flags, stdin, exit codes (a handful of real processes)
// ═══════════════════════════════════════════════════════════════════════════════════════════════

console.log("\n== 2f. the CLI end to end (real processes, real client registration) ==");
{
  const E = scenario("cli-e2e", { port: await freePort() });
  E.writeConfig();
  const cur = join(E.home, ".cursor", "mcp.json");
  const curSeed = JSON.stringify({ mcpServers: { github: { url: "http://gh" } }, other: 1 }, null, 2);
  mkdirSync(dirname(cur), { recursive: true });
  writeFileSync(cur, curSeed);

  let r = run(E, ["install", "cursor"], { input: "n\n" });
  assert("without --yes, answering n aborts: exit 1, nothing written, no client registered", r.status === 1 && read(cur) === curSeed && backupsOf(cur).length === 0 && !(await sbConfigClients(E)).cursor && /not confirmed/i.test(r.all), r.all.slice(-300));
  r = run(E, ["install", "cursor"], { input: "" });
  assert("without --yes, end of input aborts (never treated as yes)", r.status === 1 && read(cur) === curSeed);
  r = run(E, ["install", "cursor"], { input: "y\n" });
  assert("without --yes, answering y applies the change (exit 0)", r.status === 0 && readJson(cur).mcpServers.switchboard?.command === process.execPath, r.all.slice(-400));
  const tok = await tokenOf(E, "cursor");
  const clients = await sbConfigClients(E);
  assert("the CLI registered the client with the design's defaults and a real key", !!tok && eq(clients.cursor?.servers, ["*"]) && clients.cursor.max_scope === "write" && clients.cursor.max_risk === "high" && existsSync(join(E.home, ".switchboard", "clients", "cursor.key")), JSON.stringify(clients));
  assert("the token is in no client file nor backup, and not in the preview or the logs", !!tok && !read(cur).includes(tok) && backupsOf(cur).every((b) => !read(b).includes(tok)) && !r.all.includes(tok));
  assert("the CLI wrote the same entry the in-process flow writes", eq(readJson(cur).mcpServers.switchboard, { type: "stdio", command: process.execPath, args: bridgeArgsFor("cursor", E.port) }) && backupsOf(cur).length === 1 && read(backupsOf(cur)[0]) === curSeed);
  const bytes = read(cur);
  r = run(E, ["install", "cursor", "--yes"]);
  assert("a second CLI install says it is already configured and changes nothing", r.status === 0 && /identical/i.test(r.all) && read(cur) === bytes && backupsOf(cur).length === 1, r.all.slice(-300));
  r = run(E, ["uninstall", "cursor", "--yes"]);
  assert("the CLI uninstall removes only our entry (the file equals the original again)", r.status === 0 && eq(readJson(cur), JSON.parse(curSeed)) && backupsOf(cur).length === 2, r.all.slice(-300));

  r = run(E, ["install", "cursor", "--print"]);
  assert("--print still works as an alias of --dry-run and prints the exact entry and target", r.status === 0 && /Dry run: nothing was written/.test(r.out) && r.out.includes(cur) && r.out.includes('"command"') && r.out.includes("bridge"), r.out.slice(0, 600));
  r = run(E, ["install", "dsh", "--dsh-profile", "headless", "--mode", "http", "--name", "sb2", "--dry-run"]);
  assert("the CLI passes --dsh-profile, --mode and --name through (dsh http preview)", r.status === 0 && r.out.includes(join("profiles", "headless", "cordis.patch.yml")) && r.out.includes("streamable-http") && r.out.includes("id: sb2"), r.out.slice(0, 700));
  r = run(E, ["install", "vscode", "--scope", "project", "--dir", E.proj, "--dry-run"]);
  assert("the CLI passes --scope project and --dir through", r.status === 0 && r.out.includes(join(E.proj, ".vscode", "mcp.json")), r.out.slice(0, 500));
  r = run(E, ["install", "emacs"]);
  assert("an unknown client is refused (exit 1) and the supported ones are listed", r.status === 1 && /unknown client 'emacs'/.test(r.all) && r.all.includes("antigravity"));
  r = run(E, ["install", "cursor", "--mode", "ftp"]);
  assert("an unknown --mode is refused (exit 1)", r.status === 1 && /--mode must be/.test(r.all));
  r = run(E, ["install", "cursor", "--scope", "galaxy"]);
  assert("an unknown --scope is refused (exit 1)", r.status === 1 && /--scope must be/.test(r.all));
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// 3. the CLI route (stub claude, codex, agy on PATH)
// ═══════════════════════════════════════════════════════════════════════════════════════════════

console.log("\n== 3. the client's own CLI (stubs on PATH, argv recorded) ==");
const K = scenario("cli", { port: await freePort(), stubs: true });
K.writeConfig();
const kp = {
  claude: join(K.home, ".claude.json"),
  codex: join(K.home, ".codex", "config.toml"),
  agy: join(K.home, ".gemini", "config", "mcp_config.json"),
};
const claudeSeed = JSON.stringify({ numStartups: 9, mcpServers: { ctx: { type: "stdio", command: "node", args: ["x"] } } }, null, 2);
const agySeed = JSON.stringify({ mcpServers: { masai: { command: "py", args: ["s.py"], disabledTools: ["a"] } } }, null, 2);
mkdirSync(dirname(kp.codex), { recursive: true });
mkdirSync(dirname(kp.agy), { recursive: true });
writeFileSync(kp.claude, claudeSeed);
writeFileSync(kp.codex, CODEX_SEED);
writeFileSync(kp.agy, agySeed);
{
  let r = await api(K, "install", "claude-code");
  assert("claude-code: install through `claude mcp add-json` succeeds (route cli)", installed(r) && r.o.route === "cli", r.text.slice(-600));
  let calls = stubCalls(K, "claude");
  const add = calls.find((c) => c.argv[1] === "add-json");
  const wantJson = { type: "stdio", command: process.execPath, args: bridgeArgsFor("claude-code", K.port) };
  assert("claude-code: argv is mcp add-json switchboard <json> --scope user (JSON received exactly, through the .cmd shim on Windows)", add && eq(add.argv.slice(0, 3), ["mcp", "add-json", "switchboard"]) && eq(JSON.parse(add.argv[3]), wantJson) && eq(add.argv.slice(4), ["--scope", "user"]), JSON.stringify(add));
  assert("claude-code: the probe ran `claude mcp get switchboard`", calls.some((c) => eq(c.argv, ["mcp", "get", "switchboard"])));
  assert("claude-code: ~/.claude.json holds the entry and everything else", eq(readJson(kp.claude).mcpServers.switchboard, wantJson) && readJson(kp.claude).numStartups === 9 && readJson(kp.claude).mcpServers.ctx.command === "node");
  assert("claude-code: no copy of the big ~/.claude.json is made (the previous entry is recorded instead)", backupsOf(kp.claude).length === 0);
  const recDir = join(process.env.SWITCHBOARD_HOME, "install-backups");
  const recs = existsSync(recDir) ? readdirSync(recDir).filter((n) => n.startsWith("claude-code-user-")) : [];
  assert("claude-code: an install record with the previous entry was saved under SWITCHBOARD_HOME", recs.length === 1 && "previous" in readJson(join(recDir, recs[0])), recs.join());
  const nAdd = calls.filter(MUTATING).length;
  r = await api(K, "install", "claude-code");
  calls = stubCalls(K, "claude");
  assert("claude-code: a second install is a no-op (no add-json, no remove)", r.o.status === "unchanged" && calls.filter(MUTATING).length === nAdd, r.text.slice(-200));

  r = await api(K, "install", "codex");
  assert("codex: install through `codex mcp add` succeeds (route cli)", installed(r) && r.o.route === "cli", r.text.slice(-600));
  const cadd = stubCalls(K, "codex").find((c) => c.argv[1] === "add");
  assert("codex: argv is mcp add switchboard -- <node> <cli.js> bridge --client codex --url <url>", cadd && eq(cadd.argv, ["mcp", "add", "switchboard", "--", process.execPath, ...bridgeArgsFor("codex", K.port)]), JSON.stringify(cadd));
  assert("codex: the probe ran `codex mcp get switchboard --json`", stubCalls(K, "codex").some((c) => eq(c.argv, ["mcp", "get", "switchboard", "--json"])));
  const cb = backupsOf(kp.codex);
  assert("codex: config.toml was backed up before the CLI wrote, byte-identical", cb.length === 1 && read(cb[0]) === CODEX_SEED);
  assert("codex: config.toml holds the entry", read(kp.codex).includes("[mcp_servers.switchboard]"));
  const nC = stubCalls(K, "codex").filter(MUTATING).length;
  r = await api(K, "install", "codex");
  assert("codex: a second install is a no-op (judged by `codex mcp get --json`) and makes no backup", r.o.status === "unchanged" && stubCalls(K, "codex").filter(MUTATING).length === nC && backupsOf(kp.codex).length === 1, r.text.slice(-200));

  r = await api(K, "install", "antigravity");
  assert("antigravity: install through `agy mcp add` succeeds (route cli)", installed(r) && r.o.route === "cli", r.text.slice(-600));
  const aadd = stubCalls(K, "agy").find((c) => c.argv[1] === "add");
  assert("antigravity: argv is mcp add switchboard -- <node> <cli.js> bridge --client antigravity --url <url>", aadd && eq(aadd.argv, ["mcp", "add", "switchboard", "--", process.execPath, ...bridgeArgsFor("antigravity", K.port)]), JSON.stringify(aadd));
  assert("antigravity: the probe ran `agy mcp list`", stubCalls(K, "agy").some((c) => eq(c.argv, ["mcp", "list"])));
  assert("antigravity: the config was backed up byte-identical first, and masai's settings survive", backupsOf(kp.agy).length === 1 && read(backupsOf(kp.agy)[0]) === agySeed && readJson(kp.agy).mcpServers.masai.disabledTools[0] === "a");
  const nA = stubCalls(K, "agy").filter(MUTATING).length;
  r = await api(K, "install", "antigravity");
  assert("antigravity: a second install is a no-op", r.o.status === "unchanged" && stubCalls(K, "agy").filter(MUTATING).length === nA && backupsOf(kp.agy).length === 1, r.text.slice(-200));

  // project scope through the CLI: cwd is the project, scope flag is project
  const proj = join(K.dir, "claude-proj");
  mkdirSync(proj, { recursive: true });
  r = await api(K, "install", "claude-code", { scope: "project", dir: proj });
  const padd = stubCalls(K, "claude").filter((c) => c.argv[1] === "add-json").pop();
  assert("claude-code project scope: --scope project, run in the project directory, writes <dir>/.mcp.json", installed(r) && eq(padd.argv.slice(-2), ["--scope", "project"]) && resolve(padd.cwd) === resolve(proj) && existsSync(join(proj, ".mcp.json")), r.text.slice(-300));
  r = await api(K, "install", "codex", { scope: "project", dir: proj });
  assert("codex project scope: the CLI has no scope option, so the project file is written directly", installed(r) && r.o.route === "file" && existsSync(join(proj, ".codex", "config.toml")) && stubCalls(K, "codex").filter(MUTATING).length === nC, r.text.slice(-300));

  // http mode through the CLI
  const K2 = scenario("cli-http", { port: await freePort(), stubs: true });
  K2.writeConfig();
  r = await api(K2, "install", "claude-code", { mode: "http" });
  const hadd = stubCalls(K2, "claude").find((c) => c.argv[1] === "add-json");
  assert("claude-code http through the CLI: add-json with type http, url and the ${SWITCHBOARD_TOKEN} header", installed(r) && hadd && eq(JSON.parse(hadd.argv[3]), { type: "http", url: urlFor(K2.port), headers: { Authorization: "Bearer ${SWITCHBOARD_TOKEN}" } }), JSON.stringify(hadd));
  r = await api(K2, "install", "codex", { mode: "http" });
  const hc = stubCalls(K2, "codex").find((c) => c.argv[1] === "add");
  assert("codex http through the CLI: --url and --bearer-token-env-var SWITCHBOARD_TOKEN", installed(r) && hc && eq(hc.argv, ["mcp", "add", "switchboard", "--url", urlFor(K2.port), "--bearer-token-env-var", "SWITCHBOARD_TOKEN"]), JSON.stringify(hc));
  r = await api(K2, "install", "antigravity", { mode: "http" });
  assert("antigravity http is refused even with the CLI present, and no command ran", r.o.status === "refused" && stubCalls(K2, "agy").length === 0);
}

console.log("\n== 3b. uninstall through the CLI ==");
{
  let r = await api(K, "uninstall", "claude-code");
  const rm = stubCalls(K, "claude").filter((c) => c.argv[1] === "remove").pop();
  assert("claude-code: uninstall runs `claude mcp remove switchboard --scope user`", r.o.status === "removed" && rm && eq(rm.argv, ["mcp", "remove", "switchboard", "--scope", "user"]), r.text.slice(-300));
  assert("claude-code: only our entry went, everything else is as seeded", eq(readJson(kp.claude), JSON.parse(claudeSeed)));
  r = await api(K, "uninstall", "codex");
  assert("codex: uninstall runs `codex mcp remove switchboard`; the file is the original again", r.o.status === "removed" && stubCalls(K, "codex").some((c) => eq(c.argv, ["mcp", "remove", "switchboard"])) && read(kp.codex).trimEnd() === CODEX_SEED.trimEnd(), JSON.stringify(read(kp.codex).slice(-200)));
  assert("codex: a backup was taken before the removal", backupsOf(kp.codex).length === 2);
  r = await api(K, "uninstall", "antigravity");
  assert("antigravity: uninstall runs `agy mcp remove switchboard`; masai stays", r.o.status === "removed" && stubCalls(K, "agy").some((c) => eq(c.argv, ["mcp", "remove", "switchboard"])) && eq(readJson(kp.agy), JSON.parse(agySeed)), r.text.slice(-300));
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// 4. refusal and dry-run
// ═══════════════════════════════════════════════════════════════════════════════════════════════

console.log("\n== 4. refusal on an unparseable file; dry-run writes nothing ==");
{
  const R = scenario("refuse", { port: await freePort(), stubs: true });
  R.writeConfig();
  const cases = [
    ["cursor", join(R.home, ".cursor", "mcp.json"), "{ not json", /not valid JSON/],
    ["cursor", join(R.home, ".cursor", "mcp.json"), "[]", /does not hold a JSON object/],
    ["cursor", join(R.home, ".cursor", "mcp.json"), '{"mcpServers": []}', /is not an object/],
    ["cursor", join(R.home, ".cursor", "mcp.json"), '{"mcpServers": {}, // comment\n}', /not valid JSON/],
    ["vscode", join(R.appdata, "Code", "User", "mcp.json"), '{"servers": "x"}', /is not an object/],
    ["gemini", join(R.home, ".gemini", "settings.json"), "\u0000\u0001garbage", /not valid JSON/],
    ["claude-desktop", join(R.appdata, "Claude", "claude_desktop_config.json"), '{"mcpServers": {', /not valid JSON/],
    ["claude-code", join(R.home, ".claude.json"), "not json at all", /not valid JSON/],
    ["antigravity", join(R.home, ".gemini", "config", "mcp_config.json"), '{"mcpServers": 5}', /is not an object/],
    ["codex", join(R.home, ".codex", "config.toml"), 'model = "unterminated\n[x]\n', /not valid TOML/],
    ["codex", join(R.home, ".codex", "config.toml"), "garbage line without equals\n", /not valid TOML/],
    ["codex", join(R.home, ".codex", "config.toml"), 'mcp_servers.switchboard.command = "x"\n', /dotted keys/],
    ["dsh", join(R.home, ".dsh", "profiles", "web", "cordis.patch.yml"), GEN.replace("# END local-llama", "# no end"), /has no '# END local-llama'/],
    ["dsh", join(R.home, ".dsh", "profiles", "web", "cordis.patch.yml"), GEN + "- [unclosed\n", /not valid YAML/],
    ["dsh", join(R.home, ".dsh", "profiles", "web", "cordis.patch.yml"), GEN + "- id: switchboard\n  name: x\n", /did not write/],
    ["dsh", join(R.home, ".dsh", "profiles", "web", "cordis.patch.yml"), "a: 1\n", /top-level YAML list/],
  ];
  for (const [i, [client, path, content, pattern]] of cases.entries()) {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, content);
    const before = listTree(R.dir);
    const cfgBefore = read(R.cfg);
    const r = await api(R, "install", client);
    assert(`refuses ${client}: ${JSON.stringify(content.slice(0, 28))}`, r.o.status === "refused" && r.o.exitCode === 1 && pattern.test(r.text) && r.text.includes(path.split(/[\\/]/).pop()), r.text.slice(-300));
    assert(`  ... the file is byte for byte unchanged, no backup, no temp file, no client registered, no CLI run`, read(path) === content && eq(listTree(R.dir), before) && read(R.cfg) === cfgBefore && r.ensureCalls.length === 0 && stubLog(R).filter(MUTATING).length === 0);
    const d = await api(R, "install", client, { dry: true });
    assert(`  ... dry-run refuses it too`, d.o.status === "refused" && pattern.test(d.text));
    const u = await api(R, "uninstall", client);
    // A row with our id that this tool did not write is reported and left alone (nothing of ours to remove); every other bad file is refused.
    const foreign = /did not write/.test(pattern.source);
    assert(`  ... uninstall leaves it alone (${foreign ? "reports the foreign row" : "refuses"})`, read(path) === content && (foreign ? u.o.status === "absent" && /left alone/.test(u.text) : u.o.status === "refused"), u.text.slice(-200));
    if ([0, 9, 12].includes(i)) {
      const c = run(R, ["install", client, "--yes"]);
      assert(`  ... end to end through the CLI: exit 1, the message names the file, nothing touched`, c.status === 1 && pattern.test(c.all) && read(path) === content && eq(listTree(R.dir), before) && read(R.cfg) === cfgBefore, c.all.slice(-300));
    }
    rmSync(path);
  }
}
{
  // dry-run, all eight clients, empty homes, stubs on PATH
  const D = scenario("dry", { port: await freePort(), stubs: true });
  D.writeConfig();
  const before = listTree(D.dir);
  for (const c of SUPPORTED_CLIENTS) {
    const r = await api(D, "install", c, { dry: true });
    assert(`${c}: install --dry-run shows the plan and says nothing was written`, r.o.status === "dry-run" && r.o.exitCode === 0 && /Dry run: nothing was written/.test(r.text) && /bridge/.test(r.text) && r.text.includes(c) && r.ensureCalls.length === 0, r.text.slice(-300));
    const u = await api(D, "uninstall", c, { dry: true });
    assert(`${c}: uninstall --dry-run succeeds`, u.o.exitCode === 0, u.text.slice(-200));
  }
  assert("dry-run created no file anywhere in the fake home, project or config", eq(listTree(D.dir).filter((f) => !f.includes("stub.log")), before.filter((f) => !f.includes("stub.log"))));
  assert("dry-run ran no command that changes anything (no add, add-json or remove)", stubLog(D).filter(MUTATING).length === 0, JSON.stringify(stubLog(D)));
  const pv = await api(D, "install", "claude-code", { dry: true });
  assert("the preview of a CLI route prints the exact command", pv.text.includes("mcp add-json switchboard") && pv.text.includes("--scope user") && pv.text.includes("claude"), pv.text.slice(0, 800));
  const pc = await api(D, "install", "codex", { dry: true });
  assert("the codex preview prints `codex mcp add switchboard -- <node> ...`", /mcp add switchboard -- /.test(pc.text), pc.text.slice(0, 600));
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// 5. probe and rollback
// ═══════════════════════════════════════════════════════════════════════════════════════════════

console.log("\n== 5. probe failure rolls back ==");
{
  // CLI route: codex `get` fails after a successful add
  const Z = scenario("rb-codex", { port: await freePort(), stubs: true });
  Z.writeConfig();
  const cfgToml = join(Z.home, ".codex", "config.toml");
  mkdirSync(dirname(cfgToml), { recursive: true });
  writeFileSync(cfgToml, CODEX_SEED);
  let r = await api(Z, "install", "codex", { env: { STUB_GET_EXIT: "1" } });
  assert("codex: a failing `codex mcp get` makes install fail (rolled-back, exit 1) and say so", r.o.status === "rolled-back" && r.o.exitCode === 1 && /Rolled back/.test(r.text) && /probe failed/.test(r.text), r.text.slice(-400));
  assert("codex: config.toml is restored byte for byte from the backup", read(cfgToml) === CODEX_SEED);
  assert("codex: the backup is kept as evidence", backupsOf(cfgToml).length === 1 && read(backupsOf(cfgToml)[0]) === CODEX_SEED);
  assert("codex: the rollback also asked the CLI to remove the entry (there was none before)", stubCalls(Z, "codex").some((c) => c.argv[1] === "remove"));

  // add itself fails
  const Z2 = scenario("rb-add", { port: await freePort(), stubs: true });
  Z2.writeConfig();
  const t2 = join(Z2.home, ".codex", "config.toml");
  mkdirSync(dirname(t2), { recursive: true });
  writeFileSync(t2, CODEX_SEED);
  r = await api(Z2, "install", "codex", { env: { STUB_ADD_EXIT: "1" } });
  assert("codex: a failing `codex mcp add` fails the install and leaves config.toml as it was", r.o.status === "failed" && /write failed/.test(r.text) && read(t2) === CODEX_SEED, r.text.slice(-300));

  // a client that refuses to add an existing name: one retry after a remove, and the old entry is replaced
  const Z5 = scenario("replace-codex", { port: await freePort(), stubs: true });
  Z5.writeConfig();
  const t5 = join(Z5.home, ".codex", "config.toml");
  mkdirSync(dirname(t5), { recursive: true });
  const oldToml = '[mcp_servers.switchboard]\nurl = "http://127.0.0.1:1/old"\n';
  writeFileSync(t5, oldToml);
  r = await api(Z5, "install", "codex", { env: { STUB_ADD_REFUSES_EXISTING: "1" } });
  const subs5 = stubCalls(Z5, "codex").map((c) => c.argv[1]);
  assert("codex: an existing entry that `add` refuses is replaced after one remove and a retry (get, add, remove, add, get)", installed(r) && eq(subs5, ["get", "add", "remove", "add", "get"]) && !read(t5).includes("/old") && read(t5).includes("bridge"), `${subs5} ${r.text.slice(-300)}`);
  assert("codex: the replaced entry's old text is kept in the backup", backupsOf(t5).length === 1 && read(backupsOf(t5)[0]) === oldToml);

  // claude with no previous entry: removed again
  const Z3 = scenario("rb-claude", { port: await freePort(), stubs: true });
  Z3.writeConfig();
  const cj = join(Z3.home, ".claude.json");
  writeFileSync(cj, claudeSeed);
  r = await api(Z3, "install", "claude-code", { env: { STUB_GET_EXIT: "1" } });
  assert("claude-code: a failing `claude mcp get` rolls back; the entry is removed again and the rest is as it was", r.o.status === "rolled-back" && /Rolled back/.test(r.text) && eq(readJson(cj), JSON.parse(claudeSeed)), r.text.slice(-300));

  // claude with a previous entry: the old one is put back
  const Z4 = scenario("rb-claude-prev", { port: await freePort(), stubs: true });
  Z4.writeConfig();
  const cj4 = join(Z4.home, ".claude.json");
  const oldEntry = { type: "stdio", command: "C:\\old\\node.exe", args: ["old.js"], env: { KEEP: "1" } };
  writeFileSync(cj4, JSON.stringify({ mcpServers: { switchboard: oldEntry } }, null, 2));
  r = await api(Z4, "install", "claude-code", { env: { STUB_GET_EXIT: "1" } });
  const calls4 = stubCalls(Z4, "claude").map((c) => c.argv[1]);
  assert("claude-code: the previous entry is put back after a failed probe (remove, add-json new, get, remove, add-json old)", r.o.status === "rolled-back" && eq(readJson(cj4).mcpServers.switchboard, oldEntry) && eq(calls4, ["remove", "add-json", "get", "remove", "add-json"]), `${r.text.slice(-300)} ${calls4}`);

  // The bridge probe needs the client's real key: write one into this process's key store (which the probe's child reads
  // through SWITCHBOARD_HOME) and stand up gateways in this process (the flows are async, so the event loop serves them).
  const { writeClientKey } = await dist("clientkeys.js");
  const TOKEN = `sb_oracle_${"k".repeat(24)}`;
  writeClientKey("cursor", TOKEN);
  const sbEnv = { SWITCHBOARD_HOME: process.env.SWITCHBOARD_HOME };
  const keepKey = () => ({ created: false, keyIssued: false });
  const seenBad = [];
  const bad = createServer((req, res) => {
    req.on("data", () => undefined).on("end", () => {
      seenBad.push(req.headers.authorization);
      res.statusCode = 500;
      res.end("boom");
    });
  });
  await new Promise((res) => bad.listen(0, "127.0.0.1", res));
  const FB = scenario("rb-file", { port: bad.address().port });
  FB.writeConfig();
  const curB = join(FB.home, ".cursor", "mcp.json");
  mkdirSync(dirname(curB), { recursive: true });
  const curSeed = JSON.stringify({ mcpServers: { github: { url: "http://gh" } } }, null, 2);
  writeFileSync(curB, curSeed);
  r = await api(FB, "install", "cursor", { env: sbEnv, ensure: keepKey });
  assert("cursor: a gateway that answers the bridge's initialize with an error makes the probe fail (rolled-back, exit 1)", r.o.status === "rolled-back" && r.o.exitCode === 1 && /Rolled back/.test(r.text) && /bridge/.test(r.text), r.text.slice(-500));
  assert("cursor: the file is restored byte for byte and the backup is kept", read(curB) === curSeed && backupsOf(curB).length === 1 && read(backupsOf(curB)[0]) === curSeed);
  assert("cursor: the gateway really was contacted by the bridge, with this client's bearer key", seenBad.length >= 1 && seenBad[0] === `Bearer ${TOKEN}`, JSON.stringify(seenBad));
  const FB2 = scenario("rb-file-new", { port: bad.address().port });
  FB2.writeConfig();
  const cursorNew = join(FB2.home, ".cursor", "mcp.json");
  r = await api(FB2, "install", "cursor", { env: sbEnv, ensure: keepKey });
  assert("cursor (no file before): a failed probe removes the file this install created", r.o.status === "rolled-back" && !existsSync(cursorNew), r.text.slice(-300));
  bad.close();
  bad.closeAllConnections?.();

  // a working gateway: the bridge entry is started with the client's real key and gets a result
  const seenOk = [];
  const good = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c)).on("end", () => {
      const msg = JSON.parse(body);
      seenOk.push({ auth: req.headers.authorization, method: msg.method });
      if (req.headers.authorization !== `Bearer ${TOKEN}`) {
        res.statusCode = 401;
        res.end("{}");
        return;
      }
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-03-26", capabilities: {}, serverInfo: { name: "stub", version: "0" } } }));
    });
  });
  await new Promise((res) => good.listen(0, "127.0.0.1", res));
  const FG = scenario("ok-gateway", { port: good.address().port });
  FG.writeConfig();
  r = await api(FG, "install", "cursor", { env: sbEnv, ensure: keepKey });
  assert("cursor: with a gateway running, the bridge entry is started and answers initialize", installed(r) && /bridge answered initialize/.test(r.text), r.text.slice(-500));
  assert("cursor: the bridge authenticated with this client's own stored key", seenOk.length >= 1 && seenOk[0].auth === `Bearer ${TOKEN}` && seenOk[0].method === "initialize", JSON.stringify(seenOk));
  good.close();
  good.closeAllConnections?.();

  // and with no gateway at all, the install still succeeds and says the entry was not exercised
  const FN = scenario("no-gateway", { port: await freePort() });
  FN.writeConfig();
  r = await api(FN, "install", "cursor", { env: sbEnv, ensure: keepKey });
  assert("no gateway running: the install succeeds and reports the bridge entry was not exercised", installed(r) && /not exercised/.test(r.text), r.text.slice(-300));
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// 6. in-process guards
// ═══════════════════════════════════════════════════════════════════════════════════════════════

console.log("\n== 6. in-process guards ==");
{
  const d = join(SCRATCH, "inproc");
  mkdirSync(d, { recursive: true });
  const target = join(d, ".cursor", "mcp.json");
  mkdirSync(dirname(target), { recursive: true });
  const original = JSON.stringify({ mcpServers: {} });
  writeFileSync(target, original);
  const lines = [];
  const io = {
    out: (l) => lines.push(l),
    ok: (l) => lines.push(l),
    warn: (l) => lines.push(l),
    error: (l) => lines.push(l),
    confirm: async () => {
      writeFileSync(target, JSON.stringify({ mcpServers: { edited: { url: "http://changed-while-asking" } } }));
      return true;
    },
  };
  const cfg = { gateway: { transport: ["http"], http: { host: "127.0.0.1", port: 9, require_auth: "auto" } } };
  const base = { client: "cursor", mode: "bridge", scope: "project", name: "switchboard", dir: d, dshProfile: "web", yes: false, dryRun: false, cfg, cfgPath: join(d, "none.yaml"), nodePath: process.execPath, cliPath: CLI, env: { PATH: CLEAN_DIRS.join(delimiter) }, io, ensureClient: () => ({ created: false, keyIssued: false }) };
  const out1 = await inst.runInstall(base);
  assert("a file edited while the owner reads the preview is never overwritten", out1.status === "refused" && /changed after the preview/.test(out1.message) && read(target).includes("changed-while-asking") && !read(target).includes("bridge"), out1.message);
  assert("the refusal left no backup behind", backupsOf(target).length === 0);

  const okBridge = join(SCRATCH, "fake-bridge-ok.mjs");
  writeFileSync(okBridge, `process.stdin.on("data", (d) => { const m = JSON.parse(String(d).split("\\n")[0]); process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: "2025-03-26" } }) + "\\n"); });`);
  const errBridge = join(SCRATCH, "fake-bridge-err.mjs");
  writeFileSync(errBridge, `process.stdin.on("data", (d) => { const m = JSON.parse(String(d).split("\\n")[0]); process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, error: { code: -32000, message: "Switchboard rejected the key (HTTP 401)" } }) + "\\n"); });`);
  const hangBridge = join(SCRATCH, "fake-bridge-hang.mjs");
  writeFileSync(hangBridge, "setInterval(() => undefined, 1000);");
  const pr = await inst.probeBridge(process.execPath, [okBridge], process.env, 10_000);
  assert("probeBridge: a bridge that answers initialize with a result passes", pr.ok && /protocol 2025-03-26/.test(pr.detail), pr.detail);
  const pe = await inst.probeBridge(process.execPath, [errBridge], process.env, 10_000);
  assert("probeBridge: an error answer fails and carries the bridge's message", !pe.ok && /rejected the key/.test(pe.detail), pe.detail);
  const t0 = Date.now();
  const ph = await inst.probeBridge(process.execPath, [hangBridge], process.env, 800);
  assert("probeBridge: a bridge that never answers fails at the timeout (and is killed)", !ph.ok && /no answer/.test(ph.detail) && Date.now() - t0 < 5000, ph.detail);
  const pn = await inst.probeBridge(join(SCRATCH, "does-not-exist.exe"), [], process.env, 2000);
  assert("probeBridge: a command that cannot start fails cleanly", !pn.ok, pn.detail);
  const withKey = join(SCRATCH, "fake-bridge-env.mjs");
  writeFileSync(withKey, `process.stdin.on("data", (d) => { const m = JSON.parse(String(d).split("\\n")[0]); process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: process.env.SWITCHBOARD_KEY ? "KEY-LEAKED" : "clean" } }) + "\\n"); });`);
  const pk = await inst.probeBridge(process.execPath, [withKey], { ...process.env, SWITCHBOARD_KEY: "operator-key" }, 10_000);
  assert("probeBridge: the operator's SWITCHBOARD_KEY is not passed down (the probe must use the stored client key)", pk.ok && /clean/.test(pk.detail), pk.detail);
  const gp = await freePort();
  assert("gatewayReachable: false for a closed port", (await inst.gatewayReachable(`http://127.0.0.1:${gp}/mcp`, 500)) === false);
  const lis = createNetServer();
  await new Promise((res) => lis.listen(0, "127.0.0.1", res));
  assert("gatewayReachable: true for a listening port", (await inst.gatewayReachable(`http://127.0.0.1:${lis.address().port}/mcp`, 500)) === true);
  lis.close();
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// 7. hygiene
// ═══════════════════════════════════════════════════════════════════════════════════════════════

console.log("\n== 7. hygiene ==");
{
  const files = ["src/clients.ts", "src/installer.ts", "src/cliexec.ts", "src/tomlscan.ts", "src/dshpatch.ts", "src/installerror.ts", "scripts/verify-installers.mjs", "scripts/verify-install.mjs"];
  const dash = String.fromCharCode(0x2014);
  const bad = files.filter((f) => read(join(root, f)).includes(dash));
  assert("no em dash in any file this feature added or rewrote", bad.length === 0, bad.join());
  assert("the test PATH held none of the real claude, codex, agy or dsh", CLEAN_DIRS.every((d) => !["claude", "codex", "agy", "dsh"].some((n) => existsSync(join(d, n)) || existsSync(join(d, n + ".exe")) || existsSync(join(d, n + ".cmd")))));
  assert("no scenario used gateway port 8088", scenarioPorts.every((p) => p !== 8088) && scenarioPorts.length > 10, scenarioPorts.join());
  assert("backups accumulate rather than overwrite (cursor has install and uninstall copies)", backupsOf(paths.cursor).length >= 2, String(backupsOf(paths.cursor).length));
}

try {
  rmSync(SCRATCH, { recursive: true, force: true });
} catch {
  /* temp leftovers are harmless */
}
const failed = checks.filter((c) => !c.ok);
console.log(`\n${checks.length - failed.length}/${checks.length} checks passed`);
if (failed.length) console.log("FAILED:", failed.map((c) => c.name).join(" | "));
process.exitCode = failed.length === 0 ? 0 : 1;
