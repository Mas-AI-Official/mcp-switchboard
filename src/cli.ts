#!/usr/bin/env node
/**
 * `switchboard` — the command-line entry point.
 *
 *   switchboard init                 scaffold a config + home dir
 *   switchboard serve                run the gateway (stdio and/or HTTP per config)
 *   switchboard dashboard            run only the HTTP endpoint + web console
 *   switchboard dashboard login      sign in: the RUNNING gateway checks you are present, then hands out a one-time login code
 *   switchboard list                 mount everything and print the governed tool list
 *   switchboard doctor               check the environment + config
 *   switchboard catalog              list OAuth providers + connection status
 *   switchboard connect <provider>   authorize a provider via local loopback OAuth
 *   switchboard install <client>     register MCP Switchboard in an MCP client (bridge by default; preview, backup, probe, rollback)
 *   switchboard uninstall <client>   remove only the Switchboard entry from an MCP client (backup first)
 *   switchboard bridge --client <id> relay a client's stdio to the shared HTTP gateway as that client
 *   switchboard client add|list|rotate|rm   register clients (who may call /mcp) and manage their keys (a running gateway checks you are present before it grants one)
 *   switchboard local-llm            detect a local LLM server for the offline council
 *   switchboard local-llm wire       wire a detected local server into the council
 *   switchboard toolkits sync        rebuild the integration catalog from open indexes
 *   switchboard toolkits stats       print catalog counts
 *   switchboard approvals list|show|approve|deny   decide the calls waiting for the owner (talks to the running gateway)
 *   switchboard kill on|off|status   refuse every tool call, resource read and prompt get (kill switch)
 *   switchboard audit verify [--all] walk the audit log's hash chain; report the first break with its seq
 *   switchboard vault set <name>     store a secret (value read from stdin)
 *   switchboard vault list|rm <name> manage secrets
 *
 * Logs go to stderr (see logger.ts) so stdout stays clean for the stdio MCP channel.
 */

import { existsSync } from "node:fs";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { Command } from "commander";
import { loadConfig, writeConfig, starterConfig } from "./config.js";
import type { ClientConfig, SwitchboardConfig } from "./types.js";
import {
  applyProfileEnvOverride,
  describeProfile,
  withActiveProfile,
} from "./profiles.js";
import { createGateway } from "./gateway.js";
import { startDashboard, type DashboardHandle } from "./dashboard.js";
import { assertPortFree } from "./httpsec.js";
import { runExpose, TUNNEL_KINDS, type TunnelKind } from "./expose.js";
import { ensureDir } from "./atomicfile.js";
import { Vault, HOME_DIR } from "./vault.js";
import { OAuthStore } from "./oauth.js";
import { ApiKeyStore } from "./apikeys.js";
import { ClientAdmin, ClientAdminError, NEW_CLIENT_DEFAULTS, type ClientSpec } from "./clientadmin.js";
import { ClientConfigWatcher } from "./clientconfig.js";
import { APPROVAL_ID_RE, APPROVALS_FILE, summarizeArgs, type ApprovalView } from "./approvals.js";
import { ControlError, askGateway, controlRequest } from "./controlclient.js";
import { readClientKey } from "./clientkeys.js";
import { readJsonFileSync } from "./atomicfile.js";
import { BAD_CLIENT_ID, isValidClientId, type Principal } from "./principal.js";
import { inferScope } from "./policy.js";
import { killFilePath, killStatus, setKillFile } from "./killswitch.js";
import { verifyAudit } from "./audit.js";
import { buildDoctorReport } from "./doctor.js";
import {
  ingestCatalogVerbose,
  loadCatalog,
  writeCatalog,
  defaultCatalogPath,
  discoverToolkits,
  fetchAwesomeTaxonomy,
  applyTaxonomyToSnapshot,
} from "./catalog.js";
import { SUPPORTED_CLIENTS, type ClientId } from "./clients.js";
import { runInstall, runUninstall } from "./installer.js";
import { DEFAULT_BRIDGE_URL, runBridge } from "./bridge.js";
import {
  KNOWN_RUNTIMES,
  probeRuntime,
  probeAll,
  pickDefaultModel,
  buildLocalProvider,
  withLocalProvider,
  withLocalAllowance,
  wireAdvice,
  installGuide,
} from "./localllm.js";
import { log, out } from "./logger.js";
import { safeText } from "./safetext.js";
import { guardedFetch, type NetworkSettings } from "./netguard.js";

const DEFAULT_CONFIG = "switchboard.config.yaml";
const program = new Command();

program
  .name("switchboard")
  .description("Local-first governed MCP aggregator — one endpoint for all your MCP servers.")
  .version("0.1.0")
  .option("-c, --config <path>", "path to switchboard.config.yaml", DEFAULT_CONFIG);

function configPath(): string {
  return resolve(program.opts().config as string);
}

/**
 * Load the config AND fold the `SWITCHBOARD_PROFILE` env var into the active profile, so every
 * runtime boot path (serve/dashboard/expose/list) sees the same effective view. A bad env value
 * warns but never aborts — a typo in an env var must not stop the server from booting.
 */
function bootConfig(path: string): SwitchboardConfig {
  const { config, note } = applyProfileEnvOverride(loadConfig(path));
  if (note) log.warn(note);
  return config;
}

/**
 * The `settings.network` of the config on disk, or undefined when there is no readable config. For
 * commands that make outbound calls (catalog sync, local-llm probes) but must not require a valid config.
 */
function networkFromConfig(): NetworkSettings | undefined {
  try {
    return loadConfig(configPath()).settings?.network;
  } catch {
    return undefined;
  }
}

/**
 * Start the HTTP listener or stop the whole process. A busy port used to be reported as success
 * (the listen error was swallowed), leaving a second instance that looked healthy beside a stranger.
 * Now it logs the reason, tears the gateway down so no upstream child is orphaned, and exits non-zero.
 */
async function startHttpOrExit(gateway: Awaited<ReturnType<typeof createGateway>>, cfg: SwitchboardConfig, path: string): Promise<DashboardHandle> {
  try {
    return await startDashboard(gateway, cfg, path);
  } catch (err) {
    log.error(err instanceof Error ? err.message : String(err));
    await gateway.shutdown().catch(() => {});
    process.exit(1);
  }
}

/** Check the HTTP port BEFORE mounting upstream servers, so a doomed start does not spawn them at all. */
async function requireFreeHttpPort(cfg: SwitchboardConfig): Promise<void> {
  try {
    await assertPortFree(cfg.gateway.http.host, cfg.gateway.http.port);
  } catch (err) {
    log.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  }
}

program
  .command("init")
  .description("create a starter config and home directory")
  .action(() => {
    const path = configPath();
    if (existsSync(path)) {
      log.warn(`config already exists at ${path} — leaving it untouched`);
      return;
    }
    ensureDir(HOME_DIR);
    writeConfig(path, starterConfig());
    log.ok(`wrote ${path}`);
    out(`Home: ${HOME_DIR}`);
    out(`Next: edit ${DEFAULT_CONFIG}, store secrets with \`switchboard vault set <name>\`, then \`switchboard serve\`.`);
  });

program
  .command("serve")
  .description("run the gateway (transports come from config)")
  .option("--client <id>", "serve this registered client on the stdio transport (needs the client's key, the same one `bridge` reads: a client whose keys were revoked is not served)")
  .action(async (opts: { client?: string }) => {
    const path = configPath();
    const cfg = bootConfig(path);
    const wantsHttp = cfg.gateway.transport.includes("http");
    let wantsStdio = cfg.gateway.transport.includes("stdio");

    // Who the stdio transport speaks to (design 3.1 and 3.15). The launching process names the client, and the
    // client's key must still be valid: an entry whose keys were revoked (`client rm`) or never issued is not served,
    // so revoking a client revokes it on stdio too. Recorded as via "stdio". Clients configured and no --client:
    // stdio is not served unidentified.
    let stdioPrincipal: Principal | undefined;
    if (opts.client !== undefined) {
      if (!isValidClientId(opts.client)) {
        log.error(BAD_CLIENT_ID);
        process.exit(1);
      }
      if (!Object.prototype.hasOwnProperty.call(cfg.clients ?? {}, opts.client)) {
        log.error(`client '${opts.client}' is not configured: run \`switchboard client add ${opts.client}\` first`);
        process.exit(1);
      }
      let keyOk = false;
      try {
        const stored = readClientKey(opts.client);
        keyOk = stored !== null && new ApiKeyStore().inspect(stored)?.client === opts.client;
      } catch {
        keyOk = false; // unreadable or foreign key file: not a working key
      }
      if (!keyOk) {
        log.error(`client '${opts.client}' has no working key, so stdio does not serve it (a key is revoked by \`client rm\`, replaced by \`client rotate\`): issue one with \`switchboard client add ${opts.client}\``);
        process.exit(1);
      }
      stdioPrincipal = { id: opts.client, client: opts.client, via: "stdio" };
    } else if (wantsStdio && Object.keys(cfg.clients ?? {}).length > 0) {
      if (!wantsHttp) {
        log.error("clients are configured, so the stdio transport needs --client <id> (or use `switchboard bridge --client <id>` against a running gateway)");
        process.exit(1);
      }
      log.warn("clients are configured: the stdio transport is not served without --client <id>; the HTTP endpoint continues");
      wantsStdio = false;
    }

    if (!wantsHttp) {
      log.warn("the HTTP listener is off (gateway.transport has no http): calls that need approval cannot be approved, because approvals are decided on the dashboard or with `switchboard approvals` against the running listener, and `switchboard kill off`, `switchboard dashboard login` and the client grants of `switchboard client` and `install` cannot reach this gateway for the same reason (`kill on` still works)");
    }
    if (wantsHttp) await requireFreeHttpPort(cfg);
    const gateway = await createGateway(cfg);

    if (wantsHttp) await startHttpOrExit(gateway, cfg, path);

    if (wantsStdio) {
      await gateway.serveStdio(stdioPrincipal); // resolves once connected; process stays alive on the transport
    } else if (!wantsHttp) {
      log.error("no transports enabled in config (gateway.transport) — nothing to do");
      process.exitCode = 1;
      await gateway.shutdown();
      return;
    }
    // If only http, the express listener keeps the event loop alive.
  });

const dashboardCmd = program
  .command("dashboard")
  .description("run only the HTTP endpoint + web console")
  .action(async () => {
    const path = configPath();
    const cfg = bootConfig(path);
    await requireFreeHttpPort(cfg);
    const gateway = await createGateway(cfg);
    const handle = await startHttpOrExit(gateway, cfg, path);
    out(`Open ${handle.url}  (sign in first: \`switchboard dashboard login\`)`);
  });

/** Open a URL in the default browser without a shell (no quoting hazards for the `#login=` fragment). */
function openInBrowser(url: string): void {
  const [cmd, args]: [string, string[]] =
    process.platform === "win32"
      ? ["rundll32", ["url.dll,FileProtocolHandler", url]]
      : process.platform === "darwin"
        ? ["open", [url]]
        : ["xdg-open", [url]];
  const child = spawn(cmd, args, { stdio: "ignore", detached: true, windowsHide: true });
  child.on("error", () => log.warn("could not open a browser; open the URL above by hand"));
  child.unref();
}

dashboardCmd
  .command("login")
  .description("sign in to the dashboard: the running gateway checks you are present (Windows Hello, or a challenge at its own console), then a one-time login code opens it")
  .option("--no-open", "print the login URL but do not open the browser")
  .action(
    approvalAction(async (opts: { open: boolean }) => {
      const cfg = loadConfig(configPath());
      out("asking the gateway to verify you are present (Windows Hello on this machine, or a challenge at the gateway's terminal)...");
      let r;
      try {
        r = await controlCall("POST", "/login", 150_000);
      } catch (err) {
        if (err instanceof CliFail && /no gateway answered|no control key/.test(err.message)) {
          throw new CliFail(`${err.message} The login code is minted inside the running gateway, after its own presence check, so there is nothing to sign in to until one runs: start it with \`switchboard dashboard\` or \`switchboard serve\`, then run this again.`);
        }
        throw err;
      }
      if (r.status !== 200 || typeof r.body.code !== "string") throw new CliFail(String(r.body.error ?? `the gateway answered ${r.status}`));
      const url = `http://127.0.0.1:${cfg.gateway.http.port}/#login=${r.body.code}`;
      log.ok(`login code minted (presence: ${String(r.body.presence)}); it works once and expires in ${String(r.body.expires_in)} seconds`);
      out("");
      out(`  ${url}`);
      out("");
      if (opts.open) openInBrowser(url);
    }),
  );

program
  .command("expose")
  .description("expose /mcp to the public internet through a tunnel (for ChatGPT / remote MCP clients)")
  .option("-t, --tunnel <kind>", `tunnel provider: ${TUNNEL_KINDS.join(" | ")}`, "cloudflared")
  .option("-p, --port <n>", "local port for the exposed /mcp listener (default: dashboard port + 1)")
  .option("--new-token", "mint a fresh API key for this session even if keys already exist", false)
  .action(async (opts: { tunnel: string; port?: string; newToken?: boolean }) => {
    if (!TUNNEL_KINDS.includes(opts.tunnel as TunnelKind)) {
      log.error(`unknown tunnel '${opts.tunnel}' — choose one of: ${TUNNEL_KINDS.join(", ")}`);
      process.exitCode = 1;
      return;
    }
    const tunnel = opts.tunnel as TunnelKind;
    const cfg = bootConfig(configPath());
    const port = opts.port ? Number(opts.port) : cfg.gateway.http.port + 1;
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      log.error(`invalid --port '${opts.port}' — expected an integer 1–65535`);
      process.exitCode = 1;
      return;
    }

    // A busy port is checked before any key is minted or upstream mounted (fail loudly, exit non-zero).
    try {
      await assertPortFree("127.0.0.1", port);
    } catch (err) {
      log.error(err instanceof Error ? err.message : String(err));
      process.exitCode = 1;
      return;
    }

    // Refuse to expose without auth: ensure at least one key exists. Mint+print one if the
    // store is empty (or the operator asked for a fresh one); otherwise reuse what's there.
    const apiKeys = new ApiKeyStore();
    let issuedToken: string | null = null;
    if (Object.keys(cfg.clients ?? {}).length > 0) {
      // With clients configured an unbound key is refused on /mcp, so minting one would hand out a dead credential.
      log.info("clients are configured: connect with a client key (`switchboard client add <id>`, or `switchboard client rotate <id> --print`)");
    } else if (opts.newToken || apiKeys.count === 0) {
      issuedToken = apiKeys.issue("expose").token;
    }

    const gateway = await createGateway(cfg);
    // Pinned (design 3.15): this process has no control API to ask, so a client changed in the file waits for a restart.
    const clientWatcher = new ClientConfigWatcher(cfg, configPath(), { pinned: true });
    try {
      await runExpose(gateway, cfg, apiKeys, {
        tunnel,
        port,
        issuedToken,
        clients: () => {
          clientWatcher.sync();
          return cfg.clients;
        },
      });
    } catch (err) {
      // A busy port or a tunnel that never came up: say why, stop the upstream children, exit non-zero.
      log.error(err instanceof Error ? err.message : String(err));
      await gateway.shutdown().catch(() => {});
      process.exit(1);
    }
  });

program
  .command("list")
  .description("mount every server and print the governed tool list, then exit")
  .action(async () => {
    const cfg = bootConfig(configPath());
    const gateway = await createGateway(cfg);
    const tools = gateway.router.listTools();
    out(`\n${tools.length} tools exposed:\n`);
    for (const t of tools) {
      const scope = inferScope(t.name.split("__").pop() ?? t.name, t.annotations);
      out(`  ${safeText(t.name, 42).padEnd(42)} [${scope}]  ${safeText(t.description?.split("\n")[0], 160)}`);
    }
    await gateway.shutdown();
  });

program
  .command("doctor")
  .description("check the environment, config, and credentials")
  .action(() => {
    const path = configPath();
    out(`MCP Switchboard doctor`);
    out(`  node:        ${process.version}`);
    out(`  home:        ${HOME_DIR}`);
    out(`  config:      ${path} ${existsSync(path) ? "(found)" : "(missing — run `switchboard init`)"}`);
    if (!existsSync(path)) return;

    let cfg: SwitchboardConfig;
    try {
      cfg = loadConfig(path);
    } catch (err) {
      log.error(err instanceof Error ? err.message : String(err));
      process.exitCode = 1;
      return;
    }

    const vault = new Vault(cfg.vault.backend);
    const oauthClientIds = new Set(new OAuthStore(vault).catalog().filter((p) => p.hasClientId).map((p) => p.id));
    const report = buildDoctorReport({ cfg, resolve: (v) => vault.resolve(v), oauthClientIds });

    if (!report.node.ok) log.warn(`  node ${report.node.version} is below the supported floor ${report.node.floor}`);
    out(`  vault:       ${report.vaultBackend}`);
    out(`  transports:  ${report.transports.join(", ")}`);
    out(`  endpoint:    ${report.endpoint}`);
    out(`\n  servers (${report.servers.length}):`);
    for (const s of report.servers) {
      const flags = [s.enabled ? "" : "(disabled)", s.duplicateId ? "(DUPLICATE ID)" : ""].filter(Boolean).join(" ");
      out(`    - ${s.id} [${s.source}, ${s.policy}] ${flags}`);
      for (const msg of s.unresolved) log.error(`      unresolved: ${msg}`);
      for (const provider of s.oauthUnconfigured) log.warn(`      oauth '${provider}' has no client id — run \`switchboard connect ${provider}\``);
      for (const trap of s.policyTraps) log.warn(`      '${trap.tool}' -> ${trap.reason}`);
    }

    out("");
    for (const w of report.warnings) log.warn(`WARNING: ${w}`);
    if (report.ok) log.ok(report.warnings.length === 0 ? "config looks healthy" : `config is valid, but ${report.warnings.length} warning(s) above should be fixed`);
    else log.error(`${report.problems.length} issue(s) found (see above)`);
    process.exitCode = report.ok ? 0 : 1;
  });

program
  .command("catalog")
  .description("list OAuth providers and their connection status")
  .action(() => {
    const cfg = loadConfig(configPath());
    const oauth = new OAuthStore(new Vault(cfg.vault.backend));
    out(`\nOAuth providers:\n`);
    for (const p of oauth.catalog()) {
      const status = p.connected ? (p.expired ? "expired" : "connected") : p.connectable ? "ready" : "needs client id";
      out(`  ${p.label.padEnd(12)} [${status}]  ${(p.scopes ?? []).join(", ")}`);
      if (p.note) out(`               ${p.note}`);
    }
    out(`\nStore client credentials first: \`switchboard vault set oauth_<provider>_client_id\` (and _client_secret).`);
    out(`Then connect: \`switchboard connect <provider>\`.`);
  });

const toolkitsCmd = program
  .command("toolkits")
  .description("manage the browsable integration catalog (the dashboard's toolkit grid)");

toolkitsCmd
  .command("sync")
  .description("rebuild data/catalog.json from the open MCP Registry + APIs.guru indexes")
  .action(async () => {
    out("Syncing catalog from the MCP Registry and APIs.guru…");
    const { snapshot, errors, enrichment } = await ingestCatalogVerbose(networkFromConfig());
    snapshot.generated_at = new Date().toISOString();
    const path = defaultCatalogPath();
    writeCatalog(snapshot, path);
    log.ok(
      `wrote ${snapshot.counts.total} toolkits (${snapshot.counts.mcp_registry} MCP, ${snapshot.counts.apis_guru} OpenAPI) to ${path}`,
    );
    if (enrichment.taxonomy_entries > 0) {
      log.ok(
        `awesome-mcp taxonomy: ${enrichment.taxonomy_entries} categorized repos → ${enrichment.reclassified} registry servers reclassified`,
      );
    } else {
      log.warn("awesome-mcp taxonomy unavailable — categories fell back to the keyword heuristic");
    }
    for (const e of errors) log.warn(`partial: ${e.source} failed — ${e.message}`);
  });

toolkitsCmd
  .command("stats")
  .description("print counts from the on-disk catalog snapshot")
  .action(() => {
    const c = loadCatalog();
    if (c.counts.total === 0) {
      out("catalog is empty — run `switchboard toolkits sync`");
      return;
    }
    out(`\nCatalog (${c.generated_at || "unstamped"}):`);
    out(`  total:        ${c.counts.total}`);
    out(`  MCP servers:  ${c.counts.mcp_registry}`);
    out(`  OpenAPI:      ${c.counts.apis_guru}`);
    out(`\n  ${c.categories.length} categories:`);
    for (const cat of c.categories) out(`    ${cat.name.padEnd(22)} ${cat.count}`);
  });

toolkitsCmd
  .command("discover <query...>")
  .description("live-search awesome-mcp-servers for MCP servers NOT in our snapshot (never persisted)")
  .option("-n, --limit <n>", "max results", "20")
  .action(async (query: string[], opts: { limit: string }) => {
    const q = query.join(" ");
    out(`Searching awesome-mcp-servers live for "${q}" (discovery only — nothing is written)…`);
    let results;
    try {
      results = await discoverToolkits(q, { limit: Number(opts.limit) || 20, network: networkFromConfig() });
    } catch (err) {
      log.error(`discovery failed: ${err instanceof Error ? err.message : String(err)}`);
      process.exitCode = 1;
      return;
    }
    if (results.length === 0) {
      out("no new servers found (all matches are already in the snapshot, or no match)");
      return;
    }
    out(`\n${results.length} discovery result(s) — vet before mounting, none are auto-installed:`);
    for (const r of results) {
      out(`  • ${safeText(r.name, 80)}  [${safeText(r.category, 40)}]`);
      out(`    ${safeText(r.repository, 200)}`);
      if (r.description) out(`    ${safeText(r.description, 300)}`);
    }
  });

toolkitsCmd
  .command("recategorize")
  .description("re-apply the awesome-mcp category taxonomy to the existing catalog (no full re-fetch)")
  .action(async () => {
    const path = defaultCatalogPath();
    const c = loadCatalog(path);
    if (c.counts.total === 0) {
      out("catalog is empty — run `switchboard toolkits sync` first");
      return;
    }
    out("Fetching the awesome-mcp-servers category taxonomy (categories only — no server lists)…");
    let taxonomy: Map<string, string>;
    try {
      taxonomy = await fetchAwesomeTaxonomy(networkFromConfig());
    } catch (err) {
      log.error(`taxonomy fetch failed: ${err instanceof Error ? err.message : String(err)}`);
      process.exitCode = 1;
      return;
    }
    if (taxonomy.size === 0) {
      log.error("taxonomy fetch returned no categories — catalog left unchanged");
      process.exitCode = 1;
      return;
    }
    const { matched, changed } = applyTaxonomyToSnapshot(c, taxonomy);
    c.generated_at = new Date().toISOString();
    writeCatalog(c, path);
    log.ok(
      `awesome-mcp taxonomy: ${taxonomy.size} categorized repos → ${matched} catalog entries matched, ${changed} recategorized (${path})`,
    );
  });

program
  .command("connect <provider>")
  .description("authorize an OAuth provider via the local loopback flow")
  .action(async (provider: string) => {
    const cfg = loadConfig(configPath());
    const oauth = new OAuthStore(new Vault(cfg.vault.backend), () => cfg.settings?.network);
    const { host, port } = cfg.gateway.http;
    const redirectUri = `http://${host}:${port}/oauth/callback`;

    let authorizeUrl: string;
    try {
      ({ authorizeUrl } = oauth.beginAuth(provider, redirectUri));
    } catch (err) {
      log.error(err instanceof Error ? err.message : String(err));
      process.exitCode = 1;
      return;
    }

    // Spin up a one-shot loopback listener to catch the provider's redirect, complete the
    // exchange, then shut down. Tokens are sealed by OAuthStore — nothing is printed.
    await new Promise<void>((done) => {
      const server = createServer(async (req, res) => {
        const url = new URL(req.url ?? "/", `http://${host}:${port}`);
        if (url.pathname !== "/oauth/callback") {
          res.writeHead(404).end("not found");
          return;
        }
        const state = url.searchParams.get("state") ?? "";
        const code = url.searchParams.get("code") ?? "";
        const error = url.searchParams.get("error") ?? "";
        try {
          if (error) throw new Error(`provider returned: ${error}`);
          if (!state || !code) throw new Error("missing 'state' or 'code' in callback");
          const token = await oauth.completeAuth(state, code);
          res.writeHead(200, { "content-type": "text/html" }).end("<h1>Connected — you can close this tab.</h1>");
          log.ok(`connected '${token.provider}'`);
        } catch (err) {
          res.writeHead(400, { "content-type": "text/html" }).end("<h1>Authorization failed.</h1>");
          log.error(err instanceof Error ? err.message : String(err));
          process.exitCode = 1;
        } finally {
          server.close(() => done());
        }
      });
      server.on("error", (err) => {
        const msg = (err as NodeJS.ErrnoException).code === "EADDRINUSE"
          ? `port ${port} is busy — stop \`switchboard serve\` and retry, or use the dashboard's Connect button`
          : err.message;
        log.error(msg);
        process.exitCode = 1;
        done();
      });
      server.listen(port, host, () => {
        out(`\nOpen this URL in your browser to authorize:\n\n  ${authorizeUrl}\n\nWaiting for the callback…`);
      });
    });
  });

/** Shared body of `install` and `uninstall`: validate the flags, load the config, run, set the exit code. */
async function installAction(
  client: string,
  opts: { mode?: string; scope?: string; global?: boolean; dir?: string; name: string; dshProfile: string; yes?: boolean; dryRun?: boolean; print?: boolean },
  uninstall: boolean,
): Promise<void> {
  try {
    if (!SUPPORTED_CLIENTS.includes(client as ClientId)) {
      log.error(`unknown client '${client}'. Supported: ${SUPPORTED_CLIENTS.join(", ")}`);
      process.exitCode = 1;
      return;
    }
    const mode = opts.mode ?? "bridge";
    if (mode !== "bridge" && mode !== "http") throw new Error("--mode must be bridge or http");
    if (opts.scope !== undefined && opts.scope !== "user" && opts.scope !== "project") throw new Error("--scope must be user or project");
    if (opts.global && opts.scope === "project") throw new Error("--global means --scope user; it conflicts with --scope project");
    const scope: "user" | "project" = opts.scope === "project" ? "project" : "user";
    const cfgPath = configPath();
    const cfg = loadConfig(cfgPath);
    const common = {
      client: client as ClientId,
      scope,
      name: opts.name,
      dir: resolve(opts.dir ?? process.cwd()),
      dshProfile: opts.dshProfile,
      yes: opts.yes === true,
      dryRun: opts.dryRun === true || opts.print === true,
      cfg,
      cfgPath,
    };
    // import.meta.url is dist/cli.js at runtime: exactly what a bridge entry must run.
    const result = uninstall ? await runUninstall(common) : await runInstall({ ...common, mode, nodePath: process.execPath, cliPath: fileURLToPath(import.meta.url) });
    process.exitCode = result.exitCode;
  } catch (err) {
    log.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
  }
}

program
  .command("install <client>")
  .description(`register MCP Switchboard in an MCP client: preview, back up, write, probe, roll back on failure (${SUPPORTED_CLIENTS.join(", ")})`)
  .option("--mode <mode>", "bridge (default: the client starts `switchboard bridge`, which authenticates as that client) or http (the client dials the gateway URL)", "bridge")
  .option("--scope <scope>", "user (default) or project (<dir>/.mcp.json, .cursor, .vscode, .codex, .gemini)")
  .option("--yes", "do not ask for confirmation")
  .option("--dry-run", "show the plan and change nothing (no file, no client, no command that writes)")
  .option("--dsh-profile <name>", "dsh profile whose cordis.patch.yml is edited", "web")
  .option("--dir <path>", "project directory for --scope project (default: cwd)")
  .option("--name <name>", "server name to register under", "switchboard")
  .option("--global", "same as --scope user (kept for older scripts)")
  .option("--print", "same as --dry-run (kept for older scripts)")
  .action((client: string, opts) => installAction(client, opts, false));

program
  .command("uninstall <client>")
  .description("remove only the MCP Switchboard entry from an MCP client (a backup is taken first); the Switchboard client and its key are kept")
  .option("--scope <scope>", "user (default) or project", undefined)
  .option("--yes", "do not ask for confirmation")
  .option("--dry-run", "show what would be removed and change nothing")
  .option("--dsh-profile <name>", "dsh profile whose cordis.patch.yml is edited", "web")
  .option("--dir <path>", "project directory for --scope project (default: cwd)")
  .option("--name <name>", "server name the entry is registered under", "switchboard")
  .option("--global", "same as --scope user (kept for older scripts)")
  .action((client: string, opts) => installAction(client, opts, true));

program
  .command("bridge")
  .description("relay a client's stdio (JSON-RPC lines) to the shared HTTP gateway, authenticating as that client")
  .requiredOption("--client <id>", "the registered client this bridge speaks for (its key is read from the client key store)")
  .option("--url <url>", "the gateway's /mcp endpoint", DEFAULT_BRIDGE_URL)
  .option("--key-file <path>", "read the bearer token from a plain-text file (used after SWITCHBOARD_KEY, before the key store)")
  .action(async (opts: { client: string; url: string; keyFile?: string }) => {
    // stdout is the JSON-RPC channel: runBridge writes nothing else there, and flushes it before returning.
    process.exit(await runBridge({ clientId: opts.client, url: opts.url, keyFile: opts.keyFile }));
  });

const llmCmd = program
  .command("local-llm")
  .description("detect a local OpenAI-compatible LLM server (Ollama/LM Studio/llama.cpp/vLLM) for the offline council")
  .action(async () => {
    out("\nProbing localhost for OpenAI-compatible model servers…");
    const results = await probeAll(undefined, undefined, networkFromConfig());
    const live = results.filter((r) => r.reachable);
    if (live.length === 0) {
      log.warn("no local model server reachable on the usual ports.");
      out("\nRun a model locally — MCP Switchboard never downloads or runs anything for you, so copy/paste these:\n");
      for (const step of installGuide()) out(`  • ${step}`);
      return;
    }
    out("");
    for (const r of live) {
      const n = r.models.length;
      out(`  ${safeText(r.runtime.label, 26).padEnd(26)} ${safeText(r.runtime.baseUrl, 120)}  (${n} model${n === 1 ? "" : "s"})`);
      for (const m of r.models.slice(0, 8)) out(`      - ${safeText(m, 80)}`);
      if (r.models.length > 8) out(`      … and ${r.models.length - 8} more`);
    }
    out("\nWire one into the council: `switchboard local-llm wire` (uses the first reachable server + a sensible model).");
  });

llmCmd
  .command("wire")
  .description("write the detected local server into settings.council.providers.local")
  .option("--runtime <id>", `which runtime to wire (${KNOWN_RUNTIMES.map((r) => r.id).join(", ")})`)
  .option("--base-url <url>", "override the OpenAI-compatible base URL (skips probing)")
  .option("--model <id>", "force a specific model id")
  .option("--print", "print the resulting provider block without writing it")
  .action(
    async (opts: { runtime?: string; baseUrl?: string; model?: string; print?: boolean }) => {
      const cfgPath = configPath();
      const cfg = loadConfig(cfgPath);

      let baseUrl: string;
      let model: string | undefined = opts.model;

      if (opts.baseUrl) {
        baseUrl = opts.baseUrl;
        if (!model) {
          const trimmed = opts.baseUrl.replace(/\/$/, "");
          const probe = await probeRuntime({ id: "custom", label: "custom", baseUrl: trimmed, modelsUrl: `${trimmed}/models` }, undefined, cfg.settings?.network);
          model = pickDefaultModel(probe.models);
        }
      } else {
        const results = await probeAll(undefined, undefined, cfg.settings?.network);
        const live = results.filter((r) => r.reachable && r.models.length > 0);
        const chosen = opts.runtime ? live.find((r) => r.runtime.id === opts.runtime) : live[0];
        if (!chosen) {
          log.error(
            opts.runtime
              ? `runtime '${opts.runtime}' is not reachable with a loaded model.`
              : "no local model server with a loaded model was reachable.",
          );
          out("Run `switchboard local-llm` for setup steps, or pass --base-url to wire one manually.");
          process.exitCode = 1;
          return;
        }
        baseUrl = chosen.runtime.baseUrl;
        if (!model) model = pickDefaultModel(chosen.models);
      }

      if (!model) {
        log.error("no model id available — load a model first (e.g. `ollama pull llama3.1`) or pass --model.");
        process.exitCode = 1;
        return;
      }

      const provider = buildLocalProvider(baseUrl, model);
      const result = withLocalProvider(cfg, provider);
      // The SSRF guard refuses loopback and LAN targets unless the exact host is allowlisted, so wire it too.
      const allowance = await withLocalAllowance(result.config, baseUrl);
      if (allowance.changed) {
        result.config = allowance.config;
        result.changed = true;
      }
      const advice = wireAdvice(result, model);
      if (allowance.host) advice.push(`added '${allowance.host}' to settings.network.allow_private (the outbound network guard refuses local hosts otherwise).`);

      if (opts.print) {
        out("\n# settings.council.providers.local\n");
        out(JSON.stringify(provider, null, 2));
        for (const line of advice) out(`\nnote: ${line}`);
        return;
      }
      if (!result.changed) {
        log.ok(`council already wired to ${baseUrl} (${model}) — no change`);
      } else {
        writeConfig(cfgPath, result.config);
        log.ok(`wired local council provider → ${baseUrl} (model: ${model})`);
      }
      for (const line of advice) out(`  → ${line}`);
    },
  );

/** Is the gateway on this config's port refusing calls? true or false from its own /healthz, null when nothing answers. */
async function gatewayKillState(cfg: SwitchboardConfig | undefined): Promise<boolean | null> {
  if (!cfg) return null;
  try {
    const res = await guardedFetch(`http://127.0.0.1:${cfg.gateway.http.port}/healthz`, { timeoutMs: 1500, allowLoopback: true });
    const body = (await res.json()) as { service?: unknown; kill_switch?: unknown };
    return body.service === "switchboard" ? body.kill_switch === true : null;
  } catch {
    return null;
  }
}

program
  .command("kill <action>")
  .description("kill switch: refuse every tool call, resource read and prompt get until cleared (on | off | status). Turning it off needs the running gateway to verify you are present")
  .action(
    approvalAction(async (action: string) => {
      if (action !== "on" && action !== "off" && action !== "status") {
        log.error(`unknown action '${action}': use 'switchboard kill on', 'off' or 'status'`);
        process.exitCode = 1;
        return;
      }
      // The config is optional here: the file switch must work even when the config is missing or broken.
      let cfg: SwitchboardConfig | undefined;
      try {
        cfg = loadConfig(configPath());
      } catch {
        cfg = undefined;
      }
      // This process is not the gateway: it looks at the file and the config only (passive), and asks the gateway what
      // IT is doing, because a gateway that has seen the switch on keeps refusing even when the file is gone (design 3.15).
      const report = async () => {
        const st = killStatus(cfg, undefined, { passive: true });
        const gw = await gatewayKillState(cfg);
        const on = st.active || gw === true;
        out(`kill switch: ${on ? "ON" : "OFF"}`);
        out(`  file:   ${killFilePath()} (${st.file ? `present${st.since ? `, since ${st.since}` : ""}` : "absent"})`);
        out(`  config: gateway.kill_switch is ${st.config ? "true" : cfg ? "not set" : "unknown (no readable config)"}`);
        if (gw !== null) {
          out(`  gateway: ${gw ? "refusing every call" : "answering calls"}${gw && !st.file && !st.config ? " (latched in its memory although the KILL file is gone: deleting the file is not a way to turn it off)" : ""}`);
        }
        return { ...st, active: on, gateway: gw };
      };
      const configStillHolds = () => {
        log.error("the KILL file is cleared but gateway.kill_switch is still true in the config: set it to false and restart the gateway");
        process.exitCode = 1;
      };
      if (action === "status") {
        await report();
        return;
      }
      if (action === "on") {
        const wasOn = killStatus(cfg, undefined, { passive: true }).file;
        // A running gateway writes the file AND latches the switch in its own memory in one step, so a delete of the
        // file right afterwards cannot beat it. No gateway, or any failure to ask: the file alone still stops it.
        let viaGateway = false;
        if (cfg) {
          try {
            const g = await askGateway(cfg.gateway.http.port, "POST", "/kill/on", 10_000);
            viaGateway = g !== null && g.status === 200;
          } catch {
            viaGateway = false;
          }
        }
        if (!viaGateway) setKillFile(true);
        log.warn(wasOn ? "kill switch was already on" : "kill switch ON: every tool call, resource read and prompt get is now refused");
        out(
          viaGateway
            ? "the running gateway has latched it in its own memory too: deleting the KILL file does not turn it off. Clear it with 'switchboard kill off' (the gateway asks you to prove you are present)."
            : "a running gateway sees the file on its next call and latches it in memory from then on; no restart needed. Clear it with 'switchboard kill off' (the gateway asks you to prove you are present).",
        );
        await report();
        return;
      }
      // OFF re-opens every tool, so it is the one direction that needs the owner present. The CLI cannot show a trusted
      // prompt itself (anything that can run this command could run a copy of it that skipped the prompt), so it asks the
      // RUNNING gateway, which performs the presence check (Windows Hello, or a challenge at its own console) and clears
      // the file and its own latch. With nothing to clear (no file, and no gateway refusing) there is nothing to protect,
      // so that case needs no gateway.
      const before = killStatus(cfg, undefined, { passive: true });
      const gateway = await gatewayKillState(cfg);
      if (!before.file && gateway !== true) {
        const st = await report();
        if (st.active) configStillHolds();
        else log.ok("kill switch was already off");
        return;
      }
      out("asking the gateway to verify you are present (Windows Hello on this machine, or a challenge at the gateway's terminal)...");
      let r;
      try {
        r = await controlCall("POST", "/kill/off", 150_000);
      } catch (err) {
        if (err instanceof CliFail && /no gateway answered|no control key/.test(err.message)) {
          throw new CliFail(
            `${err.message} The kill switch stays ON: clearing it needs the running gateway to check owner presence (Windows Hello), and no gateway is reachable. Start one (\`switchboard dashboard\` or \`switchboard serve\`; it refuses every call while the KILL file exists), then run \`switchboard kill off\` again.`,
          );
        }
        throw err;
      }
      if (r.status !== 200) throw new CliFail(String(r.body.error ?? `the gateway answered ${r.status}`));
      const st = await report();
      if (st.active) configStillHolds();
      else log.ok("kill switch OFF: calls are allowed again");
    }),
  );

// ── approvals (design 3.3) ───────────────────────────────────────────────────────────────────────

const approvalsCmd = program
  .command("approvals")
  .description("decide the calls that wait for the owner: list, show, approve, deny (talks to the running gateway)");

/** An error the user should read as one line, with its exit code. */
class CliFail extends Error {}

/**
 * Call the RUNNING gateway's control API. The CLI never decides anything itself: `approve` makes the gateway ask
 * for owner presence (Windows Hello, or a challenge at the gateway's own console) and sign the decision. The
 * control token that authenticates this call is a convenience, not the security boundary: anything that runs as
 * this OS user can read it, so the presence prompt inside the gateway is the real gate (controlclient.ts).
 */
async function controlCall(
  method: "GET" | "POST",
  path: string,
  timeoutMs: number,
  body?: unknown,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const cfg = loadConfig(configPath());
  try {
    return await controlRequest(cfg.gateway.http.port, method, path, timeoutMs, body);
  } catch (err) {
    if (err instanceof ControlError) throw new CliFail(err.message);
    throw err;
  }
}

function checkApprovalId(id: string): void {
  if (!APPROVAL_ID_RE.test(id)) throw new CliFail(`'${id}' is not an approval id (they look like ap_7KQ2M9XD)`);
}

function until(iso: string): string {
  const ms = Date.parse(iso) - Date.now();
  if (!Number.isFinite(ms)) return iso;
  if (ms <= 0) return "expired";
  const s = Math.round(ms / 1000);
  return s < 90 ? `${s}s` : s < 5400 ? `${Math.round(s / 60)}m` : `${Math.round(s / 3600)}h`;
}

function approvalLine(a: ApprovalView): string {
  const who = a.client ?? a.principal;
  const state = a.status === "pending" || a.status === "approved" ? `${a.status}, ${until(a.expires)} left` : a.status;
  return `  ${a.id}  ${a.risk.padEnd(6)} ${a.server}__${a.tool}  ${who}  [${state}]  ${summarizeArgs(a.args_preview, 70)}`;
}

function approvalAction<A extends unknown[]>(fn: (...args: A) => Promise<void>): (...args: A) => Promise<void> {
  return async (...args: A) => {
    try {
      await fn(...args);
    } catch (err) {
      log.error(err instanceof CliFail || err instanceof Error ? err.message : String(err));
      process.exitCode = 1;
    }
  };
}

approvalsCmd
  .command("list")
  .description("list the calls waiting for the owner, and the latest decisions")
  .option("--all", "also show the finished ones (approved and used, denied, expired)")
  .action(
    approvalAction(async (opts: { all?: boolean }) => {
      let data: { pending?: ApprovalView[]; approved?: ApprovalView[]; history?: ApprovalView[] };
      try {
        const r = await controlCall("GET", "/approvals", 15_000);
        if (r.status !== 200) throw new CliFail(String(r.body.error ?? `the gateway answered ${r.status}`));
        data = r.body as typeof data;
      } catch (err) {
        if (!(err instanceof CliFail) || !/no gateway answered|no control key/.test(err.message)) throw err;
        // The gateway is not running. The file is all there is, and nothing in it is verified: say so.
        log.warn(`${err.message}`);
        log.warn(`showing the raw ${APPROVALS_FILE} instead. These records are NOT verified (only a running gateway can tell a real one from a forged one), and nothing can be approved until a gateway runs.`);
        const raw = readJsonFileSync<{ approvals?: ApprovalView[] }>(resolve(HOME_DIR, APPROVALS_FILE))?.approvals ?? [];
        data = { pending: raw.filter((a) => a.status === "pending"), approved: [], history: raw.filter((a) => a.status !== "pending") };
      }
      const pending = data.pending ?? [];
      const approved = data.approved ?? [];
      out(pending.length === 0 ? "no calls are waiting for the owner" : `${pending.length} waiting for the owner:`);
      for (const a of pending) out(approvalLine(a));
      if (approved.length > 0) {
        out(`${approved.length} approved, not used yet:`);
        for (const a of approved) out(approvalLine(a));
      }
      if (opts.all) {
        out(`${(data.history ?? []).length} finished:`);
        for (const a of data.history ?? []) out(approvalLine(a));
      }
      if (pending.length > 0) out("\n  decide with: switchboard approvals approve <id>   |   switchboard approvals deny <id>");
    }),
  );

approvalsCmd
  .command("show <id>")
  .description("show one approval request in full")
  .action(
    approvalAction(async (id: string) => {
      checkApprovalId(id);
      const r = await controlCall("GET", `/approvals/${id}`, 15_000);
      if (r.status !== 200) throw new CliFail(String(r.body.error ?? `the gateway answered ${r.status}`));
      const a = r.body.approval as ApprovalView;
      out(`${a.id}  ${a.status}`);
      out(`  call:      ${a.server}__${a.tool}  (${a.scope} scope, ${a.risk} risk)`);
      out(`  caller:    ${a.principal}${a.client ? `  client ${a.client}` : ""}`);
      out(`  why:       ${a.reason}`);
      out(`  created:   ${a.created}`);
      out(`  expires:   ${a.expires}  (${until(a.expires)})`);
      out(`  decided:   ${a.decided_via ? `${a.decided_via} at ${a.decided_at}${a.presence ? `, presence ${a.presence}` : ""}` : "not yet"}`);
      out(`  args hash: ${a.args_sha256}`);
      out(`  arguments: ${JSON.stringify(a.args_preview, null, 2).replace(/\n/g, "\n             ")}`);
    }),
  );

approvalsCmd
  .command("approve <id>")
  .description("approve one request: the gateway asks for your presence (Windows Hello), then the client may repeat the identical call once")
  .action(
    approvalAction(async (id: string) => {
      checkApprovalId(id);
      out("asking the gateway to verify you are present (Windows Hello on this machine, or a challenge at the gateway's terminal)...");
      const r = await controlCall("POST", `/approvals/${id}/approve`, 150_000);
      if (r.status !== 200) throw new CliFail(String(r.body.error ?? `the gateway answered ${r.status}`));
      const a = r.body.approval as ApprovalView;
      log.ok(`approved ${a.id}: ${a.server}__${a.tool} for ${a.client ?? a.principal}`);
      out(`  valid for ${until(a.expires)}, one use. The client must now repeat the same call with the same arguments.`);
    }),
  );

approvalsCmd
  .command("deny <id>")
  .description("deny one request (no presence check is needed to say no)")
  .action(
    approvalAction(async (id: string) => {
      checkApprovalId(id);
      const r = await controlCall("POST", `/approvals/${id}/deny`, 15_000);
      if (r.status !== 200) throw new CliFail(String(r.body.error ?? `the gateway answered ${r.status}`));
      const a = r.body.approval as ApprovalView;
      log.ok(`denied ${a.id}: ${a.server}__${a.tool} for ${a.client ?? a.principal}`);
    }),
  );

const auditCmd = program.command("audit").description("inspect the tamper-evident audit log");

auditCmd
  .command("verify")
  .description("walk the audit log's hash chain and report the first break (exit 1 on a break); --all includes rotated segments")
  .option("--all", "verify every rotated segment too, not only the current audit.log")
  .action((opts: { all?: boolean }) => {
    let res;
    try {
      res = verifyAudit({ all: opts.all === true });
    } catch (err) {
      log.error(`could not read the audit log: ${err instanceof Error ? err.message : String(err)}`);
      process.exitCode = 1;
      return;
    }
    for (const n of res.notes) log.warn(n);
    if (res.ok) {
      if (res.rows === 0 && res.legacy_rows === 0) {
        out(`audit chain: no rows to verify (${res.files.length ? res.files.join(", ") : "no audit.log"})`);
        return;
      }
      out(`audit chain OK: ${res.rows} row(s)${res.rows ? `, seq ${res.first_seq}..${res.last_seq}` : ""} in ${res.files.join(", ")}`);
      if (res.last_hash) out(`  last hash: ${res.last_hash}`);
      return;
    }
    const b = res.break!;
    log.error(`audit chain BROKEN at seq ${b.seq} (${b.file}, line ${b.line}): ${b.reason}`);
    out(`audit chain BROKEN at seq ${b.seq}`);
    out(`  file:   ${b.file} line ${b.line}`);
    out(`  reason: ${b.reason}`);
    out(`  ${res.rows} row(s) before the break verified`);
    process.exitCode = 1;
  });

const profileCmd = program
  .command("profile")
  .description("manage named, switchable views over your servers/tools (visibility + optional scope cap)");

profileCmd
  .command("list")
  .description("list defined profiles and show which one is active")
  .action(() => {
    const cfg = loadConfig(configPath());
    const profiles = cfg.settings?.profiles ?? {};
    const names = Object.keys(profiles);
    if (!names.length) {
      out("no profiles defined — add them under settings.profiles in your config.");
      out("a profile can only HIDE servers/tools and LOWER scope, never reveal a disabled tool.");
      return;
    }
    const fileActive = cfg.settings?.active_profile;
    const { active: effective, note } = applyProfileEnvOverride(cfg);
    out("");
    for (const name of names) {
      const mark = name === effective ? "● " : "  ";
      out(`${mark}${describeProfile(name, profiles[name]!)}`);
    }
    out("");
    if (effective) out(`active: ${effective}${effective !== fileActive ? " (via SWITCHBOARD_PROFILE)" : ""}`);
    else out("active: none (every enabled tool is exposed)");
    if (note) log.warn(note);
  });

profileCmd
  .command("show <name>")
  .description("print a profile's effect and its raw definition")
  .action((name: string) => {
    const cfg = loadConfig(configPath());
    const profile = cfg.settings?.profiles?.[name];
    if (!profile) {
      const defined = Object.keys(cfg.settings?.profiles ?? {});
      log.error(`no profile named '${name}'${defined.length ? ` (defined: ${defined.join(", ")})` : " (none defined)"}`);
      process.exitCode = 1;
      return;
    }
    out(`\n${describeProfile(name, profile)}\n`);
    out(JSON.stringify(profile, null, 2));
  });

profileCmd
  .command("use <name>")
  .description("activate a profile (writes settings.active_profile)")
  .action((name: string) => {
    const cfgPath = configPath();
    const cfg = loadConfig(cfgPath);
    let next: SwitchboardConfig;
    try {
      next = withActiveProfile(cfg, name);
    } catch (err) {
      log.error(err instanceof Error ? err.message : String(err));
      process.exitCode = 1;
      return;
    }
    writeConfig(cfgPath, next);
    log.ok(`active profile → '${name}'`);
    out(`  ${describeProfile(name, cfg.settings!.profiles![name]!)}`);
    out("  restart `switchboard serve` for it to take effect.");
  });

profileCmd
  .command("clear")
  .description("deactivate any profile (expose every enabled tool again)")
  .action(() => {
    const cfgPath = configPath();
    const cfg = loadConfig(cfgPath);
    if (!cfg.settings?.active_profile) {
      log.ok("no active profile — nothing to clear");
      return;
    }
    writeConfig(cfgPath, withActiveProfile(cfg, undefined));
    log.ok("active profile cleared — every enabled tool is exposed");
  });

const vaultCmd = program.command("vault").description("manage locally-stored secrets");

vaultCmd
  .command("set <name>")
  .description("store a secret (value read from stdin; pipe it to keep it out of shell history)")
  .action(async (name: string) => {
    const cfg = loadConfig(configPath());
    const vault = new Vault(cfg.vault.backend);
    const value = await readSecret(`Enter value for '${name}': `);
    if (!value) {
      log.error("empty value — nothing stored");
      process.exitCode = 1;
      return;
    }
    vault.set(name, value);
    log.ok(`stored '${name}' (${vault.list().length} secrets total)`);
  });

vaultCmd
  .command("list")
  .description("list secret names (never values)")
  .action(() => {
    const cfg = loadConfig(configPath());
    const names = new Vault(cfg.vault.backend).list();
    if (!names.length) out("no secrets stored");
    else names.forEach((n) => out(`  ${n}`));
  });

vaultCmd
  .command("rm <name>")
  .description("remove a secret")
  .action((name: string) => {
    const cfg = loadConfig(configPath());
    const vault = new Vault(cfg.vault.backend);
    vault.remove(name);
    log.ok(`removed '${name}'`);
  });

const apikeyCmd = program
  .command("apikey")
  .description("manage API keys that authenticate the HTTP /mcp endpoint (for ChatGPT, remote clients, tunnels)");

apikeyCmd
  .command("new <name>")
  .description("issue a new API key — the token is shown once and stored only as a one-way hash")
  .option("--client <id>", "bind the key to a registered client (every key must be bound once clients are configured; prefer `switchboard client add`)")
  .action((name: string, opts: { client?: string }) => {
    if (opts.client !== undefined) {
      if (!isValidClientId(opts.client)) {
        log.error(BAD_CLIENT_ID);
        process.exitCode = 1;
        return;
      }
      let known = false;
      try {
        known = Object.prototype.hasOwnProperty.call(loadConfig(configPath()).clients ?? {}, opts.client);
      } catch (err) {
        log.error(err instanceof Error ? err.message : String(err));
        process.exitCode = 1;
        return;
      }
      if (!known) {
        log.error(`client '${opts.client}' is not configured: run \`switchboard client add ${opts.client}\` first`);
        process.exitCode = 1;
        return;
      }
    }
    const { token, record } = new ApiKeyStore().issue(name, opts.client ? { client: opts.client } : {});
    log.ok(`issued API key '${record.name}' (id ${record.id}${record.client ? `, client ${record.client}` : ""})`);
    out("");
    out("  Token (shown once — copy it now):");
    out("");
    out(`    ${token}`);
    out("");
    out("  Give it to an MCP client as a bearer header:");
    out(`    Authorization: Bearer ${token}`);
    out("");
    out("  Stored as a one-way hash and never recoverable — if you lose it, issue a new one.");
  });

apikeyCmd
  .command("list")
  .description("list API keys (names + prefixes, never the full token)")
  .action(() => {
    const keys = new ApiKeyStore().list();
    if (!keys.length) {
      out("no API keys issued — run `switchboard apikey new <name>`");
      return;
    }
    for (const k of keys) {
      const used = k.last_used ? `last used ${k.last_used}` : "never used";
      out(`  ${k.id}  ${k.name.padEnd(16)} ${k.prefix}…  (created ${k.created}, ${used}${k.client ? `, client ${k.client}` : ""})`);
    }
  });

apikeyCmd
  .command("rm <id>")
  .description("revoke an API key by id")
  .action((id: string) => {
    if (new ApiKeyStore().revoke(id)) {
      log.ok(`revoked API key '${id}'`);
    } else {
      log.error(`no API key with id '${id}'`);
      process.exitCode = 1;
    }
  });

// ── clients (design 3.1) ─────────────────────────────────────────────────────────────────────────

const clientCmd = program
  .command("client")
  .description("register the clients that may call /mcp (servers, tools, scope ceiling) and manage their keys");

/**
 * Run a client subcommand: a failure is one clear line and exit code 1, never a stack. The ClientAdmin it hands over
 * is the OFFLINE one, used only when no gateway answers: nothing there proves the owner, and its audit row says so.
 * With a gateway running every grant (add, rotate) goes through the gateway instead, which checks presence first.
 */
function clientAction<A extends unknown[]>(fn: (admin: ClientAdmin, cfg: SwitchboardConfig, ...args: A) => Promise<void>): (...args: A) => Promise<void> {
  return async (...args: A) => {
    try {
      const path = configPath();
      const cfg = loadConfig(path);
      await fn(new ClientAdmin({ cfg, configPath: path, apiKeys: new ApiKeyStore(), actor: "cli" }), cfg, ...args);
    } catch (err) {
      log.error(err instanceof ClientAdminError || err instanceof Error ? err.message : String(err));
      process.exitCode = 1;
    }
  };
}

const csv = (v: string): string[] => v.split(",").map((x) => x.trim()).filter(Boolean);

/** Is a gateway running that this CLI can ask? Its answer to the (presence-free) list request, or null. */
async function runningGateway(cfg: SwitchboardConfig): Promise<Record<string, unknown> | null> {
  const r = await askGateway(cfg.gateway.http.port, "GET", "/clients", 15_000);
  if (r === null) return null;
  if (r.status !== 200) throw new CliFail(String(r.body.error ?? `the gateway answered ${r.status}`));
  return r.body;
}

/** A change request to the running gateway. A refusal (presence, validation) is an error with the gateway's words. */
async function gatewayChange(path: string, body: unknown, prompt: boolean): Promise<Record<string, unknown>> {
  if (prompt) out("asking the gateway to verify you are present (Windows Hello on this machine, or a challenge at the gateway's terminal)...");
  const r = await controlCall("POST", path, 150_000, body);
  if (r.status !== 200) throw new CliFail(String(r.body.error ?? `the gateway answered ${r.status}`));
  return r.body;
}

const OFFLINE_NOTE =
  "no gateway answered: the config file and the key store are written, and a gateway that starts later loads them. A gateway that is already running ignores file edits (it applies a change only when this command reaches it, after its presence check), so run this again while it is up if it is.";

function showToken(token: string): void {
  out("");
  out("  Token (shown once, copy it now):");
  out("");
  out(`    ${token}`);
  out("");
  out("  Stored one-way hashed in the key store; the bridge reads its own copy from the client key file.");
}

clientCmd
  .command("add <id>")
  .description("create or update a client and issue its key (stored for `switchboard bridge --client <id>`; printed only with --print). A running gateway checks you are present first")
  .option("--servers <list>", `comma separated server id globs the client may see and call (new client default: ${NEW_CLIENT_DEFAULTS.servers.join(",")})`)
  .option("--max-scope <scope>", `scope ceiling: read | write | full (new client default: ${NEW_CLIENT_DEFAULTS.max_scope})`)
  .option("--max-risk <risk>", `highest risk it may request: low | medium | high (new client default: ${NEW_CLIENT_DEFAULTS.max_risk}; a call above it is refused, high still needs an approval)`)
  .option("--print", "print the token once (otherwise it goes only to the client key file)")
  .action(
    clientAction(async (admin, cfg, id: string, opts: { servers?: string; maxScope?: string; maxRisk?: string; print?: boolean }) => {
      const spec: ClientSpec = {};
      if (opts.servers !== undefined) spec.servers = csv(opts.servers);
      if (opts.maxScope !== undefined) {
        if (!["read", "write", "full"].includes(opts.maxScope)) throw new Error("--max-scope must be read, write or full");
        spec.max_scope = opts.maxScope as ClientSpec["max_scope"];
      }
      if (opts.maxRisk !== undefined) {
        if (!["low", "medium", "high"].includes(opts.maxRisk)) throw new Error("--max-risk must be low, medium or high");
        spec.max_risk = opts.maxRisk as ClientSpec["max_risk"];
      }
      let r: { created: boolean; client: ClientConfig; keyKept: boolean; token?: string; revoked: number; keyFile: string };
      let offline = false;
      if ((await runningGateway(cfg)) !== null) {
        r = (await gatewayChange(`/clients/${encodeURIComponent(id)}/add`, { spec, print: opts.print === true }, true)) as typeof r;
      } else {
        r = admin.add(id, spec);
        offline = true;
      }
      const c = r.client;
      log.ok(`client '${id}' ${r.created ? "created" : "updated"}: servers ${c.servers.join(",") || "(none)"}, max_scope ${c.max_scope ?? "(server ceiling)"}, max_risk ${c.max_risk ?? "high"}`);
      if (r.keyKept) {
        out(`  key: the existing key is kept (${r.keyFile}); \`switchboard client rotate ${id}\` issues a new one`);
        if (opts.print) log.warn("--print: nothing to print, the existing token cannot be recovered");
      } else {
        out(`  key: issued and stored for the bridge (${r.keyFile})${r.revoked ? `; replaced ${r.revoked} earlier key(s)` : ""}`);
        if (opts.print && r.token) showToken(r.token);
      }
      out(`  next: \`switchboard bridge --client ${id}\`. ${offline ? OFFLINE_NOTE : "The running gateway has this client and its key now."}`);
    }),
  );

clientCmd
  .command("list")
  .description("list registered clients and their keys (no secrets); a running gateway's view when one answers")
  .action(
    clientAction(async (admin, cfg) => {
      const live = await runningGateway(cfg);
      type Row = { id: string; config: ClientConfig; keys: { id: string; created: string; last_used?: string }[]; key_file: boolean };
      let clients: Row[];
      let orphan_keys: { id: string; client?: string }[];
      if (live) {
        const rows = (live.clients ?? []) as (ClientConfig & { id: string; keys: Row["keys"]; key_file: boolean })[];
        clients = rows.map(({ id, keys, key_file, ...config }) => ({ id, config: config as ClientConfig, keys, key_file }));
        orphan_keys = (live.orphan_keys ?? []) as typeof orphan_keys;
        out("(the running gateway's view: these are the clients in force)");
        if (live.drift === true) {
          log.warn("the config file differs from these clients (it was edited behind the running gateway's back): the file is not applied until the gateway restarts; review it before you restart");
        }
      } else {
        const l = admin.list();
        clients = l.clients;
        orphan_keys = l.orphan_keys;
        out("(no gateway answered: this is the config file and the key store)");
      }
      if (clients.length === 0) {
        out("no clients registered: /mcp is in single-user mode. Register one with `switchboard client add <id>`.");
      }
      for (const c of clients) {
        const cfgc = c.config;
        out(`  ${c.id}${cfgc.description ? `  ${cfgc.description}` : ""}`);
        out(`      servers: ${cfgc.servers.join(", ") || "(none)"}${cfgc.tools?.length ? `  tools: ${cfgc.tools.join(", ")}` : ""}${cfgc.exclude_tools?.length ? `  exclude: ${cfgc.exclude_tools.join(", ")}` : ""}`);
        out(`      max_scope: ${cfgc.max_scope ?? "(server ceiling)"}  max_risk: ${cfgc.max_risk ?? "high"}${cfgc.limits ? `  limits: ${JSON.stringify(cfgc.limits)}` : ""}`);
        const keys = c.keys.map((k) => `${k.id} (created ${k.created}${k.last_used ? `, last used ${k.last_used}` : ", never used"})`);
        out(`      keys: ${keys.length ? keys.join("; ") : "none"}   key file: ${c.key_file ? "present" : "missing"}`);
      }
      if (orphan_keys.length > 0) {
        log.warn(`${orphan_keys.length} key(s) are bound to a client that is not configured and are refused: ${orphan_keys.map((k) => `${k.id} -> ${k.client}`).join(", ")}`);
      }
    }),
  );

clientCmd
  .command("rotate <id>")
  .description("issue a new key for a client; its earlier keys stop working at once. A running gateway checks you are present first")
  .option("--print", "print the token once (otherwise it goes only to the client key file)")
  .action(
    clientAction(async (admin, cfg, id: string, opts: { print?: boolean }) => {
      let r: { token?: string; revoked: number; keyFile: string };
      let offline = false;
      if ((await runningGateway(cfg)) !== null) {
        r = (await gatewayChange(`/clients/${encodeURIComponent(id)}/rotate`, { print: opts.print === true }, true)) as typeof r;
      } else {
        r = admin.rotate(id);
        offline = true;
      }
      log.ok(`rotated the key of client '${id}': new key stored (${r.keyFile}), ${r.revoked} earlier key(s) revoked`);
      if (opts.print && r.token) showToken(r.token);
      if (offline) out(`  ${OFFLINE_NOTE}`);
    }),
  );

clientCmd
  .command("rm <id>")
  .description("revoke a client's keys and delete its key file; the config entry is removed only with --purge (no presence check: revoking is always safe)")
  .option("--purge", "also remove the client from the config file")
  .action(
    clientAction(async (admin, cfg, id: string, opts: { purge?: boolean }) => {
      let r: { revokedKeys: number; keyFileRemoved: boolean; purged: boolean };
      let offline = false;
      if ((await runningGateway(cfg)) !== null) {
        r = (await gatewayChange(`/clients/${encodeURIComponent(id)}/rm`, { purge: opts.purge === true }, false)) as typeof r;
      } else {
        r = admin.remove(id, { purge: opts.purge === true });
        offline = true;
      }
      log.ok(`client '${id}': ${r.revokedKeys} key(s) revoked, key file ${r.keyFileRemoved ? "removed" : "was absent"}${r.purged ? ", config entry removed" : ""}`);
      if (!r.purged) out("  the config entry stays (it grants nothing without a key); add --purge to remove it too.");
      if (offline) out(`  ${OFFLINE_NOTE}`);
    }),
  );

/** Read a secret from a pipe (preferred) or an interactive prompt. */
function readSecret(prompt: string): Promise<string> {
  if (!process.stdin.isTTY) {
    return new Promise((resolveSecret) => {
      let data = "";
      process.stdin.setEncoding("utf8");
      process.stdin.on("data", (c) => (data += c));
      process.stdin.on("end", () => resolveSecret(data.replace(/\r?\n$/, "")));
    });
  }
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  return new Promise((resolveSecret) =>
    rl.question(prompt, (answer) => {
      rl.close();
      resolveSecret(answer.trim());
    }),
  );
}

program.parseAsync(process.argv).catch((err) => {
  log.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
