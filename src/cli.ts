#!/usr/bin/env node
/**
 * `switchboard` — the command-line entry point.
 *
 *   switchboard init                 scaffold a config + home dir
 *   switchboard serve                run the gateway (stdio and/or HTTP per config)
 *   switchboard dashboard            run only the HTTP endpoint + web console
 *   switchboard dashboard login      mint a one-time owner login code (owner-presence checked)
 *   switchboard list                 mount everything and print the governed tool list
 *   switchboard doctor               check the environment + config
 *   switchboard catalog              list OAuth providers + connection status
 *   switchboard connect <provider>   authorize a provider via local loopback OAuth
 *   switchboard install <client>     wire MCP Switchboard into an MCP client's config
 *   switchboard local-llm            detect a local LLM server for the offline council
 *   switchboard local-llm wire       wire a detected local server into the council
 *   switchboard toolkits sync        rebuild the integration catalog from open indexes
 *   switchboard toolkits stats       print catalog counts
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
import type { SwitchboardConfig } from "./types.js";
import {
  applyProfileEnvOverride,
  describeProfile,
  withActiveProfile,
} from "./profiles.js";
import { createGateway } from "./gateway.js";
import { startDashboard, type DashboardHandle } from "./dashboard.js";
import { LoginCodeStore, assertPortFree } from "./httpsec.js";
import { randomChallenge, verifyOwnerPresence, type PresenceMethod } from "./presence.js";
import { runExpose, TUNNEL_KINDS, type TunnelKind } from "./expose.js";
import { ensureDir } from "./atomicfile.js";
import { Vault, HOME_DIR } from "./vault.js";
import { OAuthStore } from "./oauth.js";
import { ApiKeyStore } from "./apikeys.js";
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
import { SUPPORTED_CLIENTS, buildPlan, writePlan, type ClientId } from "./clients.js";
import {
  KNOWN_RUNTIMES,
  probeRuntime,
  probeAll,
  pickDefaultModel,
  buildLocalProvider,
  withLocalProvider,
  wireAdvice,
  installGuide,
} from "./localllm.js";
import { log, out } from "./logger.js";

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
  .action(async () => {
    const path = configPath();
    const cfg = bootConfig(path);
    const wantsHttp = cfg.gateway.transport.includes("http");
    const wantsStdio = cfg.gateway.transport.includes("stdio");
    if (wantsHttp) await requireFreeHttpPort(cfg);
    const gateway = await createGateway(cfg);

    if (wantsHttp) await startHttpOrExit(gateway, cfg, path);

    if (wantsStdio) {
      await gateway.serveStdio(); // resolves once connected; process stays alive on the transport
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
  .description("mint a one-time owner login code for the dashboard, after an owner-presence check")
  .option("--presence <method>", "owner presence check: auto | hello | tty | none (none needs SWITCHBOARD_INSECURE_APPROVAL=1)", "auto")
  .option("--no-open", "print the login URL but do not open the browser")
  .action(async (opts: { presence: string; open: boolean }) => {
    const methods = ["auto", "hello", "tty", "none"];
    if (!methods.includes(opts.presence)) {
      log.error(`unknown --presence '${opts.presence}': choose one of ${methods.join(", ")}`);
      process.exitCode = 1;
      return;
    }
    const cfg = loadConfig(configPath());
    const presence = await verifyOwnerPresence(
      opts.presence as PresenceMethod | "auto",
      "Sign in to the MCP Switchboard dashboard",
      randomChallenge(4),
    );
    if (!presence.ok) {
      log.error(`owner presence check failed (${presence.method}): ${presence.reason}`);
      process.exitCode = 1;
      return;
    }
    const code = new LoginCodeStore().mint();
    const url = `http://127.0.0.1:${cfg.gateway.http.port}/#login=${code}`;
    log.ok(`login code minted (presence: ${presence.method}); it works once and expires in 120 seconds`);
    out("");
    out(`  ${url}`);
    out("");
    try {
      await fetch(`http://127.0.0.1:${cfg.gateway.http.port}/healthz`, { signal: AbortSignal.timeout(1500) });
    } catch {
      log.warn(`no gateway answered on 127.0.0.1:${cfg.gateway.http.port}: start it with \`switchboard dashboard\` or \`switchboard serve\` before the code expires`);
    }
    if (opts.open) openInBrowser(url);
  });

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
    if (opts.newToken || apiKeys.count === 0) {
      issuedToken = apiKeys.issue("expose").token;
    }

    const gateway = await createGateway(cfg);
    try {
      await runExpose(gateway, cfg, apiKeys, { tunnel, port, issuedToken });
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
      out(`  ${t.name.padEnd(42)} [${scope}]  ${t.description?.split("\n")[0] ?? ""}`);
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
    if (report.ok) log.ok("config looks healthy");
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
    const { snapshot, errors, enrichment } = await ingestCatalogVerbose();
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
      results = await discoverToolkits(q, { limit: Number(opts.limit) || 20 });
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
      out(`  • ${r.name}  [${r.category}]`);
      out(`    ${r.repository}`);
      if (r.description) out(`    ${r.description}`);
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
      taxonomy = await fetchAwesomeTaxonomy();
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
    const oauth = new OAuthStore(new Vault(cfg.vault.backend));
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

program
  .command("install <client>")
  .description(`wire MCP Switchboard into an MCP client's config (${SUPPORTED_CLIENTS.join(", ")})`)
  .option("--global", "write the client's user/global config instead of a project-local one")
  .option("--dir <path>", "project directory for project-local configs (default: cwd)")
  .option("--name <name>", "server name to register under", "switchboard")
  .option("--print", "print the resulting config without writing it")
  .action(
    (
      client: string,
      opts: { global?: boolean; dir?: string; name: string; print?: boolean },
    ) => {
      if (!SUPPORTED_CLIENTS.includes(client as ClientId)) {
        log.error(`unknown client '${client}' — supported: ${SUPPORTED_CLIENTS.join(", ")}`);
        process.exitCode = 1;
        return;
      }
      const cfgPath = configPath();
      const cfg = loadConfig(cfgPath);
      // import.meta.url is dist/cli.js at runtime — exactly what a stdio launcher must exec.
      const cliPath = fileURLToPath(import.meta.url);
      const plan = buildPlan(client as ClientId, {
        name: opts.name,
        endpoint: {
          host: cfg.gateway.http.host,
          port: cfg.gateway.http.port,
          requireAuth: cfg.gateway.http.require_auth,
        },
        launcher: { command: process.execPath, cliPath, configPath: cfgPath },
        global: opts.global,
        baseDir: opts.dir ? resolve(opts.dir) : undefined,
      });

      if (opts.print) {
        out(`\n# ${plan.target.label} — ${plan.target.path}\n`);
        out(plan.content);
        for (const note of plan.notes) out(`note: ${note}`);
        return;
      }
      if (plan.existed && !plan.changed) {
        log.ok(`${plan.target.label} already points at this MCP Switchboard (${plan.target.path}) — no change`);
      } else {
        writePlan(plan);
        log.ok(`${plan.existed ? "updated" : "wrote"} ${plan.target.label} config → ${plan.target.path}`);
      }
      for (const note of plan.notes) out(`  → ${note}`);
    },
  );

const llmCmd = program
  .command("local-llm")
  .description("detect a local OpenAI-compatible LLM server (Ollama/LM Studio/llama.cpp/vLLM) for the offline council")
  .action(async () => {
    out("\nProbing localhost for OpenAI-compatible model servers…");
    const results = await probeAll();
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
      out(`  ${r.runtime.label.padEnd(26)} ${r.runtime.baseUrl}  (${n} model${n === 1 ? "" : "s"})`);
      for (const m of r.models.slice(0, 8)) out(`      - ${m}`);
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
          const probe = await probeRuntime({ id: "custom", label: "custom", baseUrl: trimmed, modelsUrl: `${trimmed}/models` });
          model = pickDefaultModel(probe.models);
        }
      } else {
        const results = await probeAll();
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
      const advice = wireAdvice(result, model);

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

program
  .command("kill <action>")
  .description("kill switch: refuse every tool call, resource read and prompt get until cleared (on | off | status)")
  .action((action: string) => {
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
    const report = () => {
      const st = killStatus(cfg);
      out(`kill switch: ${st.active ? "ON" : "OFF"}`);
      out(`  file:   ${killFilePath()} (${st.file ? `present${st.since ? `, since ${st.since}` : ""}` : "absent"})`);
      out(`  config: gateway.kill_switch is ${st.config ? "true" : cfg ? "not set" : "unknown (no readable config)"}`);
      return st;
    };
    if (action === "status") {
      report();
      return;
    }
    if (action === "on") {
      const { changed } = setKillFile(true);
      log.warn(changed ? "kill switch ON: every tool call, resource read and prompt get is now refused" : "kill switch was already on");
      out("a running gateway sees the file on its next call; no restart needed. Clear it with 'switchboard kill off'.");
      report();
      return;
    }
    const { changed } = setKillFile(false);
    const st = report();
    if (st.active) {
      log.error("the KILL file is cleared but gateway.kill_switch is still true in the config: set it to false and restart the gateway");
      process.exitCode = 1;
      return;
    }
    log.ok(changed ? "kill switch OFF: calls are allowed again" : "kill switch was already off");
  });

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
  .action((name: string) => {
    const { token, record } = new ApiKeyStore().issue(name);
    log.ok(`issued API key '${record.name}' (id ${record.id})`);
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
      out(`  ${k.id}  ${k.name.padEnd(16)} ${k.prefix}…  (created ${k.created}, ${used})`);
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
