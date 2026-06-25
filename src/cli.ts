#!/usr/bin/env node
/**
 * `switchboard` — the command-line entry point.
 *
 *   switchboard init                 scaffold a config + home dir
 *   switchboard serve                run the gateway (stdio and/or HTTP per config)
 *   switchboard dashboard            run only the HTTP endpoint + web console
 *   switchboard list                 mount everything and print the governed tool list
 *   switchboard doctor               check the environment + config
 *   switchboard catalog              list OAuth providers + connection status
 *   switchboard connect <provider>   authorize a provider via local loopback OAuth
 *   switchboard install <client>     wire Switchboard into an MCP client's config
 *   switchboard toolkits sync        rebuild the integration catalog from open indexes
 *   switchboard toolkits stats       print catalog counts
 *   switchboard vault set <name>     store a secret (value read from stdin)
 *   switchboard vault list|rm <name> manage secrets
 *
 * Logs go to stderr (see logger.ts) so stdout stays clean for the stdio MCP channel.
 */

import { existsSync } from "node:fs";
import { createServer } from "node:http";
import { resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { Command } from "commander";
import { loadConfig, writeConfig, starterConfig } from "./config.js";
import { createGateway } from "./gateway.js";
import { startDashboard } from "./dashboard.js";
import { runExpose, TUNNEL_KINDS, type TunnelKind } from "./expose.js";
import { Vault, HOME_DIR } from "./vault.js";
import { OAuthStore } from "./oauth.js";
import { ApiKeyStore } from "./apikeys.js";
import { inferScope, evaluate } from "./policy.js";
import {
  ingestCatalogVerbose,
  loadCatalog,
  writeCatalog,
  defaultCatalogPath,
} from "./catalog.js";
import { SUPPORTED_CLIENTS, buildPlan, writePlan, type ClientId } from "./clients.js";
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

program
  .command("init")
  .description("create a starter config and home directory")
  .action(() => {
    const path = configPath();
    if (existsSync(path)) {
      log.warn(`config already exists at ${path} — leaving it untouched`);
      return;
    }
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
    const cfg = loadConfig(path);
    const gateway = await createGateway(cfg);

    const wantsHttp = cfg.gateway.transport.includes("http");
    const wantsStdio = cfg.gateway.transport.includes("stdio");

    if (wantsHttp) await startDashboard(gateway, cfg, path);

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

program
  .command("dashboard")
  .description("run only the HTTP endpoint + web console")
  .action(async () => {
    const path = configPath();
    const cfg = loadConfig(path);
    const gateway = await createGateway(cfg);
    const handle = await startDashboard(gateway, cfg, path);
    out(`Open ${handle.url}`);
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
    const cfg = loadConfig(configPath());
    const port = opts.port ? Number(opts.port) : cfg.gateway.http.port + 1;
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      log.error(`invalid --port '${opts.port}' — expected an integer 1–65535`);
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
    await runExpose(gateway, cfg, apiKeys, { tunnel, port, issuedToken });
  });

program
  .command("list")
  .description("mount every server and print the governed tool list, then exit")
  .action(async () => {
    const cfg = loadConfig(configPath());
    const gateway = await createGateway(cfg);
    const tools = gateway.router.listTools();
    out(`\n${tools.length} tools exposed:\n`);
    for (const t of tools) {
      const scope = inferScope(t.name.split("__").pop() ?? t.name);
      out(`  ${t.name.padEnd(42)} [${scope}]  ${t.description?.split("\n")[0] ?? ""}`);
    }
    await gateway.shutdown();
  });

program
  .command("doctor")
  .description("check the environment, config, and credentials")
  .action(() => {
    const path = configPath();
    out(`Switchboard doctor`);
    out(`  node:        ${process.version}`);
    out(`  home:        ${HOME_DIR}`);
    out(`  config:      ${path} ${existsSync(path) ? "(found)" : "(missing — run `switchboard init`)"}`);
    if (!existsSync(path)) return;

    let ok = true;
    try {
      const cfg = loadConfig(path);
      out(`  vault:       ${cfg.vault.backend}`);
      out(`  transports:  ${cfg.gateway.transport.join(", ")}`);
      out(`  endpoint:    http://${cfg.gateway.http.host}:${cfg.gateway.http.port}/mcp`);
      out(`\n  servers (${cfg.servers.length}):`);
      const vault = new Vault(cfg.vault.backend);
      for (const s of cfg.servers) {
        const policy = s.policy ?? cfg.gateway.default_policy;
        out(`    - ${s.id} [${s.source}, ${policy}] ${s.enabled === false ? "(disabled)" : ""}`);
        // Verify referenced secrets resolve without printing their values.
        for (const v of Object.values({ ...(s.env ?? {}), ...(s.credentials ?? {}) })) {
          try {
            vault.resolve(v);
          } catch (err) {
            ok = false;
            log.error(`      unresolved: ${err instanceof Error ? err.message : String(err)}`);
          }
        }
        // Surface obvious policy traps: a write/full tool under a read ceiling.
        for (const name of Object.keys(s.tools ?? {})) {
          const d = evaluate(s, name, cfg);
          if (d.decision === "deny") log.warn(`      '${name}' -> ${d.reason}`);
        }
      }
    } catch (err) {
      ok = false;
      log.error(err instanceof Error ? err.message : String(err));
    }
    out("");
    if (ok) log.ok("config looks healthy");
    else log.error("issues found (see above)");
    process.exitCode = ok ? 0 : 1;
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
    const { snapshot, errors } = await ingestCatalogVerbose();
    snapshot.generated_at = new Date().toISOString();
    const path = defaultCatalogPath();
    writeCatalog(snapshot, path);
    log.ok(
      `wrote ${snapshot.counts.total} toolkits (${snapshot.counts.mcp_registry} MCP, ${snapshot.counts.apis_guru} OpenAPI) to ${path}`,
    );
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
  .description(`wire Switchboard into an MCP client's config (${SUPPORTED_CLIENTS.join(", ")})`)
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
        log.ok(`${plan.target.label} already points at this Switchboard (${plan.target.path}) — no change`);
      } else {
        writePlan(plan);
        log.ok(`${plan.existed ? "updated" : "wrote"} ${plan.target.label} config → ${plan.target.path}`);
      }
      for (const note of plan.notes) out(`  → ${note}`);
    },
  );

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
