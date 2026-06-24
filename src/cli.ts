#!/usr/bin/env node
/**
 * `switchboard` — the command-line entry point.
 *
 *   switchboard init                 scaffold a config + home dir
 *   switchboard serve                run the gateway (stdio and/or HTTP per config)
 *   switchboard dashboard            run only the HTTP endpoint + web console
 *   switchboard list                 mount everything and print the governed tool list
 *   switchboard doctor               check the environment + config
 *   switchboard vault set <name>     store a secret (value read from stdin)
 *   switchboard vault list|rm <name> manage secrets
 *
 * Logs go to stderr (see logger.ts) so stdout stays clean for the stdio MCP channel.
 */

import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { createInterface } from "node:readline";
import { Command } from "commander";
import { loadConfig, writeConfig, starterConfig } from "./config.js";
import { createGateway } from "./gateway.js";
import { startDashboard } from "./dashboard.js";
import { dashboardHtml } from "./console.js";
import { Vault, HOME_DIR } from "./vault.js";
import { inferScope, evaluate } from "./policy.js";
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

    if (wantsHttp) await startDashboard(gateway, cfg, dashboardHtml(), path);

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
    const handle = await startDashboard(gateway, cfg, dashboardHtml(), path);
    out(`Open ${handle.url}`);
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
