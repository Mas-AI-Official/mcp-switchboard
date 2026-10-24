/**
 * CLI for the phase P2 layer (ADR local-composio, sections 6.3, 6.7 and 6.8):
 *
 *   switchboard toolkits sync <provider|toolkit|all> [--check]   fetch each spec through the SSRF guard and write the toolkit
 *   switchboard toolkits list | show <slug>                      what is defined, listed, searchable, verified
 *   switchboard toolkits enable <slug> [--account <ref>]          mount the toolkit as a `source: connector` server
 *   switchboard toolkits disable <slug>                           turn it off (the server stays in the config)
 *
 * `switchboard link|unlink|links` live in cli.ts: they edit the gateway's `clients:` section through ClientAdmin
 * (planning in link.ts), because there is one access-control source and it is that section.
 *
 *   switchboard coverage [toolkit] [--json] [--import [dir]] [--mark <row> --state <state> --account <ca_>]
 *
 * `toolkits sync` with no argument is the older command that rebuilds the browse catalog; it is untouched.
 */

import { existsSync } from "node:fs";
import type { Command } from "commander";
import { loadConfig, writeConfig } from "../config.js";
import { Vault } from "../vault.js";
import { log, out } from "../logger.js";
import type { NetworkSettings } from "../netguard.js";
import type { SwitchboardConfig } from "../types.js";
import { Connectors } from "./index.js";
import { DEFAULT_CHECKLIST_DIR, formatReport } from "./coverage.js";
import { VERIFICATION_STATES, type VerificationState } from "./toolkits.js";
import { syncToolkits, type SyncOutcome } from "./sync.js";
import { toolkitEnableProblem } from "./admin.js";

export interface KitCliHelpers {
  vaultBackend(): "encrypted-file" | "env";
  network(): NetworkSettings | undefined;
  configPath(): string;
}

function build(h: KitCliHelpers): Connectors {
  const network = h.network();
  return new Connectors({ vault: new Vault(h.vaultBackend()), ...(network ? { network } : {}) });
}

function fail(err: unknown): void {
  log.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
}

function table(rows: string[][]): string {
  const widths = rows[0]!.map((_, i) => Math.max(...rows.map((r) => (r[i] ?? "").length)));
  return rows.map((r) => r.map((c, i) => (c ?? "").padEnd(widths[i]!)).join("  ").trimEnd()).join("\n");
}

export function printSyncOutcome(o: SyncOutcome): void {
  const label: Record<SyncOutcome["status"], string> = { synced: "synced", unchanged: "unchanged", drift: "DRIFT", unsynced: "NOT SYNCED", no_source: "no source", failed: "FAILED" };
  const ver = o.version ? ` ${o.version}` : "";
  out(`  ${o.toolkit.padEnd(12)} ${label[o.status]}${ver}${o.actions !== undefined ? `  ${o.actions} actions from ${o.operations} operations` : ""}`);
  if (o.compile) out(`               schemas compiled ${o.compile.compiled}/${o.compile.total}; longest tool name ${o.max_tool_name} characters`);
  if (o.message) (o.status === "failed" ? log.error : out)(`               ${o.message}`);
  if (o.warnings.length) out(`               ${o.warnings.length} warning(s); first: ${o.warnings[0]}`);
}

export async function runToolkitSync(h: KitCliHelpers, target: string, opts: { check?: boolean }): Promise<void> {
  const kit = build(h).kit;
  out(`${opts.check ? "Checking" : "Syncing"} toolkit specs for '${target}' through the SSRF guard (generated files go to ${kit.toolkits.generatedRoot}, never to git)...`);
  const results = await syncToolkits(kit, target, { ...(opts.check ? { check: true } : {}), network: h.network() });
  for (const r of results) printSyncOutcome(r);
  const bad = results.some((r) => r.status === "failed" || (opts.check && (r.status === "drift" || r.status === "unsynced")));
  if (results.every((r) => r.status === "no_source")) log.warn("nothing to sync: those toolkits have no spec source");
  if (bad) process.exitCode = 1;
}

function connectorServer(cfg: SwitchboardConfig, slug: string): SwitchboardConfig["servers"][number] | undefined {
  return cfg.servers.find((s) => s.source === "connector" && s.toolkit === slug);
}

export function registerKitCommands(program: Command, toolkitsCmd: Command, h: KitCliHelpers): void {
  // ── toolkits list | show | enable | disable ─────────────────────────────────────────────────────
  toolkitsCmd
    .command("list")
    .description("the connector toolkits defined here: version, source, tools, verification")
    .action(() => {
      try {
        const kit = build(h).kit;
        let cfg: SwitchboardConfig | undefined;
        try {
          cfg = loadConfig(h.configPath());
        } catch {
          cfg = undefined;
        }
        const rows = [["toolkit", "provider", "version", "source", "tools", "listed", "enabled"]];
        for (const slug of kit.toolkits.slugs()) {
          const tk = kit.toolkits.load(slug);
          if (!tk) {
            rows.push([slug, kit.toolkits.providerSlug(slug) ?? "-", "-", "not synced", "0", "-", "-"]);
            continue;
          }
          const listed = tk.actions.filter((a) => a.important && !a.deprecated).length;
          const srv = cfg ? connectorServer(cfg, slug) : undefined;
          rows.push([slug, tk.provider, tk.version, tk.source, String(tk.tools_count), String(Math.min(listed, 28)), srv ? (srv.enabled === false ? "off" : "on") : "no server"]);
        }
        out(table(rows));
      } catch (err) {
        fail(err);
      }
    });

  toolkitsCmd
    .command("show <slug>")
    .description("one toolkit: counts by scope and risk, the listed set, overlay issues")
    .action((slug: string) => {
      try {
        const kit = build(h).kit;
        const tk = kit.toolkits.load(slug);
        if (!tk) {
          log.error(`toolkit '${slug}' is not defined here (run: switchboard toolkits sync ${slug})`);
          process.exitCode = 1;
          return;
        }
        const acts = tk.actions;
        const count = (f: (a: (typeof acts)[number]) => string): string =>
          Object.entries(acts.reduce<Record<string, number>>((m, a) => ((m[f(a)] = (m[f(a)] ?? 0) + 1), m), {})).map(([k, v]) => `${k} ${v}`).join(", ");
        out(`${tk.slug} (${tk.provider}) version ${tk.version}  [${tk.source}]`);
        out(`  actions   ${tk.tools_count} (${tk.hidden_count} hidden by the overlay)`);
        out(`  scope     ${count((a) => a.scope)}`);
        out(`  risk      ${count((a) => a.risk)}`);
        out(`  outward   ${tk.actions.filter((a) => a.outward).length}`);
        out(`  files     ${tk.actions.filter((a) => a.files?.upload.length).length} take a file`);
        out(`  listed    ${tk.actions.filter((a) => a.important && !a.deprecated).map((a) => a.slug).join(", ") || "(no important actions: the first read actions are listed)"}`);
        if (tk.spec) out(`  spec      ${tk.spec.url} fetched ${tk.spec.fetched_at} (${tk.spec.spec_revision ?? tk.spec.spec_version ?? "no revision"})`);
        for (const i of tk.overlay_issues) log.warn(`  overlay: ${i}`);
      } catch (err) {
        fail(err);
      }
    });

  toolkitsCmd
    .command("enable <slug>")
    .description("mount a toolkit as a connector server (needs an ACTIVE, probed account)")
    .option("--account <ref>", "pin this server to one connected account")
    .option("--id <id>", "the server id (default: the toolkit slug)")
    .action((slug: string, opts: { account?: string; id?: string }) => {
      try {
        const kit = build(h).kit;
        // The same check the dashboard makes (admin.ts), so the two cannot disagree.
        const problem = toolkitEnableProblem(kit.connectors, slug);
        if (problem) throw new Error(problem);
        const tk = kit.toolkits.load(slug)!;
        const provider = kit.connectors.providers.providerForToolkit(slug) ?? kit.connectors.providers.get(tk.provider)!;
        if (opts.account) kit.connectors.accounts.require(opts.account.includes("/") || opts.account.startsWith("ca_") ? opts.account : `${provider.slug}/${opts.account}`);
        const path = h.configPath();
        if (!existsSync(path)) throw new Error(`no config at ${path}: run \`switchboard init\` first`);
        const cfg = loadConfig(path);
        const existing = connectorServer(cfg, slug);
        if (existing) {
          existing.enabled = true;
          if (opts.account) existing.account = opts.account;
        } else {
          const id = opts.id ?? slug;
          if (cfg.servers.some((s) => s.id === id)) throw new Error(`a server with id '${id}' already exists; pass --id`);
          cfg.servers.push({ id, source: "connector", toolkit: slug, enabled: true, ...(opts.account ? { account: opts.account } : {}) });
        }
        writeConfig(path, cfg);
        log.ok(`toolkit '${slug}' is on in ${path}. A running gateway picks it up on restart (the dashboard toggle is live).`);
      } catch (err) {
        fail(err);
      }
    });

  toolkitsCmd
    .command("disable <slug>")
    .description("turn a connector server off (it stays in the config)")
    .action((slug: string) => {
      try {
        const path = h.configPath();
        const cfg = loadConfig(path);
        const s = connectorServer(cfg, slug);
        if (!s) throw new Error(`no connector server for toolkit '${slug}' in ${path}`);
        s.enabled = false;
        writeConfig(path, cfg);
        log.ok(`toolkit '${slug}' is off in ${path}.`);
      } catch (err) {
        fail(err);
      }
    });

  // ── coverage ────────────────────────────────────────────────────────────────────────────────
  program
    .command("coverage [toolkit]")
    .description("honest counts: only rows proven live by an owner-run probe are 'working'")
    .option("--json", "print the report as JSON")
    .option("--import [dir]", `import the R1 checklist CSVs (default ${DEFAULT_CHECKLIST_DIR}) as the local row snapshot`)
    .option("--mark <row>", "append a state line for one checklist row (with --state)")
    .option("--state <state>", `with --mark: ${VERIFICATION_STATES.join(", ")}`)
    .option("--account <ca>", "with --mark live_verified: the connected account that proved it")
    .option("--note <text>", "with --mark: a short note")
    .action((toolkit: string | undefined, opts: { json?: boolean; import?: string | boolean; mark?: string; state?: string; account?: string; note?: string }) => {
      try {
        const cov = build(h).kit.coverage;
        if (opts.import !== undefined) {
          const dir = typeof opts.import === "string" ? opts.import : DEFAULT_CHECKLIST_DIR;
          const r = cov.importCsv(dir);
          for (const p of r.problems) log.warn(p);
          log.ok(`imported ${r.rows} rows from ${r.files} checklist(s) in ${dir}; ${r.deprecated} deprecated`);
          if (r.rows === 0) process.exitCode = 1;
          return;
        }
        if (opts.mark) {
          if (!opts.state) throw new Error("--mark needs --state");
          const line = cov.mark(opts.mark, opts.state as VerificationState, { ...(opts.account ? { account: opts.account } : {}), ...(opts.note ? { note: opts.note } : {}) });
          log.ok(`${line.id} is now ${line.state} (${line.ts})`);
          return;
        }
        if (cov.rows().length === 0) {
          out("no checklist rows imported yet: run `switchboard coverage --import` first");
          process.exitCode = 1;
          return;
        }
        const r = cov.report(toolkit);
        out(opts.json ? JSON.stringify(r, null, 2) : formatReport(r));
      } catch (err) {
        fail(err);
      }
    });
}
