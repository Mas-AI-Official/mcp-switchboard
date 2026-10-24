/**
 * `switchboard connect | accounts | authconfig | providers` (ADR local-composio, 6.3).
 *
 *   switchboard connect <provider> [--account <label>] [--auth-config <id>] [--auth <id>] [--scopes a,b]
 *                                  [--token-ref <ref>] [--token-stdin] [--field name=ref] [--import]
 *   switchboard accounts list|show|default|disable|enable|revoke|probe
 *   switchboard authconfig add|list|show|rm
 *   switchboard providers list|show
 *
 * Secrets never travel on a command line: tokens and keys come from a vault or environment reference, from
 * stdin, or from a hidden prompt. Nothing printed here contains a credential; accounts are shown as the
 * summaries the store hands out.
 */

import { createServer } from "node:http";
import { createInterface } from "node:readline";
import type { Command } from "commander";
import type { NetworkSettings } from "../netguard.js";
import { Vault } from "../vault.js";
import { log, out } from "../logger.js";
import { Connectors } from "./index.js";
import { summarize } from "./accounts.js";
import { PENDING_TTL_MS } from "./oauthflow.js";
import { CONNECTOR_ERR, ConnectorError } from "./errors.js";
import type { AccountSummary, AuthDef, ProviderDef } from "./types.js";

export interface ConnectorCliHelpers {
  /** The vault backend named by the config, or the encrypted-file default when there is no readable config. */
  vaultBackend(): "encrypted-file" | "env";
  network(): NetworkSettings | undefined;
  /** The gateway address the loopback callback is served on. */
  gatewayAddress(): { host: string; port: number };
}

function build(h: ConnectorCliHelpers): Connectors {
  const network = h.network();
  return new Connectors({ vault: new Vault(h.vaultBackend()), ...(network ? { network } : {}) });
}

function fail(err: unknown): void {
  log.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
}

function when(iso: string | undefined): string {
  return iso ? iso.replace("T", " ").replace(/\.\d+Z$/, "Z") : "-";
}

function table(rows: string[][]): string {
  const widths = rows[0]!.map((_, i) => Math.max(...rows.map((r) => (r[i] ?? "").length)));
  return rows.map((r) => r.map((c, i) => (c ?? "").padEnd(widths[i]!)).join("  ").trimEnd()).join("\n");
}

function printAccount(a: AccountSummary, defaultId?: string): void {
  out(`  id            ${a.id}${a.id === defaultId ? "  (default for " + a.provider + ")" : ""}`);
  out(`  provider      ${a.provider}  (${a.auth_id}, ${a.mode})`);
  out(`  label         ${a.label}`);
  out(`  status        ${a.status}${a.status_reason ? `  (${a.status_reason})` : ""}`);
  out(`  identity      ${a.identity.display_name ?? a.identity.external_id}${a.identity.display_name ? `  [${a.identity.external_id}]` : ""}`);
  out(`  scopes        ${a.scopes_granted.length ? a.scopes_granted.join(" ") : "-"}`);
  out(`  connected     ${when(a.connected_at)}`);
  out(`  expires       ${when(a.expires_at)}`);
  out(`  last refresh  ${when(a.last_refresh_at)}`);
  out(`  last probe    ${when(a.last_probe_at)}`);
  if (a.last_error) out(`  last error    ${a.last_error}`);
  out(`  credential    ${a.has_token ? "sealed in the vault key" : "none (deleted)"}`);
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(Buffer.from(c as Buffer));
  return Buffer.concat(chunks).toString("utf8").trim();
}

/** A prompt whose answer is not echoed. Only used on a TTY. */
function promptHidden(question: string): Promise<string> {
  return new Promise((resolve) => {
    process.stderr.write(question);
    const rl = createInterface({ input: process.stdin, output: process.stderr, terminal: true });
    (rl as unknown as { _writeToOutput: (s: string) => void })._writeToOutput = () => {};
    rl.question("", (answer) => {
      rl.close();
      process.stderr.write("\n");
      resolve(answer.trim());
    });
  });
}

function pickTokenAuth(def: ProviderDef, wantedId: string | undefined, rt: Connectors): AuthDef | undefined {
  if (wantedId) return def.auth.find((a) => a.id === wantedId);
  const tokenModes = ["bearer", "api_key", "basic"];
  const d = rt.providers.defaultAuth(def);
  if (tokenModes.includes(d.mode)) return d;
  return def.auth.find((a) => tokenModes.includes(a.mode));
}

interface ConnectOpts {
  account?: string;
  authConfig?: string;
  auth?: string;
  scopes?: string;
  tokenRef?: string;
  tokenStdin?: boolean;
  field?: string[];
  refreshTokenRef?: string;
  expiresIn?: string;
  import?: boolean;
  json?: boolean;
}

function expandRedirect(uris: string[], redirect: string): string[] {
  return uris.map((u) => u.replace("{loopback_redirect}", redirect));
}

export function registerConnectorCommands(program: Command, h: ConnectorCliHelpers): void {
  // ── connect ────────────────────────────────────────────────────────────────────────────────────
  program
    .command("connect <provider>")
    .description("connect a provider account (OAuth in the browser, or a token / key you already hold)")
    .option("-a, --account <label>", "label for this account (several accounts per provider are fine)", "default")
    .option("--auth-config <id>", "the registered OAuth app to use (see: switchboard authconfig list)")
    .option("--auth <id>", "which authentication of the provider (see: switchboard providers show <provider>)")
    .option("--scopes <list>", "comma separated scopes; @group expands a scope group (for example @youtube)")
    .option("--token-ref <ref>", "a stored vault secret (or ${env:NAME}) holding the token or key")
    .option("--token-stdin", "read the token or key from stdin")
    .option("--field <name=ref>", "a named credential field from a vault or env reference (repeatable)", (v: string, prev: string[] = []) => [...prev, v])
    .option("--refresh-token-ref <ref>", "with --import: a vault reference holding the refresh token")
    .option("--expires-in <seconds>", "with --import: how long the access token has left")
    .option("--import", "adopt an OAuth token you already have instead of running the browser flow")
    .option("--json", "print the connected account as JSON")
    .action(async (provider: string, opts: ConnectOpts) => {
      try {
        await runConnect(h, provider, opts);
      } catch (err) {
        fail(err);
        if (err instanceof ConnectorError && err.detail.needsApp) {
          // The browser flow needs an OAuth app of your own: show exactly what to create and where.
          const def = build(h).providers.get(provider);
          if (def) {
            out(`\nTo connect ${def.name} through your browser you first register your own OAuth app. What to do:`);
            printProvider(def, h);
          }
        }
      }
    });

  // ── accounts ───────────────────────────────────────────────────────────────────────────────────
  const accounts = program.command("accounts").description("inspect and manage connected accounts");

  accounts
    .command("list")
    .description("list connected accounts")
    .option("--provider <slug>", "only this provider")
    .option("--json", "machine readable")
    .action((opts: { provider?: string; json?: boolean }) => {
      try {
        const rt = build(h);
        const rows = rt.accounts.summaries(opts.provider ? { provider: opts.provider } : {});
        if (opts.json) {
          out(JSON.stringify(rows, null, 2));
          return;
        }
        if (!rows.length) {
          out("No connected accounts. Connect one with: switchboard connect <provider>");
          return;
        }
        const head = ["ID", "PROVIDER", "LABEL", "STATUS", "IDENTITY", "EXPIRES", "DEFAULT"];
        out(
          table([
            head,
            ...rows.map((a) => [a.id, a.provider, a.label, a.status, a.identity.display_name ?? a.identity.external_id, when(a.expires_at), rt.accounts.defaultFor(a.provider)?.id === a.id ? "*" : ""]),
          ]),
        );
      } catch (err) {
        fail(err);
      }
    });

  accounts
    .command("show <ref>")
    .description("show one account (id, provider/label, or a unique label)")
    .option("--json", "machine readable")
    .action((ref: string, opts: { json?: boolean }) => {
      try {
        const rt = build(h);
        const a = summarize(rt.accounts.require(ref));
        if (opts.json) out(JSON.stringify(a, null, 2));
        else printAccount(a, rt.accounts.defaultFor(a.provider)?.id);
      } catch (err) {
        fail(err);
      }
    });

  accounts
    .command("default <ref>")
    .description("make this account the default for its provider")
    .action((ref: string) => {
      try {
        const a = build(h).accounts.setDefault(ref);
        out(`${a.provider}/${a.label} (${a.id}) is now the default ${a.provider} account`);
      } catch (err) {
        fail(err);
      }
    });

  accounts
    .command("disable <ref>")
    .description("refuse all use of an account but keep its credential")
    .action((ref: string) => {
      try {
        const a = build(h).accounts.disable(ref);
        out(`${a.provider}/${a.label} (${a.id}) is now ${a.status}. Re-enable with: switchboard accounts enable ${a.id}`);
      } catch (err) {
        fail(err);
      }
    });

  accounts
    .command("enable <ref>")
    .description("allow use of a disabled account again")
    .action((ref: string) => {
      try {
        const a = build(h).accounts.enable(ref);
        out(`${a.provider}/${a.label} (${a.id}) is now ${a.status}`);
      } catch (err) {
        fail(err);
      }
    });

  accounts
    .command("revoke <ref>")
    .description("revoke at the provider when it supports that, then delete the stored credential")
    .action(async (ref: string) => {
      try {
        const r = await build(h).accounts.revoke(ref);
        out(`${r.account.provider}/${r.account.label} (${r.account.id}) is now ${r.account.status}; the stored credential was deleted`);
        if (r.provider_revoked === true) out("The provider confirmed the revoke.");
        else if (r.provider_revoked === false) {
          out(`The provider-side revoke FAILED (${r.provider_error ?? "unknown error"}): the credential may still be valid at the provider until it expires. Revoke it in the provider's console too.`);
          process.exitCode = 1;
        } else out("This authentication has no provider-side revoke here: remove the grant in the provider's console if it should die now.");
      } catch (err) {
        fail(err);
      }
    });

  accounts
    .command("probe <ref>")
    .description("run the provider's identity probe with this account (refreshes once on a 401)")
    .option("--json", "machine readable")
    .action(async (ref: string, opts: { json?: boolean }) => {
      try {
        const rt = build(h);
        const target = rt.accounts.require(ref);
        const res = await rt.accounts.probe(target.id);
        if (opts.json) out(JSON.stringify({ ok: res.ok, status: res.status ?? null, identity: res.identity ?? null, error: res.error ?? null, account: res.account }, null, 2));
        else if (res.ok) out(`ok: ${res.account.provider}/${res.account.label} is ${res.identity?.display_name ?? res.identity?.external_id}`);
        else out(`FAILED: ${res.error ?? "probe failed"}`);
        if (!res.ok) process.exitCode = 1;
      } catch (err) {
        fail(err);
      }
    });

  // ── authconfig ─────────────────────────────────────────────────────────────────────────────────
  const authconfig = program.command("authconfig").description("register the OAuth apps (client ids and secret references) your connects use");

  authconfig
    .command("add <provider>")
    .description("register an OAuth app for a provider. Secrets are vault references, never values.")
    .option("--client-id-ref <ref>", "vault reference holding the client id")
    .option("--client-id <id>", "the client id itself (it is public)")
    .option("--client-secret-ref <ref>", "vault reference holding the client secret")
    .option("--auth <id>", "which authentication of the provider this app is for")
    .option("--scopes <list>", "default scopes for connects through this app")
    .option("--redirect-uri <url>", "an https redirect (a tunnel) to use instead of the loopback callback")
    .option("--label <text>", "a name for this app")
    .action((provider: string, opts: { clientIdRef?: string; clientId?: string; clientSecretRef?: string; auth?: string; scopes?: string; redirectUri?: string; label?: string }) => {
      try {
        const rt = build(h);
        const rec = rt.authConfigs.add({
          provider,
          ...(opts.auth ? { auth_id: opts.auth } : {}),
          ...(opts.label ? { label: opts.label } : {}),
          ...(opts.clientId ? { client_id: opts.clientId } : {}),
          ...(opts.clientIdRef ? { client_id_ref: opts.clientIdRef } : {}),
          ...(opts.clientSecretRef ? { client_secret_ref: opts.clientSecretRef } : {}),
          ...(opts.scopes ? { scopes: opts.scopes.split(",").map((s) => s.trim()).filter(Boolean) } : {}),
          ...(opts.redirectUri ? { redirect_uri: opts.redirectUri } : {}),
        });
        out(`auth config ${rec.id} saved for ${rec.provider}/${rec.auth_id} (secrets stay in the vault)`);
        out(`Connect with: switchboard connect ${rec.provider}${rt.authConfigs.list(rec.provider).length > 1 ? ` --auth-config ${rec.id}` : ""}`);
      } catch (err) {
        fail(err);
      }
    });

  authconfig
    .command("list")
    .description("list registered OAuth apps")
    .option("--provider <slug>", "only this provider")
    .option("--json", "machine readable")
    .action((opts: { provider?: string; json?: boolean }) => {
      try {
        const rows = build(h).authConfigs.list(opts.provider);
        if (opts.json) {
          out(JSON.stringify(rows, null, 2));
          return;
        }
        if (!rows.length) {
          out("No auth configs. Register one with: switchboard authconfig add <provider> --client-id-ref ... --client-secret-ref ...");
          return;
        }
        out(table([["ID", "PROVIDER", "AUTH", "CLIENT ID", "SECRET", "REDIRECT"], ...rows.map((c) => [c.id, c.provider, c.auth_id, c.client_id ?? c.client_id_ref ?? "-", c.client_secret_ref ?? "-", c.redirect_uri ?? "loopback"])]));
      } catch (err) {
        fail(err);
      }
    });

  authconfig
    .command("show <id>")
    .description("show one auth config")
    .action((id: string) => {
      try {
        const c = build(h).authConfigs.get(id);
        if (!c) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `no auth config '${id}'`);
        out(JSON.stringify(c, null, 2));
      } catch (err) {
        fail(err);
      }
    });

  authconfig
    .command("rm <id>")
    .description("remove an auth config (accounts connected through it keep working until they need the app again)")
    .action((id: string) => {
      try {
        out(build(h).authConfigs.remove(id) ? `removed ${id}` : `no auth config '${id}'`);
      } catch (err) {
        fail(err);
      }
    });

  // ── providers ──────────────────────────────────────────────────────────────────────────────────
  const providers = program.command("providers").description("the provider definitions (data) the connectors run on");

  providers
    .command("list")
    .description("list known providers and their authentications")
    .option("--json", "machine readable")
    .option("--seeds", "also list the seeded providers: unverified candidates that only enable Connect")
    .action((opts: { json?: boolean; seeds?: boolean }) => {
      try {
        const rt = build(h);
        const list = opts.seeds ? rt.providers.listAll() : rt.providers.list();
        const sourceOf = (slug: string): string => (rt.providers.isSeed(slug) ? "seed (unverified)" : rt.providers.isBundled(slug) ? "bundled" : "yours");
        if (opts.json) {
          out(JSON.stringify(list.map((p) => ({ slug: p.slug, name: p.name, toolkits: p.toolkits ?? [p.slug], auth: p.auth.map((a) => ({ id: a.id, mode: a.mode })), bundled: rt.providers.isBundled(p.slug), ...(rt.providers.isSeed(p.slug) ? { seed: true, verification: "unverified_seed" } : {}), docs_url: p.docs_url })), null, 2));
        } else {
          out(table([["PROVIDER", "TOOLKITS", "AUTHENTICATIONS", "SOURCE"], ...list.map((p) => [p.slug, (p.toolkits ?? [p.slug]).join(","), p.auth.map((a) => `${a.id}(${a.mode})${a.default ? "*" : ""}`).join(" "), sourceOf(p.slug)])]));
          out("\n* = what `switchboard connect` uses when you do not say otherwise");
          if (!opts.seeds) {
            const n = rt.providers.listSeeds().length;
            if (n) out(`${n} seeded providers (unverified candidates that only enable Connect, never counted as working) are not listed: add --seeds`);
          }
        }
        for (const issue of rt.providers.issues) {
          log.warn(`provider file ${issue.file} was ignored: ${issue.problems.join("; ")}`);
        }
        if (opts.seeds) for (const issue of rt.providers.seedIssues) log.warn(`seed file ${issue.file} was ignored: ${issue.problems.join("; ")}`);
      } catch (err) {
        fail(err);
      }
    });

  providers
    .command("show <slug>")
    .description("what you must set up at the provider, and how this build connects to it")
    .action((slug: string) => {
      try {
        const rt = build(h);
        const def = rt.providers.get(slug);
        if (!def) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `unknown provider '${slug}' (switchboard providers list)`);
        printProvider(def, h);
      } catch (err) {
        fail(err);
      }
    });
}

/** Everything the owner must set up at a provider, and how this build connects to it. */
function printProvider(def: ProviderDef, h: ConnectorCliHelpers): void {
  const { host, port } = h.gatewayAddress();
  const redirect = `http://${host}:${port}/oauth/callback`;
  out(`\n${def.name} (${def.slug})  toolkits: ${(def.toolkits ?? [def.slug]).join(", ")}`);
  out(`docs:     ${def.docs_url}`);
  out(`console:  ${def.owner_setup.console_url}`);
  out(`api hosts (the only places its credentials may go): ${def.api_hosts.join(", ")}`);
  out("\nsteps:");
  def.owner_setup.steps.forEach((s, i) => out(`  ${i + 1}. ${s}`));
  const uris = expandRedirect(def.owner_setup.redirect_uris, redirect);
  if (uris.length) out(`\nredirect URIs to register:\n${uris.map((u) => `  ${u}`).join("\n")}`);
  if (def.owner_setup.notes.length) out(`\nnotes:\n${def.owner_setup.notes.map((n) => `  - ${n}`).join("\n")}`);
  out("\nauthentications:");
  for (const a of def.auth) {
    const o = a.oauth2;
    out(`  ${a.id}  mode=${a.mode}${a.default ? "  (default)" : ""}${o ? `  pkce=${o.pkce} client_auth=${o.client_auth} redirect=${o.redirect} refresh=${o.refresh.kind}` : ""}`);
    if (o?.scope_catalog.length) out(`    scopes: ${o.scope_catalog.map((s) => (s.group ? `${s.scope} [@${s.group}]` : s.scope)).join(", ")}`);
  }
  out("");
}

// ── the connect action ──────────────────────────────────────────────────────────────────────────────

async function runConnect(h: ConnectorCliHelpers, provider: string, opts: ConnectOpts): Promise<void> {
  const rt = build(h);
  const def = rt.providers.get(provider);
  if (!def) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `unknown provider '${provider}' (switchboard providers list shows the known ones)`);
  const label = opts.account ?? "default";
  const scopes = opts.scopes ? opts.scopes.split(",").map((s) => s.trim()).filter(Boolean) : undefined;
  const hasTokenInput = Boolean(opts.tokenRef || opts.tokenStdin || opts.field?.length);

  let cfg = opts.authConfig ? rt.authConfigs.get(opts.authConfig) : undefined;
  if (opts.authConfig && !cfg) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `no auth config '${opts.authConfig}' (switchboard authconfig list)`);

  // Which authentication: an explicit --auth, else the auth config's, else (when you gave a token) the
  // token kind, else the one a registered app implies, else the provider's default.
  let auth: AuthDef | undefined;
  if (opts.auth) auth = def.auth.find((a) => a.id === opts.auth);
  else if (cfg) auth = def.auth.find((a) => a.id === cfg!.auth_id);
  else if (opts.import) auth = def.auth.find((a) => a.mode === "oauth2" || a.mode === "oauth2_cc");
  else if (hasTokenInput) auth = pickTokenAuth(def, undefined, rt);
  else {
    const registered = rt.authConfigs.forProvider(provider);
    auth = registered ? def.auth.find((a) => a.id === registered.auth_id) : rt.providers.defaultAuth(def);
  }
  if (!auth) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `${provider} has no matching authentication (switchboard providers show ${provider})`);
  if (!cfg && (auth.mode === "oauth2" || auth.mode === "oauth2_cc")) cfg = rt.authConfigs.forProvider(provider, { auth_id: auth.id });

  let account;
  if (auth.mode === "oauth2" && !opts.import) {
    account = await browserFlow(h, rt, def, auth, label, cfg?.id, scopes);
    if (!account) return;
  } else if (auth.mode === "oauth2" && opts.import) {
    const access = await collectSingle(rt, opts, "access token");
    const refresh = opts.refreshTokenRef ? rt.authConfigs.resolveSecretInput(opts.refreshTokenRef, "refresh token") : undefined;
    const expires = opts.expiresIn ? Number(opts.expiresIn) : undefined;
    if (expires !== undefined && !(expires > 0)) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, "--expires-in must be a number of seconds");
    ({ account } = await rt.flows.importToken({ provider, authId: auth.id, ...(cfg ? { authConfigId: cfg.id } : {}), label, access_token: access, ...(refresh ? { refresh_token: refresh } : {}), ...(expires ? { expires_in: expires } : {}), ...(scopes ? { scopes } : {}) }));
  } else if (auth.mode === "oauth2_cc") {
    ({ account } = await rt.flows.connectClientCredentials({ provider, authId: auth.id, ...(cfg ? { authConfigId: cfg.id } : {}), label, ...(scopes ? { scopes } : {}) }));
  } else if (auth.mode === "bearer" || auth.mode === "api_key" || auth.mode === "basic") {
    const fields = await collectFields(rt, auth, opts);
    ({ account } = await rt.flows.connectSecret({ provider, authId: auth.id, label, fields }));
  } else {
    throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `authentication '${auth.id}' of ${provider} uses mode '${auth.mode}', which this build does not drive`);
  }

  const sum = summarize(account);
  if (opts.json) {
    out(JSON.stringify(sum, null, 2));
    return;
  }
  out(`\nconnected ${sum.provider}/${sum.label}  ${sum.id}  ${sum.status}`);
  out(`  identity  ${sum.identity.display_name ?? sum.identity.external_id}${def.identity_probe ? "  (probe passed)" : "  (this provider defines no identity probe: the credential was stored but NOT verified)"}`);
  if (sum.expires_at) out(`  expires   ${when(sum.expires_at)}`);
  out(`  show it   switchboard accounts show ${sum.id}`);
}

/** The named fields of a token-style authentication, from references, stdin or a hidden prompt. */
async function collectFields(rt: Connectors, auth: AuthDef, opts: ConnectOpts): Promise<Record<string, string>> {
  const declared = auth.fields.connected_account_initiation;
  const fields: Record<string, string> = {};
  for (const spec of opts.field ?? []) {
    const eq = spec.indexOf("=");
    if (eq < 1) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, "--field must look like name=<vault reference>");
    const name = spec.slice(0, eq);
    fields[name] = rt.authConfigs.resolveSecretInput(spec.slice(eq + 1), `field '${name}'`);
  }
  const first = declared[0];
  if (first && fields[first.name] === undefined) {
    if (opts.tokenRef) fields[first.name] = rt.authConfigs.resolveSecretInput(opts.tokenRef, "token");
    else if (opts.tokenStdin || (!process.stdin.isTTY && declared.length === 1 && !(opts.field?.length))) {
      const v = await readStdin();
      if (v) fields[first.name] = v;
    }
  }
  for (const f of declared) {
    if (!f.required || fields[f.name] !== undefined) continue;
    if (!process.stdin.isTTY) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `${f.name} is required: pass --token-ref, --token-stdin or --field ${f.name}=<vault reference>`);
    const v = await promptHidden(`${f.label ?? f.name} (input hidden): `);
    if (!v) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `no value entered for ${f.name}; nothing was saved`);
    fields[f.name] = v;
  }
  return fields;
}

async function collectSingle(rt: Connectors, opts: ConnectOpts, what: string): Promise<string> {
  if (opts.tokenRef) return rt.authConfigs.resolveSecretInput(opts.tokenRef, what);
  if (opts.tokenStdin || !process.stdin.isTTY) {
    const v = await readStdin();
    if (v) return v;
  } else {
    const v = await promptHidden(`${what} (input hidden): `);
    if (v) return v;
  }
  throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `no ${what} given: pass --token-ref or --token-stdin`);
}

/** The browser authorization flow: print the URL, catch the loopback callback, finish. Returns undefined when it did not connect. */
async function browserFlow(h: ConnectorCliHelpers, rt: Connectors, def: ProviderDef, auth: AuthDef, label: string, authConfigId: string | undefined, scopes: string[] | undefined) {
  const { host, port } = h.gatewayAddress();
  const redirectUri = `http://${host}:${port}/oauth/callback`;
  const begin = rt.flows.begin({ provider: def.slug, authId: auth.id, ...(authConfigId ? { authConfigId } : {}), label, redirectUri, ...(scopes ? { scopes } : {}) });
  out(`\nOpen this URL in your browser to authorize ${def.name}:\n\n  ${begin.authorizeUrl}\n\nWaiting for the callback (up to ${PENDING_TTL_MS / 60000} minutes). Ctrl-C cancels and stores nothing.`);
  const startedAt = Date.now();

  type Done = { kind: "connected"; account: Awaited<ReturnType<typeof rt.flows.complete>>["account"] } | { kind: "failed"; message: string } | { kind: "other-process" } | { kind: "timeout" };
  const result = await new Promise<Done>((resolve) => {
    let settled = false;
    const finish = (d: Done, server?: ReturnType<typeof createServer>): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      process.off("SIGINT", onSigint);
      if (server) server.close(() => resolve(d));
      else resolve(d);
    };
    const onSigint = (): void => {
      rt.flows.cancel(begin.state);
      finish({ kind: "failed", message: "cancelled" }, server);
    };
    const timer = setTimeout(() => {
      rt.flows.cancel(begin.state);
      finish({ kind: "timeout" }, server);
    }, PENDING_TTL_MS + 1000);
    process.once("SIGINT", onSigint);

    const server = createServer((req, res) => {
      const url = new URL(req.url ?? "/", `http://${host}:${port}`);
      if (url.pathname !== "/oauth/callback") {
        res.writeHead(404).end("not found");
        return;
      }
      const state = url.searchParams.get("state") ?? "";
      const code = url.searchParams.get("code") ?? "";
      const error = url.searchParams.get("error") ?? "";
      if (state !== begin.state) {
        res.writeHead(400, { "content-type": "text/html" }).end("<h1>Unknown authorization.</h1>");
        return;
      }
      void (async () => {
        try {
          if (error) {
            rt.flows.cancel(state);
            throw new ConnectorError(CONNECTOR_ERR.CONNECT_FAILED, `the provider returned: ${error.slice(0, 80)}`);
          }
          if (!code) throw new ConnectorError(CONNECTOR_ERR.CONNECT_FAILED, "missing 'code' in the callback");
          const { account } = await rt.flows.complete(state, code);
          res.writeHead(200, { "content-type": "text/html" }).end("<h1>Connected. You can close this tab.</h1>");
          finish({ kind: "connected", account }, server);
        } catch (err) {
          res.writeHead(400, { "content-type": "text/html" }).end("<h1>Authorization failed.</h1>");
          finish({ kind: "failed", message: err instanceof Error ? err.message : String(err) }, server);
        }
      })();
    });
    server.on("error", (err) => {
      if ((err as NodeJS.ErrnoException).code !== "EADDRINUSE") {
        rt.flows.cancel(begin.state);
        finish({ kind: "failed", message: err.message });
        return;
      }
      // A gateway or dashboard already serves this port: it will receive the callback and finish the flow
      // (the pending state is on disk). Wait for it to be consumed.
      out(`Port ${port} is served by a running gateway: it will complete the flow. Waiting for it...`);
      const poll = setInterval(() => {
        if (settled) {
          clearInterval(poll);
          return;
        }
        if (!rt.flows.isPending(begin.state)) {
          clearInterval(poll);
          finish({ kind: "other-process" });
        }
      }, 1000);
    });
    server.listen(port, host);
  });

  if (result.kind === "connected") return result.account;
  if (result.kind === "other-process") {
    const found = rt.accounts.list({ provider: def.slug }).find((a) => a.label === begin.label && Date.parse(a.connected_at) >= startedAt - 1000);
    if (found) return found;
    throw new ConnectorError(CONNECTOR_ERR.CONNECT_FAILED, "the authorization finished without connecting an account (it was refused, denied or failed its identity probe: see the gateway log). Nothing was stored.");
  }
  if (result.kind === "timeout") throw new ConnectorError(CONNECTOR_ERR.CONNECT_FAILED, "no callback arrived within 10 minutes; nothing was stored");
  throw new ConnectorError(CONNECTOR_ERR.CONNECT_FAILED, `${result.message}. Nothing was stored.`);
}
