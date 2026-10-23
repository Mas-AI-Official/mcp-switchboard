/**
 * AuthConfig records (ADR local-composio, 6.1 and 6.2): which OAuth app (or key) a provider uses.
 *
 * An AuthConfig never holds a secret. The client secret is a reference into the vault (`${vault:name}`)
 * or the environment (`${env:NAME}`); the client id may be a reference or, because an id is public, a
 * literal. `add` refuses a reference that is not a stored vault secret, so a secret pasted into the wrong
 * flag is rejected instead of being written to disk as a "name".
 *
 * Compatibility: before connectors existed the convention was the vault names
 * `oauth_<provider>_client_id` and `oauth_<provider>_client_secret`. When a provider has no AuthConfig
 * but the vault has `oauth_<provider>_client_id`, a virtual config `legacy:<provider>` stands in for it,
 * so existing installs keep connecting without any migration step.
 */

import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { WatchedJsonFile } from "../atomicfile.js";
import type { Vault } from "../vault.js";
import type { AuthConfig, AuthDef, ProviderDef } from "./types.js";
import type { ProviderRegistry } from "./providers.js";
import { CONNECTOR_ERR, ConnectorError } from "./errors.js";

interface AuthConfigFile {
  version: 1;
  configs: Record<string, AuthConfig>;
}

const REF_FORM = /^\$\{(vault|env):([A-Za-z0-9_.-]{1,64})\}$/;
const BARE_NAME = /^[A-Za-z0-9_.-]{1,64}$/;
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** A short random id such as `ac_7KQ2M9XD`, from an alphabet without look-alike characters. */
export function newId(prefix: string, length: number): string {
  const bytes = randomBytes(length);
  let s = "";
  for (let i = 0; i < length; i++) s += CROCKFORD[bytes[i]! % 32];
  return `${prefix}_${s}`;
}

function fileShape(value: unknown): string | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return "expected a JSON object";
  const configs = (value as { configs?: unknown }).configs;
  if (typeof configs !== "object" || configs === null || Array.isArray(configs)) return "expected a 'configs' object";
  return null;
}

/** Normalise a reference to `${vault:x}` / `${env:X}`; a bare name means a vault secret. Null if it is neither. */
export function normalizeRef(input: string): string | null {
  const t = input.trim();
  const m = REF_FORM.exec(t);
  if (m) return `\${${m[1]}:${m[2]}}`;
  if (BARE_NAME.test(t)) return `\${vault:${t}}`;
  return null;
}

export interface AddAuthConfigInput {
  provider: string;
  /** Which of the provider's auth definitions; default: the first oauth2 / oauth2_cc one. */
  auth_id?: string;
  label?: string;
  client_id?: string;
  client_id_ref?: string;
  client_secret_ref?: string;
  scopes?: string[];
  redirect_uri?: string;
}

export class AuthConfigStore {
  private readonly file: WatchedJsonFile<AuthConfigFile>;

  constructor(
    home: string,
    private readonly providers: ProviderRegistry,
    private readonly vault: Vault,
    private readonly now: () => number = Date.now,
  ) {
    this.file = new WatchedJsonFile<AuthConfigFile>(join(home, "connectors", "authconfigs.json"), () => ({ version: 1, configs: {} }), {
      validate: fileShape,
      mode: 0o600,
    });
  }

  list(provider?: string): AuthConfig[] {
    const all = Object.values(this.file.get().configs).sort((a, b) => a.created.localeCompare(b.created));
    return provider ? all.filter((c) => c.provider === provider) : all;
  }

  get(id: string): AuthConfig | undefined {
    if (id.startsWith("legacy:")) return this.legacy(id.slice("legacy:".length));
    return this.file.get().configs[id];
  }

  /** The virtual config for the old vault-name convention, when the vault has that client id. */
  legacy(provider: string): AuthConfig | undefined {
    const def = this.providers.get(provider);
    if (!def) return undefined;
    const auth = def.auth.find((a) => a.mode === "oauth2");
    if (!auth) return undefined;
    let has = false;
    try {
      has = Boolean(this.vault.get(`oauth_${provider}_client_id`));
    } catch {
      has = false;
    }
    if (!has) return undefined;
    return {
      id: `legacy:${provider}`,
      provider,
      auth_id: auth.id,
      mode: "oauth2",
      client_id_ref: `\${vault:oauth_${provider}_client_id}`,
      client_secret_ref: `\${vault:oauth_${provider}_client_secret}`,
      created: new Date(0).toISOString(),
    };
  }

  /**
   * The config a connect for `provider` should use: an explicit id, else the first stored one for the
   * provider (and the named auth definition when given), else the legacy virtual config.
   */
  forProvider(provider: string, opts: { id?: string; auth_id?: string } = {}): AuthConfig | undefined {
    if (opts.id) return this.get(opts.id);
    const stored = this.list(provider).filter((c) => !opts.auth_id || c.auth_id === opts.auth_id);
    if (stored.length) return stored[0];
    const legacy = this.legacy(provider);
    if (legacy && (!opts.auth_id || legacy.auth_id === opts.auth_id)) return legacy;
    return undefined;
  }

  add(input: AddAuthConfigInput): AuthConfig {
    const def = this.providers.get(input.provider);
    if (!def) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `unknown provider '${input.provider}' (switchboard providers list shows the known ones)`);
    const auth = this.pickAuth(def, input.auth_id);
    if (auth.mode !== "oauth2" && auth.mode !== "oauth2_cc") {
      throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `auth '${auth.id}' of ${def.slug} is '${auth.mode}', which has no OAuth app to configure: connect it with a token or key instead`);
    }
    if (Boolean(input.client_id) === Boolean(input.client_id_ref)) {
      throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, "give exactly one of --client-id (the public id) or --client-id-ref (a vault reference)");
    }
    const rec: AuthConfig = {
      id: newId("ac", 8),
      provider: def.slug,
      auth_id: auth.id,
      mode: auth.mode,
      created: new Date(this.now()).toISOString(),
    };
    if (input.label) rec.label = input.label;
    if (input.client_id) {
      if (!/^[A-Za-z0-9._~:/+=@-]{3,256}$/.test(input.client_id)) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, "the client id has characters a client id never has; pass a secret as a vault reference, not here");
      rec.client_id = input.client_id;
    }
    if (input.client_id_ref) rec.client_id_ref = this.checkedRef("client id", input.client_id_ref);
    const secretRequired = auth.fields.auth_config_creation.some((f) => f.name === "client_secret" && f.required);
    if (input.client_secret_ref) rec.client_secret_ref = this.checkedRef("client secret", input.client_secret_ref);
    else if (secretRequired) {
      throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `${def.slug} needs a client secret: pass --client-secret-ref <vault name> (store it first with: switchboard vault set <name>)`);
    }
    if (input.scopes?.length) rec.scopes = [...input.scopes];
    if (input.redirect_uri) {
      let u: URL;
      try {
        u = new URL(input.redirect_uri);
      } catch {
        throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, "--redirect-uri is not a valid URL");
      }
      if (u.protocol !== "https:" && !(u.protocol === "http:" && ["127.0.0.1", "localhost", "[::1]"].includes(u.hostname))) {
        throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, "--redirect-uri must be https (or a loopback http URL)");
      }
      if (u.username || u.password || u.hash) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, "--redirect-uri must not contain credentials or a fragment");
      rec.redirect_uri = u.href;
    }
    this.file.update((cur) => ({ ...cur, version: 1, configs: { ...cur.configs, [rec.id]: rec } }));
    return rec;
  }

  remove(id: string): boolean {
    let existed = false;
    this.file.update((cur) => {
      if (!cur.configs[id]) return undefined;
      existed = true;
      const configs = { ...cur.configs };
      delete configs[id];
      return { ...cur, configs };
    });
    return existed;
  }

  /**
   * The app credentials for a config, resolved from the vault or environment. A client id that cannot be
   * resolved is always an error with the fix. A client secret that cannot be resolved is an error for an
   * explicit config; for the legacy virtual config it is simply absent, because the old convention allowed
   * providers whose secret is optional (the exchange reports a missing secret if one is actually needed).
   */
  resolveClient(cfg: AuthConfig): { clientId: string; clientSecret?: string } {
    const clientId = cfg.client_id ?? this.resolveRef(cfg.client_id_ref, "client id", cfg);
    if (!clientId) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `auth config ${cfg.id} has no client id`);
    let clientSecret: string | undefined;
    if (cfg.client_secret_ref) {
      try {
        clientSecret = this.resolveRef(cfg.client_secret_ref, "client secret", cfg);
      } catch (err) {
        if (!cfg.id.startsWith("legacy:")) throw err;
      }
    }
    return { clientId, ...(clientSecret ? { clientSecret } : {}) };
  }

  private resolveRef(ref: string | undefined, what: string, cfg: AuthConfig): string {
    if (!ref) return "";
    try {
      return this.vault.resolve(ref);
    } catch {
      const m = REF_FORM.exec(ref);
      const fix = m?.[1] === "vault" ? `run: switchboard vault set ${m[2]}` : `set the environment variable ${m?.[2] ?? ""}`;
      throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `the ${what} for auth config ${cfg.id} (${cfg.provider}) is not available: ${fix}`, { provider: cfg.provider });
    }
  }

  private pickAuth(def: ProviderDef, id?: string): AuthDef {
    if (id) {
      const a = def.auth.find((x) => x.id === id);
      if (!a) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `provider ${def.slug} has no auth '${id}' (it has: ${def.auth.map((x) => x.id).join(", ")})`);
      return a;
    }
    const oauth = def.auth.find((x) => x.mode === "oauth2") ?? def.auth.find((x) => x.mode === "oauth2_cc");
    if (!oauth) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `provider ${def.slug} has no OAuth auth definition to configure`);
    return oauth;
  }

  /**
   * The value behind a reference typed on a command line (`--token-ref`, `--field name=ref`). Only a stored
   * vault secret or a set environment variable resolves; anything else is refused WITHOUT echoing it, so a
   * secret pasted where a reference belongs does not land in the terminal log or in an error.
   */
  resolveSecretInput(input: string, what = "secret"): string {
    const ref = normalizeRef(input);
    const bad = () =>
      new ConnectorError(
        CONNECTOR_ERR.CONNECTOR_CONFIG,
        `the ${what} reference is not a stored vault secret or a set environment variable. Store the value first with: switchboard vault set <name>, then pass that name (or \${vault:<name>} or \${env:NAME}); or pipe it in with --token-stdin. Nothing was saved.`,
      );
    if (!ref) throw bad();
    try {
      const v = this.vault.resolve(ref);
      if (!v.trim()) throw bad();
      return v;
    } catch (err) {
      if (err instanceof ConnectorError) throw err;
      throw bad();
    }
  }

  /** Accept only a stored vault secret or an `${env:}` reference; never write an unverified string to disk. */
  private checkedRef(what: string, input: string): string {
    const ref = normalizeRef(input);
    const fail = () =>
      new ConnectorError(
        CONNECTOR_ERR.CONNECTOR_CONFIG,
        `the ${what} reference is not a stored vault secret. Store the value first with: switchboard vault set <name>, then pass that name (or \${vault:<name>} or \${env:NAME}). Nothing was saved.`,
      );
    if (!ref) throw fail();
    const m = REF_FORM.exec(ref)!;
    if (m[1] === "vault") {
      let present = false;
      try {
        present = this.vault.get(m[2]!) !== undefined;
      } catch {
        present = false;
      }
      if (!present) throw fail();
    }
    return ref;
  }
}
