/**
 * clientadmin.ts: create, change, rotate and remove registered clients (design 3.1).
 *
 * One implementation behind both owner channels: `switchboard client ...` (the CLI, which has a config file and
 * the key stores but no running gateway) and the dashboard's /api/clients (the live gateway). A client is two
 * things that must stay in step: an entry under `clients:` in the config file, and keys in the API key store
 * bound to it, one of which is mirrored into `<SWITCHBOARD_HOME>/clients/<id>.key` for the bridge.
 *
 * The token exists only inside this module's return value and the key file. Callers decide whether to show it
 * (the CLI does with `--print`; the admin API never does).
 */

import { existsSync } from "node:fs";
import type { ApiKeyStore, PublicApiKey } from "./apikeys.js";
import { audit } from "./audit.js";
import { log } from "./logger.js";
import { ClientConfigWatcher, deleteClientEntry, editConfigFile, writeClientEntry } from "./clientconfig.js";
import { clientKeyPath, readClientKey, removeClientKey, writeClientKey } from "./clientkeys.js";
import { parseClientEntry } from "./config.js";
import { BAD_CLIENT_ID, isValidClientId } from "./principal.js";
import type { ClientConfig, SwitchboardConfig } from "./types.js";

/** The fields of a client an owner may set. Anything omitted keeps its current value (or the default for a new client). */
export type ClientSpec = Partial<ClientConfig>;

/** What a new client gets when the owner names nothing: every server, read only, low risk. Least privilege. */
export const NEW_CLIENT_DEFAULTS = { servers: ["*"], max_scope: "read", max_risk: "low" } as const;

export interface ClientSummary {
  id: string;
  config: ClientConfig;
  keys: PublicApiKey[];
  /** Whether `<SWITCHBOARD_HOME>/clients/<id>.key` exists (the bridge can authenticate as this client). */
  key_file: boolean;
}

export interface ClientAdminOptions {
  /** The configuration the caller works on: the live one in the gateway, the loaded one in the CLI. */
  cfg: SwitchboardConfig;
  /** The config file to persist to. Omitted = the clients map is changed in memory only. */
  configPath?: string;
  apiKeys: ApiKeyStore;
  /** The gateway's watcher, so an edit is visible at once; one is made when omitted. */
  watcher?: ClientConfigWatcher;
  /** Who is acting, for the audit row of each change: "cli" or "dashboard". Default "cli". */
  actor?: string;
}

export class ClientAdminError extends Error {
  constructor(
    message: string,
    readonly status: 400 | 404 | 409 | 500 = 400,
  ) {
    super(message);
    this.name = "ClientAdminError";
  }
}

export class ClientAdmin {
  private readonly cfg: SwitchboardConfig;
  private readonly configPath?: string;
  private readonly apiKeys: ApiKeyStore;
  private readonly watcher: ClientConfigWatcher;
  private readonly actor: string;

  constructor(opts: ClientAdminOptions) {
    this.actor = opts.actor ?? "cli";
    this.cfg = opts.cfg;
    this.configPath = opts.configPath;
    this.apiKeys = opts.apiKeys;
    this.watcher = opts.watcher ?? new ClientConfigWatcher(opts.cfg, opts.configPath);
  }

  /** The clients as they are now (the file is consulted first, so a CLI edit made a moment ago is included). */
  private clients(): Record<string, ClientConfig> {
    this.watcher.sync();
    return this.cfg.clients ?? {};
  }

  /**
   * One audit row per change to who may call the gateway (a client added, changed, rotated or removed), so a
   * policy change leaves a trace in the tamper-evident log. Never carries a token. A failing audit write costs the
   * row (logged), never the change the owner asked for.
   */
  private record(action: string, id: string, reason: string): void {
    try {
      audit({ server: "switchboard", tool: `client.${action}`, scope: "full", decision: "allow", reason: `client '${id}' ${reason}`, principal: `owner:${this.actor}` });
    } catch (err) {
      log.error(`audit write failed for client.${action} '${id}': ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  private requireId(id: string): void {
    if (!isValidClientId(id)) throw new ClientAdminError(BAD_CLIENT_ID, 400);
  }

  private validate(id: string, raw: unknown): ClientConfig {
    try {
      return parseClientEntry(id, raw);
    } catch (err) {
      throw new ClientAdminError(err instanceof Error ? err.message : String(err), 400);
    }
  }

  /** Persist `entry` as client `id` (or remove it when null), then make the running config match. */
  private commit(id: string, entry: ClientConfig | null): void {
    if (this.configPath) {
      try {
        editConfigFile(this.configPath, (doc) => (entry ? writeClientEntry(doc, id, entry) : deleteClientEntry(doc, id)));
      } catch (err) {
        throw new ClientAdminError(err instanceof Error ? err.message : String(err), 400);
      }
      this.watcher.sync();
      return;
    }
    const next = { ...(this.cfg.clients ?? {}) };
    if (entry) next[id] = entry;
    else delete next[id];
    if (Object.keys(next).length > 0) this.cfg.clients = next;
    else delete this.cfg.clients;
  }

  list(): { clients: ClientSummary[]; orphan_keys: PublicApiKey[] } {
    const clients = this.clients();
    const keys = this.apiKeys.list();
    return {
      clients: Object.keys(clients)
        .sort()
        .map((id) => ({
          id,
          config: clients[id]!,
          keys: keys.filter((k) => k.client === id),
          key_file: existsSync(clientKeyPath(id)),
        })),
      orphan_keys: keys.filter((k) => k.client !== undefined && !Object.prototype.hasOwnProperty.call(clients, k.client)),
    };
  }

  /**
   * Create the client, or update the fields given when it exists, and make sure it has a working key: a new key
   * is issued unless the stored key file already holds a token the key store accepts for this client (so running
   * `add` twice does not strand a working key). Returns the token only when a key was issued.
   */
  add(id: string, spec: ClientSpec = {}): { created: boolean; client: ClientConfig; keyKept: boolean; token?: string; key?: PublicApiKey; revoked: number; keyFile: string } {
    this.requireId(id);
    const current = this.clients()[id];
    const base: ClientSpec = current ? current : { ...NEW_CLIENT_DEFAULTS, servers: [...NEW_CLIENT_DEFAULTS.servers] };
    const merged: Record<string, unknown> = { ...base };
    for (const [k, v] of Object.entries(spec)) if (v !== undefined) merged[k] = v;
    const client = this.validate(id, merged);
    this.commit(id, client);

    let keyKept = false;
    if (this.apiKeys.list().some((k) => k.client === id)) {
      try {
        const stored = readClientKey(id);
        keyKept = stored !== null && this.apiKeys.inspect(stored)?.client === id;
      } catch {
        keyKept = false; // unreadable or foreign key file: replace it
      }
    }
    const keyFile = clientKeyPath(id);
    if (keyKept) {
      this.record("add", id, `${current ? "updated" : "created"}, existing key kept`);
      return { created: !current, client, keyKept: true, revoked: 0, keyFile };
    }
    const issued = this.issue(id);
    this.record("add", id, `${current ? "updated" : "created"}, key ${issued.record.id} issued${issued.revoked ? `, ${issued.revoked} earlier key(s) revoked` : ""}`);
    return { created: !current, client, keyKept: false, token: issued.token, key: issued.record, revoked: issued.revoked, keyFile };
  }

  /** Change fields of an existing client (`null` clears an optional field). The keys are untouched. */
  update(id: string, spec: Record<string, unknown>): ClientConfig {
    this.requireId(id);
    const current = this.clients()[id];
    if (!current) throw new ClientAdminError(`no client '${id}'`, 404);
    const merged: Record<string, unknown> = { ...current };
    for (const [k, v] of Object.entries(spec)) {
      if (v === null) delete merged[k]; // null clears an optional field
      else if (v !== undefined) merged[k] = v;
    }
    const client = this.validate(id, merged);
    this.commit(id, client);
    this.record("update", id, `changed (${Object.keys(spec).join(", ") || "nothing"})`);
    return client;
  }

  /** Issue a fresh key for an existing client; every earlier key of it stops working at once. */
  rotate(id: string): { token: string; key: PublicApiKey; revoked: number; keyFile: string } {
    this.requireId(id);
    if (!this.clients()[id]) throw new ClientAdminError(`no client '${id}': add it first with \`switchboard client add ${id}\``, 404);
    const issued = this.issue(id);
    this.record("rotate", id, `key rotated, new key ${issued.record.id}, ${issued.revoked} earlier key(s) revoked`);
    return { token: issued.token, key: issued.record, revoked: issued.revoked, keyFile: clientKeyPath(id) };
  }

  /**
   * Revoke the client's keys and delete its key file. The config entry stays unless `purge` (the entry without
   * a key is harmless: nobody can authenticate as it). Idempotent; an unknown client with leftovers is cleaned.
   */
  remove(id: string, opts: { purge?: boolean } = {}): { revokedKeys: number; keyFileRemoved: boolean; purged: boolean } {
    this.requireId(id);
    const exists = Object.prototype.hasOwnProperty.call(this.clients(), id);
    const revokedKeys = this.apiKeys.revokeClientKeys(id);
    const keyFileRemoved = removeClientKey(id);
    if (!exists && revokedKeys === 0 && !keyFileRemoved) throw new ClientAdminError(`no client '${id}'`, 404);
    let purged = false;
    if (opts.purge && exists) {
      this.commit(id, null);
      purged = true;
    }
    this.record("remove", id, `removed: ${revokedKeys} key(s) revoked, key file ${keyFileRemoved ? "deleted" : "absent"}${purged ? ", config entry purged" : ", config entry kept"}`);
    return { revokedKeys, keyFileRemoved, purged };
  }

  /** Issue a key bound to the client and mirror it into the key file; undo the issue if the file cannot be written. */
  private issue(id: string): { token: string; record: PublicApiKey; revoked: number } {
    const issued = this.apiKeys.replaceClientKeys(id, `client:${id}`);
    try {
      writeClientKey(id, issued.token);
    } catch (err) {
      this.apiKeys.revokeClientKeys(id); // the token is unrecoverable now; do not leave it valid
      throw new ClientAdminError(`could not store the key for client '${id}': ${err instanceof Error ? err.message : String(err)}`, 500);
    }
    return issued;
  }
}
