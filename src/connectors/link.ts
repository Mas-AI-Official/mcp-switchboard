/**
 * `switchboard link | unlink | links`: the connector view of the clients config (pure planning, no I/O).
 *
 * There is no link table. A client's access to a toolkit is an entry in its `servers` (the id of the toolkit's
 * `source: connector` server), its ceilings are `max_scope` and `max_risk`, and the account it uses is
 * `accounts: { <provider>: <account id> }`: the same `clients:` section `switchboard client` edits, through the same
 * ClientAdmin (so a running gateway shows the owner the exact grant in its presence prompt, and the audit row says
 * who proved it). These functions turn a link request into the `ClientSpec` that ClientAdmin applies, and a clients
 * map into the rows `links` prints. Nothing here writes a file.
 */

import type { ClientSpec } from "../clientadmin.js";
import { globMatch } from "../principal.js";
import type { ClientConfig, Risk, Scope, SwitchboardConfig } from "../types.js";

const own = (o: object | undefined, k: string): boolean => o !== undefined && Object.prototype.hasOwnProperty.call(o, k);

/**
 * The connector servers a `link` target names (`*`: every connector server). The target is a toolkit slug or a connector
 * server id, resolved in this order so a link grants the least that matches:
 *   1. a configured connector server whose id IS the target (the default `toolkits enable` id, or a custom one): that one only;
 *   2. else every configured connector server of that toolkit (a toolkit mounted under other ids, such as a second mount
 *      pinned to another account, is reached by naming its server id, never by the toolkit slug);
 *   3. else the target itself, the id `switchboard toolkits enable` will give it, so a client can be linked before the
 *      toolkit is switched on.
 */
export function connectorServerIds(cfg: Pick<SwitchboardConfig, "servers">, target: string): string[] {
  const connectors = cfg.servers.filter((s) => s.source === "connector");
  if (target === "*") return connectors.map((s) => s.id);
  const exact = connectors.filter((s) => s.id === target);
  if (exact.length > 0) return exact.map((s) => s.id);
  const byToolkit = connectors.filter((s) => s.toolkit === target).map((s) => s.id);
  return byToolkit.length > 0 ? byToolkit : [target];
}

export interface LinkRequest {
  maxScope?: Scope;
  maxRisk?: Risk;
  /** The provider of the toolkit and the connected account (an id) this client should use for it. */
  account?: { provider: string; ref: string };
}

export interface LinkPlan {
  /** The fields to apply with `ClientAdmin.add(client, spec)`. */
  spec: ClientSpec;
  /** The connector server ids the client may use for this toolkit after the change. */
  serverIds: string[];
  /** Server ids that were not yet allowed and are added. */
  added: string[];
  /** The client does not exist yet: it is created (at read scope and low risk unless a flag says otherwise) with a key. */
  created: boolean;
  /** The toolkit has no connector server in the config yet (the id is a prediction). */
  noServer: boolean;
}

/** What `link <client> <toolkit>` changes in the clients config. A new client starts at the least privilege: only this toolkit, read scope, low risk. */
export function planLink(cfg: Pick<SwitchboardConfig, "servers" | "clients">, client: string, toolkit: string, req: LinkRequest = {}): LinkPlan {
  const ids = connectorServerIds(cfg, toolkit);
  if (ids.length === 0) throw new Error("no connector server is configured: turn a toolkit on first (`switchboard toolkits enable <toolkit>`)");
  const current = own(cfg.clients, client) ? cfg.clients![client] : undefined;
  const have = current?.servers ?? [];
  const added = ids.filter((id) => !have.some((g) => globMatch(g, id)));
  const spec: ClientSpec = {};
  // A new client must name its servers: the default of `client add` (every server) is wider than a link means.
  if (!current || added.length > 0) spec.servers = [...have, ...added];
  if (req.maxScope) spec.max_scope = req.maxScope;
  if (req.maxRisk) spec.max_risk = req.maxRisk;
  if (req.account) spec.accounts = { ...(current?.accounts ?? {}), [req.account.provider]: req.account.ref };
  const noServer = toolkit !== "*" && !cfg.servers.some((s) => s.source === "connector" && (s.toolkit === toolkit || s.id === toolkit));
  return { spec, serverIds: ids, added, created: !current, noServer };
}

export interface UnlinkPlan {
  spec: ClientSpec;
  /** Exact `servers` entries removed. */
  removed: string[];
  /** Entries that still cover a connector server (a glob such as `*`), which `unlink` cannot narrow. */
  stillCovered: string[];
  /** Whether the client's account bindings are cleared (a full unlink only). */
  clearsAccounts: boolean;
}

/**
 * What `unlink <client> [toolkit]` changes: the toolkit's server ids leave `servers` (or all connector servers, and the
 * account bindings, when no toolkit is named). The client itself and its key stay: `switchboard client rm` removes those.
 * `knownToolkits` (the slugs the toolkit store knows) lets a full unlink also take off a link made before the toolkit
 * had a server.
 */
export function planUnlink(cfg: Pick<SwitchboardConfig, "servers" | "clients">, client: string, toolkit?: string, knownToolkits: readonly string[] = []): UnlinkPlan | undefined {
  if (!own(cfg.clients, client)) return undefined;
  const current = cfg.clients![client]!;
  // Every connector server in the config, and (for a full unlink) the default server id of each known toolkit that has
  // no server of that id yet: a client may have been linked before its toolkit was switched on (`planLink` predicts the id).
  const ids = connectorServerIds(cfg, toolkit ?? "*");
  if (toolkit === undefined) for (const slug of knownToolkits) if (!ids.includes(slug) && !cfg.servers.some((s) => s.id === slug)) ids.push(slug);
  const removed = current.servers.filter((g) => ids.includes(g));
  const keep = current.servers.filter((g) => !ids.includes(g));
  const stillCovered = keep.filter((g) => ids.some((id) => globMatch(g, id)));
  const clearsAccounts = toolkit === undefined && Object.keys(current.accounts ?? {}).length > 0;
  if (removed.length === 0 && !clearsAccounts) return { spec: {}, removed, stillCovered, clearsAccounts };
  const spec: ClientSpec = {};
  if (removed.length > 0) spec.servers = keep;
  if (clearsAccounts) spec.accounts = {};
  return { spec, removed, stillCovered, clearsAccounts };
}

export interface LinkRow {
  client: string;
  /** The client's `servers` entries exactly as configured (ids and globs): what it may see and call. */
  servers: string;
  max_scope: string;
  max_risk: string;
  accounts: string;
}

/** The `links` table: each client's `servers`, ceilings and account bindings, exactly as the clients config says. */
export function linkRows(clients: Record<string, ClientConfig> | undefined): LinkRow[] {
  return Object.keys(clients ?? {})
    .sort()
    .map((id) => {
      const c = clients![id]!;
      return {
        client: id,
        servers: c.servers.join(",") || "(none)",
        max_scope: c.max_scope ?? "(server ceiling)",
        max_risk: c.max_risk ?? "high",
        accounts: Object.entries(c.accounts ?? {}).map(([p, a]) => `${p}=${a}`).join(" ") || "-",
      };
    });
}
