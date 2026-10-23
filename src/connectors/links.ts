/**
 * Linking (ADR local-composio, section 6.7): which client may use which toolkit, how far, and as which
 * connected account.
 *
 * The ADR's shape is the VNEXT client profile plus an account binding:
 *
 *   clients:
 *     claude-code: { servers: ["*"],                     max_scope: full,  max_risk: high }
 *     codex:       { servers: ["youtube","gmail"],       max_scope: write, max_risk: medium }
 *     daena:       { servers: ["instagram","tiktok"],    max_scope: write, max_risk: high, accounts: { instagram: ca_brand } }
 *
 * The principals and client profiles of VNEXT 3.1 are built on another branch. Until they merge, this store
 * keeps exactly that table for toolkits in `<SWITCHBOARD_HOME>/connectors/links.json`, edited by
 * `switchboard link|unlink`, and the connector layer enforces it itself, in both directions: the toolkit
 * server lists nothing for a client that is not linked, and refuses its calls. The seam for the merge is
 * `LinkStore.boundAccount`, which is what `AccountStore.setBindingResolver` calls, and the caller identity
 * the connector server reads from the MCP request `_meta`.
 *
 * Open by default, closed once used: with no client in the table every caller is allowed (nothing changes
 * for an installation that never ran `link`). The moment one client is linked, a NAMED client that is not in
 * the table is refused. A call that names no client at all is the owner's own unscoped path (a CLI run, a
 * gateway without principals) and is not narrowed.
 */

import { join } from "node:path";
import type { Scope } from "../types.js";
import { WatchedJsonFile } from "../atomicfile.js";
import type { Risk } from "./toolkits.js";
import { RISK_RANK, SCOPE_RANK } from "./toolkits.js";

export interface ClientLink {
  /** Toolkit slugs, or `*`. */
  toolkits: string[];
  max_scope: Scope;
  max_risk: Risk;
  /** provider slug -> account reference (`ca_...`, `provider/label`, or a label). */
  accounts: Record<string, string>;
}

interface LinksFile {
  version: 1;
  clients: Record<string, ClientLink>;
}

export interface LinkDecision {
  allowed: boolean;
  reason?: string;
  /** The caps that apply (absent for an unscoped caller). */
  link?: ClientLink;
  /** True when no link table is in force. */
  open: boolean;
}

const CLIENT_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$/;

function shape(value: unknown): string | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return "expected a JSON object";
  const c = (value as Partial<LinksFile>).clients;
  if (typeof c !== "object" || c === null || Array.isArray(c)) return "expected a 'clients' object";
  for (const [id, l] of Object.entries(c)) {
    const link = l as Partial<ClientLink> | null;
    if (!CLIENT_RE.test(id) || !link || !Array.isArray(link.toolkits) || !(link.max_scope! in SCOPE_RANK) || !(link.max_risk! in RISK_RANK)) return `client '${id}' is malformed`;
  }
  return null;
}

const matches = (list: string[], toolkit: string): boolean => list.some((t) => t === "*" || t === toolkit);

export class LinkStore {
  private readonly file: WatchedJsonFile<LinksFile>;

  constructor(home: string) {
    this.file = new WatchedJsonFile<LinksFile>(join(home, "connectors", "links.json"), () => ({ version: 1, clients: {} }), { validate: shape, mode: 0o600 });
  }

  all(): Record<string, ClientLink> {
    return this.file.get().clients;
  }

  get(client: string): ClientLink | undefined {
    return this.file.get().clients[client];
  }

  isOpen(): boolean {
    return Object.keys(this.file.get().clients).length === 0;
  }

  /** May `client` use `toolkit`, and within what limits. */
  check(client: string | undefined, toolkit: string): LinkDecision {
    const table = this.file.get().clients;
    if (Object.keys(table).length === 0) return { allowed: true, open: true };
    if (client === undefined || client === "") return { allowed: true, open: false };
    const link = table[client];
    if (!link) return { allowed: false, open: false, reason: `client '${client}' is not linked to any toolkit (switchboard link ${client} <toolkit>)` };
    if (!matches(link.toolkits, toolkit)) return { allowed: false, open: false, link, reason: `client '${client}' is not linked to '${toolkit}' (switchboard link ${client} ${toolkit})` };
    return { allowed: true, open: false, link };
  }

  /** The account reference bound to `client` for `provider`, if any. The binding resolver the account store uses. */
  boundAccount(client: string | undefined, provider: string): string | undefined {
    if (!client) return undefined;
    return this.file.get().clients[client]?.accounts[provider];
  }

  /** Link a client to a toolkit. A new client starts at the least privilege: read scope, low risk. */
  link(client: string, toolkit: string, opts: { maxScope?: Scope; maxRisk?: Risk } = {}): ClientLink {
    if (!CLIENT_RE.test(client)) throw new Error(`'${client}' is not a valid client id (letters, digits, . _ -; at most 48 characters)`);
    if (toolkit !== "*" && !/^[a-z][a-z0-9-]{0,31}$/.test(toolkit)) throw new Error(`'${toolkit}' is not a valid toolkit slug`);
    if (opts.maxScope && !(opts.maxScope in SCOPE_RANK)) throw new Error(`max scope must be read, write or full`);
    if (opts.maxRisk && !(opts.maxRisk in RISK_RANK)) throw new Error(`max risk must be low, medium or high`);
    let out!: ClientLink;
    this.file.update((cur) => {
      const prev = cur.clients[client];
      const next: ClientLink = {
        toolkits: [...new Set([...(prev?.toolkits ?? []), toolkit])],
        max_scope: opts.maxScope ?? prev?.max_scope ?? "read",
        max_risk: opts.maxRisk ?? prev?.max_risk ?? "low",
        accounts: { ...(prev?.accounts ?? {}) },
      };
      out = next;
      return { ...cur, clients: { ...cur.clients, [client]: next } };
    });
    return out;
  }

  unlink(client: string, toolkit?: string): boolean {
    let changed = false;
    this.file.update((cur) => {
      const prev = cur.clients[client];
      if (!prev) return undefined;
      const clients = { ...cur.clients };
      if (toolkit === undefined) {
        delete clients[client];
        changed = true;
      } else {
        const toolkits = prev.toolkits.filter((t) => t !== toolkit);
        if (toolkits.length === prev.toolkits.length) return undefined;
        clients[client] = { ...prev, toolkits };
        changed = true;
      }
      return { ...cur, clients };
    });
    return changed;
  }

  /** Bind `client` to one account of `provider`. */
  bindAccount(client: string, provider: string, account: string): void {
    this.file.update((cur) => {
      const prev = cur.clients[client];
      if (!prev) throw new Error(`client '${client}' is not linked yet: switchboard link ${client} <toolkit> first`);
      return { ...cur, clients: { ...cur.clients, [client]: { ...prev, accounts: { ...prev.accounts, [provider]: account } } } };
    });
  }

  unbindAccount(client: string, provider: string): void {
    this.file.update((cur) => {
      const prev = cur.clients[client];
      if (!prev || !(provider in prev.accounts)) return undefined;
      const accounts = { ...prev.accounts };
      delete accounts[provider];
      return { ...cur, clients: { ...cur.clients, [client]: { ...prev, accounts } } };
    });
  }
}

/** Does a call at `scope`/`risk` fit inside a link's caps? */
export function withinCaps(link: ClientLink | undefined, scope: Scope, risk: Risk): { ok: boolean; reason?: string } {
  if (!link) return { ok: true };
  if (SCOPE_RANK[scope] > SCOPE_RANK[link.max_scope]) return { ok: false, reason: `needs '${scope}' scope but this client is limited to '${link.max_scope}'` };
  if (RISK_RANK[risk] > RISK_RANK[link.max_risk]) return { ok: false, reason: `is '${risk}' risk but this client is limited to '${link.max_risk}'` };
  return { ok: true };
}
