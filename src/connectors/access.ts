/**
 * Client access for the connector layer: ONE source of truth, the gateway's `clients:` section (design 3.1).
 *
 * Until the principals work landed, the connector layer kept its own table of which client may use which toolkit
 * (`connectors/links.json`). That made two access-control sources that could disagree: the router could allow a
 * client a server that the link table refused, or the reverse. There is now one. A client's access to a toolkit is
 * its access to the toolkit's server (`servers` globs), its ceilings are `max_scope` and `max_risk`, and the account
 * it uses is `accounts: { <provider>: <account> }`. `switchboard link` edits exactly those fields through the same
 * ClientAdmin that `switchboard client` uses.
 *
 * This module only READS the live clients map (`ClientsSource`); the gateway hands it `() => cfg.clients`, which
 * ClientAdmin keeps current. With no client configured (a CLI run, a gateway in loopback single-user mode) every
 * caller is the owner's own unscoped path and nothing here narrows it.
 *
 * Account choice (`chooseAccount`), the rules that decide which connected account a call runs as:
 *   1. A server pin (`servers[].account`) is final. A call's `account` argument that names another account is
 *      refused, and so is a client bound to a different account of that provider (the pin would run the call as an
 *      identity the client was never given).
 *   2. A client with `accounts: { <provider>: <account> }` uses that account, and the `account` argument may name only
 *      that account.
 *   3. A client with `accounts: { <provider>: "*" }` uses the provider default unless it names an account.
 *   4. A client with no entry uses the provider default and may name no other account.
 *   5. The owner's unscoped path (no client) may name any account, except against a server pin.
 * A refusal is `SB_POLICY_DENY` naming the client. A named account that does not exist is `SB_ACCOUNT_NOT_FOUND`: a
 * binding or a pin never falls back to the default.
 */

import type { ClientConfig, Scope } from "../types.js";
import { globMatch } from "../principal.js";
import type { AccountStore } from "./accounts.js";
import { CONNECTOR_ERR, ConnectorError } from "./errors.js";
import { RISK_RANK, SCOPE_RANK, type Risk } from "./toolkits.js";
import type { ConnectedAccount } from "./types.js";

export type ClientsSource = () => Record<string, ClientConfig> | undefined;

export interface AccessDecision {
  allowed: boolean;
  reason?: string;
  /** The client's profile (absent for an unscoped caller). */
  profile?: ClientConfig;
  /** True when no client is configured, so nothing narrows any caller. */
  open: boolean;
}

/** What a client's `accounts` entry says about one provider. */
export type AccountBinding = { kind: "none" } | { kind: "any" } | { kind: "bound"; ref: string };

const has = (o: object | undefined, k: string): boolean => o !== undefined && Object.prototype.hasOwnProperty.call(o, k);

export class ClientAccess {
  constructor(private source: ClientsSource = () => undefined) {}

  /** Point at the live clients map (the gateway does this once its config exists). */
  setSource(source: ClientsSource): void {
    this.source = source;
  }

  private clients(): Record<string, ClientConfig> {
    return this.source() ?? {};
  }

  /** True while at least one client is configured, which is when every named caller must be one of them. */
  inForce(): boolean {
    return Object.keys(this.clients()).length > 0;
  }

  profile(client: string | undefined): ClientConfig | undefined {
    if (client === undefined || client === "") return undefined;
    const c = this.clients();
    return has(c, client) ? c[client] : undefined;
  }

  /**
   * May `client` use the connector server `serverId`? A call that names no client is the owner's unscoped path. Once
   * clients exist, a NAMED client that is not configured, or whose `servers` globs do not match, is refused.
   */
  check(client: string | undefined, serverId: string): AccessDecision {
    if (!this.inForce()) return { allowed: true, open: true };
    if (client === undefined || client === "") return { allowed: true, open: false };
    const profile = this.profile(client);
    if (!profile) return { allowed: false, open: false, reason: `client '${client}' is not configured (switchboard client add ${client})` };
    if (!profile.servers.some((g) => globMatch(g, serverId))) {
      return { allowed: false, open: false, profile, reason: `client '${client}' may not use server '${serverId}' (its servers: ${profile.servers.join(", ") || "none"}; switchboard link ${client} <toolkit>)` };
    }
    return { allowed: true, open: false, profile };
  }

  /** What the client's `accounts` entry says about `provider`. */
  binding(client: string | undefined, provider: string): AccountBinding {
    const entry = this.profile(client)?.accounts;
    if (!entry || !has(entry, provider)) return { kind: "none" };
    const ref = entry[provider]!;
    return ref === "*" ? { kind: "any" } : { kind: "bound", ref };
  }

  /** The account reference bound to `client` for `provider`, if one is (a `"*"` entry binds none). The binding resolver of the account store. */
  boundAccount(client: string | undefined, provider: string): string | undefined {
    const b = this.binding(client, provider);
    return b.kind === "bound" ? b.ref : undefined;
  }
}

/** Does a call at `scope`/`risk` fit inside the client's `max_scope` and `max_risk`? An omitted ceiling is no cap. */
export function withinCaps(profile: ClientConfig | undefined, scope: Scope, risk: Risk): { ok: boolean; reason?: string } {
  if (!profile) return { ok: true };
  if (profile.max_scope && SCOPE_RANK[scope] > SCOPE_RANK[profile.max_scope]) return { ok: false, reason: `needs '${scope}' scope but this client is limited to '${profile.max_scope}'` };
  if (profile.max_risk && RISK_RANK[risk] > RISK_RANK[profile.max_risk]) return { ok: false, reason: `is '${risk}' risk but this client is limited to '${profile.max_risk}'` };
  return { ok: true };
}

export interface AccountChoice {
  access: ClientAccess;
  accounts: AccountStore;
  provider: string;
  /** The server this call runs under (named in refusals). */
  serverId: string;
  /** The authenticated client, from the router; never from an argument. Absent: the owner's unscoped path. */
  client?: string;
  /** The `account` argument of the call, if it gave one. */
  explicit?: string;
  /** The account the server entry pins (`servers[].account`). */
  pin?: string;
}

const deny = (message: string, provider: string): ConnectorError =>
  new ConnectorError(CONNECTOR_ERR.POLICY_DENY, message, { provider, hint: "the account is chosen by the client's `accounts` entry (switchboard link <client> <toolkit> --account <ref>) or by the server's pin" });

/** The connected account a call runs as (rules in the file header). Throws SB_POLICY_DENY or SB_ACCOUNT_NOT_FOUND. */
export function chooseAccount(c: AccountChoice): ConnectedAccount {
  const { provider, serverId, client } = c;
  const pick = (ref: string): ConnectedAccount => c.accounts.resolveForCall(provider, { account: ref });
  const named = client !== undefined && client !== "" && c.access.inForce();
  const who = named ? `client '${client}'` : "this call";
  const binding = named ? c.access.binding(client, provider) : ({ kind: "none" } as AccountBinding);
  const pinned = c.pin ? pick(c.pin) : undefined;
  const own = binding.kind === "bound" ? pick(binding.ref) : undefined;

  if (pinned && own && own.id !== pinned.id) {
    throw deny(`server '${serverId}' is pinned to account ${pinned.id} (${provider}/${pinned.label}), but ${who} is bound to ${own.id} (${provider}/${own.label}): a pin is final, so the call is refused`, provider);
  }
  if (c.explicit) {
    const wanted = pick(c.explicit);
    if (pinned) {
      if (wanted.id !== pinned.id) throw deny(`server '${serverId}' is pinned to account ${pinned.id} (${provider}/${pinned.label}): the account argument cannot override a server pin (${who} asked for ${wanted.id})`, provider);
      return pinned;
    }
    if (named && binding.kind !== "any") {
      const usual = own ?? c.accounts.defaultFor(provider);
      if (!usual || wanted.id !== usual.id) {
        throw deny(
          `${who} may not use account ${wanted.id} (${provider}/${wanted.label}) for ${provider}: ${own ? `it is bound to ${own.id}` : "it has no accounts entry for this provider, so it uses the provider default"}; accounts: { ${provider}: "*" } lets it choose`,
          provider,
        );
      }
    }
    return wanted;
  }
  if (pinned) return pinned;
  if (own) return own;
  return c.accounts.resolveForCall(provider, {});
}
