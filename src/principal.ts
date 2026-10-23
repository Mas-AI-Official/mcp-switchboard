/**
 * principal.ts: who is calling, and what that caller may see (design 3.1).
 *
 * Every caller of the gateway is a Principal. HTTP callers authenticate with a per-client API key (or an
 * OAuth token whose registered client name is a configured client id); a stdio server started with
 * `--client <id>` is an assertion by the launching process; a loopback caller with no credential exists only
 * while NO client is configured (the backward compatible single-user mode).
 *
 * A configured client is a profile with a ceiling: the servers it may see and call (id globs), an optional
 * tool allowlist and denylist (exposed-name globs), and a scope ceiling that can only LOWER what the server
 * and the active profile already allow. This file holds the pure parts: the client id rule, the glob matcher,
 * the gate a principal resolves to, and the HTTP decision that turns presented credentials into a principal
 * or a refusal. Nothing here touches disk, the network or process state.
 */

import type { ClientConfig, Risk, Scope } from "./types.js";

/** The documented client id shape (design 3.1). */
export const CLIENT_ID_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
/** Windows treats these as devices whatever the extension (`nul.key` would silently swallow the key). */
const RESERVED_DEVICE_RE = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])$/;

export function isValidClientId(id: unknown): id is string {
  return typeof id === "string" && CLIENT_ID_RE.test(id) && !RESERVED_DEVICE_RE.test(id);
}

export const BAD_CLIENT_ID =
  "invalid client id: use 1 to 64 characters from a-z, 0-9, '-' and '_', starting with a letter or digit";

// ── principals ───────────────────────────────────────────────────────────────────────────────────

/**
 * How the caller was identified:
 *  - `apikey`: a bearer key from the API key store (id = the key's id, never the secret).
 *  - `oauth`: an OAuth access token (id = the OAuth client id).
 *  - `stdio`: `switchboard serve --client <id>`; an assertion by the launching process, not an authentication.
 *  - `loopback-anonymous`: no credential, no client configured, loopback single-user mode.
 */
export type PrincipalVia = "apikey" | "oauth" | "stdio" | "loopback-anonymous";

export interface Principal {
  id: string;
  /** The configured client this principal acts as, or null when it is not bound to one. */
  client: string | null;
  via: PrincipalVia;
}

/** `<via>:<id>`, the form audit rows carry. */
export function principalLabel(p: Principal): string {
  return `${p.via}:${p.id}`;
}

/** The two audit fields for a caller; empty for an internal call that has no principal. */
export function principalAudit(p: Principal | undefined): { principal?: string; client?: string } {
  if (!p) return {};
  return { principal: principalLabel(p), ...(p.client ? { client: p.client } : {}) };
}

// ── globs ────────────────────────────────────────────────────────────────────────────────────────

/** A glob pattern longer than this is a config error (and never matches). */
export const MAX_GLOB_LENGTH = 128;
/** A name longer than this is hidden from every restricted client: it is never matched against a pattern. */
export const MAX_GLOB_TEXT = 256;
/** Most patterns one list may hold. */
export const MAX_GLOB_PATTERNS = 256;

/** A pattern is printable text without control characters, within the length cap. */
export function isValidGlob(pattern: unknown): pattern is string {
  return typeof pattern === "string" && pattern.length > 0 && pattern.length <= MAX_GLOB_LENGTH && !/[\u0000-\u001f\u007f]/.test(pattern);
}

/**
 * Case sensitive glob match: `*` is any run of characters (including none, and including `__`), `?` is exactly
 * one character, everything else is literal. Iterative with a single backtrack point (no RegExp is built from
 * the pattern), so the work is bounded by the two length caps. Patterns come from the owner's config; the text
 * is a tool name chosen by an upstream, which is why it is capped too.
 */
export function globMatch(pattern: string, text: string): boolean {
  if (pattern.length > MAX_GLOB_LENGTH || text.length > MAX_GLOB_TEXT) return false;
  let p = 0;
  let t = 0;
  let star = -1;
  let mark = 0;
  while (t < text.length) {
    const pc = p < pattern.length ? pattern[p] : "";
    if (pc === "*") {
      star = p++;
      mark = t;
    } else if (pc !== "" && (pc === "?" || pc === text[t])) {
      p++;
      t++;
    } else if (star !== -1) {
      p = star + 1;
      t = ++mark;
    } else {
      return false;
    }
  }
  while (p < pattern.length && pattern[p] === "*") p++;
  return p === pattern.length;
}

const matchesAny = (patterns: readonly string[] | undefined, text: string): boolean =>
  !!patterns && patterns.some((p) => globMatch(p, text));

// ── gates ────────────────────────────────────────────────────────────────────────────────────────

const SCOPE_RANK: Record<Scope, number> = { read: 0, write: 1, full: 2 };

/**
 * What a principal's client lets it see and call. `deny` is set when the principal cannot be tied to a
 * configured client while clients are in force: such a gate hides everything and refuses everything.
 */
export interface ClientGate {
  /** Client id for attribution and messages; null when the principal has none. */
  client: string | null;
  /** The configured profile; null for a deny-all gate. */
  profile: ClientConfig | null;
  /** Why everything is refused; null for a normal gate. */
  deny: string | null;
}

const clientsInForce = (clients: Record<string, ClientConfig> | undefined): boolean =>
  !!clients && Object.keys(clients).length > 0;

/**
 * The gate for a principal, or undefined when no client filter applies.
 *   - no principal (an internal call: the owner's playground, a trigger poll, the CLI): no filter;
 *   - a principal bound to a client: that client's profile, or a deny-all gate when the client is not configured;
 *   - a principal bound to no client: no filter while no client is configured (legacy single-user mode),
 *     otherwise a deny-all gate.
 */
export function resolveClientGate(clients: Record<string, ClientConfig> | undefined, principal: Principal | undefined): ClientGate | undefined {
  if (!principal) return undefined;
  if (principal.client !== null) {
    const profile = Object.prototype.hasOwnProperty.call(clients ?? {}, principal.client) ? clients![principal.client]! : null;
    if (!profile) return { client: principal.client, profile: null, deny: `client '${principal.client}' is not configured` };
    return { client: principal.client, profile, deny: null };
  }
  if (clientsInForce(clients)) return { client: null, profile: null, deny: "the caller is not bound to a configured client" };
  return undefined;
}

/** "client 'x'", or a neutral label for a caller with no client. */
export function gateLabel(gate: ClientGate): string {
  return gate.client ? `client '${gate.client}'` : "this caller";
}

/** May this client see and call tools, prompts and resources of this server? */
export function gateAllowsServer(gate: ClientGate, serverId: string): boolean {
  if (gate.deny !== null || !gate.profile) return false;
  if (serverId.length > MAX_GLOB_TEXT) return false;
  return matchesAny(gate.profile.servers, serverId);
}

/** May this client see and call this tool, by its exposed name? Denylist beats allowlist; an empty allowlist allows all. */
export function gateAllowsTool(gate: ClientGate, exposedName: string): boolean {
  if (gate.deny !== null || !gate.profile) return false;
  if (exposedName.length > MAX_GLOB_TEXT) return false;
  if (matchesAny(gate.profile.exclude_tools, exposedName)) return false;
  const allow = gate.profile.tools;
  if (allow && allow.length > 0 && !matchesAny(allow, exposedName)) return false;
  return true;
}

/** The client's scope ceiling (an extra cap on top of the server and the active profile), if it sets one. */
export function gateScopeCeiling(gate: ClientGate | undefined): { scope: Scope; client: string } | undefined {
  if (!gate?.profile?.max_scope || !gate.client) return undefined;
  return { scope: gate.profile.max_scope, client: gate.client };
}

/** The highest risk the client may request (`max_risk`, design 3.4), if it sets one. Omitted means no extra cap (high). */
export function gateRiskCeiling(gate: ClientGate | undefined): { risk: Risk; client: string } | undefined {
  if (!gate?.profile?.max_risk || !gate.client) return undefined;
  return { risk: gate.profile.max_risk, client: gate.client };
}

/** The tighter of two optional scope ceilings. */
export function tighterScope(a: Scope | undefined, b: Scope | undefined): Scope | undefined {
  if (a === undefined) return b;
  if (b === undefined) return a;
  return SCOPE_RANK[a] <= SCOPE_RANK[b] ? a : b;
}

// ── turning credentials into a principal (the /mcp front door) ───────────────────────────────────

export interface PresentedCredentials {
  /** The configured clients right now. */
  clients: Record<string, ClientConfig> | undefined;
  /** A bearer key that verified against the API key store, with the client it is bound to. */
  apiKey: { id: string; client?: string } | null;
  /** An OAuth access token that verified, with the registered name of its OAuth client. */
  oauth: { clientId: string; clientName?: string } | null;
  /** Whether the endpoint demands a credential even when no client is configured (non loopback, or require_auth). */
  authRequired: boolean;
}

export type PrincipalDecision =
  | { ok: true; principal: Principal }
  | { ok: false; status: 401 | 403; error: string; code?: string; hint?: string };

export const UNAUTHORIZED = "unauthorized: missing or invalid API key or OAuth token";

/**
 * The decision for one /mcp request.
 *   - clients configured: a verified credential bound to a configured client is required; anything else is
 *     401 (no valid credential) or 403 (a valid credential that names no configured client);
 *   - no client configured: the 0.1.0 behavior (a key or token when auth is required, else loopback-anonymous),
 *     except that a key bound to a client that is not configured is refused rather than treated as anonymous.
 * An OAuth token maps to a client only when the registered OAuth client name equals a configured client id.
 */
export function establishPrincipal(c: PresentedCredentials): PrincipalDecision {
  const inForce = clientsInForce(c.clients);
  let principal: Principal | null = null;
  if (c.apiKey) {
    principal = { id: c.apiKey.id, client: c.apiKey.client ?? null, via: "apikey" };
  } else if (c.oauth) {
    const name = c.oauth.clientName;
    const mapped = name !== undefined && isValidClientId(name) && Object.prototype.hasOwnProperty.call(c.clients ?? {}, name) ? name : null;
    principal = { id: c.oauth.clientId, client: mapped, via: "oauth" };
  }

  if (!principal) {
    if (inForce || c.authRequired) return { ok: false, status: 401, error: UNAUTHORIZED };
    return { ok: true, principal: { id: "loopback", client: null, via: "loopback-anonymous" } };
  }

  if (principal.client !== null && !Object.prototype.hasOwnProperty.call(c.clients ?? {}, principal.client)) {
    return {
      ok: false,
      status: 403,
      error: `forbidden: client '${principal.client}' is not configured`,
      code: "SB_UNKNOWN_CLIENT",
      hint: "The credential is bound to a client that is not in the config. Re-add it with `switchboard client add`.",
    };
  }
  if (inForce && principal.client === null) {
    return {
      ok: false,
      status: 403,
      error: "forbidden: this credential is not bound to a configured client",
      code: "SB_NO_CLIENT",
      hint:
        principal.via === "oauth"
          ? "Clients are configured, so an OAuth client must register with a client_name equal to a configured client id."
          : "Clients are configured, so every key must be bound to one: use `switchboard client add <id>` to issue a client key.",
    };
  }
  return { ok: true, principal };
}
