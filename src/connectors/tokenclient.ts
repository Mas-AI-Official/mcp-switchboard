/**
 * The token endpoint client: the one place a client secret, a code or a refresh token goes on the wire.
 *
 * Every provider quirk is a field of its OAuth2Def, so there is no per-provider branch here:
 *   client_auth            HTTP Basic or form fields for the app credentials
 *   client_secret_at_exchange   when the secret must accompany the exchange (always / without PKCE / optional)
 *   client_id_param        `client_id`, or `client_key` for TikTok
 *   token_http_method      GET (Facebook documents the query form) or POST
 *   token_response_path    the token object nested in the answer (Instagram's data.0)
 *   token_shape            Slack's ok:false-on-200 errors
 *   accept_json, token_request_params, scope separators (in oauthflow)
 *
 * The answer BODY decides success, never the HTTP status alone: GitHub and Slack report errors with 200.
 * Every error string leaves this module scrubbed of the secrets the call handled.
 */

import type { AuthDef, HttpStepDef, OAuth2Def, ProviderDef } from "./types.js";
import { CONNECTOR_ERR, ConnectorError } from "./errors.js";
import { getPath } from "./inject.js";
import { guardedFetch, type NetworkSource } from "../netguard.js";
import { scrubAndClip } from "./scrub.js";

export interface ClientCredentials {
  clientId: string;
  clientSecret?: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token?: string;
  token_type?: string;
  /** Raw scope text as the provider sent it (comma or space separated). */
  scope?: string;
  expires_in?: number;
}

/** A token endpoint refusal. `providerCode` is the OAuth `error` value ("invalid_grant", ...). */
export class TokenEndpointError extends ConnectorError {
  readonly providerCode?: string;
  readonly httpStatus?: number;
  constructor(message: string, providerCode?: string, httpStatus?: number, provider?: string) {
    super(CONNECTOR_ERR.PROVIDER_ERROR, message, provider ? { provider } : {});
    this.name = "TokenEndpointError";
    if (providerCode !== undefined) this.providerCode = providerCode;
    if (httpStatus !== undefined) this.httpStatus = httpStatus;
  }
}

/** When must the client secret accompany this exchange? */
export function secretRequired(o: OAuth2Def, usedPkce: boolean): boolean {
  if (o.client_secret_at_exchange === "always") return true;
  if (o.client_secret_at_exchange === "without_pkce") return !usedPkce;
  return false;
}

function parseBody(text: string): Record<string, unknown> {
  try {
    const v = JSON.parse(text) as unknown;
    if (v && typeof v === "object" && !Array.isArray(v)) return v as Record<string, unknown>;
  } catch {
    /* fall through to the form-encoded reading */
  }
  // Some providers answer x-www-form-urlencoded when Accept is ignored (GitHub's default).
  return Object.fromEntries(new URLSearchParams(text).entries());
}

function text(v: unknown): string | undefined {
  return typeof v === "string" && v !== "" ? v : undefined;
}

export interface CallArgs {
  provider: string;
  url: string;
  method: "GET" | "POST";
  headers: Record<string, string>;
  params: URLSearchParams;
  o: OAuth2Def;
  network?: NetworkSource;
  /** Secrets this call carries, scrubbed from any error text. */
  secrets: string[];
}

/** Send one token-endpoint call and read its body into a TokenResponse, or throw a scrubbed TokenEndpointError. */
export async function tokenCall(args: CallArgs): Promise<TokenResponse> {
  const { o, secrets, provider } = args;
  let res;
  try {
    if (args.method === "GET") {
      const u = new URL(args.url);
      for (const [k, v] of args.params) u.searchParams.set(k, v);
      res = await guardedFetch(u, { method: "GET", headers: args.headers }, args.network);
    } else {
      res = await guardedFetch(args.url, { method: "POST", headers: args.headers, body: args.params }, args.network);
    }
  } catch (err) {
    throw new TokenEndpointError(scrubAndClip(`token endpoint of '${provider}' is unreachable: ${err instanceof Error ? err.message : String(err)}`, secrets), undefined, undefined, provider);
  }
  const body = parseBody(await res.text());
  let obj: Record<string, unknown> = body;
  if (o.token_response_path) {
    const inner = getPath(body, o.token_response_path);
    if (inner && typeof inner === "object" && !Array.isArray(inner)) obj = inner as Record<string, unknown>;
  }
  // Errors first: the body, not the status, says whether the exchange worked.
  if (o.token_shape === "slack") {
    if (body.ok === false) {
      const code = text(body.error) ?? "unknown";
      throw new TokenEndpointError(scrubAndClip(`Slack OAuth error from '${provider}': ${code}`, secrets), code, res.status, provider);
    }
  } else {
    const code = text(body.error) ?? (body.error && typeof body.error === "object" ? text((body.error as Record<string, unknown>).type) : undefined);
    if (code) {
      const desc = text(body.error_description) ?? (body.error && typeof body.error === "object" ? text((body.error as Record<string, unknown>).message) : undefined);
      throw new TokenEndpointError(scrubAndClip(`OAuth error from '${provider}': ${code}${desc ? ` - ${desc}` : ""}`, secrets), code, res.status, provider);
    }
  }
  const accessToken = text(obj.access_token);
  if (!accessToken) {
    const why = res.ok ? "returned no access_token" : `answered HTTP ${res.status}`;
    throw new TokenEndpointError(scrubAndClip(`token endpoint of '${provider}' ${why}`, secrets), undefined, res.status, provider);
  }
  const expiresIn = Number(obj.expires_in);
  const out: TokenResponse = { access_token: accessToken };
  const refresh = text(obj.refresh_token);
  if (refresh) out.refresh_token = refresh;
  const tokenType = text(obj.token_type);
  if (tokenType) out.token_type = tokenType;
  const scope = text(obj.scope) ?? text(obj.scopes);
  if (scope) out.scope = scope;
  if (Number.isFinite(expiresIn) && expiresIn > 0) out.expires_in = expiresIn;
  return out;
}

export interface GrantArgs {
  def: ProviderDef;
  auth: AuthDef;
  o: OAuth2Def;
  /** grant_type and its parameters (code, redirect_uri, code_verifier, refresh_token, scope...). */
  grant: Record<string, string>;
  client: ClientCredentials;
  usedPkce: boolean;
  network?: NetworkSource;
}

/** Build and send a grant request to the provider's token endpoint with the app credentials its quirks demand. */
export async function requestGrant(a: GrantArgs): Promise<TokenResponse> {
  const { def, o, client } = a;
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(a.grant)) params.set(k, v);
  for (const [k, v] of Object.entries(o.token_request_params ?? {})) params.set(k, v);
  const headers: Record<string, string> = {};
  const method = o.token_http_method ?? "POST";
  if (method === "POST") headers["Content-Type"] = "application/x-www-form-urlencoded";
  if (o.accept_json) headers.Accept = "application/json";
  const idParam = o.client_id_param ?? "client_id";
  const needSecret = secretRequired(o, a.usedPkce);
  if (needSecret && !client.clientSecret) {
    throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `${def.slug} needs a client secret for this exchange: add it to the auth config (switchboard authconfig add ${def.slug} --client-secret-ref <vault name>)`, { provider: def.slug });
  }
  if (o.client_auth === "basic" && client.clientSecret) {
    headers.Authorization = "Basic " + Buffer.from(`${client.clientId}:${client.clientSecret}`, "utf8").toString("base64");
  } else {
    // Form-field client auth, or a public client under Basic-auth providers (no secret on record): the id travels in the body.
    // A secret on record is always sent with form-field auth; "optional" only means it may be absent.
    params.set(idParam, client.clientId);
    if (client.clientSecret && o.client_auth === "body") params.set("client_secret", client.clientSecret);
  }
  const secrets = [client.clientSecret, a.grant.code, a.grant.refresh_token, a.grant.code_verifier, a.grant.fb_exchange_token].filter((x): x is string => Boolean(x));
  return tokenCall({ provider: def.slug, url: o.token_url, method, headers, params, o, ...(a.network ? { network: a.network } : {}), secrets });
}

/** The values a declarative exchange step may substitute. */
export interface StepVars {
  access_token: string;
  client_id?: string;
  client_secret?: string;
}

/** Run a post-exchange / exchange-refresh step (Meta's long-lived token trade). */
export async function runExchangeStep(def: ProviderDef, o: OAuth2Def, step: HttpStepDef, vars: StepVars, network?: NetworkSource): Promise<TokenResponse> {
  const params = new URLSearchParams();
  for (const [k, tpl] of Object.entries(step.params)) {
    const value = tpl.replace(/\{(access_token|client_id|client_secret)\}/g, (_m, name: keyof StepVars) => {
      const v = vars[name];
      if (v === undefined) {
        throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `${def.slug}: the exchange step needs {${name}} but the auth config does not provide it`, { provider: def.slug });
      }
      return v;
    });
    params.set(k, value);
  }
  const headers: Record<string, string> = {};
  if (step.method === "POST") headers["Content-Type"] = "application/x-www-form-urlencoded";
  if (o.accept_json) headers.Accept = "application/json";
  // The exchange answers in the standard flat shape even when the code exchange wraps it.
  const flat: OAuth2Def = { ...o };
  delete flat.token_response_path;
  return tokenCall({
    provider: def.slug,
    url: step.url,
    method: step.method,
    headers,
    params,
    o: flat,
    ...(network ? { network } : {}),
    secrets: [vars.access_token, vars.client_secret].filter((x): x is string => Boolean(x)),
  });
}
