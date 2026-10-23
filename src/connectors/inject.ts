/**
 * Attaching a stored credential to an outgoing API call, driven only by the provider's `inject` block.
 *
 * Templates use {token} (the access token or API key), {basic} (base64 of user:password) and {<field>}
 * (a stored named field, for providers whose credential has two parts). A placeholder that cannot be
 * filled is an error, never an empty string: a request with a blank credential must not leave.
 */

import type { AuthDef, ProviderDef, TokenPayload } from "./types.js";
import { CONNECTOR_ERR, ConnectorError } from "./errors.js";

/** The value for `{token}`. */
export function primarySecret(payload: TokenPayload): string | undefined {
  return payload.access_token ?? payload.fields?.token ?? payload.fields?.api_key;
}

export function renderTemplate(template: string, payload: TokenPayload): string {
  return template.replace(/\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_m, name: string) => {
    let value: string | undefined;
    if (name === "token") value = primarySecret(payload);
    else if (name === "basic") {
      const u = payload.fields?.username;
      const p = payload.fields?.password;
      value = u !== undefined && p !== undefined ? Buffer.from(`${u}:${p}`, "utf8").toString("base64") : undefined;
    } else value = payload.fields?.[name];
    if (value === undefined || value === "") {
      throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `the stored credential has no value for {${name}} (the provider definition's inject template needs it)`);
    }
    return value;
  });
}

const lower = (h: Record<string, string>): Set<string> => new Set(Object.keys(h).map((k) => k.toLowerCase()));

export interface InjectedRequest {
  url: URL;
  headers: Record<string, string>;
  /** Header names that carry the credential, so a cross-origin redirect drops them. */
  credentialHeaders: string[];
}

/**
 * Merge the provider's fixed headers, then the caller's, then the credential. The credential always wins
 * a name collision: an agent-supplied Authorization header cannot replace the account's.
 */
export function applyAuth(def: ProviderDef, auth: AuthDef, payload: TokenPayload, url: URL, callerHeaders: Record<string, string> = {}): InjectedRequest {
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(def.api_headers ?? {})) headers[k] = v;
  if (def.api_version_header) headers[def.api_version_header.name] = def.api_version_header.value;
  const have = lower(headers);
  for (const [k, v] of Object.entries(callerHeaders)) {
    if (k.toLowerCase() === auth.inject.name.toLowerCase()) continue;
    if (have.has(k.toLowerCase())) {
      for (const existing of Object.keys(headers)) if (existing.toLowerCase() === k.toLowerCase()) delete headers[existing];
    }
    headers[k] = v;
  }
  const value = renderTemplate(auth.inject.template, payload);
  const credentialHeaders: string[] = [];
  const out = new URL(url.href);
  if (auth.inject.in === "header") {
    for (const existing of Object.keys(headers)) if (existing.toLowerCase() === auth.inject.name.toLowerCase()) delete headers[existing];
    headers[auth.inject.name] = value;
    credentialHeaders.push(auth.inject.name);
  } else {
    out.searchParams.set(auth.inject.name, value);
  }
  return { url: out, headers, credentialHeaders };
}

/** Read a dotted path (`data.user.open_id`, `data.0.id`) out of parsed JSON. */
export function getPath(value: unknown, path: string): unknown {
  let cur: unknown = value;
  for (const seg of path.split(".")) {
    if (cur === null || cur === undefined) return undefined;
    if (Array.isArray(cur)) {
      const i = Number(seg);
      if (!Number.isInteger(i)) return undefined;
      cur = cur[i];
    } else if (typeof cur === "object") {
      cur = (cur as Record<string, unknown>)[seg];
    } else return undefined;
  }
  return cur;
}
