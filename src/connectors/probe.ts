/**
 * Identity probe (ADR local-composio, 6.1): one cheap read-only call that proves a credential is live and
 * says whose it is. It runs when an account connects (a connection only counts when it is real, gate 4)
 * and from `switchboard accounts probe`; the daily canary of phase P5 will reuse it.
 *
 * The probe talks only to the provider's own `identity_probe.url`, which the loader has already checked
 * against `api_hosts`. A failure never carries the response body: only the status and a short, scrubbed
 * provider message.
 */

import type { AccountIdentity, AuthDef, IdentityProbeDef, ProviderDef, TokenPayload } from "./types.js";
import { applyAuth, getPath, primarySecret } from "./inject.js";
import { guardedFetch, type NetworkSource } from "../netguard.js";
import { scrubAndClip } from "./scrub.js";

export interface ProbeOutcome {
  ok: boolean;
  status?: number;
  identity?: AccountIdentity;
  /** Scopes the provider reported in a response header, when the definition names one. */
  scopes?: string[];
  error?: string;
}

function secretsOf(payload: TokenPayload): string[] {
  const out: string[] = [];
  const p = primarySecret(payload);
  if (p) out.push(p);
  if (payload.refresh_token) out.push(payload.refresh_token);
  for (const v of Object.values(payload.fields ?? {})) out.push(v);
  return out;
}

function asText(v: unknown): string | undefined {
  if (typeof v === "string") return v.trim() === "" ? undefined : v;
  if (typeof v === "number" && Number.isFinite(v)) return String(v);
  return undefined;
}

/** What a failed probe says about itself: the status, plus the provider's own short message when it sent one. */
function failureMessage(status: number, json: unknown, secrets: string[]): string {
  let detail = "";
  if (json && typeof json === "object") {
    const o = json as Record<string, unknown>;
    const inner = o.error && typeof o.error === "object" ? (o.error as Record<string, unknown>) : undefined;
    const candidate = o.error_description ?? o.message ?? inner?.message ?? (typeof o.error === "string" ? o.error : undefined) ?? o.detail;
    if (typeof candidate === "string") detail = candidate;
  }
  return scrubAndClip(`identity probe failed: HTTP ${status}${detail ? ` (${detail})` : ""}`, secrets);
}

export async function runIdentityProbe(
  def: ProviderDef,
  auth: AuthDef,
  payload: TokenPayload,
  network?: NetworkSource,
): Promise<ProbeOutcome> {
  const probe: IdentityProbeDef | undefined = def.identity_probe;
  if (!probe) return { ok: false, error: `provider '${def.slug}' defines no identity probe` };
  const secrets = secretsOf(payload);
  const url = new URL(probe.url);
  for (const [k, v] of Object.entries(probe.query ?? {})) url.searchParams.set(k, v);
  const callerHeaders: Record<string, string> = { Accept: "application/json", ...(probe.headers ?? {}) };
  let body: string | undefined;
  if (probe.method === "POST") {
    if (probe.body !== undefined) {
      body = JSON.stringify(probe.body);
      callerHeaders["Content-Type"] = "application/json";
    } else body = "";
  }
  let injected;
  try {
    injected = applyAuth(def, auth, payload, url, callerHeaders);
  } catch (err) {
    return { ok: false, error: scrubAndClip(err instanceof Error ? err.message : String(err), secrets) };
  }
  let res;
  try {
    res = await guardedFetch(
      injected.url,
      { method: probe.method, headers: injected.headers, ...(body !== undefined ? { body } : {}), credentialHeaders: injected.credentialHeaders },
      network,
    );
  } catch (err) {
    return { ok: false, error: scrubAndClip(`identity probe could not reach the provider: ${err instanceof Error ? err.message : String(err)}`, secrets) };
  }
  const text = await res.text();
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = undefined;
  }
  if (!res.ok) return { ok: false, status: res.status, error: failureMessage(res.status, json, secrets) };
  if (probe.ok_field) {
    const flag = json && typeof json === "object" ? (json as Record<string, unknown>)[probe.ok_field] : undefined;
    if (flag !== true) {
      return { ok: false, status: res.status, error: failureMessage(res.status, json, secrets).replace(`HTTP ${res.status}`, `HTTP ${res.status} with ${probe.ok_field}:false`) };
    }
  }
  let externalId = probe.id_path ? asText(getPath(json, probe.id_path)) : undefined;
  if (!externalId && probe.id_static) externalId = probe.id_static;
  if (!externalId) {
    return { ok: false, status: res.status, error: `identity probe answered HTTP ${res.status} but ${probe.id_path ?? "the identity field"} was missing from the response` };
  }
  const identity: AccountIdentity = { external_id: externalId };
  const name = probe.name_path ? asText(getPath(json, probe.name_path)) : undefined;
  if (name) identity.display_name = scrubAndClip(name, secrets, 120);
  const avatar = probe.avatar_path ? asText(getPath(json, probe.avatar_path)) : undefined;
  if (avatar && /^https:\/\//i.test(avatar)) identity.avatar = avatar;
  let scopes: string[] | undefined;
  if (probe.scopes_header) {
    const header = res.headers.get(probe.scopes_header);
    if (header) scopes = header.split(/[\s,]+/).filter(Boolean);
  }
  return { ok: true, status: res.status, identity, ...(scopes ? { scopes } : {}) };
}
