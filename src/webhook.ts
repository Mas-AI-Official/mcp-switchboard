/**
 * Outbound webhook delivery for policy decisions.
 *
 * When `settings.webhook` is enabled, every governed tool-call verdict whose decision is in
 * the configured `events` list is POSTed to the operator's URL as a slim JSON event. Delivery
 * is FIRE-AND-FORGET and FAIL-OPEN by construction: a webhook that is slow, down, or
 * misconfigured must never block, delay, or alter a governance decision — the decision is
 * already made and audited before we notify.
 *
 * The payload carries decision metadata only (server, tool, scope, decision, reason, timing) —
 * never the call's arguments or the upstream response. So enabling a webhook can never quietly
 * become an I/O exfiltration channel, even when `settings.logs.capture_io` is on.
 *
 * When `secret_ref` resolves to a vault secret, each delivery is signed with an
 * `x-switchboard-signature: sha256=<hmac>` header (the same scheme as the Settings page's
 * "send test event" button) so the receiver can authenticate it. If a `secret_ref` is
 * configured but cannot be resolved we DROP the delivery rather than send an unsigned event a
 * receiver would (rightly) reject — fail-closed on authenticity, still fail-open on the
 * governance decision itself.
 */

import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import type { SwitchboardConfig } from "./types.js";
import { log } from "./logger.js";

/** Resolves a `${vault:...}` / `${env:...}` reference to its secret (Vault.resolve). */
export type SecretResolver = (ref: string) => string;

/** A policy-decision event delivered to the webhook. Decision metadata only — no call I/O. */
export interface WebhookEvent {
  decision: "allow" | "deny" | "approval_required";
  server: string;
  tool: string;
  scope: string;
  reason?: string;
  duration_ms?: number;
  error?: string;
}

/**
 * A poll-first TRIGGER event delivered to the webhook. Distinct from `WebhookEvent`: a trigger
 * fire is an observation ("the polled result changed"), NOT a governance decision, so it must
 * never enter the audit log's allow/deny/approval_required accounting. Metadata only — the
 * trigger id/name, the polled tool, and a small bounded sample of the changed item keys.
 */
export interface TriggerWebhookEvent {
  /** The trigger definition id that fired. */
  trigger_id: string;
  /** The human label of the trigger, when set. */
  trigger_name?: string;
  /** The exposed tool that was polled. */
  tool: string;
  /** How the change was detected: new list items, or a changed whole-response hash. */
  detection: "items" | "hash";
  /** Number of newly-seen items (item detection) or 1 (hash detection). */
  new_count: number;
  /** A bounded sample of the new item keys (item detection only), for human triage. */
  sample_keys?: string[];
}

const TIMEOUT_MS = 8000;
/** Standard Webhooks replay window: a delivery whose timestamp drifts past this is rejected. */
const DEFAULT_TOLERANCE_SEC = 300;

/**
 * Standard Webhooks (standardwebhooks.com) signature: HMAC-SHA256 over `${id}.${timestamp}.${payload}`,
 * returned in the spec's `v1,<base64>` form. This is the interoperable scheme Svix/Stripe-style
 * receiver libraries already verify, so a MCP Switchboard delivery drops straight into existing tooling.
 */
function signStandardWebhook(id: string, timestamp: number, payload: string, secret: string): string {
  return "v1," + createHmac("sha256", secret).update(`${id}.${timestamp}.${payload}`).digest("base64");
}

/**
 * The full signature header set for one signed delivery: the Standard Webhooks triple
 * (`webhook-id` / `webhook-timestamp` / `webhook-signature`) so any spec-compliant receiver can
 * verify, PLUS the legacy `x-switchboard-signature: sha256=<hex over body>` for receivers built
 * against the older scheme. Both sign the SAME body; a receiver may check either.
 */
function signatureHeaders(payload: string, secret: string): Record<string, string> {
  const id = randomUUID();
  const timestamp = Math.floor(Date.now() / 1000);
  return {
    "webhook-id": id,
    "webhook-timestamp": String(timestamp),
    "webhook-signature": signStandardWebhook(id, timestamp, payload, secret),
    "x-switchboard-signature": "sha256=" + createHmac("sha256", secret).update(payload).digest("hex"),
  };
}

/** Input to {@link verifyWebhook}: the three Standard Webhooks header values plus the raw body. */
export interface VerifyWebhookInput {
  /** `webhook-id` header value. */
  id: string;
  /** `webhook-timestamp` header value (unix seconds; string or number both accepted). */
  timestamp: string | number;
  /** The exact raw request body that was signed. */
  payload: string;
  /** The resolved signing secret — the same value the sender used. */
  secret: string;
  /** `webhook-signature` header value: one or more space-delimited `v1,<base64>` signatures. */
  signature: string;
  /** Replay window in seconds (default 300). */
  toleranceSec?: number;
}

/**
 * Verify a Standard Webhooks delivery. Enforces the replay window on `timestamp`, recomputes the
 * `v1,<base64>` signature over `${id}.${timestamp}.${payload}`, and constant-time compares it
 * against each space-delimited candidate in `signature` (so key rotation / multiple signatures
 * work). Returns true iff the timestamp is fresh AND some candidate matches. Never throws — a
 * malformed timestamp, an empty signature, or a length mismatch all return false.
 */
export function verifyWebhook(input: VerifyWebhookInput): boolean {
  const { id, payload, secret, signature } = input;
  const toleranceSec = input.toleranceSec ?? DEFAULT_TOLERANCE_SEC;
  const ts = typeof input.timestamp === "number" ? input.timestamp : Number(input.timestamp);
  if (!Number.isFinite(ts)) return false;
  if (Math.abs(Math.floor(Date.now() / 1000) - ts) > toleranceSec) return false;

  const expected = Buffer.from(signStandardWebhook(id, ts, payload, secret));
  for (const candidate of signature.split(" ")) {
    const sig = candidate.trim();
    if (!sig.startsWith("v1,")) continue;
    const buf = Buffer.from(sig);
    if (buf.length === expected.length && timingSafeEqual(buf, expected)) return true;
  }
  return false;
}

/**
 * Notify the configured webhook of one decision. Returns immediately; the POST runs detached.
 * Any failure is swallowed (logged at warn) so it can never affect the caller.
 */
export function deliverWebhook(cfg: SwitchboardConfig, event: WebhookEvent, resolveSecret: SecretResolver): void {
  const wh = cfg.settings?.webhook;
  if (!wh?.enabled || !wh.url) return;

  // Per the config contract: an empty/omitted `events` list means "deliver every decision".
  // The shipped example pins it to [deny, approval_required] so this fallback only fires if
  // the operator deliberately clears the list.
  if (wh.events && wh.events.length > 0 && !wh.events.includes(event.decision)) return;

  const payload = JSON.stringify({
    type: "switchboard.decision",
    ts: new Date().toISOString(),
    decision: event.decision,
    server: event.server,
    tool: event.tool,
    scope: event.scope,
    ...(event.reason ? { reason: event.reason } : {}),
    ...(typeof event.duration_ms === "number" ? { duration_ms: event.duration_ms } : {}),
    ...(event.error ? { error: event.error } : {}),
  });

  const headers: Record<string, string> = { "content-type": "application/json" };
  if (wh.secret_ref) {
    try {
      Object.assign(headers, signatureHeaders(payload, resolveSecret(wh.secret_ref)));
    } catch {
      // A signature was promised but the secret is unavailable: drop rather than send an
      // unsigned event the receiver will reject. Never throws into the caller.
      log.warn(`webhook: cannot resolve secret '${wh.secret_ref}', dropping ${event.decision} notification`);
      return;
    }
  }

  const url = wh.url;
  // Detached delivery. The governance decision is already settled + audited; this is best effort.
  void (async () => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
    try {
      await fetch(url, { method: "POST", headers, body: payload, signal: ctrl.signal });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      log.warn(`webhook: delivery to ${url} failed: ${msg}`);
    } finally {
      clearTimeout(timer);
    }
  })();
}

/**
 * Notify the configured webhook of one TRIGGER fire. Reuses the operator's single
 * `settings.webhook` URL + signing secret (there are no per-trigger webhook URLs) but posts a
 * distinct `type: "switchboard.trigger"` payload and IGNORES the decision `events` filter — a
 * trigger is not a decision, so the allow/deny/approval_required filter never applies to it.
 * Same fire-and-forget, fail-open, HMAC-signed delivery contract as `deliverWebhook`.
 */
export function deliverTriggerWebhook(
  cfg: SwitchboardConfig,
  event: TriggerWebhookEvent,
  resolveSecret: SecretResolver,
): void {
  const wh = cfg.settings?.webhook;
  if (!wh?.enabled || !wh.url) return;

  const payload = JSON.stringify({
    type: "switchboard.trigger",
    ts: new Date().toISOString(),
    trigger_id: event.trigger_id,
    ...(event.trigger_name ? { trigger_name: event.trigger_name } : {}),
    tool: event.tool,
    detection: event.detection,
    new_count: event.new_count,
    ...(event.sample_keys && event.sample_keys.length > 0 ? { sample_keys: event.sample_keys } : {}),
  });

  const headers: Record<string, string> = { "content-type": "application/json" };
  if (wh.secret_ref) {
    try {
      Object.assign(headers, signatureHeaders(payload, resolveSecret(wh.secret_ref)));
    } catch {
      // Promised a signature we can't produce: drop rather than send an unsigned event. Never throws.
      log.warn(`webhook: cannot resolve secret '${wh.secret_ref}', dropping trigger '${event.trigger_id}' notification`);
      return;
    }
  }

  const url = wh.url;
  void (async () => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
    try {
      await fetch(url, { method: "POST", headers, body: payload, signal: ctrl.signal });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      log.warn(`webhook: trigger delivery to ${url} failed: ${msg}`);
    } finally {
      clearTimeout(timer);
    }
  })();
}
