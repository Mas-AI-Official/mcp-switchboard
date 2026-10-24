/**
 * Secret hygiene for every string the connector layer lets out (errors, CLI lines, audit reasons).
 *
 * Two layers, applied in this order:
 *   1. exact values: the secrets this call actually handled (client secret, refresh token, access token,
 *      authorization code, PKCE verifier). A provider that echoes one of them in an error body cannot get
 *      it into our output, whatever shape it has. The base64 and percent-encoded forms are covered too,
 *      because Basic headers and form bodies carry them in those shapes.
 *   2. shapes: the audit log's pattern scrub (provider key prefixes, bearer tokens, JWTs, long tokens).
 *
 * The exact-value pass runs BEFORE any truncation, so a secret cut in half by a length cap is never left
 * behind as a recognisable prefix.
 */

import { redactSecretShapes } from "../audit.js";

const MIN_SECRET_LEN = 6;

function variants(secret: string): string[] {
  const out = new Set<string>([secret]);
  out.add(encodeURIComponent(secret));
  out.add(Buffer.from(secret, "utf8").toString("base64"));
  out.add(Buffer.from(secret, "utf8").toString("base64url"));
  return [...out].filter((v) => v.length >= MIN_SECRET_LEN);
}

/** Replace every occurrence of the given secrets (and their encoded forms), then scrub secret shapes. */
export function scrubSecrets(text: string, secrets: ReadonlyArray<string | undefined> = []): string {
  let out = text;
  for (const s of secrets) {
    if (!s || s.length < MIN_SECRET_LEN) continue;
    for (const v of variants(s)) out = out.split(v).join("[redacted]");
  }
  return redactSecretShapes(out);
}

/** `scrubSecrets` then cut to `max` characters (never the other way round). */
export function scrubAndClip(text: string, secrets: ReadonlyArray<string | undefined> = [], max = 240): string {
  const clean = scrubSecrets(text, secrets);
  return clean.length > max ? `${clean.slice(0, max)}...` : clean;
}
