/**
 * HTTP hardening shared by the dashboard listener and the `expose` listener (design vNext 3.2).
 *
 * Why this exists. 0.1.0 trusted the TCP peer address: any process that could reach 127.0.0.1 (a tunnel
 * binary, a DNS-rebinding page, a local agent) was "the owner". This module replaces that with three
 * independent layers, each of which must pass:
 *   1. Host allowlist: a request whose Host header is not one of this listener's own names is refused,
 *      which is what defeats DNS rebinding (the browser still sends the attacker's hostname).
 *   2. Origin check: a browser always labels cross-site writes with an Origin; one that is not ours is refused.
 *   3. Owner session: the admin API needs a session id sent in the X-Switchboard-Session header, only
 *      obtainable by redeeming a single-use login code that the RUNNING GATEWAY mints after its own owner-presence
 *      check (`switchboard dashboard login` asks it), plus a CSRF header on every mutating call. Codes and sessions
 *      live in the gateway's memory only. The session id is never a cookie: a cookie is sent to every port of the
 *      same host (it is not scoped by port), so any other local listener the browser visited would have held a
 *      working credential. Client API keys are never accepted there.
 *
 * Everything here is plain functions and classes over node built-ins (no new dependency). Time is
 * injectable so the oracle can prove expiry without sleeping.
 */

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { connect } from "node:net";
import type { ErrorRequestHandler, Request, RequestHandler, Response } from "express";
import { log } from "./logger.js";

export type Clock = () => number;

const sha256 = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");

// ── security headers ──────────────────────────────────────────────────────────────────────────────

/**
 * CSP for the SPA in `public/`: scripts only from this origin (no inline script, no eval), a same-origin
 * fetch surface, no plugins, no framing, no <base>. `style-src 'unsafe-inline'` is deliberate: the SPA and
 * the server-rendered consent and callback pages use inline style attributes and one <style> block, and
 * style injection is not the threat model here (script execution is). `img-src` allows https and http
 * because operators can set a logo URL in the auth-screen settings. `form-action` is intentionally absent:
 * Chrome applies it to the redirect that follows a form POST, which would break the OAuth consent
 * redirect back to the client.
 */
export const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: https: http:",
  "font-src 'self'",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
].join("; ");

/** Headers set on EVERY response (registered first, so refusals carry them too). */
export function securityHeaders(): RequestHandler {
  return (_req, res, next) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Content-Security-Policy", CONTENT_SECURITY_POLICY);
    next();
  };
}

/**
 * Terminal error handler. Express's default one prints the stack (absolute file paths) for a
 * malformed JSON body and replaces the response CSP with its own, so any caller could read internals.
 * This one answers with a bare JSON error (4xx keeps its status, anything else is a 500) and keeps the
 * security headers; the detail goes to the log only.
 */
export function jsonErrorHandler(): ErrorRequestHandler {
  return (err, _req, res, next) => {
    if (res.headersSent) return next(err);
    const status = Number((err as { status?: unknown })?.status ?? (err as { statusCode?: unknown })?.statusCode);
    const clientError = Number.isInteger(status) && status >= 400 && status < 500;
    if (!clientError) log.error(`request failed: ${err instanceof Error ? err.message : String(err)}`);
    res.status(clientError ? status : 500).json({ error: clientError ? "bad request" : "internal error" });
  };
}

// ── request size guards ───────────────────────────────────────────────────────────────────────────

/**
 * Longest request URL (path plus query) any route of this gateway accepts. Real URLs here are short (an
 * OAuth authorize request, with its PKCE challenge, redirect URI and state, is the longest in practice);
 * Node itself allows 16 KiB of headers, which is enough room for a hostile path to make later middleware
 * do needless work. Defence in depth: the pre-auth code is linear on its own, this bounds what it sees.
 */
export const MAX_URL_CHARS = 4096;

/**
 * Answer 414 to an over-long URL before anything else looks at it, Host check included (design 3.2 and
 * the DoS review: the Host check is the first thing that parses the path, so it must not meet a 16 KiB
 * one). Registered after `securityHeaders()` so the refusal still carries them. No body detail.
 */
export function urlLengthGuard(): RequestHandler {
  return (req, res, next) => {
    if ((req.originalUrl ?? req.url).length > MAX_URL_CHARS) {
      res.status(414).type("text/plain").send("uri too long");
      return;
    }
    next();
  };
}

/**
 * `s.replace(/\/+$/, "")` in linear time. That regex is quadratic on a string with a long run of
 * slashes that is not at the end (`//////x`): the engine retries from every slash of the run, and each
 * try scans to the end of the run. Used on request paths BEFORE the Host check, where the input is
 * chosen by whoever can reach the port, so it must stay linear.
 */
export function stripTrailingSlashes(s: string): string {
  let end = s.length;
  while (end > 0 && s.charCodeAt(end - 1) === 47) end--;
  return end === s.length ? s : s.slice(0, end);
}

// ── Host and Origin allowlist ─────────────────────────────────────────────────────────────────────

/**
 * Routes that may be reached through the public host (the OAuth issuer / tunnel): the MCP endpoint and
 * the OAuth authorization-server surface. Everything else (dashboard, /api/*, static, the connected
 * accounts callback) is loopback-only. Case-insensitive because Express routes are.
 */
export function isPublicRoutePath(path: string): boolean {
  const p = stripTrailingSlashes(path.toLowerCase()) || "/";
  return (
    p === "/mcp" ||
    p === "/authorize" ||
    p === "/token" ||
    p === "/register" ||
    p === "/revoke" ||
    p === "/oauth/consent" ||
    p.startsWith("/.well-known/")
  );
}

function isMcpPath(path: string): boolean {
  return (stripTrailingSlashes(path.toLowerCase()) || "/") === "/mcp";
}

const isSafeMethod = (m: string): boolean => m === "GET" || m === "HEAD";

export interface HostGuardOptions {
  /** The port this listener is bound to; the loopback names are only valid with it. */
  port: number;
  /** Issuer / tunnel URL whose host is also accepted, on public routes only. */
  publicUrl?: string;
}

/** Host and Origin allowlist (design 3.2). Refusals are a bare 403 with no detail. */
export class HostGuard {
  private port: number;
  private readonly publicHosts = new Set<string>();
  private readonly publicOrigins = new Set<string>();

  constructor(opts: HostGuardOptions) {
    this.port = opts.port;
    if (opts.publicUrl) this.addPublicUrl(opts.publicUrl);
  }

  setPort(port: number): void {
    this.port = port;
  }

  /** Accept the host (and its scheme+host+port origin) of `url` on public routes. Bad URLs are ignored. */
  addPublicUrl(url: string): void {
    try {
      const u = new URL(url);
      this.publicHosts.add(u.host.toLowerCase());
      this.publicOrigins.add(`${u.protocol}//${u.host}`.toLowerCase());
    } catch {
      /* an unparsable public URL simply adds nothing: fail closed */
    }
  }

  private loopbackHosts(): string[] {
    return [`127.0.0.1:${this.port}`, `localhost:${this.port}`, `[::1]:${this.port}`];
  }

  /** Exposed for the oracle and for callers that need the effective allowlist. */
  allowedHosts(publicRoute: boolean): Set<string> {
    const hosts = new Set(this.loopbackHosts());
    if (publicRoute) for (const h of this.publicHosts) hosts.add(h);
    return hosts;
  }

  allowedOrigins(publicRoute: boolean): Set<string> {
    const origins = new Set(this.loopbackHosts().map((h) => `http://${h}`));
    if (publicRoute) for (const o of this.publicOrigins) origins.add(o);
    return origins;
  }

  handler(): RequestHandler {
    return (req, res, next) => {
      const publicRoute = isPublicRoutePath(req.path);
      const host = (req.headers.host ?? "").toLowerCase();
      if (!host || !this.allowedHosts(publicRoute).has(host)) return void refuse(res);

      const origin = req.headers.origin;
      if (origin !== undefined && (!isSafeMethod(req.method) || isMcpPath(req.path))) {
        const o = String(Array.isArray(origin) ? origin[0] : origin).toLowerCase();
        if (!this.allowedOrigins(publicRoute).has(o)) return void refuse(res);
      }
      next();
    };
  }
}

function refuse(res: Response): void {
  res.status(403).type("text/plain").send("forbidden");
}

// ── single-use login codes (minted by the running gateway, redeemed by the running gateway) ──────

export const LOGIN_CODE_TTL_MS = 120_000;
const CODE_SHAPE = /^[A-Za-z0-9_-]{16,200}$/;
/** More outstanding codes than this means something is minting in a loop: the oldest is dropped. */
const MAX_OUTSTANDING_CODES = 32;

export interface LoginCodeStoreOptions {
  ttlMs?: number;
  clock?: Clock;
}

/**
 * Login codes, in the memory of the process that serves the dashboard and nowhere else. A code used to be a file
 * under SWITCHBOARD_HOME written by the CLI, which any process of the same OS user can write: planting
 * `login-codes/<sha256(code)>.json` made a session with no owner anywhere near it. Now the gateway mints a code
 * only after its own owner-presence check (the control API in dashboard.ts) and keeps only the hash. A code works
 * once and for `ttlMs`. Nothing is written to disk, so there is nothing for another process to plant, and a
 * restart forgets every code.
 */
export class LoginCodeStore {
  private readonly codes = new Map<string, number>();
  private readonly ttlMs: number;
  private readonly now: Clock;

  constructor(opts: LoginCodeStoreOptions = {}) {
    this.ttlMs = opts.ttlMs ?? LOGIN_CODE_TTL_MS;
    this.now = opts.clock ?? Date.now;
  }

  /** Mint a code valid for the TTL. Returns the plaintext code; only its hash is kept. */
  mint(): string {
    this.purge();
    while (this.codes.size >= MAX_OUTSTANDING_CODES) {
      const oldest = this.codes.keys().next().value;
      if (oldest === undefined) break;
      this.codes.delete(oldest);
    }
    const code = randomBytes(32).toString("base64url");
    this.codes.set(sha256(code), this.now() + this.ttlMs);
    return code;
  }

  /** True exactly once per unexpired code. Unknown, malformed, expired and replayed codes are false. */
  redeem(code: unknown): boolean {
    if (typeof code !== "string" || !CODE_SHAPE.test(code)) return false;
    const h = sha256(code);
    const expires = this.codes.get(h);
    if (expires === undefined) return false;
    this.codes.delete(h); // the claim: single use, whatever happens next
    return this.now() < expires;
  }

  /** Forget expired codes. Returns how many were removed. */
  purge(): number {
    let removed = 0;
    const t = this.now();
    for (const [h, expires] of this.codes) {
      if (expires <= t) {
        this.codes.delete(h);
        removed++;
      }
    }
    return removed;
  }
}

// ── owner sessions ────────────────────────────────────────────────────────────────────────────────

/** The request header that carries the owner session id. Never a cookie (see the file header). */
export const SESSION_HEADER = "x-switchboard-session";
export const CSRF_HEADER = "x-switchboard-csrf";
export const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const SID_SHAPE = /^[A-Za-z0-9_-]{20,128}$/;

export interface OwnerSession {
  csrf: string;
  expires: number;
}

export interface OwnerSessionsOptions {
  ttlMs?: number;
  clock?: Clock;
  codes?: LoginCodeStore;
}

/**
 * Owner sessions: a map of sha256(session id) to expiry and CSRF value, in this process's memory only. Nothing is
 * persisted (a session file is something another process of the same OS user could write), so a gateway restart
 * signs the owner out. The CSRF value is random per session and is handed over once, in the login answer; it is
 * not derived from the session id, so the id alone does not yield it.
 */
export class OwnerSessions {
  readonly codes: LoginCodeStore;
  private readonly ttlMs: number;
  private readonly now: Clock;
  private readonly live = new Map<string, { expires: number; csrf: string }>();

  constructor(opts: OwnerSessionsOptions = {}) {
    this.ttlMs = opts.ttlMs ?? SESSION_TTL_MS;
    this.now = opts.clock ?? Date.now;
    this.codes = opts.codes ?? new LoginCodeStore({ clock: this.now });
  }

  get sessionTtlMs(): number {
    return this.ttlMs;
  }

  /** Mint a login code. Only the gateway's own presence-checked route calls this. */
  mintLoginCode(): string {
    return this.codes.mint();
  }

  /** Redeem a login code for a new session. Null when the code is unknown, expired or already used. */
  login(code: unknown): { sid: string; csrf: string; expires: number } | null {
    if (!this.codes.redeem(code)) return null;
    const sid = randomBytes(32).toString("base64url");
    const csrf = randomBytes(32).toString("base64url");
    const expires = this.now() + this.ttlMs;
    this.prune();
    this.live.set(sha256(sid), { expires, csrf });
    return { sid, csrf, expires };
  }

  lookup(sid: string | undefined): OwnerSession | null {
    if (!sid || !SID_SHAPE.test(sid)) return null;
    const h = sha256(sid);
    const s = this.live.get(h);
    if (s === undefined) return null;
    if (s.expires <= this.now()) {
      this.live.delete(h);
      return null;
    }
    return { csrf: s.csrf, expires: s.expires };
  }

  /** The session behind a request's session header, or null. */
  fromRequest(req: Request): OwnerSession | null {
    return this.lookup(sessionIdOf(req));
  }

  revoke(sid: string | undefined): boolean {
    if (!sid || !SID_SHAPE.test(sid)) return false;
    return this.live.delete(sha256(sid));
  }

  private prune(): void {
    const t = this.now();
    for (const [h, s] of this.live) if (s.expires <= t) this.live.delete(h);
  }
}

/** The session id a request presents in the session header (a single string value), or undefined. */
export function sessionIdOf(req: Request): string | undefined {
  const v = req.headers[SESSION_HEADER];
  return typeof v === "string" ? v.trim() : undefined;
}

/** Constant-time comparison of a presented CSRF value against the session's. */
export function csrfMatches(session: { csrf: string }, presented: unknown): boolean {
  if (typeof presented !== "string" || presented === "") return false;
  const a = Buffer.from(presented);
  const b = Buffer.from(session.csrf);
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Gate for every admin route: a valid owner session in the `X-Switchboard-Session` header is required, and mutating
 * methods also need the `X-Switchboard-CSRF` header to equal the session's CSRF value. Nothing else authenticates
 * here: cookies, Authorization headers and `x-api-key` are never read, so neither a cookie that another port received
 * nor a client API key can reach the admin API.
 */
export function ownerSessionGate(sessions: OwnerSessions): RequestHandler {
  return (req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    const session = sessions.fromRequest(req);
    if (!session) {
      res.status(401).json({
        error: "owner session required: run `switchboard dashboard login` to sign in",
        code: "SB_OWNER_SESSION_REQUIRED",
      });
      return;
    }
    if (!isSafeMethod(req.method) && !csrfMatches(session, req.get(CSRF_HEADER))) {
      res.status(403).json({ error: "missing or invalid CSRF header", code: "SB_CSRF" });
      return;
    }
    res.locals.ownerSession = session;
    next();
  };
}

// ── DCR rate limit and cap ────────────────────────────────────────────────────────────────────────

export const DCR_MAX_CLIENTS = 50;
export const DCR_PER_HOUR = 20;

export interface DcrLimiterOptions {
  maxClients?: number;
  perHour?: number;
  clock?: Clock;
  /** How many clients are registered right now. */
  clientCount: () => number;
}

/**
 * Dynamic client registration is open by design (RFC 7591) so it must be bounded: at most `perHour`
 * attempts in a rolling hour, and no registration once `maxClients` exist. The window is global, not
 * per IP: behind a tunnel every caller shares the loopback address, so an IP key would mean nothing.
 */
export class DcrLimiter {
  private stamps: number[] = [];
  private readonly maxClients: number;
  private readonly perHour: number;
  private readonly now: Clock;

  constructor(private readonly opts: DcrLimiterOptions) {
    this.maxClients = opts.maxClients ?? DCR_MAX_CLIENTS;
    this.perHour = opts.perHour ?? DCR_PER_HOUR;
    this.now = opts.clock ?? Date.now;
  }

  handler(): RequestHandler {
    return (req, res, next) => {
      if (req.method !== "POST") return next();
      const t = this.now();
      this.stamps = this.stamps.filter((s) => t - s < 3_600_000);
      if (this.opts.clientCount() >= this.maxClients) {
        res.status(429).json({
          error: "too_many_clients",
          error_description: `this server holds the maximum of ${this.maxClients} registered clients; the owner must remove one first`,
        });
        return;
      }
      if (this.stamps.length >= this.perHour) {
        const retryAfter = Math.max(1, Math.ceil((this.stamps[0]! + 3_600_000 - t) / 1000));
        res.set("Retry-After", String(retryAfter));
        res.status(429).json({
          error: "too_many_requests",
          error_description: `client registration is limited to ${this.perHour} per hour`,
        });
        return;
      }
      this.stamps.push(t);
      next();
    };
  }
}

// ── fail loudly on a busy port ────────────────────────────────────────────────────────────────────

function probeListening(host: string, port: number, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = connect({ host, port });
    const done = (listening: boolean): void => {
      sock.destroy();
      resolve(listening);
    };
    sock.setTimeout(timeoutMs, () => done(false));
    sock.once("connect", () => done(true));
    sock.once("error", () => done(false));
  });
}

/**
 * Refuse to start when something already accepts connections where we are about to listen. The
 * `listen` error alone is not enough: on Windows a second process can bind 127.0.0.1:<port> while
 * another holds 0.0.0.0:<port> (or [::1]:<port>) and traffic then goes to whichever answers, so the
 * new instance would run beside a stranger and look healthy. A connect probe sees that case.
 * Throws with `message` (or a default) when the port is taken.
 */
export async function assertPortFree(host: string, port: number, message?: string): Promise<void> {
  const loopback = host === "127.0.0.1" || host === "localhost" || host === "::1" || host.startsWith("127.");
  const wildcard = host === "0.0.0.0" || host === "::" || host === "";
  const targets = loopback ? ["127.0.0.1", "::1"] : wildcard ? ["127.0.0.1"] : [host];
  for (const t of targets) {
    if (await probeListening(t, port, 1000)) {
      throw new Error(message ?? `port ${port} is already in use by another process (${t}:${port} accepted a connection); stop it or change gateway.http.port`);
    }
  }
}
