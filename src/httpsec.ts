/**
 * HTTP hardening shared by the dashboard listener and the `expose` listener (design vNext 3.2).
 *
 * Why this exists. 0.1.0 trusted the TCP peer address: any process that could reach 127.0.0.1 (a tunnel
 * binary, a DNS-rebinding page, a local agent) was "the owner". This module replaces that with three
 * independent layers, each of which must pass:
 *   1. Host allowlist: a request whose Host header is not one of this listener's own names is refused,
 *      which is what defeats DNS rebinding (the browser still sends the attacker's hostname).
 *   2. Origin check: a browser always labels cross-site writes with an Origin; one that is not ours is refused.
 *   3. Owner session: the admin API needs an HttpOnly, SameSite=Strict cookie that is only obtainable by
 *      redeeming a single-use login code minted by `switchboard dashboard login` after an owner-presence
 *      check, plus a CSRF header on every mutating call. Client API keys are never accepted there.
 *
 * Everything here is plain functions and classes over node built-ins (no new dependency). Time is
 * injectable so the oracle can prove expiry without sleeping.
 */

import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { readFileSync, readdirSync, statSync, unlinkSync } from "node:fs";
import { connect } from "node:net";
import { join } from "node:path";
import type { ErrorRequestHandler, Request, RequestHandler, Response } from "express";
import { atomicWriteFileSync, ensureDir, readJsonFileSync, writeJsonAtomic } from "./atomicfile.js";
import { HOME_DIR } from "./vault.js";
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

// ── Host and Origin allowlist ─────────────────────────────────────────────────────────────────────

/**
 * Routes that may be reached through the public host (the OAuth issuer / tunnel): the MCP endpoint and
 * the OAuth authorization-server surface. Everything else (dashboard, /api/*, static, the connected
 * accounts callback) is loopback-only. Case-insensitive because Express routes are.
 */
export function isPublicRoutePath(path: string): boolean {
  const p = path.toLowerCase().replace(/\/+$/, "") || "/";
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
  return (path.toLowerCase().replace(/\/+$/, "") || "/") === "/mcp";
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

// ── single-use login codes (CLI mints, running gateway redeems) ───────────────────────────────────

export const LOGIN_CODE_TTL_MS = 120_000;
const CODE_SHAPE = /^[A-Za-z0-9_-]{16,200}$/;

export interface LoginCodeStoreOptions {
  /** Home dir holding `login-codes/`. Defaults to SWITCHBOARD_HOME. */
  dir?: string;
  ttlMs?: number;
  clock?: Clock;
}

/**
 * File-backed store of sha256(code): one file per code under `<home>/login-codes/`, named by the hash,
 * so the plaintext code never touches disk. It is deliberately a directory and not one JSON list: the
 * CLI process mints while the gateway process redeems, and a shared list would lose updates between
 * them (a redeemed code could be resurrected by a concurrent rewrite). Here redemption is `unlink`,
 * which succeeds for exactly one caller, so a code is single use across processes. Every redemption
 * re-reads the file, so a code minted after the gateway started is honoured.
 */
export class LoginCodeStore {
  private readonly dir: string;
  private readonly ttlMs: number;
  private readonly now: Clock;

  constructor(opts: LoginCodeStoreOptions = {}) {
    this.dir = join(opts.dir ?? HOME_DIR, "login-codes");
    this.ttlMs = opts.ttlMs ?? LOGIN_CODE_TTL_MS;
    this.now = opts.clock ?? Date.now;
  }

  private fileFor(code: string): string {
    return join(this.dir, `${sha256(code)}.json`);
  }

  /** Mint a code valid for the TTL. Returns the plaintext code; only its hash is stored. */
  mint(): string {
    ensureDir(this.dir);
    this.purge();
    const code = randomBytes(32).toString("base64url");
    const rec = { created: this.now(), expires: this.now() + this.ttlMs };
    // Temp file + fsync + rename: a redeemer never sees a half-written code. No .bak: a code is one use.
    atomicWriteFileSync(this.fileFor(code), JSON.stringify(rec), { mode: 0o600 });
    return code;
  }

  /** True exactly once per unexpired code. Unknown, malformed, expired and replayed codes are false. */
  redeem(code: unknown): boolean {
    if (typeof code !== "string" || !CODE_SHAPE.test(code)) return false;
    const file = this.fileFor(code);
    let raw: string;
    try {
      raw = readFileSync(file, "utf8");
    } catch {
      return false;
    }
    try {
      unlinkSync(file); // the claim: of N concurrent redeemers exactly one gets past this line
    } catch {
      return false;
    }
    try {
      const expires = Number((JSON.parse(raw) as { expires?: unknown }).expires);
      return Number.isFinite(expires) && this.now() < expires;
    } catch {
      return false;
    }
  }

  /** Delete expired code files. Returns how many were removed. */
  purge(): number {
    let removed = 0;
    let names: string[];
    try {
      names = readdirSync(this.dir);
    } catch {
      return 0;
    }
    for (const n of names) {
      if (!n.endsWith(".json")) continue;
      const f = join(this.dir, n);
      try {
        const expires = Number((JSON.parse(readFileSync(f, "utf8")) as { expires?: unknown }).expires);
        if (!Number.isFinite(expires) || expires <= this.now()) {
          unlinkSync(f);
          removed++;
        }
      } catch {
        /* unreadable or racing with a redeemer: leave it */
      }
    }
    return removed;
  }
}

// ── owner sessions ────────────────────────────────────────────────────────────────────────────────

export const SESSION_COOKIE = "switchboard_session";
export const CSRF_HEADER = "x-switchboard-csrf";
export const SESSION_TTL_MS = 12 * 60 * 60 * 1000;
const SID_SHAPE = /^[A-Za-z0-9_-]{20,128}$/;

/** The CSRF value is derived from the session id, so it survives a page reload and a gateway restart. */
const csrfFor = (sid: string): string => createHash("sha256").update(`switchboard-csrf-v1:${sid}`, "utf8").digest("base64url");

export interface OwnerSession {
  csrf: string;
  expires: number;
}

export interface OwnerSessionsOptions {
  /** Persisted list of hashed session ids. Defaults to `<SWITCHBOARD_HOME>/sessions.json`. */
  path?: string;
  ttlMs?: number;
  clock?: Clock;
  codes?: LoginCodeStore;
}

/**
 * Owner sessions: an in-memory map of sha256(session id) to expiry, mirrored to a persisted list of the
 * same hashes so a gateway restart does not log the owner out. Only hashes are stored, so a copy of
 * the file cannot be turned into a cookie. A corrupt file means nobody is logged in (fail closed).
 */
export class OwnerSessions {
  readonly codes: LoginCodeStore;
  private readonly path: string;
  private readonly ttlMs: number;
  private readonly now: Clock;
  private readonly live = new Map<string, number>();
  private diskMtime = -1;

  constructor(opts: OwnerSessionsOptions = {}) {
    this.path = opts.path ?? join(HOME_DIR, "sessions.json");
    this.ttlMs = opts.ttlMs ?? SESSION_TTL_MS;
    this.now = opts.clock ?? Date.now;
    this.codes = opts.codes ?? new LoginCodeStore({ clock: this.now });
    this.loadDisk();
  }

  get sessionTtlMs(): number {
    return this.ttlMs;
  }

  /** Redeem a login code for a new session. Null when the code is unknown, expired or already used. */
  login(code: unknown): { sid: string; csrf: string; expires: number } | null {
    if (!this.codes.redeem(code)) return null;
    const sid = randomBytes(32).toString("base64url");
    const expires = this.now() + this.ttlMs;
    this.prune();
    this.live.set(sha256(sid), expires);
    this.persist();
    return { sid, csrf: csrfFor(sid), expires };
  }

  lookup(sid: string | undefined): OwnerSession | null {
    if (!sid || !SID_SHAPE.test(sid)) return null;
    const h = sha256(sid);
    let expires = this.live.get(h);
    if (expires === undefined) {
      this.loadDisk();
      expires = this.live.get(h);
    }
    if (expires === undefined) return null;
    if (expires <= this.now()) {
      this.live.delete(h);
      this.persist();
      return null;
    }
    return { csrf: csrfFor(sid), expires };
  }

  /** The session behind a request's cookie, or null. */
  fromRequest(req: Request): OwnerSession | null {
    return this.lookup(readCookie(req, SESSION_COOKIE));
  }

  revoke(sid: string | undefined): boolean {
    if (!sid || !SID_SHAPE.test(sid)) return false;
    const had = this.live.delete(sha256(sid));
    if (had) this.persist();
    return had;
  }

  private prune(): void {
    const t = this.now();
    for (const [h, e] of this.live) if (e <= t) this.live.delete(h);
  }

  private loadDisk(): void {
    let mtime: number;
    try {
      mtime = statSync(this.path).mtimeMs;
    } catch {
      return; // no file yet
    }
    if (mtime === this.diskMtime) return;
    this.diskMtime = mtime;
    try {
      const parsed = readJsonFileSync<{ sessions?: { h?: unknown; expires?: unknown }[] }>(this.path) ?? {};
      const t = this.now();
      for (const s of parsed.sessions ?? []) {
        if (typeof s.h === "string" && typeof s.expires === "number" && s.expires > t && !this.live.has(s.h)) {
          this.live.set(s.h, s.expires);
        }
      }
    } catch (err) {
      log.warn(`owner session file ${this.path} is unreadable (${err instanceof Error ? err.message : String(err)}); no sessions restored`);
    }
  }

  private persist(): void {
    try {
      // Atomic replace (temp, fsync, rename). No .bak: a lost session only means logging in again, and a
      // backup would keep revoked session hashes on disk.
      writeJsonAtomic(this.path, { sessions: [...this.live].map(([h, expires]) => ({ h, expires })) }, { mode: 0o600, backup: false, space: 0 });
      this.diskMtime = statSync(this.path).mtimeMs;
    } catch (err) {
      log.warn(`could not persist owner sessions: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
}

export function readCookie(req: Request, name: string): string | undefined {
  const raw = req.headers.cookie;
  if (!raw) return undefined;
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return undefined;
}

/** Set the owner cookie: HttpOnly, SameSite=Strict, Path=/, lifetime = the session TTL. */
export function setSessionCookie(res: Response, sid: string, ttlMs: number, secure: boolean): void {
  res.append(
    "Set-Cookie",
    `${SESSION_COOKIE}=${sid}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${Math.floor(ttlMs / 1000)}${secure ? "; Secure" : ""}`,
  );
}

export function clearSessionCookie(res: Response, secure: boolean): void {
  res.append("Set-Cookie", `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure ? "; Secure" : ""}`);
}

/** Constant-time comparison of a presented CSRF value against the session's. */
export function csrfMatches(session: { csrf: string }, presented: unknown): boolean {
  if (typeof presented !== "string" || presented === "") return false;
  const a = Buffer.from(presented);
  const b = Buffer.from(session.csrf);
  return a.length === b.length && timingSafeEqual(a, b);
}

/**
 * Gate for every admin route: a valid owner session cookie is required, and mutating methods also need
 * the `X-Switchboard-CSRF` header to equal the session's CSRF value. Nothing else authenticates here:
 * Authorization headers and `x-api-key` are never read, so a client API key can never reach the admin API.
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
