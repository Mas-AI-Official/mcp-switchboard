/**
 * HTTP server — hosts everything on one port:
 *   1. The MCP Streamable HTTP endpoint at `/mcp` (stateless: a fresh Server +
 *      transport per request, the pattern the SDK recommends for stateless servers).
 *   2. The dashboard SPA — static files served from `public/` — plus the JSON API
 *      it calls (catalog, toolkits, settings, usage, audit, api keys, OAuth).
 *
 * Bound to `gateway.http.host` (127.0.0.1 by default) — local-first means the
 * endpoint is not exposed to the network unless the operator deliberately changes it.
 *
 * Hardening (design vNext 3.2, see httpsec.ts): every route passes a Host allowlist and an Origin check;
 * every response carries the security headers; every `/api/*` route except `/healthz` and
 * `/api/health` needs an owner session cookie (plus a CSRF header when it mutates). Client API
 * keys authenticate `/mcp` only and are never read by the admin API.
 */

import { createHmac } from "node:crypto";
import { fileURLToPath } from "node:url";
import express, { type Request, type Response } from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { Gateway } from "./gateway.js";
import { VERSION } from "./gateway.js";
import type { SwitchboardConfig, SettingsConfig, ServerConfig, CouncilConfig, ClientConfig } from "./types.js";
import type { BreakerHealth, BreakerState } from "./breaker.js";
import { writeConfig, parseTriggersConfig, configIssues, uniqueServerId } from "./config.js";
import { isExactNpmVersion, isPinnedNpmSpec, npmPackageName } from "./packagespec.js";
import { audit, recentAudit, usageStats } from "./audit.js";
import { resolveRisk, resolveToolScope, DEFAULT_REQUIRE_FOR_RISK } from "./policy.js";
import { killStatus, setKillFile } from "./killswitch.js";
import { DEFAULT_TTL_SECONDS, type ApprovalChannel, type ApprovalOutcome } from "./approvals.js";
import { bearerOf, controlTokenMatches, newControlToken, writeControlKey } from "./controlkey.js";
import { activeProfileName, describeProfile } from "./profiles.js";
import { ApiKeyStore } from "./apikeys.js";
import { ClientAdmin, ClientAdminError } from "./clientadmin.js";
import { ClientConfigWatcher } from "./clientconfig.js";
import { establishPrincipal, isValidClientId } from "./principal.js";
import { loadCatalog, queryCatalog, type CatalogSnapshot, type Toolkit } from "./catalog.js";
import { listTriggerTemplates } from "./trigger-templates.js";
import { mcpAuthRouter, getOAuthProtectedResourceMetadataUrl } from "@modelcontextprotocol/sdk/server/auth/router.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { resolveOAuthServerOptions, SwitchboardAuthProvider, OAUTH_SCOPES_SUPPORTED } from "./authserver.js";
import {
  CSRF_HEADER,
  DcrLimiter,
  HostGuard,
  jsonErrorHandler,
  LoginCodeStore,
  OwnerSessions,
  SESSION_COOKIE,
  assertPortFree,
  clearSessionCookie,
  csrfMatches,
  ownerSessionGate,
  readCookie,
  securityHeaders,
  setSessionCookie,
  urlLengthGuard,
  type Clock,
} from "./httpsec.js";
import { log } from "./logger.js";
import { guardedFetch } from "./netguard.js";
import { safeText } from "./safetext.js";

export interface DashboardHandle {
  url: string;
  close: () => Promise<void>;
}

/**
 * Test and embedding seams. Production passes none of these: defaults are the wall clock, the 120 s
 * login-code TTL, the 12 h session TTL and the 50-client / 20-per-hour DCR limits from design 3.2.
 */
export interface DashboardOptions {
  clock?: Clock;
  loginCodeTtlMs?: number;
  sessionTtlMs?: number;
  dcr?: { maxClients?: number; perHour?: number };
}

/** Where the built SPA lives: `public/` at the package root (one level above dist/ or src/). */
function publicDir(): string {
  return fileURLToPath(new URL("../public", import.meta.url));
}

/** A loopback bind needs no network auth; anything else is reachable by other hosts. */
function isLoopbackHost(host: string): boolean {
  return host === "127.0.0.1" || host === "localhost" || host === "::1" || host.startsWith("127.");
}

/** Resolve whether `/mcp` requires an API key, given the configured mode and bind host. */
function authRequired(mode: "auto" | "always" | "never", host: string): boolean {
  if (mode === "always") return true;
  if (mode === "never") return false;
  return !isLoopbackHost(host); // auto: require iff exposed beyond loopback
}

/** Pull a bearer token from `Authorization: Bearer <t>` or the `x-api-key` header. */
function presentedToken(req: Request): string | null {
  const auth = req.headers["authorization"];
  if (typeof auth === "string" && auth.startsWith("Bearer ")) return auth.slice(7).trim();
  const apiKey = req.headers["x-api-key"];
  if (typeof apiKey === "string" && apiKey.trim()) return apiKey.trim();
  return null;
}

/**
 * True if the TCP peer is a loopback address. It is NO LONGER an authorization gate: a tunnel binary or a
 * DNS-rebinding page also connects from loopback, so the peer address proves nothing about who is
 * asking (defect D4). Admin routes are gated by the owner session in httpsec.ts. The predicate is kept
 * exported, unchanged, only because the dashboard oracle pins its behaviour.
 */
export function isLocalRequest(req: Request): boolean {
  const ip = req.ip ?? req.socket.remoteAddress ?? "";
  return ip === "127.0.0.1" || ip === "::1" || ip === "::ffff:127.0.0.1" || ip.startsWith("127.");
}

/**
 * Map currently-configured servers back to the catalog slugs they were mounted from, by matching
 * each server's identifying upstream value against the catalog (remote→url, npx→package,
 * app2mcp→openapi). Correlation is by upstream identity, NOT a stored slug, so it survives id
 * renames and hand-added servers; `manual`-source toolkits (no mountable identity) never match.
 * Used to float already-mounted toolkits to the front of the catalog grid and badge them as added.
 * Exported so the deterministic dashboard oracle can prove the correlation without a live server.
 */
export function correlateMountedSlugs(toolkits: Toolkit[], servers: ServerConfig[]): Set<string> {
  const byRemote = new Map<string, string>();
  const byNpx = new Map<string, string>();
  const byApp2mcp = new Map<string, string>();
  for (const t of toolkits) {
    if (t.mount.source === "remote") byRemote.set(t.mount.url, t.slug);
    else if (t.mount.source === "npx") byNpx.set(npmPackageName(t.mount.package), t.slug);
    else if (t.mount.source === "app2mcp") byApp2mcp.set(t.mount.openapi, t.slug);
  }
  const mounted = new Set<string>();
  for (const s of servers) {
    let slug: string | undefined;
    if (s.url) slug = byRemote.get(s.url);
    else if (s.package) slug = byNpx.get(npmPackageName(s.package)); // a pinned `name@1.2.3` is still the catalog's `name`
    else if (s.openapi) slug = byApp2mcp.get(s.openapi);
    if (slug) mounted.add(slug);
  }
  return mounted;
}

/**
 * Honest page count for a paginated catalog response. Clamps `limit` to the SAME [1,200] window
 * `queryCatalog` enforces internally, so `total_pages` reflects the page size actually used (a
 * caller asking for limit=500 is paginated by 200, and the page count says so). Zero results → 0.
 * Exported for the oracle.
 */
export function pageCount(total: number, limit: number): number {
  const effective = Math.min(200, Math.max(1, limit || 60));
  return total <= 0 ? 0 : Math.ceil(total / effective);
}

/** The non-secret council summary surfaced by `/api/settings`. */
export interface CouncilSummary {
  enabled: boolean;
  providers: { anthropic: boolean; openai: boolean; local: boolean };
  /** The local provider's NON-secret endpoint+model, so the Playground can offer the zero-cloud path. */
  local: { base_url: string; default_model: string } | null;
  max_rounds: number;
  token_budget: number;
  require_approval: boolean;
}

/**
 * Reduce the council config to a settings-safe summary: which providers are configured (booleans)
 * and the local provider's non-secret base_url/default_model — but NEVER any `api_key_ref` value.
 * Absent council → disabled with no providers. Exported so the oracle can pin the redaction.
 */
export function councilSummary(council?: CouncilConfig): CouncilSummary {
  const p = council?.providers;
  return {
    enabled: Boolean(council?.enabled),
    providers: {
      anthropic: Boolean(p?.anthropic),
      openai: Boolean(p?.openai),
      local: Boolean(p?.local),
    },
    local: p?.local ? { base_url: p.local.base_url, default_model: p.local.default_model } : null,
    max_rounds: council?.max_rounds ?? 3,
    token_budget: council?.token_budget ?? 2048,
    require_approval: Boolean(council?.require_approval),
  };
}

/** One row of `/api/health`: a declared server folded together with its live mount + circuit state. */
export interface ServerHealthRow {
  id: string;
  source: string;
  enabled: boolean;
  /** True iff the registry currently holds a live client for this id. */
  mounted: boolean;
  /** Tool count when mounted, 0 otherwise (never a stale/guessed number). */
  tools: number;
  /** Circuit-breaker state; "closed" when the breaker has never observed this server. */
  circuit: BreakerState;
  consecutiveFailures: number;
  retryAfterMs: number;
}

/** The `/api/health` payload: a per-server roll-up plus a single ok/degraded verdict. */
export interface HealthReport {
  status: "ok" | "degraded";
  servers: ServerHealthRow[];
  summary: { total: number; mounted: number; enabled: number; circuits_open: number };
}

/**
 * Fold the declared servers, the live mount map, and circuit-breaker health into one honest report.
 * `configured` is the declared server surface (id/source/enabled). `mounted` maps a server id → its
 * live tool count; PRESENCE in the map means the registry holds a client for it (the value is the
 * tool count, used verbatim — never guessed). `circuits` is `Router.serverHealth()`; the breaker only
 * tracks servers it has actually CALLED, so a freshly-mounted-but-never-called server is absent and
 * defaults to a closed circuit. The verdict is "degraded" iff some ENABLED server failed to mount OR
 * some circuit is open — a `half_open` probe and a deliberately-disabled (and therefore unmounted)
 * server do NOT degrade. Breaker rows whose id is not in `configured` are ignored, so a stale/synthetic
 * breaker entry can never fabricate a server row. Exported so the oracle can pin the verdict offline.
 */
export function buildHealthReport(
  configured: { id: string; source: string; enabled: boolean }[],
  mounted: Map<string, number>,
  circuits: BreakerHealth[],
): HealthReport {
  const byId = new Map(circuits.map((c) => [c.server, c]));
  let circuitsOpen = 0;
  let degraded = false;
  const servers: ServerHealthRow[] = configured.map((s) => {
    const isMounted = mounted.has(s.id);
    const c = byId.get(s.id);
    const circuit: BreakerState = c?.state ?? "closed";
    if (circuit === "open") {
      circuitsOpen++;
      degraded = true;
    }
    if (s.enabled && !isMounted) degraded = true;
    return {
      id: s.id,
      source: s.source,
      enabled: s.enabled,
      mounted: isMounted,
      tools: mounted.get(s.id) ?? 0,
      circuit,
      consecutiveFailures: c?.consecutiveFailures ?? 0,
      retryAfterMs: c?.retryAfterMs ?? 0,
    };
  });
  return {
    status: degraded ? "degraded" : "ok",
    servers,
    summary: {
      total: configured.length,
      mounted: servers.filter((s) => s.mounted).length,
      enabled: configured.filter((s) => s.enabled).length,
      circuits_open: circuitsOpen,
    },
  };
}

export interface McpEndpointOptions {
  /**
   * Re-evaluated per request so a live settings change to `require_auth` takes effect
   * without a restart. Return true to demand a valid bearer key.
   */
  requireAuth: () => boolean;
  /** The key store the bearer token is verified against. */
  apiKeys: ApiKeyStore;
  /**
   * Optional OAuth bearer verifier. When the built-in Authorization Server is enabled, the
   * `/mcp` gate accepts EITHER a valid API key OR an OAuth access token this resolves to a
   * non-null `AuthInfo`. Never throws (the provider's `verifyToken` swallows errors → null).
   */
  verifyOAuthToken?: (token: string) => Promise<AuthInfo | null>;
  /**
   * RFC 9728 protected-resource metadata URL. When set, an unauthenticated `/mcp` response
   * advertises it via `WWW-Authenticate: Bearer ..., resource_metadata="<url>"` so a spec
   * client (e.g. claude.ai web) can discover the Authorization Server and start the flow.
   */
  resourceMetadataUrl?: string;
  /**
   * The configured clients right now (design 3.1), read on every request so a reload takes effect at once.
   * While it holds an entry, `/mcp` requires a principal bound to a configured client, whatever `requireAuth`
   * says and whatever the bind host is. Omitted = no clients (the 0.1.0 behavior).
   */
  clients?: () => Record<string, ClientConfig> | undefined;
  /** The name an OAuth client registered with (RFC 7591), used to map an OAuth token to a configured client. */
  oauthClientName?: (oauthClientId: string) => string | undefined;
  /**
   * Respond with plain JSON instead of an SSE stream. Needed behind tunnels that do not
   * support Server-Sent Events (e.g. cloudflared quick tunnels). Safe for the stateless
   * server pattern, where each `/mcp` POST is a single request/response.
   */
  enableJsonResponse?: boolean;
}

/**
 * Register the MCP Streamable HTTP endpoint (`/mcp`) on an express app. This is the single
 * source of truth for the endpoint's auth gate, so the dashboard and `switchboard expose`
 * enforce bearer auth identically. Stateless: a fresh Server + transport per request.
 */
export function mountMcpEndpoint(app: express.Express, gateway: Gateway, opts: McpEndpointOptions): void {
  app.all("/mcp", async (req: Request, res: Response) => {
    // Gate before doing any work. Fail closed: a missing/invalid key is a 401, and we
    // never echo or log the presented token. A presented credential is always checked (even when auth is
    // not required) so the call is attributed to its key; a bad one only matters when a principal is needed.
    const clients = opts.clients?.();
    const token = presentedToken(req);
    let apiKey: ReturnType<ApiKeyStore["authenticate"]> = null;
    let oauth: { clientId: string; clientName?: string } | null = null;
    if (token) {
      apiKey = opts.apiKeys.authenticate(token);
      if (!apiKey && opts.verifyOAuthToken) {
        // Never throws (the provider's verifyToken swallows errors -> null). The token is not echoed or logged.
        const info = await opts.verifyOAuthToken(token);
        if (info) oauth = { clientId: info.clientId, clientName: opts.oauthClientName?.(info.clientId) };
      }
    }
    const decision = establishPrincipal({
      clients,
      apiKey: apiKey ? { id: apiKey.id, client: apiKey.client } : null,
      oauth,
      authRequired: opts.requireAuth(),
    });
    if (!decision.ok) {
      if (decision.status === 401) {
        // RFC 9728: point spec clients at the protected-resource metadata so they can
        // discover the Authorization Server and run the PKCE flow.
        const challenge = opts.resourceMetadataUrl
          ? `Bearer realm="switchboard", resource_metadata="${opts.resourceMetadataUrl}"`
          : 'Bearer realm="switchboard"';
        res.set("WWW-Authenticate", challenge);
        res.status(401).json({ error: decision.error });
      } else {
        res.status(403).json({ error: decision.error, code: decision.code, hint: decision.hint });
      }
      return;
    }
    const principal = decision.principal;
    // This endpoint is stateless (a fresh Server and transport per request), so there is no session for a standalone
    // GET to attach a server-to-client stream to. The SDK would open an event stream anyway and hold the socket for
    // as long as the client likes: an unbounded resource per caller. The Streamable HTTP spec lets a server answer
    // 405 to say it offers no such stream. Authentication comes first, so an unauthenticated GET is still a 401.
    if (req.method === "GET") {
      res.set("Allow", "POST");
      res.status(405).json({ error: "method not allowed: this MCP endpoint is stateless and offers no event stream; POST JSON-RPC messages to /mcp" });
      return;
    }
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      ...(opts.enableJsonResponse ? { enableJsonResponse: true } : {}),
    });
    res.on("close", () => void transport.close());
    try {
      const server = gateway.buildServer(principal);
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      log.error(`/mcp request failed: ${msg}`);
      if (!res.headersSent) res.status(500).json({ error: msg });
    }
  });
}

/**
 * Start the HTTP server. `configPath` is where settings/toggles are persisted so
 * they survive a restart; pass undefined to keep changes in-memory only.
 */
export async function startDashboard(
  gateway: Gateway,
  cfg: SwitchboardConfig,
  configPath?: string,
  opts: DashboardOptions = {},
): Promise<DashboardHandle> {
  const { host, port } = cfg.gateway.http;
  // Refuse to start beside another listener (including a wildcard or ::1 bind that would shadow us).
  await assertPortFree(host, port);

  const clock: Clock = opts.clock ?? Date.now;
  const app = express();
  app.disable("x-powered-by");
  app.use(securityHeaders());
  // Over-long URLs are refused before the Host check parses the path (DoS review).
  app.use(urlLengthGuard());
  // Host and Origin are checked before any body is parsed and before any route runs.
  const guard = new HostGuard({ port });
  app.use(guard.handler());
  app.use(express.json());

  const sessions = new OwnerSessions({
    clock,
    ttlMs: opts.sessionTtlMs,
    codes: new LoginCodeStore({ clock, ttlMs: opts.loginCodeTtlMs }),
  });
  const apiKeys = new ApiKeyStore();
  // The clients section follows the config file (design 3.1): `switchboard client add` on the CLI reaches this
  // running gateway without a restart. Only `clients` is reloaded; every other setting needs a restart.
  const clientWatcher = new ClientConfigWatcher(cfg, configPath);
  const clientAdmin = new ClientAdmin({ cfg, configPath, apiKeys, watcher: clientWatcher, actor: "dashboard" });
  const liveClients = (): Record<string, ClientConfig> | undefined => {
    clientWatcher.sync();
    return cfg.clients;
  };
  // `let`, not `const`: a settings change to require_auth re-evaluates this live.
  let requireAuth = authRequired(cfg.gateway.http.require_auth, host);

  // The toolkit catalog is a static snapshot loaded once; `toolkits sync` rewrites the
  // file out of band, and a dashboard restart picks it up. Reload lazily if it was empty.
  let catalog: CatalogSnapshot = loadCatalog();

  // --- OAuth 2.1 + PKCE Authorization Server (optional; for claude.ai-web over a tunnel) ---
  // Off unless `settings.oauth_server.enabled`. When on, this dashboard's own `/mcp` becomes
  // an OAuth Resource Server: a spec client discovers metadata, dynamically registers, runs
  // the PKCE authorize→consent→token dance, then presents a bearer token. Mounting the SDK
  // router at the app ROOT (its hard contract) installs `/.well-known/*`, `/authorize`,
  // `/token`, `/register`, and `/revoke`. `resolveOAuthServerOptions` fails closed: it logs
  // and returns null if enabled-without-public_url, so a misconfig never silently runs HTTP.
  const oauthOpts = resolveOAuthServerOptions(cfg);
  let oauthProvider: SwitchboardAuthProvider | undefined;
  let resourceMetadataUrl: string | undefined;
  if (oauthOpts) {
    oauthProvider = new SwitchboardAuthProvider(oauthOpts, cfg.settings?.auth_screen, {
      sessionFor: (r) => sessions.fromRequest(r),
      resumeUrl: (id) => `http://127.0.0.1:${port}/oauth/consent?pending_id=${encodeURIComponent(id)}`,
    });
    // The issuer host is reachable on /mcp and the OAuth routes only (never the dashboard or /api/*).
    guard.addPublicUrl(oauthOpts.publicUrl);
    if (!oauthOpts.consent) {
      log.warn(
        "settings.oauth_server.consent is false: every registered client is auto-approved WITHOUT an owner session. Set consent: true unless this is a throwaway instance",
      );
    }
    // Registration is open by design (RFC 7591), so bound it: 20 attempts per hour, 50 clients total.
    // This runs before the SDK router, whose own per-IP limiter is switched off below (behind a tunnel
    // every caller shares one IP, so an IP key would mean nothing).
    app.use(
      "/register",
      new DcrLimiter({ ...opts.dcr, clock, clientCount: () => oauthProvider!.clientCount() }).handler(),
    );
    app.use(
      mcpAuthRouter({
        provider: oauthProvider,
        issuerUrl: oauthOpts.issuerUrl,
        // Supplying the resource server URL makes the router also advertise RFC 9728
        // protected-resource metadata pointing back at this issuer.
        resourceServerUrl: new URL(oauthOpts.canonicalResource),
        scopesSupported: [...OAUTH_SCOPES_SUPPORTED],
        resourceName: "MCP Switchboard",
        // Public clients (claude.ai) register without a secret; any issued secret never expires.
        clientRegistrationOptions: { clientSecretExpirySeconds: 0, rateLimit: false },
      }),
    );
    // A signed-in owner who was bounced to the sign-in page resumes the pending request here.
    app.get("/oauth/consent", (req: Request, res: Response) => {
      const pendingId = typeof req.query.pending_id === "string" ? req.query.pending_id : "";
      const owner = sessions.fromRequest(req);
      res.set("Cache-Control", "no-store");
      const html = owner ? oauthProvider!.renderPendingConsent(pendingId, owner.csrf) : oauthProvider!.renderOwnerRequired(pendingId);
      if (!html) {
        res.status(400).type("html").send(callbackPage("This authorization request expired. Start again from your client.", false, cfg.settings?.auth_screen));
        return;
      }
      res.status(owner ? 200 : 401).type("html").send(html);
    });
    // The consent screen rendered by the provider's `authorize()` POSTs the owner's decision here. It needs
    // an owner session AND the CSRF value (header or form field): the requester can never self-approve.
    // Finalize it and 302 the user-agent back to the client with a code, or 400 an expired/unknown
    // request with a themed page.
    app.post("/oauth/consent", express.urlencoded({ extended: false }), (req: Request, res: Response) => {
      const owner = sessions.fromRequest(req);
      if (!owner) {
        res
          .status(401)
          .type("html")
          .send(callbackPage("Owner sign-in required: run `switchboard dashboard login` and approve from that browser.", false, cfg.settings?.auth_screen));
        return;
      }
      const body = (req.body ?? {}) as { pending_id?: unknown; decision?: unknown; csrf?: unknown };
      if (!csrfMatches(owner, req.get(CSRF_HEADER) ?? body.csrf)) {
        res.status(403).type("html").send(callbackPage("This consent request was rejected: missing or invalid CSRF value.", false, cfg.settings?.auth_screen));
        return;
      }
      const pendingId = typeof body.pending_id === "string" ? body.pending_id : "";
      const url = oauthProvider!.completeConsent(pendingId, body.decision === "approve");
      if (!url) {
        res
          .status(400)
          .type("html")
          .send(callbackPage("This authorization request expired — start again from your client.", false, cfg.settings?.auth_screen));
        return;
      }
      res.redirect(url);
    });
    resourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(new URL(oauthOpts.canonicalResource));
    // A tunnel-fronted endpoint must NEVER serve `/mcp` unauthenticated. Force the gate on
    // regardless of the loopback `require_auth` heuristic — the public issuer implies exposure.
    requireAuth = true;
    log.info(
      `OAuth 2.1 Authorization Server enabled — issuer ${oauthOpts.issuerUrl.href} · /mcp now requires an API key OR an OAuth bearer token`,
    );
  }

  // --- MCP Streamable HTTP endpoint (stateless) ---
  // `() => requireAuth` is re-read per request so a live settings change takes effect.
  mountMcpEndpoint(app, gateway, {
    requireAuth: () => requireAuth,
    apiKeys,
    verifyOAuthToken: oauthProvider ? (t) => oauthProvider!.verifyToken(t) : undefined,
    oauthClientName: oauthProvider ? (id) => oauthProvider!.clientNameOf(id) : undefined,
    clients: liveClients,
    resourceMetadataUrl,
  });

  // ====================================================================
  // Routes outside the owner gate, on purpose: liveness, health, and the login exchange itself.
  // Registered BEFORE the gate below; Express runs middleware in registration order, so every
  // /api route registered after `app.use("/api", ...)` is owner-session protected by construction.
  // ====================================================================
  // --- Liveness probe: a tiny, dependency-free 200 for uptime monitors / `docker healthcheck` /
  // k8s readiness. Reveals only the service name + version + process uptime: no config, no server
  // ids. Registered before the SPA catch-all so the exact path wins over the fallback handler. ---
  app.get("/healthz", (_req: Request, res: Response) => {
    res.json({
      status: "ok",
      service: "switchboard",
      version: VERSION,
      uptime_s: Math.round(process.uptime()),
      // Liveness is unaffected by the kill switch (the process is up); the flag tells a monitor that
      // every tool call, resource read and prompt get is currently refused.
      kill_switch: killStatus(cfg).active,
    });
  });

  // --- Readiness/health: per-server mount + circuit-breaker roll-up with one ok/degraded verdict.
  // Unauthenticated by design (monitors poll it); it exposes only server ids + circuit state, never
  // secrets. This is the endpoint that wires the otherwise-dead Router.serverHealth() into an
  // operator-visible surface. ---
  app.get("/api/health", (_req: Request, res: Response) => {
    const configured = cfg.servers.map((s) => ({ id: s.id, source: s.source, enabled: s.enabled !== false }));
    const mounted = new Map<string, number>();
    for (const s of cfg.servers) {
      const m = gateway.registry.get(s.id);
      if (m) mounted.set(s.id, m.tools.length);
    }
    const report = buildHealthReport(configured, mounted, gateway.router.serverHealth());
    // 200 when ready, 503 when degraded, so a monitor polling /api/health gets an honest HTTP signal,
    // not a green 200 hiding an unmounted/tripped upstream.
    // The kill switch is an operator decision, not a fault, so like a disabled server it does not
    // degrade the verdict; it is reported beside it so a monitor can alert on it deliberately.
    res.status(report.status === "ok" ? 200 : 503).json({ ...report, kill_switch: killStatus(cfg) });
  });

  // Exchange a one-time login code (minted by `switchboard dashboard login`) for the owner session.
  app.post("/api/session", (req: Request, res: Response) => {
    res.set("Cache-Control", "no-store");
    const body = (req.body ?? {}) as { code?: unknown };
    const session = sessions.login(body.code);
    if (!session) {
      res.status(401).json({ error: "invalid, expired or already used login code", code: "SB_LOGIN_CODE" });
      return;
    }
    setSessionCookie(res, session.sid, sessions.sessionTtlMs, req.secure);
    res.json({ csrf: session.csrf, expires_at: new Date(session.expires).toISOString() });
  });

  // ====================================================================
  // Control API (design 3.3): how `switchboard approvals ...` reaches THIS running gateway. It is a separate
  // router with its own credential, the control token minted at start and kept in SWITCHBOARD_HOME/control.key
  // (DPAPI-wrapped). An owner session does not open it and the control token does not open the owner routes.
  // The token is a convenience that keeps stray local callers out; the security boundary is the owner presence
  // check the gateway performs inside approve() (Windows Hello), which no caller can answer for the owner.
  // ====================================================================
  const approvals = gateway.approvals;
  const controlToken = newControlToken();
  try {
    writeControlKey(controlToken);
  } catch (err) {
    log.warn(`could not store the control key (${err instanceof Error ? err.message : String(err)}): \`switchboard approvals\` cannot reach this gateway; decide approvals in the dashboard`);
  }

  const outcomeToResponse = (res: Response, out: ApprovalOutcome, key: string): void => {
    if (out.ok) {
      res.json({ [key]: true, approval: out.record });
      return;
    }
    res.status(out.status).json({ error: out.error, code: out.code, ...(out.record ? { approval: out.record } : {}) });
  };
  const approvalError = (res: Response, err: unknown): void => {
    res.status(500).json({ error: `the approval store cannot be used: ${err instanceof Error ? err.message : String(err)}`, code: "SB_APPROVAL_STORE" });
  };
  /** Approve through the gateway's own presence check, whichever door the request came through. */
  const approveVia = (via: ApprovalChannel) => async (req: Request, res: Response): Promise<void> => {
    try {
      outcomeToResponse(res, await approvals.approve(String(req.params.id), via), "approved");
    } catch (err) {
      approvalError(res, err);
    }
  };
  const denyVia = (via: ApprovalChannel) => (req: Request, res: Response): void => {
    try {
      outcomeToResponse(res, approvals.deny(String(req.params.id), via), "denied");
    } catch (err) {
      approvalError(res, err);
    }
  };
  const approvalsPayload = () => ({
    ...approvals.list(),
    now: new Date().toISOString(),
    ttl_seconds: cfg.gateway.approval?.ttl_seconds ?? DEFAULT_TTL_SECONDS,
    require_for_risk: cfg.gateway.approval?.require_for_risk ?? [...DEFAULT_REQUIRE_FOR_RISK],
    // Harness switches that weaken the gate: the page says so out loud when either is on.
    auto_approve: process.env.SWITCHBOARD_AUTO_APPROVE === "1",
    insecure_presence: process.env.SWITCHBOARD_INSECURE_APPROVAL === "1",
  });

  // Owner decisions are audited under the channel they came through (`owner:dashboard`, `owner:cli`).
  const ownerAudit = (tool: string, reason: string, actor: "dashboard" | "cli"): void => {
    try {
      audit({ server: "switchboard", tool, scope: "full", decision: "allow", reason, principal: `owner:${actor}` });
    } catch (err) {
      log.error(`audit write failed for ${tool}: ${err instanceof Error ? err.message : String(err)}`);
    }
  };
  /**
   * Turn the kill switch OFF, the one kill-switch direction that re-opens every tool. It is performed by THIS gateway
   * after its own owner-presence check (Windows Hello, or a challenge at its console), whichever door the request came
   * through: the dashboard (owner session plus CSRF) or the control API (`switchboard kill off`). A process that is not
   * the gateway cannot answer the presence prompt, which is the point: `kill off` used to delete the KILL file directly,
   * so anything that could run the CLI (an agent with a shell) could undo the owner's emergency stop.
   */
  const killOff = async (actor: "dashboard" | "cli"): Promise<{ status: number; body: Record<string, unknown> }> => {
    if (cfg.gateway.kill_switch === true) {
      return {
        status: 409,
        body: { error: "gateway.kill_switch is true in the config, which a running gateway cannot clear: set it to false and restart the gateway", code: "SB_KILL_CONFIG" },
      };
    }
    const presence = await approvals.verifyPresence("Turn the MCP Switchboard kill switch OFF: tool calls will be allowed again");
    if (!presence.ok) {
      ownerAudit("kill.off_refused", `presence check failed (${presence.method}): ${presence.reason}`, actor);
      return { status: 403, body: { error: `owner presence was not verified (${presence.method}): ${presence.reason}`, code: "SB_PRESENCE_FAILED" } };
    }
    const { changed } = setKillFile(false);
    ownerAudit("kill.off", `${changed ? "kill switch turned OFF" : "kill switch was already off"} from the ${actor === "cli" ? "CLI" : "dashboard"} (presence ${presence.method})`, actor);
    return { status: 200, body: { ...killStatus(cfg) } };
  };

  const control = express.Router();
  control.use((req: Request, res: Response, next: () => void) => {
    res.setHeader("Cache-Control", "no-store");
    const presented = bearerOf(req.headers["authorization"]);
    if (presented === null || !controlTokenMatches(presented, controlToken)) {
      res.status(401).json({ error: "control token required: `switchboard approvals` reads it from SWITCHBOARD_HOME/control.key", code: "SB_CONTROL_TOKEN" });
      return;
    }
    next();
  });
  control.get("/approvals", (_req: Request, res: Response) => {
    try {
      res.json(approvalsPayload());
    } catch (err) {
      approvalError(res, err);
    }
  });
  control.get("/approvals/:id", (req: Request, res: Response) => {
    try {
      const rec = approvals.get(String(req.params.id));
      if (!rec) res.status(404).json({ error: `no approval '${req.params.id}'`, code: "SB_APPROVAL_UNKNOWN" });
      else res.json({ approval: rec });
    } catch (err) {
      approvalError(res, err);
    }
  });
  control.post("/approvals/:id/approve", approveVia("cli"));
  control.post("/approvals/:id/deny", denyVia("cli"));
  // `switchboard kill off`: the only kill-switch route here. Turning it ON needs no gateway, and the control API
  // has no route that does anything else to the switch.
  control.post("/kill/off", async (_req: Request, res: Response) => {
    try {
      const off = await killOff("cli");
      res.status(off.status).json(off.body);
    } catch (err) {
      res.status(500).json({ error: err instanceof Error ? err.message : String(err) });
    }
  });
  app.use("/api/control", control);

  // ====================================================================
  // Owner gate: every /api route below needs a valid owner session cookie, and every mutating one the
  // X-Switchboard-CSRF header. Client API keys are never read here (defect D4: a loopback peer is not
  // the owner).
  // ====================================================================
  app.use("/api", ownerSessionGate(sessions));
  // Pick up a clients change made on the CLI before any admin route reads or rewrites the config.
  app.use("/api", (_req: Request, _res: Response, next: () => void) => {
    clientWatcher.sync();
    next();
  });

  // Who am I: lets the SPA recover its CSRF value after a reload (the cookie is HttpOnly).
  app.get("/api/session", (_req: Request, res: Response) => {
    const owner = res.locals.ownerSession as { csrf: string; expires: number };
    res.json({ authenticated: true, csrf: owner.csrf, expires_at: new Date(owner.expires).toISOString() });
  });

  // Sign out: drops the session server side and expires the cookie.
  app.delete("/api/session", (req: Request, res: Response) => {
    sessions.revoke(readCookie(req, SESSION_COOKIE));
    clearSessionCookie(res, req.secure);
    res.json({ ok: true });
  });

  // ====================================================================
  // JSON API for the dashboard
  // ====================================================================

  app.get("/api/state", (_req: Request, res: Response) => {
    const endpoint = `http://${cfg.gateway.http.host}:${cfg.gateway.http.port}/mcp`;
    // Overlay live circuit-breaker state so the dashboard can badge a tripped upstream. The breaker
    // only tracks servers it has called, so an unobserved server resolves to a closed circuit.
    const circuits = new Map(gateway.router.serverHealth().map((c) => [c.server, c.state]));
    const servers = cfg.servers.map((s) => {
      const mounted = gateway.registry.get(s.id);
      const policy = s.policy ?? cfg.gateway.default_policy;
      const tools = (mounted?.tools ?? []).map((t) => ({
        name: t.name,
        enabled: s.tools?.[t.name]?.enabled !== false,
        scope: resolveToolScope(t.name, s.tools?.[t.name], mounted?.scopeHints?.[t.name], t.annotations),
        risk: resolveRisk(s, resolveToolScope(t.name, s.tools?.[t.name], mounted?.scopeHints?.[t.name], t.annotations), s.tools?.[t.name]),
      }));
      return {
        id: s.id,
        source: s.source,
        policy,
        enabled: s.enabled !== false,
        mounted: Boolean(mounted),
        circuit: circuits.get(s.id) ?? "closed",
        tools,
      };
    });
    // Profiles are named, switchable views (visibility + optional scope cap). The active one is
    // already folded into `cfg` at boot (env > file), so the dashboard reports the EFFECTIVE view.
    const definedProfiles = cfg.settings?.profiles ?? {};
    const profiles = Object.entries(definedProfiles).map(([name, p]) => ({
      name,
      description: p.description ?? null,
      summary: describeProfile(name, p),
      servers: p.servers ?? null,
      scope_cap: p.policy ?? null,
    }));
    res.json({
      endpoint,
      organization: cfg.settings?.general?.organization_name ?? "Local",
      project: cfg.settings?.general?.project_name ?? "default",
      tool_exposure: cfg.gateway.tool_exposure,
      default_policy: cfg.gateway.default_policy,
      active_profile: activeProfileName(cfg) ?? null,
      kill_switch: killStatus(cfg),
      profiles,
      servers,
    });
  });

  // --- Approvals (design 3.3). Owner session and CSRF as for every /api route; approving also needs the
  // owner to be PRESENT: the gateway shows Windows Hello (or a challenge on its own console) before it signs. ---
  app.get("/api/approvals", (_req: Request, res: Response) => {
    try {
      res.json(approvalsPayload());
    } catch (err) {
      approvalError(res, err);
    }
  });
  app.get("/api/approvals/:id", (req: Request, res: Response) => {
    try {
      const rec = approvals.get(String(req.params.id));
      if (!rec) res.status(404).json({ error: `no approval '${req.params.id}'`, code: "SB_APPROVAL_UNKNOWN" });
      else res.json({ approval: rec });
    } catch (err) {
      approvalError(res, err);
    }
  });
  app.post("/api/approvals/:id/approve", approveVia("dashboard"));
  app.post("/api/approvals/:id/deny", denyVia("dashboard"));

  // --- Kill switch from the dashboard. ON is immediate. OFF is the dangerous direction (it re-opens every tool),
  // so it needs the owner present, performed by the gateway (see killOff above), exactly like an approval. ---
  app.get("/api/kill", (_req: Request, res: Response) => {
    res.json(killStatus(cfg));
  });
  app.post("/api/kill", async (req: Request, res: Response) => {
    const on = (req.body as { on?: unknown } | undefined)?.on;
    if (typeof on !== "boolean") {
      res.status(400).json({ error: "body must be {\"on\": true|false}" });
      return;
    }
    try {
      if (on) {
        const { changed } = setKillFile(true);
        ownerAudit("kill.on", changed ? "kill switch turned ON from the dashboard" : "kill switch was already on", "dashboard");
        res.json(killStatus(cfg));
        return;
      }
      const off = await killOff("dashboard");
      res.status(off.status).json(off.body);
    } catch (err) {
      res.status(500).json({ error: err instanceof Error ? err.message : String(err) });
    }
  });

  app.get("/api/audit", (_req: Request, res: Response) => {
    res.json(recentAudit(200));
  });

  // --- Usage: aggregated tool-call metering, the local twin of Composio's Usage page ---
  app.get("/api/usage", (_req: Request, res: Response) => {
    res.json(usageStats());
  });

  // ====================================================================
  // Playground: try any exposed tool against the live gateway. Listing reuses the
  // router's governed tool surface (so `search` mode shows the two meta-tools, namespaced
  // mode shows `server__tool`, etc.); execution routes through `router.callTool`, so policy
  // + approval + audit all apply exactly as they would for a downstream agent. Running a
  // tool needs an owner session and CSRF header: nothing else may drive real calls.
  // ====================================================================
  app.get("/api/playground/tools", (_req: Request, res: Response) => {
    res.json({ tools: gateway.router.listTools(), tool_exposure: cfg.gateway.tool_exposure });
  });

  app.post("/api/playground/call", async (req: Request, res: Response) => {
    const name = typeof req.body?.name === "string" ? req.body.name : "";
    if (!name) {
      res.status(400).json({ error: "missing tool 'name'" });
      return;
    }
    const args =
      req.body?.arguments && typeof req.body.arguments === "object"
        ? (req.body.arguments as Record<string, unknown>)
        : {};
    const start = Date.now();
    try {
      // The call self-audits (timing + opt-in I/O) and enforces policy/approval inside the router.
      const result = await gateway.router.callTool(name, args);
      res.json({ result, duration_ms: Date.now() - start });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: msg });
    }
  });

  // ====================================================================
  // Toolkit catalog (the Composio-style "1000+ toolkits" grid)
  // ====================================================================

  app.get("/api/catalog/stats", (_req: Request, res: Response) => {
    if (catalog.toolkits.length === 0) catalog = loadCatalog();
    res.json({
      generated_at: catalog.generated_at,
      counts: catalog.counts,
      categories: catalog.categories,
    });
  });

  app.get("/api/toolkits", (req: Request, res: Response) => {
    if (catalog.toolkits.length === 0) catalog = loadCatalog();
    const q = typeof req.query.q === "string" ? req.query.q : "";
    const category = typeof req.query.category === "string" ? req.query.category : "";
    const origin = typeof req.query.origin === "string" ? req.query.origin : "";
    const offset = Number.parseInt(String(req.query.offset ?? "0"), 10) || 0;
    const limit = Number.parseInt(String(req.query.limit ?? "60"), 10) || 60;
    // Always correlate (cheap) so every item carries an honest `mounted` flag; `?sort=mounted`
    // additionally floats the already-mounted toolkits to the front as a stable alpha partition.
    const mountedSlugs = correlateMountedSlugs(catalog.toolkits, cfg.servers);
    const sortBy = req.query.sort === "mounted" ? "mounted" : "alpha";
    const { total, items } = queryCatalog(catalog, { q, category, origin, offset, limit, sortBy, mountedSlugs });
    res.json({
      total,
      offset,
      limit,
      total_pages: pageCount(total, limit),
      items: items.map((t) => ({ ...t, mounted: mountedSlugs.has(t.slug) })),
      catalog_total: catalog.counts.total,
    });
  });

  app.get("/api/toolkits/:slug", (req: Request, res: Response) => {
    if (catalog.toolkits.length === 0) catalog = loadCatalog();
    const slug = String(req.params.slug);
    const tk = catalog.toolkits.find((t) => t.slug === slug);
    if (!tk) {
      res.status(404).json({ error: `unknown toolkit '${slug}'` });
      return;
    }
    res.json(tk);
  });

  // Add a catalog toolkit as a mounted (disabled) server. The new server starts disabled so the
  // operator wires credentials and flips it on deliberately.
  app.post("/api/toolkits/:slug/add", async (req: Request, res: Response) => {
    if (catalog.toolkits.length === 0) catalog = loadCatalog();
    const tk = catalog.toolkits.find((t) => t.slug === String(req.params.slug));
    if (!tk) {
      res.status(404).json({ error: `unknown toolkit '${req.params.slug}'` });
      return;
    }
    if (tk.mount.source === "manual") {
      res.status(400).json({ error: `'${tk.name}' must be installed manually: ${tk.mount.note}` });
      return;
    }
    // An npx toolkit runs code fetched from the npm registry at every start, so a NEW mount must name one exact
    // version (`name@1.2.3`): the catalog's own version when it lists one, else the one the owner sends. A floating
    // name is never added. (An unpinned entry already in a config file still mounts, with a warning.)
    let npxPackage: string | undefined;
    if (tk.mount.source === "npx") {
      const sent = ((req.body ?? {}) as { version?: unknown }).version;
      const spec = tk.mount.package;
      const name = npmPackageName(spec);
      const version = sent !== undefined ? sent : tk.mount.version;
      if (sent === undefined && isPinnedNpmSpec(spec)) npxPackage = spec;
      else if (isExactNpmVersion(version)) npxPackage = `${name}@${version as string}`;
      else {
        res.status(400).json({
          error: `'${safeText(tk.name, 80)}' runs the npm package '${safeText(name, 80)}', and a new mount needs one exact version: send {"version": "x.y.z"} (the catalog lists ${tk.mount.version ? `'${safeText(tk.mount.version, 40)}', which is not an exact version` : "none"}). Floating versions such as 'latest' or '^1.2.0' are not added.`,
          code: "SB_PACKAGE_UNPINNED",
          package: name,
        });
        return;
      }
    }

    // Derive a valid config id from the slug; ensure it is unique.
    const id = uniqueServerId(tk.slug, cfg.servers.map((s) => s.id));

    const server: SwitchboardConfig["servers"][number] =
      tk.mount.source === "remote"
        ? { id, source: "remote", url: tk.mount.url, enabled: false, auth: "none" }
        : tk.mount.source === "npx"
          ? { id, source: "npx", package: npxPackage, enabled: false, policy: cfg.gateway.default_policy }
          : { id, source: "app2mcp", openapi: tk.mount.openapi, enabled: false, policy: cfg.gateway.default_policy };

    // Whatever is written must load again: refuse an entry the strict schema would reject at the next start.
    const issues = configIssues({ ...cfg, servers: [...cfg.servers, server] });
    if (issues) {
      res.status(400).json({ error: `'${safeText(tk.name, 80)}' cannot be added: ${issues.join("; ")}`, code: "SB_CONFIG_INVALID", issues });
      return;
    }

    cfg.servers.push(server);
    try {
      if (configPath) writeConfig(configPath, cfg);
      res.json({ id, added: true, server });
    } catch (err) {
      cfg.servers = cfg.servers.filter((s) => s.id !== id); // roll back the in-memory add
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: msg });
    }
  });

  // ====================================================================
  // API keys: bearer tokens that authenticate `/mcp` (Composio "API Keys" page)
  // ====================================================================
  // Listing is redacted (never the hash). Issuing/revoking mutate local state and sit behind the owner gate.
  app.get("/api/apikeys", (_req: Request, res: Response) => {
    res.json({ keys: apiKeys.list(), require_auth: cfg.gateway.http.require_auth, enforced: requireAuth });
  });

  app.post("/api/apikeys", (req: Request, res: Response) => {
    const name = typeof req.body?.name === "string" ? req.body.name : "";
    const client = typeof req.body?.client === "string" && req.body.client !== "" ? req.body.client : undefined;
    if (client !== undefined && (!isValidClientId(client) || !Object.prototype.hasOwnProperty.call(cfg.clients ?? {}, client))) {
      res.status(400).json({ error: `unknown client '${client}': add it first with POST /api/clients` });
      return;
    }
    const { token, record } = apiKeys.issue(name, client ? { client } : {});
    // The plaintext token is returned ONCE here and never again.
    res.json({ token, key: record });
  });

  app.delete("/api/apikeys/:id", (req: Request, res: Response) => {
    const removed = apiKeys.revoke(String(req.params.id));
    if (!removed) {
      res.status(404).json({ error: `unknown key '${req.params.id}'` });
      return;
    }
    res.json({ revoked: req.params.id });
  });

  // ====================================================================
  // Clients (design 3.1): the principals that may call /mcp, and the keys bound to them. Owner session and
  // CSRF as for every /api route. No route here ever returns a token: a new or rotated key goes only to the
  // client's key file (the bridge reads it), exactly as `switchboard client add` does without --print.
  // ====================================================================
  const CLIENT_FIELDS = ["description", "servers", "tools", "exclude_tools", "max_scope", "max_risk", "limits"] as const;
  const clientFields = (body: Record<string, unknown>, extra: readonly string[] = []): Record<string, unknown> => {
    const unknown = Object.keys(body).filter((k) => !(CLIENT_FIELDS as readonly string[]).includes(k) && !extra.includes(k));
    if (unknown.length > 0) throw new ClientAdminError(`unknown field '${unknown[0]}'`, 400);
    const out: Record<string, unknown> = {};
    for (const k of CLIENT_FIELDS) if (k in body) out[k] = body[k];
    return out;
  };
  const clientError = (res: Response, err: unknown): void => {
    if (err instanceof ClientAdminError) {
      res.status(err.status).json({ error: err.message });
      return;
    }
    res.status(500).json({ error: err instanceof Error ? err.message : String(err) });
  };
  const bodyOf = (req: Request): Record<string, unknown> =>
    req.body && typeof req.body === "object" && !Array.isArray(req.body) ? (req.body as Record<string, unknown>) : {};

  app.get("/api/clients", (_req: Request, res: Response) => {
    const { clients, orphan_keys } = clientAdmin.list();
    res.json({
      clients: clients.map((c) => ({ id: c.id, ...c.config, keys: c.keys, key_file: c.key_file })),
      orphan_keys,
      // True while /mcp demands a principal bound to one of these clients.
      enforced: clients.length > 0,
    });
  });

  app.post("/api/clients", (req: Request, res: Response) => {
    try {
      const body = bodyOf(req);
      const spec = clientFields(body, ["id"]);
      const id = typeof body.id === "string" ? body.id : "";
      if (Object.prototype.hasOwnProperty.call(cfg.clients ?? {}, id)) {
        res.status(409).json({ error: `client '${id}' already exists: change it with PUT /api/clients/${id}` });
        return;
      }
      const r = clientAdmin.add(id, spec);
      res.status(201).json({ id, client: r.client, key: r.key ?? null, key_file: true });
    } catch (err) {
      clientError(res, err);
    }
  });

  app.put("/api/clients/:id", (req: Request, res: Response) => {
    try {
      const id = String(req.params.id);
      const client = clientAdmin.update(id, clientFields(bodyOf(req)));
      res.json({ id, client });
    } catch (err) {
      clientError(res, err);
    }
  });

  app.post("/api/clients/:id/rotate", (req: Request, res: Response) => {
    try {
      const id = String(req.params.id);
      const r = clientAdmin.rotate(id);
      res.json({ rotated: id, key: r.key, revoked: r.revoked });
    } catch (err) {
      clientError(res, err);
    }
  });

  app.delete("/api/clients/:id", (req: Request, res: Response) => {
    try {
      const id = String(req.params.id);
      // Default: remove the client entirely. `?purge=0` revokes its keys and key file but keeps the config entry.
      const purge = req.query.purge !== "0" && req.query.purge !== "false";
      const r = clientAdmin.remove(id, { purge });
      res.json({ removed: id, purged: r.purged, revoked_keys: r.revokedKeys, key_file_removed: r.keyFileRemoved });
    } catch (err) {
      clientError(res, err);
    }
  });

  // ====================================================================
  // Settings (the Composio Settings pages: General, Auth Screen, Webhook)
  // ====================================================================
  app.get("/api/settings", (_req: Request, res: Response) => {
    res.json({
      general: cfg.settings?.general ?? {},
      auth_screen: cfg.settings?.auth_screen ?? {},
      webhook: cfg.settings?.webhook ?? {},
      triggers: cfg.settings?.triggers ?? {},
      logs: cfg.settings?.logs ?? {},
      // Council reasoning loop — non-secret summary only (provider presence + the local
      // endpoint/model), never an api_key_ref value. Lets the Playground offer the zero-cloud path.
      council: councilSummary(cfg.settings?.council),
      // Built-in OAuth 2.1 authorization server — the path that lets ChatGPT / claude.ai reach a
      // tunnelled MCP Switchboard. `enforced` reflects whether it is actually wired this run.
      oauth_server: {
        enabled: Boolean(cfg.settings?.oauth_server?.enabled),
        public_url: cfg.settings?.oauth_server?.public_url ?? "",
        consent: cfg.settings?.oauth_server?.consent !== false,
        enforced: Boolean(oauthOpts),
      },
      // Per-call upstream timeout (ms); null = SDK default.
      call_timeout_ms: cfg.settings?.call_timeout_ms ?? null,
      // Hand-declared HTTP tools per server (id + count only — the defs themselves carry secret refs).
      http_tools: cfg.servers
        .filter((s) => s.source === "http-tool")
        .map((s) => ({ id: s.id, enabled: s.enabled, count: s.http_tools?.length ?? 0 })),
      gateway: {
        host: cfg.gateway.http.host,
        port: cfg.gateway.http.port,
        require_auth: cfg.gateway.http.require_auth,
        tool_exposure: cfg.gateway.tool_exposure,
        default_policy: cfg.gateway.default_policy,
        endpoint: `http://${cfg.gateway.http.host}:${cfg.gateway.http.port}/mcp`,
      },
      vault_secrets: gateway.vault.list(),
    });
  });

  // Persist a partial settings/gateway update (it writes config.yaml).
  app.put("/api/settings", (req: Request, res: Response) => {
    const body = (req.body ?? {}) as {
      settings?: SettingsConfig;
      gateway?: { require_auth?: "auto" | "always" | "never"; tool_exposure?: "namespaced" | "flat" | "search"; default_policy?: "read" | "write" | "full" };
    };

    // The change is built on a COPY and checked with the same strict schema the file is loaded with, BEFORE anything
    // live or on disk changes. 0.1.0 merged the body into the running config and wrote it: `require_auth: "bogus"`
    // or an unknown key was accepted, saved, and the next start failed to load the file.
    const next = JSON.parse(JSON.stringify(cfg)) as SwitchboardConfig;
    next.settings = next.settings ?? {};
    if (body.settings?.general) next.settings.general = { ...next.settings.general, ...body.settings.general };
    if (body.settings?.auth_screen) next.settings.auth_screen = { ...next.settings.auth_screen, ...body.settings.auth_screen };
    if (body.settings?.webhook) next.settings.webhook = { ...next.settings.webhook, ...body.settings.webhook };
    if (body.gateway?.require_auth) next.gateway.http.require_auth = body.gateway.require_auth;
    if (body.gateway?.tool_exposure) next.gateway.tool_exposure = body.gateway.tool_exposure;
    if (body.gateway?.default_policy) next.gateway.default_policy = body.gateway.default_policy;
    const issues = configIssues(next);
    if (issues) {
      res.status(400).json({
        error: `these settings would make the configuration invalid, so nothing was changed: ${issues.join("; ")}`,
        code: "SB_CONFIG_INVALID",
        issues,
      });
      return;
    }

    // Apply only what the body touched, to the live objects the rest of the gateway holds.
    const hadSettings = cfg.settings !== undefined;
    cfg.settings = cfg.settings ?? {};
    const before = {
      general: cfg.settings.general,
      auth_screen: cfg.settings.auth_screen,
      webhook: cfg.settings.webhook,
      require_auth: cfg.gateway.http.require_auth,
      tool_exposure: cfg.gateway.tool_exposure,
      default_policy: cfg.gateway.default_policy,
    };
    if (body.settings?.general) cfg.settings.general = next.settings.general;
    if (body.settings?.auth_screen) cfg.settings.auth_screen = next.settings.auth_screen;
    if (body.settings?.webhook) cfg.settings.webhook = next.settings.webhook;
    cfg.gateway.http.require_auth = next.gateway.http.require_auth;
    cfg.gateway.tool_exposure = next.gateway.tool_exposure;
    cfg.gateway.default_policy = next.gateway.default_policy;

    try {
      if (configPath) writeConfig(configPath, cfg);
    } catch (err) {
      // The write is atomic, so the old file is intact; put the running config back to match it.
      cfg.settings.general = before.general;
      cfg.settings.auth_screen = before.auth_screen;
      cfg.settings.webhook = before.webhook;
      if (!hadSettings && Object.values(cfg.settings).every((v) => v === undefined)) cfg.settings = undefined;
      cfg.gateway.http.require_auth = before.require_auth;
      cfg.gateway.tool_exposure = before.tool_exposure;
      cfg.gateway.default_policy = before.default_policy;
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: msg });
      return;
    }
    // Re-evaluate the live auth posture so a require_auth change takes effect immediately.
    // The OAuth AS, when enabled, is a hard floor: a settings edit must never drop the
    // `/mcp` gate below "required" while a public issuer is exposing the endpoint.
    requireAuth = authRequired(cfg.gateway.http.require_auth, host) || Boolean(oauthOpts);
    res.json({ ok: true, enforced: requireAuth });
  });

  // Send a sample event to the configured webhook so the operator can verify it end to end.
  app.post("/api/webhook/test", async (_req: Request, res: Response) => {
    const wh = cfg.settings?.webhook;
    if (!wh?.url) {
      res.status(400).json({ error: "no webhook URL configured" });
      return;
    }
    const payload = JSON.stringify({
      type: "switchboard.test",
      ts: new Date().toISOString(),
      message: "Test event from MCP Switchboard.",
    });
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (wh.secret_ref) {
      try {
        const secret = gateway.vault.resolve(wh.secret_ref);
        headers["x-switchboard-signature"] = "sha256=" + createHmac("sha256", secret).update(payload).digest("hex");
      } catch (err) {
        res.status(400).json({ error: `cannot resolve webhook secret: ${err instanceof Error ? err.message : String(err)}` });
        return;
      }
    }
    try {
      const r = await guardedFetch(wh.url, { method: "POST", headers, body: payload, timeoutMs: 8000 }, () => cfg.settings?.network);
      res.json({ ok: r.ok, status: r.status, signed: Boolean(headers["x-switchboard-signature"]) });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(502).json({ error: `delivery failed: ${msg}` });
    }
  });

  // ====================================================================
  // Triggers (poll-first change detection). The definitions live in
  // `settings.triggers` and round-trip to config.yaml like webhook/council;
  // the live poller state (last poll/fire, errors, recent fires) is read from
  // the running TriggerManager. Mutating endpoints need the CSRF header on top of the owner session.
  // ====================================================================
  app.get("/api/triggers", (_req: Request, res: Response) => {
    res.json(gateway.triggers.state());
  });

  // Replace the whole triggers config (definitions + master switch + interval).
  // Validated with the same strict schema used at startup, persisted, then the
  // poller is reloaded so the change takes effect without a restart.
  app.put("/api/triggers", (req: Request, res: Response) => {
    let parsed;
    try {
      parsed = parseTriggersConfig(req.body?.triggers ?? req.body ?? {});
    } catch (err) {
      res.status(400).json({ error: `invalid triggers config: ${err instanceof Error ? err.message : String(err)}` });
      return;
    }
    cfg.settings = cfg.settings ?? {};
    cfg.settings.triggers = parsed;
    try {
      if (configPath) writeConfig(configPath, cfg);
    } catch (err) {
      res.status(500).json({ error: err instanceof Error ? err.message : String(err) });
      return;
    }
    gateway.triggers.reload();
    res.json({ ok: true, state: gateway.triggers.state() });
  });

  // Run one trigger's poll right now (the "Poll now" button). A poll is a real governed tool call.
  // Returns the PollResult (fired? new_count? error?).
  app.post("/api/triggers/:id/poll", async (req: Request, res: Response) => {
    try {
      const result = await gateway.triggers.pollOnce(String(req.params.id));
      res.json(result);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: msg });
    }
  });

  // Pause / resume a single trigger WITHOUT removing its definition. Pause short-circuits the
  // poller before the governed tool call, so the trigger stays configured but goes quiet; resume
  // re-arms it (both change live poller behavior). A 404 when the id is unknown so
  // the dashboard never silently no-ops a typo'd id. Pause state is in-memory and resets on reload.
  app.post("/api/triggers/:id/pause", (req: Request, res: Response) => {
    const id = String(req.params.id);
    if (!gateway.triggers.pauseTrigger(id)) {
      res.status(404).json({ error: `unknown trigger '${id}'` });
      return;
    }
    res.json({ id, paused: true, state: gateway.triggers.state() });
  });

  app.post("/api/triggers/:id/resume", (req: Request, res: Response) => {
    const id = String(req.params.id);
    if (!gateway.triggers.resumeTrigger(id)) {
      res.status(404).json({ error: `unknown trigger '${id}'` });
      return;
    }
    res.json({ id, paused: false, state: gateway.triggers.state() });
  });

  // The curated poll-first trigger templates (pure data) — the picker the dashboard renders so an
  // operator can stamp a "watch X for new items" recipe onto a tool a mounted server exposes.
  // Read-only catalog; safe for any caller (no secrets, no mutation).
  app.get("/api/trigger-templates", (_req: Request, res: Response) => {
    res.json({ templates: listTriggerTemplates() });
  });

  // ====================================================================
  // OAuth catalog (Connected Accounts): browse providers, connect via the loopback callback
  // ====================================================================
  const redirectUri = `http://${cfg.gateway.http.host}:${cfg.gateway.http.port}/oauth/callback`;

  app.get("/api/catalog", (_req: Request, res: Response) => {
    res.json(gateway.oauth.catalog());
  });

  app.post("/api/connect/:provider", (req: Request, res: Response) => {
    try {
      const { authorizeUrl } = gateway.oauth.beginAuth(String(req.params.provider), redirectUri);
      res.json({ authorizeUrl });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(400).json({ error: msg });
    }
  });

  // The provider redirects the browser here after consent. Exchange the code, seal the
  // token, and show a self-closing confirmation page. Fails closed with a visible message.
  app.get("/oauth/callback", async (req: Request, res: Response) => {
    const state = typeof req.query.state === "string" ? req.query.state : "";
    const code = typeof req.query.code === "string" ? req.query.code : "";
    const err = typeof req.query.error === "string" ? req.query.error : "";
    const brand = cfg.settings?.auth_screen;
    if (err) {
      res.status(400).type("html").send(callbackPage(`Authorization was denied: ${err}`, false, brand));
      return;
    }
    if (!state || !code) {
      res.status(400).type("html").send(callbackPage("Missing 'state' or 'code' in the callback.", false, brand));
      return;
    }
    try {
      const token = await gateway.oauth.completeAuth(state, code);
      res.type("html").send(callbackPage(`Connected ${token.provider}. You can close this tab.`, true, brand));
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      res.status(400).type("html").send(callbackPage(msg, false, brand));
    }
  });

  app.post("/api/servers/:id/toggle", async (req: Request, res: Response) => {
    const id = req.params.id;
    const server = cfg.servers.find((s) => s.id === id);
    if (!server) {
      res.status(404).json({ error: `unknown server '${id}'` });
      return;
    }
    server.enabled = server.enabled === false;
    try {
      if (server.enabled) await gateway.registry.mount(server);
      else await gateway.registry.unmount(server.id);
      if (configPath) writeConfig(configPath, cfg);
      res.json({ id, enabled: server.enabled });
    } catch (err) {
      server.enabled = server.enabled === false; // revert the optimistic flip on failure
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: msg });
    }
  });

  // Remove a server entirely. Unmounts it first if it's live.
  app.delete("/api/servers/:id", async (req: Request, res: Response) => {
    const id = String(req.params.id);
    const idx = cfg.servers.findIndex((s) => s.id === id);
    if (idx === -1) {
      res.status(404).json({ error: `unknown server '${id}'` });
      return;
    }
    try {
      await gateway.registry.unmount(id).catch(() => {});
      cfg.servers.splice(idx, 1);
      if (configPath) writeConfig(configPath, cfg);
      res.json({ id, removed: true });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: msg });
    }
  });

  // ====================================================================
  // Static SPA (served last so /api/* and /mcp win) + SPA fallback
  // ====================================================================
  const dir = publicDir();
  app.use(express.static(dir));
  // Any non-API GET falls back to the SPA shell (hash routing means this is mostly `/`).
  // Excludes the API, `/mcp`, the OAuth connect routes, and — so the AS router (or a clean
  // 404 when it's off) handles them — the OAuth 2.1 metadata/endpoint paths.
  app.get(/^(?!\/api\/|\/mcp|\/oauth\/|\/\.well-known\/|\/authorize|\/token|\/register|\/revoke).*/, (_req: Request, res: Response) => {
    res.sendFile("index.html", { root: dir }, (err) => {
      if (err) res.status(404).type("text").send("dashboard not built — run `npm run build`");
    });
  });

  // Terminal handlers, registered last. Without them Express answers an unmatched route with its own
  // HTML page (which replaces our CSP) and prints a stack trace, with file paths, for a malformed JSON body.
  app.use((_req: Request, res: Response) => {
    res.status(404).json({ error: "not found" });
  });
  app.use(jsonErrorHandler());

  // Surface the auth posture loudly at startup so a misconfigured exposure is obvious.
  const startClients = Object.keys(cfg.clients ?? {});
  if (startClients.length > 0) {
    log.info(
      `${startClients.length} client${startClients.length === 1 ? "" : "s"} configured (${startClients.join(", ")}): /mcp requires a key bound to one of them, on every bind host`,
    );
    if (apiKeys.count === 0 && !oauthProvider) {
      log.warn("no client key exists yet: run `switchboard client add <id>` (or rotate) so a client can connect");
    }
  } else if (requireAuth) {
    if (apiKeys.count === 0 && !oauthProvider) {
      log.warn(
        `/mcp requires an API key but none exist — run \`switchboard apikey new <name>\` to issue one; clients cannot connect until you do`,
      );
    } else if (apiKeys.count === 0 && oauthProvider) {
      log.info("/mcp authentication required — no API keys issued; clients authenticate via the OAuth 2.1 flow");
    } else {
      log.info(`/mcp authentication required (${apiKeys.count} API key${apiKeys.count === 1 ? "" : "s"} issued)`);
    }
  } else if (!isLoopbackHost(host)) {
    log.warn(
      `/mcp is exposed on ${host} WITHOUT authentication (require_auth: never) — anyone who can reach this host can use your tools`,
    );
  }

  if (catalog.counts.total === 0) {
    log.warn("toolkit catalog is empty — run `switchboard toolkits sync` to fetch the catalog");
  } else {
    log.info(`toolkit catalog: ${catalog.counts.total} entries (${catalog.counts.mcp_registry} MCP, ${catalog.counts.apis_guru} OpenAPI)`);
  }

  // No callback on listen: Express 5 invokes a listen callback with the error too, so a callback that
  // resolves would report "listening" when the bind failed. Resolve on 'listening', reject on 'error'.
  return new Promise<DashboardHandle>((resolve, reject) => {
    const httpServer = app.listen(port, host);
    httpServer.once("error", (err: NodeJS.ErrnoException) => {
      reject(
        new Error(
          err.code === "EADDRINUSE"
            ? `port ${port} on ${host} is already in use: stop the other process or change gateway.http.port`
            : `cannot listen on ${host}:${port}: ${err.message}`,
        ),
      );
    });
    httpServer.once("listening", () => {
      httpServer.on("error", (err) => log.error(`HTTP server error: ${err.message}`));
      const url = `http://${host}:${port}`;
      log.ok(`dashboard + HTTP endpoint on ${url}`);
      log.info("the admin API needs an owner session: run `switchboard dashboard login` to sign in");
      resolve({
        url,
        close: () =>
          new Promise<void>((done) => {
            httpServer.close(() => done());
          }),
      });
    });
  });
}

/**
 * Minimal self-contained HTML for the OAuth redirect landing page. No external requests.
 * Themed by the optional `auth_screen` settings block (title/subtitle/logo/accent).
 */
function callbackPage(message: string, ok: boolean, brand?: SettingsConfig["auth_screen"]): string {
  const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c] ?? c);
  const safe = esc(message);
  const accent = brand?.accent_color && /^#[0-9a-fA-F]{3,8}$/.test(brand.accent_color) ? brand.accent_color : "#2dd4bf";
  const color = ok ? "#3fb950" : "#f85149";
  const title = ok ? brand?.title ? esc(brand.title) : "Connected" : "Authorization failed";
  const subtitle = brand?.subtitle ? `<p class="sub">${esc(brand.subtitle)}</p>` : "";
  const logo =
    brand?.logo_url && /^https?:\/\//.test(brand.logo_url)
      ? `<img src="${esc(brand.logo_url)}" alt="" style="max-height:40px;margin-bottom:16px" />`
      : `<span class="dot" style="background:${color}"></span>`;
  const support =
    brand?.support_url && /^https?:\/\//.test(brand.support_url)
      ? `<p class="sub"><a href="${esc(brand.support_url)}" style="color:${accent}">Need help?</a></p>`
      : "";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8" />
<title>MCP Switchboard · ${title}</title>
<style>
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
    background:#0d1117; color:#e6edf3; font:15px/1.6 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
  .box { max-width:440px; padding:32px 36px; border:1px solid #2a3340; border-radius:14px; background:#161b22; text-align:center; border-top:3px solid ${accent}; }
  .dot { width:14px; height:14px; border-radius:50%; display:inline-block; margin-bottom:14px; }
  h1 { margin:0 0 8px; font-size:18px; }
  p { margin:0; color:#8b98a5; }
  .sub { margin-top:10px; font-size:13px; }
</style></head>
<body><div class="box">${logo}<h1>${title}</h1><p>${safe}</p>${subtitle}${support}</div></body></html>`;
}
