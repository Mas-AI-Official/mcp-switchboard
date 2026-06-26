/**
 * HTTP server — hosts everything on one port:
 *   1. The MCP Streamable HTTP endpoint at `/mcp` (stateless: a fresh Server +
 *      transport per request, the pattern the SDK recommends for stateless servers).
 *   2. The dashboard SPA — static files served from `public/` — plus the JSON API
 *      it calls (catalog, toolkits, settings, usage, audit, api keys, OAuth).
 *
 * Bound to `gateway.http.host` (127.0.0.1 by default) — local-first means the
 * endpoint is not exposed to the network unless the operator deliberately changes it.
 */

import { createHmac } from "node:crypto";
import { fileURLToPath } from "node:url";
import express, { type Request, type Response } from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { Gateway } from "./gateway.js";
import { VERSION } from "./gateway.js";
import type { SwitchboardConfig, SettingsConfig, ServerConfig, CouncilConfig } from "./types.js";
import type { BreakerHealth, BreakerState } from "./breaker.js";
import { writeConfig, parseTriggersConfig } from "./config.js";
import { recentAudit, usageStats } from "./audit.js";
import { inferScope } from "./policy.js";
import { activeProfileName, describeProfile } from "./profiles.js";
import { ApiKeyStore } from "./apikeys.js";
import { loadCatalog, queryCatalog, type CatalogSnapshot, type Toolkit } from "./catalog.js";
import { listTriggerTemplates } from "./trigger-templates.js";
import { mcpAuthRouter, getOAuthProtectedResourceMetadataUrl } from "@modelcontextprotocol/sdk/server/auth/router.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { resolveOAuthServerOptions, SwitchboardAuthProvider, OAUTH_SCOPES_SUPPORTED } from "./authserver.js";
import { log } from "./logger.js";

export interface DashboardHandle {
  url: string;
  close: () => Promise<void>;
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
 * True if the request originated from the local machine (loopback peer address). Every state-mutating
 * dashboard endpoint gates on this so a tunnelled/exposed dashboard can't mint a key, connect an
 * account, toggle/remove a server, or rewrite settings from off-box. Exported so the deterministic
 * oracle can prove the loopback verdict without a live server.
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
    else if (t.mount.source === "npx") byNpx.set(t.mount.package, t.slug);
    else if (t.mount.source === "app2mcp") byApp2mcp.set(t.mount.openapi, t.slug);
  }
  const mounted = new Set<string>();
  for (const s of servers) {
    let slug: string | undefined;
    if (s.url) slug = byRemote.get(s.url);
    else if (s.package) slug = byNpx.get(s.package);
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
    // never echo or log the presented token.
    if (opts.requireAuth()) {
      const token = presentedToken(req);
      // Accept either a local API key or — when the OAuth AS is enabled — a valid OAuth
      // access token. The token value is never echoed or logged.
      const apiKeyOk = !!token && opts.apiKeys.verify(token);
      const oauthOk = !apiKeyOk && !!token && !!opts.verifyOAuthToken && (await opts.verifyOAuthToken(token)) !== null;
      if (!apiKeyOk && !oauthOk) {
        // RFC 9728: point spec clients at the protected-resource metadata so they can
        // discover the Authorization Server and run the PKCE flow.
        const challenge = opts.resourceMetadataUrl
          ? `Bearer realm="switchboard", resource_metadata="${opts.resourceMetadataUrl}"`
          : 'Bearer realm="switchboard"';
        res.set("WWW-Authenticate", challenge);
        res.status(401).json({ error: "unauthorized: missing or invalid API key or OAuth token" });
        return;
      }
    }
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      ...(opts.enableJsonResponse ? { enableJsonResponse: true } : {}),
    });
    res.on("close", () => void transport.close());
    try {
      const server = gateway.buildServer();
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
): Promise<DashboardHandle> {
  const app = express();
  app.use(express.json());

  const apiKeys = new ApiKeyStore();
  const { host, port } = cfg.gateway.http;
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
    oauthProvider = new SwitchboardAuthProvider(oauthOpts, cfg.settings?.auth_screen);
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
        clientRegistrationOptions: { clientSecretExpirySeconds: 0 },
      }),
    );
    // The consent screen rendered by the provider's `authorize()` POSTs the human decision
    // here. Finalize it and 302 the user-agent back to the client with a code, or 400 an
    // expired/unknown request with a themed page.
    app.post("/oauth/consent", express.urlencoded({ extended: false }), (req: Request, res: Response) => {
      const body = req.body as { pending_id?: unknown; decision?: unknown };
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
    resourceMetadataUrl,
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
        scope: s.tools?.[t.name]?.policy ?? inferScope(t.name),
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
      profiles,
      servers,
    });
  });

  app.get("/api/audit", (_req: Request, res: Response) => {
    res.json(recentAudit(200));
  });

  // --- Usage: aggregated tool-call metering, the local twin of Composio's Usage page ---
  app.get("/api/usage", (_req: Request, res: Response) => {
    res.json(usageStats());
  });

  // --- Liveness probe: a tiny, dependency-free 200 for uptime monitors / `docker healthcheck` /
  // k8s readiness. Reveals only the service name + version + process uptime — no config, no server
  // ids. Registered before the SPA catch-all so the exact path wins over the fallback handler. ---
  app.get("/healthz", (_req: Request, res: Response) => {
    res.json({ status: "ok", service: "switchboard", version: VERSION, uptime_s: Math.round(process.uptime()) });
  });

  // --- Readiness/health: per-server mount + circuit-breaker roll-up with one ok/degraded verdict.
  // Read-only and unauthenticated like /api/state and /api/audit (the dashboard binds loopback by
  // default); it exposes only server ids + circuit state, never secrets. This is the endpoint that
  // wires the otherwise-dead Router.serverHealth() into an operator-visible surface. ---
  app.get("/api/health", (_req: Request, res: Response) => {
    const configured = cfg.servers.map((s) => ({ id: s.id, source: s.source, enabled: s.enabled !== false }));
    const mounted = new Map<string, number>();
    for (const s of cfg.servers) {
      const m = gateway.registry.get(s.id);
      if (m) mounted.set(s.id, m.tools.length);
    }
    const report = buildHealthReport(configured, mounted, gateway.router.serverHealth());
    // 200 when ready, 503 when degraded — so a monitor polling /api/health gets an honest HTTP signal,
    // not a green 200 hiding an unmounted/tripped upstream.
    res.status(report.status === "ok" ? 200 : 503).json(report);
  });

  // ====================================================================
  // Playground: try any exposed tool against the live gateway. Listing reuses the
  // router's governed tool surface (so `search` mode shows the two meta-tools, namespaced
  // mode shows `server__tool`, etc.); execution routes through `router.callTool`, so policy
  // + approval + audit all apply exactly as they would for a downstream agent. Running a
  // tool is loopback-only — a tunnelled dashboard must never be able to drive real calls.
  // ====================================================================
  app.get("/api/playground/tools", (_req: Request, res: Response) => {
    res.json({ tools: gateway.router.listTools(), tool_exposure: cfg.gateway.tool_exposure });
  });

  app.post("/api/playground/call", async (req: Request, res: Response) => {
    if (!isLocalRequest(req)) {
      res.status(403).json({ error: "the playground can only run tools from the local machine" });
      return;
    }
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

  // Add a catalog toolkit as a mounted (disabled) server. Loopback-only: a tunnelled
  // dashboard must not be able to add servers. The new server starts disabled so the
  // operator wires credentials and flips it on deliberately.
  app.post("/api/toolkits/:slug/add", async (req: Request, res: Response) => {
    if (!isLocalRequest(req)) {
      res.status(403).json({ error: "servers can only be added from the local machine" });
      return;
    }
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
    // Derive a config id from the slug; ensure it is unique.
    const base = tk.slug.replace(/^[^:]+:/, "").replace(/[^a-zA-Z0-9]+/g, "-").replace(/^-+|-+$/g, "").toLowerCase() || "toolkit";
    let id = base;
    let n = 1;
    while (cfg.servers.some((s) => s.id === id)) id = `${base}-${++n}`;

    const server: SwitchboardConfig["servers"][number] =
      tk.mount.source === "remote"
        ? { id, source: "remote", url: tk.mount.url, enabled: false, auth: "none" }
        : tk.mount.source === "npx"
          ? { id, source: "npx", package: tk.mount.package, enabled: false, policy: cfg.gateway.default_policy }
          : { id, source: "app2mcp", openapi: tk.mount.openapi, enabled: false, policy: cfg.gateway.default_policy };

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
  // Listing is redacted (never the hash). Issuing/revoking mutate local state and are
  // restricted to loopback callers so a tunnelled dashboard can't mint itself a key.
  app.get("/api/apikeys", (_req: Request, res: Response) => {
    res.json({ keys: apiKeys.list(), require_auth: cfg.gateway.http.require_auth, enforced: requireAuth });
  });

  app.post("/api/apikeys", (req: Request, res: Response) => {
    if (!isLocalRequest(req)) {
      res.status(403).json({ error: "API keys can only be issued from the local machine" });
      return;
    }
    const name = typeof req.body?.name === "string" ? req.body.name : "";
    const { token, record } = apiKeys.issue(name);
    // The plaintext token is returned ONCE here and never again.
    res.json({ token, key: record });
  });

  app.delete("/api/apikeys/:id", (req: Request, res: Response) => {
    if (!isLocalRequest(req)) {
      res.status(403).json({ error: "API keys can only be revoked from the local machine" });
      return;
    }
    const removed = apiKeys.revoke(String(req.params.id));
    if (!removed) {
      res.status(404).json({ error: `unknown key '${req.params.id}'` });
      return;
    }
    res.json({ revoked: req.params.id });
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

  // Persist a partial settings/gateway update. Loopback-only (it writes config.yaml).
  app.put("/api/settings", (req: Request, res: Response) => {
    if (!isLocalRequest(req)) {
      res.status(403).json({ error: "settings can only be changed from the local machine" });
      return;
    }
    const body = (req.body ?? {}) as {
      settings?: SettingsConfig;
      gateway?: { require_auth?: "auto" | "always" | "never"; tool_exposure?: "namespaced" | "flat" | "search"; default_policy?: "read" | "write" | "full" };
    };

    cfg.settings = cfg.settings ?? {};
    if (body.settings?.general) cfg.settings.general = { ...cfg.settings.general, ...body.settings.general };
    if (body.settings?.auth_screen) cfg.settings.auth_screen = { ...cfg.settings.auth_screen, ...body.settings.auth_screen };
    if (body.settings?.webhook) cfg.settings.webhook = { ...cfg.settings.webhook, ...body.settings.webhook };

    if (body.gateway?.require_auth) cfg.gateway.http.require_auth = body.gateway.require_auth;
    if (body.gateway?.tool_exposure) cfg.gateway.tool_exposure = body.gateway.tool_exposure;
    if (body.gateway?.default_policy) cfg.gateway.default_policy = body.gateway.default_policy;

    // Re-evaluate the live auth posture so a require_auth change takes effect immediately.
    // The OAuth AS, when enabled, is a hard floor: a settings edit must never drop the
    // `/mcp` gate below "required" while a public issuer is exposing the endpoint.
    requireAuth = authRequired(cfg.gateway.http.require_auth, host) || Boolean(oauthOpts);

    try {
      if (configPath) writeConfig(configPath, cfg);
      res.json({ ok: true, enforced: requireAuth });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: msg });
    }
  });

  // Send a sample event to the configured webhook so the operator can verify it end to end.
  app.post("/api/webhook/test", async (req: Request, res: Response) => {
    if (!isLocalRequest(req)) {
      res.status(403).json({ error: "webhook tests can only be triggered from the local machine" });
      return;
    }
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
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 8000);
    try {
      const r = await fetch(wh.url, { method: "POST", headers, body: payload, signal: ctrl.signal });
      res.json({ ok: r.ok, status: r.status, signed: Boolean(headers["x-switchboard-signature"]) });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(502).json({ error: `delivery failed: ${msg}` });
    } finally {
      clearTimeout(timer);
    }
  });

  // ====================================================================
  // Triggers (poll-first change detection). The definitions live in
  // `settings.triggers` and round-trip to config.yaml like webhook/council;
  // the live poller state (last poll/fire, errors, recent fires) is read from
  // the running TriggerManager. Mutating endpoints are loopback-only.
  // ====================================================================
  app.get("/api/triggers", (_req: Request, res: Response) => {
    res.json(gateway.triggers.state());
  });

  // Replace the whole triggers config (definitions + master switch + interval).
  // Validated with the same strict schema used at startup, persisted, then the
  // poller is reloaded so the change takes effect without a restart.
  app.put("/api/triggers", (req: Request, res: Response) => {
    if (!isLocalRequest(req)) {
      res.status(403).json({ error: "triggers can only be changed from the local machine" });
      return;
    }
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

  // Run one trigger's poll right now (the "Poll now" button). Loopback-only because
  // a poll is a real governed tool call. Returns the PollResult (fired? new_count? error?).
  app.post("/api/triggers/:id/poll", async (req: Request, res: Response) => {
    if (!isLocalRequest(req)) {
      res.status(403).json({ error: "triggers can only be polled from the local machine" });
      return;
    }
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
  // re-arms it. Loopback-only (both change live poller behavior). A 404 when the id is unknown so
  // the dashboard never silently no-ops a typo'd id. Pause state is in-memory and resets on reload.
  app.post("/api/triggers/:id/pause", (req: Request, res: Response) => {
    if (!isLocalRequest(req)) {
      res.status(403).json({ error: "triggers can only be paused from the local machine" });
      return;
    }
    const id = String(req.params.id);
    if (!gateway.triggers.pauseTrigger(id)) {
      res.status(404).json({ error: `unknown trigger '${id}'` });
      return;
    }
    res.json({ id, paused: true, state: gateway.triggers.state() });
  });

  app.post("/api/triggers/:id/resume", (req: Request, res: Response) => {
    if (!isLocalRequest(req)) {
      res.status(403).json({ error: "triggers can only be resumed from the local machine" });
      return;
    }
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
  // OAuth catalog (Connected Accounts): browse providers, connect via loopback
  // ====================================================================
  const redirectUri = `http://${cfg.gateway.http.host}:${cfg.gateway.http.port}/oauth/callback`;

  app.get("/api/catalog", (_req: Request, res: Response) => {
    res.json(gateway.oauth.catalog());
  });

  app.post("/api/connect/:provider", (req: Request, res: Response) => {
    if (!isLocalRequest(req)) {
      res.status(403).json({ error: "accounts can only be connected from the local machine" });
      return;
    }
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
    if (!isLocalRequest(req)) {
      res.status(403).json({ error: "servers can only be toggled from the local machine" });
      return;
    }
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

  // Remove a server entirely (loopback-only). Unmounts it first if it's live.
  app.delete("/api/servers/:id", async (req: Request, res: Response) => {
    if (!isLocalRequest(req)) {
      res.status(403).json({ error: "servers can only be removed from the local machine" });
      return;
    }
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

  // Surface the auth posture loudly at startup so a misconfigured exposure is obvious.
  if (requireAuth) {
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

  return new Promise<DashboardHandle>((resolve) => {
    const httpServer = app.listen(port, host, () => {
      const url = `http://${host}:${port}`;
      log.ok(`dashboard + HTTP endpoint on ${url}`);
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
