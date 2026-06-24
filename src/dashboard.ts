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
import type { SwitchboardConfig, SettingsConfig } from "./types.js";
import { writeConfig } from "./config.js";
import { recentAudit, usageStats } from "./audit.js";
import { inferScope } from "./policy.js";
import { ApiKeyStore } from "./apikeys.js";
import { loadCatalog, queryCatalog, type CatalogSnapshot } from "./catalog.js";
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

/** True if the request originated from the local machine (loopback peer address). */
function isLocalRequest(req: Request): boolean {
  const ip = req.ip ?? req.socket.remoteAddress ?? "";
  return ip === "127.0.0.1" || ip === "::1" || ip === "::ffff:127.0.0.1" || ip.startsWith("127.");
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

  // --- MCP Streamable HTTP endpoint (stateless) ---
  app.all("/mcp", async (req: Request, res: Response) => {
    // Gate before doing any work. Fail closed: a missing/invalid key is a 401, and we
    // never echo or log the presented token.
    if (requireAuth) {
      const token = presentedToken(req);
      if (!token || !apiKeys.verify(token)) {
        res.set("WWW-Authenticate", 'Bearer realm="switchboard"');
        res.status(401).json({ error: "unauthorized: missing or invalid API key" });
        return;
      }
    }
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
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

  // ====================================================================
  // JSON API for the dashboard
  // ====================================================================

  app.get("/api/state", (_req: Request, res: Response) => {
    const endpoint = `http://${cfg.gateway.http.host}:${cfg.gateway.http.port}/mcp`;
    const servers = cfg.servers.map((s) => {
      const mounted = gateway.registry.get(s.id);
      const policy = s.policy ?? cfg.gateway.default_policy;
      const tools = (mounted?.tools ?? []).map((t) => ({
        name: t.name,
        enabled: s.tools?.[t.name]?.enabled !== false,
        scope: s.tools?.[t.name]?.policy ?? inferScope(t.name),
      }));
      return { id: s.id, source: s.source, policy, enabled: s.enabled !== false, tools };
    });
    res.json({
      endpoint,
      organization: cfg.settings?.general?.organization_name ?? "Local",
      project: cfg.settings?.general?.project_name ?? "default",
      tool_exposure: cfg.gateway.tool_exposure,
      default_policy: cfg.gateway.default_policy,
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
    const { total, items } = queryCatalog(catalog, { q, category, origin, offset, limit });
    res.json({ total, offset, limit, items, catalog_total: catalog.counts.total });
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
    requireAuth = authRequired(cfg.gateway.http.require_auth, host);

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
      message: "Test event from Switchboard.",
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
  // OAuth catalog (Connected Accounts): browse providers, connect via loopback
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
  app.get(/^(?!\/api\/|\/mcp|\/oauth\/).*/, (_req: Request, res: Response) => {
    res.sendFile("index.html", { root: dir }, (err) => {
      if (err) res.status(404).type("text").send("dashboard not built — run `npm run build`");
    });
  });

  // Surface the auth posture loudly at startup so a misconfigured exposure is obvious.
  if (requireAuth) {
    if (apiKeys.count === 0) {
      log.warn(
        `/mcp requires an API key but none exist — run \`switchboard apikey new <name>\` to issue one; clients cannot connect until you do`,
      );
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
<title>Switchboard · ${title}</title>
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
