/**
 * HTTP server — hosts two things on one port:
 *   1. The MCP Streamable HTTP endpoint at `/mcp` (stateless: a fresh Server +
 *      transport per request, the pattern the SDK recommends for stateless servers).
 *   2. The dashboard UI at `/` plus a small JSON API the UI polls.
 *
 * Bound to `gateway.http.host` (127.0.0.1 by default) — local-first means the
 * endpoint is not exposed to the network unless the operator deliberately changes it.
 */

import express, { type Request, type Response } from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { Gateway } from "./gateway.js";
import type { SwitchboardConfig } from "./types.js";
import { writeConfig } from "./config.js";
import { recentAudit } from "./audit.js";
import { inferScope } from "./policy.js";
import { log } from "./logger.js";

export interface DashboardHandle {
  url: string;
  close: () => Promise<void>;
}

/**
 * Start the HTTP server. `configPath` is where enable/disable toggles are persisted so
 * they survive a restart; pass undefined to keep toggles in-memory only.
 */
export async function startDashboard(
  gateway: Gateway,
  cfg: SwitchboardConfig,
  html: string,
  configPath?: string,
): Promise<DashboardHandle> {
  const app = express();
  app.use(express.json());

  // --- MCP Streamable HTTP endpoint (stateless) ---
  app.all("/mcp", async (req: Request, res: Response) => {
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

  // --- Dashboard UI ---
  app.get("/", (_req: Request, res: Response) => {
    res.type("html").send(html);
  });

  // --- JSON API for the dashboard ---
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
    res.json({ endpoint, servers });
  });

  app.get("/api/audit", (_req: Request, res: Response) => {
    res.json(recentAudit(100));
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
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: msg });
    }
  });

  const { host, port } = cfg.gateway.http;
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
