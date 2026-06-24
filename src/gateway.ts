/**
 * Gateway — the downstream-facing MCP server.
 *
 * This is the single endpoint every agent connects to. It builds a low-level MCP
 * `Server` whose `tools/list` and `tools/call` handlers delegate to the Router, so the
 * full set of governed upstream tools appears as one server. Two transports are
 * supported and may run at once:
 *   - stdio            (one long-lived Server, for `claude mcp add` / Cursor / etc.)
 *   - Streamable HTTP  (a fresh Server per request, stateless — see dashboard.ts)
 *
 * The Gateway owns lifecycle: it loads config, builds the vault + registry, mounts every
 * enabled server, and exposes `buildServer()` for the transports to wire up.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type CallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import type { SwitchboardConfig } from "./types.js";
import { Vault } from "./vault.js";
import { Registry } from "./registry.js";
import { Router } from "./router.js";
import { setStdioActive } from "./approval.js";
import { log } from "./logger.js";

const NAME = "switchboard";
const VERSION = "0.1.0";

export class Gateway {
  readonly vault: Vault;
  readonly registry: Registry;
  readonly router: Router;

  constructor(private readonly cfg: SwitchboardConfig) {
    this.vault = new Vault(cfg.vault.backend);
    this.registry = new Registry(this.vault);
    this.router = new Router(this.registry, cfg);
  }

  /** Mount every enabled server. Failures are isolated so one bad server can't sink the rest. */
  async mountAll(): Promise<void> {
    const enabled = this.cfg.servers.filter((s) => s.enabled !== false);
    log.info(`mounting ${enabled.length} server${enabled.length === 1 ? "" : "s"}…`);
    for (const server of enabled) {
      try {
        await this.registry.mount(server);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        log.error(`failed to mount '${server.id}': ${msg}`);
      }
    }
  }

  /** A fresh downstream MCP Server wired to the router. One per stdio session / HTTP request. */
  buildServer(): Server {
    const server = new Server({ name: NAME, version: VERSION }, { capabilities: { tools: {} } });

    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: this.router.listTools(),
    }));

    server.setRequestHandler(CallToolRequestSchema, async (req): Promise<CallToolResult> => {
      const { name, arguments: args } = req.params;
      return this.router.callTool(name, args ?? {});
    });

    return server;
  }

  /** Serve the stdio transport. Blocks for the life of the process. */
  async serveStdio(): Promise<void> {
    setStdioActive(true);
    const server = this.buildServer();
    await server.connect(new StdioServerTransport());
    log.ok(`stdio transport ready — ${this.router.listTools().length} tools exposed`);
  }

  async shutdown(): Promise<void> {
    await this.registry.unmountAll();
  }
}

/** Build a fully-mounted gateway from a validated config. */
export async function createGateway(cfg: SwitchboardConfig): Promise<Gateway> {
  const gateway = new Gateway(cfg);
  await gateway.mountAll();
  return gateway;
}
