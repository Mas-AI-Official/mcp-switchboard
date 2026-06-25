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
  ListResourcesRequestSchema,
  ListResourceTemplatesRequestSchema,
  ReadResourceRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
  type CallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import type { ServerConfig, SwitchboardConfig } from "./types.js";
import { Vault } from "./vault.js";
import { OAuthStore } from "./oauth.js";
import { Registry } from "./registry.js";
import { Router } from "./router.js";
import { TriggerManager } from "./triggers.js";
import { setStdioActive } from "./approval.js";
import { buildCouncilServer, COUNCIL_SERVER_ID } from "./council.js";
import { log } from "./logger.js";

const NAME = "switchboard";
const VERSION = "0.1.0";

export class Gateway {
  readonly vault: Vault;
  readonly oauth: OAuthStore;
  readonly registry: Registry;
  readonly router: Router;
  readonly triggers: TriggerManager;

  constructor(private readonly cfg: SwitchboardConfig) {
    this.vault = new Vault(cfg.vault.backend);
    this.oauth = new OAuthStore(this.vault);
    this.registry = new Registry(this.vault, this.oauth);
    this.router = new Router(this.registry, cfg, (ref) => this.vault.resolve(ref));
    // Polls run through this.router, so every trigger poll is governed + audited like any call.
    this.triggers = new TriggerManager(this.router, cfg, (ref) => this.vault.resolve(ref));
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
    await this.mountCouncil();
  }

  /**
   * Mount the synthetic council relay server when `settings.council.enabled`. It is built
   * in-process and linked over an in-memory transport (same wiring as app2mcp), so its tools
   * are governed and audited by the router exactly like any upstream server. The synthetic
   * config carries a `write` ceiling and, when configured, an approval gate over write/full.
   */
  private async mountCouncil(): Promise<void> {
    const council = this.cfg.settings?.council;
    if (!council?.enabled) return;

    try {
      const { server, scopeHints, toolCount } = buildCouncilServer(council, this.vault);
      if (toolCount === 0) return;
      const synthetic: ServerConfig = {
        id: COUNCIL_SERVER_ID,
        source: "council",
        enabled: true,
        policy: "write",
        approval: council.require_approval ? { require_for: ["write", "full"] } : undefined,
      };
      await this.registry.mountLocal(synthetic, server, scopeHints);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      log.error(`failed to mount council: ${msg}`);
    }
  }

  /** A fresh downstream MCP Server wired to the router. One per stdio session / HTTP request.
   *  Declares all three content capabilities — tools, resources, prompts — so a full MCP client
   *  (Claude Desktop, Cursor) discovers every governed upstream surface through the one endpoint,
   *  not just tools. (The SDK refuses to register a resources/* or prompts/* handler unless the
   *  matching capability is declared here.) */
  buildServer(): Server {
    const server = new Server(
      { name: NAME, version: VERSION },
      { capabilities: { tools: {}, resources: {}, prompts: {} } },
    );

    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: this.router.listTools(),
    }));

    server.setRequestHandler(CallToolRequestSchema, async (req): Promise<CallToolResult> => {
      const { name, arguments: args } = req.params;
      return this.router.callTool(name, args ?? {});
    });

    // Resources — opaque URIs, aggregated across upstreams and read back by URI (not namespaced).
    server.setRequestHandler(ListResourcesRequestSchema, async () => ({
      resources: await this.router.listResources(),
    }));

    server.setRequestHandler(ListResourceTemplatesRequestSchema, async () => ({
      resourceTemplates: await this.router.listResourceTemplates(),
    }));

    server.setRequestHandler(ReadResourceRequestSchema, async (req) =>
      this.router.readResource(req.params.uri),
    );

    // Prompts — namespaced `serverId__name`, aggregated across upstreams.
    server.setRequestHandler(ListPromptsRequestSchema, async () => ({
      prompts: await this.router.listPrompts(),
    }));

    server.setRequestHandler(GetPromptRequestSchema, async (req) =>
      this.router.getPrompt(req.params.name, req.params.arguments),
    );

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
    // Stop pollers before unmounting so an in-flight poll can't hit a torn-down upstream.
    this.triggers.stop();
    await this.registry.unmountAll();
  }
}

/** Build a fully-mounted gateway from a validated config. */
export async function createGateway(cfg: SwitchboardConfig): Promise<Gateway> {
  const gateway = new Gateway(cfg);
  await gateway.mountAll();
  // Start polling only after every upstream is mounted (so the first poll can reach its tool).
  // No-op unless `settings.triggers.enabled`. Verifiers that use `new Gateway()` directly never
  // auto-start pollers — they drive `pollOnce()` deterministically instead.
  gateway.triggers.start();
  return gateway;
}
