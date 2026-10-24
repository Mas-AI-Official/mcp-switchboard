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
import { Approvals } from "./approvals.js";
import { isKilled } from "./killswitch.js";
import { buildCouncilServer, COUNCIL_SERVER_ID } from "./council.js";
import { retryDelay, resolveMountRetry } from "./retry.js";
import { unpinnedPackageWarnings } from "./packagespec.js";
import { safeText } from "./safetext.js";
import type { Principal } from "./principal.js";
import { log } from "./logger.js";

const NAME = "switchboard";
/** Server version, surfaced over MCP `initialize` and the `/healthz` liveness probe. */
export const VERSION = "0.1.0";

export class Gateway {
  readonly vault: Vault;
  readonly oauth: OAuthStore;
  readonly registry: Registry;
  readonly router: Router;
  readonly triggers: TriggerManager;
  /** Out-of-band approvals (design 3.3): the router asks them, the dashboard and the control API decide on them. */
  readonly approvals: Approvals;

  /** Pending background remount timers, tracked so `shutdown()` can cancel every one — a
   *  scheduled retry must never resurrect a server after the gateway has been torn down. */
  private readonly pendingRetries = new Set<NodeJS.Timeout>();
  private shuttingDown = false;
  private readonly sweepTimer: NodeJS.Timeout;
  private readonly killTimer: NodeJS.Timeout;

  /** `opts.approvals` replaces the approvals manager (tests inject their own presence provider; production passes none). */
  constructor(private readonly cfg: SwitchboardConfig, opts: { approvals?: Approvals } = {}) {
    this.vault = new Vault(cfg.vault.backend);
    // The network guard reads the live config object, so a settings change is picked up without a restart.
    this.oauth = new OAuthStore(this.vault, () => cfg.settings?.network);
    this.registry = new Registry(this.vault, this.oauth, () => cfg.settings?.network);
    this.approvals = opts.approvals ?? new Approvals();
    this.router = new Router(this.registry, cfg, (ref) => this.vault.resolve(ref), this.approvals);
    // Polls run through this.router, so every trigger poll is governed + audited like any call.
    this.triggers = new TriggerManager(this.router, cfg, (ref) => this.vault.resolve(ref));
    // Undecided requests and unused approvals expire on their own clock; sweeping writes the `expired` audit row
    // even when nobody is calling. unref'd, so it never keeps the process alive.
    this.sweepTimer = setInterval(() => {
      try {
        this.approvals.sweep();
      } catch (err) {
        log.warn(`approval sweep failed: ${err instanceof Error ? err.message : String(err)}`);
      }
    }, 30_000);
    this.sweepTimer.unref();
    // The kill switch latches the first time this process sees it (killswitch.ts). Looking every quarter second, not
    // only when a call arrives, means a KILL file made by the CLI is latched, and a later delete of it is noticed and
    // audited, even while nobody is calling. One stat per tick; unref'd like the sweep.
    this.killTimer = setInterval(() => {
      try {
        isKilled(cfg);
      } catch (err) {
        log.warn(`kill switch check failed: ${err instanceof Error ? err.message : String(err)}`);
      }
    }, 250);
    this.killTimer.unref();
  }

  /** Mount every enabled server. Failures are isolated so one bad server can't sink the rest. */
  async mountAll(): Promise<void> {
    const enabled = this.cfg.servers.filter((s) => s.enabled !== false);
    log.info(`mounting ${enabled.length} server${enabled.length === 1 ? "" : "s"}…`);
    // A floating npx package still mounts (existing configs keep working), but never quietly.
    for (const warning of unpinnedPackageWarnings(enabled)) log.warn(`WARNING: ${warning}`);
    for (const server of enabled) {
      try {
        await this.registry.mount(server);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        log.error(`failed to mount '${server.id}': ${safeText(msg, 500)}`);
        // Self-heal: a transient failure (slow upstream, DNS blip, child still warming up)
        // is retried in the background on a capped backoff instead of staying dead-until-restart.
        this.scheduleRemount(server, 1);
      }
    }
    await this.mountCouncil();
  }

  /**
   * Schedule the `attempt`-th background remount of a server that failed to mount, on the capped
   * exponential backoff from `retry.ts`. Returns silently when retry is disabled, and logs one
   * give-up line when the attempts are spent. The timer is `unref()`'d so a pending retry can
   * never keep the process alive, and tracked in `pendingRetries` so `shutdown()` can cancel it.
   */
  private scheduleRemount(server: ServerConfig, attempt: number): void {
    if (this.shuttingDown) return;
    const policy = resolveMountRetry(this.cfg.settings?.mount_retry);
    if (!policy.enabled || policy.max_attempts <= 0) return; // retry off — dead-until-restart
    const delay = retryDelay(attempt, policy);
    if (delay === null) {
      log.error(
        `gave up mounting '${server.id}' after ${policy.max_attempts} ` +
          `${policy.max_attempts === 1 ? "retry" : "retries"}`,
      );
      return;
    }
    log.info(`will retry mount of '${server.id}' in ${delay}ms (attempt ${attempt}/${policy.max_attempts})`);
    const timer = setTimeout(() => {
      this.pendingRetries.delete(timer);
      void this.attemptRemount(server, attempt);
    }, delay);
    timer.unref();
    this.pendingRetries.add(timer);
  }

  /** One background mount attempt; reschedules the next on failure. Idempotent via the registry
   *  (a mount that has since succeeded by another path is a no-op). */
  private async attemptRemount(server: ServerConfig, attempt: number): Promise<void> {
    if (this.shuttingDown) return;
    try {
      await this.registry.mount(server);
      log.ok(`recovered '${server.id}' on retry ${attempt}`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      log.error(`retry ${attempt} to mount '${server.id}' failed: ${safeText(msg, 500)}`);
      this.scheduleRemount(server, attempt + 1);
    }
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
      const { server, scopeHints, toolCount } = buildCouncilServer(council, this.vault, () => this.cfg.settings?.network);
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
   *  matching capability is declared here.)
   *
   *  `principal` is who this server speaks to (design 3.1): every handler passes it to the router, which
   *  filters listings and refuses hidden calls by the principal's client. Omitted = an internal, unfiltered
   *  caller (the owner's own tooling), never an HTTP or stdio client. */
  buildServer(principal?: Principal): Server {
    const server = new Server(
      { name: NAME, version: VERSION },
      { capabilities: { tools: {}, resources: {}, prompts: {} } },
    );

    server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: this.router.listTools(principal),
    }));

    server.setRequestHandler(CallToolRequestSchema, async (req): Promise<CallToolResult> => {
      const { name, arguments: args } = req.params;
      return this.router.callTool(name, args ?? {}, principal);
    });

    // Resources — opaque URIs, aggregated across upstreams and read back by URI (not namespaced).
    server.setRequestHandler(ListResourcesRequestSchema, async () => ({
      resources: await this.router.listResources(principal),
    }));

    server.setRequestHandler(ListResourceTemplatesRequestSchema, async () => ({
      resourceTemplates: await this.router.listResourceTemplates(principal),
    }));

    server.setRequestHandler(ReadResourceRequestSchema, async (req) =>
      this.router.readResource(req.params.uri, principal),
    );

    // Prompts — namespaced `serverId__name`, aggregated across upstreams.
    server.setRequestHandler(ListPromptsRequestSchema, async () => ({
      prompts: await this.router.listPrompts(principal),
    }));

    server.setRequestHandler(GetPromptRequestSchema, async (req) =>
      this.router.getPrompt(req.params.name, req.params.arguments, principal),
    );

    return server;
  }

  /** Serve the stdio transport. Blocks for the life of the process. `principal` comes from `serve --client <id>`
   *  (via "stdio": an assertion by the launching process, not an authentication). */
  async serveStdio(principal?: Principal): Promise<void> {
    // stdin and stdout now carry JSON-RPC: no terminal prompt may use them, for the legacy gate or for a presence challenge.
    setStdioActive(true);
    this.approvals.setStdioActive(true);
    const server = this.buildServer(principal);
    await server.connect(new StdioServerTransport());
    log.ok(`stdio transport ready: ${this.router.listTools(principal).length} tools exposed${principal?.client ? ` to client '${principal.client}'` : ""}`);
  }

  async shutdown(): Promise<void> {
    this.shuttingDown = true;
    clearInterval(this.sweepTimer);
    clearInterval(this.killTimer);
    // Cancel every pending background remount so a dead server can't resurrect after shutdown.
    for (const timer of this.pendingRetries) clearTimeout(timer);
    this.pendingRetries.clear();
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
