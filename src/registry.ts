/**
 * Server registry — mounts upstream MCP servers and holds the live client connections.
 *
 * One `Client` per upstream server:
 *   - npx | binary -> StdioClientTransport (spawns a child process)
 *   - remote       -> StreamableHTTPClientTransport (connects over HTTP)
 *   - app2mcp      -> roadmap (Phase 4); fails closed with a clear message for now
 *
 * Credentials (`${vault:..}` refs) are resolved here, at mount time, and injected into
 * the child process env — they never touch the config on disk or the network.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { ServerConfig } from "./types.js";
import type { Vault } from "./vault.js";
import { log } from "./logger.js";

export interface MountedServer {
  id: string;
  config: ServerConfig;
  client: Client;
  tools: Tool[];
}

export class Registry {
  private readonly mounted = new Map<string, MountedServer>();

  constructor(private readonly vault: Vault) {}

  list(): MountedServer[] {
    return [...this.mounted.values()];
  }

  get(id: string): MountedServer | undefined {
    return this.mounted.get(id);
  }

  has(id: string): boolean {
    return this.mounted.has(id);
  }

  /** Connect to an upstream server and cache its tool list. Idempotent per id. */
  async mount(config: ServerConfig): Promise<MountedServer> {
    const existing = this.mounted.get(config.id);
    if (existing) return existing;

    const client = new Client({ name: `switchboard:${config.id}`, version: "0.1.0" });
    await client.connect(this.buildTransport(config));
    const { tools } = await client.listTools();

    const mounted: MountedServer = { id: config.id, config, client, tools };
    this.mounted.set(config.id, mounted);
    log.ok(`mounted '${config.id}' — ${tools.length} tool${tools.length === 1 ? "" : "s"}`);
    return mounted;
  }

  async unmount(id: string): Promise<void> {
    const mounted = this.mounted.get(id);
    if (!mounted) return;
    try {
      await mounted.client.close();
    } catch {
      /* upstream already gone */
    }
    this.mounted.delete(id);
    log.info(`unmounted '${id}'`);
  }

  async unmountAll(): Promise<void> {
    await Promise.all([...this.mounted.keys()].map((id) => this.unmount(id)));
  }

  private buildTransport(config: ServerConfig): Transport {
    if (config.source === "remote") {
      if (!config.url) throw new Error(`server '${config.id}': remote source needs a 'url'`);
      return new StreamableHTTPClientTransport(new URL(config.url));
    }

    if (config.source === "app2mcp") {
      throw new Error(`server '${config.id}': app2mcp generation is on the roadmap (Phase 4), not yet implemented`);
    }

    // stdio sources: npx | binary
    const env = this.childEnv(config);
    let command: string;
    let args: string[];

    if (config.source === "npx") {
      if (!config.package) throw new Error(`server '${config.id}': npx source needs a 'package'`);
      command = process.platform === "win32" ? "npx.cmd" : "npx";
      args = ["-y", config.package, ...(config.args ?? [])];
    } else {
      if (!config.command) throw new Error(`server '${config.id}': binary source needs a 'command'`);
      command = config.command;
      args = config.args ?? [];
    }

    return new StdioClientTransport({ command, args, env, stderr: "inherit" });
  }

  /** Inherit the parent env (PATH etc.) and layer resolved env + credentials on top. */
  private childEnv(config: ServerConfig): Record<string, string> {
    const env: Record<string, string> = {};
    for (const [k, v] of Object.entries(process.env)) {
      if (typeof v === "string") env[k] = v;
    }
    for (const [k, v] of Object.entries(config.env ?? {})) env[k] = this.vault.resolve(v);
    for (const [k, v] of Object.entries(config.credentials ?? {})) env[k] = this.vault.resolve(v);
    return env;
  }
}
