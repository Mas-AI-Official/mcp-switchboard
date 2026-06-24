/**
 * Server registry — mounts upstream MCP servers and holds the live client connections.
 *
 * One `Client` per upstream server:
 *   - npx | binary -> StdioClientTransport (spawns a child process)
 *   - remote       -> StreamableHTTPClientTransport (connects over HTTP, creds as headers)
 *   - app2mcp      -> an in-process MCP `Server` generated from an OpenAPI/Swagger spec,
 *                     linked to this registry's `Client` over an in-memory transport. The
 *                     generated server carries per-tool scope hints (verb→scope) so the
 *                     router can govern each operation before it is forwarded.
 *
 * Credentials are resolved here, at mount time, and never touch the config on disk:
 *   - `${vault:name}` / `${env:NAME}` -> resolved synchronously by the vault (fail-closed).
 *   - `${oauth:provider}`             -> resolved asynchronously to a bare access token via
 *                                        the OAuth store (refreshing if needed, fail-closed).
 * For stdio sources they are injected as child-process env; for remote/app2mcp HTTP sources
 * the `credentials` map is rendered into request headers.
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { Scope, ServerConfig } from "./types.js";
import type { Vault } from "./vault.js";
import type { OAuthStore } from "./oauth.js";
import { buildOpenApiServer } from "./openapi.js";
import { log } from "./logger.js";

/** `${oauth:provider}` reference — resolved to a bare access token at mount time. */
const OAUTH_RE = /\$\{oauth:([^}]+)\}/g;

export interface MountedServer {
  id: string;
  config: ServerConfig;
  client: Client;
  tools: Tool[];
  /** Per-tool scope hints for app2mcp-generated tools (verb→scope). */
  scopeHints?: Record<string, Scope>;
}

export class Registry {
  private readonly mounted = new Map<string, MountedServer>();

  constructor(
    private readonly vault: Vault,
    private readonly oauth?: OAuthStore,
  ) {}

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
    let scopeHints: Record<string, Scope> | undefined;

    if (config.source === "app2mcp") {
      // Generate an in-process MCP server from the OpenAPI/Swagger spec and link it to
      // our client over an in-memory transport. Credentials become request headers,
      // resolved lazily (per call) so OAuth tokens can refresh between invocations.
      const generated = await buildOpenApiServer(config, () => this.resolveHeaders(config));
      const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
      await generated.server.connect(serverTransport);
      await client.connect(clientTransport);
      scopeHints = generated.scopeHints;
    } else {
      await client.connect(await this.buildTransport(config));
    }

    const { tools } = await client.listTools();

    const mounted: MountedServer = { id: config.id, config, client, tools, scopeHints };
    this.mounted.set(config.id, mounted);
    log.ok(`mounted '${config.id}' — ${tools.length} tool${tools.length === 1 ? "" : "s"}`);
    return mounted;
  }

  /**
   * Mount a pre-built in-process MCP `Server` (e.g. the council relay) under a synthetic
   * config, linking it to a fresh client over an in-memory transport — the same wiring as
   * the `app2mcp` branch, generalized so built-in servers reuse the registry + router path.
   * Idempotent per id.
   */
  async mountLocal(
    config: ServerConfig,
    server: Server,
    scopeHints?: Record<string, Scope>,
  ): Promise<MountedServer> {
    const existing = this.mounted.get(config.id);
    if (existing) return existing;

    const client = new Client({ name: `switchboard:${config.id}`, version: "0.1.0" });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const { tools } = await client.listTools();
    const mounted: MountedServer = { id: config.id, config, client, tools, scopeHints };
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

  private async buildTransport(config: ServerConfig): Promise<Transport> {
    if (config.source === "remote") {
      if (!config.url) throw new Error(`server '${config.id}': remote source needs a 'url'`);
      const headers = await this.resolveHeaders(config);
      return new StreamableHTTPClientTransport(new URL(config.url), {
        requestInit: { headers },
      });
    }

    // stdio sources: npx | binary
    const env = await this.childEnv(config);
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
  private async childEnv(config: ServerConfig): Promise<Record<string, string>> {
    const env: Record<string, string> = {};
    for (const [k, v] of Object.entries(process.env)) {
      if (typeof v === "string") env[k] = v;
    }
    for (const [k, v] of Object.entries(config.env ?? {})) env[k] = this.vault.resolve(v);
    for (const [k, v] of Object.entries(config.credentials ?? {})) env[k] = await this.resolveRef(v);
    return env;
  }

  /**
   * Render a config's `credentials` map into HTTP request headers for remote / app2mcp
   * sources, resolving every `${vault:}` / `${env:}` / `${oauth:}` reference (fail-closed).
   */
  private async resolveHeaders(config: ServerConfig): Promise<Record<string, string>> {
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(config.credentials ?? {})) {
      headers[k] = await this.resolveRef(v);
    }
    return headers;
  }

  /**
   * Resolve one credential value: first swap any `${oauth:provider}` ref for a live bearer
   * token via the OAuth store (refreshing as needed), then hand the rest to the vault for
   * `${vault:}` / `${env:}`. Fails closed if a referenced provider/secret is unavailable.
   */
  private async resolveRef(value: string): Promise<string> {
    OAUTH_RE.lastIndex = 0;
    const providers = [...value.matchAll(OAUTH_RE)].map((m) => m[1]);
    let resolved = value;
    for (const provider of providers) {
      if (!this.oauth) {
        throw new Error(`server credential references '\${oauth:${provider}}' but no OAuth store is configured`);
      }
      const token = await this.oauth.accessToken(provider);
      // String-form search + function replacement: literal match, no `$&` interpolation.
      resolved = resolved.replace(`\${oauth:${provider}}`, () => token);
    }
    return this.vault.resolve(resolved);
  }
}
