/**
 * Connectors: the wired-together connector layer (providers, auth configs, accounts, connect flows).
 *
 * One instance per process. The gateway reaches it through `OAuthStore` (oauth.ts keeps its old API and
 * delegates here), and the CLI builds its own for `connect`, `accounts`, `authconfig` and `providers`.
 * Everything it reads or writes lives under SWITCHBOARD_HOME (`connectors/*.json`, `providers/*.json`).
 */

import { AuditLog, type AuditInput } from "../audit.js";
import { HOME_DIR, loadVaultKey, type Vault } from "../vault.js";
import type { NetworkSource } from "../netguard.js";
import { AccountStore, type ConnectorContext } from "./accounts.js";
import { AuthConfigStore } from "./authconfigs.js";
import { ConnectFlows } from "./oauthflow.js";
import { ProviderRegistry } from "./providers.js";
import { ConnectorKit, type KitConfig } from "./kit.js";

export interface ConnectorsOptions {
  vault: Vault;
  network?: NetworkSource;
  /** SWITCHBOARD_HOME. Default: the process-wide home. */
  home?: string;
  /** Clock in epoch ms. Tests inject one to cross expiry and the 10 minute pending window. */
  clock?: () => number;
  /** Where lifecycle events go. Default: the home's hash-chained audit.log. */
  audit?: (entry: AuditInput) => void;
  /** Refresh margin before expiry. Default 60 000 ms. */
  skewMs?: number;
  /** Replace the bundled provider directory (tests only). */
  bundledProviderDir?: string;
  /** Replace the seed directory (tests only); `false` turns seeds off. Default: `seed/` beside the bundled directory. */
  seedProviderDir?: string | false;
  /** Initial settings for the connector kit (live settings, kill switch, approvals, bundled toolkit directory). */
  kit?: KitConfig;
}

export class Connectors {
  readonly ctx: ConnectorContext;
  readonly providers: ProviderRegistry;
  readonly authConfigs: AuthConfigStore;
  readonly accounts: AccountStore;
  readonly flows: ConnectFlows;
  private kitInstance: ConnectorKit | undefined;
  private readonly kitConfig: KitConfig | undefined;

  /** The phase P2 layer (toolkits, links, files, media, execution, coverage), built on first use. */
  get kit(): ConnectorKit {
    return (this.kitInstance ??= new ConnectorKit(this, this.kitConfig));
  }

  constructor(opts: ConnectorsOptions) {
    const home = opts.home ?? HOME_DIR;
    this.kitConfig = opts.kit;
    const now = opts.clock ?? Date.now;
    const providers = ProviderRegistry.load({
      home,
      ...(opts.bundledProviderDir ? { bundledDir: opts.bundledProviderDir } : {}),
      ...(opts.seedProviderDir !== undefined ? { seedDir: opts.seedProviderDir } : {}),
    });
    const authConfigs = new AuthConfigStore(home, providers, opts.vault, now);
    const log = new AuditLog(home);
    this.ctx = {
      home,
      vault: opts.vault,
      key: loadVaultKey(home),
      ...(opts.network ? { network: opts.network } : {}),
      now,
      audit: opts.audit ?? ((e) => log.append(e)),
      providers,
      authConfigs,
      skewMs: opts.skewMs ?? 60_000,
    };
    this.providers = providers;
    this.authConfigs = authConfigs;
    this.accounts = new AccountStore(this.ctx);
    this.flows = new ConnectFlows(this.ctx, this.accounts);
  }
}

export { AccountStore, summarize } from "./accounts.js";
export type { BindingResolver, ConnectorContext, Credential, RevokeResult } from "./accounts.js";
export { AuthConfigStore } from "./authconfigs.js";
export { ConnectFlows, PENDING_TTL_MS } from "./oauthflow.js";
export { ProviderRegistry, validateProviderDef, seedProblems, bundledSeedDir } from "./providers.js";
export { CONNECTOR_ERR, ConnectorError, isConnectorError } from "./errors.js";
export { ConnectorKit } from "./kit.js";
export type { KitConfig } from "./kit.js";
export type * from "./types.js";
