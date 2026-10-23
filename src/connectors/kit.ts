/**
 * ConnectorKit: the phase P2 layer wired together on top of the P1 `Connectors` (providers, auth configs,
 * accounts, connect flows).
 *
 *   toolkits   versioned toolkit definitions (generated + recipes + overlay)
 *   links      which client may use which toolkit, how far, as which account
 *   files      upload rules and download storage
 *   media      ephemeral public URLs for platforms that fetch media themselves
 *   exec       the execution pipeline
 *   coverage   honest counts
 *
 * One kit per `Connectors` instance (`connectors.kit`). The gateway configures it with live settings, the
 * kill switch and its approval path; a CLI run uses the defaults.
 */

import { join } from "node:path";
import type { AuditInput } from "../audit.js";
import { isKilled } from "../killswitch.js";
import type { ConnectorSettings } from "../types.js";
import type { Connectors } from "./index.js";
import { Coverage } from "./coverage.js";
import { Executor, type ApprovalRequest, type ExecDeps } from "./exec.js";
import { FileService } from "./files.js";
import { LinkStore } from "./links.js";
import { MediaStage } from "./mediastage.js";
import { ToolkitStore } from "./toolkits.js";
import type { Action } from "./toolkits.js";

export interface KitConfig {
  /** Live `settings.connectors`. */
  settings?: () => ConnectorSettings | undefined;
  /** True while the kill switch is on (file or config flag). */
  killed?: () => boolean;
  /** The human decision for an action that needs one. */
  approve?: (req: ApprovalRequest) => Promise<boolean>;
  needsApproval?: (action: Action) => boolean;
  /** Write each run's audit row from the executor (standalone) or leave it to the router (inside the gateway). */
  ownAudit?: boolean;
  sleep?: (ms: number) => Promise<void>;
  /** Replace the bundled overlay/recipe directory (tests). */
  bundledToolkitDir?: string;
}

export class ConnectorKit {
  readonly toolkits: ToolkitStore;
  readonly links: LinkStore;
  readonly files: FileService;
  readonly media: MediaStage;
  readonly exec: Executor;
  readonly coverage: Coverage;
  private readonly deps: ExecDeps;
  private settingsFn: () => ConnectorSettings | undefined = () => undefined;

  constructor(
    readonly connectors: Connectors,
    cfg: KitConfig = {},
  ) {
    const ctx = connectors.ctx;
    const home = ctx.home;
    this.settingsFn = cfg.settings ?? this.settingsFn;
    const settings = (): ConnectorSettings | undefined => this.settingsFn();
    this.toolkits = new ToolkitStore({ home, ...(cfg.bundledToolkitDir ? { bundledDir: cfg.bundledToolkitDir } : {}) });
    this.links = new LinkStore(home);
    this.files = new FileService({ home, settings, ...(ctx.network ? { network: ctx.network } : {}), now: ctx.now });
    this.media = new MediaStage({ home, settings, now: ctx.now });
    this.coverage = new Coverage(home, ctx.now, (id) => {
      const a = connectors.accounts.find(id);
      return Boolean(a && (a.provider_verification === "unverified_seed" || ctx.providers.isSeed(a.provider)));
    });
    this.deps = {
      accounts: connectors.accounts,
      providers: connectors.providers,
      toolkits: this.toolkits,
      links: this.links,
      files: this.files,
      media: this.media,
      now: ctx.now,
      ...(ctx.network ? { network: ctx.network } : {}),
      audit: (e: AuditInput) => ctx.audit(e),
      killed: cfg.killed ?? (() => isKilled(undefined, home)),
      ...(cfg.approve ? { approve: cfg.approve } : {}),
      ...(cfg.needsApproval ? { needsApproval: cfg.needsApproval } : {}),
      settings,
      ...(cfg.sleep ? { sleep: cfg.sleep } : {}),
      ownAudit: cfg.ownAudit ?? true,
    };
    this.exec = new Executor(this.deps);
    // A client bound to an account of a provider uses it (the seam the principals work replaces).
    connectors.accounts.setBindingResolver(({ provider, client }) => this.links.boundAccount(client, provider));
  }

  /** Adjust what the gateway knows that a CLI run does not. Only the fields given change. */
  configure(cfg: KitConfig): void {
    if (cfg.settings) this.settingsFn = cfg.settings;
    if (cfg.killed) this.deps.killed = cfg.killed;
    if (cfg.approve) this.deps.approve = cfg.approve;
    if (cfg.needsApproval) this.deps.needsApproval = cfg.needsApproval;
    if (cfg.ownAudit !== undefined) this.deps.ownAudit = cfg.ownAudit;
    if (cfg.sleep) this.deps.sleep = cfg.sleep;
  }

  get home(): string {
    return this.connectors.ctx.home;
  }

  /** Where the media files and downloads live, for the doctor. */
  get filesDir(): string {
    return join(this.home, "files");
  }

  /**
   * What `manage_connections` returns for a toolkit: every account of its provider with status and expiry,
   * which one this client uses, the toolkit's version and verification counts. Never a credential.
   */
  connectionStatus(toolkit: string, client?: string): Record<string, unknown> {
    const tk = this.toolkits.load(toolkit);
    const provider = this.connectors.providers.providerForToolkit(toolkit) ?? this.connectors.providers.get(tk?.provider ?? toolkit);
    const slug = provider?.slug ?? toolkit;
    const def = this.connectors.accounts.defaultFor(slug);
    const bound = client ? this.links.boundAccount(client, slug) : undefined;
    const used = (() => {
      try {
        return this.connectors.accounts.resolveForCall(slug, client ? { client } : {});
      } catch {
        return undefined;
      }
    })();
    return {
      toolkit,
      provider: slug,
      version: tk?.version,
      tools: tk?.tools_count ?? 0,
      verification: this.coverage.summary(toolkit),
      client: client ?? null,
      bound_account: bound ?? null,
      accounts: this.connectors.accounts.list({ provider: slug }).map((a) => ({
        id: a.id,
        label: a.label,
        status: a.status,
        ...(a.status_reason ? { status_reason: a.status_reason } : {}),
        identity: a.identity.display_name ?? a.identity.external_id,
        scopes: a.scopes_granted,
        expires_at: a.expires_at ?? null,
        last_refresh_at: a.last_refresh_at ?? null,
        last_probe_at: a.last_probe_at ?? null,
        ...(a.last_error ? { last_error: a.last_error } : {}),
        default: def?.id === a.id,
        used_by_this_client: used?.id === a.id,
        paused_for_s: this.exec.cooldownLeft(a.id),
      })),
    };
  }
}
