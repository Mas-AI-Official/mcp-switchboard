/**
 * The execution pipeline (ADR local-composio, section 6.4). Order matters, and `ExecResult.stages` records
 * the order a run actually took so the oracle can hold it to the ADR:
 *
 *   kill_switch      the switch is on: refuse
 *   client_filter    the calling client must be linked to this toolkit (links.ts)
 *   toolkit_account  the toolkit exists, the action exists, the account is chosen and ACTIVE
 *   validate         Ajv against the action's input schema (scalar coercion only)
 *   policy           the client's scope and risk caps
 *   approval         out-of-band approval bound to (principal, server, tool, sha256(canonical args)); file
 *                    inputs are read and hashed here, and the same bytes are sent later, so a swapped file
 *                    cannot ride on an earlier approval
 *   limits           the account's provider cooldown (a 429 with Retry-After pauses the account)
 *   token            a fresh credential (single-flight refresh); a dead one stops here with the fix command
 *   build            path, query, body mapping, or the recipe's steps
 *   files            uploads are staged (resumable sessions, media URLs)
 *   fetch            guardedFetch with the provider's `api_hosts` host lock (SB_HOST_NOT_ALLOWED)
 *   normalize        provider errors to SB_PROVIDER_*, 429 + Retry-After to the cooldown, JSON parsed
 *   output_files     binary responses saved under files/<run_id>/ and returned as { uri, bytes, sha256, mimeType }
 *   redact           the credential's own values removed from anything returned
 *   audit            one row: toolkit, toolkit version, account id, client, risk; never a token
 *
 * Rules that do not bend:
 *   - an action with `idempotent: false` (a post, an upload finalize, a send) is NEVER retried. If the request
 *     left and the answer was lost, the result is SB_OUTCOME_UNKNOWN with a reconcile hint (look the thing up
 *     before doing it again). Only idempotent reads are retried, a bounded number of times, on a 5xx or a
 *     failure to connect.
 *   - the credential only ever goes to a host in the provider's `api_hosts`, over https (loopback excepted),
 *     and a redirect to another origin drops it (accounts.authFetch plus the guard).
 *   - the router's own checks (policy ceilings, profiles, limits, approvals by scope) still run in front of
 *     this pipeline when it is reached through the gateway; the steps here are the connector's own.
 */

import { createHash, randomBytes } from "node:crypto";
import type { Scope, ConnectorSettings } from "../types.js";
import type { AuditInput } from "../audit.js";
import { canonicalJson } from "../audit.js";
import { NetGuardError, guardedFetch, type GuardedResponse, type NetworkSource } from "../netguard.js";
import type { AccountStore } from "./accounts.js";
import { hostAllowed } from "./providers.js";
import type { ProviderRegistry } from "./providers.js";
import type { ConnectedAccount, ProviderDef } from "./types.js";
import { CONNECTOR_ERR, ConnectorError, isConnectorError, reconnectCommand, type ConnectorErrorCode } from "./errors.js";
import { FileService, newRunId, type FileRef, type ResolvedFile } from "./files.js";
import { MediaStage } from "./mediastage.js";
import { LinkStore, withinCaps } from "./links.js";
import { makeAjv, type Action, type ActionHttp, type Risk, type Toolkit, type ToolkitStore } from "./toolkits.js";
import { RecipeError, runRecipe, type HttpResult, type RecipeRuntime } from "./recipes.js";
import { scrubAndClip } from "./scrub.js";

// ── public shapes ─────────────────────────────────────────────────────────────────────────────────

export const STAGES = ["kill_switch", "client_filter", "toolkit_account", "validate", "policy", "approval", "limits", "token", "build", "files", "fetch", "normalize", "output_files", "redact", "audit"] as const;
export type Stage = (typeof STAGES)[number];

export interface ApprovalRequest {
  client?: string;
  server: string;
  toolkit: string;
  tool: string;
  scope: Scope;
  risk: Risk;
  outward: boolean;
  /** sha256 over the canonical args with every file input replaced by its content hash. */
  args_hash: string;
  files: { param: string; sha256: string; bytes: number }[];
  reason: string;
}

export interface ExecDeps {
  accounts: AccountStore;
  providers: ProviderRegistry;
  toolkits: ToolkitStore;
  links: LinkStore;
  files: FileService;
  media: MediaStage;
  now: () => number;
  network?: NetworkSource;
  audit: (entry: AuditInput) => void;
  /** True while the kill switch is on. */
  killed: () => boolean;
  /** The human decision. Resolves true to allow. Absent: an action that requires approval is refused. */
  approve?: (req: ApprovalRequest) => Promise<boolean>;
  /** Which actions need a decision. Default: only `approval: "always"` (proxy_request). */
  needsApproval?: (action: Action) => boolean;
  settings: () => ConnectorSettings | undefined;
  sleep?: (ms: number) => Promise<void>;
  /** Write the audit row here (standalone use). False inside the gateway: the router writes it from `ExecResult.audit`. */
  ownAudit: boolean;
}

export interface RunInput {
  toolkit: string;
  action: string;
  args: Record<string, unknown>;
  client?: string;
  /** The server id this runs under (audit `server`). Default: the toolkit slug. */
  server?: string;
  /** The account the server config pins; below a tool argument and a client binding, above the provider default. */
  serverAccount?: string;
  /** An action built in code (proxy_request) rather than loaded from the toolkit. */
  synthetic?: Action;
}

export interface ExecErrorInfo {
  code: ConnectorErrorCode | "SB_RECIPE_FAILED" | string;
  message: string;
  hint?: string;
  retry_after_s?: number;
  reconcile?: string;
  reconnect?: string;
  /** Recipe steps that had already completed when it stopped. */
  completed?: string[];
  status?: number;
}

/** The fields the router merges into its own audit row. */
export interface AuditFields {
  toolkit: string;
  toolkit_version?: string;
  account?: string;
  client?: string;
  risk?: Risk;
  outward?: boolean;
  run_id: string;
  error_code?: string;
}

export interface ExecResult {
  ok: boolean;
  run_id: string;
  data?: unknown;
  files?: FileRef[];
  error?: ExecErrorInfo;
  /** HTTP status of the provider's (last) answer, when there was one. */
  status?: number;
  audit: AuditFields;
  stages: Stage[];
  /** The decision the audit row carries: `deny` for a refusal before anything was sent, else `allow`. */
  decision: "allow" | "deny";
  duration_ms: number;
}

// ── helpers ───────────────────────────────────────────────────────────────────────────────────────

const IDEMPOTENT_METHODS = new Set(["GET", "HEAD", "OPTIONS", "PUT", "DELETE"]);
const MAX_RETRIES = 2;
const PRE_SEND_NET = new Set(["ECONNREFUSED", "ENOTFOUND", "EAI_AGAIN"]);
const PRE_SEND_GUARD = new Set(["invalid_url", "bad_scheme", "blocked_host", "blocked_address", "dns_failed"]);
const DEFAULT_COOLDOWN_S = 30;
const MAX_COOLDOWN_S = 3600;

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;

function parseRetryAfter(h: string | null, now: number): number | undefined {
  if (!h) return undefined;
  const n = Number(h);
  if (Number.isFinite(n) && n >= 0) return Math.ceil(n);
  const d = Date.parse(h);
  return Number.isFinite(d) ? Math.max(0, Math.ceil((d - now) / 1000)) : undefined;
}

function headersObject(res: GuardedResponse): Record<string, string> {
  const out: Record<string, string> = {};
  res.headers.forEach((v, k) => {
    out[k.toLowerCase()] = v;
  });
  return out;
}

/** The provider's own message, from the shapes APIs commonly use. Always scrubbed and clipped. */
function providerMessage(body: unknown, secrets: string[]): string {
  if (typeof body === "string") return scrubAndClip(body, secrets, 300);
  if (body && typeof body === "object") {
    const o = body as Record<string, unknown>;
    const inner = o.error && typeof o.error === "object" ? (o.error as Record<string, unknown>) : undefined;
    const errs = Array.isArray(o.errors) ? (o.errors[0] as Record<string, unknown> | string | undefined) : undefined;
    const candidates = [inner?.message, o.error_description, o.message, o.detail, o.title, typeof o.error === "string" ? o.error : undefined, typeof errs === "string" ? errs : errs?.message, o.reason];
    const first = candidates.find((c) => typeof c === "string" && c.trim());
    if (typeof first === "string") return scrubAndClip(first, secrets, 300);
  }
  return "the provider gave no error message";
}

const SLACK_AUTH = /^(invalid_auth|not_authed|token_expired|token_revoked|account_inactive|invalid_token)$/;
const SLACK_FORBIDDEN = /^(missing_scope|not_allowed_token_type|restricted_action|access_denied|no_permission)$/;

interface Mapped {
  code: ConnectorErrorCode;
  hint?: string;
  retryAfterS?: number;
}

function mapFailure(status: number, body: unknown, headers: Record<string, string>, now: number): Mapped {
  const ra = parseRetryAfter(headers["retry-after"] ?? null, now);
  // Slack-style: HTTP 200 with {ok:false,error:"..."}.
  if (status >= 200 && status < 300 && body && typeof body === "object" && (body as { ok?: unknown }).ok === false) {
    const err = String((body as { error?: unknown }).error ?? "");
    if (SLACK_AUTH.test(err)) return { code: CONNECTOR_ERR.PROVIDER_UNAUTHORIZED };
    if (SLACK_FORBIDDEN.test(err)) return { code: CONNECTOR_ERR.PROVIDER_FORBIDDEN };
    if (err === "ratelimited") return { code: CONNECTOR_ERR.PROVIDER_RATE_LIMITED, ...(ra !== undefined ? { retryAfterS: ra } : {}) };
    if (/not_found$/.test(err)) return { code: CONNECTOR_ERR.PROVIDER_NOT_FOUND };
    return { code: CONNECTOR_ERR.PROVIDER_BAD_REQUEST };
  }
  if (status === 429) return { code: CONNECTOR_ERR.PROVIDER_RATE_LIMITED, retryAfterS: ra ?? DEFAULT_COOLDOWN_S };
  if (status === 403 && body && typeof body === "object") {
    const errs = ((body as { error?: { errors?: { reason?: string }[] } }).error?.errors ?? []).map((e) => String(e.reason ?? ""));
    if (errs.some((r) => /rateLimit|quotaExceeded|userRateLimit/i.test(r))) return { code: CONNECTOR_ERR.PROVIDER_RATE_LIMITED, ...(ra !== undefined ? { retryAfterS: ra } : {}) };
  }
  if (status === 400 || status === 422) return { code: CONNECTOR_ERR.PROVIDER_BAD_REQUEST };
  if (status === 401) return { code: CONNECTOR_ERR.PROVIDER_UNAUTHORIZED };
  if (status === 403) return { code: CONNECTOR_ERR.PROVIDER_FORBIDDEN };
  if (status === 404) return { code: CONNECTOR_ERR.PROVIDER_NOT_FOUND };
  if (status === 409) return { code: CONNECTOR_ERR.PROVIDER_CONFLICT };
  if (status === 408 || status >= 500) return { code: CONNECTOR_ERR.PROVIDER_UNAVAILABLE, ...(ra !== undefined ? { retryAfterS: ra } : {}) };
  return { code: CONNECTOR_ERR.PROVIDER_FAILED };
}

function isFailureBody(status: number, body: unknown): boolean {
  if (status < 200 || status >= 300) return true;
  return Boolean(body && typeof body === "object" && (body as { ok?: unknown }).ok === false && typeof (body as { error?: unknown }).error === "string");
}

function defaultReconcile(toolkit: string): string {
  return `This call changes data and was not retried. Before repeating it, look for its effect with a list or get action of ${toolkit} (for example the item it would have created).`;
}

/** Replace `{name}` and `{+name}` in a path template from the bound path arguments. */
function expandPath(template: string, action: Action, http: ActionHttp, args: Record<string, unknown>): string {
  return template.replace(/\{(\+?)([^}]+)\}/g, (_m, plus: string, name: string) => {
    const key = Object.keys(http.params).find((k) => http.params[k]!.in === "path" && http.params[k]!.name === name);
    const raw = key !== undefined ? args[key] : undefined;
    if (raw === undefined || raw === null || raw === "") throw new ConnectorError(CONNECTOR_ERR.BAD_REQUEST, `'${key ?? name}' is required (${action.slug})`);
    const text = Array.isArray(raw) ? raw.join(",") : String(raw);
    return plus ? text.split("/").map(encodeURIComponent).join("/") : encodeURIComponent(text);
  });
}

function queryPairs(http: ActionHttp, args: Record<string, unknown>): [string, string][] {
  const out: [string, string][] = [];
  for (const [key, b] of Object.entries(http.params)) {
    if (b.in !== "query") continue;
    const v = args[key];
    if (v === undefined || v === null) continue;
    if (Array.isArray(v)) {
      if (b.repeated === false) out.push([b.name, v.join(",")]);
      else for (const x of v) out.push([b.name, String(x)]);
    } else out.push([b.name, typeof v === "object" ? JSON.stringify(v) : String(v)]);
  }
  return out;
}

function multipart(parts: { name: string; value?: string; file?: { bytes: Uint8Array; name: string; mimeType: string } }[]): { body: Buffer; contentType: string } {
  const boundary = `----sb${randomBytes(12).toString("hex")}`;
  const chunks: Buffer[] = [];
  for (const p of parts) {
    if (p.file) {
      chunks.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${p.name}"; filename="${p.file.name.replace(/"/g, "")}"\r\nContent-Type: ${p.file.mimeType}\r\n\r\n`));
      chunks.push(Buffer.from(p.file.bytes));
      chunks.push(Buffer.from("\r\n"));
    } else {
      chunks.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${p.name}"\r\n\r\n${p.value ?? ""}\r\n`));
    }
  }
  chunks.push(Buffer.from(`--${boundary}--\r\n`));
  return { body: Buffer.concat(chunks), contentType: `multipart/form-data; boundary=${boundary}` };
}

interface Prepared {
  method: string;
  url: URL;
  headers: Record<string, string>;
  body?: string | Uint8Array;
  /** Upload to perform instead of a single request: metadata body in `body`, file bytes below. */
  resumable?: { initUrl: URL; file: ResolvedFile };
}

function secretsOf(a: { payload?: { access_token?: string; refresh_token?: string; fields?: Record<string, string> } }): string[] {
  const p = a.payload;
  if (!p) return [];
  return [p.access_token, p.refresh_token, ...Object.values(p.fields ?? {})].filter((x): x is string => typeof x === "string" && x.length >= 6);
}

/** Replace the exact values of the credential, wherever they appear in returned data. */
function scrubExact(value: unknown, secrets: string[]): unknown {
  if (secrets.length === 0) return value;
  const variants = secrets.flatMap((s) => [s, encodeURIComponent(s), Buffer.from(s).toString("base64")]).filter((v) => v.length >= 6);
  const walk = (v: unknown): unknown => {
    if (typeof v === "string") {
      let out = v;
      for (const s of variants) if (out.includes(s)) out = out.split(s).join("[redacted]");
      return out;
    }
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, walk(x)]));
    return v;
  };
  return walk(value);
}

function parseBody(res: GuardedResponse, bytes: Uint8Array): { kind: "json" | "text" | "binary"; value: unknown } {
  const ct = (res.headers.get("content-type") ?? "").toLowerCase();
  if (bytes.byteLength === 0) return { kind: "json", value: null };
  const text = (): string => new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  if (ct.includes("json") || ct.includes("+json")) {
    try {
      return { kind: "json", value: JSON.parse(text()) };
    } catch {
      return { kind: "text", value: text() };
    }
  }
  if (ct.startsWith("text/") || ct.includes("xml") || ct.includes("javascript") || ct === "") {
    const t = text();
    if (ct === "") {
      try {
        return { kind: "json", value: JSON.parse(t) };
      } catch {
        /* plain text */
      }
    }
    return { kind: "text", value: t };
  }
  return { kind: "binary", value: bytes };
}

// ── the executor ──────────────────────────────────────────────────────────────────────────────────

export class Executor {
  private readonly ajv = makeAjv();
  private readonly validators = new Map<string, ReturnType<typeof makeAjv>["compile"] extends (s: object) => infer R ? R : never>();
  /** account id -> epoch ms until which the provider asked us to stop (a 429's Retry-After). */
  private readonly cooldown = new Map<string, number>();

  constructor(private readonly d: ExecDeps) {}

  /** Seconds left on an account's provider cooldown (0 when none). */
  cooldownLeft(accountId: string): number {
    const until = this.cooldown.get(accountId) ?? 0;
    return Math.max(0, Math.ceil((until - this.d.now()) / 1000));
  }

  async run(input: RunInput): Promise<ExecResult> {
    const started = this.d.now();
    const runId = newRunId(started);
    const stages: Stage[] = [];
    const audit: AuditFields = { toolkit: input.toolkit, run_id: runId, ...(input.client ? { client: input.client } : {}) };
    const cleanup: (() => void)[] = [];
    let result: ExecResult;
    let executed = false;
    const ctx: RunCtx = { stages, audit, cleanup, markExecuted: () => (executed = true), info: {} };
    try {
      const out = await this.pipeline(input, runId, ctx);
      result = { ok: true, run_id: runId, data: out.data, ...(out.files.length ? { files: out.files } : {}), status: out.status, audit, stages, decision: "allow", duration_ms: this.d.now() - started };
    } catch (err) {
      const info = this.toError(err, ctx);
      audit.error_code = info.code;
      result = { ok: false, run_id: runId, error: info, ...(info.status !== undefined ? { status: info.status } : {}), audit, stages, decision: executed ? "allow" : "deny", duration_ms: this.d.now() - started };
    } finally {
      for (const fn of cleanup) {
        try {
          fn();
        } catch {
          /* best effort: a staged media file also expires on its own */
        }
      }
    }
    stages.push("audit");
    if (this.d.ownAudit) this.writeAudit(input, result, ctx);
    return result;
  }

  /** The one row a run writes (standalone use); inside the gateway the router writes it from `result.audit`. */
  writeAudit(input: RunInput, r: ExecResult, ctx?: { info?: { scope?: Scope; tool?: string } }): void {
    try {
      this.d.audit({
        server: input.server ?? input.toolkit,
        tool: input.synthetic?.slug ?? input.action,
        scope: ctx?.info?.scope ?? "write",
        decision: r.decision,
        reason: r.ok ? "ok" : (r.error?.message ?? "failed").slice(0, 160),
        toolkit: r.audit.toolkit,
        ...(r.audit.toolkit_version ? { toolkit_version: r.audit.toolkit_version } : {}),
        ...(r.audit.account ? { account: r.audit.account } : {}),
        ...(r.audit.client ? { client: r.audit.client } : {}),
        ...(r.audit.risk ? { risk: r.audit.risk } : {}),
        ...(r.audit.outward !== undefined ? { outward: r.audit.outward } : {}),
        run_id: r.run_id,
        duration_ms: r.duration_ms,
        ...(r.error ? { error: r.error.message, error_code: r.error.code } : {}),
      });
    } catch {
      /* the audit write must never cost the caller its result */
    }
  }

  // ── pipeline ─────────────────────────────────────────────────────────────────────────────────

  private async pipeline(input: RunInput, runId: string, ctx: RunCtx): Promise<{ data: unknown; files: FileRef[]; status?: number }> {
    const d = this.d;
    const { stages, audit } = ctx;
    const mark = (s: Stage): void => {
      stages.push(s);
    };

    mark("kill_switch");
    if (d.killed()) throw new ConnectorError(CONNECTOR_ERR.KILL_SWITCH, "the kill switch is on: every tool call is refused", { hint: "run `switchboard kill off`" });

    mark("client_filter");
    const link = d.links.check(input.client, input.toolkit);
    if (!link.allowed) throw new ConnectorError(CONNECTOR_ERR.CLIENT_NOT_LINKED, link.reason ?? "this client is not linked to the toolkit");

    mark("toolkit_account");
    const tk = d.toolkits.load(input.toolkit);
    if (!tk && !input.synthetic) throw new ConnectorError(CONNECTOR_ERR.TOOLKIT_NOT_FOUND, `toolkit '${input.toolkit}' is not defined here`, { hint: `run \`switchboard toolkits sync ${input.toolkit}\`` });
    if (tk) audit.toolkit_version = tk.version;
    const action = input.synthetic ?? tk!.actions.find((a) => a.slug === input.action);
    if (!action) throw new ConnectorError(CONNECTOR_ERR.ACTION_NOT_FOUND, `toolkit '${input.toolkit}' has no action '${input.action}'`);
    ctx.info.scope = action.scope;
    ctx.info.tool = action.slug;
    audit.risk = action.risk;
    audit.outward = action.outward;
    const provider = d.providers.providerForToolkit(input.toolkit) ?? d.providers.get(tk?.provider ?? input.toolkit);
    if (!provider) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `no provider definition backs toolkit '${input.toolkit}'`);
    let args = clone(input.args ?? {});
    const explicit = typeof args.account === "string" && args.account.trim() ? args.account.trim() : undefined;
    if ("account" in args && !(action.input_schema.properties as Record<string, unknown> | undefined)?.account) delete args.account;
    const ref = explicit ?? d.links.boundAccount(input.client, provider.slug) ?? input.serverAccount;
    const account = d.accounts.resolveForCall(provider.slug, ref ? { account: ref, ...(input.client ? { client: input.client } : {}) } : input.client ? { client: input.client } : {});
    audit.account = account.id;
    this.assertActive(account);

    mark("validate");
    const validate = this.validatorFor(tk?.slug ?? input.toolkit, tk?.version ?? "synthetic", action);
    const valid = validate(args);
    if (!valid) {
      const first = (validate.errors ?? []).slice(0, 3).map((e) => `${e.instancePath || "(arguments)"} ${e.message ?? "is invalid"}`).join("; ");
      throw new ConnectorError(CONNECTOR_ERR.BAD_REQUEST, `the arguments do not match ${action.slug}: ${first}`, { hint: "check the tool's input schema" });
    }

    mark("policy");
    const caps = withinCaps(link.link, action.scope, action.risk);
    if (!caps.ok) throw new ConnectorError(CONNECTOR_ERR.POLICY_DENY, `${action.slug} ${caps.reason}`, { hint: "raise the client's limits with `switchboard link <client> <toolkit> --max-scope ... --max-risk ...`" });

    // Files are read and hashed once, here. The approval binds to those hashes and the same bytes are sent.
    const resolved = await this.resolveFiles(action, args, ctx);
    mark("approval");
    const needs = (d.needsApproval ?? ((a: Action) => a.approval === "always"))(action);
    if (needs) {
      const hashable = this.hashableArgs(action, args, resolved);
      const req: ApprovalRequest = {
        ...(input.client ? { client: input.client } : {}),
        server: input.server ?? input.toolkit,
        toolkit: input.toolkit,
        tool: action.slug,
        scope: action.scope,
        risk: action.risk,
        outward: action.outward,
        args_hash: createHash("sha256").update(canonicalJson(hashable)).digest("hex"),
        files: [...resolved.entries()].map(([param, f]) => ({ param, sha256: f.sha256, bytes: f.bytes.byteLength })),
        reason: `${action.slug} (${action.scope}, ${action.risk} risk${action.outward ? ", visible to others" : ""}) on ${provider.slug}`,
      };
      const ok = d.approve ? await d.approve(req) : false;
      if (!ok) throw new ConnectorError(CONNECTOR_ERR.APPROVAL_DENIED, `${action.slug} needs a human decision and none was given`, { hint: "approve it in the dashboard or at the terminal prompt, then repeat the call" });
    }

    mark("limits");
    const left = this.cooldownLeft(account.id);
    if (left > 0) throw new ConnectorError(CONNECTOR_ERR.PROVIDER_RATE_LIMITED, `${provider.slug} asked us to wait: account ${account.id} is paused for ${left} more second${left === 1 ? "" : "s"}`, { hint: "no request was sent; try again after the pause" });

    mark("token");
    const cred = await d.accounts.credential(account.id);
    const secrets = secretsOf(cred);

    mark("build");
    const toolkitBase = this.baseUrlFor(tk, action, provider);
    let result: { data: unknown; files: FileRef[]; status?: number };
    if (action.steps) {
      mark("files");
      mark("fetch");
      result = await this.runRecipeAction(action, args, resolved, account, provider, toolkitBase, runId, ctx, secrets);
      mark("normalize");
      mark("output_files");
    } else if (action.proxy) {
      const prepared = this.prepareProxy(args, toolkitBase);
      mark("files");
      mark("fetch");
      const res = await this.send(account, prepared, action, ctx, secrets, false);
      mark("normalize");
      result = await this.finish(res, action, runId, ctx, secrets, input.toolkit);
      mark("output_files");
    } else {
      const prepared = this.prepare(action, args, resolved);
      mark("files");
      mark("fetch");
      const res = await this.send(account, prepared, action, ctx, secrets, Boolean(action.http?.download));
      mark("normalize");
      result = await this.finish(res, action, runId, ctx, secrets, input.toolkit);
      mark("output_files");
    }

    mark("redact");
    const data = scrubExact(result.data, secrets);
    return { data, files: result.files, ...(result.status !== undefined ? { status: result.status } : {}) };
  }

  // ── stages ───────────────────────────────────────────────────────────────────────────────────

  private assertActive(a: ConnectedAccount): void {
    if (a.status === "ACTIVE") return;
    const reconnect = reconnectCommand(a.provider, a.label);
    const base = { account: a.id, provider: a.provider };
    switch (a.status) {
      case "EXPIRED":
        throw new ConnectorError(CONNECTOR_ERR.ACCOUNT_EXPIRED, `account ${a.id} (${a.provider}/${a.label}) has expired. Reconnect it: ${reconnect}`, { ...base, reconnect });
      case "INACTIVE":
        throw new ConnectorError(CONNECTOR_ERR.ACCOUNT_DISABLED, `account ${a.id} is disabled. Enable it: switchboard accounts enable ${a.id}`, { ...base, reconnect: `switchboard accounts enable ${a.id}` });
      case "REVOKED":
        throw new ConnectorError(CONNECTOR_ERR.ACCOUNT_REVOKED, `account ${a.id} was revoked. Connect it again: ${reconnect}`, { ...base, reconnect });
      default:
        throw new ConnectorError(CONNECTOR_ERR.ACCOUNT_NOT_ACTIVE, `account ${a.id} is ${a.status}, not ACTIVE. Connect it: ${reconnect}`, { ...base, reconnect });
    }
  }

  private validatorFor(toolkit: string, version: string, action: Action) {
    const key = `${toolkit}@${version}:${action.slug}`;
    let v = this.validators.get(key);
    if (!v) {
      v = this.ajv.compile(action.input_schema);
      this.validators.set(key, v);
    }
    return v;
  }

  private fileParams(action: Action): string[] {
    return action.files?.upload ?? [];
  }

  /** Read every file input once (allowlist, sensitive paths, symlinks, size) and hash it. */
  private async resolveFiles(action: Action, args: Record<string, unknown>, ctx: RunCtx): Promise<Map<string, ResolvedFile>> {
    const out = new Map<string, ResolvedFile>();
    const props = (action.input_schema.properties ?? {}) as Record<string, unknown>;
    for (const param of this.fileParams(action)) {
      const raw = args[param];
      if (raw === undefined || raw === null) continue;
      const refs = Array.isArray(raw) ? raw : [raw];
      for (const [i, ref] of refs.entries()) {
        const key = Array.isArray(raw) ? `${param}[${i}]` : param;
        const maxBytes = action.http?.upload?.max_bytes;
        const file = await this.d.files.resolveUpload(ref, maxBytes ? Math.min(maxBytes, this.d.files.maxUpload()) : undefined);
        out.set(key, file);
        // A platform that fetches the media itself gets an ephemeral public URL instead of the bytes.
        const flag = (props[param] as { "x-file"?: string; items?: { "x-file"?: string } } | undefined);
        if ((flag?.["x-file"] ?? flag?.items?.["x-file"]) === "public_url") {
          const staged = await this.d.media.backend().publish({ bytes: file.bytes, name: file.name, mimeType: file.mimeType }, {});
          ctx.cleanup.push(() => this.d.media.release(staged.id));
          if (Array.isArray(raw)) (args[param] as unknown[])[i] = staged.url;
          else args[param] = staged.url;
        }
      }
    }
    return out;
  }

  private hashableArgs(action: Action, args: Record<string, unknown>, resolved: Map<string, ResolvedFile>): unknown {
    const copy = clone(args);
    for (const param of this.fileParams(action)) {
      const raw = copy[param];
      if (raw === undefined) continue;
      const digest = (key: string): unknown => {
        const f = resolved.get(key);
        return f ? { file_sha256: f.sha256, bytes: f.bytes.byteLength } : null;
      };
      copy[param] = Array.isArray(raw) ? raw.map((_x, i) => digest(`${param}[${i}]`)) : digest(param);
    }
    return copy;
  }

  private baseUrlFor(tk: Toolkit | undefined, action: Action, provider: ProviderDef): string {
    if (action.http?.base_url) return action.http.base_url;
    if (action.base_url) return action.base_url;
    if (tk?.base_url) return tk.base_url;
    const host = provider.api_hosts.find((h) => !h.startsWith("*"));
    return host ? (/^(127\.0\.0\.1|localhost)/.test(host) ? `http://${host}` : `https://${host}`) : "";
  }

  private prepare(action: Action, args: Record<string, unknown>, resolved: Map<string, ResolvedFile>): Prepared {
    const http = action.http;
    if (!http) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `action ${action.slug} has no request definition`);
    const base = new URL(http.base_url);
    const path = expandPath(http.path, action, http, args);
    const url = new URL(base.origin + (base.pathname.replace(/\/+$/, "") + "/" + path.replace(/^\/+/, "")).replace(/\/{2,}/g, "/"));
    if (url.origin !== base.origin) throw new ConnectorError(CONNECTOR_ERR.HOST_NOT_ALLOWED, "the operation path changes the host of the base URL");
    for (const [k, v] of queryPairs(http, args)) url.searchParams.append(k, v);
    const headers: Record<string, string> = { accept: "application/json" };
    for (const [key, b] of Object.entries(http.params)) if (b.in === "header" && args[key] !== undefined && args[key] !== null) headers[b.name] = String(args[key]);

    const bodyKeys = Object.entries(http.params).filter(([, b]) => b.in === "body");
    const fileKeys = new Set(this.fileParams(action));
    let bodyValue: unknown;
    if (http.body === "merged") {
      const o: Record<string, unknown> = {};
      for (const [key, b] of bodyKeys) if (args[key] !== undefined && !fileKeys.has(key)) o[b.name] = args[key];
      if (Object.keys(o).length) bodyValue = o;
    } else if (http.body === "nested") {
      const k = bodyKeys.find(([, b]) => b.name === "__body__")?.[0];
      if (k && args[k] !== undefined) bodyValue = args[k];
    }

    const sends = http.method !== "GET" && http.method !== "HEAD";
    const prep: Prepared = { method: http.method, url, headers };

    // Media upload (Discovery): a resumable session when a file is given, a plain metadata call otherwise.
    if (http.upload && sends) {
      const file = resolved.get(http.upload.param);
      if (file) {
        const path2 = http.upload.resumable_path ?? http.upload.simple_path;
        if (!path2) throw new ConnectorError(CONNECTOR_ERR.CONNECTOR_CONFIG, `action ${action.slug} supports upload but names no upload path`);
        const initUrl = new URL(base.origin + path2);
        for (const [k, v] of queryPairs(http, args)) initUrl.searchParams.append(k, v);
        initUrl.searchParams.set("uploadType", "resumable");
        prep.resumable = { initUrl, file };
        prep.headers["content-type"] = "application/json; charset=UTF-8";
        prep.body = JSON.stringify(bodyValue ?? {});
        return prep;
      }
    }

    if (sends && http.body_type === "multipart") {
      const parts: Parameters<typeof multipart>[0] = [];
      for (const [key, b] of bodyKeys) {
        const v = args[key];
        if (v === undefined || v === null) continue;
        const f = resolved.get(key);
        if (f) parts.push({ name: b.name, file: { bytes: f.bytes, name: f.name, mimeType: f.mimeType } });
        else parts.push({ name: b.name, value: typeof v === "object" ? JSON.stringify(v) : String(v) });
      }
      const m = multipart(parts);
      prep.body = m.body;
      prep.headers["content-type"] = m.contentType;
    } else if (sends && http.body_type === "binary") {
      const k = bodyKeys.find(([key]) => resolved.has(key))?.[0];
      const f = k ? resolved.get(k) : undefined;
      if (f) {
        prep.body = f.bytes;
        prep.headers["content-type"] = f.mimeType;
      }
    } else if (sends && bodyValue !== undefined) {
      if (http.body_type === "form" && bodyValue && typeof bodyValue === "object") {
        const form = new URLSearchParams();
        for (const [k, v] of Object.entries(bodyValue as Record<string, unknown>)) if (v !== undefined && v !== null) form.append(k, typeof v === "object" ? JSON.stringify(v) : String(v));
        prep.body = form.toString();
        prep.headers["content-type"] = "application/x-www-form-urlencoded";
      } else {
        prep.body = JSON.stringify(bodyValue);
        prep.headers["content-type"] = "application/json";
      }
    }
    return prep;
  }

  private prepareProxy(args: Record<string, unknown>, base: string): Prepared {
    const method = String(args.method ?? "GET").toUpperCase();
    const hasUrl = typeof args.url === "string" && args.url !== "";
    const hasPath = typeof args.path === "string" && args.path !== "";
    if (hasUrl === hasPath) throw new ConnectorError(CONNECTOR_ERR.BAD_REQUEST, "proxy_request needs exactly one of 'url' (absolute) or 'path' (relative to the toolkit's API base)");
    let url: URL;
    try {
      url = hasUrl ? new URL(String(args.url)) : new URL(base.replace(/\/+$/, "") + (String(args.path).startsWith("/") ? "" : "/") + String(args.path));
    } catch {
      throw new ConnectorError(CONNECTOR_ERR.BAD_REQUEST, "proxy_request: the URL could not be parsed");
    }
    if (hasPath && url.origin !== new URL(base).origin) throw new ConnectorError(CONNECTOR_ERR.HOST_NOT_ALLOWED, "proxy_request: the path changes the host of the API base");
    for (const [k, v] of Object.entries((args.query ?? {}) as Record<string, unknown>)) {
      if (Array.isArray(v)) for (const x of v) url.searchParams.append(k, String(x));
      else if (v !== undefined && v !== null) url.searchParams.append(k, String(v));
    }
    const headers: Record<string, string> = { accept: "application/json" };
    for (const [k, v] of Object.entries((args.headers ?? {}) as Record<string, unknown>)) if (typeof v === "string") headers[k] = v;
    const prep: Prepared = { method, url, headers };
    if (args.body !== undefined && method !== "GET" && method !== "HEAD") {
      prep.body = typeof args.body === "string" ? args.body : JSON.stringify(args.body);
      if (!Object.keys(headers).some((h) => h.toLowerCase() === "content-type")) prep.headers["content-type"] = typeof args.body === "string" ? "text/plain" : "application/json";
    }
    return prep;
  }

  /** One request through the account (host lock, credential, one refresh on a 401), with the retry rules. */
  private async send(account: ConnectedAccount, p: Prepared, action: Action, ctx: RunCtx, secrets: string[], download: boolean): Promise<{ res: GuardedResponse; bytes: Uint8Array }> {
    const idem = action.idempotent && IDEMPOTENT_METHODS.has(p.method);
    const maxBytes = download ? this.d.files.maxDownload() : undefined;
    const attempt = async (): Promise<{ res: GuardedResponse; bytes: Uint8Array }> => {
      ctx.markExecuted();
      if (p.resumable) return this.sendResumable(account, p, maxBytes);
      const res = await this.d.accounts.authFetch(account.id, p.url, {
        method: p.method,
        headers: p.headers,
        ...(p.body !== undefined ? { body: p.body } : {}),
        ...(maxBytes ? { maxBytes, timeoutMs: 600_000 } : {}),
      });
      return { res, bytes: await res.bytes() };
    };
    let lastErr: unknown;
    for (let n = 0; n <= (idem ? MAX_RETRIES : 0); n++) {
      try {
        const out = await attempt();
        if (idem && n < MAX_RETRIES && (out.res.status === 502 || out.res.status === 503 || out.res.status === 504)) {
          await (this.d.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms))))(200 * 2 ** n);
          continue;
        }
        return out;
      } catch (err) {
        lastErr = err;
        if (isConnectorError(err)) throw err; // host lock, account state: never retried
        if (idem && n < MAX_RETRIES && this.isPreSend(err)) {
          await (this.d.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms))))(200 * 2 ** n);
          continue;
        }
        break;
      }
    }
    throw this.transportFailure(lastErr, action, p, secrets, ctx.audit.toolkit);
  }

  private async sendResumable(account: ConnectedAccount, p: Prepared, maxBytes?: number): Promise<{ res: GuardedResponse; bytes: Uint8Array }> {
    const r = p.resumable!;
    const init = await this.d.accounts.authFetch(account.id, r.initUrl, {
      method: p.method,
      headers: { ...p.headers, "x-upload-content-type": r.file.mimeType, "x-upload-content-length": String(r.file.bytes.byteLength) },
      ...(p.body !== undefined ? { body: p.body } : {}),
    });
    const initBytes = await init.bytes();
    const session = init.headers.get("location");
    if (!init.ok || !session) return { res: init, bytes: initBytes };
    const put = await this.d.accounts.authFetch(account.id, session, {
      method: "PUT",
      headers: { "content-type": r.file.mimeType },
      body: r.file.bytes,
      timeoutMs: 600_000,
      ...(maxBytes ? { maxBytes } : {}),
    });
    return { res: put, bytes: await put.bytes() };
  }

  private isPreSend(err: unknown): boolean {
    if (err instanceof NetGuardError) return PRE_SEND_GUARD.has(err.code);
    const code = (err as NodeJS.ErrnoException | undefined)?.code ?? ((err as { cause?: NodeJS.ErrnoException } | undefined)?.cause?.code);
    return typeof code === "string" && PRE_SEND_NET.has(code);
  }

  private transportFailure(err: unknown, action: Action, p: Prepared, secrets: string[], toolkit: string): ConnectorError {
    const msg = scrubAndClip(err instanceof Error ? err.message : String(err), secrets, 200);
    if (this.isPreSend(err)) return new ConnectorError(CONNECTOR_ERR.PROVIDER_UNREACHABLE, `could not reach ${p.url.host} (nothing was sent): ${msg}`);
    const reconcile = action.reconcile ?? defaultReconcile(toolkit);
    if (!action.idempotent || !IDEMPOTENT_METHODS.has(p.method)) {
      return new ConnectorError(CONNECTOR_ERR.OUTCOME_UNKNOWN, `the request to ${p.url.host} left but no answer came back (${msg}); it may or may not have taken effect, and it was NOT retried`, { hint: reconcile });
    }
    return new ConnectorError(CONNECTOR_ERR.PROVIDER_UNAVAILABLE, `${p.url.host} did not answer after ${MAX_RETRIES + 1} attempts: ${msg}`);
  }

  /** Turn the provider's answer into data, files or a mapped error. */
  private async finish(out: { res: GuardedResponse; bytes: Uint8Array }, action: Action, runId: string, ctx: RunCtx, secrets: string[], toolkit: string): Promise<{ data: unknown; files: FileRef[]; status: number }> {
    const { res, bytes } = out;
    const headers = headersObject(res);
    const parsed = parseBody(res, bytes);
    if (parsed.kind !== "binary" && isFailureBody(res.status, parsed.value)) throw this.providerFailure(res.status, parsed.value, headers, action, ctx, secrets, toolkit);
    if (parsed.kind === "binary") {
      if (res.status < 200 || res.status >= 300) throw this.providerFailure(res.status, "binary error body", headers, action, ctx, secrets, toolkit);
      const name = (/filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(headers["content-disposition"] ?? "")?.[1] ?? `${action.slug}.bin`).trim();
      const ref = this.d.files.saveDownload(runId, bytes, { name: decodeURIComponent(name), mimeType: (headers["content-type"] ?? "application/octet-stream").split(";")[0]!.trim() });
      return { data: { file: ref }, files: [ref], status: res.status };
    }
    if (parsed.kind === "text" && typeof parsed.value === "string" && parsed.value.length > 64 * 1024) {
      const ref = this.d.files.saveDownload(runId, bytes, { name: `${action.slug}.txt`, mimeType: "text/plain" });
      return { data: { file: ref }, files: [ref], status: res.status };
    }
    return { data: parsed.value, files: [], status: res.status };
  }

  private providerFailure(status: number, body: unknown, headers: Record<string, string>, action: Action, ctx: RunCtx, secrets: string[], toolkit: string): ConnectorError {
    const m = mapFailure(status, body, headers, this.d.now());
    const message = providerMessage(body, secrets);
    if (m.code === CONNECTOR_ERR.PROVIDER_RATE_LIMITED && m.retryAfterS !== undefined && ctx.audit.account) {
      const s = Math.min(MAX_COOLDOWN_S, m.retryAfterS);
      this.cooldown.set(ctx.audit.account, this.d.now() + s * 1000);
    }
    let hint = m.hint;
    const detail: ConstructorParameters<typeof ConnectorError>[2] = {};
    if (m.code === CONNECTOR_ERR.PROVIDER_UNAUTHORIZED) {
      const acct = ctx.audit.account ? this.d.accounts.find(ctx.audit.account) : undefined;
      if (acct) detail.reconnect = reconnectCommand(acct.provider, acct.label);
      hint = `the provider rejected the credential; reconnect the account${detail.reconnect ? `: ${detail.reconnect}` : ""}`;
    } else if (m.code === CONNECTOR_ERR.PROVIDER_FORBIDDEN) {
      const acct = ctx.audit.account ? this.d.accounts.find(ctx.audit.account) : undefined;
      const missing = acct && action.scopes.length ? action.scopes.filter((s) => !acct.scopes_granted.includes(s)) : [];
      hint = missing.length === action.scopes.length && action.scopes.length ? `the account has none of the scopes this action needs (${action.scopes.slice(0, 3).join(", ")}); reconnect with them` : "the account lacks permission for this call";
    } else if (m.code === CONNECTOR_ERR.PROVIDER_UNAVAILABLE || m.code === CONNECTOR_ERR.PROVIDER_FAILED) {
      if (!action.idempotent) hint = action.reconcile ?? defaultReconcile(toolkit);
    }
    const err = new ConnectorError(m.code, `${message} (HTTP ${status})`, { ...detail, ...(hint ? { hint } : {}) });
    (err as ConnectorError & { status?: number; retryAfterS?: number }).status = status;
    if (m.retryAfterS !== undefined) (err as ConnectorError & { retryAfterS?: number }).retryAfterS = m.retryAfterS;
    return err;
  }

  // ── recipes ──────────────────────────────────────────────────────────────────────────────────

  private async runRecipeAction(
    action: Action,
    args: Record<string, unknown>,
    resolved: Map<string, ResolvedFile>,
    account: ConnectedAccount,
    provider: ProviderDef,
    base: string,
    runId: string,
    ctx: RunCtx,
    secrets: string[],
  ): Promise<{ data: unknown; files: FileRef[]; status?: number }> {
    const byRef = new Map<string, ResolvedFile>();
    for (const [param, f] of resolved) {
      const m = /^([^[]+)(?:\[(\d+)\])?$/.exec(param);
      const raw = m ? args[m[1]!] : undefined;
      const ref = Array.isArray(raw) ? raw[Number(m![2])] : raw;
      if (typeof ref === "string") byRef.set(ref, f);
    }
    const toPrepared = (req: { method: string; url: string; query: Record<string, string | string[]>; headers: Record<string, string>; json?: unknown; form?: Record<string, string> }): Prepared => {
      let url: URL;
      try {
        url = /^https?:\/\//i.test(req.url) ? new URL(req.url) : new URL(base.replace(/\/+$/, "") + (req.url.startsWith("/") ? "" : "/") + req.url);
      } catch {
        throw new ConnectorError(CONNECTOR_ERR.RECIPE_FAILED, "a recipe step has an unusable URL");
      }
      for (const [k, v] of Object.entries(req.query)) {
        if (Array.isArray(v)) for (const x of v) url.searchParams.append(k, x);
        else url.searchParams.append(k, v);
      }
      const headers: Record<string, string> = { accept: "application/json", ...req.headers };
      const p: Prepared = { method: req.method, url, headers };
      if (req.json !== undefined) {
        p.body = JSON.stringify(req.json);
        if (!Object.keys(headers).some((h) => h.toLowerCase() === "content-type")) headers["content-type"] = "application/json";
      } else if (req.form) {
        p.body = new URLSearchParams(req.form).toString();
        headers["content-type"] = "application/x-www-form-urlencoded";
      }
      return p;
    };
    const toResult = async (out: { res: GuardedResponse; bytes: Uint8Array }): Promise<HttpResult> => {
      const parsed = parseBody(out.res, out.bytes);
      return { status: out.res.status, headers: headersObject(out.res), body: parsed.kind === "binary" ? null : parsed.value };
    };
    const unauth = async (p: Prepared, init: { method: string; headers: Record<string, string>; body?: string | Uint8Array }): Promise<{ res: GuardedResponse; bytes: Uint8Array }> => {
      ctx.markExecuted();
      // A pre-signed URL: no credential, the SSRF guard only. An https URL is required (loopback excepted).
      if (p.url.protocol !== "https:" && !/^(127\.0\.0\.1|localhost|\[::1\])$/.test(p.url.hostname)) throw new ConnectorError(CONNECTOR_ERR.HOST_NOT_ALLOWED, `refusing a plain http request to ${p.url.host}`);
      const res = await guardedFetch(p.url, { method: init.method, headers: init.headers, ...(init.body !== undefined ? { body: init.body } : {}), timeoutMs: 600_000 }, this.d.network);
      return { res, bytes: await res.bytes() };
    };
    const rt: RecipeRuntime = {
      http: async (req) => {
        const p = toPrepared(req);
        try {
          if (req.auth === "none") return await toResult(await unauth(p, { method: p.method, headers: p.headers, ...(p.body !== undefined ? { body: p.body } : {}) }));
          return await toResult(await this.send(account, p, { ...action, idempotent: false }, ctx, secrets, false));
        } catch (err) {
          if (err instanceof ConnectorError) throw err;
          throw this.transportFailure(err, action, p, secrets, ctx.audit.toolkit);
        }
      },
      file: async (arg) => {
        const f = typeof arg === "string" ? byRef.get(arg) : undefined;
        if (!f) throw new ConnectorError(CONNECTOR_ERR.FILE_REFUSED, "a recipe step named a file that was not declared as a file input of the action");
        return { bytes: f.bytes, name: f.name, mimeType: f.mimeType, sha256: f.sha256 };
      },
      put: async (req) => {
        let url: URL;
        try {
          url = new URL(req.url);
        } catch {
          throw new ConnectorError(CONNECTOR_ERR.RECIPE_FAILED, "the upload session returned an unusable URL");
        }
        const p: Prepared = { method: "PUT", url, headers: req.headers, body: req.body };
        try {
          if (req.auth === "none") return await toResult(await unauth(p, { method: "PUT", headers: req.headers, body: req.body }));
          if (!hostAllowed(provider.api_hosts, url.hostname)) throw new ConnectorError(CONNECTOR_ERR.HOST_NOT_ALLOWED, `${url.hostname} is not one of ${provider.slug}'s API hosts; the credential was not sent`, { provider: provider.slug });
          ctx.markExecuted();
          const res = await this.d.accounts.authFetch(account.id, url, { method: "PUT", headers: req.headers, body: req.body, timeoutMs: 600_000 });
          return await toResult({ res, bytes: await res.bytes() });
        } catch (err) {
          if (err instanceof ConnectorError) throw err;
          throw this.transportFailure(err, { ...action, idempotent: false }, p, secrets, ctx.audit.toolkit);
        }
      },
      sleep: this.d.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms))),
    };
    try {
      const out = await runRecipe(action.steps!, args, action.result, rt);
      // A recipe may return a saved file; none does by itself, but a binary last step would have been null.
      return { data: out.value, files: [], status: 200 };
    } catch (err) {
      if (err instanceof RecipeError) {
        const info = new ConnectorError(CONNECTOR_ERR.RECIPE_FAILED, `${err.message}${err.response ? ` (HTTP ${err.response.status}: ${providerMessage(err.response.body, secrets)})` : ""}`, {
          hint: err.completed.length && !action.idempotent ? `${action.reconcile ?? defaultReconcile(action.slug)} Steps already done: ${err.completed.join(", ")}.` : action.reconcile ?? "",
        });
        (info as ConnectorError & { completed?: string[]; status?: number }).completed = err.completed;
        if (err.response) (info as ConnectorError & { status?: number }).status = err.response.status;
        throw info;
      }
      throw err;
    } finally {
      void runId;
    }
  }

  // ── errors ───────────────────────────────────────────────────────────────────────────────────

  private toError(err: unknown, ctx: RunCtx): ExecErrorInfo {
    if (isConnectorError(err)) {
      const ext = err as ConnectorError & { status?: number; retryAfterS?: number; completed?: string[] };
      const info: ExecErrorInfo = { code: err.code, message: scrubAndClip(err.message, [], 400) };
      if (err.detail.hint) info.hint = err.detail.hint;
      if (err.detail.reconnect) info.reconnect = err.detail.reconnect;
      if (ext.retryAfterS !== undefined) info.retry_after_s = ext.retryAfterS;
      if (ext.status !== undefined) info.status = ext.status;
      if (ext.completed) info.completed = ext.completed;
      if (err.code === CONNECTOR_ERR.OUTCOME_UNKNOWN && err.detail.hint) info.reconcile = err.detail.hint;
      if (err.code === CONNECTOR_ERR.PROVIDER_RATE_LIMITED && info.retry_after_s === undefined && ctx.audit.account) info.retry_after_s = this.cooldownLeft(ctx.audit.account);
      return info;
    }
    return { code: CONNECTOR_ERR.PROVIDER_FAILED, message: scrubAndClip(err instanceof Error ? err.message : String(err), [], 300) };
  }
}

interface RunCtx {
  stages: Stage[];
  audit: AuditFields;
  cleanup: (() => void)[];
  markExecuted: () => void;
  info: { scope?: Scope; tool?: string };
}
