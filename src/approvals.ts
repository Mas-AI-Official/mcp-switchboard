/**
 * Out-of-band approvals (design vNext 3.3). They replace the in-band TTY gate (approval.ts), which was unbound
 * to arguments, never expired and could not work while stdio carried the protocol.
 *
 * THE MODEL
 *   A gated call does not wait for a keystroke. It creates (or reuses) a PENDING record bound to
 *   (principal, server, tool, sha256 of the canonical arguments), and the caller is told to ask the owner.
 *   The owner decides through the dashboard or `switchboard approvals approve <id>`; both end in this module.
 *   The caller then repeats the IDENTICAL call, which consumes the approval exactly once.
 *
 * WHO MAY APPROVE: THE GATEWAY, AFTER ITS OWN PRESENCE CHECK
 *   `<SWITCHBOARD_HOME>/approvals.json` can be written by any process of the same OS user, an AI agent included,
 *   so a record found there proves nothing. This module therefore holds a random 32-byte HMAC key IN MEMORY ONLY
 *   (new on every start). Every record the gateway writes carries an HMAC over the whole record (a superset of
 *   id, principal, server, tool, args_sha256, expires and status), and a record counts only when that HMAC
 *   verifies under the live key. `approve()` signs the "approved" state only after `verifyOwnerPresence` (Windows
 *   Hello, or a challenge on the gateway's own console) succeeded INSIDE this process. A record written or edited
 *   by anyone else, or left by an earlier run, fails the check, is ignored for matching and listing, and is logged.
 *
 *   Two more properties the HMAC alone does not give:
 *   - SINGLE USE across a file rollback. Consuming is a locked read-modify-write, and the ids this process has
 *     consumed are also kept in memory, so restoring an older copy of the file (an "approved" record that was
 *     already used) cannot approve a second call.
 *   - WHAT THE OWNER SEES IS WHAT IS BOUND. The preview shown in the presence prompt is part of the signed
 *     record, so an edited preview fails the check like any other edit.
 *
 * ARGUMENTS HASH. `argsSha256` is the SHA-256 of the canonical JSON (sorted keys at every depth, no whitespace)
 * of the arguments exactly as the client sent them: after the client's own call is parsed, BEFORE the gateway
 * injects any secret (`inject_args`) or reverses a rename. A hash taken after injection would put a vault secret
 * into a value that is stored and could be guessed against.
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { join } from "node:path";
import { WatchedJsonFile } from "./atomicfile.js";
import { audit, canonicalJson, sanitizeForAudit, type AuditInput } from "./audit.js";
import { log } from "./logger.js";
import { randomChallenge, verifyOwnerPresence, type PresenceResult } from "./presence.js";
import type { Risk, Scope } from "./types.js";
import { HOME_DIR } from "./vault.js";

// ── constants ────────────────────────────────────────────────────────────────────────────────────

export type ApprovalStatus = "pending" | "approved" | "denied" | "consumed" | "expired";
const STATUSES: ReadonlySet<string> = new Set(["pending", "approved", "denied", "consumed", "expired"]);

/** A record lives this long (pending, then approved) unless `gateway.approval.ttl_seconds` says otherwise. */
export const DEFAULT_TTL_SECONDS = 900;
export const MIN_TTL_SECONDS = 60;
export const MAX_TTL_SECONDS = 86400;
/** Longest a gated call may wait for a decision before it returns SB_APPROVAL_PENDING. */
export const MAX_WAIT_SECONDS = 50;
/** One caller may have this many undecided requests; a flood of distinct arguments is refused, not queued. */
export const MAX_PENDING_PER_PRINCIPAL = 16;
export const MAX_PENDING_TOTAL = 64;
/** Finished records kept for the dashboard history (the audit log is the durable record). */
export const MAX_HISTORY = 200;
/** The dashboard shows this many finished records. */
export const HISTORY_SHOWN = 50;

/** `ap_` plus 8 characters from a 32 symbol alphabet without look-alikes (no I, O, 0, 1). */
export const APPROVAL_ID_RE = /^ap_[A-HJ-NP-Z2-9]{8}$/;
const ID_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/** The principal recorded for a call that has none (the owner's playground, a trigger poll). */
export const INTERNAL_PRINCIPAL = "internal";

export const APPROVALS_FILE = "approvals.json";

// ── records ──────────────────────────────────────────────────────────────────────────────────────

/** One approval request and its life. `mac` and `instance` are internal and never leave the process. */
export interface ApprovalRecord {
  id: string;
  /** `<via>:<id>` of the caller (principal.ts), or "internal". Part of the match. */
  principal: string;
  client: string | null;
  server: string;
  tool: string;
  /** SHA-256 hex of the canonical JSON of the arguments the client sent. Part of the match. */
  args_sha256: string;
  /** Redacted, size-capped copy of the arguments, for the owner to read. */
  args_preview: unknown;
  scope: Scope;
  risk: Risk;
  reason: string;
  created: string;
  expires: string;
  status: ApprovalStatus;
  /** "dashboard", "cli" or "env-auto"; null while undecided. */
  decided_via: string | null;
  decided_at: string | null;
  /** The presence method that backed the decision ("hello", "tty", "none"); absent for env-auto. */
  presence?: string;
  consumed_at?: string;
  /** Which gateway run wrote the record (random per start). Tells "earlier run" from "forged" in the log. */
  instance: string;
  /** HMAC-SHA256 hex over the record without this field, under the in-memory key. */
  mac: string;
}

/** A record as the dashboard, the CLI and the control API see it. */
export type ApprovalView = Omit<ApprovalRecord, "mac" | "instance">;

export interface ApprovalRequest {
  principal: string;
  client: string | null;
  server: string;
  tool: string;
  /** The arguments as the client sent them (hashed and previewed, never stored whole). */
  args: unknown;
  scope: Scope;
  risk: Risk;
  /** Why approval is needed (the policy reason). */
  reason: string;
}

export type ApprovalGate =
  | { kind: "approved"; record: ApprovalView; via: string }
  | { kind: "pending"; record: ApprovalView; created: boolean };

export type ApprovalChannel = "dashboard" | "cli";

export type ApprovalOutcome =
  | { ok: true; record: ApprovalView }
  | { ok: false; status: 400 | 403 | 404 | 409 | 500; code: string; error: string; record?: ApprovalView };

/** Asks the owner to prove they are present. The default is `verifyOwnerPresence`; tests inject their own. */
export type PresenceProvider = (message: string, ttyChallenge: string) => Promise<PresenceResult>;

/** Too many undecided requests: a flood of distinct arguments is refused instead of queued. */
export class ApprovalLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ApprovalLimitError";
  }
}

// ── pure helpers ─────────────────────────────────────────────────────────────────────────────────

const sha256hex = (s: string): string => createHash("sha256").update(s, "utf8").digest("hex");

/** SHA-256 of the canonical JSON of the arguments (sorted keys at every depth, no whitespace). */
export function argsSha256(args: unknown): string {
  return sha256hex(canonicalJson(args ?? {}));
}

const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g;

function oneLine(s: string): string {
  return s.replace(CONTROL_CHARS, " ").replace(/\s+/g, " ").trim();
}

function cap(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, Math.max(0, max - 3))}...` : s;
}

/**
 * One line that tells the owner what the call would do: `key=value` pairs of the top-level arguments (values as
 * JSON), control characters flattened, cut to `max` characters. Names and values come from a client, so nothing
 * here can start a second line in a terminal or a dialog.
 */
export function summarizeArgs(preview: unknown, max = 120): string {
  let text: string;
  try {
    if (preview === undefined || preview === null) text = "(no arguments)";
    else if (typeof preview === "object" && !Array.isArray(preview)) {
      const entries = Object.entries(preview as Record<string, unknown>);
      text = entries.length === 0 ? "(no arguments)" : entries.map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(", ");
    } else text = JSON.stringify(preview) ?? "(no arguments)";
  } catch {
    text = "(arguments cannot be shown)";
  }
  return cap(oneLine(text), max);
}

/**
 * The text of the presence prompt: `Approve <tool> on <server> for <client>: <one-line argument summary>`. The
 * summary is at most 120 characters and is shortened further so the whole message stays within the 200
 * characters the presence prompt keeps (presence.ts), because a cut in the middle of the summary is the one place
 * the owner could be misled by what they did not see.
 */
export function presenceMessage(r: Pick<ApprovalRecord, "tool" | "server" | "client" | "principal" | "args_preview">): string {
  const prefix = `Approve ${cap(oneLine(r.tool), 48)} on ${cap(oneLine(r.server), 32)} for ${cap(oneLine(r.client ?? r.principal), 32)}: `;
  const room = Math.max(20, Math.min(120, 200 - prefix.length));
  return prefix + summarizeArgs(r.args_preview, room);
}

const view = (r: ApprovalRecord): ApprovalView => {
  const { mac: _mac, instance: _instance, ...rest } = r;
  void _mac;
  void _instance;
  return JSON.parse(JSON.stringify(rest)) as ApprovalView;
};

function isShape(v: unknown): v is ApprovalRecord {
  if (!v || typeof v !== "object" || Array.isArray(v)) return false;
  const r = v as Record<string, unknown>;
  const str = (x: unknown): x is string => typeof x === "string";
  return (
    str(r.id) && APPROVAL_ID_RE.test(r.id) &&
    str(r.principal) && str(r.server) && str(r.tool) &&
    str(r.args_sha256) && /^[0-9a-f]{64}$/.test(r.args_sha256) &&
    (r.client === null || str(r.client)) &&
    (r.scope === "read" || r.scope === "write" || r.scope === "full") &&
    (r.risk === "low" || r.risk === "medium" || r.risk === "high") &&
    str(r.reason) &&
    str(r.created) && Number.isFinite(Date.parse(r.created)) &&
    str(r.expires) && Number.isFinite(Date.parse(r.expires)) &&
    str(r.status) && STATUSES.has(r.status) &&
    (r.decided_via === null || str(r.decided_via)) &&
    (r.decided_at === null || str(r.decided_at)) &&
    str(r.instance) &&
    str(r.mac)
  );
}

interface StoreFile {
  version: 1;
  approvals: unknown[];
}

const emptyStore = (): StoreFile => ({ version: 1, approvals: [] });

const validateStore = (v: unknown): string | null =>
  v && typeof v === "object" && !Array.isArray(v) && Array.isArray((v as { approvals?: unknown }).approvals)
    ? null
    : "expected an object with an 'approvals' array";

const sameTuple = (r: ApprovalRecord, q: { principal: string; server: string; tool: string; hash: string }): boolean =>
  r.principal === q.principal && r.server === q.server && r.tool === q.tool && r.args_sha256 === q.hash;

// ── the manager ──────────────────────────────────────────────────────────────────────────────────

export interface ApprovalsOptions {
  /** The store file. Default `<SWITCHBOARD_HOME>/approvals.json`. */
  path?: string;
  /** Wall clock in ms; injectable so the oracle can prove expiry without sleeping. */
  clock?: () => number;
  /** How presence is proved. Default: `verifyOwnerPresence` (see `defaultPresence`). */
  presence?: PresenceProvider;
  /** Audit sink. Default: the process-wide audit log. It must never throw; a failure costs the row, not the call. */
  audit?: (entry: AuditInput) => void;
}

type EventKind = "approval_required" | "approved" | "denied" | "expired" | "consumed";
interface PendingEvent {
  kind: EventKind;
  record: ApprovalRecord;
  /** Who did it: the owner channel for a decision, else the record's own caller. */
  by?: string;
  note?: string;
}

export class Approvals {
  /** The HMAC key. In memory only and new on every start, so no record outlives a restart. */
  private readonly key = randomBytes(32);
  /** Tells this run's records from an earlier run's in the log. */
  readonly instance = randomBytes(8).toString("hex");
  private readonly path: string;
  private readonly now: () => number;
  private readonly presenceProvider: PresenceProvider;
  private readonly sink: (entry: AuditInput) => void;
  private storeFile: WatchedJsonFile<StoreFile> | undefined;
  /** id -> expiry (ms) of every approval this process consumed: the replay guard against a restored file. */
  private readonly consumed = new Map<string, number>();
  private readonly ignoredSeen = new Set<string>();
  private presenceChain: Promise<unknown> = Promise.resolve();
  private stdioActive = false;
  /** The records that last passed the check, keyed by the parsed file object so an unchanged file costs nothing. */
  private checked: { raw: StoreFile; trusted: ApprovalRecord[] } | undefined;

  constructor(opts: ApprovalsOptions = {}) {
    this.path = opts.path ?? join(HOME_DIR, APPROVALS_FILE);
    this.now = opts.clock ?? Date.now;
    this.presenceProvider = opts.presence ?? defaultPresence(() => this.stdioActive);
    this.sink = opts.audit ?? ((entry) => audit(entry));
    if (autoApproveOn()) {
      log.warn("SWITCHBOARD_AUTO_APPROVE=1: every gated call is approved with no human decision (recorded as decided_via env-auto). For test harnesses only.");
    }
    if (process.env.SWITCHBOARD_INSECURE_APPROVAL === "1") {
      log.warn("SWITCHBOARD_INSECURE_APPROVAL=1: owner presence checks are switched off, so anyone who can reach the approval API can approve. For test harnesses only.");
    }
  }

  get filePath(): string {
    return this.path;
  }

  /** True while the stdio transport owns stdin/stdout: the gateway's own terminal can then not be used for a challenge. */
  setStdioActive(active: boolean): void {
    this.stdioActive = active;
  }

  // ── store access ───────────────────────────────────────────────────────────────────────────────

  /** Opened on first use so a damaged approvals.json fails the call that needs it, not the gateway's start. */
  private get store(): WatchedJsonFile<StoreFile> {
    return (this.storeFile ??= new WatchedJsonFile<StoreFile>(this.path, emptyStore, { validate: validateStore }));
  }

  private macFor(r: ApprovalRecord): string {
    const { mac: _mac, ...rest } = r;
    void _mac;
    return createHmac("sha256", this.key).update(canonicalJson(rest), "utf8").digest("hex");
  }

  private sign(r: ApprovalRecord): ApprovalRecord {
    r.mac = this.macFor(r);
    return r;
  }

  private macOk(r: ApprovalRecord): boolean {
    if (!/^[0-9a-f]{64}$/.test(r.mac)) return false;
    return timingSafeEqual(Buffer.from(r.mac, "hex"), Buffer.from(this.macFor(r), "hex"));
  }

  /** ok: signed by this run. earlier: signed by a run that is gone (or by nobody). forged: claims this run, fails. */
  private classify(item: unknown): "ok" | "earlier" | "forged" {
    if (!isShape(item)) return "forged";
    if (this.macOk(item)) return "ok";
    return item.instance === this.instance ? "forged" : "earlier";
  }

  /** Keep what this run signed; log (once per record) what it did not. Never throws. */
  private inspect(raw: unknown[]): ApprovalRecord[] {
    const trusted: ApprovalRecord[] = [];
    let earlier = 0;
    const forged: string[] = [];
    for (const item of raw) {
      const verdict = this.classify(item);
      if (verdict === "ok") {
        trusted.push(item as ApprovalRecord);
        continue;
      }
      let fp: string;
      try {
        fp = sha256hex(canonicalJson(item)).slice(0, 24);
      } catch {
        fp = "unprintable";
      }
      if (this.ignoredSeen.has(fp)) continue;
      if (this.ignoredSeen.size > 2000) this.ignoredSeen.clear();
      this.ignoredSeen.add(fp);
      if (verdict === "earlier") earlier++;
      else forged.push(isShape(item) ? item.id : "(malformed record)");
    }
    if (earlier > 0) {
      const note = `ignored ${earlier} approval record(s) written by an earlier gateway run (their HMAC key is gone, so none of them can approve anything)`;
      log.info(note);
      this.emitIgnored(note);
    }
    for (const id of forged) {
      const note = `ignored approval record ${id}: it does not carry a valid HMAC from this gateway run (forged, edited or damaged)`;
      log.warn(note);
      this.emitIgnored(note);
    }
    return trusted;
  }

  private emitIgnored(note: string): void {
    this.safeSink({ server: "switchboard", tool: "approval.ignored", scope: "full", decision: "deny", reason: note, principal: "gateway" });
  }

  /** The signed records, re-read when the file changed. */
  private trustedRecords(): ApprovalRecord[] {
    const raw = this.store.get();
    if (this.checked?.raw !== raw) this.checked = { raw, trusted: this.inspect(raw.approvals) };
    return this.checked.trusted;
  }

  private safeSink(entry: AuditInput): void {
    try {
      this.sink(entry);
    } catch (err) {
      log.error(`audit write failed for ${entry.tool}: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  private flush(events: PendingEvent[]): void {
    for (const e of events) {
      const r = e.record;
      const call = `${r.server}__${r.tool}`;
      const caller = `${r.principal}${r.client ? ` (client ${r.client})` : ""}`;
      const base = { server: "switchboard", tool: `approval.${e.kind}`, scope: r.scope, risk: r.risk, approval_id: r.id } as const;
      switch (e.kind) {
        case "approval_required":
          this.safeSink({
            ...base, decision: "approval_required", principal: r.principal, ...(r.client ? { client: r.client } : {}),
            reason: `approval_required: ${call} for ${caller}, ${r.risk} risk, args ${r.args_sha256.slice(0, 12)}, expires ${r.expires}. ${e.note ?? r.reason}`,
          });
          break;
        case "approved":
          this.safeSink({
            ...base, decision: "allow", principal: `owner:${e.by ?? "unknown"}`,
            reason: `approved: ${r.id} ${call} for ${caller}, args ${r.args_sha256.slice(0, 12)}, decided_via ${r.decided_via}${r.presence ? ` (presence ${r.presence})` : ""}`,
          });
          break;
        case "denied":
          this.safeSink({
            ...base, decision: "deny", principal: `owner:${e.by ?? "unknown"}`, error_code: "SB_APPROVAL_DENIED",
            reason: `denied: ${r.id} ${call} for ${caller}, decided_via ${r.decided_via}`,
          });
          break;
        case "expired":
          this.safeSink({
            ...base, decision: "deny", principal: "gateway", error_code: "SB_APPROVAL_DENIED",
            reason: `expired: ${r.id} ${call} for ${caller}, ${e.note ?? "not used before it expired"}`,
          });
          break;
        case "consumed":
          this.safeSink({
            ...base, decision: "allow", principal: r.principal, ...(r.client ? { client: r.client } : {}),
            reason: `consumed: ${r.id} ${call} for ${caller}, decided_via ${r.decided_via}`,
          });
          break;
      }
    }
  }

  /** Mark undecided or unused records past their expiry. Pure on the array; the caller writes and audits. */
  private expireStale(recs: ApprovalRecord[], now: number, events: PendingEvent[]): boolean {
    let changed = false;
    for (const r of recs) {
      if ((r.status === "pending" || r.status === "approved") && Date.parse(r.expires) <= now) {
        const was = r.status;
        r.status = "expired";
        this.sign(r);
        events.push({ kind: "expired", record: r, note: was === "pending" ? "nobody decided in time" : "approved but not used in time" });
        changed = true;
      }
    }
    return changed;
  }

  /** Live records stay; finished ones are cut to the newest MAX_HISTORY. */
  private prune(recs: ApprovalRecord[]): ApprovalRecord[] {
    const done = recs.filter((r) => r.status !== "pending" && r.status !== "approved");
    if (done.length <= MAX_HISTORY) return recs;
    const stamp = (r: ApprovalRecord): number => Date.parse(r.decided_at ?? r.created) || 0;
    const keep = new Set(done.sort((a, b) => stamp(b) - stamp(a)).slice(0, MAX_HISTORY).map((r) => r.id));
    return recs.filter((r) => r.status === "pending" || r.status === "approved" || keep.has(r.id));
  }

  /**
   * Run a read-modify-write on the store under its cross-process lock. `mutate` gets this run's signed records
   * (anything else is dropped on the way, after being logged) and returns whether it changed them.
   */
  private transact(mutate: (recs: ApprovalRecord[], now: number, events: PendingEvent[]) => boolean): PendingEvent[] {
    const events: PendingEvent[] = [];
    const now = this.now();
    this.store.update((cur) => {
      const trusted = this.inspect(cur.approvals);
      const dropped = trusted.length !== cur.approvals.length;
      const recs = trusted.map((r) => ({ ...r }));
      const expired = this.expireStale(recs, now, events);
      const changed = mutate(recs, now, events);
      if (!dropped && !expired && !changed) return undefined; // nothing to write
      return { version: 1, approvals: this.prune(recs) };
    });
    this.checked = undefined;
    for (const [id, until] of this.consumed) if (until < now - 86_400_000) this.consumed.delete(id);
    this.flush(events);
    return events;
  }

  // ── the call path ──────────────────────────────────────────────────────────────────────────────

  /**
   * A gated call arrives. Consume a matching approved record if there is one (`approved`); otherwise reuse
   * the pending record for the same call or create it (`pending`, `created` says which). Synchronous, so two
   * identical concurrent calls cannot both consume one approval.
   *
   * Throws `ApprovalLimitError` when the caller already has too many undecided requests, and
   * `StoreCorruptError` (or an fs error) when the store cannot be used: the caller must fail closed.
   */
  request(req: ApprovalRequest, ttlSeconds: number = DEFAULT_TTL_SECONDS): ApprovalGate {
    const ttl = Math.min(MAX_TTL_SECONDS, Math.max(MIN_TTL_SECONDS, Math.floor(ttlSeconds)));
    const hash = argsSha256(req.args);
    const q = { principal: req.principal, server: req.server, tool: req.tool, hash };
    if (autoApproveOn()) return this.autoApproved(req, hash, ttl);

    let gate: ApprovalGate | undefined;
    let consumedNow: ApprovalRecord | undefined;
    this.transact((recs, now, events) => {
      const usable = (r: ApprovalRecord): boolean => Date.parse(r.expires) > now;
      const approved = recs.find((r) => r.status === "approved" && sameTuple(r, q) && usable(r) && !this.consumed.has(r.id));
      if (approved) {
        approved.status = "consumed";
        approved.consumed_at = new Date(now).toISOString();
        this.sign(approved);
        events.push({ kind: "consumed", record: approved });
        consumedNow = approved;
        gate = { kind: "approved", record: view(approved), via: approved.decided_via ?? "unknown" };
        return true;
      }
      const pending = recs.find((r) => r.status === "pending" && sameTuple(r, q) && usable(r));
      if (pending) {
        gate = { kind: "pending", record: view(pending), created: false };
        return false;
      }
      const mine = recs.filter((r) => r.status === "pending" && r.principal === req.principal).length;
      const all = recs.filter((r) => r.status === "pending").length;
      if (mine >= MAX_PENDING_PER_PRINCIPAL || all >= MAX_PENDING_TOTAL) {
        throw new ApprovalLimitError(
          mine >= MAX_PENDING_PER_PRINCIPAL
            ? `${mine} approvals from ${req.principal} are already waiting for the owner (limit ${MAX_PENDING_PER_PRINCIPAL}); decide or let some expire first`
            : `${all} approvals are already waiting for the owner (limit ${MAX_PENDING_TOTAL}); decide or let some expire first`,
        );
      }
      const created = this.sign({
        id: newId(new Set(recs.map((r) => r.id))),
        principal: req.principal,
        client: req.client,
        server: req.server,
        tool: req.tool,
        args_sha256: hash,
        args_preview: sanitizeForAudit(req.args ?? {}),
        scope: req.scope,
        risk: req.risk,
        reason: req.reason,
        created: new Date(now).toISOString(),
        expires: new Date(now + ttl * 1000).toISOString(),
        status: "pending",
        decided_via: null,
        decided_at: null,
        instance: this.instance,
        mac: "",
      });
      recs.push(created);
      events.push({ kind: "approval_required", record: created, note: req.reason });
      gate = { kind: "pending", record: view(created), created: true };
      return true;
    });
    // The id is remembered only after the write succeeded: a failed write leaves the approval usable.
    if (consumedNow) this.consumed.set((consumedNow as ApprovalRecord).id, Date.parse((consumedNow as ApprovalRecord).expires));
    return gate!;
  }

  /** SWITCHBOARD_AUTO_APPROVE=1: approved with no human, recorded as such. A harness switch, announced at start. */
  private autoApproved(req: ApprovalRequest, hash: string, ttl: number): ApprovalGate {
    const now = this.now();
    let rec!: ApprovalRecord;
    const events: PendingEvent[] = [];
    this.transact((recs) => {
      rec = this.sign({
        id: newId(new Set(recs.map((r) => r.id))),
        principal: req.principal,
        client: req.client,
        server: req.server,
        tool: req.tool,
        args_sha256: hash,
        args_preview: sanitizeForAudit(req.args ?? {}),
        scope: req.scope,
        risk: req.risk,
        reason: req.reason,
        created: new Date(now).toISOString(),
        expires: new Date(now + ttl * 1000).toISOString(),
        status: "consumed",
        decided_via: "env-auto",
        decided_at: new Date(now).toISOString(),
        consumed_at: new Date(now).toISOString(),
        instance: this.instance,
        mac: "",
      });
      recs.push(rec);
      events.push({ kind: "approved", record: rec, by: "env-auto" }, { kind: "consumed", record: rec });
      return true;
    });
    this.flush(events);
    return { kind: "approved", record: view(rec), via: "env-auto" };
  }

  /**
   * Wait up to `ms` for the record to leave `pending`, polling the store (decisions are written by this process,
   * but the store, not a callback, is the truth). Resolves with the record as it then is, or the still-pending
   * record at the deadline; undefined if the record vanished.
   */
  async waitForDecision(id: string, ms: number): Promise<ApprovalView | undefined> {
    const deadline = Date.now() + Math.min(Math.max(0, ms), MAX_WAIT_SECONDS * 1000);
    for (;;) {
      this.sweep();
      const r = this.trustedRecords().find((x) => x.id === id);
      if (!r) return undefined;
      if (r.status !== "pending") return view(r);
      if (Date.now() >= deadline) return view(r);
      await new Promise((resolve) => setTimeout(resolve, Math.min(100, Math.max(1, deadline - Date.now()))));
    }
  }

  // ── reading ────────────────────────────────────────────────────────────────────────────────────

  /** Expire what is past its time (and audit it). Safe to call often: it writes only when something expired. */
  sweep(): number {
    const now = this.now();
    if (!this.trustedRecords().some((r) => (r.status === "pending" || r.status === "approved") && Date.parse(r.expires) <= now)) return 0;
    return this.transact(() => false).filter((e) => e.kind === "expired").length;
  }

  get(id: string): ApprovalView | undefined {
    this.sweep();
    const r = this.trustedRecords().find((x) => x.id === id);
    return r ? view(r) : undefined;
  }

  /** Undecided requests (oldest first) and the newest finished ones (newest first, at most HISTORY_SHOWN). */
  list(): { pending: ApprovalView[]; approved: ApprovalView[]; history: ApprovalView[] } {
    this.sweep();
    const recs = this.trustedRecords();
    const stamp = (r: ApprovalRecord): number => Date.parse(r.decided_at ?? r.created) || 0;
    return {
      pending: recs.filter((r) => r.status === "pending").sort((a, b) => Date.parse(a.created) - Date.parse(b.created)).map(view),
      approved: recs.filter((r) => r.status === "approved").sort((a, b) => stamp(b) - stamp(a)).map(view),
      history: recs
        .filter((r) => r.status !== "pending" && r.status !== "approved")
        .sort((a, b) => stamp(b) - stamp(a))
        .slice(0, HISTORY_SHOWN)
        .map(view),
    };
  }

  // ── deciding ───────────────────────────────────────────────────────────────────────────────────

  /**
   * Prove the owner is present, one prompt at a time (two Hello dialogs at once would be indistinguishable).
   * Also used for other owner-only changes, such as turning the kill switch off.
   */
  verifyPresence(message: string): Promise<PresenceResult> {
    const challenge = randomChallenge(4);
    const run: Promise<PresenceResult> = this.presenceChain.then(
      () => this.presenceProvider(message, challenge),
      () => this.presenceProvider(message, challenge),
    ).catch((err: unknown) => ({ ok: false as const, method: "none" as const, reason: err instanceof Error ? err.message : String(err) }));
    this.presenceChain = run.catch(() => undefined);
    return run;
  }

  /**
   * Approve a pending request. The gateway asks for owner presence with the exact action, and only on success
   * signs the "approved" state. Called by the dashboard route and by the control API (the CLI); neither can
   * skip the check, and neither is trusted to have done it.
   */
  async approve(id: string, via: ApprovalChannel): Promise<ApprovalOutcome> {
    if (!APPROVAL_ID_RE.test(id)) return { ok: false, status: 400, code: "SB_BAD_REQUEST", error: "not an approval id" };
    let rec: ApprovalRecord | undefined;
    try {
      this.sweep();
      rec = this.trustedRecords().find((r) => r.id === id);
    } catch (err) {
      return storeFailure(err);
    }
    if (!rec) return { ok: false, status: 404, code: "SB_APPROVAL_UNKNOWN", error: `no approval '${id}' (it may have expired or belong to an earlier gateway run)` };
    if (rec.status !== "pending") {
      return { ok: false, status: 409, code: "SB_APPROVAL_STATE", error: `approval ${id} is already ${rec.status}`, record: view(rec) };
    }

    const message = presenceMessage(rec);
    const presence = await this.verifyPresence(message);
    if (!presence.ok) {
      this.safeSink({
        server: "switchboard", tool: "approval.presence_failed", scope: rec.scope, risk: rec.risk, approval_id: id, decision: "deny",
        principal: `owner:${via}`, reason: `presence check failed (${presence.method}) for ${id}: ${presence.reason}`,
      });
      return { ok: false, status: 403, code: "SB_PRESENCE_FAILED", error: presenceFailure(presence) };
    }

    // The prompt can take minutes: the record may have been denied, used up or expired meanwhile.
    let done: ApprovalRecord | undefined;
    let refused: ApprovalOutcome | undefined;
    try {
      this.transact((recs, now, events) => {
        const cur = recs.find((r) => r.id === id);
        if (!cur) {
          refused = { ok: false, status: 404, code: "SB_APPROVAL_UNKNOWN", error: `approval ${id} is gone` };
          return false;
        }
        if (cur.status !== "pending") {
          refused = { ok: false, status: 409, code: "SB_APPROVAL_STATE", error: `approval ${id} became ${cur.status} while the presence prompt was open`, record: view(cur) };
          return false;
        }
        cur.status = "approved";
        cur.decided_via = via;
        cur.decided_at = new Date(now).toISOString();
        cur.presence = presence.method;
        this.sign(cur);
        events.push({ kind: "approved", record: cur, by: via });
        done = cur;
        return true;
      });
    } catch (err) {
      return storeFailure(err);
    }
    return refused ?? { ok: true, record: view(done!) };
  }

  /** Deny (or withdraw) a pending or approved-but-unused request. Declining needs no presence check. */
  deny(id: string, via: ApprovalChannel): ApprovalOutcome {
    if (!APPROVAL_ID_RE.test(id)) return { ok: false, status: 400, code: "SB_BAD_REQUEST", error: "not an approval id" };
    let done: ApprovalRecord | undefined;
    let refused: ApprovalOutcome | undefined;
    try {
      this.transact((recs, now, events) => {
        const cur = recs.find((r) => r.id === id);
        if (!cur) {
          refused = { ok: false, status: 404, code: "SB_APPROVAL_UNKNOWN", error: `no approval '${id}' (it may have expired or belong to an earlier gateway run)` };
          return false;
        }
        if (cur.status !== "pending" && cur.status !== "approved") {
          refused = { ok: false, status: 409, code: "SB_APPROVAL_STATE", error: `approval ${id} is already ${cur.status}`, record: view(cur) };
          return false;
        }
        cur.status = "denied";
        cur.decided_via = via;
        cur.decided_at = new Date(now).toISOString();
        this.sign(cur);
        events.push({ kind: "denied", record: cur, by: via });
        done = cur;
        return true;
      });
    } catch (err) {
      return storeFailure(err);
    }
    return refused ?? { ok: true, record: view(done!) };
  }
}

// ── small pieces ─────────────────────────────────────────────────────────────────────────────────

function autoApproveOn(): boolean {
  return process.env.SWITCHBOARD_AUTO_APPROVE === "1";
}

function newId(taken: Set<string>): string {
  for (;;) {
    const id = `ap_${Array.from(randomBytes(8), (b) => ID_ALPHABET[b & 31]).join("")}`;
    if (!taken.has(id)) return id;
  }
}

function storeFailure(err: unknown): ApprovalOutcome {
  return { ok: false, status: 500, code: "SB_APPROVAL_STORE", error: `the approval store cannot be used: ${err instanceof Error ? err.message : String(err)}` };
}

/** A presence refusal in words an owner can act on. */
function presenceFailure(p: Extract<PresenceResult, { ok: false }>): string {
  const base = `owner presence was not verified (${p.method}): ${p.reason}`;
  if (p.method === "tty" || p.method === "hello") {
    return `${base}. Approving needs Windows Hello, or an interactive terminal attached to the gateway process; neither answered. Start the gateway in a terminal (switchboard dashboard) or enable Windows Hello.`;
  }
  return base;
}

/**
 * The presence provider of a real gateway. Windows Hello where it exists, else a challenge typed at the gateway's
 * own terminal. While the stdio transport owns stdin and stdout the terminal is unusable, so only Hello counts.
 * `none` exists for test harnesses and only with SWITCHBOARD_INSECURE_APPROVAL=1 (presence.ts refuses it otherwise).
 */
export function defaultPresence(stdioActive: () => boolean): PresenceProvider {
  return (message, challenge) => {
    const method = process.env.SWITCHBOARD_INSECURE_APPROVAL === "1" ? "none" : stdioActive() ? "hello" : "auto";
    return verifyOwnerPresence(method, message, challenge);
  };
}
