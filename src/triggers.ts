/**
 * Poll-first triggers.
 *
 * A trigger periodically calls a (normally read-scoped) tool and fires when the result
 * changes. It is the LOCAL-FIRST answer to a provider webhook: the poll is an OUTBOUND call,
 * so Switchboard never needs an inbound port, a public tunnel, or a provider that supports
 * push — it works behind NAT, on a laptop, fully offline-capable except for the upstream it
 * polls. (Inbound webhooks — `settings.webhook` — go the other way: Switchboard POSTs OUT to
 * the operator. Triggers are how Switchboard learns that something CHANGED upstream.)
 *
 * Two governed actions per trigger, kept deliberately distinct:
 *   1. THE POLL is a real `router.callTool(...)`, so it runs the full policy → approval →
 *      audit path exactly like any agent call. A denied/over-scope poll is denied + audited
 *      as `allow`/`deny` like everything else — triggers get NO special access.
 *   2. THE FIRE (the result changed) is an OBSERVATION, never a governance decision. It is
 *      recorded to a local fired-event log and, when `settings.webhook` is enabled, delivered
 *      as a distinct `type:"switchboard.trigger"` event (`deliverTriggerWebhook`). It must
 *      NEVER become an `AuditEntry.decision`, or it would inflate the allow/deny/approval
 *      accounting in `audit.usageStats()`.
 *
 * Change detection, per definition:
 *   - ITEM-LEVEL when `item_path` resolves to an array in the tool's JSON result AND `item_key`
 *     names a unique field on its elements: the set of new keys fires (the natural "new issue /
 *     new row / new email" semantic). `seen` tracks the last poll's key snapshot.
 *   - WHOLE-RESPONSE HASH otherwise: a SHA-256 of the response text; any change fires once.
 *
 * The FIRST poll of a trigger only establishes a baseline (seeds `seen` / `last_hash`) and
 * fires nothing — so enabling a trigger never floods on the pre-existing backlog.
 *
 * Seen-state persists to `~/.switchboard/triggers-state.json` (honoring `SWITCHBOARD_HOME`) so
 * a restart resumes from the last baseline instead of re-firing the whole list.
 */

import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { Router } from "./router.js";
import type { SwitchboardConfig, TriggerDefinition } from "./types.js";
import { deliverTriggerWebhook, type SecretResolver, type TriggerWebhookEvent } from "./webhook.js";
import { HOME_DIR } from "./vault.js";
import { log } from "./logger.js";

const STATE_PATH = join(HOME_DIR, "triggers-state.json");
/** Cap on the global fired-event ring kept on disk + shown in the dashboard. */
const FIRES_CAP = 200;
/** Max new-item keys carried in a fire's sample (human triage only). */
const SAMPLE_CAP = 10;
const DEFAULT_INTERVAL_SECONDS = 60;

/** Persisted change-detection state for one trigger. */
interface PersistedTriggerState {
  /** Last poll's item-key snapshot (item detection). */
  seen: string[];
  /** Last whole-response hash (hash detection). */
  last_hash?: string;
  /** Whether a baseline poll has run. Distinguishes "first poll" from "genuinely empty". */
  baseline: boolean;
  last_poll_ts?: string;
  last_error?: string;
  last_fire_ts?: string;
}

/** One recorded fire, newest-first in the ring. */
export interface FireRecord {
  trigger_id: string;
  trigger_name?: string;
  tool: string;
  detection: "items" | "hash";
  new_count: number;
  sample_keys?: string[];
  ts: string;
}

interface StateFile {
  triggers: Record<string, PersistedTriggerState>;
  fires: FireRecord[];
}

/** Outcome of a single poll — returned to the verifier and the dashboard "poll now" button. */
export interface PollResult {
  id: string;
  /** Poll completed without an upstream/transport error. */
  ok: boolean;
  /** A change was detected and a fire was recorded/delivered. */
  fired: boolean;
  detection?: "items" | "hash";
  new_count: number;
  /** This poll only seeded the baseline (so it fired nothing by design). */
  baseline: boolean;
  error?: string;
  /** Set when the trigger was not polled at all (unknown id / disabled). */
  skipped?: string;
}

/** Snapshot of trigger config + runtime state for the dashboard. */
export interface TriggersState {
  enabled: boolean;
  running: boolean;
  poll_interval_seconds: number;
  triggers: Array<{
    id: string;
    name: string | null;
    tool: string;
    enabled: boolean;
    interval_seconds: number;
    detection: "items" | "hash";
    baseline: boolean;
    seen_count: number;
    last_poll_ts: string | null;
    last_fire_ts: string | null;
    last_error: string | null;
  }>;
  recent_fires: FireRecord[];
}

/** Navigate a dot-path (e.g. `data.issues`) into a parsed JSON value. */
function navigatePath(root: unknown, path: string): unknown {
  if (!path) return root;
  let cur: unknown = root;
  for (const seg of path.split(".")) {
    if (cur === null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[seg];
  }
  return cur;
}

/** First text block of a tool result, if any. */
function firstText(result: CallToolResult): string | undefined {
  for (const c of result.content ?? []) {
    if (c && typeof c === "object" && (c as { type?: string }).type === "text") {
      const t = (c as { text?: unknown }).text;
      if (typeof t === "string") return t;
    }
  }
  return undefined;
}

/** Human-readable text of an upstream error result. */
function resultErrorText(result: CallToolResult): string {
  const text = firstText(result);
  return (text ?? "").trim() || "upstream returned an error result";
}

export class TriggerManager {
  private data: StateFile;
  private timers: ReturnType<typeof setInterval>[] = [];
  private running = false;
  /** Per-trigger in-flight lock so an interval tick and a manual poll never race on state. */
  private readonly inflight = new Map<string, Promise<PollResult>>();

  constructor(
    private readonly router: Router,
    private readonly cfg: SwitchboardConfig,
    private readonly resolveSecret: SecretResolver,
  ) {
    this.data = loadState();
  }

  /** Begin polling every enabled definition on its interval. No-op unless triggers are enabled. */
  start(): void {
    const t = this.cfg.settings?.triggers;
    if (!t?.enabled) {
      this.running = false;
      return;
    }
    if (this.running) return;

    const baseInterval = t.poll_interval_seconds ?? DEFAULT_INTERVAL_SECONDS;
    const defs = (t.definitions ?? []).filter((d) => d.enabled !== false);
    for (const d of defs) {
      const secs = Math.max(1, d.interval_seconds ?? baseInterval);
      const timer = setInterval(() => {
        void this.pollOnce(d.id);
      }, secs * 1000);
      // The HTTP/stdio server owns process lifetime; a poller must not keep the process alive on its own.
      timer.unref?.();
      this.timers.push(timer);
    }
    this.running = true;
    log.info(`triggers: ${defs.length} active poller${defs.length === 1 ? "" : "s"} (default every ${baseInterval}s)`);
  }

  /** Stop every poller. Safe to call when nothing was ever started. */
  stop(): void {
    for (const timer of this.timers) clearInterval(timer);
    this.timers = [];
    this.running = false;
  }

  /** Reconcile pollers with the current config (call after a `settings.triggers` edit). */
  reload(): void {
    this.stop();
    this.start();
  }

  /** Poll one trigger exactly once and await the verdict. Concurrent calls share one in-flight poll. */
  pollOnce(id: string): Promise<PollResult> {
    const existing = this.inflight.get(id);
    if (existing) return existing;
    const p = this.doPoll(id).finally(() => this.inflight.delete(id));
    this.inflight.set(id, p);
    return p;
  }

  /** Config + runtime snapshot for the dashboard. */
  state(): TriggersState {
    const t = this.cfg.settings?.triggers;
    const defs = t?.definitions ?? [];
    const interval = t?.poll_interval_seconds ?? DEFAULT_INTERVAL_SECONDS;
    return {
      enabled: t?.enabled === true,
      running: this.running,
      poll_interval_seconds: interval,
      triggers: defs.map((d) => {
        const s = this.data.triggers[d.id];
        return {
          id: d.id,
          name: d.name ?? null,
          tool: d.tool,
          enabled: d.enabled !== false,
          interval_seconds: d.interval_seconds ?? interval,
          detection: d.item_path && d.item_key ? "items" : "hash",
          baseline: s?.baseline ?? false,
          seen_count: s?.seen?.length ?? 0,
          last_poll_ts: s?.last_poll_ts ?? null,
          last_fire_ts: s?.last_fire_ts ?? null,
          last_error: s?.last_error ?? null,
        };
      }),
      recent_fires: this.data.fires.slice(0, 50),
    };
  }

  // --- internals ---

  private defsById(): Map<string, TriggerDefinition> {
    const m = new Map<string, TriggerDefinition>();
    for (const d of this.cfg.settings?.triggers?.definitions ?? []) m.set(d.id, d);
    return m;
  }

  private ensureState(id: string): PersistedTriggerState {
    let s = this.data.triggers[id];
    if (!s) {
      s = { seen: [], baseline: false };
      this.data.triggers[id] = s;
    }
    return s;
  }

  private async doPoll(id: string): Promise<PollResult> {
    const def = this.defsById().get(id);
    if (!def) return { id, ok: false, fired: false, new_count: 0, baseline: false, skipped: "unknown trigger" };
    if (def.enabled === false) return { id, ok: false, fired: false, new_count: 0, baseline: false, skipped: "disabled" };

    const st = this.ensureState(id);

    // THE POLL — a normal governed tool call. Policy/approval/audit all apply here.
    let result: CallToolResult;
    try {
      result = await this.router.callTool(def.tool, def.args ?? {});
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      st.last_poll_ts = new Date().toISOString();
      st.last_error = msg;
      this.persist();
      log.warn(`trigger '${id}': poll threw: ${msg}`);
      return { id, ok: false, fired: false, new_count: 0, baseline: false, error: msg };
    }

    st.last_poll_ts = new Date().toISOString();

    // A denied/errored poll never fires — only the audit log records why.
    if (result.isError) {
      const msg = resultErrorText(result);
      st.last_error = msg;
      this.persist();
      return { id, ok: false, fired: false, new_count: 0, baseline: false, error: msg };
    }
    st.last_error = undefined;

    // Decide detection mode: item-level if the path resolves to an array and keys extract.
    const text = firstText(result);
    const itemPath = def.item_path;
    const itemKey = def.item_key;
    if (itemPath && itemKey && text) {
      try {
        const parsed: unknown = JSON.parse(text);
        const arr = navigatePath(parsed, itemPath);
        if (Array.isArray(arr)) {
          const keys = arr
            .map((el) => (el && typeof el === "object" ? (el as Record<string, unknown>)[itemKey] : undefined))
            .filter((k): k is string | number => k !== undefined && k !== null)
            .map((k) => String(k));
          // An empty array is a legitimate item-detection state; a non-empty array whose
          // elements never yield the key is a misconfiguration → fall through to hash.
          if (arr.length === 0 || keys.length > 0) {
            return this.detectItems(def, st, keys);
          }
        }
      } catch {
        // Not JSON, or the path didn't resolve — fall through to whole-response hashing.
      }
    }

    const hashInput = text ?? JSON.stringify(result.content ?? []);
    return this.detectHash(def, st, hashInput);
  }

  private detectItems(def: TriggerDefinition, st: PersistedTriggerState, currentKeys: string[]): PollResult {
    if (!st.baseline) {
      st.seen = currentKeys;
      st.baseline = true;
      this.persist();
      return { id: def.id, ok: true, fired: false, detection: "items", new_count: 0, baseline: true };
    }
    const seenSet = new Set(st.seen);
    const fresh = currentKeys.filter((k) => !seenSet.has(k));
    st.seen = currentKeys; // snapshot semantics — `seen` always mirrors the latest poll.
    if (fresh.length === 0) {
      this.persist();
      return { id: def.id, ok: true, fired: false, detection: "items", new_count: 0, baseline: false };
    }
    this.fire(def, "items", fresh.length, fresh.slice(0, SAMPLE_CAP));
    return { id: def.id, ok: true, fired: true, detection: "items", new_count: fresh.length, baseline: false };
  }

  private detectHash(def: TriggerDefinition, st: PersistedTriggerState, input: string): PollResult {
    const hash = createHash("sha256").update(input).digest("hex");
    if (!st.baseline) {
      st.last_hash = hash;
      st.baseline = true;
      this.persist();
      return { id: def.id, ok: true, fired: false, detection: "hash", new_count: 0, baseline: true };
    }
    if (hash === st.last_hash) {
      this.persist();
      return { id: def.id, ok: true, fired: false, detection: "hash", new_count: 0, baseline: false };
    }
    st.last_hash = hash;
    this.fire(def, "hash", 1);
    return { id: def.id, ok: true, fired: true, detection: "hash", new_count: 1, baseline: false };
  }

  /** Record a fire locally (ring + state) and notify the webhook. NEVER writes an audit decision. */
  private fire(def: TriggerDefinition, detection: "items" | "hash", newCount: number, sampleKeys?: string[]): void {
    const ts = new Date().toISOString();
    const st = this.ensureState(def.id);
    st.last_fire_ts = ts;

    const rec: FireRecord = {
      trigger_id: def.id,
      ...(def.name ? { trigger_name: def.name } : {}),
      tool: def.tool,
      detection,
      new_count: newCount,
      ...(sampleKeys && sampleKeys.length > 0 ? { sample_keys: sampleKeys } : {}),
      ts,
    };
    this.data.fires.unshift(rec);
    if (this.data.fires.length > FIRES_CAP) this.data.fires.length = FIRES_CAP;
    this.persist();
    log.info(`trigger '${def.id}' fired (${detection}, +${newCount})`);

    const event: TriggerWebhookEvent = {
      trigger_id: def.id,
      ...(def.name ? { trigger_name: def.name } : {}),
      tool: def.tool,
      detection,
      new_count: newCount,
      ...(sampleKeys && sampleKeys.length > 0 ? { sample_keys: sampleKeys } : {}),
    };
    deliverTriggerWebhook(this.cfg, event, this.resolveSecret);
  }

  private persist(): void {
    try {
      if (!existsSync(HOME_DIR)) mkdirSync(HOME_DIR, { recursive: true });
      writeFileSync(STATE_PATH, JSON.stringify(this.data, null, 2));
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      log.warn(`triggers: could not persist state: ${msg}`);
    }
  }
}

/** Load persisted trigger state, tolerating a missing or corrupt file. */
function loadState(): StateFile {
  if (!existsSync(STATE_PATH)) return { triggers: {}, fires: [] };
  try {
    const raw = JSON.parse(readFileSync(STATE_PATH, "utf8")) as Partial<StateFile>;
    return {
      triggers: raw.triggers && typeof raw.triggers === "object" ? raw.triggers : {},
      fires: Array.isArray(raw.fires) ? raw.fires : [],
    };
  } catch {
    return { triggers: {}, fires: [] };
  }
}
