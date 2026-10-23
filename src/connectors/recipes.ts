/**
 * Recipes (ADR local-composio, section 6.1): a tiny declarative step language for composite actions.
 *
 *   http               one authenticated request
 *   poll               repeat a request until a condition holds (container status, publish status)
 *   upload_resumable   open a resumable session, then PUT the file (Google, Meta, TikTok shaped)
 *   foreach            run steps once per element of an array
 *   map                turn an array into another array with a template
 *   assert             stop with a clear error unless a condition holds
 *
 * There is NO code evaluation. A recipe is JSON; values are templates (`{{input.title}}`,
 * `{{steps.container.body.id}}`, `{{item.url | default:""}}`); conditions are data (`equals`, `in`, `exists`).
 * The only functions are the five named in FILTERS, each a fixed pure transform. Path lookups follow own
 * properties only and refuse `__proto__`, `constructor` and `prototype`, so a response body cannot reach
 * the interpreter's own objects. Every run is bounded: steps, requests, iterations and nesting depth.
 *
 * This module is pure logic over an injected runtime, so the oracle exercises it without a network; exec.ts
 * supplies the runtime that sends requests through the host lock and the guarded fetch.
 */

// ── step types ────────────────────────────────────────────────────────────────────────────────────

export interface HttpReq {
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  /** Absolute https URL, or a path starting with `/` joined to the toolkit's base URL. Templated. */
  url: string;
  query?: Record<string, unknown>;
  headers?: Record<string, string>;
  json?: unknown;
  form?: Record<string, unknown>;
  /** `provider` (default): the account's credential is injected and the host must be an API host. `none`: a pre-signed URL. */
  auth?: "provider" | "none";
}

export interface Condition {
  path: string;
  equals?: unknown;
  not_equals?: unknown;
  in?: unknown[];
  not_in?: unknown[];
  exists?: boolean;
  truthy?: boolean;
}

interface StepBase {
  /** Name the result is stored under: `steps.<bind>` is `{ status, headers, body }` (or the collected value). */
  bind?: string;
}
export interface HttpStep extends StepBase {
  type: "http";
  request: HttpReq;
  /** Accepted statuses. Default: any 2xx. */
  expect?: number[];
}
export interface PollStep extends StepBase {
  type: "poll";
  request: HttpReq;
  until: Condition;
  fail_when?: Condition;
  interval_ms: number;
  max_attempts: number;
}
export interface UploadResumableStep extends StepBase {
  type: "upload_resumable";
  /** Opens the session. */
  init: HttpReq;
  /** Template that yields the file argument (`{{input.video}}`). */
  file: string;
  /** Where the session URL is: the `Location` header (default) or a body path such as `body.upload_url`. */
  location?: string;
  content_type?: string;
  /** Send in chunks of this size (Content-Range); omitted = one PUT. */
  chunk_bytes?: number;
  /** Statuses that mean "send the next chunk" (Google 308, TikTok 206). */
  partial_status?: number[];
  auth?: "provider" | "none";
}
export interface ForeachStep extends StepBase {
  type: "foreach";
  items: string;
  as: string;
  steps: RecipeStep[];
  /** Template evaluated after each iteration; default is the last sub step's body. */
  collect?: unknown;
  max_items?: number;
}
export interface MapStep extends StepBase {
  type: "map";
  items: string;
  as: string;
  to: unknown;
}
export interface AssertStep {
  type: "assert";
  that: Condition;
  message: string;
}
export type RecipeStep = HttpStep | PollStep | UploadResumableStep | ForeachStep | MapStep | AssertStep;

export const MAX_STEPS = 200;
export const MAX_REQUESTS = 100;
export const MAX_FOREACH_ITEMS = 50;
export const MAX_DEPTH = 3;

// ── validation ────────────────────────────────────────────────────────────────────────────────────

const FILTERS = new Set(["join", "default", "json", "length", "lower"]);
const TEMPLATE_RE = /\{\{\s*([^{}]*?)\s*\}\}/g;
const METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);

function templateProblem(value: unknown, where: string): string | undefined {
  if (typeof value === "string") {
    const stripped = value.replace(TEMPLATE_RE, (_m, expr: string) => {
      const [path, ...fns] = splitFilters(expr);
      if (!path || !/^[A-Za-z_][\w-]*(\.[A-Za-z_][\w-]*|\[\d+\])*$/.test(path.trim())) return "\u0000bad";
      for (const f of fns) {
        const name = f.trim().split(":")[0]!.trim();
        if (!FILTERS.has(name)) return "\u0000bad";
      }
      return "";
    });
    if (stripped.includes("\u0000bad")) return `${where}: a template expression is malformed or names an unknown function (allowed: ${[...FILTERS].join(", ")})`;
    if (/\{\{|\}\}/.test(stripped)) return `${where}: unbalanced {{ }}`;
    return undefined;
  }
  if (Array.isArray(value)) {
    for (const [i, v] of value.entries()) {
      const p = templateProblem(v, `${where}[${i}]`);
      if (p) return p;
    }
    return undefined;
  }
  if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) {
      const p = templateProblem(v, `${where}.${k}`);
      if (p) return p;
    }
  }
  return undefined;
}

function conditionProblem(c: unknown, where: string): string | undefined {
  if (!c || typeof c !== "object") return `${where}: a condition is required`;
  const cond = c as Condition;
  if (typeof cond.path !== "string" || !/^[A-Za-z_][\w-]*(\.[A-Za-z_][\w-]*|\[\d+\])*$/.test(cond.path)) return `${where}: condition.path must be a dotted path`;
  const ops = ["equals", "not_equals", "in", "not_in", "exists", "truthy"].filter((k) => k in cond);
  if (ops.length !== 1) return `${where}: a condition needs exactly one of equals, not_equals, in, not_in, exists, truthy`;
  if ((cond.in !== undefined && !Array.isArray(cond.in)) || (cond.not_in !== undefined && !Array.isArray(cond.not_in))) return `${where}: in and not_in take an array`;
  return undefined;
}

function reqProblem(r: unknown, where: string): string | undefined {
  if (!r || typeof r !== "object") return `${where}: a request is required`;
  const req = r as HttpReq;
  if (!METHODS.has(req.method)) return `${where}: method must be one of ${[...METHODS].join(", ")}`;
  if (typeof req.url !== "string" || !req.url) return `${where}: url is required`;
  if (req.auth !== undefined && req.auth !== "provider" && req.auth !== "none") return `${where}: auth must be provider or none`;
  if (!/^(\/|https:\/\/|\{\{)/.test(req.url) && !/^http:\/\/(127\.0\.0\.1|localhost|\[::1\])/.test(req.url)) return `${where}: url must start with /, https:// or a template`;
  return templateProblem(req.url, `${where}.url`) ?? templateProblem(req.query, `${where}.query`) ?? templateProblem(req.headers, `${where}.headers`) ?? templateProblem(req.json, `${where}.json`) ?? templateProblem(req.form, `${where}.form`);
}

/** Structural check of a recipe. Returns the first problem, or undefined when the recipe is well formed. */
export function validateRecipeSteps(steps: unknown, depth = 0): string | undefined {
  if (!Array.isArray(steps) || steps.length === 0) return "steps must be a non-empty array";
  if (depth >= MAX_DEPTH) return `steps are nested deeper than ${MAX_DEPTH}`;
  let n = 0;
  const count = (list: unknown[]): void => {
    for (const s of list) {
      n += 1;
      const sub = (s as { steps?: unknown[] }).steps;
      if (Array.isArray(sub)) count(sub);
    }
  };
  count(steps);
  if (n > 40) return "a recipe may have at most 40 steps";
  for (const [i, raw] of steps.entries()) {
    const where = `step ${i + 1}`;
    if (!raw || typeof raw !== "object") return `${where}: not an object`;
    const s = raw as { type?: string; bind?: unknown };
    if (s.bind !== undefined && (typeof s.bind !== "string" || !/^[A-Za-z_][\w-]*$/.test(s.bind) || ["__proto__", "constructor", "prototype"].includes(s.bind))) return `${where}: bind must be a plain name`;
    switch (s.type) {
      case "http": {
        const st = raw as HttpStep;
        const p = reqProblem(st.request, `${where}.request`);
        if (p) return p;
        break;
      }
      case "poll": {
        const st = raw as PollStep;
        const p = reqProblem(st.request, `${where}.request`) ?? conditionProblem(st.until, `${where}.until`) ?? (st.fail_when ? conditionProblem(st.fail_when, `${where}.fail_when`) : undefined);
        if (p) return p;
        if (!Number.isInteger(st.interval_ms) || st.interval_ms < 0 || st.interval_ms > 60_000) return `${where}: interval_ms must be 0 to 60000`;
        if (!Number.isInteger(st.max_attempts) || st.max_attempts < 1 || st.max_attempts > 120) return `${where}: max_attempts must be 1 to 120`;
        break;
      }
      case "upload_resumable": {
        const st = raw as UploadResumableStep;
        const p = reqProblem(st.init, `${where}.init`) ?? templateProblem(st.file, `${where}.file`);
        if (p) return p;
        if (typeof st.file !== "string" || !st.file.includes("{{")) return `${where}: file must be a template naming the file argument`;
        if (st.chunk_bytes !== undefined && (!Number.isInteger(st.chunk_bytes) || st.chunk_bytes < 1024)) return `${where}: chunk_bytes must be at least 1024`;
        break;
      }
      case "foreach": {
        const st = raw as ForeachStep;
        if (typeof st.items !== "string" || typeof st.as !== "string" || !/^[A-Za-z_]\w*$/.test(st.as)) return `${where}: foreach needs items and a plain 'as' name`;
        const p = templateProblem(st.items, `${where}.items`) ?? templateProblem(st.collect, `${where}.collect`) ?? validateRecipeSteps(st.steps, depth + 1);
        if (p) return p;
        break;
      }
      case "map": {
        const st = raw as MapStep;
        if (typeof st.items !== "string" || typeof st.as !== "string" || !/^[A-Za-z_]\w*$/.test(st.as)) return `${where}: map needs items and a plain 'as' name`;
        const p = templateProblem(st.items, `${where}.items`) ?? templateProblem(st.to, `${where}.to`);
        if (p) return p;
        break;
      }
      case "assert": {
        const st = raw as AssertStep;
        const p = conditionProblem(st.that, `${where}.that`) ?? templateProblem(st.message, `${where}.message`);
        if (p) return p;
        if (typeof st.message !== "string" || !st.message) return `${where}: assert needs a message`;
        break;
      }
      default:
        return `${where}: unknown step type '${String(s.type)}'`;
    }
  }
  return undefined;
}

// ── templates and paths ───────────────────────────────────────────────────────────────────────────

export type Scope = Record<string, unknown>;

const FORBIDDEN = new Set(["__proto__", "constructor", "prototype"]);

function splitFilters(expr: string): string[] {
  // A `|` inside a quoted literal is not a separator.
  const parts: string[] = [];
  let cur = "";
  let quote = false;
  for (const ch of expr) {
    if (ch === '"') quote = !quote;
    if (ch === "|" && !quote) {
      parts.push(cur);
      cur = "";
    } else cur += ch;
  }
  parts.push(cur);
  return parts.map((p) => p.trim());
}

/** Look a dotted path (`a.b[0].c`) up in the scope, own properties only. Undefined when any hop is missing. */
export function lookup(scope: unknown, path: string): unknown {
  const tokens = path.match(/[A-Za-z_][\w-]*|\[\d+\]/g);
  if (!tokens) return undefined;
  let cur: unknown = scope;
  for (const t of tokens) {
    if (cur === null || cur === undefined) return undefined;
    if (t.startsWith("[")) {
      if (!Array.isArray(cur)) return undefined;
      cur = cur[Number(t.slice(1, -1))];
    } else {
      if (FORBIDDEN.has(t) || typeof cur !== "object" || Array.isArray(cur) || !Object.prototype.hasOwnProperty.call(cur, t)) return undefined;
      cur = (cur as Record<string, unknown>)[t];
    }
  }
  return cur;
}

function applyFilter(value: unknown, filter: string): unknown {
  const colon = filter.indexOf(":");
  const name = (colon === -1 ? filter : filter.slice(0, colon)).trim();
  const argText = colon === -1 ? undefined : filter.slice(colon + 1).trim();
  const arg = argText === undefined ? undefined : (JSON.parse(argText) as unknown);
  switch (name) {
    case "join":
      return Array.isArray(value) ? value.map((v) => String(v)).join(typeof arg === "string" ? arg : ",") : value;
    case "default":
      return value === undefined || value === null || value === "" ? arg : value;
    case "json":
      return JSON.stringify(value);
    case "length":
      return Array.isArray(value) || typeof value === "string" ? value.length : 0;
    case "lower":
      return typeof value === "string" ? value.toLowerCase() : value;
    default:
      throw new RecipeError("SB_RECIPE_INVALID", `unknown template function '${name}'`);
  }
}

function evalExpr(expr: string, scope: Scope): unknown {
  const [path, ...fns] = splitFilters(expr);
  let v = lookup(scope, path!);
  for (const f of fns) v = applyFilter(v, f);
  return v;
}

/**
 * Fill templates in a value. A string that is exactly one `{{expr}}` keeps the value's type; a string with
 * text around it is interpolated and an unset reference is an error (a request must not go out with the
 * word "undefined" in it). In an object, a whole-value template that resolves to nothing drops the key.
 */
export function render(value: unknown, scope: Scope): unknown {
  if (typeof value === "string") {
    const whole = value.match(/^\{\{\s*([^{}]*?)\s*\}\}$/);
    if (whole) return evalExpr(whole[1]!, scope);
    return value.replace(TEMPLATE_RE, (_m, expr: string) => {
      const v = evalExpr(expr, scope);
      if (v === undefined || v === null) throw new RecipeError("SB_RECIPE_INVALID", `the template '{{${expr}}}' has no value`);
      return typeof v === "object" ? JSON.stringify(v) : String(v);
    });
  }
  if (Array.isArray(value)) return value.map((v) => render(v, scope)).map((v) => (v === undefined ? null : v));
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      const r = render(v, scope);
      if (r !== undefined) out[k] = r;
    }
    return out;
  }
  return value;
}

const same = (a: unknown, b: unknown): boolean => JSON.stringify(a) === JSON.stringify(b);

export function check(cond: Condition, scope: Scope): boolean {
  const v = lookup(scope, cond.path);
  if ("equals" in cond) return same(v, cond.equals);
  if ("not_equals" in cond) return !same(v, cond.not_equals);
  if ("in" in cond) return (cond.in ?? []).some((x) => same(v, x));
  if ("not_in" in cond) return !(cond.not_in ?? []).some((x) => same(v, x));
  if ("exists" in cond) return (v !== undefined && v !== null) === cond.exists;
  if ("truthy" in cond) return Boolean(v) === cond.truthy;
  return false;
}

// ── interpreter ───────────────────────────────────────────────────────────────────────────────────

export class RecipeError extends Error {
  constructor(
    readonly code: "SB_RECIPE_INVALID" | "SB_RECIPE_ASSERT" | "SB_RECIPE_TIMEOUT" | "SB_RECIPE_STEP_FAILED" | "SB_RECIPE_LIMIT",
    message: string,
    /** Step ids completed before the failure, so the caller can say what already happened. */
    readonly completed: string[] = [],
    /** The provider's answer when a request step failed. */
    readonly response?: { status: number; body: unknown },
  ) {
    super(message);
    this.name = "RecipeError";
  }
}

export interface HttpResult {
  status: number;
  headers: Record<string, string>;
  body: unknown;
}

/** What the interpreter needs from the outside: the three things a recipe cannot do by itself. */
export interface RecipeRuntime {
  http(req: { method: string; url: string; query: Record<string, string | string[]>; headers: Record<string, string>; json?: unknown; form?: Record<string, string>; auth: "provider" | "none" }): Promise<HttpResult>;
  /** Resolve a file argument (path, https URL, `staged:<id>`) to bytes, applying every file rule. */
  file(arg: unknown): Promise<{ bytes: Uint8Array; name: string; mimeType: string; sha256: string }>;
  /** PUT bytes to a session URL. Returns the response. */
  put(req: { url: string; headers: Record<string, string>; body: Uint8Array; auth: "provider" | "none" }): Promise<HttpResult>;
  sleep(ms: number): Promise<void>;
}

interface RunState {
  steps: number;
  requests: number;
  completed: string[];
}

function toQuery(q: Record<string, unknown> | undefined, scope: Scope): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  if (!q) return out;
  const rendered = render(q, scope) as Record<string, unknown>;
  for (const [k, v] of Object.entries(rendered)) {
    if (v === undefined || v === null) continue;
    out[k] = Array.isArray(v) ? v.map((x) => String(x)) : typeof v === "object" ? JSON.stringify(v) : String(v);
  }
  return out;
}

function toHeaders(h: Record<string, string> | undefined, scope: Scope): Record<string, string> {
  const out: Record<string, string> = {};
  if (!h) return out;
  for (const [k, v] of Object.entries(render(h, scope) as Record<string, unknown>)) if (v !== undefined && v !== null) out[k] = String(v);
  return out;
}

async function sendHttp(rt: RecipeRuntime, req: HttpReq, scope: Scope, state: RunState): Promise<HttpResult> {
  state.requests += 1;
  if (state.requests > MAX_REQUESTS) throw new RecipeError("SB_RECIPE_LIMIT", `the recipe made more than ${MAX_REQUESTS} requests`, state.completed);
  const url = String(render(req.url, scope));
  const form = req.form ? (Object.fromEntries(Object.entries(render(req.form, scope) as Record<string, unknown>).filter(([, v]) => v !== undefined && v !== null).map(([k, v]) => [k, String(v)])) as Record<string, string>) : undefined;
  return rt.http({
    method: req.method,
    url,
    query: toQuery(req.query, scope),
    headers: toHeaders(req.headers, scope),
    ...(req.json !== undefined ? { json: render(req.json, scope) } : {}),
    ...(form ? { form } : {}),
    auth: req.auth ?? "provider",
  });
}

const okStatus = (s: number, expect?: number[]): boolean => (expect ? expect.includes(s) : s >= 200 && s < 300);

function asResult(r: HttpResult): Record<string, unknown> {
  return { status: r.status, headers: r.headers, body: r.body };
}

function failFrom(state: RunState, what: string, r: HttpResult): RecipeError {
  return new RecipeError("SB_RECIPE_STEP_FAILED", `${what} answered HTTP ${r.status}`, state.completed, { status: r.status, body: r.body });
}

async function runSteps(steps: RecipeStep[], scope: Scope, rt: RecipeRuntime, state: RunState, depth: number): Promise<unknown> {
  let last: unknown;
  const stepsBag = scope.steps as Record<string, unknown>;
  for (const [i, step] of steps.entries()) {
    state.steps += 1;
    if (state.steps > MAX_STEPS) throw new RecipeError("SB_RECIPE_LIMIT", `the recipe ran more than ${MAX_STEPS} steps`, state.completed);
    const id = (step as StepBase).bind ?? `${step.type}${i + 1}`;
    switch (step.type) {
      case "http": {
        const r = await sendHttp(rt, step.request, scope, state);
        if (!okStatus(r.status, step.expect)) throw failFrom(state, `step '${id}'`, r);
        if (step.bind) stepsBag[step.bind] = asResult(r);
        last = r.body;
        break;
      }
      case "poll": {
        let done = false;
        let r: HttpResult | undefined;
        for (let attempt = 1; attempt <= step.max_attempts; attempt++) {
          r = await sendHttp(rt, step.request, scope, state);
          if (!okStatus(r.status)) throw failFrom(state, `poll '${id}'`, r);
          const view = { ...scope, response: asResult(r) };
          if (step.fail_when && check(step.fail_when, view)) throw new RecipeError("SB_RECIPE_STEP_FAILED", `poll '${id}' reported a failure state`, state.completed, { status: r.status, body: r.body });
          if (check(step.until, view)) {
            done = true;
            break;
          }
          if (attempt < step.max_attempts) await rt.sleep(step.interval_ms);
        }
        if (!done) throw new RecipeError("SB_RECIPE_TIMEOUT", `poll '${id}' did not reach its condition in ${step.max_attempts} attempts`, state.completed);
        if (step.bind) stepsBag[step.bind] = asResult(r!);
        last = r!.body;
        break;
      }
      case "upload_resumable": {
        const file = await rt.file(render(step.file, scope));
        const auth = step.auth ?? "provider";
        const type = step.content_type ?? file.mimeType;
        const init = await sendHttp(
          rt,
          { ...step.init, headers: { "X-Upload-Content-Type": type, "X-Upload-Content-Length": String(file.bytes.byteLength), ...(step.init.headers ?? {}) } },
          scope,
          state,
        );
        if (!okStatus(init.status)) throw failFrom(state, `the upload session of '${id}'`, init);
        const where = step.location ?? "header.location";
        const sessionUrl = where.startsWith("header.") ? init.headers[where.slice(7).toLowerCase()] : lookup({ body: init.body, headers: init.headers }, where);
        if (typeof sessionUrl !== "string" || !sessionUrl) throw new RecipeError("SB_RECIPE_STEP_FAILED", `the upload session of '${id}' returned no URL at '${where}'`, state.completed, { status: init.status, body: init.body });
        const total = file.bytes.byteLength;
        const chunk = step.chunk_bytes ?? Math.max(total, 1);
        const partial = new Set(step.partial_status ?? [308]);
        let sent = 0;
        let final: HttpResult | undefined;
        do {
          const end = Math.min(total, sent + chunk);
          const body = file.bytes.subarray(sent, end);
          state.requests += 1;
          if (state.requests > MAX_REQUESTS) throw new RecipeError("SB_RECIPE_LIMIT", `the recipe made more than ${MAX_REQUESTS} requests`, state.completed);
          const res = await rt.put({
            url: sessionUrl,
            headers: {
              "Content-Type": type,
              ...(step.chunk_bytes !== undefined || total === 0 ? { "Content-Range": total === 0 ? "bytes */0" : `bytes ${sent}-${end - 1}/${total}` } : {}),
            },
            body,
            auth,
          });
          sent = end;
          if (partial.has(res.status) && sent < total) continue;
          final = res;
          break;
        } while (sent < total);
        if (!final || !okStatus(final.status)) throw failFrom(state, `the upload of '${id}'`, final ?? { status: 0, headers: {}, body: null });
        if (step.bind) stepsBag[step.bind] = asResult(final);
        last = final.body;
        break;
      }
      case "foreach": {
        const items = render(step.items, scope);
        if (!Array.isArray(items)) throw new RecipeError("SB_RECIPE_INVALID", `foreach '${id}': '${step.items}' is not an array`, state.completed);
        const cap = Math.min(step.max_items ?? MAX_FOREACH_ITEMS, MAX_FOREACH_ITEMS);
        if (items.length > cap) throw new RecipeError("SB_RECIPE_LIMIT", `foreach '${id}' has ${items.length} items (limit ${cap})`, state.completed);
        const collected: unknown[] = [];
        for (const item of items) {
          const inner: Scope = { ...scope, [step.as]: item, steps: { ...stepsBag } };
          const tail = await runSteps(step.steps, inner, rt, state, depth + 1);
          collected.push(step.collect !== undefined ? render(step.collect, inner) : tail);
        }
        if (step.bind) stepsBag[step.bind] = collected;
        last = collected;
        break;
      }
      case "map": {
        const items = render(step.items, scope);
        if (!Array.isArray(items)) throw new RecipeError("SB_RECIPE_INVALID", `map '${id}': '${step.items}' is not an array`, state.completed);
        if (items.length > 1000) throw new RecipeError("SB_RECIPE_LIMIT", `map '${id}' has ${items.length} items (limit 1000)`, state.completed);
        const out = items.map((item) => render(step.to, { ...scope, [step.as]: item }));
        if (step.bind) stepsBag[step.bind] = out;
        last = out;
        break;
      }
      case "assert": {
        if (!check(step.that, scope)) throw new RecipeError("SB_RECIPE_ASSERT", String(render(step.message, scope)), state.completed);
        break;
      }
    }
    state.completed.push(id);
  }
  return last;
}

export interface RecipeOutcome {
  value: unknown;
  completed: string[];
  requests: number;
}

/** Run a recipe. `result` is a template over `{ input, steps }`; absent, the last step's body. */
export async function runRecipe(steps: RecipeStep[], input: Record<string, unknown>, result: unknown, rt: RecipeRuntime): Promise<RecipeOutcome> {
  const state: RunState = { steps: 0, requests: 0, completed: [] };
  const scope: Scope = { input, steps: {} };
  let last: unknown;
  try {
    last = await runSteps(steps, scope, rt, state, 0);
  } catch (err) {
    // Whatever stopped the run (a refused host, a dropped connection), the caller learns which steps had finished.
    if (err && typeof err === "object" && !(err instanceof RecipeError)) (err as { completed?: string[] }).completed = [...state.completed];
    throw err;
  }
  const value = result !== undefined ? render(result, scope) : last;
  return { value, completed: state.completed, requests: state.requests };
}
