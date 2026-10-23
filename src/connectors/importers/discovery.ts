/**
 * Google Discovery document -> toolkit actions (ADR local-composio, section 6.1, "Discovery is new").
 *
 * A Discovery document (`discovery#restDescription`) describes one API: `resources` (nested) holding
 * `methods`, `schemas` (JSON Schema flavoured, `$ref` by bare name, `type: "any"`), `parameters` shared by all
 * methods, `rootUrl` and `servicePath`. Each method becomes one action:
 *
 *   - the action slug is the method id without the API name: `youtube.playlistItems.insert` is
 *     `playlist_items_insert`, `gmail.users.messages.send` is `users_messages_send`;
 *   - path, query and header parameters are exposed under their own names; a path parameter with a default
 *     (Gmail's `userId: "me"`) stays optional and keeps the default;
 *   - the request body's top level fields are exposed beside the parameters (read only fields dropped; a
 *     field the method requires per `annotations.required` is required), or nested under `body` when a name
 *     collides; every schema is kept as a `$defs` entry referenced with `#/$defs/<Name>`, so a recursive type
 *     stays finite and the document is never inlined;
 *   - `supportsMediaUpload` adds a `media_file` argument (a file argument: path, https URL or staged:<id>) and
 *     the resumable upload path; `supportsMediaDownload` raises the response cap and exposes `alt`;
 *   - scope and risk come from the HTTP method and the verbs in the name (toolkits.ts `deriveSafety`).
 *
 * The importer never reads a credential and never performs a request: it only reads the document it is
 * given. Fetching it is `toolkits sync`'s job.
 */

import { createHash } from "node:crypto";
import { deriveSafety, maxActionSlug, toSnake, uniqueSlug, type Action, type ParamBinding, type UploadSpec } from "../toolkits.js";

export interface ImportOptions {
  toolkit: string;
  provider: string;
}

export interface ImportResult {
  actions: Action[];
  warnings: string[];
  base_url: string;
  spec_revision?: string;
  spec_version?: string;
  /** Operations found in the document. */
  operations: number;
}

type Json = Record<string, any>;

const PARAM_DESC_MAX = 240;
const ACTION_DESC_MAX = 400;

function clip(text: unknown, max: number): string {
  const t = String(text ?? "").replace(/\s+/g, " ").trim();
  return t.length > max ? `${t.slice(0, max - 3).trimEnd()}...` : t;
}

function num(v: unknown): number | undefined {
  const n = typeof v === "number" ? v : typeof v === "string" ? Number(v) : NaN;
  return Number.isFinite(n) ? n : undefined;
}

/** Converts Discovery schema nodes to JSON Schema, keeping named schemas as `$defs`. */
class SchemaConverter {
  private readonly defs = new Map<string, Json>();
  constructor(private readonly schemas: Json) {}

  node(n: any): Json {
    if (!n || typeof n !== "object") return {};
    if (typeof n.$ref === "string") return { $ref: `#/$defs/${n.$ref}` };
    const out: Json = {};
    let type: string | undefined = n.type;
    if (type === undefined) type = n.properties ? "object" : n.items ? "array" : undefined;
    switch (type) {
      case "object": {
        out.type = "object";
        if (n.properties && typeof n.properties === "object") {
          out.properties = Object.fromEntries(Object.entries(n.properties as Json).map(([k, v]) => [k, this.node(v)]));
        }
        if (n.additionalProperties && typeof n.additionalProperties === "object") out.additionalProperties = this.node(n.additionalProperties);
        break;
      }
      case "array":
        out.type = "array";
        out.items = this.node(n.items);
        break;
      case "string":
        out.type = "string";
        if (Array.isArray(n.enum)) out.enum = [...new Set(n.enum as unknown[])];
        if (typeof n.format === "string") out.format = n.format;
        break;
      case "integer":
      case "number":
        out.type = type;
        if (typeof n.format === "string") out.format = n.format;
        if (num(n.minimum) !== undefined) out.minimum = num(n.minimum);
        if (num(n.maximum) !== undefined) out.maximum = num(n.maximum);
        break;
      case "boolean":
        out.type = "boolean";
        break;
      default:
        break; // "any" and unknown: no constraint
    }
    if (typeof n.description === "string" && n.description) out.description = clip(n.description, PARAM_DESC_MAX);
    return out;
  }

  /** The named schema as JSON Schema (converted once). */
  def(name: string): Json {
    let d = this.defs.get(name);
    if (!d) {
      d = {};
      this.defs.set(name, d); // placeholder first: a self reference terminates
      const src = this.schemas[name];
      Object.assign(d, src ? this.node(src) : {});
    }
    return d;
  }

  /** Every named schema reachable from `roots`, as a `$defs` object. */
  closure(roots: Json[]): Json {
    const out: Json = {};
    const queue: string[] = [];
    const scan = (v: unknown): void => {
      if (Array.isArray(v)) v.forEach(scan);
      else if (v && typeof v === "object") {
        const o = v as Json;
        if (typeof o.$ref === "string" && o.$ref.startsWith("#/$defs/")) queue.push(o.$ref.slice(8));
        for (const x of Object.values(o)) scan(x);
      }
    };
    roots.forEach(scan);
    while (queue.length) {
      const name = queue.pop()!;
      if (name in out) continue;
      const d = this.def(name);
      out[name] = d;
      scan(d);
    }
    return out;
  }
}

function* methodsOf(res: Json, trail: string[] = []): Generator<{ method: Json; resource: string[] }> {
  for (const m of Object.values((res.methods ?? {}) as Json)) yield { method: m as Json, resource: trail };
  for (const [name, r] of Object.entries((res.resources ?? {}) as Json)) yield* methodsOf(r as Json, [...trail, name]);
}

function paramSchema(p: Json): { schema: Json; repeated: boolean } {
  const base: Json = { type: ["string", "integer", "number", "boolean"].includes(p.type) ? p.type : "string" };
  if (typeof p.format === "string") base.format = p.format;
  if (Array.isArray(p.enum)) base.enum = [...new Set(p.enum as unknown[])];
  if (num(p.minimum) !== undefined) base.minimum = num(p.minimum);
  if (num(p.maximum) !== undefined) base.maximum = num(p.maximum);
  if (p.location === "path" && p.default !== undefined) base.default = base.type === "string" ? String(p.default) : p.default;
  const description = typeof p.description === "string" && p.description ? clip(p.description, PARAM_DESC_MAX) : undefined;
  if (p.repeated === true) {
    const { enum: _e, ...itemBase } = base;
    void _e;
    // A model sends "snippet,statistics" as often as ["snippet","statistics"]: both are accepted.
    return { schema: { type: [base.type, "array"], items: itemBase, ...(description ? { description } : {}) }, repeated: true };
  }
  return { schema: { ...base, ...(description ? { description } : {}) }, repeated: false };
}

const titleOf = (slug: string): string => {
  const t = slug.replace(/_/g, " ");
  return t.charAt(0).toUpperCase() + t.slice(1);
};

/** `/youtube/v3/videos/{}`: the method and path with parameter names erased, for matching coverage rows. */
function normalizedHttp(method: string, baseUrl: string, path: string): string {
  let basePath = "/";
  try {
    basePath = new URL(baseUrl).pathname;
  } catch {
    /* keep "/" */
  }
  const joined = `${basePath.replace(/\/+$/, "")}/${path.replace(/^\/+/, "")}`.replace(/\/{2,}/g, "/");
  return `${method.toUpperCase()} ${joined.replace(/\{\+?[^}]+\}/g, "{}")}`;
}

export function importDiscovery(doc: unknown, opts: ImportOptions): ImportResult {
  const d = doc as Json;
  if (!d || typeof d !== "object" || (d.kind !== "discovery#restDescription" && !d.resources && !d.methods)) {
    throw new Error("this is not a Google Discovery document (no discovery#restDescription, resources or methods)");
  }
  const warnings: string[] = [];
  const apiName = String(d.name ?? "");
  const rootUrl = String(d.rootUrl ?? "");
  const baseUrl = String(d.baseUrl ?? `${rootUrl}${d.servicePath ?? ""}`);
  if (!/^https:\/\//.test(baseUrl) && !/^http:\/\/(127\.0\.0\.1|localhost|\[::1\])(:|\/|$)/.test(baseUrl)) throw new Error(`the document names no https base URL (rootUrl '${rootUrl}')`);
  const conv = new SchemaConverter((d.schemas ?? {}) as Json);
  const globalParams = (d.parameters ?? {}) as Json;
  const taken = new Set<string>();
  const max = maxActionSlug(opts.toolkit);
  const actions: Action[] = [];
  let operations = 0;

  for (const { method: m, resource } of methodsOf(d)) {
    operations += 1;
    try {
      const id = String(m.id ?? "");
      if (!id || !m.httpMethod || typeof m.path !== "string") {
        warnings.push(`a method without id, httpMethod or path was skipped (${id || "no id"})`);
        continue;
      }
      const bare = apiName && id.startsWith(`${apiName}.`) ? id.slice(apiName.length + 1) : id;
      const slug = uniqueSlug(toSnake(bare), taken, max);
      const properties: Json = {};
      const required: string[] = [];
      const params: Record<string, ParamBinding> = {};

      const addParam = (name: string, p: Json, location: string): void => {
        if (name in properties) return;
        const { schema, repeated } = paramSchema({ ...p, location });
        properties[name] = schema;
        const isRequired = p.required === true && !(location === "path" && p.default !== undefined);
        if (isRequired) required.push(name);
        params[name] = { in: location as ParamBinding["in"], name, required: isRequired, ...(repeated ? { repeated: true } : {}) };
      };
      for (const [name, p] of Object.entries((m.parameters ?? {}) as Json)) {
        const loc = (p as Json).location;
        if (loc === "path" || loc === "query" || loc === "header") addParam(name, p as Json, loc);
      }
      // `{+name}` reserved expansion in the path template: keep slashes.
      for (const key of Object.keys(params)) {
        if (params[key]!.in === "path" && String(m.path).includes(`{+${key}}`)) params[key]!.reserved = true;
      }
      if (globalParams.fields && !("fields" in properties)) addParam("fields", globalParams.fields as Json, "query");
      const downloads = m.supportsMediaDownload === true;
      if (downloads && !("alt" in properties)) {
        properties.alt = { type: "string", enum: ["json", "media"], description: "Use media to download the file's content instead of its metadata." };
        params.alt = { in: "query", name: "alt", required: false };
      }

      // Request body.
      let bodyMode: "none" | "merged" | "nested" = "none";
      const requestRef = m.request?.$ref as string | undefined;
      if (requestRef) {
        const bodyDef = ((d.schemas ?? {}) as Json)[requestRef] as Json | undefined;
        const props = bodyDef?.type === "object" && bodyDef.properties ? (bodyDef.properties as Json) : undefined;
        const collides = props ? Object.keys(props).some((k) => k in properties) : true;
        if (props && !collides) {
          bodyMode = "merged";
          for (const [k, v] of Object.entries(props)) {
            if ((v as Json).readOnly === true) continue;
            properties[k] = conv.node(v);
            const req = ((v as Json).annotations?.required ?? []) as string[];
            const isRequired = req.includes(id);
            params[k] = { in: "body", name: k, required: isRequired };
            if (isRequired) required.push(k);
          }
        } else {
          bodyMode = "nested";
          const key = "body" in properties ? "request_body" : "body";
          properties[key] = conv.node({ $ref: requestRef });
          params[key] = { in: "body", name: "__body__", required: false };
        }
      }

      // Media upload.
      let upload: UploadSpec | undefined;
      let files: Action["files"];
      if (m.supportsMediaUpload === true && m.mediaUpload) {
        const mu = m.mediaUpload as Json;
        const param = "media_file";
        properties[param] = { type: "string", description: "The file to upload: an absolute local path inside an allowlisted folder, an https URL, or staged:<id>.", "x-file": "upload" };
        upload = {
          param,
          ...(mu.protocols?.resumable?.path ? { resumable_path: String(mu.protocols.resumable.path) } : {}),
          ...(mu.protocols?.simple?.path ? { simple_path: String(mu.protocols.simple.path) } : {}),
          accept: Array.isArray(mu.accept) ? (mu.accept as string[]) : [],
          ...(num(mu.maxSize) !== undefined ? { max_bytes: num(mu.maxSize)! } : {}),
        };
        files = { upload: [param], download: [] };
      }

      const defs = conv.closure(Object.values(properties));
      const input_schema: Json = { type: "object", properties, ...(required.length ? { required } : {}), ...(Object.keys(defs).length ? { $defs: defs } : {}) };
      const safety = deriveSafety(String(m.httpMethod), bare, {});
      actions.push({
        slug,
        title: titleOf(slug),
        description: clip(m.description ?? `${m.httpMethod} ${m.path}`, ACTION_DESC_MAX),
        input_schema,
        http: {
          method: String(m.httpMethod).toUpperCase(),
          base_url: baseUrl,
          path: String(m.path),
          params,
          body: bodyMode,
          body_type: "json",
          ...(upload ? { upload } : {}),
          ...(downloads ? { download: true } : {}),
        },
        scopes: Array.isArray(m.scopes) ? (m.scopes as string[]) : [],
        scope: safety.scope,
        risk: safety.risk,
        outward: safety.outward,
        idempotent: safety.idempotent,
        important: false,
        tags: [...new Set(resource.map((r) => toSnake(r).replace(/_/g, " ")))],
        deprecated: m.deprecated === true,
        ...(files ? { files } : {}),
        verification: "mapped",
        origin: { operation: id, http: normalizedHttp(String(m.httpMethod), baseUrl, String(m.path)) },
      });
    } catch (err) {
      warnings.push(`${String(m.id ?? "a method")}: ${(err as Error).message}`);
    }
  }
  return {
    actions,
    warnings,
    base_url: baseUrl,
    ...(typeof d.revision === "string" ? { spec_revision: d.revision } : {}),
    ...(typeof d.version === "string" ? { spec_version: d.version } : {}),
    operations,
  };
}

/** sha256 of the exact text of the document: what `toolkits sync --check` compares. */
export function specHash(raw: string): string {
  return createHash("sha256").update(raw).digest("hex");
}
