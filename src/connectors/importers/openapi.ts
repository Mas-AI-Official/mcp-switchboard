/**
 * OpenAPI 3.x and Swagger 2.0 -> toolkit actions (ADR local-composio, section 6.1).
 *
 * This wraps the flattening `src/openapi.ts` already does for `source: app2mcp` (`buildOperation`: path,
 * query and header parameters plus the JSON body merged into one input schema, `$ref`s inlined with a
 * circular guard) and adds what a connector needs on top of it:
 *
 *   - action slugs that fit `<toolkit>__<action>` in 64 characters, unique, from the `operationId`;
 *   - scope, risk, outward and idempotency from the verb and the name (toolkits.ts `deriveSafety`), with the
 *     `x-mcp-scope` and `x-mcp-risk` vendor extensions as upstream hints that can only tighten;
 *   - file arguments: a `multipart/form-data` property or a Swagger `formData` field typed `file` or
 *     `format: binary`, and an `application/octet-stream` body, become `x-file: upload` arguments;
 *   - a download flag for operations whose success response is a file;
 *   - the provider's OAuth scopes from the operation's `security` requirement;
 *   - a depth cap on pathological inlined schemas (some public specs expand to megabytes).
 *
 * The host a spec names is NOT trusted: the connector sends credentials only to the provider's `api_hosts`
 * (accounts.authFetch), whatever `servers` says. The importer reports the base URL it found; `toolkits sync`
 * refuses a toolkit whose base host is outside `api_hosts`.
 */

import { buildOperation, makeDeref } from "../../openapi.js";
import { deriveSafety, maxActionSlug, sanitizeSchema, toSnake, uniqueSlug, type Action, type ParamBinding } from "../toolkits.js";
import type { ImportOptions, ImportResult } from "./discovery.js";

type Json = Record<string, any>;
const HTTP_METHODS = ["get", "put", "post", "delete", "patch", "head"] as const;
const SCHEMA_SIZE_CAP = 160_000;
const DEPTH_CAP = 4;
const ACTION_DESC_MAX = 400;

const clip = (t: unknown, max: number): string => {
  const s = String(t ?? "").replace(/\s+/g, " ").trim();
  return s.length > max ? `${s.slice(0, max - 3).trimEnd()}...` : s;
};

function baseUrlOf(spec: Json, swagger2: boolean): string {
  if (swagger2) {
    if (!spec.host) throw new Error("the Swagger 2.0 document has no 'host'");
    const schemes: string[] = Array.isArray(spec.schemes) && spec.schemes.length ? spec.schemes : ["https"];
    return `${schemes.includes("https") ? "https" : schemes[0]}://${spec.host}${spec.basePath ?? ""}`.replace(/\/$/, "");
  }
  const server = spec.servers?.[0];
  if (typeof server?.url !== "string") throw new Error("the OpenAPI document has no servers[0].url");
  const vars = server.variables ?? {};
  const url = server.url.replace(/\{([^}]+)\}/g, (_m: string, n: string) => vars[n]?.default ?? `{${n}}`);
  if (!/^https?:\/\//i.test(url)) throw new Error(`servers[0].url '${url}' is not absolute`);
  return url.replace(/\/$/, "");
}

/** Replace objects nested deeper than `max` with an open object, so one operation cannot weigh megabytes. */
function capDepth(node: unknown, max: number, depth = 0): unknown {
  if (Array.isArray(node)) return node.map((n) => capDepth(n, max, depth));
  if (!node || typeof node !== "object") return node;
  const o = node as Json;
  if (o.type === "object" && o.properties && depth >= max) return { type: "object", additionalProperties: true, ...(o.description ? { description: o.description } : {}) };
  const out: Json = {};
  for (const [k, v] of Object.entries(o)) {
    const nextDepth = k === "properties" || k === "items" || k === "additionalProperties" ? depth + (k === "properties" ? 1 : 0) : depth;
    out[k] = capDepth(v, max, nextDepth);
  }
  return out;
}

function scopesOf(op: Json, spec: Json): string[] {
  const sec = (op.security ?? spec.security ?? []) as Json[];
  const out = new Set<string>();
  for (const req of sec) for (const v of Object.values(req)) if (Array.isArray(v)) for (const s of v) if (typeof s === "string") out.add(s);
  return [...out];
}

function isBinarySchema(s: Json | undefined): boolean {
  return Boolean(s && (s.format === "binary" || s.type === "file"));
}

/** Names of body properties that carry a file. */
function fileProps(bodyContent: Json | undefined, deref: (n: unknown) => any): string[] {
  const schema = bodyContent?.["multipart/form-data"]?.schema;
  if (!schema) return [];
  const s = deref(schema) as Json;
  return Object.entries((s.properties ?? {}) as Json)
    .filter(([, v]) => isBinarySchema(deref(v) as Json) || (deref(v) as Json)?.items?.format === "binary")
    .map(([k]) => k);
}

export function importOpenApi(spec: unknown, opts: ImportOptions): ImportResult {
  const s = spec as Json;
  if (!s || typeof s !== "object") throw new Error("the document did not parse to an object");
  const swagger2 = typeof s.swagger === "string" && s.swagger.startsWith("2");
  if (!swagger2 && !s.openapi) throw new Error("this is neither OpenAPI 3.x nor Swagger 2.0");
  const warnings: string[] = [];
  const baseUrl = baseUrlOf(s, swagger2);
  const deref = makeDeref(s);
  const actions: Action[] = [];
  const taken = new Set<string>();
  const flatTaken = new Set<string>();
  const max = maxActionSlug(opts.toolkit);
  let operations = 0;

  for (const [rawPath, item] of Object.entries((s.paths ?? {}) as Json)) {
    if (!item || typeof item !== "object") continue;
    if (!rawPath.startsWith("/")) {
      warnings.push(`path '${rawPath}' does not start with '/': skipped (it could change the request host)`);
      continue;
    }
    const pathParams: any[] = Array.isArray((item as Json).parameters) ? (item as Json).parameters : [];
    for (const method of HTTP_METHODS) {
      const op = (item as Json)[method];
      if (!op || typeof op !== "object") continue;
      operations += 1;
      try {
        const candidate = String(op["x-mcp-tool-name"] ?? op.operationId ?? `${method}_${rawPath}`);
        const slug = uniqueSlug(toSnake(candidate), taken, max);
        const { tool, plan } = buildOperation(rawPath, method, op, pathParams, deref, flatTaken, slug);
        let input = sanitizeSchema(tool.inputSchema) as Json;
        if (JSON.stringify(input).length > SCHEMA_SIZE_CAP) {
          input = capDepth(input, DEPTH_CAP) as Json;
          warnings.push(`${slug}: the input schema was over ${SCHEMA_SIZE_CAP} characters, nested objects deeper than ${DEPTH_CAP} were left open`);
        }
        const params: Record<string, ParamBinding> = {};
        for (const [key, f] of Object.entries(plan.flat)) params[key] = { in: f.location, name: f.originalName, required: f.required };

        // Files and body type.
        let bodyType: "json" | "form" | "multipart" | "binary" = plan.bodyContentType;
        const content = (op.requestBody ? (deref(op.requestBody) as Json).content : undefined) as Json | undefined;
        const uploads: string[] = [];
        if (content && !content["application/json"] && !content["application/x-www-form-urlencoded"]) {
          if (content["multipart/form-data"]) {
            bodyType = "multipart";
            for (const name of fileProps(content, deref)) {
              if (name in (input.properties ?? {})) {
                input.properties[name] = { type: "string", "x-file": "upload", description: clip(input.properties[name]?.description ?? "The file to upload: an absolute path inside an allowlisted folder, an https URL, or staged:<id>.", 240) };
                uploads.push(name);
              }
            }
          } else if (content["application/octet-stream"]) {
            bodyType = "binary";
            const nested = Object.entries(params).find(([, b]) => b.in === "body");
            if (nested && input.properties?.[nested[0]]) {
              input.properties[nested[0]] = { type: "string", "x-file": "upload", description: "The file to upload: an absolute path inside an allowlisted folder, an https URL, or staged:<id>." };
              uploads.push(nested[0]);
            }
          }
        }
        if (swagger2) {
          const formFiles = ((op.parameters ?? []) as Json[]).map((p) => deref(p) as Json).filter((p) => p.in === "formData" && (p.type === "file" || isBinarySchema(p)));
          if (formFiles.length) {
            bodyType = "multipart";
            for (const f of formFiles) {
              const key = f.name as string;
              if (input.properties?.[key]) {
                input.properties[key] = { type: "string", "x-file": "upload", description: "The file to upload: an absolute path inside an allowlisted folder, an https URL, or staged:<id>." };
                uploads.push(key);
              }
            }
          }
        }

        // A file response.
        const ok = (op.responses ?? {})["200"] ?? (op.responses ?? {})["201"] ?? (op.responses ?? {}).default;
        const respContent = ok ? ((deref(ok) as Json).content as Json | undefined) : undefined;
        const download = Boolean(respContent && Object.entries(respContent).some(([ct, v]) => /^(application\/octet-stream|application\/pdf|image\/|video\/|audio\/)/.test(ct) || isBinarySchema(deref((v as Json)?.schema) as Json)));

        const safety = deriveSafety(method, slug, { scope: op["x-mcp-scope"], risk: op["x-mcp-risk"] });
        const bodyKeys = Object.values(params).filter((b) => b.in === "body");
        actions.push({
          slug,
          title: clip(op.summary ?? slug.replace(/_/g, " "), 120),
          description: clip(tool.description ?? `${method.toUpperCase()} ${rawPath}`, ACTION_DESC_MAX),
          input_schema: input,
          http: {
            method: method.toUpperCase(),
            base_url: baseUrl,
            path: rawPath,
            params,
            body: bodyKeys.length ? plan.bodyMode : "none",
            body_type: bodyType,
            ...(download ? { download: true } : {}),
          },
          scopes: scopesOf(op, s),
          scope: safety.scope,
          risk: safety.risk,
          outward: safety.outward,
          idempotent: safety.idempotent,
          important: false,
          tags: Array.isArray(op.tags) ? (op.tags as unknown[]).filter((t): t is string => typeof t === "string").map((t) => t.toLowerCase()) : [],
          deprecated: op.deprecated === true,
          ...(uploads.length ? { files: { upload: uploads, download: [] } } : {}),
          verification: "mapped",
          origin: { operation: String(op.operationId ?? slug), http: `${method.toUpperCase()} ${new URL(baseUrl).pathname.replace(/\/+$/, "")}${rawPath.replace(/\{\+?[^}]+\}/g, "{}")}`.replace(/\/{2,}/g, "/") },
        });
      } catch (err) {
        warnings.push(`${method.toUpperCase()} ${rawPath}: ${(err as Error).message}`);
      }
    }
  }
  return {
    actions,
    warnings,
    base_url: baseUrl,
    ...(typeof s.info?.version === "string" ? { spec_version: s.info.version } : {}),
    operations,
  };
}
