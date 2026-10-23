/**
 * app2mcp — OpenAPI / Swagger → generated MCP server (Phase 4).
 *
 * Turns an OpenAPI 3.x or Swagger 2.0 spec into a real in-process MCP `Server`:
 * each operation (path × method) becomes one tool whose `inputSchema` is the
 * flattened union of its path / query / header parameters and JSON request body.
 * Tool calls (and the spec fetch itself) go through the SSRF guard (`guardedFetch`, src/netguard.ts):
 * **zero deps**. Private, loopback and metadata targets are refused unless the exact host is in
 * `settings.network.allow_private`, redirects are re-validated hop by hop and never carry credentials
 * to another origin, and every call has a deadline and a response-size cap. A spec is untrusted input:
 * when the server carries credentials or inject_args, the base URL must be set explicitly in the config
 * and the spec's own `servers` host must match it (see `assertCredentialHost`).
 *
 * Scope inference follows the project rule: GET/HEAD → read, POST/PUT/PATCH →
 * write, DELETE → full. The generated server does NOT itself enforce scope — the
 * gateway's Router/Policy engine governs every call before it reaches here — but
 * it surfaces a per-tool `scopeHints` map so the policy engine classifies each
 * generated tool by its HTTP verb instead of guessing from the tool name.
 *
 * Auth is injected per call via `resolveHeaders()` (so OAuth tokens refresh) and
 * merged with any per-operation header parameters.
 */

import { readFileSync } from "node:fs";
import { resolve as resolvePath } from "node:path";
import { parse as parseYaml } from "yaml";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import type { Scope, ServerConfig } from "./types.js";
import { BULK_DOCUMENT_MAX_BYTES, BULK_DOCUMENT_TIMEOUT_MS, guardedFetch, type NetworkSource } from "./netguard.js";
import { dotSegmentProblem, pathParamProblem } from "./pathparam.js";

const HTTP_METHODS = ["get", "put", "post", "delete", "options", "head", "patch", "trace"] as const;
const MAX_RESPONSE_CHARS = 50_000;

type ParamLocation = "path" | "query" | "header" | "body";

interface FlatParam {
  location: ParamLocation;
  /** The real name to send upstream. `__body__` means "the entire request body". */
  originalName: string;
  required: boolean;
}

interface GeneratedOp {
  toolName: string;
  method: string; // upper-case HTTP method
  pathTemplate: string; // e.g. /pet/{petId}
  scope: Scope;
  bodyMode: "none" | "merged" | "nested";
  bodyContentType: "json" | "form";
  flat: Record<string, FlatParam>;
}

export interface OpenApiServer {
  server: Server;
  scopeHints: Record<string, Scope>;
  toolCount: number;
}

/** GET/HEAD/OPTIONS/TRACE → read, DELETE → full, everything else → write. */
function scopeForMethod(method: string): Scope {
  const m = method.toLowerCase();
  if (m === "get" || m === "head" || m === "options" || m === "trace") return "read";
  if (m === "delete") return "full";
  return "write";
}

/**
 * Build a `$ref` resolver over `root`. References are inlined; a `$ref` that is
 * already being expanded on the current branch resolves to `{}` (circular guard),
 * and a dangling pointer resolves to `{}` (fail-soft, never throw mid-generation).
 * Supports OpenAPI 3.x (`#/components/...`) and Swagger 2.0 (`#/definitions/...`).
 */
function makeDeref(root: unknown): (node: unknown) => any {
  function resolvePointer(ref: string): unknown {
    if (!ref.startsWith("#/")) return undefined;
    const parts = ref.slice(2).split("/").map((p) => p.replace(/~1/g, "/").replace(/~0/g, "~"));
    let cur: any = root;
    for (const part of parts) {
      if (cur == null || typeof cur !== "object") return undefined;
      cur = cur[part];
    }
    return cur;
  }
  function deref(node: any, active: Set<string>): any {
    if (node == null || typeof node !== "object") return node;
    if (Array.isArray(node)) return node.map((n) => deref(n, active));
    if (typeof node.$ref === "string") {
      const ref = node.$ref;
      if (active.has(ref)) return {};
      const target = resolvePointer(ref);
      if (target === undefined) return {};
      const next = new Set(active);
      next.add(ref);
      return deref(target, next);
    }
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(node)) out[k] = deref(v, active);
    return out;
  }
  return (node: unknown) => deref(node, new Set<string>());
}

/** Coerce an OpenAPI/Swagger parameter into a JSON Schema fragment. */
function paramSchema(param: any, deref: (n: unknown) => any): any {
  if (param.schema) return deref(param.schema); // OpenAPI 3.x
  // Swagger 2.0 inline typing.
  const schema: any = { type: param.type ?? "string" };
  if (param.format) schema.format = param.format;
  if (param.items) schema.items = deref(param.items);
  if (param.enum) schema.enum = param.enum;
  if (param.description) schema.description = param.description;
  return schema;
}

/** Sanitize to the MCP tool-name charset `[a-z0-9_-]{1,64}`, truncated for headroom. */
function sanitizeName(raw: string): string {
  let name = raw.toLowerCase().replace(/[^a-z0-9_-]/g, "_");
  name = name.replace(/_+/g, "_").replace(/^[_-]+/, "");
  if (name.length === 0) name = "op";
  if (name.length > 56) name = name.slice(0, 56).replace(/[_-]+$/, "");
  return name;
}

/** A key not already present in `taken`, suffixed `_2`, `_3`, … on collision. */
function uniqueKey(base: string, taken: Set<string>): string {
  if (!taken.has(base)) return base;
  let i = 2;
  while (taken.has(`${base}_${i}`)) i += 1;
  return `${base}_${i}`;
}

/** Load + parse a spec from a local path or http(s) URL. YAML parser also reads JSON. */
async function loadSpec(source: string, network: NetworkSource): Promise<any> {
  let raw: string;
  if (/^https?:\/\//i.test(source)) {
    // Specs are bulk public documents (a large API's spec runs to many MiB), so they get the bulk caps,
    // not the tool-response cap; the address checks and redirect rules are the same as for any call.
    const resp = await guardedFetch(source, { maxBytes: BULK_DOCUMENT_MAX_BYTES, timeoutMs: BULK_DOCUMENT_TIMEOUT_MS }, network);
    if (!resp.ok) {
      throw new Error(`failed to fetch OpenAPI spec '${source}': HTTP ${resp.status}`);
    }
    raw = await resp.text();
  } else {
    raw = readFileSync(resolvePath(source), "utf8");
  }
  const parsed = parseYaml(raw);
  if (parsed == null || typeof parsed !== "object") {
    throw new Error(`OpenAPI spec '${source}' did not parse to an object`);
  }
  return parsed;
}

/**
 * Derive the absolute base URL. Precedence: explicit `config.base_url` >
 * OpenAPI 3.x `servers[0].url` (with `{var}` defaults substituted) > Swagger 2.0
 * `schemes`+`host`+`basePath`. Fail closed (throw) if none yields an absolute URL —
 * we never invent a host or silently call a relative path.
 */
function deriveBaseUrl(config: ServerConfig, spec: any, isSwagger2: boolean): string {
  if (config.base_url) return config.base_url.replace(/\/$/, "");

  if (isSwagger2) {
    if (!spec.host) {
      throw new Error(`server '${config.id}': Swagger 2.0 spec has no 'host'; set base_url in the config`);
    }
    const schemes: string[] = Array.isArray(spec.schemes) && spec.schemes.length ? spec.schemes : ["https"];
    const scheme = schemes.includes("https") ? "https" : schemes[0];
    return `${scheme}://${spec.host}${spec.basePath ?? ""}`.replace(/\/$/, "");
  }

  const server = spec.servers?.[0];
  let url: string | undefined = server?.url;
  if (!url) {
    throw new Error(`server '${config.id}': spec has no servers[0].url; set base_url in the config`);
  }
  const vars = server.variables ?? {};
  url = url.replace(/\{([^}]+)\}/g, (_m: string, name: string) => vars[name]?.default ?? `{${name}}`);
  if (url.startsWith("/")) {
    throw new Error(`server '${config.id}': servers[0].url '${url}' is relative; set base_url in the config`);
  }
  return url.replace(/\/$/, "");
}

const hasKeys = (o?: Record<string, unknown>) => !!o && Object.keys(o).length > 0;

/** True when calls made through this server carry the operator's secrets or forced arguments. */
function carriesCredentials(config: ServerConfig): boolean {
  return (
    hasKeys(config.credentials) ||
    hasKeys(config.inject_args) ||
    Object.values(config.tools ?? {}).some((t) => hasKeys(t?.inject_args)) ||
    Boolean(config.auth_scheme) ||
    (config.auth !== undefined && config.auth !== "none")
  );
}

/** The host (and non-default port) the spec itself declares for its API, or undefined when it names none. */
function specDeclaredHost(spec: any, isSwagger2: boolean): string | undefined {
  try {
    if (isSwagger2) return typeof spec.host === "string" && spec.host ? new URL(`https://${spec.host}`).host : undefined;
    const server = spec.servers?.[0];
    if (typeof server?.url !== "string") return undefined;
    const vars = server.variables ?? {};
    const url = server.url.replace(/\{([^}]+)\}/g, (_m: string, name: string) => vars[name]?.default ?? `{${name}}`);
    return /^https?:\/\//i.test(url) ? new URL(url).host : undefined;
  } catch {
    return undefined;
  }
}

/**
 * A spec is attacker-influenced input. When the server carries credentials or inject_args, the host
 * they are sent to must be the operator's, not the spec's: `base_url` is required, and a spec whose own
 * `servers[0]` (or Swagger `host`) names a different host is refused rather than silently ignored,
 * because a mismatch means a stale or hostile spec.
 */
function assertCredentialHost(config: ServerConfig, spec: any, isSwagger2: boolean): void {
  if (!carriesCredentials(config)) return;
  if (!config.base_url) {
    throw new Error(
      `server '${config.id}': it carries credentials or inject_args, so base_url must be set explicitly; ` +
        `the host the spec declares is not trusted with them`,
    );
  }
  let baseHost: string;
  try {
    baseHost = new URL(config.base_url).host;
  } catch {
    throw new Error(`server '${config.id}': base_url '${config.base_url}' is not a valid absolute URL`);
  }
  const declared = specDeclaredHost(spec, isSwagger2);
  if (declared && declared.toLowerCase() !== baseHost.toLowerCase()) {
    throw new Error(
      `server '${config.id}': the spec declares host '${declared}' but base_url is host '${baseHost}'; ` +
        `refusing to send credentials until the two agree (use a trusted copy of the spec or fix base_url)`,
    );
  }
}

/** Flatten one operation into a tool definition + an invocation plan. */
function buildOperation(
  rawPath: string,
  method: string,
  op: any,
  pathLevelParams: any[],
  deref: (n: unknown) => any,
  takenToolNames: Set<string>,
): { tool: Tool; plan: GeneratedOp } {
  const candidate = op["x-mcp-tool-name"] ?? op.operationId ?? `${method}_${sanitizeName(rawPath)}`;
  const toolName = uniqueKey(sanitizeName(String(candidate)), takenToolNames);
  takenToolNames.add(toolName);

  const properties: Record<string, any> = {};
  const required: string[] = [];
  const flat: Record<string, FlatParam> = {};
  const takenKeys = new Set<string>();

  // --- parameters (path / query / header); body/formData handled separately ---
  const rawParams: any[] = [...pathLevelParams, ...(op.parameters ?? [])].map((p) => deref(p));
  const valueParams = rawParams.filter((p) => p.in === "path" || p.in === "query" || p.in === "header");
  for (const p of valueParams) {
    if (!p.name || !p.in) continue;
    const key = uniqueKey(p.name, takenKeys);
    takenKeys.add(key);
    const schema = paramSchema(p, deref);
    if (p.description && !schema.description) schema.description = p.description;
    properties[key] = schema;
    if (p.required) required.push(key);
    flat[key] = { location: p.in as ParamLocation, originalName: p.name, required: Boolean(p.required) };
  }

  // --- request body (OpenAPI 3.x requestBody, Swagger 2.0 in:body / in:formData) ---
  let bodySchema: any;
  let bodyRequired = false;
  let bodyContentType: "json" | "form" = "json";

  if (op.requestBody) {
    const rb = deref(op.requestBody);
    bodyRequired = Boolean(rb.required);
    const content: Record<string, any> = rb.content ?? {};
    if (content["application/json"]?.schema) {
      bodySchema = content["application/json"].schema;
    } else if (content["application/x-www-form-urlencoded"]?.schema) {
      bodySchema = content["application/x-www-form-urlencoded"].schema;
      bodyContentType = "form";
    } else {
      const first = Object.values(content)[0];
      if (first?.schema) bodySchema = first.schema;
    }
  } else {
    const bodyParam = rawParams.find((p) => p.in === "body"); // Swagger 2.0
    const formParams = rawParams.filter((p) => p.in === "formData"); // Swagger 2.0
    if (bodyParam?.schema) {
      bodySchema = bodyParam.schema;
      bodyRequired = Boolean(bodyParam.required);
    } else if (formParams.length) {
      bodyContentType = "form";
      bodySchema = {
        type: "object",
        properties: Object.fromEntries(formParams.map((f) => [f.name, paramSchema(f, deref)])),
        required: formParams.filter((f) => f.required).map((f) => f.name),
      };
      bodyRequired = formParams.some((f) => f.required);
    }
  }

  let bodyMode: GeneratedOp["bodyMode"] = "none";
  if (bodySchema) {
    const bs = deref(bodySchema);
    const props: Record<string, any> | undefined =
      bs && bs.type === "object" && bs.properties && typeof bs.properties === "object" ? bs.properties : undefined;
    const collides = props ? Object.keys(props).some((k) => k in properties) : true;
    if (props && !collides) {
      // Merge object body fields up to the top level (the common, ergonomic case).
      bodyMode = "merged";
      const bodyReq: string[] = Array.isArray(bs.required) ? bs.required : [];
      for (const [k, sub] of Object.entries(props)) {
        properties[k] = sub;
        flat[k] = { location: "body", originalName: k, required: bodyReq.includes(k) };
        if (bodyReq.includes(k)) required.push(k);
      }
    } else {
      // Non-object body, or a name collision with a path/query/header param → nest it.
      bodyMode = "nested";
      const key = uniqueKey("body", takenKeys);
      takenKeys.add(key);
      properties[key] = bs;
      flat[key] = { location: "body", originalName: "__body__", required: bodyRequired };
      if (bodyRequired) required.push(key);
    }
  }

  const description = String(op.summary ?? op.description ?? `${method.toUpperCase()} ${rawPath}`).slice(0, 400);
  const tool: Tool = {
    name: toolName,
    description,
    inputSchema: { type: "object", properties, ...(required.length ? { required } : {}) },
  };
  const plan: GeneratedOp = {
    toolName,
    method: method.toUpperCase(),
    pathTemplate: rawPath,
    scope: scopeForMethod(method),
    bodyMode,
    bodyContentType,
    flat,
  };
  return { tool, plan };
}

/** Execute one generated operation as an HTTP request and shape the MCP result. */
async function invokeOperation(
  baseUrl: string,
  op: GeneratedOp,
  args: Record<string, unknown>,
  authHeaders: Record<string, string>,
  network: NetworkSource,
): Promise<CallToolResult> {
  let path = op.pathTemplate;
  const queryPairs: [string, string][] = [];
  const headers: Record<string, string> = { accept: "application/json", ...authHeaders };
  const mergedBody: Record<string, unknown> = {};
  let wholeBody: unknown;
  let haveWholeBody = false;

  for (const [key, meta] of Object.entries(op.flat)) {
    if (!(key in args)) continue;
    const value = args[key];
    if (value === undefined) continue;
    switch (meta.location) {
      case "path": {
        const serialized = Array.isArray(value) ? value.join(",") : String(value);
        // `.` and `..` survive encodeURIComponent and are navigation to a URL parser: refuse before a request exists.
        const bad = pathParamProblem(serialized);
        if (bad) {
          return { content: [{ type: "text", text: `refusing request: path parameter '${meta.originalName}': ${bad}` }], isError: true };
        }
        path = path.replace(`{${meta.originalName}}`, encodeURIComponent(serialized));
        break;
      }
      case "query": {
        if (Array.isArray(value)) {
          for (const v of value) queryPairs.push([meta.originalName, String(v)]);
        } else if (value !== null) {
          queryPairs.push([meta.originalName, String(value)]);
        }
        break;
      }
      case "header": {
        if (value !== null) headers[meta.originalName] = String(value);
        break;
      }
      case "body": {
        if (meta.originalName === "__body__") {
          wholeBody = value;
          haveWholeBody = true;
        } else {
          mergedBody[meta.originalName] = value;
        }
        break;
      }
    }
  }

  // Two values that only form a dot segment together (`{a}{b}`), or a template that carries one, are refused too.
  const dot = dotSegmentProblem(path);
  if (dot) return { content: [{ type: "text", text: `refusing request: path parameter substitution: ${dot}` }], isError: true };
  const url = new URL(baseUrl + path);
  // Belt and braces behind the build-time path check: the final URL must stay on the base origin.
  if (url.origin !== new URL(baseUrl).origin) {
    return { content: [{ type: "text", text: "refusing request: the operation path changes the host of the base URL" }], isError: true };
  }
  for (const [k, v] of queryPairs) url.searchParams.append(k, v);

  let payload: string | undefined;
  const sendsBody = op.method !== "GET" && op.method !== "HEAD";
  let body: unknown;
  if (haveWholeBody) body = wholeBody;
  else if (op.bodyMode === "merged" && Object.keys(mergedBody).length) body = mergedBody;

  if (sendsBody && body !== undefined) {
    if (op.bodyContentType === "form" && body !== null && typeof body === "object") {
      const form = new URLSearchParams();
      for (const [k, v] of Object.entries(body as Record<string, unknown>)) form.append(k, String(v));
      payload = form.toString();
      headers["content-type"] = "application/x-www-form-urlencoded";
    } else {
      payload = JSON.stringify(body);
      headers["content-type"] = "application/json";
    }
  }

  let resp: Awaited<ReturnType<typeof guardedFetch>>;
  try {
    // Every header except accept/content-type may carry a secret (auth headers, operation header params).
    const sensitive = Object.keys(headers).filter((h) => h !== "accept" && h !== "content-type");
    resp = await guardedFetch(url, { method: op.method, headers, body: payload, credentialHeaders: sensitive }, network);
  } catch (err) {
    return {
      content: [{ type: "text", text: `request to ${op.method} ${url.pathname} failed: ${(err as Error).message}` }],
      isError: true,
    };
  }

  const text = await resp.text();
  const shown =
    text.length > MAX_RESPONSE_CHARS
      ? `${text.slice(0, MAX_RESPONSE_CHARS)}\n…[truncated ${text.length - MAX_RESPONSE_CHARS} chars]`
      : text;
  return {
    content: [{ type: "text", text: `HTTP ${resp.status} ${resp.statusText}\n\n${shown}` }],
    isError: resp.status >= 400,
  };
}

/**
 * Build an in-process MCP `Server` from an OpenAPI/Swagger spec. The registry
 * links this server to a real SDK `Client` over an in-memory transport, so the
 * rest of the gateway treats it identically to a mounted external server.
 *
 * @param resolveHeaders called per tool-call to produce auth headers (e.g.
 *   `{ Authorization: "Bearer …" }`) — async so OAuth tokens can refresh.
 * @param network the live `settings.network` (or a thunk returning it) for the SSRF guard.
 */
export async function buildOpenApiServer(
  config: ServerConfig,
  resolveHeaders: () => Promise<Record<string, string>>,
  network?: NetworkSource,
): Promise<OpenApiServer> {
  if (!config.openapi) {
    throw new Error(`server '${config.id}': source 'app2mcp' requires an 'openapi' spec path or URL`);
  }

  const spec = await loadSpec(config.openapi, network);
  const isSwagger2 = typeof spec.swagger === "string" && spec.swagger.startsWith("2");
  if (!isSwagger2 && !spec.openapi) {
    throw new Error(`server '${config.id}': '${config.openapi}' is neither OpenAPI 3.x nor Swagger 2.0`);
  }

  assertCredentialHost(config, spec, isSwagger2);
  const baseUrl = deriveBaseUrl(config, spec, isSwagger2);
  const deref = makeDeref(spec);

  const tools: Tool[] = [];
  const plans = new Map<string, GeneratedOp>();
  const scopeHints: Record<string, Scope> = {};
  const takenToolNames = new Set<string>();
  const warnings: string[] = [];

  const paths: Record<string, any> = spec.paths ?? {};
  for (const [rawPath, pathItem] of Object.entries(paths)) {
    if (!pathItem || typeof pathItem !== "object") continue;
    // A path key is appended to the base URL. One that does not start with "/" ("@evil.example/x",
    // ".evil.example/x", ":99/x") would rewrite the host of the final URL, so it is never mounted.
    if (!rawPath.startsWith("/")) {
      warnings.push(`path '${rawPath}': does not start with '/', skipped (it could change the request host)`);
      continue;
    }
    const pathLevelParams: any[] = Array.isArray((pathItem as any).parameters) ? (pathItem as any).parameters : [];
    for (const method of HTTP_METHODS) {
      const op = (pathItem as any)[method];
      if (!op || typeof op !== "object") continue;
      try {
        const { tool, plan } = buildOperation(rawPath, method, op, pathLevelParams, deref, takenToolNames);
        tools.push(tool);
        plans.set(tool.name, plan);
        scopeHints[tool.name] = plan.scope;
      } catch (err) {
        // Validate-but-warn: a single malformed operation never kills the mount.
        warnings.push(`${method.toUpperCase()} ${rawPath}: ${(err as Error).message}`);
      }
    }
  }

  if (tools.length === 0) {
    throw new Error(`server '${config.id}': OpenAPI spec '${config.openapi}' yielded zero callable operations`);
  }
  if (warnings.length) {
    console.error(`[switchboard] app2mcp '${config.id}' skipped ${warnings.length} operation(s):`);
    for (const w of warnings) console.error(`  - ${w}`);
  }

  const server = new Server(
    { name: `switchboard-openapi:${config.id}`, version: "0.1.0" },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
  server.setRequestHandler(CallToolRequestSchema, async (request): Promise<CallToolResult> => {
    const plan = plans.get(request.params.name);
    if (!plan) {
      return { content: [{ type: "text", text: `unknown tool '${request.params.name}'` }], isError: true };
    }
    const args = (request.params.arguments ?? {}) as Record<string, unknown>;
    let authHeaders: Record<string, string>;
    try {
      authHeaders = await resolveHeaders();
    } catch (err) {
      // Fail closed: a missing/expired credential must not silently send an unauthenticated call.
      return { content: [{ type: "text", text: `credential error: ${(err as Error).message}` }], isError: true };
    }
    return invokeOperation(baseUrl, plan, args, authHeaders, network);
  });

  return { server, scopeHints, toolCount: tools.length };
}
