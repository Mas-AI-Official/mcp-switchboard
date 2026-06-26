/**
 * Tool-shaping transforms — MCP Switchboard's answer to Composio's "modifiers".
 *
 * Three pure functions sit on the request/response path:
 *   - shapeExposedTool   : rewrite the tool AS AGENTS SEE IT (description, dropped/hidden/renamed
 *                          params, optional required-only slimming) — feeds BOTH listTools and search.
 *   - applyArgTransforms : rewrite agent-supplied args into what is actually sent UPSTREAM
 *                          (reverse renames, then overlay injected/pinned values).
 *   - applyResponseRedaction : strip/replace top-level JSON fields from a result before the agent sees it.
 *
 * Everything here is pure and clones its inputs — the upstream tool list and live results are never
 * mutated — so a deterministic verifier can exercise each function in isolation. We deliberately
 * NEVER stamp `additionalProperties:false` onto a shaped schema: dropping params must not turn a
 * permissive upstream schema into a strict one that rejects calls the upstream would have accepted.
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { ResponseRedaction, SchemaModifier, ServerConfig, ToolOverride } from "./types.js";

/** Resolves a `${vault:..}`/`${env:..}` reference to its value; a literal with no `${...}` passes through. */
export type SecretResolver = (ref: string) => string;

/** Loose view of a JSON-Schema object — enough to add/drop/rename properties without fighting the SDK type. */
type JsonSchema = {
  type?: unknown;
  properties?: Record<string, unknown>;
  required?: string[];
  [k: string]: unknown;
};

/**
 * Merge a server-level modifier with a per-tool one. Lists union (deduped); rename maps merge with the
 * tool winning on a key collision; trim_description takes the tool value when present, else the server.
 */
function mergeSchemaModifier(serverMod?: SchemaModifier, toolMod?: SchemaModifier): SchemaModifier {
  const hide = [...(serverMod?.hide_params ?? []), ...(toolMod?.hide_params ?? [])];
  const rename = { ...(serverMod?.rename_params ?? {}), ...(toolMod?.rename_params ?? {}) };
  return {
    hide_params: hide.length ? Array.from(new Set(hide)) : undefined,
    rename_params: Object.keys(rename).length ? rename : undefined,
    trim_description: toolMod?.trim_description ?? serverMod?.trim_description,
  };
}

/** exposed-name -> upstream-name. rename_params is keyed upstream->exposed, so this inverts it. */
function reverseRenameMap(mod: SchemaModifier): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [upstream, exposed] of Object.entries(mod.rename_params ?? {})) {
    out[exposed] = upstream;
  }
  return out;
}

/**
 * Produce the tool AS AGENTS SEE IT: description override/trim, dropped+hidden params removed from the
 * input schema (and from `required`), optional `required_only` slimming, then param renames. Pure —
 * clones the input, never mutates the upstream tool, never adds `additionalProperties:false`.
 */
export function shapeExposedTool(
  tool: Tool,
  serverCfg: ServerConfig,
  override?: ToolOverride,
): Tool {
  const clone = structuredClone(tool) as Tool;
  const mod = mergeSchemaModifier(serverCfg.schema_modifiers, override?.schema_modifiers);

  // --- description ---
  if (override?.description_override !== undefined) {
    clone.description = override.description_override;
  } else if (
    mod.trim_description !== undefined &&
    typeof clone.description === "string" &&
    clone.description.length > mod.trim_description
  ) {
    clone.description = clone.description.slice(0, mod.trim_description);
  }

  // --- input schema ---
  const schema = clone.inputSchema as JsonSchema | undefined;
  if (schema && typeof schema === "object") {
    const props =
      schema.properties && typeof schema.properties === "object"
        ? (schema.properties as Record<string, unknown>)
        : undefined;
    let required = Array.isArray(schema.required) ? [...schema.required] : [];

    // 1. drop_params ∪ hide_params: remove from properties and from required.
    const remove = new Set<string>([...(override?.drop_params ?? []), ...(mod.hide_params ?? [])]);
    if (props) for (const key of remove) delete props[key];
    required = required.filter((r) => !remove.has(r));

    // 2. schema_mode required_only: keep only properties that remain required (slims the schema).
    if (serverCfg.schema_mode === "required_only" && props) {
      const keep = new Set(required);
      for (const key of Object.keys(props)) if (!keep.has(key)) delete props[key];
    }

    // 3. rename_params (upstream -> exposed): rename in properties and in required.
    for (const [from, to] of Object.entries(mod.rename_params ?? {})) {
      if (props && Object.prototype.hasOwnProperty.call(props, from)) {
        props[to] = props[from];
        delete props[from];
      }
      required = required.map((r) => (r === from ? to : r));
    }

    if (props) schema.properties = props;
    if (required.length) schema.required = required;
    else delete schema.required;
  }

  return clone;
}

/**
 * Names of originally-required params that the shaping removed AND for which no value is injected.
 * Agents cannot satisfy these (the upstream will reject the call), so the router warns once per tool.
 */
export function removedRequiredNotInjected(
  tool: Tool,
  serverCfg: ServerConfig,
  override?: ToolOverride,
): string[] {
  const schema = tool.inputSchema as JsonSchema | undefined;
  const required = schema && Array.isArray(schema.required) ? schema.required : [];
  if (!required.length) return [];
  const mod = mergeSchemaModifier(serverCfg.schema_modifiers, override?.schema_modifiers);
  const remove = new Set<string>([...(override?.drop_params ?? []), ...(mod.hide_params ?? [])]);
  const injected = new Set<string>([
    ...Object.keys(serverCfg.inject_args ?? {}),
    ...Object.keys(override?.inject_args ?? {}),
  ]);
  return required.filter((r) => remove.has(r) && !injected.has(r));
}

/**
 * The argument names `applyArgTransforms` overlays with an injected value (server-level merged with
 * per-tool, tool wins). An injected value is almost always a resolved `${vault:..}`/`${oauth:..}`/
 * `${env:..}` secret, and the operator chooses the key it lands under — which may look perfectly
 * benign (`q`, `query`, `id`). Audit I/O capture redacts secret-LOOKING key names by regex, so a
 * secret injected under a non-secret-looking key would slip into `audit.log` in cleartext. This set
 * is the exact, name-agnostic redaction list for the capture path. Pure.
 */
export function injectedArgKeys(serverCfg: ServerConfig, override?: ToolOverride): Set<string> {
  return new Set<string>([
    ...Object.keys(serverCfg.inject_args ?? {}),
    ...Object.keys(override?.inject_args ?? {}),
  ]);
}

/**
 * Transform agent-supplied arguments into what is actually sent upstream: first reverse-map renamed
 * keys back to their upstream names, then overlay injected values (server then tool, tool wins).
 * Injected values resolve `${vault:..}`/`${env:..}` refs (or pass a literal through) and ALWAYS win
 * over an agent-supplied value for the same key. Pure aside from `resolveSecret`.
 */
export function applyArgTransforms(
  args: Record<string, unknown>,
  serverCfg: ServerConfig,
  override: ToolOverride | undefined,
  resolveSecret: SecretResolver,
): Record<string, unknown> {
  const mod = mergeSchemaModifier(serverCfg.schema_modifiers, override?.schema_modifiers);
  const reverse = reverseRenameMap(mod);

  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(args ?? {})) {
    out[reverse[key] ?? key] = value;
  }

  const inject = { ...(serverCfg.inject_args ?? {}), ...(override?.inject_args ?? {}) };
  for (const [key, ref] of Object.entries(inject)) {
    out[key] = resolveSecret(ref);
  }
  return out;
}

/**
 * Redact top-level JSON fields from a tool's text result before it reaches the agent. A per-tool
 * `redact_response` overrides the server-level one. Only well-formed top-level JSON OBJECTS are
 * touched; non-JSON text, JSON arrays, and primitives pass through unchanged. Clones — never mutates input.
 */
export function applyResponseRedaction<
  T extends { content?: Array<Record<string, unknown>>; [k: string]: unknown },
>(result: T, serverCfg: ServerConfig, override?: ToolOverride): T {
  const redaction: ResponseRedaction | undefined =
    override?.redact_response ?? serverCfg.redact_response;
  const fields = redaction?.fields;
  if (!redaction || !fields || !fields.length || !Array.isArray(result?.content)) {
    return result;
  }

  const clone = structuredClone(result) as T;
  for (const item of clone.content ?? []) {
    if (item?.type !== "text" || typeof item.text !== "string") continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(item.text);
    } catch {
      continue; // not JSON — leave the text untouched
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) continue;
    const obj = parsed as Record<string, unknown>;
    let changed = false;
    for (const f of fields) {
      if (Object.prototype.hasOwnProperty.call(obj, f)) {
        if (redaction.replace_with !== undefined) obj[f] = redaction.replace_with;
        else delete obj[f];
        changed = true;
      }
    }
    if (changed) item.text = JSON.stringify(obj);
  }
  return clone;
}
