/**
 * localllm.ts — `switchboard local-llm`: detect a local, OpenAI-compatible model server and wire it
 * into the council as the zero-cloud, zero-key provider.
 *
 * The adoption story for non-cloud users: run a model on your own machine (Ollama, LM Studio,
 * llama.cpp's `llama-server`, vLLM — all speak the OpenAI `/v1` API), point MCP Switchboard at it, and
 * the cross-provider council/playground works fully offline with no API key. This module does the
 * boring-but-fiddly parts: probe the usual localhost ports, read the model list, pick a sane default,
 * and merge a `settings.council.providers.local` block into the config WITHOUT touching anything else.
 *
 * Safety rule (same as `install`): MCP Switchboard NEVER downloads or executes an installer. When no
 * server is found we PRINT exact copy-paste steps and stop — the user runs them.
 *
 * The pure pieces (parsers, model picker, config merge, install guide) are exported so the
 * deterministic oracle can prove them without a network or a running model.
 */

import type { LocalProviderConfig, SwitchboardConfig } from "./types.js";

/** A local server we know how to probe. `baseUrl` is the OpenAI-compatible root (ends in `/v1`). */
export interface LocalRuntime {
  id: string;
  label: string;
  baseUrl: string;
  /** Where `GET` returns the OpenAI `{ data: [{ id }] }` model list. */
  modelsUrl: string;
}

const rt = (id: string, label: string, baseUrl: string): LocalRuntime => ({
  id,
  label,
  baseUrl,
  modelsUrl: `${baseUrl}/models`,
});

/** Default ports for the four most common local OpenAI-compatible servers (2026). */
export const KNOWN_RUNTIMES: LocalRuntime[] = [
  rt("ollama", "Ollama", "http://127.0.0.1:11434/v1"),
  rt("lmstudio", "LM Studio", "http://127.0.0.1:1234/v1"),
  rt("llamacpp", "llama.cpp (llama-server)", "http://127.0.0.1:8080/v1"),
  rt("vllm", "vLLM", "http://127.0.0.1:8000/v1"),
];

/** Extract model ids from an OpenAI `/v1/models` body (`{ data: [{ id }] }`). Defensive to junk. */
export function parseOpenAiModels(body: unknown): string[] {
  if (!body || typeof body !== "object") return [];
  const data = (body as { data?: unknown }).data;
  if (!Array.isArray(data)) return [];
  return data
    .map((m) => (m && typeof m === "object" ? (m as { id?: unknown }).id : undefined))
    .filter((x): x is string => typeof x === "string" && x.length > 0);
}

/** Extract model names from Ollama's native `/api/tags` body (`{ models: [{ name }] }`). */
export function parseOllamaTags(body: unknown): string[] {
  if (!body || typeof body !== "object") return [];
  const models = (body as { models?: unknown }).models;
  if (!Array.isArray(models)) return [];
  return models
    .map((m) => (m && typeof m === "object" ? (m as { name?: unknown }).name : undefined))
    .filter((x): x is string => typeof x === "string" && x.length > 0);
}

/** Capable general-chat models, best first — used to pick a default when the user doesn't name one. */
export const PREFERRED_MODELS = ["llama3.1", "llama3", "qwen2.5", "qwen", "mistral", "phi", "gemma"];

/** A model that can't drive a chat-based council relay. Used to warn instead of silently wiring junk. */
export type NonChatKind = "embedding" | "rerank" | "speech" | "image";

/**
 * Name fragments that mark a local model as NOT a general chat/instruct model. Heuristic,
 * case-insensitive, FIRST MATCH WINS — so the more-specific `rerank` is checked before
 * `embedding` (a `bge-reranker` model also contains the `bge-` embedding hint).
 */
const NON_CHAT_FAMILIES: { kind: NonChatKind; hints: string[] }[] = [
  { kind: "rerank", hints: ["rerank"] },
  { kind: "embedding", hints: ["embed", "nomic-embed", "mxbai", "bge-", "gte-", "e5-", "all-minilm", "arctic-embed"] },
  { kind: "speech", hints: ["whisper", "parakeet", "piper", "-tts", "tts-", "bark"] },
  { kind: "image", hints: ["stable-diffusion", "sdxl", "flux.1", "flux-", "playground-v2"] },
];

/**
 * Classify a model id as a usable chat model or a specific non-chat kind (embedding/rerank/speech/image).
 * Heuristic by name only — a box with just `nomic-embed-text` loaded shouldn't be wired as the council
 * voice. Returns "chat" when nothing matches (treat as usable), so it never blocks an unknown model.
 */
export function classifyModel(model: string): NonChatKind | "chat" {
  const m = model.toLowerCase();
  for (const fam of NON_CHAT_FAMILIES) if (fam.hints.some((h) => m.includes(h))) return fam.kind;
  return "chat";
}

/**
 * Pick a default model: the first that matches a preferred family; else the first model that at least
 * looks like a chat model (skipping embedding/rerank/speech/image); else the first available.
 */
export function pickDefaultModel(models: string[], prefer: string[] = PREFERRED_MODELS): string | undefined {
  if (models.length === 0) return undefined;
  for (const p of prefer) {
    const hit = models.find((m) => m.toLowerCase().includes(p));
    if (hit) return hit;
  }
  const chat = models.find((m) => classifyModel(m) === "chat");
  return chat ?? models[0];
}

/** Build the council `local` provider block. No api_key_ref — local servers are keyless by default. */
export function buildLocalProvider(baseUrl: string, model: string): LocalProviderConfig {
  return { base_url: baseUrl, default_model: model };
}

export interface WireResult {
  /** A NEW config object (the input is never mutated). */
  config: SwitchboardConfig;
  /** Whether the merge actually altered anything (false ⇒ already wired identically). */
  changed: boolean;
  /** The resulting council.enabled — false means the tools won't mount until the user flips it. */
  enabled: boolean;
  /** Advisory to surface (e.g. council is disabled). */
  note?: string;
}

/**
 * Merge a local provider into `settings.council.providers.local`, preserving every other setting and
 * any already-configured cloud providers. Creates the council (enabled) when it's entirely absent;
 * respects an explicit prior `enabled: false` rather than silently flipping a deliberate opt-out.
 */
export function withLocalProvider(cfg: SwitchboardConfig, provider: LocalProviderConfig): WireResult {
  const next: SwitchboardConfig = JSON.parse(JSON.stringify(cfg));
  next.settings ??= {};
  const councilExisted = next.settings.council !== undefined;
  next.settings.council ??= { enabled: true };
  const council = next.settings.council;
  council.providers ??= {};
  council.providers.local = provider;
  if (!councilExisted) council.enabled = true; // freshly created ⇒ turn it on; otherwise leave as-is
  const enabled = council.enabled === true;
  const changed = JSON.stringify(cfg) !== JSON.stringify(next);
  const note = enabled
    ? undefined
    : "settings.council.enabled is false — set it to true to mount the council tools.";
  return { config: next, changed, enabled, note };
}

/**
 * Post-wire next-step advice as plain lines (no styling), derived only from the WireResult and the
 * chosen model so the CLI's after-wire guidance is centralized and testable. In order:
 *   1. a correctness WARNING when the wired model doesn't look like a chat model (embedding/rerank/…);
 *   2. the council-disabled note, or the enabled → next-step line;
 *   3. a single-voice hint when `local` is the only provider (`council_debate` needs ≥2 to compare).
 */
export function wireAdvice(result: WireResult, model: string): string[] {
  const lines: string[] = [];
  const kind = classifyModel(model);
  if (kind !== "chat") {
    const article = kind === "embedding" ? "an" : "a";
    lines.push(
      `'${model}' looks like ${article} ${kind} model, not a chat model — the council needs a chat/instruct model. ` +
        "Load one (e.g. `ollama pull llama3.1`) and re-run with `--model <chat-model>`.",
    );
  }
  if (!result.enabled) {
    lines.push(result.note ?? "settings.council.enabled is false — set it to true to mount the council tools.");
  } else {
    lines.push("council is enabled; run `switchboard serve`, then call `council_consult` / `council_debate`.");
    const providers = result.config.settings?.council?.providers ?? {};
    if (Object.keys(providers).length === 1) {
      lines.push(
        "only the local provider is wired — `council_debate` needs two providers to compare. " +
          "Add a cloud key (e.g. `council.providers.anthropic.api_key_ref`) for a real cross-model debate.",
      );
    }
  }
  return lines;
}

/** Exact, copy-paste setup steps. PRINTED ONLY — MCP Switchboard never runs these for you. */
export function installGuide(platform: NodeJS.Platform = process.platform): string[] {
  const steps: string[] = [];
  if (platform === "win32") {
    steps.push("Install Ollama: download https://ollama.com/download/windows and run the installer.");
  } else if (platform === "darwin") {
    steps.push("Install Ollama: `brew install ollama` (or download https://ollama.com/download/mac).");
  } else {
    steps.push("Install Ollama: `curl -fsSL https://ollama.com/install.sh | sh`.");
  }
  steps.push("Pull a small, capable model: `ollama pull llama3.1` (≈4.7 GB; or `qwen2.5:7b`, `mistral`).");
  steps.push("Ollama then serves an OpenAI-compatible API at http://127.0.0.1:11434/v1 — no API key needed.");
  steps.push("Wire it into MCP Switchboard: `switchboard local-llm wire`.");
  steps.push("Prefer a GUI? LM Studio (https://lmstudio.ai) serves the same API at http://127.0.0.1:1234/v1.");
  return steps;
}

export interface ProbeResult {
  runtime: LocalRuntime;
  reachable: boolean;
  models: string[];
  error?: string;
}

/** Probe one runtime's `/v1/models` with a short timeout. Impure (network) — kept out of the oracle. */
export async function probeRuntime(runtime: LocalRuntime, timeoutMs = 1500): Promise<ProbeResult> {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const res = await fetch(runtime.modelsUrl, { signal: ac.signal, headers: { accept: "application/json" } });
    if (!res.ok) return { runtime, reachable: false, models: [], error: `HTTP ${res.status}` };
    const body = await res.json();
    return { runtime, reachable: true, models: parseOpenAiModels(body) };
  } catch (err) {
    return { runtime, reachable: false, models: [], error: err instanceof Error ? err.message : String(err) };
  } finally {
    clearTimeout(timer);
  }
}

/** Probe every known runtime in parallel. */
export async function probeAll(runtimes: LocalRuntime[] = KNOWN_RUNTIMES, timeoutMs = 1500): Promise<ProbeResult[]> {
  return Promise.all(runtimes.map((runtime) => probeRuntime(runtime, timeoutMs)));
}
