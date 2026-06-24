/**
 * Council relay tools — the synthetic in-process MCP server behind `settings.council`.
 *
 * Switchboard already brokers tool calls; the council lets one agent broker a *peer model*.
 * Two tools are exposed:
 *   - `council_consult` — relay a single prompt to a configured provider (Anthropic or
 *     OpenAI) and return its reply. The headline use case: a ChatGPT or Claude client
 *     connected to Switchboard asking the *other* provider for a second opinion.
 *   - `council_debate`  — run a bounded, multi-round exchange between the configured
 *     providers on a topic, then synthesize a moderator's conclusion.
 *
 * Why this is a synthetic MCP `Server` (not a bespoke handler):
 *   It is built exactly like the `app2mcp` server (`openapi.ts`) — a `Server` linked to a
 *   `Client` over an in-memory transport via `Registry.mountLocal`. That means every council
 *   call flows through the SAME router path as any upstream tool: scope inference → policy
 *   ceiling → approval gate → audit log. No governance is duplicated or bypassed.
 *
 * Safety posture:
 *   - Outbound + metered, so the whole feature is OFF by default (`enabled: false`).
 *   - API keys are NEVER held in config — `api_key_ref` is a `${vault:..}`/`${env:..}`
 *     reference resolved through the vault at CALL time, fail-closed (config.ts enforces the
 *     reference form; the vault throws if the secret is missing).
 *   - Model ids are config/param-driven (`default_model`, optional per-call `model`) so a
 *     post-cutoff model rename never silently breaks — nothing is hardcoded.
 *   - Loop/cost guards: `token_budget` caps every call's `max_tokens`; `max_rounds` caps the
 *     debate; the total provider calls per debate are bounded by `rounds * participants + 1`.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js";
import type {
  CouncilConfig,
  CouncilProviderConfig,
  Scope,
} from "./types.js";
import type { Vault } from "./vault.js";

/** Synthetic server id — also the tool namespace (`council__council_consult`, …). */
export const COUNCIL_SERVER_ID = "council";

type ProviderName = "anthropic" | "openai";

const DEFAULT_BASE_URL: Record<ProviderName, string> = {
  anthropic: "https://api.anthropic.com",
  openai: "https://api.openai.com",
};

/** One model turn's result: the text plus token counts for the audit/usage summary. */
interface CallResult {
  text: string;
  inputTokens: number;
  outputTokens: number;
}

/** Providers actually configured (have a key ref + default model). Order is stable. */
function configuredProviders(council: CouncilConfig): ProviderName[] {
  const providers = council.providers ?? {};
  const out: ProviderName[] = [];
  if (providers.anthropic) out.push("anthropic");
  if (providers.openai) out.push("openai");
  return out;
}

function providerConfig(council: CouncilConfig, name: ProviderName): CouncilProviderConfig {
  const cfg = council.providers?.[name];
  if (!cfg) {
    throw new Error(`council provider '${name}' is not configured under settings.council.providers`);
  }
  return cfg;
}

/** Strip a trailing slash so `${base}/v1/...` never doubles up. */
function baseUrl(name: ProviderName, cfg: CouncilProviderConfig): string {
  return (cfg.base_url ?? DEFAULT_BASE_URL[name]).replace(/\/$/, "");
}

/**
 * Anthropic Messages API. `system` is a top-level field; the conversation is a single user
 * turn (the council composes any prior context into the prompt text itself, so there is no
 * multi-turn role-alternation to get wrong). Key resolved from the vault at call time.
 */
async function callAnthropic(
  vault: Vault,
  cfg: CouncilProviderConfig,
  args: { prompt: string; system?: string; model?: string; maxTokens: number },
): Promise<CallResult> {
  const key = vault.resolve(cfg.api_key_ref); // fail-closed: throws if missing
  const model = args.model?.trim() || cfg.default_model;
  const res = await fetch(`${baseUrl("anthropic", cfg)}/v1/messages`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-api-key": key,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model,
      max_tokens: args.maxTokens,
      ...(args.system ? { system: args.system } : {}),
      messages: [{ role: "user", content: args.prompt }],
    }),
  });

  const bodyText = await res.text();
  if (!res.ok) {
    throw new Error(`anthropic ${res.status}: ${bodyText.slice(0, 500)}`);
  }
  const data = JSON.parse(bodyText) as {
    content?: { type: string; text?: string }[];
    usage?: { input_tokens?: number; output_tokens?: number };
  };
  const text = (data.content ?? [])
    .filter((b) => b.type === "text" && typeof b.text === "string")
    .map((b) => b.text as string)
    .join("")
    .trim();
  return {
    text: text || "(empty response)",
    inputTokens: data.usage?.input_tokens ?? 0,
    outputTokens: data.usage?.output_tokens ?? 0,
  };
}

/**
 * OpenAI Chat Completions API. `system` becomes a system message. `max_tokens` is used for
 * broad gpt-4o-class compatibility (note: o1/o3 reasoning models want `max_completion_tokens`
 * — a documented tradeoff; point `default_model` at a chat model or override `base_url`).
 */
async function callOpenAI(
  vault: Vault,
  cfg: CouncilProviderConfig,
  args: { prompt: string; system?: string; model?: string; maxTokens: number },
): Promise<CallResult> {
  const key = vault.resolve(cfg.api_key_ref); // fail-closed: throws if missing
  const model = args.model?.trim() || cfg.default_model;
  const messages: { role: string; content: string }[] = [];
  if (args.system) messages.push({ role: "system", content: args.system });
  messages.push({ role: "user", content: args.prompt });

  const res = await fetch(`${baseUrl("openai", cfg)}/v1/chat/completions`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${key}`,
    },
    body: JSON.stringify({ model, messages, max_tokens: args.maxTokens }),
  });

  const bodyText = await res.text();
  if (!res.ok) {
    throw new Error(`openai ${res.status}: ${bodyText.slice(0, 500)}`);
  }
  const data = JSON.parse(bodyText) as {
    choices?: { message?: { content?: string } }[];
    usage?: { prompt_tokens?: number; completion_tokens?: number };
  };
  const text = (data.choices?.[0]?.message?.content ?? "").trim();
  return {
    text: text || "(empty response)",
    inputTokens: data.usage?.prompt_tokens ?? 0,
    outputTokens: data.usage?.completion_tokens ?? 0,
  };
}

/** Dispatch one turn to the named provider. */
async function dispatch(
  vault: Vault,
  council: CouncilConfig,
  name: ProviderName,
  args: { prompt: string; system?: string; model?: string; maxTokens: number },
): Promise<CallResult> {
  const cfg = providerConfig(council, name);
  return name === "anthropic"
    ? callAnthropic(vault, cfg, args)
    : callOpenAI(vault, cfg, args);
}

/** Clamp a requested round count into `[1, max_rounds]` (the loop guard). */
function clampRounds(requested: unknown, maxRounds: number): number {
  const n = typeof requested === "number" && Number.isFinite(requested) ? Math.floor(requested) : maxRounds;
  return Math.max(1, Math.min(maxRounds, n));
}

/** Validate + dedupe requested participants down to the configured set, preserving order. */
function resolveParticipants(requested: unknown, available: ProviderName[]): ProviderName[] {
  if (!Array.isArray(requested) || requested.length === 0) return available;
  const want = new Set(requested.map((p) => String(p)));
  const picked = available.filter((p) => want.has(p));
  return picked.length ? picked : available;
}

/** A short usage footer appended to every council reply for audit/transparency. */
function usageFooter(calls: CallResult[]): string {
  const input = calls.reduce((s, c) => s + c.inputTokens, 0);
  const output = calls.reduce((s, c) => s + c.outputTokens, 0);
  return `\n\n— council usage: ${calls.length} model call${calls.length === 1 ? "" : "s"}, ${input} in / ${output} out tokens`;
}

/**
 * Build the council MCP server + its per-tool scope hints. Both tools are `write`-scoped
 * (they perform an outbound, metered side effect — not a read), so the router governs and
 * audits them and the synthetic server can carry an approval gate.
 */
export function buildCouncilServer(
  council: CouncilConfig,
  vault: Vault,
): { server: Server; scopeHints: Record<string, Scope>; toolCount: number } {
  const available = configuredProviders(council);
  const maxRounds = council.max_rounds ?? 3;
  const maxTokens = council.token_budget ?? 2048;

  // The provider enum reflects only what's configured, so an agent can't pick a dead provider.
  const providerEnum = available.length ? available : (["anthropic", "openai"] as ProviderName[]);

  const tools: Tool[] = [
    {
      name: "council_consult",
      description:
        "Relay a single prompt to a peer LLM provider and return its reply. Use to get a " +
        "second opinion from the other model (e.g. a Claude client consulting OpenAI, or " +
        "vice-versa). Outbound + metered; governed and audited like any tool.",
      inputSchema: {
        type: "object",
        properties: {
          provider: {
            type: "string",
            enum: providerEnum,
            description: "Which configured provider to consult.",
          },
          prompt: {
            type: "string",
            description: "The question or task to send to the provider.",
          },
          system: {
            type: "string",
            description: "Optional system instruction / role for the provider.",
          },
          model: {
            type: "string",
            description: "Optional model id override; defaults to the provider's configured default_model.",
          },
        },
        required: ["provider", "prompt"],
      },
    },
    {
      name: "council_debate",
      description:
        "Run a bounded multi-round debate between the configured providers on a topic, then " +
        "return a synthesized moderator conclusion plus the full transcript. Needs at least " +
        "two configured providers. Outbound + metered; rounds are capped by settings.council.max_rounds.",
      inputSchema: {
        type: "object",
        properties: {
          topic: {
            type: "string",
            description: "The question or motion the council debates.",
          },
          rounds: {
            type: "number",
            description: `How many rounds each participant speaks. Clamped to 1..${maxRounds}.`,
          },
          participants: {
            type: "array",
            items: { type: "string", enum: providerEnum },
            description: "Subset of configured providers to include. Defaults to all configured.",
          },
        },
        required: ["topic"],
      },
    },
  ];

  const server = new Server(
    { name: `switchboard-council:${COUNCIL_SERVER_ID}`, version: "0.1.0" },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));

  server.setRequestHandler(CallToolRequestSchema, async (request): Promise<CallToolResult> => {
    const name = request.params.name;
    const a = (request.params.arguments ?? {}) as Record<string, unknown>;

    try {
      if (name === "council_consult") {
        const provider = String(a.provider ?? "") as ProviderName;
        if (!available.includes(provider)) {
          throw new Error(
            `provider '${provider}' is not configured. Available: ${available.join(", ") || "(none)"}`,
          );
        }
        const prompt = typeof a.prompt === "string" ? a.prompt : "";
        if (!prompt.trim()) throw new Error("'prompt' is required and must be a non-empty string");

        const result = await dispatch(vault, council, provider, {
          prompt,
          system: typeof a.system === "string" ? a.system : undefined,
          model: typeof a.model === "string" ? a.model : undefined,
          maxTokens,
        });
        return {
          content: [{ type: "text", text: `[${provider}]\n${result.text}${usageFooter([result])}` }],
        };
      }

      if (name === "council_debate") {
        const topic = typeof a.topic === "string" ? a.topic : "";
        if (!topic.trim()) throw new Error("'topic' is required and must be a non-empty string");

        const participants = resolveParticipants(a.participants, available);
        if (participants.length < 2) {
          throw new Error(
            `council_debate needs at least two configured providers; have: ${available.join(", ") || "(none)"}`,
          );
        }
        const rounds = clampRounds(a.rounds, maxRounds);

        const transcript: { provider: ProviderName; round: number; text: string }[] = [];
        const calls: CallResult[] = [];

        for (let round = 1; round <= rounds; round++) {
          for (const p of participants) {
            const others = participants.filter((x) => x !== p).join(", ");
            const opening = transcript.length === 0;
            const system =
              `You are the "${p}" member of an AI council debating with ${others}. ` +
              `Be concise, substantive, and either build on or directly challenge the prior points. ` +
              `This is round ${round} of ${rounds}.`;
            const history = opening
              ? "(you speak first — state your opening position)"
              : transcript.map((t) => `[${t.provider}, round ${t.round}]: ${t.text}`).join("\n\n");
            const prompt =
              `Motion: ${topic}\n\nDebate so far:\n${history}\n\n` +
              `Give your ${opening ? "opening position" : "response"} as ${p}.`;

            const result = await dispatch(vault, council, p, { prompt, system, maxTokens });
            transcript.push({ provider: p, round, text: result.text });
            calls.push(result);
          }
        }

        // Synthesis: the first participant acts as impartial moderator over the full transcript.
        const moderator = participants[0];
        const synthSystem =
          "You are an impartial moderator. Summarize the council debate into one balanced " +
          "conclusion: the strongest point from each side, where they agree, where they differ, " +
          "and a single clear recommendation. Do not take a side beyond the evidence given.";
        const synthPrompt =
          `Motion: ${topic}\n\nFull debate transcript:\n` +
          transcript.map((t) => `[${t.provider}, round ${t.round}]: ${t.text}`).join("\n\n") +
          `\n\nProduce the synthesis.`;
        const synthesis = await dispatch(vault, council, moderator, {
          prompt: synthPrompt,
          system: synthSystem,
          maxTokens,
        });
        calls.push(synthesis);

        const transcriptText = transcript
          .map((t) => `### ${t.provider} — round ${t.round}\n${t.text}`)
          .join("\n\n");
        const text =
          `# Council debate: ${topic}\n\n` +
          `## Synthesis (moderator: ${moderator})\n${synthesis.text}\n\n` +
          `## Transcript\n${transcriptText}${usageFooter(calls)}`;
        return { content: [{ type: "text", text }] };
      }

      throw new Error(`unknown council tool: ${name}`);
    } catch (err) {
      return {
        content: [{ type: "text", text: `council error: ${err instanceof Error ? err.message : String(err)}` }],
        isError: true,
      };
    }
  });

  return {
    server,
    scopeHints: { council_consult: "write", council_debate: "write" },
    toolCount: tools.length,
  };
}
