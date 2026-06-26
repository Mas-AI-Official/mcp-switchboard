## Title

Show HN: MCP Switchboard – one governed MCP endpoint shared by Claude and ChatGPT

## Body

If you use both Claude and ChatGPT to actually do things — read GitHub, triage Gmail, update Notion, ping Slack, hit your internal API — you've probably hit two walls.

First, the N×M wiring. Every client (Claude Desktop, Claude Code, Cursor, VS Code, ChatGPT, your own agents) has to be wired to every app, by hand, in its own config format. Add a tool and you redo it everywhere.

Second, the "easy" shortcut. Hosted tool routers solve the wiring, but they do it by parking your OAuth tokens on their server and metering your calls. For a lot of us that trade isn't acceptable.

MCP Switchboard is a local-first, governed MCP aggregator that tries to fix both. You run one local process that re-exposes all your MCP servers behind one governed endpoint. You add that endpoint once in Claude and once in ChatGPT, and now both reach the same tools through the same encrypted local vault, the same on/off + read/write/full policy, the same approval gates, and the same audit log. It collapses N×M wiring into N×1.

How it works, concretely:

- Your bring-your-own keys live in a local AES-256-GCM vault on your machine. There's zero token custody — nothing is parked on a vendor server. Config files only ever hold ${vault:..} / ${env:..} / ${oauth:..} references, never raw secrets.
- The governance layer is per-tool on/off toggles, read/write/full scopes, approval gates that fail closed, and an append-only audit log. A disabled server or an over-ceiling scope is a deny, not a silent allow.
- Local clients hit 127.0.0.1 directly. Cloud clients (claude.ai web, ChatGPT custom connectors) reach the same endpoint via `switchboard expose` plus a built-in OAuth 2.1 / PKCE server — same governed path, still no token custody.
- It can run fully offline: the cross-provider "council" can point at an auto-detected local LLM (Ollama / LM Studio / llama.cpp / vLLM), so you get a second-opinion model with no account and no API key.
- The embedded dashboard (http://127.0.0.1:8088, localhost by default) browses a catalog of 4,700+ toolkits; flip one on, and `switchboard install <client>` wires Claude Desktop / Claude Code / Cursor / VS Code / Codex in one command.

There's also a tier of stuff hosted routers don't really give you on your own hardware: per-client profiles, rate-limits, spend budgets, a per-server circuit breaker, decision webhooks, poll-first triggers (local change detection, no inbound listener), request/response modifiers, HTTP-to-MCP tool servers, and OpenAPI→MCP import.

Honesty up front: this is a working alpha, not production-ready. It just launched — zero GitHub stars, zero known production users, no benchmarks against named competitors. It's pure TypeScript/Node ESM with exactly 5 runtime dependencies and zero native dependencies, and every feature is backed by deterministic verification oracles (~1,150 automated checks). But "verified by oracles" is not the same as "battle-tested in your environment" — it hasn't been. Treat the cloud-exposure path (expose + OAuth + tunnel) as alpha and run it knowingly. Expect rough edges; I'd rather you find them now.

Positioning, to be fair about it: hosted routers like Composio and Pipedream are good products. The difference is they custody your tokens and meter your calls; MCP Switchboard keeps keys, governance, and audit on your machine and is free / Apache-2.0. It's the self-hosted, governed alternative, not a claim that they're bad.

Install:

    npm install -g mcp-switchboard
    switchboard init && switchboard serve

or zero-install: `npx mcp-switchboard serve` (requires Node >= 18.18).

Repo: https://github.com/Mas-AI-Official/mcp-switchboard

I'd genuinely like criticism — on the threat model, the governance design, and whether the local-first trade-offs are worth it. Tear into it.

## Author's first comment

Author here. A bit more context on why this exists and what I actually want feedback on.

The itch was personal: I run both Claude and ChatGPT and kept re-wiring the same MCP servers into every client, in every config dialect, and re-doing it whenever I added a tool. The hosted routers fix the wiring but the price is that they hold your OAuth tokens and meter your calls. I didn't want either the busywork or the custody.

So the design stance is deliberate: local-first, zero token custody. Bring-your-own keys sit in a local AES-256-GCM vault on your box, and config can only ever reference a secret (${vault:..} / ${env:..} / ${oauth:..}) — there is no field where a raw secret lives, so there's nothing to accidentally commit or hand to a vendor. The HTTP endpoint binds to 127.0.0.1 by default. The governance layer (per-tool toggles, read/write/full scopes, fail-closed approval gates, append-only audit) is the same for Claude and ChatGPT, so both assistants act on, say, your Gmail under identical policy with every call logged in one place. It's a shared control plane, not a shared session — they don't see each other's chats, they share the layer underneath.

Two things I want to be clear about. It's a working alpha: every phase is implemented and pinned by deterministic oracles (~1,150 checks of compiled code, no model tokens), but it has zero production users and zero stars as of today, and oracles prove the contract holds in a test harness, not that it survives your messy real setup. And the moat isn't the catalog — hosted players have bigger catalogs. The bet is that local credentials + a real governance layer + a usable dashboard, built as an aggregator riding the existing MCP ecosystem, is the combination worth having.

Specific feedback I'm after:

- The threat model around `switchboard expose` + the built-in OAuth 2.1 / PKCE server. Enabling the OAuth server forces auth on /mcp (fail-closed) and tokens are opaque, sealed, and one-way hashed — but exposing a local gateway over a tunnel is the scariest surface here and I want it stress-tested.
- The governance model: are read/write/full + per-tool overrides + fail-closed approval the right primitives, or too coarse / too fine?
- Whether the fail-open design for webhooks and triggers (a down webhook never blocks a governance decision) is the right call, or a footgun.
- The 5-runtime-dependency, zero-native-dependency constraint — is it worth the friction it occasionally causes, and where would you relax it?

Apache-2.0, free, self-hosted, no per-call meter. Repo: https://github.com/Mas-AI-Official/mcp-switchboard — issues and PRs welcome, and harsh reviews especially.
