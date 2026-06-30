# MCP Switchboard — Product Hunt launch kit

## Tagline

One governed MCP endpoint for Claude AND ChatGPT

## Description

Run ONE local process that re-exposes all your MCP servers behind ONE governed endpoint. Claude, ChatGPT, Cursor, VS Code and your own agents share the same local vault, on/off + read/write/full policy, approval gates and audit log. Local-first, BYO keys, Apache-2.0.

## Maker's first comment

Hi PH 👋 I'm Masoud, building MCP Switchboard at MAS-AI Technologies.

The problem that started this: I have two of the best agents in the world — Claude and ChatGPT — and I want both of them to actually *do things* (read GitHub, triage Gmail, update Notion, ping Slack, hit my internal API). Today that means wiring every client to every app by hand. N clients × M apps. And the "easy" hosted shortcut parks your OAuth tokens on someone else's server and meters every call.

MCP Switchboard collapses N×M into N×1. You run one local process that re-exposes all your MCP servers behind one governed endpoint. You add that endpoint once in Claude and once in ChatGPT, and now *both* assistants reach the same tools through the same encrypted local vault, the same on/off + read/write/full policy, the same approval gates, and the same audit log. One control plane. Your machine. No "us" in the middle.

Why local-first matters here:
- **Your keys stay yours.** BYO credentials live in a local AES-256-GCM vault on your machine — zero token custody, nothing parked on a vendor server. Secret fields only ever hold `${vault:..}` / `${env:..}` / `${oauth:..}` references, never raw values.
- **Governance you control.** Per-tool on/off, read/write/full scopes, approval gates that fail *closed*, and an append-only audit log.
- **It runs offline.** Point the cross-provider "council" at an auto-detected local LLM (Ollama / LM Studio / llama.cpp / vLLM) and get a second-opinion model with no account and no API key.
- **Free and self-hosted**, Apache-2.0, no per-call meter.

How it connects: local clients (Claude Desktop, Claude Code, Cursor, your own agents) hit `127.0.0.1` directly. Cloud clients (claude.ai web, ChatGPT custom connectors) reach the same governed endpoint via `switchboard expose` plus a built-in OAuth 2.1 / PKCE server — still zero token custody.

Two things make day one easy: browse 4,700+ toolkits in the embedded dashboard, flip one on, and `switchboard install <client>` wires Claude Desktop / Claude Code / Cursor / VS Code / Codex in one command. There's also a tier hosted routers don't sell on your own hardware: per-client profiles, rate-limits, spend budgets, a circuit breaker, webhooks, poll-first triggers, request/response modifiers, HTTP-to-MCP tool servers, and OpenAPI→MCP import.

**The honest part — this is a working alpha.** Every phase is shipped and verified, but it just launched: zero stars, no production users yet, and I'm not going to pretend otherwise. Under the hood it's pure-TypeScript/Node ESM with exactly 5 runtime dependencies, zero native dependencies, and every feature is backed by deterministic verification oracles (1,171 automated checks — code checking code, no model tokens).

Positioning, plainly: hosted tool routers like Composio and Pipedream are genuinely good hosted SaaS — but they custody your tokens and meter your calls. MCP Switchboard is the self-hosted, governed alternative that keeps keys, governance and audit on *your* machine, free and open-source.

```
npm install -g https://github.com/Mas-AI-Official/mcp-switchboard/releases/download/v0.1.0/mcp-switchboard-0.1.0.tgz
switchboard init && switchboard serve
```

Requires Node ≥ 18.18. Dashboard opens at http://127.0.0.1:8088 (binds localhost by default).

Repo: https://github.com/Mas-AI-Official/mcp-switchboard

I'd genuinely rather hear what's wrong with it than collect upvotes — tear into the threat model, the governance design, the offline path. Issues and PRs welcome.

## Gallery slide captions

1. **N×M → N×1.** One local MCP Switchboard process re-exposes all your MCP servers behind one governed endpoint — so Claude *and* ChatGPT (plus Cursor, Claude Code, VS Code, your own agents) reach the same tools the same way.

2. **Your keys never leave the box.** BYO credentials live in a local AES-256-GCM vault; config holds only `${vault:..}` references. Zero token custody — nothing parked on a vendor server.

3. **Governance, per tool.** On/off toggles, read / write / full scopes, approval gates that fail closed, and an append-only audit log — the same policy for every client and every assistant.

4. **Browse 4,700+ toolkits, wire one in seconds.** Flip a toolkit on in the embedded dashboard, then `switchboard install <client>` configures Claude Desktop / Claude Code / Cursor / VS Code / Codex in one command.

5. **Runs fully offline.** The cross-provider council points at an auto-detected local LLM (Ollama, LM Studio, llama.cpp, vLLM) — a second-opinion model with no cloud account and no API key required.

## Topics

- Developer Tools
- Artificial Intelligence
- Open Source
- Privacy
- GitHub
- Productivity

## First-24h checklist

- Publish the GitHub release and confirm `npm install -g https://github.com/Mas-AI-Official/mcp-switchboard/releases/download/v0.1.0/mcp-switchboard-0.1.0.tgz` + `switchboard serve` both work cleanly on a fresh machine with Node 18.18.
- Verify the repo URL in every asset points to https://github.com/Mas-AI-Official/mcp-switchboard and the README quickstart matches the launch copy.
- Post the maker's first comment the moment the listing goes live; pin it.
- Confirm all 5 gallery slides are uploaded in order and captions render correctly.
- Be present in the comments all day — answer every question fast, especially anything on the threat model, token custody, and the offline local-LLM path. Invite criticism; don't get defensive.
- When asked "how is this different from Composio / Pipedream?", give the honest framing: they're solid hosted SaaS, MCP Switchboard is the self-hosted, governed, Apache-2.0 alternative that keeps keys + governance + audit on your machine.
- State the alpha status plainly if anyone asks about maturity — working alpha, just launched, no production users yet.
- Cross-post truthfully to a Show HN and a relevant subreddit (r/LocalLLaMA, r/ClaudeAI, r/ChatGPT) with the problem-first framing; link back to the repo, not the PH page only.
- Watch GitHub issues and the `npm` page; triage and reply to the first bug reports same-day.
- Do NOT fabricate or imply star counts, downloads, users, or testimonials — there are none yet, and saying so builds more trust than faking it.
- Thank everyone who tries it and files an issue or PR; capture recurring feedback into the issue tracker for the next iteration.

