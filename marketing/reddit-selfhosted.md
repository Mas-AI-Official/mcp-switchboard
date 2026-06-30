## Title

MCP Switchboard: a local-first, governed MCP aggregator — BYO keys in a local AES-256-GCM vault, zero token custody, governance + audit on your own box (working alpha, Apache-2.0)

## Body

I got tired of two things about wiring AI assistants up to my tools, so I built something for my own machine and figured this crowd would have opinions.

**The problem.** If you use MCP (Model Context Protocol) servers to let an agent actually *do* things — read GitHub, triage Gmail, poke Notion, hit your own REST API — you end up hand-wiring every client to every server. N clients x M apps of config. And the "easy" shortcut is a hosted router that parks your OAuth tokens on someone else's server and meters every call. Not what I want running my email.

**What MCP Switchboard does.** It's one local process that re-exposes all your MCP servers behind one governed endpoint, so it collapses that N x M wiring into N x 1. You point a client at one endpoint instead of wiring each tool into each client. The same vault, the same on/off + read/write/full policy, the same approval gates, and the same audit log sit underneath every assistant that connects — Claude Desktop, Claude Code, Cursor, VS Code, your own agents.

The bits that matter for r/selfhosted specifically:

- **BYO keys, local custody.** Credentials live only in a local AES-256-GCM vault on your machine (`~/.switchboard/vault.json`, encrypted with a key in `~/.switchboard/vault.key`). The vault makes no network calls. Your config never contains a secret — secret fields accept **only** `${vault:..}` / `${env:..}` / `${oauth:..}` references, so you literally can't paste a raw token into the config by habit. Zero token custody; nothing is parked on a vendor server.
- **Governance layer.** Per-tool on/off toggles, `read` / `write` / `full` scopes, approval gates that **fail closed**, and an append-only audit log. A disabled server, an over-ceiling scope, or an unverifiable approval context all resolve to *deny*, not a silent allow.
- **Binds localhost by default.** The HTTP endpoint and the embedded zero-build dashboard sit on `http://127.0.0.1:8088` — not exposed to your network unless you choose to expose it.
- **Runs fully offline.** The cross-provider "council" can run against an auto-detected **local LLM** (Ollama / LM Studio / llama.cpp / vLLM — any OpenAI-compatible server). No account, no API key, nothing leaves the box. `switchboard local-llm` only reads/probes; it never downloads or runs a model for you.
- **One-command install.** Browse a catalog of 4,700+ toolkits in the dashboard (built from the open MCP Registry + APIs.guru, both CC0), flip one on, and `switchboard install <client>` writes the right config block into Claude Desktop / Claude Code / Cursor / VS Code / Codex. It merges into existing servers non-destructively, and `--print` previews the exact block before writing.
- **Self-hosted extras** that a metered cloud can't really sell you, all on your own hardware: per-client **profiles** (a locked-down "demo" view vs a full "dev" surface, one switch — can only narrow, never widen), **rate-limits + spend budgets** (fail-closed ceilings on call count *and* cost), a per-server **circuit breaker** (a flapping upstream fast-fails instead of hanging), decision **webhooks** (each policy verdict POSTed as metadata-only JSON, HMAC-signed), poll-first **triggers** (polls a read-scoped tool on a schedule and fires on new items — no inbound listener, no public URL), request/response **modifiers**, **HTTP-to-MCP** tool servers, and **OpenAPI -> MCP** import.

**Cloud clients, if you want them.** Local clients hit `127.0.0.1` directly with an API key. If you also want claude.ai web or a ChatGPT custom connector to reach it, `switchboard expose` opens an HTTPS tunnel and there's a built-in OAuth 2.1 + PKCE authorization server — still zero token custody, and enabling it forces auth on (fail-closed). Entirely opt-in; the default posture is localhost-only.

**Engineering / why it might survive on your box.** Pure TypeScript/Node ESM, exactly **5 runtime dependencies, zero native dependencies**, one-command install. Every feature claim ("fails closed", "never auto-downloads", "metadata only", "a profile can only narrow") is pinned by a deterministic verification oracle — zero-dependency Node scripts that import the compiled code and check the contract, 1,171 automated checks total via `npm run verify`. No model tokens, just code checking code.

**Prerequisite:** Node >= 18.18. That's the only thing you need installed.

**Honest status — this is a working alpha.** It just launched: zero GitHub stars, no known production users, no battle-testing. Every phase is implemented and verified by the oracles above, but please treat it as alpha and tell me where it breaks. I'd rather hear the holes now. Specific things I'd love eyes on: the vault/key-on-disk model, the fail-closed governance paths, and whether the `expose` + OAuth flow is sane for anyone who actually wants remote access.

**Positioning, to be upfront:** hosted tool routers (Composio, Pipedream, etc.) are solid hosted SaaS — but they custody your tokens and meter your calls. MCP Switchboard is the self-hosted, governed alternative: keys + governance + audit stay on your machine, free and OSS. Not claiming they're bad; claiming this is the local-first option.

**License:** Apache-2.0. Author/maintainer: MAS-AI Technologies (Masoud Masoori).

**Repo:** https://github.com/Mas-AI-Official/mcp-switchboard

```bash
# Node >= 18.18 required
npm install -g https://github.com/Mas-AI-Official/mcp-switchboard/releases/download/v0.1.0/mcp-switchboard-0.1.0.tgz
switchboard init && switchboard serve
```

Dashboard opens at http://127.0.0.1:8088. Feedback, issues, and PRs all welcome.

## Note on self-promo

Per sub etiquette: I'm the author, this is my own project, and it's free and open-source (Apache-2.0, self-hosted, no paid tier or upsell). Posting it here because it's squarely a self-hosted, local-first tool and I genuinely want this community's scrutiny rather than upvotes. Happy to answer anything in the comments, and mods — please remove if this crosses the line.

