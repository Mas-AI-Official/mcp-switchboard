## Title

MCP Switchboard: a local-first MCP aggregator whose cross-provider "council" runs against your auto-detected local LLM — no account, no API key, keys stay in a local vault (working alpha, Apache-2.0)

## Body

I've been building **MCP Switchboard**, a local-first, governed MCP (Model Context Protocol) aggregator/proxy, and I wanted to post it here first because the piece this sub cares about — running fully offline against a local model — is a first-class path, not an afterthought.

**The angle for r/LocalLLaMA:** MCP Switchboard has a cross-provider "council" feature (one model asks another for a second opinion or runs a bounded multi-round debate). The third provider slot is just `local` — **any OpenAI-compatible server: Ollama, LM Studio, llama.cpp's `llama-server`, or vLLM.** No cloud, no key, nothing leaves the box. You don't even have to find the URL or model id yourself:

```
switchboard local-llm          # scans the usual ports, prints what's running + a ready-to-paste config block
switchboard local-llm wire     # writes the detected server into the council config
switchboard local-llm wire --base-url http://127.0.0.1:11434/v1 --model llama3.1   # or pin it manually
```

The local provider needs **no API key reference at all** — the offline council is genuinely keyless. `local-llm` *only reads*: it auto-detects a server **you** started and never downloads or runs a model for you, by design. It also guards against you accidentally wiring a non-chat model (an embedding/rerank/speech model) as the council voice. Those contracts (auto-detect, keyless wiring, never auto-download, non-chat-model guard) are pinned by a deterministic test oracle — `npm run verify:local-llm` reports 107/107.

**What the thing actually is.** You probably have several MCP clients (Claude Desktop, Claude Code, Cursor, VS Code, your own agents) and you wire each one to each MCP server by hand — N clients × M servers of config sprawl. The "easy" hosted shortcut parks your OAuth tokens on someone else's server and meters your calls. MCP Switchboard collapses N×M into N×1: you run **one** local process that re-exposes all your MCP servers behind **one** governed endpoint. Each client points at that one endpoint and reaches the same tools through the same vault, the same policy, the same approval gates, and the same audit log.

**Architecture (the path every call takes):**

```
agent clients ──MCP──▶ GATEWAY ──▶ ROUTER ──▶ POLICY ENGINE ──▶ REGISTRY ──▶ upstream MCP servers
(stdio + HTTP)         one server   namespaced/  read<write<full   mounted     (npx / remote)
                                    flat/search  + approval gates   clients
                                        │              │              ▲
                                    DASHBOARD       AUDIT LOG        VAULT
                                    (toggle/scope)  (append-only)    (AES-256-GCM, local)
```

Relevant design choices for this crowd:

- **Local credential custody.** Bring-your-own keys live in a local AES-256-GCM vault on your machine (`~/.switchboard/vault.json`, key in `~/.switchboard/vault.key`). The vault makes no network calls. Config files hold only `${vault:..}` / `${env:..}` / `${oauth:..}` references — never raw secrets.
- **Governance layer.** Per-tool on/off toggles; `read` / `write` / `full` scopes; approval gates that **fail closed** (a disabled server, an over-ceiling scope, or an unverifiable approval context all resolve to *deny*, never a silent allow); an append-only audit log.
- **Binds localhost by default.** The HTTP endpoint and the embedded zero-build dashboard sit on `http://127.0.0.1:8088` — not exposed to the network unless you explicitly tunnel.
- **Context blow-up control.** Mount 30 servers and naive aggregation dumps ~600 tool schemas into your context. A `search` exposure mode collapses that to two meta-tools (`find_tools(query)` + `call_tool(name, args)`), so the surface stays flat no matter how many servers you mount.
- **Catalog to wire from.** The dashboard browses 4,700+ toolkits (built from the open MCP Registry + APIs.guru, both CC0); flip one on and `switchboard install <client>` wires Claude Desktop / Claude Code / Cursor / VS Code / Codex in one command.

It also has the stuff a metered cloud can't really sell you because it runs on your own hardware: per-client profiles (a narrow-only "demo" view vs a full "dev" surface), rate limits + spend budgets that fail closed, a per-server circuit breaker, decision webhooks, poll-first triggers (it *polls* a read-scoped tool and diffs the result — no inbound listener or public URL), HTTP-to-MCP tool servers, and OpenAPI→MCP import.

**Engineering.** Pure TypeScript/Node ESM, exactly 5 runtime dependencies, zero native dependencies, one-command install (Node ≥ 18.18). Every feature claim is backed by deterministic verification oracles — zero-dependency Node scripts that import the compiled code and check the contract, no model tokens involved. `npm run verify` runs the build plus 25 oracles, ~1,150 automated checks total.

**Where it honestly sits.** This is a **working alpha**. It just launched — zero GitHub stars, zero known production users, no benchmarks against named competitors. I'm posting it here to get torn apart by people who actually run local models and care about credential custody. The thing I most want feedback on: the local-LLM auto-detect/wire path (does it find your Ollama/LM Studio/llama.cpp/vLLM setup cleanly?) and whether the keyless offline council is genuinely useful or just a neat demo. If you find a place where governance *doesn't* fail closed, that's the bug report I want most.

**Positioning, to be upfront:** hosted tool routers (Composio, Pipedream, etc.) are solid hosted SaaS — but they custody your tokens and meter your calls. MCP Switchboard is the self-hosted, governed alternative: keys + governance + audit stay on your machine, free and OSS. Not claiming they're bad; claiming the trade-off is different.

**Install (zero cloud account needed):**

```
npm install -g mcp-switchboard
switchboard init && switchboard serve
# or zero-install:
npx mcp-switchboard serve
```

Dashboard at `http://127.0.0.1:8088`. License: Apache-2.0.

Repo: **https://github.com/Mas-AI-Official/mcp-switchboard**

## Note on self-promo

Heads up to anyone posting this kind of thing here: r/LocalLLaMA has self-promotion etiquette — read the rules, don't just drop a link and leave. Show up in the comments, answer the hard questions, take the criticism, and contribute to other threads too rather than treating the sub as a launchpad. If a mod or the community says it's over the line, respect that. Genuine technical discussion is the price of admission, not the link.
