**1/**
Both Claude AND ChatGPT can drive your real tools — Gmail, GitHub, Notion, your own API.

But wiring every client to every app by hand is N×M pain, and the "easy" hosted shortcut parks your OAuth tokens on someone else's server.

MCP Switchboard collapses N×M into N×1. 🧵

**2/**
The idea: run ONE local process that re-exposes all your MCP servers behind ONE governed endpoint.

Add it once in Claude, once in ChatGPT (+ Cursor, Claude Code, VS Code, your agents) — and they all reach the same tools, same policy, same audit log. Your machine. No middleman.

**3/**
Zero token custody.

Your BYO keys live in a LOCAL AES-256-GCM vault on your machine. Nothing parked on a vendor server. Config secret fields accept ONLY ${vault:..} / ${env:..} / ${oauth:..} references — never the raw value.

**4/**
Real governance, not all-or-nothing.

Per-tool on/off toggles. read / write / full scopes. Approval gates that FAIL CLOSED. An append-only audit log of every verdict.

Disabled server, over-ceiling scope, unverifiable approval → deny, not a silent allow.

**5/**
One control plane for both Claude AND ChatGPT.

Local clients hit 127.0.0.1 directly. Cloud clients (claude.ai web, ChatGPT custom connectors) reach the SAME endpoint via `switchboard expose` + a built-in OAuth 2.1 / PKCE server. Same governed door.

**6/**
No cloud account? Run it fully offline.

The cross-provider council can run against an auto-detected LOCAL LLM — Ollama, LM Studio, llama.cpp, vLLM. No account, no API key, nothing leaving the box. A keyless second-opinion model on your own hardware.

**7/**
Browse 4,700+ toolkits in the embedded dashboard (http://127.0.0.1:8088, localhost by default), flip one on, then:

`switchboard install claude-code`

One command wires Claude Desktop / Claude Code / Cursor / VS Code / Codex. No hand-edited JSON.

**8/**
Extras at parity-or-beyond hosted routers — on your own hardware:

per-client profiles · rate limits · spend budgets · a circuit breaker · webhooks · poll-first triggers · request/response modifiers · HTTP→MCP servers · OpenAPI→MCP import.

Free, no per-call meter.

**9/**
Honest engineering: pure-TypeScript/Node ESM, exactly 5 runtime deps, ZERO native deps.

Every feature is pinned by deterministic verification oracles — 1,171 automated checks, code checking code, no model tokens.

Positioning: the self-hosted, governed alternative to hosted tool routers.

**10/**
It's a working alpha — fresh launch, Apache-2.0, by MAS-AI Technologies. Honest feedback and criticism very welcome.

```
npm install -g https://github.com/Mas-AI-Official/mcp-switchboard/releases/download/v0.1.0/mcp-switchboard-0.1.0.tgz
switchboard init && switchboard serve
```

Repo (Node ≥ 18.18): https://github.com/Mas-AI-Official/mcp-switchboard

Star it, try it, tell me what breaks. 🔌

