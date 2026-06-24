# Switchboard → Composio Parity: Local, Self-Hosted, Zero-Custody Tool Router

> Design + build plan. Decision-grade synthesis of six grounded research reports + a read of the current Switchboard source. KNOWN vs INFERRED is called out throughout; low-confidence/post-cutoff items carry caveats verbatim.

## 0. Build Status — ALL PHASES SHIPPED & VERIFIED

The DO-set below is **fully built**, and several items the original plan marked "defer" (Triggers, Webhooks) were also delivered. Each feature is pinned by a zero-dep deterministic oracle; `npm run verify` runs the build + all ten and is **green (301 checks)**.

| Phase / feature | Status | Oracle | Source |
|---|---|---|---|
| **0 — `/mcp` endpoint auth** (named API keys, fail-closed) | ✅ | `verify:auth` 13/13 | `apikeys.ts`, `dashboard.ts` |
| **1 — Dashboard SPA + catalog grid + settings** | ✅ | `verify:dashboard` 43/43 | `dashboard.ts`, `catalog.ts` |
| **2 — Catalog (multi-category, mounted-first ordering)** | ✅ | `verify:catalog` 20/20 | `catalog.ts` |
| **3 — Playground + opt-in tool I/O capture / Logs** | ✅ | (dashboard) | `router.ts`, `audit.ts` |
| **4 — `switchboard expose` (safe public tunnel)** | ✅ | — | `expose.ts`, `cli.ts` |
| **5a — Council relay tools** (`council_consult`/`council_debate`) | ✅ | `verify:council` 34/34 | `council.ts` |
| **5b — claude.ai-web / ChatGPT OAuth 2.1 + PKCE AS** | ✅ | `verify:oauth` 20/20 | `authserver.ts`, `dashboard.ts` |
| **Triggers** (poll-first, pause/resume, templates) — *was "defer"* | ✅ | `verify:triggers` 60/60 | `triggers.ts`, `trigger-templates.ts` |
| **Webhooks** (signed, Standard Webhooks) — *was "defer"* | ✅ | `verify:webhook` 33/33 | `webhook.ts` |
| **Response modifiers** (drop_params/inject_args/redact_response) | ✅ | `verify:modifiers` 28/28 | `transforms.ts` |
| **Auth schemes** (bearer/api_key/basic per server) | ✅ | (httptool/config) | `authscheme.ts` |
| **HTTP-tool servers** (declare REST calls inline as MCP tools) | ✅ | `verify:httptool` 29/29 | `httptool.ts` |
| **Offline local-LLM council provider** (Ollama/LM Studio/llama.cpp/vLLM) | ✅ | `verify:config` 21/21 | `council.ts`, `config.ts` |
| **Shipped example config exercises every parity feature** | ✅ | `verify:config` 21/21 | `switchboard.config.example.yaml` |

**Deliberately NOT built (out of scope, documented forks):** multi-user/per-end-user isolation (`?user_id=` carried, full isolation = L fork, §7.7); Composio-style per-end-user managed OAuth apps (we use the operator's own app, zero-custody, §3 Auth Screen); the catalog *ingest* pipeline at full registry scale (Adapters A+B designed in §4; the catalog UI + schema ship, bulk CC0 ingest is a maintainer-run sync, not a launch blocker). **Not published to npm** (v0.1.0 — publishing is an explicit, separate go-ahead). The sections below are the original plan, kept verbatim for provenance; where they say "defer/optional," see this table for what actually shipped.

## 1. Executive Summary

**What Composio is.** A managed "tools-for-agents" platform: ~1000+ pre-built toolkits (Gmail/GitHub/Notion/Slack/Supabase/Linear/…), managed per-end-user OAuth/API-key auth, and a flagship **Tool Router** that mints a per-user pre-signed MCP URL so an agent uses a few meta-tools (search / execute / manage-connections) to discover and run tools just-in-time instead of loading thousands of schemas into context. Entity model: **Organization > Project (`proj_`) > Auth Config (`ac_`) > Connected Account (`ca_`) > Tools/Triggers**. Dashboard left-nav: Toolkits / Auth Configs / Connected Accounts / Triggers / MCP / Logs / Playground, plus Project + Org settings. Metered purely on **TOOL CALLS** (Free 20K → $29/200K → $229/2M → Enterprise). SDKs are open (MIT); the catalog pipeline, toolkit definitions, and managed OAuth apps are proprietary.

**The thesis for a local clone.** Switchboard **already owns the hard, billable parts**: a local AES-256-GCM vault (zero custody), scope-based policy + approval gates (governance), an OpenAPI→MCP wrapper (`app2mcp`, `src/openapi.ts` invoked by `src/registry.ts`), OAuth-per-provider with PKCE, an append-only audit log, and a stateless Streamable-HTTP `/mcp` endpoint. What is missing is **breadth and presentation, not the engine**:
1. **Catalog scale** — 5 hardcoded OAuth providers + a flat server list vs Composio's 1000+ browsable toolkits.
2. **Tool-Router context-economy at scale** — partially present as the `search` exposure mode (`config.ts gateway.tool_exposure` enum includes `search`); needs a real shared index.
3. **The Composio-style dashboard/settings IA** — today the UI is a single vanilla-JS HTML string (`src/console.ts`) with 4 tab-cards; no catalog grid, categories, API-keys page, usage panel, logs, or settings.

The local **win** is removing the tool-call meter and the OAuth-app lock-in entirely while keeping execution unlimited and credentials on-device.

**The one blocking issue.** `src/dashboard.ts:39` — `app.all("/mcp", ...)` has **zero authentication**, protected only by the `127.0.0.1` bind (confirmed by direct read; `src/config.ts` `gateway.http` schema has only `{ host, port }`, no auth field). Tunneling it as-is hands every governed tool and vaulted credential to anyone who finds the URL. **Endpoint auth must land before any public-exposure feature.**

## 2. Critical Answers

### 2a. Can the consumer ChatGPT app (chatgpt.com) connect to a LOCAL Switchboard?
**Yes — but never directly to localhost, only via a public HTTPS tunnel, and only after `/mcp` is authenticated.** chatgpt.com supports custom MCP servers via Settings → Apps & Connectors → Advanced → **Developer mode** (beta), including write actions. The connector MUST be a **remote** MCP server over public HTTPS (SSE or Streamable HTTP); ChatGPT's cloud connects **outbound** and can never reach `127.0.0.1`/LAN. Path: keep Switchboard's Streamable-HTTP `/mcp` (already present), expose via a public HTTPS tunnel (Cloudflare **named** tunnel preferred; quick tunnel works for stateless request/response but has **no SSE** and a random ephemeral URL; ngrok free injects an interstitial that breaks the handshake), and register the URL under Developer mode. ChatGPT generally accepts a **static bearer token via custom header**, so Switchboard's planned bearer auth suffices on the ChatGPT side.
- **Confidence: HIGH** on architecture. **MEDIUM** on the Free-tier boundary (Apps-SDK doc says "all plans" 2025-11-13; Developer-mode list enumerates only Pro/Plus/Business/Enterprise/Edu — treat Free as unsupported until re-verified). Fast-moving beta; re-verify live.

### 2b. claude.ai web? Claude Desktop? Claude Code?
- **claude.ai WEB** — cloud-bound. Anthropic connects **from its cloud**, explicitly **cannot** reach `127.0.0.1`/VPN/firewalled hosts; needs a public HTTPS remote-MCP URL. **CRITICAL:** web custom connectors require **OAuth 2.1 + PKCE** and **reject** static bearer tokens / `?token=`. A bearer-only expose path does **not** light up claude.ai web; full web support needs an OAuth-server layer. Free/Pro/Max/Team/Enterprise (Free = 1 connector; Team/Enterprise = Owner adds org-wide).
- **Claude Desktop** — works **locally, no tunnel**: local stdio subprocess via `claude_desktop_config.json` (Switchboard already ships stdio). Can also use cloud remote connectors.
- **Claude Code (CLI)** — works **locally, no tunnel**: `claude mcp add switchboard -- <cmd>` (stdio) or `--transport http http://127.0.0.1:8088/mcp`. localhost works.
- **Confidence: HIGH** on all three (grounded in Anthropic/MCP docs incl. verbatim cloud-vs-local statements). **MEDIUM** on the web OAuth-rejects-bearer specifics.
- **Net contrast:** only claude.ai web + chatgpt.com are cloud-bound and need a tunnel; Desktop + Code reach local directly. claude.ai web additionally needs OAuth Switchboard lacks today.

### 2c. A "council" between ChatGPT and claude.ai via Switchboard?
**Not as the two models talking over MCP — that is a category error.** MCP shares **tools** between one client and one server; it does **not** bridge two providers. Each model independently calls Switchboard tools.
- **Free today:** both apps hit the one Switchboard, so every call is governed by the same vault + policy + approval + audit. That uniform governance is the real aggregator value.
- **A real council = build it as tools:** a `council_consult` / `ask_claude` / `ask_chatgpt` Switchboard tool that proxies a prompt to the **other** provider's API (keys in the vault) and returns the reply; the chat-window model orchestrates, Switchboard relays + governs + logs. Add max-rounds + token-budget + loop guards.
- **Confidence: HIGH** (follows from protocol design).

### 2d. Realistically ~1047 toolkits locally?
**Yes — by INGESTING freely-redistributable registries, re-implementing nothing, cloning nothing.**
- **Anchor:** Official MCP Registry (`registry.modelcontextprotocol.io/v0/servers`, cursor-paginated, ~2,000), metadata **CC0 1.0**; `server.json` already encodes name/description/install-method + auth hints — near 1:1 onto Switchboard's catalog.
- **Multiplier:** apis.guru openapi-directory (~2,529 APIs / 3,992 specs, **CC0**) through Switchboard's **existing** `app2mcp` wrapper — one entry per spec, `tool_count` = operation count, `auth_type` from `securitySchemes`.
- MCP Registry (~2k) + apis.guru (~2.5k) **> 1047**, all CC0-clean. Glama (~48k) / PulseMCP (~19k) are **discovery/enrichment only** (query live, don't snapshot). **Never** import Composio's specs (proprietary; MIT covers SDK client code only).
- **"Have" = browsable/installable catalog ENTRIES**, not 1047 live pre-warmed connections (same as Composio).
- **Confidence: HIGH** on load-bearing facts; **MEDIUM** on registry sizes (mid-2026, preview — schema may shift). Dedupe by `registryType+identifier`/normalized repo URL; validate before installable; tag provenance/license.

## 3. Composio → Switchboard Feature Map

| Composio feature | Local-first equivalent | Effort |
|---|---|---|
| **Toolkits grid** (1000+ cards: logo, auth badge, tool/trigger count, version, collapsible tools, inline playground) | New normalized **catalog table** + searchable/filterable card grid; replaces the flat `config.servers` list. Biggest gap. | **L** (P1 shell, P2 fill) |
| **Use-case / semantic search** (= agent `COMPOSIO_SEARCH_TOOLS`) | Upgrade existing `search` exposure mode (`config.ts gateway.tool_exposure`, router `find_tools`/`call_tool`) with a shared keyword(+embedding) index powering both the dashboard box and the agent — the Tool-Router context-economy primitive, locally. | **M** |
| **Auth Configs** (per-toolkit blueprint) | Generalize hardcoded `PROVIDERS` (`oauth.ts`, 5 providers) into data-driven blueprints; users bring own `client_id/secret` (vault convention exists); add api_key/Bearer/Basic/No-Auth (extend `config.ts server.auth` enum). | **M** |
| **Connected Accounts** (`ca_`, status, auto-refresh) | Vault + `oauth.json` + refresh-before-expiry **is** the single-user store (`OAuthStore.catalog()` already at `/api/catalog`); add status surfacing. True multi-user (user_id-scoped) = L, **defer**; carry `?user_id=` now. | **S** single / **L** multi |
| **Triggers** (webhook+polling, signed) | Net-new; **poll-first** (NAT-friendly), optional signed webhook when tunneled. Lowest priority. | **L**, defer |
| **Users / Sessions** (pre-signed per-session MCP URL) | Thin session layer = (user_id, allow/deny server ids, policy ceiling) resolved at `/mcp`; full ephemeral minting optional. | **M** (full = L) |
| **Logs** (payload/response/timings) | `audit.ts` records verdicts only (`recentAudit(100)` at `/api/audit`); extend record with opt-in request/response/duration + a Logs page. | **M** |
| **Playground** (live tool test) | Schema-driven input form → execute through gateway (policy/approval honored) → show output; inline on cards. | **M** |
| **Settings: General** (toggles) | Config-backed page (`config.ts writeConfig` exists); map `require_mcp_api_key`→`/mcp` auth, `log_visibility`→Logs capture, mask→vault already masks. | **S** |
| **Settings: API Keys** (named keys) | Net-new + **enables auth**: issue named bearer tokens (hashed, shown once) → `/mcp` middleware. This **is** the security fix + multi-client story. | **M** |
| **Settings: Webhooks** | Pairs with Triggers — **defer**. | **L**, defer |
| **Settings: Auth Screen / White-Labeling** | Largely **moot** — local OAuth uses the operator's own app, so there's no Composio-branded consent to remove; only cosmetic branding of `callbackPage` in `dashboard.ts`. | **S** |
| **Usage / Billing** | **Remove billing.** Keep counting executions for a free Usage/observability panel from the audit log; no quotas. | **S** |

## 4. Catalog Strategy (concrete)

**One normalized schema:** `{ name, title, description, category, auth_type(none|api_key|oauth2|bearer|basic|secret_env), install_method(npx|uvx|docker|pip|remote_url|openapi_wrap), source_registry, source_license, tool_count, repository_url, dedupe_key, version }`.

**Ingest pipeline (pluggable adapters → one table; CLI command + scheduled refresh):**
- **Adapter A (anchor, CC0, ~2,000):** paginate `/v0/servers` (follow `nextCursor`); map `server.json` → row (install/runtime from `packages[]`/`remotes[]`; auth from `environmentVariables[].isSecret`/`remotes[].variables`). The `runtimeHint`/`transport` becomes the launch command for `registry.ts mount()`.
- **Adapter B (multiplier, CC0, ~2,500):** `GET api.apis.guru/v2/list.json` → fetch each spec → wrap via existing `src/openapi.ts buildOpenApiServer` → row with `tool_count`=operations, `auth_type` from `securitySchemes`.
- **Adapter C (enrichment, live, NOT snapshotted):** Glama/PulseMCP for stars/last-updated at card-expand only.
- **Dedupe:** canonical key = `registryType+identifier` or normalized repo URL.
- **Categories:** parse awesome-mcp-servers headings + OpenAPI provider domains.
- **Search:** local keyword/BM25 index first (ships immediately, also feeds the agent `find_tools`), embedding later; SAME index for dashboard box + agent.
- **Licensing rules:** bulk-copy ONLY MCP-Registry (CC0) + apis.guru (CC0); enrichment registries = discovery only; **never** import Composio specs; tag `source_registry`+`source_license`; validate before installable; pin to the **preview** `server.json` schema.

**Result:** ~2,000 + ~2,500 **> 1,047**, CC0-clean, categorized — beating the spirit of Composio's count with zero dependence on its catalog.

## 5. Council Concept (honest)

- **MCP gives, free:** Switchboard as the single governed bus — both apps' calls flow through one vault + policy + approval + audit (after Phase-0 auth).
- **MCP does NOT give:** model-to-model conversation. ChatGPT and Claude each call tools independently.
- **A real council = relay tools:** `council_consult` (proxy a prompt to the other provider via vault-held keys, return the reply, governed + logged) + optional `council_debate` (fan-out + synthesis); add max-rounds + token-budget + loop guards. Chat-window model orchestrates; Switchboard is the bus.
- **Connectivity reality:** zero-tunnel council = Claude Desktop + Claude Code only; adding ChatGPT needs the authenticated tunnel (bearer header); adding claude.ai web additionally needs the OAuth 2.1 + PKCE layer.

## 6. Phased Build Plan (mapped to existing files)

**Phase 0 — SECURITY FIX (blocking, first).** No `/mcp` path serves without a credential, even on localhost. Add bearer middleware to `src/dashboard.ts` (constant-time compare, 401 default, never log token); extend `src/config.ts` `gateway.http` (currently `{host,port}`) with `{ token_ref, require_auth, expose }` (host stays `127.0.0.1`); add hashed named-token issuance to `src/vault.ts`/`src/types.ts`. **Verify:** curl `/mcp` w/o header → 401; with → handshake OK.

**Phase 1 — Composio-style dashboard shell + catalog grid + settings (highest leverage).** Replace the single HTML string (`src/console.ts`) with a real structured frontend; build the Toolkit catalog grid + card from an extended `/api/catalog`; wire search to a keyword index; build Settings (General, API Keys, Auth Screen) and Connected Accounts pages (`src/dashboard.ts`, `src/config.ts`, `src/oauth.ts`). **Verify:** >1000 entries render with working search + category filter; General persists to `config.yaml`; API Keys issues a working bearer token.

**Phase 2 — Catalog ingest pipeline.** Adapters A+B, dedupe, provenance, categories; make an entry installable through `registry.ts` (`src/cli.ts`, `src/registry.ts`, `src/openapi.ts`, `src/config.ts`). **Verify:** `switchboard catalog sync` → count > 1047 with `source_registry`/`source_license`; a sampled entry mounts.

**Phase 3 — Logs, Usage, Playground.** Extend `src/audit.ts` with opt-in request/response/duration; Logs UI on `/api/audit`; Usage panel (counts/error-rate/latency, no quotas); schema-driven Playground through the gateway (`src/dashboard.ts`, `src/console.ts`, `src/router.ts`). **Verify:** Logs show captured executions; Usage aggregates; Playground runs a tool honoring policy.

**Phase 4 — Safe public exposure (unblocks ChatGPT + claude.ai web).** `switchboard expose [--tunnel cloudflared|ngrok|tailscale]` in `src/cli.ts`: refuse without a token (generate+print once), ensure middleware active, spawn tunnel child, parse + print public URL + `Authorization: Bearer` config; path-scope tunnel to `/mcp` only (console stays local); detect missing binary. **Verify:** refuses w/o token; unauthenticated public hit → 401; prints paste-ready config.

**Phase 5 (optional fork) — claude.ai-web OAuth + council relay tools.** OAuth 2.1 + PKCE on the gateway (AS metadata, DCR, `/authorize`+`/token`) for claude.ai web; `council_consult`/`council_debate` tools with guards; defer Triggers (poll-first) + Webhooks here or later (`src/gateway.ts`, `src/dashboard.ts`, `src/router.ts`, `src/oauth.ts`, `src/cli.ts`).

- **Phase 5a — council relay tools: DONE.** `src/council.ts` builds a synthetic in-process MCP server (`council_consult` + `council_debate`) mounted via `Registry.mountLocal`, so both tools flow through the existing scope → policy → approval → audit path (both `write`-scoped). Keys are `${vault:..}`/`${env:..}` refs resolved at call time (fail-closed, enforced in `config.ts`); model ids are config/param-driven; loop/cost guards are `token_budget` (per-call `max_tokens`) + `max_rounds` (debate cap, total calls ≤ `rounds*participants + 1`). Gated by `settings.council.enabled` (off by default). Anthropic Messages + OpenAI Chat Completions via global `fetch`. **Verified:** mounts as `council__council_consult` / `council__council_debate` with `write` hints; approval gate denies fail-closed under no-TTY; dispatch returns a graceful `isError` result on transport failure (no outbound traffic in the test).
- **Phase 5b — claude.ai-web OAuth 2.1 + PKCE Authorization Server: DONE.** Config-gated (`settings.oauth_server`), off by default. Enabling it turns the dashboard's own `/mcp` into an OAuth Resource Server using the MCP SDK's `mcpAuthRouter` (`src/dashboard.ts`) backed by a custom `SwitchboardAuthProvider` (`src/authserver.ts`). It publishes RFC 8414 AS metadata + RFC 9728 protected-resource metadata at `/.well-known/*`, accepts RFC 7591 Dynamic Client Registration at `/register`, and runs the mandatory-PKCE (S256) `authorize → consent → token` flow with RFC 8707 resource-indicator audience binding (`<public_url>/mcp`). Tokens are **opaque** (random 32-byte, looked up server-side by `sha256` — never JWTs), persisted **sealed** with the vault key to `~/.switchboard/authserver.json` and additionally stored one-way hashed; auth codes + pending consents live in-memory with lazy GC. A config-gated consent screen is the human gate (POST `/oauth/consent`). `/mcp` then accepts **either** a local API key **or** a valid OAuth bearer; enabling OAuth **forces** `/mcp` auth on (fail-closed, floored even across a live settings edit). `public_url` is required-when-enabled (config `refine`) and must be the public HTTPS tunnel origin. **Verified** end-to-end by `npm run verify:oauth` (`scripts/verify-oauth.mjs`, zero-dep deterministic oracle): 20/20 — AS+PR metadata correct, unauth `/mcp` → 401 with `WWW-Authenticate: resource_metadata=…`, DCR → PKCE authorize → consent-approve → token (Bearer + refresh) → authenticated `/mcp` (200) → bogus token rejected (401) → refresh rotation → revoke → revoked token rejected (401).

## 7. Risks & Forks (maintainer decisions)

1. **Is cloud exposure in scope now?** If yes → Phase 0 + Phase 4 committed. If no → ship P1–P3 local; still do Phase 0 (cheap, closes the one real hole). **DECISION: in scope — the brainstorm explicitly asks to connect ChatGPT/claude.ai, so Phase 0 + Phase 4 are committed.**
2. **Security (not optional):** `dashboard.ts:39` `/mcp` has zero auth; only the loopback bind protects it. Fix in Phase 0 regardless of cloud scope.
3. **Dashboard rewrite size:** current UI is one vanilla-JS template literal, no build. Fork: (a) stay no-build vanilla vs (b) adopt a light build/framework. **DECISION: stay no-build vanilla, structured SPA (hash-routing + component functions) — preserves the project's zero-dep ethos and keeps the one-click launcher build step unchanged (just `tsc`). Reversible if it proves limiting.**
4. **Catalog licensing:** bulk-copy ONLY CC0 (MCP Registry + apis.guru); enrichment registries query-live-only; never import Composio specs; registry is PREVIEW (pin + re-sync).
5. **claude.ai-web auth:** rejects bearer/`?token=`, needs OAuth 2.1 + PKCE. Fork: is web a launch requirement? **DECISION: not a launch blocker — Phase 0 bearer covers ChatGPT + Desktop + Code now; claude.ai web is labeled OAuth-pending and lands in Phase 5.**
6. **"1047 toolkits" expectation:** browsable/installable ENTRIES, not live connections — set this expectation explicitly.
7. **Multi-user vs single-operator:** Composio is per-end-user; Switchboard is single-user. Multi-user isolation = L fork; carry `?user_id=` now, build later.
8. **Council is a build, not a protocol feature:** budget the relay tools + provider keys if a true council is wanted; "shared governed tools" is free after Phase 0. **DECISION: ship "shared governed tools" with Phase 0; build the council relay tools in Phase 5.**

## 8. Sources

**Composio:** composio.dev (+ /pricing, /toolkits, /toolkits/github); docs.composio.dev (tools-and-toolkits, authentication, using-triggers, mcp-overview, projects, glossary, white-labeling-authentication, toolkit-versioning, changelog, reference, tool-router/postToolRouterSession); github.com/ComposioHQ/composio.

**ChatGPT MCP:** help.openai.com (developer-mode-apps-and-full-mcp-connectors; connectors-in-chatgpt); developers.openai.com (guides/developer-mode; apps-sdk/deploy/connect-chatgpt; apps-sdk/build/mcp-server; api/docs/mcp; codex/mcp).

**Claude MCP:** support.claude.com (get-started-with-custom-connectors-using-remote-mcp; build-custom-connectors-via-remote-mcp-servers; getting-started-with-local-mcp-servers-on-claude-desktop); claude.com/docs/connectors/custom/remote-mcp + connectors/building/authentication; modelcontextprotocol.io/docs/develop/connect-local-servers; code.claude.com/docs/en/mcp.

**Tunnels/exposure:** developers.cloudflare.com (trycloudflare, tunnel/setup); ngrok.com/docs (free-plan-limits, http/oauth, getting-started); tailscale.com/docs (tailscale-funnel, funnel CLI, tailscale-serve); modelcontextprotocol.io/docs/tutorials/security/authorization; github.com/modelcontextprotocol discussions/1247; sunpeak.ai/blogs/claude-connector-oauth-authentication.

**Catalog:** registry.modelcontextprotocol.io (/, /docs, /v0/servers, generic-server-json.md, terms-of-service, about); blog.modelcontextprotocol.io/posts/2025-09-08-mcp-registry-preview; github.com/modelcontextprotocol/registry; smithery.ai/docs; glama.ai/mcp/servers; pulsemcp.com/api + /servers; mcp.so; github.com/punkpeye/awesome-mcp-servers; github.com/APIs-guru/openapi-directory (+ LICENSE); api.apis.guru/v2/metrics.json; nordicapis.com/7-mcp-registries-worth-checking-out; truefoundry.com/blog/best-mcp-registries.

**Switchboard source (read this session):** `src/dashboard.ts` (unauth `/mcp` at :39; `/api/catalog`, `/api/audit`, `/oauth/callback`, callbackPage), `src/config.ts` (`gateway.http` = `{host,port}` only; `tool_exposure` enum incl. `search`; `server.auth` enum `[none|oauth|bearer]`), `src/registry.ts` (`mount()` lifecycle; app2mcp via `buildOpenApiServer`), `src/oauth.ts` (5-provider PKCE table).
