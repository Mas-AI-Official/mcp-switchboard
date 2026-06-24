<div align="center">

# 🔌 Switchboard

**One governed MCP endpoint for every app your agents touch.**
**Local-first. Bring your own keys. Nothing leaves your machine.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-2dd4bf.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/Model_Context_Protocol-1.29-2dd4bf.svg)](https://modelcontextprotocol.io)
[![Node](https://img.shields.io/badge/node-%E2%89%A518.18-2dd4bf.svg)](https://nodejs.org)
[![Status](https://img.shields.io/badge/status-working_alpha-D4A843.svg)](#project-status)

</div>

---

## The 30-second pitch

You have N agents (Claude Desktop, Claude Code, Cursor, your own agents) and M apps
(GitHub, Notion, Slack, Gmail, an internal API). Wiring that up today is **N×M** pain: every
client configures every server by hand, and the "easy" hosted shortcut means **your OAuth
tokens live on someone else's server**.

Switchboard collapses **N×M into N×1**. You run one local process. A **dashboard** lets you
toggle apps **ON/OFF** and set each to **read / write / full**. Agents connect to **one MCP
endpoint** and see only what you allowed. Your credentials sit in a **local encrypted vault** —
there is no cloud, because there is no "us".

```
   Claude ─┐                          ┌─ github   (write,  delete_repo blocked)
   Cursor ─┼──▶  SWITCHBOARD  ──▶─────┼─ notion   (read)
   agents ─┘   one MCP endpoint       ├─ slack    (OFF)
              + policy + vault        └─ everything (read, approval-gated)
```

## Why it's different

|  | Switchboard | Hosted tool routers |
|---|---|---|
| **Where your tokens live** | A local AES-256 vault on **your** machine | Their cloud |
| **Integrations** | **Mounts existing MCP servers** — no treadmill | Hand-built, must be maintained |
| **Governance** | Per-tool `read/write/full` + approval gates + audit log | Usually all-or-nothing |
| **Context blow-up** | `search` mode → 2 meta-tools no matter how many servers | Dump every tool into context |
| **Cost** | Free, Apache-2.0, self-hosted | Metered SaaS |

The catalog is **not** the moat — hosted players already have bigger ones. The defensible
combination is **local credentials + a governance layer + a usable dashboard**, built as an
**aggregator** that rides the existing MCP ecosystem instead of re-implementing it.

## Quickstart

### Fastest start — one click

> One-time prerequisite: install **[Node 18.18+](https://nodejs.org)**.

1. Get the code — `git clone https://github.com/Masoud-Masoori/switchboard.git`, or **Code ▸ Download ZIP** on GitHub and unzip it.
2. **Windows:** double-click **`start-switchboard.bat`**.
   **macOS / Linux:** run **`./start-switchboard.sh`** (`chmod +x start-switchboard.sh` once).
3. That's it. The first run installs dependencies, builds, and writes a starter config for you; then the gateway starts and **the dashboard opens in your browser** automatically.

To stop it: press **Ctrl+C** in the launcher window — or, if you closed the window and the port is still busy, double-click **`stop-switchboard.bat`** (`./stop-switchboard.sh` isn't needed on Unix; Ctrl+C is enough).

The launcher runs Switchboard in **HTTP + dashboard** mode on `http://127.0.0.1:8088`. To wire a stdio client (`claude mcp add`, Cursor) or change the transport, edit `switchboard.config.yaml` or use the from-source commands below.

### From source (manual)

> Requires Node ≥ 18.18. Not yet on npm — run it from source.

```bash
git clone https://github.com/Masoud-Masoori/switchboard.git
cd switchboard
npm install
npm run build

# scaffold a config + the ~/.switchboard home directory
node dist/cli.js init

# mount everything and print the governed tool list (no credentials needed —
# the bundled @modelcontextprotocol/server-everything is a real test server)
node dist/cli.js list

# run it: stdio for local clients + an HTTP endpoint & dashboard
node dist/cli.js serve
```

Open the dashboard at **http://127.0.0.1:8088**, then point an agent at the MCP endpoint:

```bash
# Claude Code / Claude Desktop, stdio transport:
claude mcp add switchboard -- node /absolute/path/to/switchboard/dist/cli.js serve

# or the Streamable HTTP endpoint, for any HTTP MCP client:
#   http://127.0.0.1:8088/mcp
```

### Storing a secret (BYO keys)

Secrets never appear in your config — the config holds only `${vault:name}` **references**.

```bash
# pipe the value in so it stays out of your shell history
printf '%s' 'ghp_xxx' | node dist/cli.js vault set github_pat
node dist/cli.js vault list      # names only, never values
```

```yaml
# switchboard.config.yaml
servers:
  - id: github
    source: npx
    package: "@modelcontextprotocol/server-github"
    enabled: true
    policy: write
    credentials:
      GITHUB_TOKEN: ${vault:github_pat}   # resolved locally at mount time
    tools:
      delete_repo: { enabled: false }     # hard-block the destructive one
```

### Connecting an OAuth provider (Phase 3)

For the five managed providers you don't paste a token — you authorize once and Switchboard seals
the result in the vault. Store the provider's client credentials, then run the loopback flow:

```bash
# one-time: store the OAuth app's client id/secret (names are a fixed convention)
printf '%s' '<client-id>'     | node dist/cli.js vault set oauth_github_client_id
printf '%s' '<client-secret>' | node dist/cli.js vault set oauth_github_client_secret

node dist/cli.js catalog            # see provider status: ready / needs client id / connected
node dist/cli.js connect github     # prints an authorize URL, waits on a local loopback callback
```

Or click **Connect** in the dashboard's catalog card. The browser bounces through the provider and
back to `127.0.0.1`, the token is sealed, and the row flips to **connected** — no token ever leaves
your machine.

### Wrapping a REST API as MCP (app2mcp, Phase 4)

Point a server at an OpenAPI/Swagger spec and Switchboard generates the MCP tools in-process at mount:

```yaml
servers:
  - id: petstore
    source: app2mcp
    openapi: https://petstore3.swagger.io/api/v3/openapi.json
    base_url: https://petstore3.swagger.io/api/v3   # override for relative/host-less specs
    policy: read                                     # ceiling: GET tools allowed, DELETE denied
    credentials:
      Authorization: ${vault:petstore_token}         # resolved per call from the vault
```

Each operation becomes a governed tool. Scope is inferred from the HTTP verb
(`GET`→read, `POST/PUT/PATCH`→write, `DELETE`→full), so a generated `deletepet` is **denied** under the
`read` ceiling above — same policy engine as every other server.

### Cross-provider council (Phase 5)

Switchboard already brokers tool calls; the **council** lets one agent broker a *peer model*. Turn it
on and Switchboard exposes two governed tools — `council_consult` (relay a prompt to the other provider
and return its reply) and `council_debate` (a bounded multi-round exchange between providers plus a
synthesized conclusion). The headline use case: a **Claude client asking OpenAI for a second opinion**,
or vice-versa — the chat-window model orchestrates, Switchboard relays + governs + logs.

```bash
# keys live in the vault, never in config (BYO keys, zero custody)
printf '%s' 'sk-ant-...' | node dist/cli.js vault set anthropic_api_key
printf '%s' 'sk-...'     | node dist/cli.js vault set openai_api_key
```

```yaml
# switchboard.config.yaml  (off by default — outbound + metered)
settings:
  council:
    enabled: true
    max_rounds: 3          # loop guard for council_debate
    token_budget: 2048     # max_tokens cap per provider call (cost guard)
    require_approval: false # true → every council call needs a human confirm
    providers:
      anthropic: { api_key_ref: ${vault:anthropic_api_key}, default_model: claude-opus-4-8 }
      openai:    { api_key_ref: ${vault:openai_api_key},    default_model: gpt-4o }
```

The council mounts as a synthetic in-process MCP server, so its tools flow through the **same**
policy → approval → audit path as any upstream tool (both are `write`-scoped). Model ids are
config/param-driven, so nothing breaks when a provider renames a model. A local Claude Desktop or
Claude Code client can use the council with zero tunnel; reaching **claude.ai *web*** additionally
needs the OAuth layer below.

### Streaming decisions to a webhook (real-time governance feed)

Every policy verdict can be POSTed to a URL of your choosing the instant it happens — wire your agents'
governance feed into Slack, a SIEM, a dashboard, or your own automation. The same append-only verdicts
that hit the audit log are delivered as slim JSON events.

```yaml
# switchboard.config.yaml  (off by default)
settings:
  webhook:
    enabled: true
    url: "https://example.com/hooks/switchboard"
    events: [deny, approval_required]   # any of: allow | deny | approval_required (empty = all)
    secret_ref: ${vault:webhook_secret}  # set via `switchboard vault set webhook_secret`
```

The payload is **decision metadata only** — `{ type, ts, decision, server, tool, scope, reason?,
duration_ms? }` — *never* the call's arguments or the upstream response, so a webhook can't quietly
become an exfiltration channel even with `logs.capture_io` on. When `secret_ref` resolves, each
delivery carries an `x-switchboard-signature: sha256=<hmac>` header (HMAC-SHA256 over the raw body)
so the receiver can authenticate it; verify with `crypto.createHmac("sha256", secret).update(body)`.
Delivery is **fire-and-forget and fail-open**: a slow, down, or misconfigured webhook never blocks,
delays, or alters a governance decision (8s timeout, detached). It fails *closed* on only one thing —
a promised-but-unresolvable signing secret drops the delivery rather than send an unsigned event a
receiver would reject. The whole contract (off-by-default, per-decision `events` filtering, valid
signature, metadata-only even under `capture_io`, drop-on-unresolvable-secret, non-blocking) is
verified by a deterministic oracle: `npm run verify:webhook` — 25/25.

### Poll-first triggers (turn any read tool into an event source)

Hosted tool routers sell "triggers" as inbound webhooks you have to expose to the cloud. Switchboard
does it the local-first way: it **polls** a read-scoped tool you already mounted on a schedule, diffs
each result against the last poll, and fires an event the moment something new shows up — no inbound
listener, no public URL, no third-party relay.

```yaml
# switchboard.config.yaml  (off by default)
settings:
  webhook:                                   # fires are delivered through your webhook…
    enabled: true
    url: "https://example.com/hooks/switchboard"
    secret_ref: ${vault:webhook_secret}      # …and signed with this same secret
  triggers:
    enabled: true
    poll_interval_seconds: 60                # default cadence (1..86400)
    definitions:
      - id: new-github-issues
        name: New GitHub issues
        tool: github__list_issues            # namespaced, READ-scoped upstream tool to poll
        args: { state: open }                # passed to the tool on each poll (optional)
        interval_seconds: 300                # per-trigger override (optional)
        item_path: ""                        # dot path to the array in the result; blank = whole result
        item_key: id                         # field uniquely identifying a row; new keys fire
        enabled: true
```

The design keeps the same governance/honesty contract as everything else:

- **The poll is a real governed call.** It runs through policy → approval → audit exactly like an
  agent call, so a trigger whose `tool` isn't read-scoped is **denied by the read ceiling**, and every
  poll lands in the Logs page. You cannot use triggers to smuggle a write past the policy engine.
- **The fire is an observation, not a decision.** A detected new item is delivered as a distinct
  `type: switchboard.trigger` webhook event — it is *never* written as an audit verdict, so the audit
  log stays a faithful record of governed calls only. Fires carry
  `{ type, ts, trigger_id, trigger_name?, tool, detection, new_count, sample_keys? }`, signed with the
  **same** `x-switchboard-signature: sha256=<hmac>` header as decision webhooks, and they ignore the
  webhook `events` filter (they always deliver when the webhook is on).
- **New-item detection** uses `item_path` (dot path to the array, e.g. `items` or `data.records`) +
  `item_key` (the unique field). Keys unseen since the last poll are "new"; baselines persist in
  `~/.switchboard/triggers-state.json` so a restart doesn't replay history. Omit both to fire whenever
  the raw result text changes.
- **Off by default, fail-open delivery.** Nothing polls until `triggers.enabled: true`, and fires
  inherit the webhook's non-blocking, drop-on-unresolvable-secret delivery. Drive a single poll on
  demand from the **Triggers** dashboard page or `POST /api/triggers/:id/poll`.

The whole contract — poll is audited, fire is not, fire bypasses the `events` filter, read ceiling
denies a non-read trigger, baseline survives restart — is verified by a deterministic oracle:
`npm run verify:triggers` — 36/36. (`npm run verify` runs the build + all three oracles.)

### Connecting claude.ai web (OAuth 2.1 + PKCE, Phase 5b)

Claude Desktop, Claude Code, and ChatGPT dev-mode all reach a *local* `/mcp` endpoint with a plain
API key (`switchboard apikey new <name>`) — no OAuth required. **claude.ai web is different**: it can
only reach Switchboard through a public HTTPS URL and refuses a static bearer, so it speaks OAuth 2.1
with mandatory PKCE and Dynamic Client Registration. Turn on the built-in Authorization Server only
for that case.

```bash
# 1) expose the local gateway over an HTTPS tunnel and copy the public URL
node dist/cli.js expose            # prints e.g. https://abc123.trycloudflare.com
```

```yaml
# 2) switchboard.config.yaml — paste the tunnel URL as the issuer/audience
settings:
  oauth_server:
    enabled: true
    public_url: "https://abc123.trycloudflare.com"   # REQUIRED when enabled; the loopback URL can't be the issuer
    access_token_ttl: 3600        # 1h
    refresh_token_ttl: 1209600    # 14d (0 disables refresh)
    consent: true                 # show the human approval screen on every authorization
```

Then add `https://abc123.trycloudflare.com/mcp` as a custom connector in claude.ai. The SDK router
publishes RFC 8414 AS metadata + RFC 9728 protected-resource metadata under `/.well-known/*`, accepts
RFC 7591 dynamic client registration at `/register`, and runs the mandatory-PKCE `authorize → consent
→ token` flow. Tokens are **opaque** (looked up server-side, never JWTs), persisted *sealed* with your
vault key and additionally stored one-way hashed; the token audience is bound to `<public_url>/mcp`
(RFC 8707). `/mcp` then accepts **either** a local API key **or** a valid OAuth bearer, and enabling
the server **forces `/mcp` authentication on** (fail-closed — a public issuer means the endpoint is
exposed). The full chain (metadata → DCR → PKCE → consent → token → authed `/mcp` → refresh → revoke)
is verified end-to-end by a deterministic oracle: `npm run verify:oauth` (20/20).

## CLI

| Command | What it does |
|---|---|
| `switchboard init` | Scaffold `switchboard.config.yaml` + the `~/.switchboard` home |
| `switchboard serve` | Run the gateway (stdio and/or HTTP, per config) |
| `switchboard dashboard` | Run only the HTTP endpoint + web console |
| `switchboard expose` | Open an HTTPS tunnel to the local endpoint (for claude.ai web / remote clients) |
| `switchboard list` | Mount everything and print the governed tool list, then exit |
| `switchboard doctor` | Check Node, config, transports, and that every secret resolves |
| `switchboard catalog` | List the OAuth providers and their connection status |
| `switchboard connect <provider>` | Authorize a provider locally (loopback OAuth → token sealed in the vault) |
| `switchboard apikey new <name>\|list\|rm <id>` | Manage `/mcp` bearer API keys for local clients |
| `switchboard vault set\|list\|rm <name>` | Manage locally-stored secrets |

Global flag: `-c, --config <path>` (default `switchboard.config.yaml`).
Once built and linked (`npm link`), the `switchboard` command replaces `node dist/cli.js`.

## How it works

```
   agent clients ──MCP──▶  GATEWAY  ──▶  ROUTER ──▶ POLICY ENGINE ──▶ REGISTRY ──▶ upstream
   (stdio + HTTP)          one server     namespaced/    read<write<     mounted     MCP servers
                                          flat/search    full + gates    clients     (npx / remote)
                                              │              │              ▲
                                          DASHBOARD       AUDIT LOG       VAULT
                                          (toggle/scope)  (append-only)   (AES-256-GCM, local)
```

Every call is classified (`read`/`write`/`full`), checked against the server's scope ceiling and
any per-tool override, optionally held for human approval, then forwarded — and **every verdict is
written to an append-only audit log**. Full walkthrough in **[docs/BLUEPRINT.md](docs/BLUEPRINT.md)**.

### Tool-exposure modes

Mount 30 servers and naive aggregation dumps ~600 tool schemas into your agent's context — accuracy
collapses, tokens explode. Switchboard offers three modes via `gateway.tool_exposure`:

- **`namespaced`** (default) — tools prefixed `github__create_issue`; only enabled servers exposed.
- **`flat`** — bare tool names (small setups; first server to claim a name wins).
- **`search`** — expose just two meta-tools, **`find_tools(query)`** and **`call_tool(name,args)`**.
  The agent searches; Switchboard returns only the relevant handful. The surface stays flat no
  matter how many servers you mount.

## Project status

**Working alpha — all five phases shipped.** Real and verified today: the aggregating gateway
(stdio + Streamable HTTP), the policy engine, all three tool-exposure modes, the encrypted vault, the
approval gate, the audit log, the dashboard, and the CLI. The full `find_tools → call_tool` round-trip
works end-to-end through the governed path.

- **Managed OAuth (Phase 3)** — local OAuth for **5 providers** (Google, GitHub, Slack, Notion, Linear)
  via the catalog UI or `switchboard connect <provider>`; tokens are sealed in the same local vault as
  BYO keys. Hand-rolled on Node `crypto` — no third-party auth service, zero native deps.
- **app2mcp (Phase 4)** — point `source: app2mcp` at an OpenAPI/Swagger spec and Switchboard generates
  an in-process MCP server at mount, with verb→scope inference flowing into the **same** governance
  engine (a generated `deletepet` is denied under a `read` ceiling). A reference without a resolvable
  spec still fails closed.
- **Council relay (Phase 5a)** — `settings.council` exposes `council_consult` + `council_debate` as a
  synthetic in-process server, letting one model consult/debate the other provider through the same
  policy → approval → audit path. Off by default; outbound + metered; keys resolved from the vault at
  call time.
- **claude.ai-web OAuth (Phase 5b)** — `settings.oauth_server` turns the `/mcp` endpoint into an OAuth
  2.1 + PKCE Authorization Server (RFC 8414/9728/7591/8707 + RFC 7009 revocation) so claude.ai web can
  connect over an HTTPS tunnel. Opaque tokens, sealed + one-way-hashed in the vault; consent-gated;
  `/mcp` accepts an API key **or** an OAuth bearer; enabling it forces auth on (fail-closed). Off by
  default. Verified end-to-end (metadata → DCR → PKCE → consent → token → refresh → revoke) by
  `npm run verify:oauth` — 20/20.
- **Decision webhooks** — `settings.webhook` streams each policy verdict (`allow`/`deny`/
  `approval_required`) to a URL as it happens, signed with an `x-switchboard-signature` HMAC. Payload
  is decision metadata only (never call I/O), fire-and-forget + fail-open, off by default. Verified by
  `npm run verify:webhook` — 25/25.
- **Poll-first triggers** — `settings.triggers` polls a read-scoped tool on a schedule, diffs the
  result by `item_key`, and fires a `switchboard.trigger` webhook on new items. The poll is a real
  governed/audited call (read ceiling denies a non-read trigger); the fire is an observation, never an
  audit verdict. Baselines persist across restarts; off by default. Verified by
  `npm run verify:triggers` — 36/36.

See **[docs/ROADMAP.md](docs/ROADMAP.md)** for the phase-by-phase detail.

## Docs

- **[Blueprint](docs/BLUEPRINT.md)** — the as-built architecture, module by module
- [Vision & positioning](docs/VISION.md)
- [Architecture overview](docs/ARCHITECTURE.md)
- [Roadmap](docs/ROADMAP.md)
- [Competitive landscape](docs/COMPETITIVE.md)
- [Example config](switchboard.config.example.yaml) · [search-mode example](examples/switchboard.config.yaml)

## Security

- Credentials live only in `~/.switchboard/vault.json`, **AES-256-GCM** encrypted with a key in
  `~/.switchboard/vault.key`. Nothing is transmitted off the machine; the vault makes no network calls.
- The HTTP endpoint binds to **127.0.0.1** by default — local-first, not exposed to the network.
- Governance **fails closed**: a disabled server, an over-ceiling scope, or an unverifiable approval
  context all result in *deny*, not a silent allow.
- Found a vulnerability? Please report it privately (see [CONTRIBUTING.md](CONTRIBUTING.md)) rather
  than opening a public issue.

## Contributing

Issues and PRs welcome — see **[CONTRIBUTING.md](CONTRIBUTING.md)**. The project is deliberately
small and dependency-light (zero native deps); please keep it that way.

## License

[Apache-2.0](LICENSE) © MAS-AI Technologies.
