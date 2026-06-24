# Switchboard — Blueprint (as-built)

> This is the **as-built** architecture: what actually exists in the source tree today, module
> by module, with the real names, the real data flow, and the real contracts. It is written from
> the code, not from the plan. For the *why* and the market positioning, see
> [VISION.md](VISION.md); for what's next, [ROADMAP.md](ROADMAP.md).

**Stack as shipped:** TypeScript on Node (ESM, `"type": "module"`, NodeNext module resolution),
`@modelcontextprotocol/sdk` 1.29.0, `zod` 4 for config validation, `yaml` for the on-disk config,
`commander` for the CLI, `express` 5 for the HTTP endpoint, and a single self-contained vanilla-JS
HTML page for the dashboard. **Zero native dependencies** — the vault uses Node's built-in `crypto`,
so `npm install` never needs a C/C++ toolchain. No database, no React build step, no keychain bindings.

---

## 1. The shape in one diagram

```
                      ┌──────────────────────── GATEWAY (src/gateway.ts) ───────────────────────┐
   agent clients      │  the single MCP server every agent connects to                          │
   Claude / Cursor ──▶│  transports: stdio  +  Streamable HTTP                                   │
   /  your agents     │                                                                          │
                      │   ListTools ─▶ Router.listTools()      CallTool ─▶ Router.callTool()      │
                      │                      │                          │                          │
                      │            ┌─────────▼──────────────────────────▼─────────┐               │
                      │            │            ROUTER  (src/router.ts)            │               │
                      │            │  exposure mode: namespaced | flat | search    │               │
                      │            │  search mode → find_tools + call_tool meta    │               │
                      │            └─────────┬───────────────────────┬─────────────┘               │
                      │                      │ forward()             │ resolve creds               │
                      │            ┌─────────▼─────────┐   ┌──────────▼──────────┐                  │
                      │            │ POLICY (policy.ts) │   │  VAULT (vault.ts)   │                  │
                      │            │ read<write<full    │   │ AES-256-GCM, local  │                  │
                      │            │ ceiling + overrides│   │ ${vault:..}/${env:..}│                 │
                      │            │ → allow/deny/gate  │   └─────────────────────┘                  │
                      │            └───┬───────────┬────┘                                            │
                      │     approval.ts│           │ audit.ts (append-only ~/.switchboard/audit.log) │
                      │   (human gate) ▼           ▼                                                 │
                      │            ┌────────────────────── REGISTRY (src/registry.ts) ────────────┐ │
                      │            │  one MCP Client per enabled server; mount / unmount live      │ │
                      │            └───────┬──────────────────┬───────────────────┬───────────────┘ │
                      └────────────────────┼──────────────────┼───────────────────┼─────────────────┘
                                           ▼                  ▼                   ▼
                                   stdio (npx/binary)    remote (HTTP)      app2mcp (roadmap,
                                   e.g. server-github    e.g. hosted MCP    fails closed today)

   DASHBOARD (src/dashboard.ts + src/console.ts) ──HTTP──▶ /api/state · /api/audit · toggle servers
```

---

## 2. Module map

Every file under `src/` and what it owns. Fourteen modules, no dead code.

| Module | Responsibility | Key exports |
|---|---|---|
| `types.ts` | The typed shape of `switchboard.config.yaml`, mirrored 1:1. The contract everything else consumes. | `Scope`, `ServerConfig`, `GatewayConfig`, `VaultConfig`, `SwitchboardConfig`, `ToolOverride`, `ApprovalConfig` |
| `config.ts` | Load YAML → validate with a zod schema → typed config. Also writes configs and emits the starter. | `loadConfig`, `writeConfig`, `starterConfig` |
| `vault.ts` | Local encrypted credential store + `${vault:..}` / `${env:..}` reference resolution. | `Vault`, `HOME_DIR` |
| `registry.ts` | Mounts upstream MCP servers (one `Client` each), holds the live connections, mounts/unmounts on demand. | `Registry`, `MountedServer` |
| `policy.ts` | Scope inference from tool names + the read/write/full governance decision. | `evaluate`, `inferScope`, `PolicyDecision` |
| `approval.ts` | The fail-closed human approval gate for scope-gated calls. | `approve`, `setStdioActive` |
| `audit.ts` | Append-only JSON-lines audit log of every governance verdict. | `audit`, `recentAudit`, `AuditEntry` |
| `router.ts` | The single governed tool surface. Exposure modes + the governed `forward()` path + search meta-tools. | `Router` |
| `gateway.ts` | Wires the MCP `Server` to the router; serves stdio + builds per-request servers for HTTP. | `Gateway`, `createGateway` |
| `dashboard.ts` | The express app: `/mcp` Streamable HTTP endpoint, the web console, and the control-plane API. | `startDashboard`, `DashboardHandle` |
| `console.ts` | The embedded dashboard — one self-contained dark-theme HTML document, vanilla JS, no build step. | `dashboardHtml` |
| `cli.ts` | The `switchboard` command (init / serve / dashboard / list / doctor / vault). | *(bin entry)* |
| `logger.ts` | stderr-only logging so stdout stays clean for the stdio MCP channel. | `log`, `out` |
| `index.ts` | Public library surface — the gateway is embeddable inside another Node process. | re-exports all of the above |

---

## 3. The configuration contract (`types.ts` + `config.ts`)

The on-disk `switchboard.config.yaml` is the single source of truth, validated by zod on load.
A `SwitchboardConfig` has three sections:

```yaml
gateway:
  transport: [stdio, http]        # which transports agents connect over
  http: { host: 127.0.0.1, port: 8088 }
  tool_exposure: namespaced       # namespaced | flat | search
  default_policy: read            # scope ceiling for servers that omit their own
vault:
  backend: encrypted-file         # encrypted-file | env
servers:
  - id: github                    # becomes the tool namespace: github__create_issue
    source: npx                   # npx | binary | remote | app2mcp
    enabled: true                 # toggled live from the dashboard
    policy: write                 # this server's scope ceiling
    package: "@modelcontextprotocol/server-github"
    credentials: { GITHUB_TOKEN: "${vault:github_pat}" }
    tools: { delete_repo: { enabled: false } }   # per-tool override
    approval: { require_for: [full] }            # gate the most privileged calls
```

`config.ts` rejects anything that doesn't match the schema (bad enum, missing `id`, wrong port
type) **at load time** — a malformed config never reaches the gateway. `starterConfig()` produces
a minimal working config (loopback HTTP on 8088, encrypted-file vault, one bundled npx server)
that `switchboard init` writes to disk.

---

## 4. The credential vault (`vault.ts`)

Local-first, zero-custody. This is the structural differentiator, so it gets the most care.

- **Home:** `~/.switchboard` (override with `SWITCHBOARD_HOME`). Holds `vault.json` (the
  encrypted blob), `vault.key` (the key), and `audit.log`.
- **Cipher:** **AES-256-GCM** via Node's built-in `crypto`. Each secret is sealed with its own IV
  and auth tag — no native module, no external service, no network call ever.
- **Backends:** `encrypted-file` (the portable default) or `env` (read secrets straight from the
  process environment — for CI/containers where the orchestrator injects them).
- **References:** config values like `${vault:github_pat}` or `${env:OPENAI_API_KEY}` are resolved
  by `Vault.resolve()` at server-mount time and injected into the upstream process's environment.
  The pattern is `/\$\{(vault|env):([^}]+)\}/g`, so a single value can interleave multiple refs.
- **Fail-closed:** an unresolved reference (missing secret, unset env var) **throws** — the server
  doesn't mount with an empty credential. `switchboard doctor` resolves every reference up front
  (without printing values) so you catch a missing secret before an agent does.

Secrets are written only via `vault set` (value read from stdin/TTY, kept out of argv and shell
history). `vault list` returns names only — values are never printed, logged, or echoed.

---

## 5. The server registry (`registry.ts`)

The registry owns the live upstream connections. One `@modelcontextprotocol/sdk` `Client` per
enabled server. Three working source types plus one roadmap stub:

- **`npx`** → `StdioClientTransport` launching `npx -y <package> <args>`. (On Windows the command
  is `npx.cmd`.) The child's environment inherits `process.env`, then layers the server's resolved
  `env` and `credentials` on top — so a mounted GitHub server sees `GITHUB_TOKEN` and nothing the
  agent could read back.
- **`binary`** → same stdio path, launching an arbitrary `command` instead of npx.
- **`remote`** → `StreamableHTTPClientTransport(new URL(url))` to a hosted MCP server.
- **`app2mcp`** → **throws** "on the roadmap (Phase 4)". It fails closed by design; configs ship it
  `enabled: false`.

`mountAll()` connects every enabled server at startup; the dashboard can `mount()` / `unmount()` a
single server live when you flip its toggle, without restarting the gateway.

---

## 6. The policy engine (`policy.ts`)

The governance core. Two responsibilities: **infer** a scope for a tool, then **decide** whether a
call may proceed.

**Scope inference** (`inferScope`) classifies a tool by its name against ordered ranks
`read(0) < write(1) < full(2)`:

- **read** — names starting with `get / list / read / search / fetch / find / query / describe /
  show / view / count / head / lookup / browse / inspect`.
- **full** — names containing `delete / destroy / drop / remove / purge / wipe / revoke /
  terminate / deactivate / admin / grant / sudo`.
- **write** — everything else (the safe-but-not-trivial default for an unrecognized verb).

**The decision** (`evaluate`) is deliberately small and total:

1. Tool explicitly `enabled: false` → **deny**.
2. Effective scope (override → inference) exceeds the server's ceiling (`policy` → `default_policy`)
   → **deny**.
3. The server's `approval.require_for` includes this scope → **approval_required**.
4. Otherwise → **allow**.

Least privilege is the default: a server with no `policy` inherits `default_policy` (which the
starter sets to `read`), so an unconfigured server can only read.

---

## 7. The approval gate (`approval.ts`)

When `evaluate()` returns `approval_required`, the call is held at `approve()`. It is **fail-closed**:

- `SWITCHBOARD_AUTO_APPROVE=1` → allow, and the auto-approval is logged (for non-interactive/CI runs
  the operator has explicitly opted into).
- The stdio MCP channel is active **or** there's no TTY → **deny** (you can't safely prompt a human
  on the same pipe the protocol is using).
- Otherwise → an interactive `y/N` prompt on the terminal, defaulting to **no**.

`setStdioActive()` is called by the gateway when it binds the stdio transport, so the gate knows it
must not try to read from that pipe.

---

## 8. The audit log (`audit.ts`)

Every governance verdict — allow, deny, approval outcome — is appended as one JSON line to
`~/.switchboard/audit.log`. An `AuditEntry` is `{ ts, server, tool, scope, decision, reason? }`.
The log is **append-only**; `recentAudit(limit)` reads it back newest-first for the dashboard.
This is the accountability surface: what did agents try, what was allowed, what was blocked, and why.

---

## 9. The router (`router.ts`) — one governed surface

The router is where aggregation, governance, and the context-scaling fix meet. It presents a
single tool list to the agent and is the **only** path to an upstream tool.

**Exposure modes** (`gateway.tool_exposure`):

- **`namespaced`** (default) — every enabled server's tools, prefixed `serverId__toolName`
  (separator `__`). Collision-free; the safe default.
- **`flat`** — bare upstream tool names. Small setups only; first server to claim a name wins.
- **`search`** — exposes exactly **two** meta-tools regardless of how many servers you mount:
  - **`find_tools(query, limit?)`** — dependency-free keyword scoring across every mounted tool
    (name match +3, exact-phrase +2, description hit +1), returns the top matches (default 10,
    max 50).
  - **`call_tool(name, arguments)`** — invoke any discovered tool by its namespaced name.

  This is the answer to the too-many-tools context wall: the agent *searches* instead of being
  handed 600 schemas, so the surface stays flat at any catalog size.

**The governed forward path** (`forward()`), run for every real tool call:

```
resolve server + upstream tool name
        │
   evaluate(policy)  ──deny──────────────▶ audit(deny) ─▶ return isError to agent
        │
   approval_required ──▶ approve() ──no──▶ audit(deny) ─▶ return isError
        │ allow / approved
   audit(allow)
        │
   registry[server].client.callTool(tool, args)  ──▶ upstream result back to the agent
```

No call reaches an upstream server without passing `evaluate()` first, and no verdict goes
unaudited.

---

## 10. The gateway (`gateway.ts`)

`createGateway(cfg)` is **async** and mounts everything before it resolves — callers get a ready
gateway. It wires the low-level MCP `Server`'s `ListTools` handler to `router.listTools()` and its
`CallTool` handler to `router.callTool(name, args)`. It exposes:

- `serveStdio()` — bind the stdio transport (and mark the approval gate stdio-active).
- `buildServer()` — construct a fresh MCP `Server` for a single HTTP request (the Streamable HTTP
  endpoint is stateless; see below).
- `shutdown()` — tear down upstream clients cleanly.

Identity: name `switchboard`, version `0.1.0`.

---

## 11. The dashboard + HTTP endpoint (`dashboard.ts` + `console.ts`)

`startDashboard()` stands up an express app bound to `gateway.http.host:port` (loopback by
default):

- **`POST /mcp`** — the Streamable HTTP MCP endpoint. Stateless: a fresh `StreamableHTTPServerTransport`
  (`sessionIdGenerator: undefined`) and a fresh server are built per request, so any HTTP MCP client
  can connect without session bookkeeping.
- **`GET /`** — the web console (the `dashboardHtml()` string).
- **`GET /api/state`** — current servers, their enabled/scope state, and the exposed tool count.
- **`GET /api/audit`** — recent audit entries, newest-first.
- **`POST /api/servers/:id/toggle`** — flip a server ON/OFF: mounts or unmounts it live **and**
  persists the change back to `switchboard.config.yaml`.

`console.ts` is a single self-contained HTML document — dark theme (`--bg #0d1117`, teal accent
`#2dd4bf`), scope pills for read/write/full — that polls `/api/state` and `/api/audit` every 5s.
No React, no Vite, no bundler: the "operator console" is one file the gateway serves verbatim.

---

## 12. The CLI (`cli.ts`)

`commander`-based, global `-c, --config <path>` (default `switchboard.config.yaml`):

| Command | Behaviour |
|---|---|
| `init` | Write a starter config (refuses to clobber an existing one) and report the home dir. |
| `serve` | Load config, `await createGateway`, start the dashboard if `http` is enabled, bind stdio if `stdio` is enabled. Errors out if neither transport is configured. |
| `dashboard` | Start only the HTTP endpoint + console; print the URL. |
| `list` | Mount everything, print `${n} tools exposed` with each tool's inferred scope, then shut down. |
| `doctor` | Print Node version, home, config path, vault backend, transports, the `/mcp` endpoint, and every server — resolving each secret (without printing it) and flagging policy traps. Exit non-zero on any problem. |
| `vault set\|list\|rm` | Manage secrets; `set` reads the value from stdin/TTY, `list` shows names only. |

Logs go to **stderr** (`logger.ts`) so **stdout** stays a clean MCP channel for the stdio transport.

---

## 13. A single tool call, end to end

1. An agent connected over stdio (or HTTP `/mcp`) calls `github__create_issue`.
2. The gateway's `CallTool` handler hands it to `Router.callTool()`.
3. The router splits the namespace, looks up the `github` server, and runs `evaluate()`:
   server enabled? `create_issue` not blocked? inferred scope (`write`) ≤ the server's ceiling
   (`write`)? approval required for `write`?
4. If an approval gate matches → `approve()` prompts the operator (or denies if non-interactive).
5. The verdict is written to the audit log.
6. On *allow*, the registry's `github` client forwards the call — with `GITHUB_TOKEN` already
   injected from the vault at mount time — and the upstream result is returned to the agent.

A blocked `delete_repo` never leaves step 3: it's denied, audited, and the agent gets a clean error.

---

## 14. What's proven vs. what's roadmap

**Verified working today** (compiles clean with `tsc`; exercised end-to-end):

- The aggregating gateway over **stdio + Streamable HTTP**.
- Real aggregation: `switchboard list` mounts `@modelcontextprotocol/server-everything` and prints
  its tools with correct inferred scopes.
- All three exposure modes, including `search` returning exactly the two meta-tools.
- The **full governed round-trip**: `find_tools` → `call_tool` through `evaluate()` → upstream →
  result, with the verdict audited.
- The vault (encrypt/resolve/fail-closed), the approval gate, the audit log, and the dashboard.

**On the roadmap** ([ROADMAP.md](ROADMAP.md)):

- Managed **OAuth-per-provider** (today: BYO keys via the vault, and `remote` servers you've
  pre-authed).
- **app2mcp** (OpenAPI→MCP generation) — the `app2mcp` source fails closed until the generator ships.

---

## 15. Layout

```
switchboard/
├── src/                         # 14 modules (table in §2)
├── dist/                        # tsc output (gitignored)
├── docs/
│   ├── BLUEPRINT.md             # this file
│   ├── VISION.md  ARCHITECTURE.md  ROADMAP.md  COMPETITIVE.md
├── examples/switchboard.config.yaml      # a search-mode, many-servers example
├── switchboard.config.example.yaml       # the canonical annotated example
├── package.json                 # ESM, Apache-2.0, bin: switchboard → dist/cli.js
├── tsconfig.json                # NodeNext ESM
├── LICENSE                      # Apache-2.0
├── CONTRIBUTING.md
└── README.md
```
