# MCP Switchboard baseline: what the gateway is on `vnext/governed-hub`

Status: describes the code on branch `vnext/governed-hub` (package version 0.1.0, HEAD cdaa7a9 when revised). It is a
reading guide, not a second design. The design and every decision number are in
[architecture/MCP_SWITCHBOARD_VNEXT.md](architecture/MCP_SWITCHBOARD_VNEXT.md) ("the design doc").
Labels: Observed (read in code on this branch), Per doc (taken from a design page, not re-read in code), Inferred, Unknown.

## Documents

[RUNBOOK.md](RUNBOOK.md) (operate it), [THREAT_MODEL.md](THREAT_MODEL.md) (what it defends and what it does not),
[VALIDATION.md](VALIDATION.md) (how it is verified), [CONNECTOR_CONTRACT.md](CONNECTOR_CONTRACT.md) (connector rules),
[PROVIDER_COST_COMPARISON.md](PROVIDER_COST_COMPARISON.md) (cost of local vs hosted),
[connectors/OWNER_SETUP.md](connectors/OWNER_SETUP.md) (per-platform setup),
[architecture/LOCAL_TOOLKITS.md](architecture/LOCAL_TOOLKITS.md) and [architecture/CONNECTORS.md](architecture/CONNECTORS.md).

## 1. What it is

A local-first gateway that mounts many MCP servers and exposes them to agents as one MCP endpoint, with scope
ceilings, risk tiers, out-of-band approvals, a kill switch and a hash-chained audit log. It runs as a Node process on
the operator's machine. License: Apache-2.0 (`package.json`).

Node version: `package.json` says `engines.node >= 22.12.0` and `switchboard doctor` uses the same floor
(`NODE_FLOOR` in `src/doctor.ts`). It is the highest floor among the pinned dependencies: `commander` 15.0.0
declares `node >= 22.12.0` and the MCP SDK v2 packages declare `>= 20` (Observed, each `node_modules/*/package.json`).
The Dockerfile and CI use Node 22. Not run on Node 20 or older.

## 2. Transports

| Transport | How | Source |
|---|---|---|
| Streamable HTTP, stateless | `POST /mcp`. Modern requests go to `createMcpHandler`; handshake-era requests get a per-request `WebStandardStreamableHTTPServerTransport`. Every non-POST request to `/mcp` is 405 (an unauthenticated one is still 401 first). | `src/dashboard.ts` (`mountMcpEndpoint`) |
| stdio (server side) | `switchboard serve` with `stdio` in `gateway.transport`; with clients configured it needs `--client <id>` and that client's key. | `src/gateway.ts` (`serveStdio`), `src/cli.ts` |
| stdio bridge | `switchboard bridge --client <id> [--url <url>]` relays a client's stdio to the shared HTTP gateway with that client's key. Default URL `http://127.0.0.1:8088/mcp`. | `src/bridge.ts` |

`gateway.transport` is an array of `stdio` and `http`. The schema default when the key is absent is `["stdio"]`; the
starter config written by `switchboard init` and the example config set `["stdio", "http"]` (Observed, `src/config.ts`).
The HTTP listener defaults to `127.0.0.1:8088` with `require_auth: auto`.

`switchboard expose` publishes `/mcp` to the public internet through a tunnel (`cloudflared`, `ngrok` or `tailscale`,
`src/expose.ts`) behind a bearer key. The design doc (section 5) calls public hosting out of scope until the OAuth server issues
audience-checked tokens, so treat `expose` as an operator-accepted risk, not a supported hosting mode.

Open by default on loopback: with no client registered and `require_auth: auto`, `/mcp` accepts any local process as
`loopback-anonymous`, and none of the per-client ceilings below apply (Observed, `src/principal.ts`). Register a client
(`switchboard client add <id>`) to require a principal on every request.

## 3. Protocol revisions served

Both eras are served from the same endpoint (Observed in `src/dashboard.ts` and `src/gateway.ts`; oracle
`verify:dualera`, 43 checks per the maintainer's report, see [VALIDATION.md](VALIDATION.md)):

- MCP `2026-07-28`: stateless, `server/discover`, `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name` headers, `resultType`.
- Handshake era: `2025-11-25`, `2025-06-18`, `2025-03-26`.

Upstream servers mount through the v2 client; 1.x upstream servers still mount (per the maintainer's report). The
dependency list carries the v2 packages (`@modelcontextprotocol/server`, `client`, `node`) and the 1.x SDK (`package.json`).
Compatibility is claimed only for eras an oracle exercises (design doc decision 8).

Known limitation: the OAuth authorization server routes use `@modelcontextprotocol/server-legacy` 2.3.1 (Observed,
`src/authserver.ts` imports and `package.json`). Upstream marks that package deprecated; it is a frozen copy of the v1 helpers.

## 4. Clients supported by `switchboard install`

`SUPPORTED_CLIENTS` in `src/clients.ts` (Observed):

| Client id | User-scope target | Notes |
|---|---|---|
| `claude-code` | `~/.claude.json` (project: `<dir>/.mcp.json`) | `claude mcp add-json` when `claude` is on PATH. |
| `claude-desktop` | `claude_desktop_config.json` under the platform app-config dir | User scope only; bridge mode only. |
| `codex` | `$CODEX_HOME` or `~/.codex/config.toml` | `codex mcp add` for user scope. |
| `gemini` | `~/.gemini/settings.json` | Bridge mode only. |
| `antigravity` | `~/.gemini/config/mcp_config.json` (older path only on an unmigrated machine) | `agy mcp add`; user scope and bridge mode only. |
| `dsh` | `$DSH_HOME` or `~/.dsh`, `profiles/<profile>/cordis.patch.yml` | User scope only. |
| `cursor` | `~/.cursor/mcp.json` (project: `<dir>/.cursor/mcp.json`) | |
| `vscode` | `Code/User/mcp.json` under the app-config dir (project: `<dir>/.vscode/mcp.json`) | Key `servers`. |

Default mode is `bridge`: no token goes into a client file. `--mode http` works only where the client can name the
token by environment reference (Claude Code, Cursor, VS Code, Codex, dsh). Flow (Observed, `src/installer.ts`): preview,
confirm (`--yes` skips), register the client with the gateway if it is new, back up (a file copy; for the `claude`
CLI route the previous entry is recorded under `SWITCHBOARD_HOME/install-backups` instead), write, probe, roll back on probe failure.

Known limits (Per doc, design doc 3.13): a Store (MSIX) install of Claude Desktop keeps its config under
`%LOCALAPPDATA%\Packages\Claude_*`, which is not searched, so copy the entry by hand; JSON with comments is refused rather
than rewritten; a PowerShell-only shim or app execution alias is not started, so the file is edited instead.

## 5. Server sources

`servers[].source` is one of `npx`, `binary`, `remote`, `app2mcp`, `http-tool`, `connector` (`src/config.ts`):

- `npx` and `binary`: a stdio child. Adding an npx toolkit through the dashboard or catalog requires an exact version
  (`SB_PACKAGE_UNPINNED`, HTTP 400, `src/dashboard.ts`). An npx entry written by hand in the config still mounts with a
  floating name and only logs a WARNING (also shown by `switchboard doctor`).
- `remote`: a remote MCP server through the SSRF-guarded fetch (`src/netguard.ts`).
- `app2mcp`: an OpenAPI 3.x or Swagger 2.0 spec as an in-process MCP server (`src/openapi.ts`).
- `http-tool`: hand-declared HTTP endpoints as governed tools (`src/httptool.ts`).
- `connector`: one toolkit of the connectors kit, see [CONNECTOR_CONTRACT.md](CONNECTOR_CONTRACT.md).

Stdio children get a closed environment: the design 3.6 allowlist plus the SDK default names pinned to the SDK 1.x set;
any other SDK default is masked at spawn because SDK 2.x widened its defaults (`baseChildEnv`, `exactChildEnv` in `src/childenv.ts`).

## 6. Tool exposure modes

`gateway.tool_exposure` (`src/config.ts`, `src/router.ts`):

- `namespaced` (default): `serverId__toolName`.
- `flat`: bare tool name; first claimant wins, later collisions are dropped and logged.
- `search`: the meta-tools `find_tools`, `call_tool` and `batch_call` instead of every upstream tool; a direct namespaced call still resolves.

In any mode, `find_tools` and `call_tool` are also listed while a visible connector toolkit has unlisted actions. A name
resolves only to a tool the upstream declared at mount (listed, or for connector toolkits held as callable but unlisted);
anything else is `SB_UNKNOWN_TOOL`. The `router.ts` header comment still says search mode has two meta-tools; the code has three.

## 7. Policy and risk tiers

- Scope `read`, `write`, `full` is the ceiling, applied by server, active profile and client; the tightest wins (design doc 3.1).
- Classifier: tool names are tokenized; read only when the first token is a read verb and no token is a write or exec verb (3.5, `src/policy.ts`).
- Risk `low`, `medium`, `high`: defaults read low, write medium, full high; `outward: true` raises write and full to high; a per-tool `risk` wins (3.4).
- A client's `max_scope` and `max_risk` apply only once a client is registered (section 2).

## 8. Approvals

Calls at a gated risk (default `gateway.approval.require_for_risk: [high]`) create a pending approval bound to principal,
server, tool and the SHA-256 of the canonical arguments. `gateway.approval.ttl_seconds` is 60 to 86400 (default 900) and
runs from creation of the request; `wait_seconds` is 0 to 50 (default 0). Statuses: pending, approved, denied, consumed,
expired. A restart makes the gateway ignore records from the earlier run (the signing key is per run, design doc 3.3). Single use.

Only the running gateway signs a decision, after its own presence check: Windows Hello where available, else a typed
challenge at the gateway console, which is weaker because a pseudo-terminal can be scripted (`src/presence.ts`). The
harness switches `SWITCHBOARD_AUTO_APPROVE=1` and `SWITCHBOARD_INSECURE_APPROVAL=1` disable it. This stops a
well-behaved agent from approving its own call, not a hostile process of the same OS user that can restart the gateway.
CLI: `switchboard approvals list|show|approve|deny`. Detail: design doc 3.3 and 3.4; [THREAT_MODEL.md](THREAT_MODEL.md).

## 9. Kill switch

`switchboard kill on|off|status`, or `gateway.kill_switch: true`. Every tool call, resource read and prompt get is refused
with `SB_KILL_SWITCH`. The running gateway latches the switch in memory, and turning it off needs the gateway's presence
check. The latch is memory only: if the `KILL` file is removed and the gateway is then restarted, the switch starts off
with no presence check (`src/killswitch.ts` header). It stops a well-behaved agent, not a same-user process that can restart the gateway.

## 10. Audit chain

`audit.log` under `SWITCHBOARD_HOME` (default `~/.switchboard`); each row has `seq`, `prev_hash` and `hash`; rotation at
20 MB keeps the chain (`src/audit.ts`). `switchboard audit verify [--all]` reports the first break. The hash is unkeyed
SHA-256, so the chain is tamper evident only if the latest hash is anchored somewhere the log writer cannot reach
(`src/audit.ts` header). Write and full calls log an `attempt` row first and fail closed with `SB_AUDIT_FAILED`.
`settings.logs.capture_io` is off by default (design doc 3.7).

## 11. Connectors kit

Local equivalents of hosted integration toolkits: provider auth definitions, connected accounts, generated toolkits, one
MCP server per toolkit. See [CONNECTOR_CONTRACT.md](CONNECTOR_CONTRACT.md) and design doc 3.16.

## 12. Other surfaces

Dashboard SPA with owner sessions, per-client keys (`switchboard client`, `switchboard apikey`), encrypted local vault,
profiles, rate limits and spend budgets (`src/governor.ts`), circuit breaker, optional OAuth 2.1 authorization server
(`settings.oauth_server`).

## 13. Not claimed

- No isolation between two processes of one OS user (design doc 3.15, "What this does NOT do").
- No public hosting, tunnel included, and no multi-tenant mode (design doc 5).
- No scope or client ceiling for callers when no client is registered (section 2).
