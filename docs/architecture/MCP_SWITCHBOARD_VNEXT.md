# MCP Switchboard vNext: governed tool hub

Status: accepted, 2026-10-23. Supersedes nothing; extends ARCHITECTURE.md.
Evidence base: code review and live probes of 0.1.0 (HEAD ce8cb00 plus the catalog taxonomy commit), the
2026-07-28 MCP specification, the TypeScript SDK registry, and provider documentation. Every defect named
below was reproduced on an isolated instance before this document was written.

## 1. Problem

Switchboard 0.1.0 aggregates MCP servers behind one endpoint with scopes, a vault and an audit log. It is
not yet safe to put credentialed or outward-facing servers (voice, video, social publishing) behind it,
and it cannot tell its callers apart:

| ID | Defect (0.1.0) | Evidence |
|---|---|---|
| D1 | No Host or Origin validation; loopback default has no auth. DNS rebinding reaches every route. | `Host: evil.example` minted an API key and ran `initialize` |
| D2 | Read classifier is a bare prefix regex (`browser_run_code`, `fetch_and_execute` are "read") | `policy.ts` READ_RE, 29 of 54 sampled names |
| D3 | OAuth AS consent is satisfied by the requester (register, consent, token with no credential) | live walk, 201/200/302/200/200 |
| D4 | Loopback gate trusts the socket peer, so any tunnel passes it | `X-Forwarded-For` request minted a key |
| D5 | Every stdio upstream inherits the full gateway environment | `get-env` returned 119 variables |
| D6 | API key store and vault go stale across processes; the gateway rewrites the file from memory | revoked key kept working and came back |
| D10 | Vault key beside the ciphertext; torn write wipes the vault | demonstrated |
| D11 | Resources and prompts bypass policy, approval and limits | `router.ts` resource paths |
| D12 | No principals: Claude Code, Codex, Daena and a local model are the same anonymous actor | `callTool(name, args)` |
| D13 | `capture_io` stores bodies in cleartext; redaction is by key name only | audit row with env preview |
| D14 | Approval is a TTY prompt: unbound to arguments, no expiry, unusable when stdio is active | mechanism test |
| D23 | SDK 1.29.0 has 5 advisories and no 1.x supports MCP 2026-07-28 | npm audit, SDK constants |

## 2. Decisions

1. **Keep the TypeScript codebase.** 26 oracles with 1,201 passing checks are an asset. Fix in place.
2. **Switchboard is the policy authority.** Connector providers (Composio, local guard servers, remote MCP
   servers) are executors. No provider-side hook, firewall or approval is trusted as the control; ours run
   first, at call time, on every route.
3. **Every caller is a principal.** HTTP callers authenticate with a per-client key (or an OAuth token whose
   client maps to a principal). The key is bound to a client profile with a ceiling. Unauthenticated
   access exists only for loopback when no client is configured (backward compatible single-user mode).
4. **Human approval is out of band.** High-risk calls create a pending approval bound to
   `(principal, server, tool, sha256(canonical args))`, expiring and single use. Only the owner channel can
   approve: the CLI with an owner-presence check (Windows Hello where available, else a TTY code), or the
   dashboard with an owner session. No MCP tool and no client key can approve anything.
5. **Credentials stay with whoever holds them least exposed.** Guard servers that read their own keys from
   the OS credential store are mounted as `binary` upstreams with no secret in Switchboard config. The
   Switchboard vault key is protected with the OS user scope (DPAPI on Windows) and written atomically.
6. **Composio is optional and off by default.** A native `composio` source calls the REST API directly
   (no SDK dependency, so no supply-chain age risk), exposes only allowlisted toolkits, and routes every call
   through Switchboard policy. Reason it is optional: Composio holds OAuth tokens in its cloud and disclosed
   a credential breach in May 2026; it is the fastest path to many social platforms, not the default custodian.
7. **One stdio bridge for every client.** `switchboard bridge --client <id>` relays JSON-RPC between a
   client's stdio and the shared HTTP gateway, authenticating with that client's key loaded from a
   user-protected key file. Every MCP client supports stdio, so one shared gateway (one warm set of upstream
   processes) serves Claude Code, Claude Desktop, Codex, Gemini/Antigravity, the DeepSeek harness and any
   agent platform, with distinct identities and no tokens written into client config files.
8. **Protocol: dual era.** Move to the official TypeScript SDK v2 packages (`@modelcontextprotocol/server`,
   `/client`, 2.3.1) when the migration spike confirms they serve 2026-07-28 and the handshake era from one
   endpoint. Until then bump to `@modelcontextprotocol/sdk` 1.32.1 (security fixes, same API); modern
   clients fall back to `initialize` automatically. Compatibility is claimed only for eras a test exercises.
9. **Scope is necessary, risk decides approval.** Scope (read/write/full) stays the ceiling check. A second
   axis, risk (low/medium/high), decides approval. Outward-facing, spend-bearing and irreversible tools are
   high. Defaults: read is low, write is medium, full is high; `outward: true` on a server makes its writes
   high.

## 3. Components and contracts

### 3.1 Principals and clients

Config (new top-level `clients`, optional):

```yaml
clients:
  claude-code:
    description: Claude Code CLI
    servers: ["*"]                  # server id globs this client may see and call
    tools: []                       # optional tool allowlist (exposed-name globs); empty = all on allowed servers
    exclude_tools: []
    max_scope: full                 # ceiling, can only lower the server ceiling
    max_risk: high                  # highest risk this client may request (high still needs approval)
    limits: { per_minute: 60 }      # optional, same shape as server limits
  local-model:
    servers: ["voice", "youtube"]
    max_scope: read
    max_risk: low
```

- `Principal = { id, client, via: "apikey" | "oauth" | "stdio" | "loopback-anonymous" }`.
- API key records gain `client` (string). `switchboard client add <id>` creates the client entry if missing,
  issues a key bound to it, and writes the token to `~/.switchboard/clients/<id>.key` protected for the
  current OS user (DPAPI on Windows; mode 0600 elsewhere). The token is never printed unless `--print`.
- When `clients` is non-empty, `/mcp` requires a principal on every request regardless of bind host.
- Listing and calling are both filtered by the principal's client profile. The effective ceiling is the
  tightest of server, active profile and client. Audit rows carry `principal` and `client`.
- stdio serve mode takes `--client <id>`; it is recorded as `via: "stdio"` (an assertion by the launching
  process, documented as such). The bridge is the authenticated path.

### 3.2 HTTP hardening

- Host allowlist on every route: `127.0.0.1:<port>`, `localhost:<port>`, `[::1]:<port>`, plus the host of
  `settings.public_url` for `/mcp` and OAuth routes only. Other hosts get 403 with no body detail.
- Origin: if present it must match the allowlist (scheme + host + port) on every non-GET route and on
  `/mcp`; otherwise 403.
- Admin API (every route that mutates state or executes a tool, and the GET routes that reveal settings,
  audit, usage, keys or tools) requires an owner session: an HttpOnly, SameSite=Strict cookie issued by
  `POST /api/session` in exchange for a one-time login code. `switchboard dashboard login` mints the code
  after an owner-presence check and opens the browser at `/#login=<code>`. Codes live 120 s and work once.
  Client API keys are never accepted on admin routes.
- Mutating admin requests also require the header `X-Switchboard-CSRF` equal to the session's CSRF value.
- Security headers on every response: `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `X-Frame-Options: DENY`, a restrictive CSP for the SPA; `x-powered-by` disabled.
- OAuth AS consent (`/oauth/consent`) requires an owner session. DCR is rate limited and capped.
- `listen` errors (port in use) fail loudly and exit non-zero instead of shadowing.
- Request URLs longer than 4096 characters get 414 in the first middleware after the security headers, before
  the Host check parses the path. Anything that runs before authentication must be linear in its input: the
  trailing-slash trim on the request path and on the OAuth `resource` parameter is a loop, not a regex
  (`stripTrailingSlashes`), because the regex is quadratic on a long run of slashes.

### 3.3 Approvals

Store `~/.switchboard/approvals.json` (atomic writes, re-read on every access so the CLI and the gateway
share it). Record:

```json
{ "id": "ap_7KQ2M9XD", "principal": "apikey:3f9a..", "client": "codex", "server": "voice",
  "tool": "text_to_speech", "args_sha256": "..", "args_preview": {"text": "..."}, "scope": "write",
  "risk": "high", "reason": "..", "created": "..", "expires": "..", "status": "pending",
  "decided_via": null, "decided_at": null }
```

- `forward()`: when policy says approval is required, consume a matching approved record if one exists
  (match on principal, server, tool and args hash; unexpired; not consumed). Otherwise create (or reuse) a
  pending record, optionally wait up to `approval.wait_seconds` (default 0, max 50) polling the store, and
  if still pending return `isError` with code `SB_APPROVAL_PENDING`, the id, the expiry and the exact owner
  instruction. The client repeats the identical call after approval.
- Statuses: pending, approved, denied, consumed, expired. TTL default 900 s, configurable 60 to 86400 s.
- Presence is performed by the GATEWAY process, never trusted from a caller. Files under SWITCHBOARD_HOME are
  writable by any process of the same OS user, so a record an agent can write proves nothing. The gateway
  holds a random HMAC key in memory only (new on every start); an approval counts only when its decision
  carries a valid HMAC from that key, which the gateway writes after its own presence check succeeded. A
  forged or pre-restart record is ignored (approvals expire within minutes anyway).
- Approve channels both end in the same gateway-side check: the dashboard (owner session plus CSRF) and the
  CLI `switchboard approvals approve <id>` (which asks the running gateway over its loopback admin API). The
  gateway then shows Windows Hello with the exact action ("Approve <tool> on <server> for <client>: <short
  argument summary>"). Hello unavailable: TTY challenge on the gateway console when one is attached, else
  refuse. `--presence none` only with `SWITCHBOARD_INSECURE_APPROVAL=1` (test harnesses).
- CLI: `switchboard approvals list|show <id>|approve <id>|deny <id>`. Deny needs no presence check.
- Dashboard: an Approvals page lists pending records with the argument preview and a live countdown.
- Until this store lands, the interactive TTY gate (`approval.ts`) is the only human channel and is serialised:
  every pending call waits in one queue behind one readline interface, only the head prompt is shown, and it
  is approved only by typing that prompt's own random 4 character code. A bare `y`, a wrong code, type-ahead
  and EOF deny, so one typed line can resolve at most one call (0.1.0: one `y` approved a whole `batch_call`).
  At most 16 calls may wait; the rest are refused at once. Superseded by the out-of-band flow above.
- `SWITCHBOARD_AUTO_APPROVE=1` stays for test harnesses and is recorded as `decided_via: "env-auto"` in the
  audit row, with a startup warning.
- Every create and decision writes an audit row (`approval_required`, `approved`, `denied`, `expired`).

### 3.4 Risk

`risk` per tool override; `risk_defaults` per server (`{read, write, full}`); `outward: true` per server
raises write and full to high. Gateway default approval: `gateway.approval: { require_for_risk: [high] }`.
Server `approval.require_for` (scopes) keeps working; the two are OR-ed.

### 3.5 Classifier

Tokenize the tool name (split on `_ - . /` and camelCase, lowercase). Read only when the first token is a
read verb AND no token is a write or exec verb (run, exec, execute, eval, evaluate, click, type, press,
upload, send, post, publish, create, update, set, write, put, patch, mutate, apply, deploy, push, replace,
generate, clone, design, remix, convert, transfer, pay, buy, order, submit, schedule, invite, share, import,
install, start, stop, restart, kill, and, then). Full when any token is a destructive verb (existing list).
Otherwise write. Upstream annotations may only tighten: `destructiveHint: true` raises to full;
`readOnlyHint: true` never lowers. Per-tool `policy` overrides still win.

### 3.6 Child environment

Stdio children get the SDK safe default environment plus a platform allowlist (Windows: SYSTEMROOT,
WINDIR, COMSPEC, PATH, PATHEXT, TEMP, TMP, USERPROFILE, HOMEDRIVE, HOMEPATH, APPDATA, LOCALAPPDATA,
PROGRAMDATA, PROGRAMFILES, PROGRAMFILES(X86), NUMBER_OF_PROCESSORS, PROCESSOR_ARCHITECTURE,
NPM_CONFIG_CACHE, NODE_EXTRA_CA_CERTS), plus the server's `env` and `credentials`, plus names listed in
`env_passthrough`. Nothing else crosses. A passthrough name matching the secret pattern is refused unless
also listed in `env_passthrough_secrets`.

### 3.7 Audit

Rows gain `seq`, `principal`, `client`, `risk`, `approval_id`, `prev_hash`, `hash` (SHA-256 over the
canonical row without `hash`). `switchboard audit verify` checks the chain. `capture_io` defaults to false
and, when on, string values are scanned for secret shapes (provider key prefixes, bearer tokens, JWTs, PEM
blocks, long high-entropy tokens) and replaced. Rotation at 20 MB keeps the chain (`prev_hash` carries over).
Every scrub is linear in its input and looks at no more than 8192 characters: longer text is cut back to a token
boundary (so no half of a secret survives) and marked `[truncated:<length>]`. This applies to captured I/O and to
`error` text, which is scrubbed whether or not `capture_io` is on, because an upstream chooses it.

### 3.8 Kill switch

`switchboard kill on|off` (file `~/.switchboard/KILL`) or `gateway.kill_switch: true`: every tool call,
resource read and prompt get is refused with `SB_KILL_SWITCH` until cleared. Checked per call.

### 3.9 Storage

Vault, API keys, OAuth state, approvals and config writes use write-temp, fsync, rename, keep `.bak`. A file
that exists but does not parse is an error, never an empty store. API key and vault stores re-read when the
file changes, so CLI changes reach a running gateway. On Windows the vault key is stored DPAPI-protected
(`vault.key.dpapi`); an existing raw `vault.key` is migrated and removed.

### 3.10 Resources and prompts

`resources/read` and `prompts/get` go through policy at read scope, the client filter, the kill switch and
the governor. Unlisted resource URIs are not broadcast to every server. The server that DECLARED a matching
resource template owns the URI; templates are chosen by the upstream and URIs by the client, so matching is a
linear NFA run (`uritemplate.ts`, no RegExp built from upstream text) with caps on template and URI length and one
work budget per lookup. An out-of-bounds template is a non-match, never an error.

### 3.11 Composio source (superseded)

Superseded on 2026-10-23 by the owner's decision: the goal is a local equivalent of Composio, not a client of
it. The method Composio uses per platform (auth definition plus actions that wrap the platform's own API,
connected accounts, search, MCP exposure) is re-implemented locally as Switchboard toolkits; the architecture
is recorded in docs/architecture/LOCAL_TOOLKITS.md once its research ADR is ruled. The text below is kept only
as the record of the rejected option and is not built on main.

```yaml
- id: social
  source: composio
  composio:
    api_key: ${vault:composio_api_key}
    user_id: owner
    toolkits: [youtube, instagram, facebook]
    tools: ["YOUTUBE_*", "INSTAGRAM_*"]      # optional allowlist of tool slugs
    allow_sensitive: false                   # gmail, googledrive, outlook and similar refused unless true
  outward: true
```

Mount lists tools for the allowlisted toolkits (REST v3.1), exposes them namespaced, and executes through
`POST /api/v3.1/tools/execute/{slug}`. `switchboard connect composio --toolkit <slug>` creates or reuses an
auth config, requests a connection link, opens it, polls until ACTIVE, FAILED or EXPIRED (10 minute cap),
and deletes the provisional connection on failure or cancel. `switchboard connections` shows real status
from the provider, never from saved config. Tests use a local mock of the API.

### 3.12 Bridge

`switchboard bridge --client <id> [--url http://127.0.0.1:8088/mcp]` reads newline-delimited JSON-RPC on
stdin, POSTs each message with `Authorization: Bearer <client key>` and the negotiated
`MCP-Protocol-Version`, parses JSON or SSE responses, writes each JSON-RPC message to stdout, and answers
with a JSON-RPC error (not a crash) when the gateway is down. Logs go to stderr only.

### 3.13 Client registration

`switchboard install <client>` supports claude-code, claude-desktop, codex, gemini, antigravity, dsh, cursor
and vscode. Default mode writes a bridge entry. Flow: preview, validate, backup, confirm (`--yes` skips the
prompt), write (the client's own CLI when it has one, else an atomic file write), probe, roll back on probe
failure.

## 4. Order of work

1. Security core on SDK 1.32.1: D1, D2, D4, D5, D6, D10, D11, D13 (storage and capture), kill switch, listen errors.
2. Principals, clients, approvals, risk, audit chain (D12, D14, D3).
3. Bridge, client installers, Composio source, dashboard pages.
4. SDK v2 dual-era migration after the spike.
5. Adversarial review, full oracle run, live smoke with each client.

Each step lands with new deterministic oracles; no existing oracle is weakened.

## 5. Not decided here

- Hosting a public endpoint (tunnel or cloud): out of scope until the OAuth AS issues audience-checked
  tokens and supports Client ID Metadata Documents.
- Multi-tenant SaaS isolation: one principal set per process today.
