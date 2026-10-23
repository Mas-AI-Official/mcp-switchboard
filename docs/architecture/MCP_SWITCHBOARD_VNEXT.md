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

Implementation notes (step 2, `src/principal.ts`, `clientconfig.ts`, `clientadmin.ts`; oracle `verify:principals`). Where the
code makes a choice the text above leaves open, it is recorded here:

- `servers` omitted or empty means no server (a client sees only what it is given). `client add <id>` with no flags creates
  `servers: ["*"]`, `max_scope: read`, `max_risk: low`; on an existing client it changes only the flags given and keeps a
  working key. `max_risk` is stored, shown and, since step 3, enforced on every call (3.4): a call above it is refused with `SB_POLICY_DENY` before any approval exists.
- `max_scope` joins the server and the active profile: the tightest wins and the denial names which one binds. `limits` is
  a fourth governor level, read live, so a reload changes it. `tools` and `exclude_tools` are exposed-name globs (`*`, `?`)
  and apply to tools; resources and prompts follow the client's `servers`.
- `/mcp` with clients configured: no valid credential is 401; a valid credential that names no configured client is 403
  (`SB_NO_CLIENT`, `SB_UNKNOWN_CLIENT`), because the caller is known but has no profile. This holds with `require_auth: never`.
  A key bound to a client that is no longer configured is refused even when no client is configured.
- stdio: with clients configured, `serve` without `--client` does not serve stdio (HTTP, if enabled, continues); stdio only
  and no `--client` exits 1. `--client` must name a configured client.
- OAuth: the token's OAuth client maps to a client only by exact equality of its registered `client_name` and a client id.
- Live changes: the key store is re-read on every request. A gateway watches the config file's mtime, size and inode and, on a
  change, re-parses the whole file through the strict schema and swaps in only `clients` with one assignment; an invalid file
  is ignored and the previous clients stay. Everything else in the config still needs a restart. `client add|rotate|rm` and
  the admin API edit the YAML in place (comments and order kept), validate before writing, and write atomically with a `.bak`.
- Every change to the client set writes an audit row (`client.add`, `client.update`, `client.rotate`, `client.remove`,
  principal `owner:cli` or `owner:dashboard`), never with a token.

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
- `GET /mcp` (wave 2): the endpoint is stateless, so there is no session for a standalone GET to attach an event stream
  to, and the SDK would hold the socket open for as long as the caller likes. After authentication a GET gets 405 with
  `Allow: POST` (an unauthenticated one is still 401). `PUT /api/settings` builds the change on a copy, validates the
  whole result with the config schema and answers 400 `SB_CONFIG_INVALID` with the issues BEFORE the running config or
  the file changes; 0.1.0 saved `require_auth: "bogus"` and then could not load its own file.
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
- Before this store the interactive TTY gate (`approval.ts`) was the only human channel; it was serialised (one
  prompt at a time, approved only by typing that prompt's own random 4 character code, at most 16 waiting). It is
  superseded by the out-of-band flow above and, since step 3, is no longer on the call path.
- `SWITCHBOARD_AUTO_APPROVE=1` stays for test harnesses and is recorded as `decided_via: "env-auto"` in the
  audit row, with a startup warning.
- Every create and decision writes an audit row (`approval_required`, `approved`, `denied`, `expired`).

### 3.4 Risk

`risk` per tool override; `risk_defaults` per server (`{read, write, full}`); `outward: true` per server
raises write and full to high. Gateway default approval: `gateway.approval: { require_for_risk: [high] }`.
Server `approval.require_for` (scopes) keeps working; the two are OR-ed.

Implementation notes (step 3, `src/approvals.ts`, `controlkey.ts`; oracle `verify:approvals`). Where the code makes a choice
the text above leaves open, or differs from it, it is recorded here:

- Store and trust. `approvals.json` is a `WatchedJsonFile` (atomic writes, locked read-modify-write, `.bak`). Only the
  gateway writes decisions: the CLI never edits the file, it asks the running gateway over the control API. Every record the
  gateway writes carries `mac`, an HMAC-SHA256 over the whole record without `mac`. That is a superset of the fields the text
  above names (id, principal, server, tool, args_sha256, expires, status): it also covers client, args_preview, scope, risk, the
  timestamps, decided_via and the run `instance`, so the preview the owner is shown cannot be edited either. Pending, approved,
  denied, consumed and expired records are all signed. A record that does not verify is ignored for matching and listing,
  logged on stderr and as an `approval.ignored` audit row, and dropped at the next write; a record left by an earlier run (its key
  is gone) is the same case, logged once as a count.
- Single use survives a file rollback: consuming is a locked read-modify-write, and the consumed ids are also kept in memory for
  the life of the process, so restoring an older copy of the file cannot approve a used call a second time.
- A damaged `approvals.json` fails closed: the gated call is refused with `SB_APPROVAL_DENIED` (the approval store cannot be
  used), the file is not replaced, and the gateway keeps running. `switchboard approvals list` with no gateway running reads the
  raw file and labels it unverified.
- The match is (principal label `<via>:<id>`, or `internal` for a call with no principal such as the playground or a trigger
  poll; server; tool; args hash). The client label is not part of it. Rotating a client key changes the key id and so the
  principal: an approval does not carry over to the new key.
- The hash is the SHA-256 of the canonical JSON (sorted keys at every depth, no whitespace: the `canonicalJson` of the audit
  chain) of the arguments as the client sent them. `forward()` has no separate validation step; the hash is taken where the call
  arrives, which is also where `call_tool` and every `batch_call` entry land, so the same call through any door matches, and
  before `inject_args` and the rename reversal run. For `resources/read` the bound value is the URI, for `prompts/get` the name
  and arguments.
- TTL (60 to 86400, default 900) is clamped in code as well as bounded by the schema. `gateway.approval.wait_seconds` (0 to 50,
  default 0) polls the store every 100 ms, looks at the kill switch again after any wait (the approval is left unused if it is
  on), and turns a denial or an expiry during the wait into `SB_APPROVAL_DENIED`. The text above says `approval.wait_seconds`;
  the key is `gateway.approval.wait_seconds`.
- Caps: 16 undecided requests per principal and 64 in all; the next distinct request is refused with `SB_RATE_LIMITED` instead of
  queued. The same call repeating reuses its pending record (same id), and the approval_required audit row and the webhook
  notification are written once, when the record is created.
- Presence: `approve` asks `verifyOwnerPresence` with `Approve <tool> on <server> for <client>: <summary>` (the summary is at
  most 120 characters, shortened further so the message fits the 200 characters the prompt keeps), one prompt at a time, and signs
  only after it succeeded and the record was re-checked. While stdio carries the protocol only Windows Hello is accepted (no
  terminal challenge). Presence `none` is selected only when `SWITCHBOARD_INSECURE_APPROVAL=1`, and `SWITCHBOARD_AUTO_APPROVE=1`
  (recorded as `decided_via: env-auto`) stays for harnesses; both print a startup warning. `deny` and withdrawing need no presence.
- Control API: `GET /api/control/approvals`, `GET .../:id`, `POST .../:id/approve|deny`, on the dashboard's listener, outside the
  owner-session gate, behind `Authorization: Bearer <control token>`. The token is minted at every listener start and stored
  DPAPI-wrapped in `SWITCHBOARD_HOME/control.key`. It is a convenience, not a boundary: anything running as the same OS user can
  read it. The boundary is the presence prompt inside the gateway. An owner session does not open the control API and the control
  token does not open the owner routes. Two gateways sharing one SWITCHBOARD_HOME overwrite each other's control key and are not
  supported. A gateway with no HTTP listener (stdio only) cannot have its approvals decided; `serve` says so at start.
- Audit: `server: switchboard`, `tool: approval.<event>` for approval_required, approved, denied, expired and consumed (plus
  `approval.ignored` and `approval.presence_failed`), each with `approval_id` and `risk`. The executed call's own row carries
  `approval_id` and `risk` too, as does every other row of a call whose risk is known. The principal of an approved or denied row
  is the owner channel (`owner:dashboard`, `owner:cli`, `owner:env-auto`).
- Risk (3.4): a tool's `risk` beats the server's `risk_defaults[scope]`, which beats the built-in default (read low, write medium,
  full high); `outward: true` then raises write and full to high and never lowers anything. `gateway.approval.require_for_risk`
  (default `[high]`) is OR-ed with `approval.require_for`. Consequence: with the defaults every full-scope call needs an approval,
  also on a server that had no `approval` block before. `max_risk` is checked after the scope ceiling and before any approval is
  created, so a client cannot put a call it may not make in front of the owner. Resources and prompts use the same gate at scope
  read, so they are gated only when the operator sets `risk` on `resources/read` / `prompts/get` or `risk_defaults.read`.
- Dashboard: an Approvals page (pending with a live countdown, approved but unused, the last 50 decisions), a Clients page (the
  3.1 routes; `DELETE /api/clients/:id?purge=0` revokes keys and keeps the entry), a kill-switch banner and toggle
  (`GET|POST /api/kill`; turning it off goes through gateway presence), and Sign out.
- `approval.ts` (the TTY gate) is off the call path and no longer used by the Router. It stays exported, with its own oracle
  sections, until the owner decides to delete it.

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

Write-ahead (wave 2). For write and full scope the router appends an `attempt` row BEFORE it contacts the upstream:
`phase: "attempt"`, the call's principal, client, risk, approval id and, when `capture_io` is on, the redacted
arguments. It is written with `audit()` directly, not as a verdict: it is not a webhook event and the usage stats skip
it. If the append throws, the call is refused with `SB_AUDIT_FAILED` and the upstream is never contacted (fail
closed); an approval that was already consumed is spent, so the call needs a new one. The result row that follows
(success, upstream error or timeout) carries `attempt_seq`, the `seq` of its attempt row. Read scope keeps after-call
logging: it changes nothing, and a failed append there costs the row (logged loudly), never the result. A call that
waits for an approval writes no attempt row, because nothing has started.

### 3.8 Kill switch

`switchboard kill on|off` (file `~/.switchboard/KILL`) or `gateway.kill_switch: true`: every tool call,
resource read and prompt get is refused with `SB_KILL_SWITCH` until cleared. Checked per call.

Turning it off (wave 2). OFF re-opens every tool, so it needs the owner present, performed by the gateway as for an
approval: the dashboard route does it, and so does `switchboard kill off`, which asks the running gateway
(`POST /api/control/kill/off`, control token) instead of deleting the file itself. A caller that can only run the
CLI, such as an agent with a shell, therefore cannot undo the owner's emergency stop. No gateway reachable: exit 1 and
the file stays (starting a gateway is safe, it refuses every call while the file exists). Nothing to clear: no gateway
needed. `kill on` and `kill status` need none. The control API has no other kill-switch route. Both doors write
`kill.off` and `kill.off_refused` audit rows under `owner:dashboard` or `owner:cli`.

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

### 3.14 Wave 2 hardening (review findings, oracle `verify:hardening-2`)

Eleven findings from the wave 1 adversarial review, each reproduced before it was closed. The contract:

- **Unlisted tools (router).** A namespaced name resolves only to a tool the upstream LISTED at mount. `serverId__x` for
  an `x` the server never listed is `SB_UNKNOWN_TOOL`, in `tools/call`, `call_tool` and every `batch_call` entry; when
  the prefix names a real server the refusal is audited as a deny (a name that names nothing stays unaudited). 0.1.0
  split the name and forwarded the rest, so every listing-based control (profiles, client globs, tool overrides) was
  bypassed by naming a hidden tool directly. A tool an upstream adds after mount is unknown until the next mount.
- **Server ids.** `^[a-z0-9][a-z0-9_-]{0,63}$` with no `__` (the first `__` splits id from tool), unique in the file.
  Config load fails with the path of the bad id (`servers.2.id`) and names both positions of a duplicate. The dashboard
  add path derives its id with `uniqueServerId` (prefix stripped, cut to leave room for `-NN`, `toolkit` as the fallback)
  and refuses an entry the strict schema would not load again.
- **Package strings.** An npx package is a name, optionally `@version`: no leading `-` (`--call=...` runs a command),
  no whitespace, no URL, path or git spec (`packagespec.ts`; a PyPI validator is provided for a future `uvx` source, none
  exists yet). A floating name is VALID, because existing configs have them: it still mounts, with a `WARNING` line in the
  startup log for each one and in `switchboard doctor` (kept in `warnings`, apart from `problems`). A NEW mount (dashboard
  or catalog add) must carry an exact version, `name@x.y.z`: the catalog's own version when `toolkits sync` recorded one,
  else the one sent with the add (`{"version":"1.2.3"}`); anything else is 400 `SB_PACKAGE_UNPINNED`. The registry
  re-checks the string before it spawns anything. `init` writes a pinned starter server.
- **Remote MCP upstreams.** `source: remote` passes `guardedMcpFetch(network)` to the SDK transport as its `fetch`: the same
  address classes, exact-host `allow_private`, pinned connection and per-hop redirect checks as every other outbound call.
  It streams (an MCP reply can be an event stream open for the whole session), so the deadline covers resolution, connect
  and headers only, there is no body cap, and aborting the caller's signal errors the body with the abort reason.
  `redirect: "manual"` (what SDK 1.32 asks for) returns the 3xx unfollowed so the SDK's same-origin policy applies and
  each permitted hop calls the guard again.
- **Path parameters (http-tool, app2mcp).** `.` and `..` are refused before a request exists, and so is a filled path
  containing a dot segment (two values can form one together). Writing the dots as `%2E` is not a fix: the WHATWG URL
  parser collapses `%2e%2e` too, so the design's "encode or reject" is "reject". Every other value stays one encoded
  segment, so `a/../x` cannot leave the declared path.
- **Provider strings.** `stripControl` (ANSI sequences, C0, DEL, C1, bidi and zero-width formatting characters, the line
  separators; newline and tab kept) runs on every message of the logger, stderr and stdout, so no caller can forget it.
  `safeText(value, max)` is the form for one value inside a message (control characters gone, whitespace collapsed, capped
  with `...`); it is applied to the DCR `client_name` in the registration log and on the consent and sign-in pages, to
  upstream tool, resource and error text in router warnings, and to the names the CLI prints for `list`, `toolkits
  discover` and `local-llm`. The stored `client_name` is not altered: the client mapping of 3.1 compares it exactly.
- **Webhook.** The `error` carried by a webhook payload is scrubbed with the audit's `redactSecretShapes` before it is
  handed over; the audit row scrubs its own copy, so the two never differ in what they hide.

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
