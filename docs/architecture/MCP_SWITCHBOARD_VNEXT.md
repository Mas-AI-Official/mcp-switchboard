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
  assistant-a:
    servers: ["gmail"]
    accounts: { google: ca_work }   # connector accounts: the account this client runs as (3.16); "*" lets it choose
```

- `Principal = { id, client, via: "apikey" | "oauth" | "stdio" | "loopback-anonymous" }`.
- API key records gain `client` (string). `switchboard client add <id>` creates the client entry if missing,
  issues a key bound to it, and writes the token to `~/.switchboard/clients/<id>.key` protected for the
  current OS user (DPAPI on Windows; mode 0600 elsewhere). The token is never printed unless `--print`.
- When `clients` is non-empty, `/mcp` requires a principal on every request regardless of bind host.
- Listing and calling are both filtered by the principal's client profile. The effective ceiling is the
  tightest of server, active profile and client. Audit rows carry `principal` and `client`.
- stdio serve mode takes `--client <id>`; it is recorded as `via: "stdio"`. Since wave 3 (3.15) it also needs the
  client's key: the stored key file must hold a token the key store accepts for that client, so revoking a client
  (`client rm`) revokes it on stdio too. It is still the launching process that names the client, and the key file is
  readable by every process of the OS user (see 3.15, "What this does not do"). The bridge is the authenticated path.

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
- Live changes: the key store is re-read on every request. A watcher looks at the config file's mtime, size and inode and, on a
  change, re-parses the whole file through the strict schema; an invalid file is ignored and the previous clients stay.
  An ordinary watcher (the CLI, a library caller) swaps in only `clients` with one assignment. A RUNNING GATEWAY's watcher is
  pinned (3.15): it reports the difference and does not apply it. Everything else in the config still needs a restart. `client add|rotate|rm` and
  the admin API edit the YAML in place (comments and order kept), validate before writing, and write atomically with a `.bak`.
- Every change to the client set writes an audit row (`client.add`, `client.update`, `client.rotate`, `client.remove`),
  never with a token. The principal is `owner:dashboard` (an owner session), `owner:cli` (a gateway-side presence check
  passed, named in the reason) or, when nothing proved the owner, `local:cli` (3.15).

### 3.2 HTTP hardening

- Host allowlist on every route: `127.0.0.1:<port>`, `localhost:<port>`, `[::1]:<port>`, plus the host of
  `settings.public_url` for `/mcp` and OAuth routes only. Other hosts get 403 with no body detail.
- Origin: if present it must match the allowlist (scheme + host + port) on every non-GET route and on
  `/mcp`; otherwise 403.
- Admin API (every route that mutates state or executes a tool, and the GET routes that reveal settings,
  audit, usage, keys or tools) requires an owner session: a session id sent in the `X-Switchboard-Session` header,
  issued by `POST /api/session` in exchange for a one-time login code (no cookie, see 3.15). `switchboard dashboard login`
  asks the RUNNING gateway, which performs the owner-presence check itself, mints the code in its own memory and opens
  the browser at `/#login=<code>`. Codes live 120 s and work once. Client API keys are never accepted on admin routes.
- Mutating admin requests also require the header `X-Switchboard-CSRF` equal to the session's CSRF value.
- Security headers on every response: `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `X-Frame-Options: DENY`, a restrictive CSP for the SPA; `x-powered-by` disabled.
- OAuth AS consent is decided in the dashboard (`GET /api/oauth/pending/:id`, `POST /api/oauth/consent`) with an owner
  session and the CSRF value, never on a page of its own (3.15). DCR is rate limited and capped.
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
needed. `kill on` and `kill status` need none. The control API's kill-switch routes are `kill/off` (presence) and, since wave 3, `kill/on`. Both doors write
`kill.off` and `kill.off_refused` audit rows under `owner:dashboard` or `owner:cli`. Wave 3 (3.15) adds the latch: the
gateway keeps the switch on in memory once it has seen it, so deleting the KILL file does not turn it off, and the control
API gains `POST /api/control/kill/on`.

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
is recorded in docs/architecture/LOCAL_TOOLKITS.md and integrated with principals and approvals in 3.16. The text
below is kept only as the record of the rejected option and is not built on main.

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

Implementation notes (step 3, `src/clients.ts`, `installer.ts`, `cliexec.ts`, `tomlscan.ts`, `dshpatch.ts`; oracle
`verify:installers`). Where the code makes a choice the text above leaves open, it is recorded here:

- Commands: `switchboard install <client> [--mode bridge|http] [--scope user|project] [--yes] [--dry-run] [--dsh-profile <p>]
  [--dir <d>] [--name <n>]` and `switchboard uninstall <client>` with the same flags (it removes only the entry, after a backup,
  and keeps the registered client and its key). The default scope is `user`: a bridge entry holds absolute paths of this
  machine, which do not belong in a project file that gets committed (0.1.0 defaulted to project-local). `--global` and `--print`
  remain as aliases of `--scope user` and `--dry-run`. A project scope needs an existing `--dir`, and is refused for Claude
  Desktop, Antigravity and dsh, which have none.
- Entry: `command` is the absolute path of the running node, `args` are `[dist/cli.js, bridge, --client, <id>]` plus `--url` exactly
  when the gateway URL is not `http://127.0.0.1:8088/mcp` (so also a LAN bind on port 8088, which the default URL would not
  reach). `type: "stdio"` is added where the client's own docs show it (Claude Code, Cursor, VS Code). The key never appears.
- Registration: after the confirmation and before the client file is touched, an unconfigured client is created with
  `servers ["*"]`, `max_scope write`, `max_risk high` (the install defaults of this section; `client add` with no flags gives
  read and low). A configured client keeps its settings and gets a key only when it has no working one. A rollback of the client
  file does not undo the registration. The preview says all of this, `--dry-run` registers nothing.
- Write route: the client's own CLI when it is on PATH (`claude mcp add-json <name> <json> --scope user|project`, which refuses an
  existing name, so the old entry is removed first; `codex mcp add <name> -- <command> <args...>`, user scope only, replaces;
  `agy mcp add <name> -- <command> <args...>`, "add or update", syntax confirmed from `agy mcp add --help`). CLIs are started by
  the absolute path found in PATH (never the working directory, relative PATH entries skipped) without a shell. A Windows
  `.cmd` shim (an npm-installed `codex` or `claude`) needs cmd.exe: every argument is quoted for the C runtime and one holding
  `& | < > ^ %` or `!` or a line break is refused, and then the file is edited instead. Otherwise, and for every client without
  a documented command, the file is edited and replaced atomically through the shared helper, following a symlink so a dotfile
  manager's link is not replaced.
- Refusal and drift: a JSON file must be an object (comments and trailing commas are not accepted, a BOM is kept), a TOML file
  must pass `tomlscan.ts` (a syntax scanner, there is no TOML dependency) and keep the entry as a `[mcp_servers.<name>]` table
  (dotted keys or an inline table are refused, not duplicated), a dsh patch file must be a block-style YAML list whose
  `# BEGIN <name>` / `# END <name>` pairs balance. The file is read again just before the write; if it changed while the owner
  read the preview, nothing is written. The entry name must match `^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$` (a TOML bare key and a dsh
  serverName).
- Backup and rollback: a timestamped byte copy `<file>.bak-switchboard-<YYYYMMDDTHHMMSSZ>` (a counter is added within the same
  second) is taken for every file route and for codex and agy; for `claude mcp` no copy of the large, constantly rewritten
  `~/.claude.json` is made, the previous entry is recorded (and saved under `SWITCHBOARD_HOME/install-backups`) and put back with
  `add-json`. A failed probe or write restores the file byte for byte, removes a file the install created, or asks the CLI to
  remove the entry when there was none. Backups are never deleted.
- Probe: registration first (`claude mcp get <name>`, which exits 0 even for "Failed to connect", observed; `codex mcp get <name>
  --json`, whose command and args must match; `agy mcp list`, whose row must name our script; or a re-read of the file). Then,
  in bridge mode and only when a TCP connect to the gateway address succeeds, the bridge entry is started once with an
  `initialize` request (without the operator's `SWITCHBOARD_KEY`, so the stored client key is what is tested) and must answer
  with a result. A gateway that is not running is reported, not a failure. Codex rewrites its own TOML, so an existing entry
  counts as identical when its `get --json` says so, not by text.
- Antigravity: `agy` 1.4.5 reads `~/.gemini/config/mcp_config.json` (observed: `agy mcp list` shows exactly that file's servers and
  none of the ones left in `~/.gemini/antigravity/mcp_config.json`, the older location, which is left alone). The file target is
  the newer path unless only the older file exists and there is no `~/.gemini/config/.migrated` marker. Where `agy mcp add`
  itself writes is inferred from that listing, not observed.
- dsh: the profile file is `$DSH_HOME` (default `~/.dsh`) `/profiles/<profile>/cordis.patch.yml`, default profile `web`. The
  row is a root-level `insert` entry (`dsh --dump-config-schema`: "An insert appends entries") for `@deepseek-ai/dsh-mcp-client`
  (its README: `serverName`, `transport: stdio | streamable-http`, `command`, `args`, `url`, `headers`). It is appended at the
  end of the file, outside every generated block, between `# switchboard:begin` and `# switchboard:end`, a spelling that is not a
  BEGIN/END pair, so it can be found again and a generated-block reader never takes it for one. A row with the same id that
  this tool did not write is refused (install) or left alone (uninstall).
- `--mode http` is supported where the client's config can name the token by environment reference: Claude Code (`${VAR}`),
  Cursor and VS Code (`${env:VAR}`), Codex (`bearer_token_env_var`), dsh (a `!!js` header expression). Claude Desktop, Gemini CLI
  and Antigravity are refused with that reason, because the alternative would be a token inside a client file. The 0.1.0 header
  for Claude Code, `${env:VAR}`, was wrong for its documented syntax and is now `${VAR}`. The library `buildPlan` without a mode
  keeps its 0.1.0 meaning (http where the client can dial a URL); the CLI always passes the mode.
- Not covered: a Store (MSIX) install of Claude Desktop keeps its config under `%LOCALAPPDATA%\Packages\Claude_*`, which is not
  searched; a PowerShell-only shim (`.ps1`) and a Windows app execution alias are not started by this module (the file is edited
  instead); JSON with comments (VS Code accepts it) is refused rather than rewritten.

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

### 3.15 Wave 3 hardening (identity and approvals review, oracle `verify:hardening-3`)

Six findings from the wave 2 identity and installer reviews, reproduced on 6deb12f (HEAD of this branch) against the
adversary this document names: a process of the SAME OS user, such as an agent with a shell, that can run the CLI,
read and write every file under SWITCHBOARD_HOME and reach the loopback ports. Two of them are one defect (the kill
file). Every defect below was reproduced before it was closed; the oracle replays each attack and fails on the old code.

- **The gateway mints the login code (finding 1; 3.2 already said the code is minted after an owner-presence check).**
  0.1.0 did the check inside `switchboard dashboard login`, a process the caller controls: `--presence none` plus
  `SWITCHBOARD_INSECURE_APPROVAL=1` in the caller's own environment passed it, and the code was a file under
  `SWITCHBOARD_HOME/login-codes/`, as were the sessions (`sessions.json`), both writable by the caller. Now
  `POST /api/control/login` (control token) makes THIS gateway ask `approvals.verifyPresence` ("Sign in to the MCP
  Switchboard dashboard"), mint the code and return it; the CLI has no `--presence` option and no environment variable
  of the caller reaches the check. One prompt at a time (a second request while one is open is 429 `SB_PRESENCE_BUSY`).
  Codes (120 s, once) and sessions (12 h) are in the gateway's memory only; `login-codes/` and `sessions.json` are not
  read, not written, and a restart signs the owner out. Audit: `dashboard.login` and `dashboard.login_refused`.
- **The session is a header, not a cookie (finding 4).** A cookie is not scoped by port (RFC 6265, and SameSite does not
  separate ports): after sign-in, a browser visit to any other listener on `127.0.0.1` handed it a working owner session
  (observed in Chromium), and the CSRF value was derived from the session id and returned to a cookie-only caller, so the
  cookie alone could mint a full-privilege client key. Now `POST /api/session` answers `{session, csrf, expires_at}` and sets
  no cookie; the SPA keeps both in `sessionStorage` (scoped to the origin, port included, never sent by the browser on its
  own) and sends `X-Switchboard-Session` on every call and `X-Switchboard-CSRF` on every mutating one. The CSRF value is
  random per session and `GET /api/session` does not return it. A Cookie header is never read. Consent for the OAuth server
  moves the same way: `/authorize` renders no form (a navigation cannot carry a header), it links to `#/oauth/<id>` in the
  dashboard, and the decision is `POST /api/oauth/consent` with the session and CSRF headers; the `/oauth/consent` page and
  form route are gone. A session lives in one tab: open the consent link in the tab that `dashboard login` opened.
- **The kill switch is latched in the gateway (findings 2 and 6; 3.8 says an agent with a shell cannot undo the stop).**
  The file alone was the state, so `rm KILL` re-opened every tool, with no audit row. Now the first time the gateway
  process sees the switch on (the file, or `setKillFile(true)` in this process) it latches it in memory; from then on it is on
  whatever the file says. The only way back is `setKillFile(false)`, which the gateway calls after its own presence check
  (the dashboard toggle and `POST /api/control/kill/off`, which also clears a latch whose file is already gone). A file that
  vanishes while latched writes one `kill.tamper` audit row and one error log line and keeps refusing; a file seen for the
  first time writes `kill.latched`. `kill on` against a running gateway goes through `POST /api/control/kill/on`, which writes the
  file and latches in one step (a delete right after cannot win a race), and a 250 ms timer in the gateway latches a CLI-made
  file even when nobody is calling. `switchboard kill status` and `kill off` also ask the gateway what it is doing. Residual:
  the latch is memory, so a restart starts without it (a file still present latches again at the first look).
- **Clients are administered through the gateway (finding 3).** `client add|rotate` and the client registration of
  `install` go through the running gateway: `POST /api/control/clients/:id/add|rotate` show the owner the exact grant in the
  presence prompt ("Register client 'x': servers *, max_scope full, max_risk high"), check that what was shown is still what
  will be done after the prompt, then act inside the gateway (live at once, key file written). `client rm` (a revocation) needs no
  presence, like deny. With no gateway running there is nothing to ask: the CLI writes the files, and the audit row is
  `local:cli` with "no owner presence proven", never `owner:cli`. The running gateway's client watcher is pinned: the YAML file is
  writable by the caller, so a client added or widened there (plus a key written to the key store) would be a full-privilege client
  nobody approved. The gateway applies a client change only from ClientAdmin and at start; a file that differs is reported once
  (warning and a `client.drift_ignored` audit row), shown by `client list`, and loaded by the next restart. `serve --client` now
  needs the client's key, which makes `client rm` revoke stdio as well (a revoked client used to stay serveable by assertion).
  The dashboard's client routes are unchanged: their proof is the owner session, which now exists only after presence.
- **One approval, one upstream call (finding 5).** `applyArgTransforms` let the later key win after the reverse rename while
  the approval hash ignores key order, so `{to, recipient}` and `{recipient, to}` were one approval and two upstream calls.
  Two arguments that map to the same upstream name are now refused with `SB_BAD_REQUEST` (`ArgCollisionError`), in the router
  BEFORE the governor, the approval request and any approval (nothing to approve, nothing to spend), and again inside
  `applyArgTransforms`. The rename lookup is a Map (an argument named `constructor` was renamed to the source text of
  `Object`), and an own `__proto__` argument stays an own key. With no collision the mapping is injective, so the approval hash
  determines the upstream arguments.

What this does NOT do (stated plainly, and recorded as open):

- **Same-user agents are not isolated from each other.** Decision 7 promises distinct identities, and they are distinct against
  mistakes and against a caller that has no key, but they are not a boundary between processes of one OS user: a client key file is
  DPAPI user-scope, which separates nothing between two processes of that user, so a process that is `lowmodel` can run
  `switchboard bridge --client boss` and be `boss`; `apikey new --client boss` prints a token for it as well. Closing that needs an
  OS boundary this design does not have: a separate OS account or a sandbox per agent, or a per-launch secret handed only to the
  process a client starts. Until then Switchboard governs what a well-behaved agent may do and stops an agent from raising its own
  ceiling or minting a client (which needs the owner present); it does not stop agent A from acting as agent B.
- Everything on disk under SWITCHBOARD_HOME and the config file is trusted at gateway start. An agent that can stop and restart
  the gateway can load an edited config and forget a latch. The gateway's presence checks are the boundary while it runs.
- A login prompt cannot name who asked. An agent that calls the control login route gets a Windows Hello prompt that says "Sign in
  to the MCP Switchboard dashboard"; if the owner approves a prompt they did not start, the agent receives the code. That is a
  confused-deputy risk of any presence prompt; the prompt text and the 429 on a second request are the mitigation.
- `/oauth/consent` stays in the public-route allowlist of `isPublicRoutePath` with no handler behind it (404); it is harmless and
  left to keep two oracles that pin that list unchanged.

### 3.16 Connector integration (local toolkits on the governed gateway, oracle `verify:integration`)

The local connector layer (`src/connectors/`, LOCAL_TOOLKITS.md, CONNECTORS.md) mounts each toolkit as a `source: connector`
server. This section is the contract between it and sections 3.1 to 3.15. Where the two designs overlapped, this document
decides anything about authentication, owner sessions, CSRF, approvals, presence, the kill switch and principals; the
connector layer adds features on top.

- **One access-control source.** The connector layer used to keep its own table of which client may use which toolkit
  (`connectors/links.json`, `switchboard link`). It is gone. A client's access to a toolkit is its access to the toolkit's
  server (`servers` globs), its ceilings are `max_scope` and `max_risk`, and the account it runs as is the new optional
  `accounts: { <provider>: <account> }`. `src/connectors/access.ts` only READS the live `clients:` map (the gateway hands
  it `() => cfg.clients`, which ClientAdmin keeps current). `switchboard link|unlink|links` plan a change to that section
  (`connectors/link.ts`) and apply it through the same ClientAdmin as `switchboard client add`: with a gateway running the
  owner sees the exact grant, accounts included, in the gateway's presence prompt; with none, the audit row says `local:cli`.
  `link <client> <toolkit-or-server-id>` adds only the server whose id is the target (else the toolkit's servers, else the
  default id a later `toolkits enable` gives it); a second mount pinned elsewhere is reached by naming its server id.
- **Which account a call runs as** (`chooseAccount`, one function for the router's preflight and the pipeline):
  1. a server pin (`servers[].account`) is final: the `account` argument cannot override it, and a client bound to a
     different account of that provider is refused on that server (the call would run as an identity it was not given);
  2. a client with `accounts: { <provider>: <account> }` runs as that account, and the argument may name only that account;
  3. `accounts: { <provider>: "*" }` runs as the provider default unless the argument names an account;
  4. a client with no entry runs as the provider default and may name no other account;
  5. the owner's own path (no principal: the playground, a trigger poll) may name any account, except against a pin.
  A refusal is `SB_POLICY_DENY` naming the client (the gateway's own refusal shape, also when the pipeline makes it); a named
  account that does not exist is `SB_ACCOUNT_NOT_FOUND`, never a fall back to the default. The binding resolver of the account
  store reads the same map (`AccountStore.setBindingResolver`).
- **The identity the connector server sees is the router's.** The router puts the authenticated principal's client in the
  request `_meta` (`io.mcpswitchboard/client`); nothing in a tool's arguments or in the client's own request can set it. A
  client id that is present but malformed is refused by the connector server, never read as "no client" (the connectors
  branch accepted 48 characters while a client id may have 64, which would have turned a long id into the owner's unscoped path).
- **Risk comes from the action.** Each connector action carries `scope`, `risk`, `outward` and `approval`. The router asks
  the mounted toolkit (`MountedServer.connector.hints`) and `evaluate()` raises risk by them: the action's risk is a floor
  that the server's `risk_defaults` cannot go under, `outward: true` makes write and full high exactly like the server flag,
  and `approval: "always"` (proxy_request) needs a human whatever `gateway.approval.require_for_risk` says. Only the
  operator's explicit per-tool `risk` can lower a connector action's risk. Client `max_scope` and `max_risk` then apply
  as for any tool, before any approval exists. Unlisted actions (the long tail reached through `find_tools` and `call_tool`)
  go through the same gates; `find_tools` and `call_tool` are listed to a client only while a server it may see has some.
- **An approval binds the account and the request.** For a gated connector call the router resolves the call without
  sending anything (`Executor.plan`: the final arguments after `inject_args`, the authenticated client, the account, the file
  hashes, the built request) BEFORE it asks the owner, and binds `{ account, request, arguments, connector }` where
  `connector` holds the account id, the toolkit version and, for a one-request action, the method, host, path, a hash of the
  query string and a hash of the body (multipart by its parts, so the random boundary does not matter); a recipe is bound by
  a hash of its steps. The owner is shown the account and the request first. After the approval is consumed the router passes
  the digest to the connector server (`io.mcpswitchboard/approved`); the pipeline rebuilds the call and refuses one that
  hashes to anything else (`SB_APPROVAL_DENIED`), so an approval for account A cannot run as account B, and an approval does
  not survive a change of the default account, of the toolkit definition or of a file's bytes. The old TTY seam (`approve` in
  the gateway) is not wired: the router decides every approval, and a pipeline reached without the router's attestation
  refuses an action that needs a decision.
- **Admin surfaces.** The Connectors page and its `/api/connectors/*` routes are registered after the owner-session gate, so
  they need the `X-Switchboard-Session` header (never a cookie, never a client key) and, for every mutation, the CSRF header.
  The page uses the one fetch wrapper of the SPA. `/media/<id>` (ephemeral single-file media URLs for platforms that fetch
  media themselves) is the one extra public route; an unknown id is an identical 404.

What this does not change: the same-user boundary of 3.15. A client's account binding is a ceiling for a well-behaved agent
and a record of intent, not a boundary between two processes of one OS user: a process that can run `switchboard bridge
--client other` can be `other`, and so can use `other`'s account.

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
