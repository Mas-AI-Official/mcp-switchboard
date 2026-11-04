# Operator runbook

Everyday operation of a Switchboard gateway. Every command below exists in `src/cli.ts` or `src/connectors/*.ts`
(Observed); run `switchboard <command> --help` for flags. The config is `switchboard.config.yaml` in the current
directory unless you pass `-c, --config <path>` before the command. State lives in `SWITCHBOARD_HOME` (default
`~/.switchboard`). From a checkout, run `npm ci && npm run build` first (`dist/` is not committed), then replace
`switchboard` with `node dist/cli.js`. Node: see the version note in [MCP_SWITCHBOARD_BASELINE.md](MCP_SWITCHBOARD_BASELINE.md)
section 1 (practical floor 22.12). See also [THREAT_MODEL.md](THREAT_MODEL.md), [VALIDATION.md](VALIDATION.md),
[CONNECTOR_CONTRACT.md](CONNECTOR_CONTRACT.md) and the design doc
[architecture/MCP_SWITCHBOARD_VNEXT.md](architecture/MCP_SWITCHBOARD_VNEXT.md).

## 1. Start, stop, health

| Task | Command |
|---|---|
| First setup | `switchboard init` (starter config with `transport: [stdio, http]`; leaves an existing config alone) |
| Check environment and config | `switchboard doctor` (exit 1 on an invalid config or report problems; exit 0 with only a hint when no config file exists; floating npx versions are warnings) |
| Preview the tool list | `switchboard list` |
| Run the gateway | `switchboard serve` (transports from `gateway.transport`) |
| HTTP endpoint and dashboard only | `switchboard dashboard` |
| Liveness | `GET http://127.0.0.1:8088/healthz` (port from `gateway.http.port`; reports `service` and `kill_switch`) |

There is no stop subcommand: stop the process that runs `serve`. A stop loses the kill latch, owner sessions and the
approval signing key, so undecided and unused approvals from the earlier run are ignored. A busy port makes `serve` exit 1
before mounting anything. Approvals, `kill off`, `dashboard login` and client grants need the HTTP listener, so set
`gateway.transport` to include `http`; with stdio only, `serve` warns that they cannot reach the gateway.

Owner presence needs an interactive context: Windows Hello, or a typed challenge at the gateway's own terminal. The terminal
fallback is weaker, works only with an attached TTY and with the stdio transport not active, and a background service has
neither, so run the gateway from a desktop session or terminal. Failures return `SB_PRESENCE_FAILED` (403) or
`SB_PRESENCE_BUSY` (429, one prompt at a time). Never put `SWITCHBOARD_AUTO_APPROVE` or `SWITCHBOARD_INSECURE_APPROVAL`
in a service or launcher environment: they approve every gated call or switch presence off.

## 2. Link a client

1. Start the gateway with `http` in `gateway.transport`.
2. `switchboard install <client>`: `claude-code`, `claude-desktop`, `codex`, `gemini`, `antigravity`, `dsh`, `cursor`, `vscode`.
   Flags: `--dry-run` (shows the plan and the grant, changes nothing), `--yes`, `--scope user|project` (default user),
   `--mode bridge|http`, `--name <n>`, `--dir <d>`, `--dsh-profile <p>`.
3. With a gateway running, the presence prompt shows the exact grant. A client created by `install` gets `servers ["*"]`,
   `max_scope write`, `max_risk high`. `client add` and `link` create clients at `max_scope read`, `max_risk low`
   (`--servers` default `*`). Check the grant before confirming.
4. Restart the client so it launches `switchboard bridge --client <id>`.

Without touching any client file: `switchboard client add <id> [--servers a,b] [--max-scope read|write|full]
[--max-risk low|medium|high] [--print]`; list with `switchboard client list`. A key is printed once, only with `--print`.
Install limits: a Store (MSIX) Claude Desktop config is not searched (copy the entry by hand), and JSON with comments is refused.

## 3. Dashboard login

`switchboard dashboard login [--no-open]`: the running gateway checks you are present, mints a one-time code (120 s, one
use) and the command opens `http://127.0.0.1:<port>/#login=<code>`. Sessions last 12 hours in gateway memory. No gateway
running means no login.

## 4. Approve a pending call

An agent whose call needs approval gets `SB_APPROVAL_PENDING` with an id like `ap_7KQ2M9XD`.

1. `switchboard approvals list` (`--all` adds finished ones), `switchboard approvals show <id>`. `show` prints a redacted,
   size-capped preview (secrets masked, 4 KB cap). The approval covers the exact full arguments by hash, and the presence
   prompt shows a shorter summary still (at most 120 characters).
2. `switchboard approvals approve <id>`: the gateway asks for presence; the client must then repeat the identical call.
   The TTL counts from when the request was created, so approving late leaves only the remainder.
3. `switchboard approvals deny <id>` needs no presence check.

Lifecycle: statuses pending, approved, denied, consumed, expired. `gateway.approval.ttl_seconds` is 60 to 86400 (default
900); `wait_seconds` is 0 to 50 (default 0, so the agent gets `SB_APPROVAL_PENDING` at once and must retry). An identical
repeat call reuses the pending id; after a deny or expiry (with the default `wait_seconds: 0`) a repeat creates a new
pending approval. Caps: 16 undecided per principal, 64 in all (`SB_RATE_LIMITED`). Each step writes an `approval.*` audit row.
Leftover pending approvals of a revoked client can be denied. With no gateway running, `approvals list` shows the raw file
marked unverified and nothing can be approved.

## 5. Kill switch

- `switchboard kill on` refuses every tool call, resource read and prompt get with `SB_KILL_SWITCH`; no presence needed.
  `/healthz` reports `kill_switch`. An approval already granted but unused is left unused while the switch is on and can lapse.
- `switchboard kill status` shows file, config and the gateway's view.
- `switchboard kill off` asks the running gateway to check presence (up to 150 s), then clears the file and its latch. With
  no gateway reachable the switch stays on; start one and repeat. If `gateway.kill_switch: true` is still in the config,
  `kill off` exits 1: set it false and restart.
- Deleting `KILL` does not turn a running gateway off. The latch is in gateway memory only, so a same-user process that
  can kill and restart the gateway after deleting `KILL` can clear the switch. It stops naive removal, not that process.
- Rows written: `kill.latched`, `kill.on`, `kill.off`, `kill.off_refused`, `kill.tamper`.

## 6. Rotate or revoke a client key

- Rotate: `switchboard client rotate <id> [--print]`; earlier keys stop at once; a running gateway asks for presence.
  Approvals made under the old key do not carry over.
- Revoke: `switchboard client rm <id>` revokes keys and deletes the key file (no presence). `--purge` also removes the config
  entry; without it an OAuth access token whose registered name equals the client id still maps to the client, so purge to
  fully revoke an OAuth-connected client. `rm` takes effect on the next HTTP request but not for an already running
  `serve --client` stdio session (restart it, Inferred from code). The only operator-side revocation of OAuth tokens is
  removing the OAuth state file, which revokes every registered client and token. Deny leftover pending approvals.
- Raw keys: `switchboard apikey new <name> --client <id>`, `apikey list`, `apikey rm <key-id>`. `apikey new --client`
  refuses while a gateway answers (use `client rotate <id> --print`); with no gateway it issues a key with no presence check.
  Prefer `client add`.

## 7. Connect a provider

1. `switchboard providers list` and `switchboard providers show <provider>` (owner setup steps).
2. `switchboard vault set <name>` (value on stdin).
3. `switchboard authconfig add <provider> --client-id-ref <ref> --client-secret-ref <ref>`.
4. `switchboard connect <provider> [-a <label>]`; check with `accounts list` and `accounts probe <ref>`.
5. `switchboard toolkits sync <toolkit>`, then `switchboard toolkits enable <toolkit>`.
6. `switchboard link <client> <toolkit> [--account <ref>] [--max-scope s] [--max-risk r]`.

Google projects left in Testing status expire refresh tokens every 7 days, so reconnect weekly or publish the app. Disable or
revoke: `accounts disable|enable|revoke <ref>` (`revoke` deletes the credential and exits 1 if the provider-side revoke
failed), `toolkits disable <toolkit>`.

## 8. Audit log

`audit.log` in `SWITCHBOARD_HOME`, rotated at 20 MB. `switchboard audit verify [--all]`: exit 0 prints `audit chain OK` with
the row count and last hash, or `no rows to verify` (also exit 0, so a deleted log looks like this); exit 1 prints `audit
chain BROKEN at seq N`. Copy the printed `last hash` and row count to a place the gateway's user cannot write: the chain has
no secret, so without that anchor a full rewrite is undetectable. On a break, copy the files before touching anything.

## 9. Uninstall and roll back a client config

`switchboard uninstall <client> [--scope user|project] [--dry-run] [--yes] [--name <n>]` removes only the Switchboard entry;
the registered client and its key stay (`client rm` revokes). With the `claude` CLI on PATH the previous entry is recorded
under `SWITCHBOARD_HOME/install-backups` and no file copy is made; otherwise the file is edited and a
`<file>.bak-switchboard-<YYYYMMDDTHHMMSSZ>` copy is kept beside it. Backups are never deleted by the tool and may contain
other servers' tokens: delete old ones once a probe passed. To roll back, copy the backup over the file. A failed probe
during `install` restores the file by itself.

## 10. Back up and move

Back up the config, `vault.json`, the vault key, `clients/`, `approvals.json`, `audit.log` and `connectors/`. On Windows the
vault key and client keys are DPAPI-wrapped to the user and machine, so a copy on another profile cannot decrypt them:
re-enter secrets (`vault set`, `connect`). A damaged vault key or OAuth state needs the `.bak` or a fresh state. Afterwards
run `switchboard doctor` and `switchboard audit verify --all`.

## 11. Expose through a tunnel

`switchboard expose [--tunnel cloudflared|ngrok|tailscale] [--port <n>] [--new-token]` boots its own gateway and a `/mcp`-only
listener (default dashboard port + 1) behind a bearer key. It has no control API (Observed, `src/cli.ts`), so `approvals`,
`kill off`, `dashboard login` and client grants do not reach that process, and approvals are signed per gateway instance, so
a high-risk call arriving through it cannot be approved from another gateway (Inferred, untested). Treat it as an
operator-accepted risk (design doc 5). Stop it by ending the process.

## 12. Common failures

| Symptom | Cause and fix |
|---|---|
| `/mcp` answers 401 | No valid key. Use the bridge, or a client key as bearer. |
| 403 `SB_UNKNOWN_CLIENT` | Key is bound to a client not in the config: `switchboard client add <id>`. |
| 403 `SB_NO_CLIENT` | Key is bound to no client while clients exist: issue one with `client add <id> --print` (or `apikey new <name> --client <id>` with no gateway running). |
| 403 on every browser call | Host or Origin not allowed (design 3.2). Use `127.0.0.1`, `localhost` or `[::1]` with the gateway's port. |
| `no control key` | No gateway has started in this `SWITCHBOARD_HOME`, or the CLI points at a different home. |
| `no gateway answered` | Gateway down or on another port. Start `serve` or `dashboard`. |
| `rejected the control token` | The gateway restarted since the key was read, or two gateways share a home. Run the command again. |
| `serve --client <id>` exits: no working key | Revoked or never issued: `switchboard client add <id>`. |
| `SB_POLICY_DENY` | Scope, risk or server ceiling of the client or profile; the message names which. |
| `SB_UNKNOWN_TOOL` | No exposed tool has that name (typo, server disabled or not mounted, or never listed at mount). Run `switchboard list`. |
| `SB_PACKAGE_UNPINNED` | The dashboard refused an npx toolkit add without an exact version (HTTP 400; send `version` as `x.y.z`). In config files pin `name@x.y.z` or `doctor` warns. |
| `SB_APPROVAL_PENDING` | Waiting for the owner. Decide it (section 4). |
| `SB_APPROVAL_DENIED` | Approval store unusable (file damaged, not replaced), a connector request changed after approval, or, only with `wait_seconds` above 0, denied or expired during the wait. |
| `SB_APPROVAL_UNKNOWN` (404), `SB_APPROVAL_STATE` (409) | Unknown or earlier-run id; already decided. |
| `SB_ACCOUNT_EXPIRED` | Reconnect with the command in the error (weekly on Google Testing projects). |
| `SB_ACCOUNT_REVOKED`, `SB_ACCOUNT_DISABLED`, `SB_ACCOUNT_NOT_FOUND` | Reconnect, `accounts enable <ref>`, or name an existing account. |
| `SB_AUDIT_FAILED` | The write-ahead audit row could not be written; fix disk or permissions. A consumed approval is spent. |
| `SB_RATE_LIMITED` | A governor limit, or too many undecided approvals. |
| Client edit ignored by a running gateway | It applies client changes only through its own control path; run the command while it is up, or restart (design 3.15). |
