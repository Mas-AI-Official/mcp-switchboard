# MCP Switchboard threat model

Status: describes branch `vnext/governed-hub` (HEAD cdaa7a9 when revised). Section numbers refer to
[architecture/MCP_SWITCHBOARD_VNEXT.md](architecture/MCP_SWITCHBOARD_VNEXT.md) ("the design doc"). Mitigations name the
code and, where one exists, the oracle ([VALIDATION.md](VALIDATION.md)). Labels: Observed (read in code), Per doc,
Inferred, Unknown. Related: [RUNBOOK.md](RUNBOOK.md), [MCP_SWITCHBOARD_BASELINE.md](MCP_SWITCHBOARD_BASELINE.md).

## 1. Scope and the same-user boundary

Switchboard contains agents that reach tools only through MCP. It does not contain a process that runs as the same OS
user as the gateway (design doc 3.15). That process can read and write every file under `SWITCHBOARD_HOME` and the config
file, run the CLI, reach the loopback ports and, Inferred and untested here, attach to or inject into the gateway process
itself, so memory-only secrets (approval signing key, kill latch) do not hold against it.

- Client key files are user-scope protected (DPAPI on Windows, mode 0600 elsewhere): that separates users, not two
  processes of one user. A process that is client `a` can run `switchboard bridge --client b` and be `b`.
- The key store is re-read on every request, so a same-user process can write a key record directly and have it work.
- `switchboard apikey new <name> --client <id>` refuses while a gateway answers and names `client rotate <id> --print`;
  offline (no gateway) it issues a bound key with no presence check, like offline `client add|rotate`.
- Everything on disk is trusted at gateway start. A process that can stop and restart the gateway can load an edited
  config, forget the kill latch, and set `SWITCHBOARD_AUTO_APPROVE=1` or `SWITCHBOARD_INSECURE_APPROVAL=1` in its
  environment, which approve every gated call or switch presence off for approvals, dashboard login, `kill off` and client
  grants (startup warning, `decided_via: env-auto`; `src/approvals.ts`, `src/presence.ts`). They are for test harnesses.
- The control token in `SWITCHBOARD_HOME/control.key` is readable by the same user: a convenience, not a boundary.

Presence-gated while a gateway runs: `client add|rotate|link`, `kill off`, `approvals approve`, `dashboard login`.
Not gated: `client rm`, `kill on`, `approvals deny`, `apikey rm` (these only restrict; an availability risk), and any
change made with no gateway running. Switchboard governs what a well-behaved agent may do and stops it from raising its
own ceiling, minting a client, approving its own call or clearing the kill switch while a gateway runs. Closing the
same-user gap needs an OS boundary this design does not have (a separate account or a sandbox per agent).

## 2. Assets

Provider credentials and connector tokens (vault, sealed account store); client keys (hashed store, per-client key
files); approval decisions (`approvals.json`, signed by the gateway); the audit log; outward actions (posts, sends, spend);
operator config; and the backups `install` leaves: `<client file>.bak-switchboard-<stamp>` and
`SWITCHBOARD_HOME/install-backups`. Client config files can hold other servers' tokens in plaintext (Inferred), so
backups are extra copies of them; review and delete old ones after a successful probe.

## 3. Actors and trust boundaries

Actors: an agent with MCP access only; a same-user process (agent with a shell); a web page that can rebind DNS; a
malicious upstream server or npm package; attacker-influenced remote responses and redirects; a network attacker if the
operator uses `switchboard expose` or a LAN bind. Boundaries: client to gateway (bearer key or the launching process's
key file); browser to admin API (session header plus CSRF header, never a client key); CLI to gateway (control token,
then the gateway's presence check); gateway to child (filtered environment); gateway to network (SSRF guard).

## 4. Threats and mitigations

| Threat | Mitigation | Evidence |
|---|---|---|
| DNS rebinding | Host allowlist on every route (`127.0.0.1:<port>`, `localhost:<port>`, `[::1]:<port>`, plus the public hosts: `oauth_server.public_url`, `connectors.media.public_base_url`, the `expose` tunnel host, accepted on `/mcp`, OAuth routes and `/media/<id>` only). Origin, when present, must match on non-GET/HEAD routes and `/mcp`; a request with no Origin is not refused by this layer. Refusals are 403. | `src/httpsec.ts`, design 3.2, `verify:http-security` |
| Unauthenticated local callers | `require_auth` (`auto`, `always`, `never`). With no client configured and `auto` on loopback, `/mcp` is open as `loopback-anonymous` (residual). Once a client exists, every request needs a principal: no credential 401, unknown or unbound client 403. Per-client keys carry scope, risk and server ceilings. | `src/principal.ts`, design 3.1, `verify:principals` |
| Agent approves its own call | Approval bound to principal, server, tool and SHA-256 of canonical arguments; single use; TTL from request creation; decision signed with an HMAC key held only in gateway memory; unsigned or earlier-run records ignored; `approve` needs the gateway's presence check (Windows Hello, else a typed console challenge); no MCP tool or client key can approve. | `src/approvals.ts`, `src/presence.ts`, design 3.3 and 3.4, `verify:approvals` |
| One approval, two upstream calls | Arguments that map to one upstream name are refused before any approval exists. | design 3.15, `verify:hardening-3` |
| Key theft at rest | Vault key and client keys wrapped with DPAPI (CurrentUser, fixed entropy); elsewhere mode 0600 in a 0700 directory, which is not encryption (`isOsProtected()` says which). Connector tokens sealed with the vault key (Per doc: AES-256-GCM). API keys stored as one-way hashes. | `src/oscrypt.ts`, `src/clientkeys.ts`, `verify:oscrypt`, `verify:vault` |
| Binary planting of `powershell.exe` | Launched by absolute path from `SystemRoot\System32\WindowsPowerShell\v1.0`, cwd System32, `NoDefaultCurrentDirectoryInExePath=1`; payload on stdin; throws rather than fall back to a bare name. | `src/oscrypt.ts` (`systemPowershell`, `hardenedEnv`) |
| SSRF from remote upstreams and config URLs | DNS resolved first and every answer classified (loopback, RFC1918, CGNAT, link-local, ULA, metadata and their encodings refused); connection pinned to the validated address; at most 3 manual redirects, each re-checked; credentials dropped on origin change; body and time caps. `source: remote` uses the same address checks but streams: no body cap, and the deadline ends at the response headers. Exceptions: exact hosts in `settings.network.allow_private`, plus explicit `allowLoopback` local probes (CLI healthz, control client, local-llm probe), loopback only. | `src/netguard.ts`, `verify:netguard` |
| Env leakage into child servers | Child gets the design 3.6 allowlist, the SDK 1.x default names pinned (any other SDK default masked at spawn), the server's `env` and `credentials`, and `env_passthrough` names; a secret-looking passthrough name is refused unless also in `env_passthrough_secrets`. | `src/childenv.ts`, `verify:policy-hardening` |
| Log leakage | `settings.logs.capture_io` off by default; when on, secret shapes are replaced; scrubs are linear and cut at 8192 characters; upstream `error` text is scrubbed whether or not capture is on. Control characters are stripped from every message that goes through `src/logger.ts`. Not covered: inherited child stderr and app2mcp skipped-operation warnings (`console.error`, `src/openapi.ts`). | `src/audit.ts`, `src/logger.ts`, `src/safetext.ts`, `verify:audit`, `verify:hardening-2` |
| Audit tampering | `seq`, `prev_hash`, `hash` per row; `audit verify [--all]` reports the first break; write and full calls log an `attempt` row first and fail closed. Against a same-user process this is evidence only if the latest hash is anchored out of its reach (section 5). | `src/audit.ts`, `verify:audit-chain` |
| Runaway spend or outward action | Risk tiers; `outward: true` raises writes to high; high needs approval; client `max_scope` and `max_risk` refuse before an approval exists; governor limits (`per_minute`, `per_hour`, `per_day`, `cost_per_*`) at global, server, tool and client level; undecided approvals capped at 16 per principal and 64 in all; `proxy_request` always needs approval. Calls that reach the governor count even if the approval is then pending or denied or the upstream fails; calls refused earlier (policy, ceilings, profile, argument collision, unknown tool) are not counted. | `src/governor.ts`, `src/router.ts`, `verify:limits`, `verify:approvals` |
| Agent turns the kill switch off | `kill off` needs the gateway's presence check; the gateway latches the switch in memory so deleting `KILL` does nothing and writes `kill.tamper`. `kill on` needs no presence (anyone can stop the gateway). | `src/killswitch.ts`, `verify:hardening-3` |
| Hostile upstream names a hidden tool | A name resolves only to a tool the upstream declared at mount (listed, or for connector toolkits callable but unlisted); gates still apply. | `src/router.ts`, `verify:hardening-2` |
| Malicious npm package as upstream | Catalog or dashboard adds of npx toolkits need an exact version; hand-written floating names still mount and warn in `switchboard doctor`. | `src/packagespec.ts`, `src/doctor.ts`, `src/dashboard.ts`, `verify:hardening-2` |
| Admin API abuse from a browser | Owner session in `X-Switchboard-Session`, never a cookie; CSRF header on every mutation; client keys never accepted; login code minted only after presence; CSP and security headers. | `src/httpsec.ts`, design 3.2 and 3.15, `verify:http-security`, `verify:hardening-3` |
| Public `/media/<id>` route | The one unauthenticated public route: 192 bit id, at most 15 minutes, 3 fetches by default, identical 404 for unknown ids (Per doc). | `src/connectors/mediastage.ts`, `verify:connectors-exec` |
| OAuth authorization server (optional) | Consent decided in the dashboard with session and CSRF; DCR rate limited and capped (Per doc). Token lifetime defaults: access 3600 s, refresh 14 days, `refresh_token_ttl: 0` means never (Observed, `src/authserver.ts`). Built on the deprecated `server-legacy` helpers. A token whose registered name equals a client id maps to that client. | `src/authserver.ts`, `verify:oauth` |
| Token sent to a mounted MCP server | The built-in connectors send a credential only to the provider's `api_hosts`. A token injected into a mounted server through `${oauth:provider}` goes to that server (stdio servers get it at spawn). | `src/connectors/exec.ts`, LOCAL_TOOLKITS section 11 |

## 5. Residual risks

- Same-user processes can impersonate each other, mint or borrow keys, and, with the environment switches above, defeat approvals (section 1).
- Open loopback mode: with no client configured, `/mcp` takes anonymous callers and no ceiling applies. Register a client.
- `install` registers a new client with `servers ["*"]`, `max_scope write`, `max_risk high`; `client add` and `link` start at `read` and `low` (Observed, `src/installer.ts`, `src/clientadmin.ts`). `install --dry-run` shows the grant.
- Presence without Windows Hello (every non-Windows host, or Windows without Hello) is a 4 character challenge typed at the gateway console, which a same-user process that controls that terminal can answer (`src/presence.ts`). With the stdio transport active only Hello is accepted, and with no interactive terminal the action is refused.
- Login and `kill off` prompts cannot name who asked. An approval prompt names the client label, but a same-user process can act under another client's key, so the label is not proof of who asked.
- Audit: the hash is unkeyed, so a same-user process can rewrite and re-hash the whole file undetected; deleting the newest rows or the oldest rotated segments is not a break (a note at most); deleting `audit.log` verifies as "no rows" with exit 0. Anchor `last hash` and the row count elsewhere.
- Memory-only state resets on restart: kill latch, approval signing key, rate limits and cost budgets (token buckets, not calendar periods).
- Secrets at rest on non-Windows hosts rely on file mode.
- `revoke` limits: `client rm` stops HTTP keys on the next request, but a running `serve --client` stdio session keeps its client until restarted (Inferred); an OAuth token mapped by name survives unless the client entry is purged.
- Two gateways sharing one `SWITCHBOARD_HOME` overwrite each other's control key; a stdio-only gateway cannot have approvals decided.
- `switchboard expose` publishes `/mcp` to the internet behind a bearer key; the design treats public hosting as out of scope (design doc 5).
