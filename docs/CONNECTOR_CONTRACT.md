# Connector contract

What a provider, toolkit or connector must satisfy to run on the governed gateway. This page states the rules; it does
not repeat the architecture. Read with [architecture/LOCAL_TOOLKITS.md](architecture/LOCAL_TOOLKITS.md) (design),
[architecture/CONNECTORS.md](architecture/CONNECTORS.md) (file map) and
[architecture/MCP_SWITCHBOARD_VNEXT.md](architecture/MCP_SWITCHBOARD_VNEXT.md) section 3.16 (principals and approvals).
Per-platform setup: [connectors/OWNER_SETUP.md](connectors/OWNER_SETUP.md). Also: [RUNBOOK.md](RUNBOOK.md),
[THREAT_MODEL.md](THREAT_MODEL.md). Labels: Observed (read in code), Per doc (from the architecture pages, not re-read
in code), Inferred, Unknown.

## 1. ProviderDef

A provider is data, `src/connectors/providers/*.json`, validated against `src/connectors/schemas/provider.schema.json`.
Provider auth quirks are fields of the definition. Some response-shape handling is shared code selected by a data flag:
Slack (`token_shape: slack`, `ok:false` bodies) and Google rate-limit reasons live in `src/connectors/exec.ts` and
`tokenclient.ts` (Observed). Fields (`src/connectors/types.ts`):

| Field | Required | Meaning |
|---|---|---|
| `slug`, `name`, `categories`, `docs_url` | yes | identity and listing |
| `api_hosts` | yes | the only hosts this provider's credentials may reach (`*.example.com` matches subdomains) |
| `owner_setup` | yes | `console_url`, `steps`, `redirect_uris`, `notes` printed when no OAuth app is registered |
| `auth` | yes | list of `AuthDef` |
| `toolkits` | no | toolkits this provider backs (default `[slug]`) |
| `identity_probe` | no | one read-only call proving a credential is live and whose it is |
| `api_version_header`, `api_headers` | no | headers sent on every API call |
| `provenance` | no | `derived_from`, `license`, `attribution` |
| `source`, `verification` | seeds only | `src/connectors/providers.ts` refuses them in a curated file |

`AuthDef.mode` is `oauth2`, `oauth2_cc`, `oauth1`, `api_key`, `bearer`, `basic` or `custom`. The engine runs `oauth2`,
`oauth2_cc`, `api_key`, `bearer`, `basic`; `oauth1` and `custom` are named in the schema and refused
(`IMPLEMENTED_AUTH_MODES`). Each `AuthDef` has `inject` (header or query, name, template) and field lists for auth config
creation and account initiation.

## 2. Auth configs: vault references, never inline secrets

An `AuthConfig` (`ac_...`) names the OAuth app a provider uses: `client_id` or `client_id_ref` (exactly one; a client id
is public so a literal is allowed), `client_secret_ref`, `scopes`, optional `redirect_uri`.

- A client secret is only a vault or environment reference (`${vault:NAME}`, `${env:NAME}`). A string that is not a stored
  secret is refused and never echoed (Per doc, `authconfigs.ts`). This rule is for auth config creation fields.
- Connected-account credentials (API key, token, basic fields) are accepted as a reference, on stdin, through a hidden
  interactive prompt, or through the owner-session dashboard form (Observed, `src/connectors/cli.ts`, `admin.ts`). The
  `secret` flag on a `FieldDef` is a masking hint for the dashboard, not an enforcement.
- Store secrets with `switchboard vault set <name>` (stdin), then `switchboard authconfig add <provider> --client-id-ref ...
  --client-secret-ref ...`.
- Tokens are scrubbed from errors, audit rows and output by exact-value and pattern redaction (`src/connectors/scrub.ts`).
  That is best effort: a secret the call did not handle, in an unrecognised shape, is not covered.

## 3. Connected accounts

Statuses, exactly seven (Observed, `ACCOUNT_STATUSES`): `INITIALIZING`, `INITIATED`, `ACTIVE`, `FAILED`, `EXPIRED`,
`INACTIVE`, `REVOKED`. `INITIALIZING`, `INITIATED` and `FAILED` describe flow outcomes and are never stored; stored accounts
are `ACTIVE`, `EXPIRED`, `INACTIVE` (disabled) or `REVOKED` (`src/connectors/accounts.ts` header). Several accounts per
provider are allowed, with one default. Errors: `SB_ACCOUNT_EXPIRED`, `SB_ACCOUNT_DISABLED`, `SB_ACCOUNT_REVOKED`,
`SB_ACCOUNT_NOT_FOUND` (`src/connectors/errors.ts`).

`switchboard accounts revoke <ref>` asks the provider to revoke when the definition supports it, then deletes the stored
credential and sets `REVOKED`. If the provider-side revoke fails it prints that the credential may still be valid there
and exits 1; with no provider-side revoke it tells you to remove the grant in the provider's console. Reconnect to use it again.

Refresh (Per doc; the single-flight map is Observed in `accounts.ts`): single flight per account; proactive and reactive
(one retry on a 401); a rotated refresh token is written atomically before the new access token is used; `invalid_grant`
sets `EXPIRED`, writes one `account_expired` row and returns `SB_ACCOUNT_EXPIRED` with the reconnect command; a 429 with
`Retry-After` pauses that account in memory. Google projects in Testing publishing status expire refresh tokens after 7 days
(Per doc, LOCAL_TOOLKITS section 12), so a weekly `SB_ACCOUNT_EXPIRED` there is expected until the app is published.

A toolkit mounts only when its provider has an `ACTIVE` account that passed the identity probe, when the provider defines
one (Observed, `mcpserver.ts`, `admin.ts`). A provider with no `identity_probe` mounts on any `ACTIVE` account, and its
credential is stored unverified.

## 4. Toolkits, actions and importers

Toolkits are versioned `YYYYMMDD_NN`. An action (Per doc) has `slug`, `title`, `input_schema`, `http` or `steps`, `scope`,
`risk`, `outward`, `idempotent`, `important`, `tags`, optional `files`, and a `verification` state. Tool names are
`<toolkit>__<action>`, at most 64 characters.

- Importers: `src/connectors/importers/discovery.ts` (Google Discovery) and `importers/openapi.ts` (OpenAPI 3.x, Swagger 2.0).
- `switchboard toolkits sync <provider|toolkit|all> [--check]` fetches the public spec through the SSRF guard and writes
  `SWITCHBOARD_HOME/toolkits/<slug>/<YYYYMMDD_NN>/actions.json` on the operator's machine.
- Sync writes nothing unless every schema compiles, names are unique within 64 characters and every API host is one of the
  provider's `api_hosts`. `--check` writes nothing and exits 1 on drift.
- Generated files are never committed: `.gitignore` excludes `/toolkits/`, `*.generated.json`, version directories and
  `current.json` (Observed), and an oracle checks it.
- Overlays (`src/connectors/toolkits/<slug>/overlay.json`) are data and can only tighten safety.

## 5. Declarative recipes

No code evaluation (Observed, `recipes.ts`): step types `http`, `poll`, `upload_resumable`, `foreach`, `map`, `assert`.
Limits: 200 steps, 100 requests, 50 foreach items, depth 3. An approval covering a recipe binds a hash of its steps.

## 6. Files and media staging

Per doc (LOCAL_TOOLKITS section 6, CONNECTORS.md):

- Upload inputs: a local absolute path inside `settings.connectors.upload_allowlist` (real path, so symlinks cannot escape),
  an https URL through the SSRF guard, or `staged:<run_id>/<name>`. On Windows only drive-letter paths; UNC, device and
  `file://host` are refused before any filesystem call. Sensitive segments (`.ssh`, `.aws`, `.env`, key and vault files,
  browser profiles) are never uploadable. Every action has a size cap.
- Downloads land in `SWITCHBOARD_HOME/files/<run_id>/` and return `{uri, bytes, sha256, mimeType}`, never inline.
- Platforms that fetch media get one file at `/media/<id>`: 192 bit id, at most 15 minutes, 3 fetches by default (at most
  10), deleted afterwards. By default, with no https `settings.connectors.media.public_base_url` those actions fail with
  `SB_MEDIA_NOT_CONFIGURED`; `media.allow_local: true` opts into a local address (Observed, `mediastage.ts`).
  `public_base_url` comes from a tunnel such as `switchboard expose` (CONNECTORS.md); see
  [THREAT_MODEL.md](THREAT_MODEL.md) for what a tunnel exposes.

## 7. One MCP server per toolkit

`source: connector` with a `toolkit` slug; a connector server without `toolkit` fails config load, and `toolkit` or
`account` on any other source fails too (Observed, `src/config.ts`).

- `tools/list` shows the `important` set plus two meta tools, at most 30 (`MAX_LISTED_TOOLS`, `mcpserver.ts`):
  `manage_connections` (read, low) and `proxy_request` (full, high, approval always, host-locked to the provider).
- The rest of the API is reached through `find_tools` and `call_tool`, which pass the same gates.
- Access is the gateway's `clients:` section: `servers` globs, `max_scope`, `max_risk`, `accounts: { <provider>: <account> }`.
  There is no second table. `switchboard link` and `unlink` edit that section; `links` lists it. With no client configured,
  every caller is unscoped and may use every enabled toolkit and any connected account; ceilings and account bindings
  apply only once a client exists (Observed, `src/connectors/access.ts`, `src/cli.ts`).
- An action's `scope`, `risk`, `outward` and `approval` feed the router: its risk is a floor, `outward` makes write and full
  high, and an approval binds the account and the built request (method, host, path, query and body hashes).
- No non-idempotent action is retried after the request left (`SB_OUTCOME_UNKNOWN`). Idempotent actions (GET, HEAD,
  OPTIONS, PUT, DELETE by default) retry up to 2 times on 502, 503 and 504 (Observed, `exec.ts`).

## 8. Coverage states: only `live_verified` is working

`VERIFICATION_STATES` (Observed, `toolkits.ts`): `unmapped`, `mapped`, `mock_tested`, `live_verified`,
`blocked_by_platform`, `declined`, `deprecated`.

- Only `live_verified` counts as working. A `live_verified` line needs an account id and a date or it is ignored when
  counting (Observed, `coverage.ts`). `blocked_by_platform` is never counted; a registered count is not a working count.
- Marking: `switchboard coverage --mark <row> --state live_verified --account <ca_...>`. The row must already exist, and rows
  come from `switchboard coverage --import <dir>`, which requires a directory of checklist CSVs that this repository does not
  ship. The account must be a `ca_` id of a curated provider (a seeded provider's account is refused).
- The ledger is append-only: `SWITCHBOARD_HOME/connectors/verification.ndjson` (default `~/.switchboard/connectors/`).

## 9. Seeded providers

`src/connectors/providers/seed/*.json` are candidate definitions derived from another project's published auth settings
(see `NOTICE`): `verification: "unverified_seed"`, no toolkits, no identity probe. They enable Connect and nothing more and
can never count as working. A curated definition with the same slug shadows a seed.

## 10. Checklist for a new connector

1. `ProviderDef` validates; `api_hosts` lists only hosts the credentials may reach.
2. No secret literal anywhere; references, stdin or the owner dashboard only.
3. Identity probe is read-only and credit-free (without one the account is stored unverified).
4. Toolkit comes from `toolkits sync`, not a committed file.
5. Every outward action is marked `outward`.
6. Coverage is claimed only as `live_verified` with an account and a date.
7. Oracles: `verify:connectors-core`, `verify:connectors-exec`, `verify:connectors-seed`, `verify:file-refs`, `verify:integration`.
