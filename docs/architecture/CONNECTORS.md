# Connectors: provider auth, accounts, toolkits, execution, seeds, dashboard (phases P1, P2, P3-seed)

Status: implemented on `vnext/connectors`. Architecture and phases: the local-Composio ADR (sections 6 to 9).
This page records what P1 (auth, accounts, connect flows), P2 (execution, importers, exposure, files) and the
seed and dashboard step (seeded provider breadth, the Connectors page and its admin API) built and where it lives.
Principals, approvals and risk tiers were built on the governed gateway and are integrated here: access, accounts,
risk and approvals follow [MCP_SWITCHBOARD_VNEXT.md](MCP_SWITCHBOARD_VNEXT.md) section 3.16 (the daily canary is not built).
The architecture in one page, for readers outside the project: [LOCAL_TOOLKITS.md](LOCAL_TOOLKITS.md); per-platform setup:
[../connectors/OWNER_SETUP.md](../connectors/OWNER_SETUP.md).

## What exists, P1

| Piece | File | Notes |
|---|---|---|
| Provider definitions (data) | `src/connectors/providers/*.json` | 13 bundled: google, github, slack, notion, linear, meta-facebook, meta-instagram, linkedin, tiktok, x, elevenlabs, higgsfield, buffer. Validated by `src/connectors/schemas/provider.schema.json` (Ajv, pinned). `npm run build` copies both folders to `dist/connectors/`. |
| Registry | `src/connectors/providers.ts` | Bundled definitions cannot be overridden. The owner's own definitions go in `<SWITCHBOARD_HOME>/providers/<slug>.json` (new slugs only). A bad file is reported in `issues` and skipped. |
| Auth configs | `src/connectors/authconfigs.ts` | `connectors/authconfigs.json`. Secrets are vault references only; a string that is not a stored vault secret is refused and never echoed. The old vault names `oauth_<provider>_client_id/_secret` still work as a virtual `legacy:<provider>` config. |
| Accounts | `src/connectors/accounts.ts` | `connectors/accounts.json`. Tokens sealed with the vault key. Statuses INITIALIZING, INITIATED, ACTIVE, FAILED, EXPIRED, INACTIVE, REVOKED (a failed or cancelled connect never reaches the file, so INITIALIZING, INITIATED and FAILED describe flow outcomes and are never stored; a stored account is ACTIVE, EXPIRED, INACTIVE or REVOKED). Several accounts per provider, a per-provider default, atomic writes, re-read when the file changes. |
| Connect flows | `src/connectors/oauthflow.ts` | OAuth2 code (+PKCE per quirk), client credentials, API key, bearer or PAT, basic, token import. Pending authorizations live 10 minutes in `connectors/pending.json` (verifier sealed), so any process on the dashboard port can finish a flow another process began. |
| Token client | `src/connectors/tokenclient.ts` | The one place app credentials go on the wire. Every quirk is a field of the definition. |
| Identity probe | `src/connectors/probe.ts` | Runs on connect (a failing probe fails the connect) and from `accounts probe`. |
| CLI | `src/connectors/cli.ts` | `connect`, `accounts`, `authconfig`, `providers`. |
| Gateway handle | `src/oauth.ts` | Keeps `beginAuth`, `completeAuth`, `accessToken`, `catalog`, `disconnect`; delegates to the engine. `${oauth:provider}` resolves to the provider's default account, `${oauth:provider/label}` to another. |

## What exists, P2

| Piece | File | Notes |
|---|---|---|
| Toolkits | `src/connectors/toolkits.ts` | An action is a spec operation or a recipe, with `scope` (read, write, full), `risk` (low, medium, high), `outward`, `idempotent`, an Ajv checked input schema and an optional upload or download spec. `ToolkitStore` reads the generated versions under `<SWITCHBOARD_HOME>/toolkits/<slug>/<YYYYMMDD_NN>/actions.json` plus the overlay and recipes shipped in `src/connectors/toolkits/<slug>/`. |
| Overlays | `src/connectors/toolkits/*/overlay.json` | Data only: spec source URL, `important` list, renames, `hide`, tags, `outward`, reconcile hints. Safety can only tighten (an overlay that would loosen a derived scope or risk is ignored and reported in `overlay_issues`). The owner can add `<SWITCHBOARD_HOME>/toolkits/<slug>/overlay.json`, including `unhide`. Shipped: youtube, gmail, drive, x, slack, notion. |
| Discovery importer | `src/connectors/importers/discovery.ts` | Google Discovery documents (YouTube v3, Gmail v1, Drive v3). One action per method, `$ref` kept as `$defs`, repeated parameters accept a string or an array, media upload and download recorded. |
| OpenAPI importer | `src/connectors/importers/openapi.ts` | OpenAPI 3.x and Swagger 2.0 (X, Slack, Notion). Reuses the operation builder in `src/openapi.ts`, repairs vendor schema defects (duplicate enum entries, invalid unicode patterns) so the schema compiles. |
| Sync | `src/connectors/sync.ts` | `toolkits sync <provider\|toolkit\|all> [--check]`. Fetch through the SSRF guard with bulk caps, import, require 100% Ajv compile, unique names within 64 characters and an API host that is one of the provider's `api_hosts`; otherwise nothing is written. `--check` writes nothing and reports `unchanged`, `drift` or `unsynced` (exit 1 on drift). Generated files never go in git (`.gitignore` rules and an oracle check). |
| Recipes | `src/connectors/recipes.ts` | Declarative multi-step actions: `http`, `poll`, `upload_resumable`, `foreach`, `map`, `assert`. Templates are `{{path \| fn:arg}}` over an own-property lookup with a closed filter set; there is no code evaluation. Limits: 200 steps, 100 requests, 50 foreach items, depth 3. Shipped: `youtube/upload_video`. |
| Execution | `src/connectors/exec.ts` | One pipeline, stage order fixed by the ADR: kill switch, client filter, toolkit and account, validate, policy, approval, limits, token, build, files, fetch, normalize, output files, redact, audit. Provider errors map to `SB_PROVIDER_*`. A 429 with Retry-After pauses that account. Idempotent reads retry on 502, 503, 504 and pre-send failures; anything that can change data is never retried, and a failure after the request left is `SB_OUTCOME_UNKNOWN` with the action's reconcile hint. |
| Files | `src/connectors/files.ts` | Uploads: a LOCAL absolute path inside `settings.connectors.upload_allowlist` (by realpath), https URL through the guard, `file:///`, or `staged:<run_id>/<name>`. On Windows only `X:/folder/file` forms are accepted: UNC and device paths (`\host\share`, `//host/share`, `\?\`, `\.\`), `file://host/...`, device names and `name:stream` syntax are refused lexically, before any filesystem call, so a network path never makes the gateway wait on SMB; a path outside every allowlisted folder is refused by name, so it answers the same whether or not the file exists. Sensitive path segments are never uploadable, whatever the allowlist. A public URL for a platform that fetches the media itself (`x-file: public_url`) is made only after the approval. Downloads land in `<SWITCHBOARD_HOME>/files/<run_id>/` and come back as `{uri, bytes, sha256, mimeType}`, never inline. |
| Media stage | `src/connectors/mediastage.ts` | `GET\|HEAD /media/<id>` for platforms that fetch media themselves. 192 bit ids, at most 15 minutes, 3 fetches by default (at most 10), the file is deleted after the last. An unknown id is an identical 404. `s3` is an interface that refuses until built. Mounted on the dashboard and tunnel listeners; `/media/` is a public route path for the host guard, nothing else is. |
| Per-toolkit MCP server | `src/connectors/mcpserver.ts` | `source: connector` in the config. Fail closed: a toolkit mounts only when its provider has an ACTIVE account that passed the identity probe. Lists at most 28 important actions plus `manage_connections` and `proxy_request` (30). The rest are reachable through `find_tools` and `call_tool`, which the router lists while any toolkit has unlisted actions. |
| Client access | `src/connectors/access.ts`, `src/connectors/link.ts` | No table of its own: the gateway's `clients:` section is the one source. A client may use a toolkit server when its `servers` allow it, within its `max_scope` and `max_risk`, as the account in its `accounts: { <provider>: <account> }` entry (`"*"`: it may choose). `access.ts` reads the live map; `link.ts` plans the change `switchboard link` applies through ClientAdmin. The old `connectors/links.json` and `LinkStore` are gone. |
| Coverage | `src/connectors/coverage.ts` | Reads the R1 checklists (12 CSVs, 1,740 rows, 31 named deprecated). `mapped` means a reviewed endpoint mapping; only an account-stamped `live_verified` line in `connectors/verification.ndjson` makes a row `working`. |
| CLI | `src/connectors/cli-kit.ts`, `src/cli.ts` | `toolkits list\|show\|enable\|disable\|sync <target>`, `coverage [toolkit] [--import dir] [--mark id --state s --account a] [--json]`; and in `cli.ts`, `link <client> <toolkit-or-server-id> [--account ref] [--max-scope s] [--max-risk r]`, `unlink <client> [toolkit]`, `links`, which edit the clients config through ClientAdmin (a running gateway asks you to be present first). `toolkits sync` with no argument is the older browse catalog sync and is unchanged. |

## What exists, seeds and the Connectors page

| Piece | File | Notes |
|---|---|---|
| Seed definitions | `src/connectors/providers/seed/*.json`, `_manifest.json` | 594 candidate ProviderDefs derived from the MIT-licensed Activepieces community pieces (commit `6f4be340d7c4`). Auth definitions by mode: api_key 379, basic 12, custom 144, oauth2 90, oauth2_cc 3 (computed by the extractor into `_manifest.json`). Each is a ProviderDef plus `source: { activepieces_commit, piece }` and `verification: "unverified_seed"`. Licence and copyright: `NOTICE`. |
| Extractor | `scripts/extract-activepieces-auth.mjs` | Parses the pieces' TypeScript with the compiler API (no program, no type checker, no module loading), so no piece code runs; never follows an import out of a piece's own `src`; copies URLs, scope names, field names and a product name only; anything it cannot resolve statically is left out and counted in the manifest. Deterministic. Regenerate: `npm run seed:activepieces -- <sparse checkout dir>`. |
| Registry rules | `src/connectors/providers.ts` | `get` and `has` resolve curated first, then a seed; `list()` stays curated-only so nothing that enumerates providers changed; `listAll()`, `listSeeds()`, `isSeed()` and `shadowedSeeds()` serve the dashboard and `providers list --seeds`. Seeds are read lazily, one file per `get`. A seed whose slug is a curated slug or toolkit is shadowed (curated wins); an owner's `providers/<slug>.json` replaces a seed. A seed with a probe, toolkits, a broad wildcard host or no `unverified_seed` mark is refused. A curated file may not declare `source` or `verification`. |
| Never working | `accounts.ts`, `coverage.ts`, `admin.ts` | An account connected through a seed carries `provider_verification: "unverified_seed"`. `coverage --mark live_verified` refuses an account of a seeded provider and a ledger line stamped with one is ignored when counting. The dashboard reports a seed as `unverified_seed` whatever a ledger says. |
| Admin API | `src/connectors/admin.ts`, routes in `src/dashboard.ts` | Behind the owner session and CSRF like every `/api` route: `GET /api/connectors/providers` (search `q`, filters `auth`, `source`, `connectable`, paging `offset` and `limit`, facet counts), `GET /api/connectors/providers/:slug`, `POST /api/connectors/providers/:slug/connect` (answers `redirect`, `connected`, `needs_setup` with the owner steps, or `needs_input` with the fields), `GET /api/connectors/accounts`, `POST /api/connectors/accounts/:id/probe`, `GET /api/connectors/toolkits`, `POST /api/connectors/toolkits/:slug/enable|disable` (live mount and unmount), `GET /api/connectors/coverage`. Metadata only: no response carries a credential. |
| Connectors page | `public/app.js`, `public/app.css` | `#/connectors`: search, curated or seed, authentication mode, toolkits available, Connect (consent URL, owner steps when no app is registered, a pasted key), connected accounts with status and last probe, Enable and Disable per toolkit, coverage state. Dependency free. |

## Behaviour worth knowing

- Refresh is single flight per account, proactive (a margin before expiry, never more than half the token's
  lifetime) and reactive (one 401). A rotated refresh token is written atomically before the new access token is
  returned. `invalid_grant` marks the account EXPIRED in the same call, writes one `account_expired` audit row and
  returns `SB_ACCOUNT_EXPIRED` with the reconnect command. Nothing retries on its own.
- `AccountStore.authFetch` is the authenticated-call primitive: the credential is injected per the definition's
  `inject` block, the URL host must be in the provider's `api_hosts`, and a redirect to another origin never
  carries the credential. The execution pipeline sends every provider request through it.
- Principals: `AccountStore.setBindingResolver(({ provider, client }) => accountRef)` is installed by the connector kit
  and reads the client's `accounts` entry in the gateway's `clients:` config. The router puts the authenticated principal's
  client in the request `_meta` key `io.mcpswitchboard/client` (never from an argument); a malformed client id is refused,
  not read as the owner's own path. Which account a call runs as (a server pin is final, a client may name only its own
  account, `"*"` lets it choose, a refusal is `SB_POLICY_DENY` naming the client) is `chooseAccount` in `access.ts`, run
  both by the router before an approval exists and by the pipeline.
- Every connector call writes one audit row with `toolkit`, `toolkit_version`, `account`, `client`, `risk`,
  `outward` and `run_id`. The router adds these fields only from a `source: connector` server and only in a strict
  shape, so another upstream cannot write them. No row carries a credential.
- Risk and approvals: each action carries `scope`, `risk`, `outward` and `approval`. The router raises a call's risk by
  them (outward write and full are high; the action's risk is a floor for the server's `risk_defaults`; `proxy_request`
  needs a human on every call) and applies the client's `max_scope` and `max_risk` before any approval exists. A gated call
  is resolved first (`Executor.plan`): the owner approves the account and the built request (method, host, path, query
  hash, body hash, file hashes) as well as the arguments, and the pipeline refuses a call that no longer hashes to what was
  approved. There is no approval seam in the gateway wiring: the router decides, out of band (3.3).
- A 429 pause is per account and lives in memory; `breaker.ts` stays per-server transport health.
- Lifecycle events (`account_connected`, `account_expired`, `account_disabled`, `account_enabled`,
  `account_revoked`) are rows in the hash-chained audit log under server `connectors`.
- A migration of an existing `oauth.json` runs once (marker in `accounts.json`) and leaves the file untouched.

## Using it

```bash
node dist/cli.js connect google                   # prints an authorize URL; the account is probed on connect
node dist/cli.js toolkits sync google            # fetch the YouTube, Gmail and Drive specs into SWITCHBOARD_HOME
node dist/cli.js toolkits sync all --check       # exit 1 when a vendor spec drifted since the last sync
node dist/cli.js toolkits enable gmail           # adds a `source: connector` server to the config
node dist/cli.js link claude-code gmail --max-scope write --account google/me   # edits the clients config (servers, ceilings, accounts)
node dist/cli.js coverage --import <directory of checklist CSVs>
node dist/cli.js providers list --seeds        # curated and seeded providers; a seed is an unverified candidate
```

`settings.connectors` (all optional): `upload_allowlist`, `upload_deny_segments`, `max_upload_bytes`,
`max_download_bytes`, and `media` (`public_base_url` from `switchboard expose --tunnel`, `ttl_seconds`,
`max_fetches`). See `switchboard.config.example.yaml`.

## Not here

A dashboard form for a client's `accounts` binding (the Clients page does not show it yet: use `switchboard link --account`
or the clients API; editing a client on the page leaves its `accounts` untouched); daily canary probes and the
`live_verified` ledger writes they would make; the S3 media
backend; OAuth 1.0a and `custom` auth modes (the schema names them; the engine refuses them); provider breadth
beyond the 13 curated definitions and the seeds (a seed is not a working provider) and toolkit breadth beyond the
six overlays.

Oracles: `npm run verify:connectors-core` (P1) and `npm run verify:connectors-exec` (P2, offline, fixture specs
and a loopback mock provider), and `npm run verify:integration` (the connector layer on the governed gateway: bindings,
the account argument, approvals bound to account and request, risk, hidden toolkits, the owner session, `link`). `node scripts/live-sync-check.mjs` measures the importers against the real public
YouTube, Gmail, Drive, X, Slack and Notion documents and needs the network; it is not part of the chain.
