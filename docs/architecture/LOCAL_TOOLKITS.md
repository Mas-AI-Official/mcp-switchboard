# Local toolkits: connect your own accounts once, share them with every agent

Status: implemented on the `vnext/connectors` branch (provider auth, connected accounts, toolkits, execution, the
dashboard Connectors page, seeded provider breadth). This page is the architecture. The file-by-file notes of what
is built live in [CONNECTORS.md](CONNECTORS.md); step-by-step provider setup is in
[../connectors/OWNER_SETUP.md](../connectors/OWNER_SETUP.md).

## 1. The goal

A hosted tool router gives an agent three things: an account per provider that is signed in once, tools that wrap
each provider's own API, and one MCP endpoint that exposes them. This design gives the same three things on your
own machine:

- tokens are sealed in your local vault and go only to the provider that issued them;
- every toolkit is mounted as an ordinary Switchboard server (`source: connector`), so the on/off switch, scope
  ceilings, per-tool overrides, profiles, rate limits, the circuit breaker, the audit log and per-client links apply
  without a new concept;
- there is no subscription and no third party in the path. The cost is that you register your own OAuth app at each
  provider (section 11): an open-source program cannot ship a client secret, and it cannot hold a provider's
  review on your behalf.

Non-goals: a hosted multi-tenant service, managed OAuth apps, a general code-executing workflow language, and
scraping or cookie-based access of any platform. Official APIs only.

## 2. Architecture

Everything lives under `src/connectors/`.

| Module | Responsibility |
|---|---|
| `providers.ts`, `providers/*.json`, `providers/seed/*.json` | Provider registry. A provider's authentication is data: URLs, PKCE rules, client authentication, scope separator, refresh rules, the hosts its credentials may reach, and the owner setup steps. Curated definitions are hand-written; seeds are unverified candidates (section 9). |
| `authconfigs.ts` | Auth configs: which OAuth app (client id and a vault reference to its secret) a provider uses. Always owner-owned; a secret is a vault reference, never a literal. |
| `accounts.ts` | Connected accounts: status, scopes, identity, expiry, sealed tokens, single-flight refresh, probe, disable, revoke. Several accounts per provider. |
| `oauthflow.ts`, `tokenclient.ts` | Connect flows: OAuth 2 code (with PKCE where the provider supports it), client credentials, API key, bearer or personal access token, basic, token import. A pending authorization lives 10 minutes. |
| `probe.ts` | The identity probe: one read-only call that proves a credential is live and says whose it is. |
| `toolkits.ts`, `toolkits/<slug>/` | Toolkit and action definitions, versioned `YYYYMMDD_NN`, plus the overlay (rename, hide, tags, risk, `important`) and recipes that ship with the code. |
| `importers/discovery.ts`, `importers/openapi.ts`, `sync.ts` | Turn a provider's public specification into actions. The output goes to your `SWITCHBOARD_HOME`, never into git. |
| `recipes.ts` | A tiny declarative step language for composite actions: `http`, `poll`, `upload_resumable`, `foreach`, `map`, `assert`. No code is evaluated. |
| `exec.ts` | The execution pipeline (section 5). |
| `files.ts`, `mediastage.ts` | Input file rules, saved downloads, and short-lived public URLs for platforms that fetch media themselves. |
| `mcpserver.ts`, `links.ts` | One in-process MCP server per toolkit; which client may use which toolkit, how far, as which account. |
| `coverage.ts` | Honest counts (section 8). |
| `admin.ts` | What the dashboard needs: provider listing, connect, accounts, toolkit on/off, coverage state. |

## 3. Data model

```text
ProviderDef   slug, name, categories[], api_hosts[]   (the only hosts this provider's credentials may reach)
              auth[]: AuthDef, owner_setup { console_url, steps[], redirect_uris[], notes[] }, docs_url,
              identity_probe?, api_version_header?
AuthDef       mode: oauth2 | oauth2_cc | oauth1 | api_key | bearer | basic | custom
              oauth2?: authorize_url, token_url, revoke, pkce (required | supported | unsupported),
                       client_auth (body | basic), client_secret_at_exchange, scope_separator,
                       default_scopes[], scope_catalog[], extra_auth_params, redirect (loopback | https | custom),
                       refresh { kind, rotates, lifetime_s }
              inject { in, name, template }, fields { auth_config_creation[], connected_account_initiation[] }
AuthConfig    id (ac_...), provider, auth_id, client_id or client_id_ref, client_secret_ref, scopes[], redirect_uri
ConnectedAccount
              id (ca_...), provider, label, status, scopes_granted[], identity { external_id, display_name },
              expires_at, last_refresh_at, last_probe_at, last_error, sealed token
              status: INITIALIZING | INITIATED | ACTIVE | FAILED | EXPIRED | INACTIVE | REVOKED
Toolkit       slug, provider, version, tools_count, actions[]
Action        slug, title, input_schema, http | steps[], scope (read | write | full), risk (low | medium | high),
              outward, idempotent, important, tags[], files?, verification
VerificationState
              unmapped | mapped | mock_tested | live_verified | blocked_by_platform | declined | deprecated
```

Tool names are `<toolkit>__<action>` and at most 64 characters.

## 4. Flows

**Connect.** `switchboard connect <provider> [--account label]` loads the provider definition, requires a registered
OAuth app (when it has none it prints the owner setup steps and stops), builds the consent URL, waits for the
loopback callback, exchanges the code, runs the identity probe and stores the account. A flow that is cancelled,
expires, is refused, or fails its probe stores nothing. The dashboard runs the same flow.

**Refresh.** Proactive (a margin before expiry) and reactive (one retry on a 401), single flight per account so
concurrent calls cause one token request. A rotated refresh token is written to disk before the new access token
is used. `invalid_grant` marks the account `EXPIRED`, writes one `account_expired` audit row, and returns
`SB_ACCOUNT_EXPIRED` with the exact reconnect command. Nothing retries on its own.

**Disable and revoke.** Disable keeps the tokens and refuses their use. Revoke calls the provider's revoke endpoint
when it has one, then deletes the sealed token.

**Account choice.** An explicit account, else the account bound to the calling client, else the provider's default.
This is how two agents can use two different accounts of the same provider.

A toolkit cannot be enabled until the provider has an `ACTIVE` account that passed its identity probe (fail closed).

## 5. Execution pipeline

The stage order is fixed: kill switch, client filter, toolkit and account, argument validation, scope and risk
policy, approval, limits, token freshness, request build (path, query, body or recipe steps), file staging, the
outbound call through the SSRF guard with the provider's host lock, response normalization, output files,
redaction, audit row (toolkit, version, account, client, risk; never a token).

- A provider's `api_hosts` is a host lock: a URL outside the list is refused, and a redirect to another origin never
  carries the credential.
- Reads may retry on 502, 503 and 504. Anything that can change data (a post, an upload finalize, a send) is never
  retried: a failure after the request left returns `SB_OUTCOME_UNKNOWN` with a reconcile hint (look up the
  container or publish id) instead of risking a double post.
- A 429 with `Retry-After` pauses that account until the provider says it may continue.
- `proxy_request` (a raw call with injected authentication) is a meta tool, host-locked to the provider, and always
  needs a human approval.

## 6. Files and media

Actions may declare `file: upload` and `file: download` parameters. An upload accepts a local path inside an
allowlisted folder (resolved by real path, so a symlink escape is refused), an https URL (through the SSRF guard),
or `staged:<id>`. Sensitive path segments (`.ssh`, `.aws`, `.env`, key and vault files, browser profiles) are never
uploadable whatever the allowlist says; every action has a size cap. A download is written under
`SWITCHBOARD_HOME/files/<run_id>/` and returned as `{uri, bytes, sha256, mimeType}`, never inline.

Some platforms (Instagram images, TikTok pull from URL) fetch media from a public URL. The media stage serves one
file at `/media/<id>` through your own tunnel for at most 15 minutes, a bounded number of fetches, and deletes it
afterwards. With no tunnel configured those actions fail with a clear message.

## 7. Exposure, on and off, per-client links

- One MCP server per toolkit; `servers[].enabled` is the switch (dashboard toggle or `switchboard toolkits
  enable|disable`).
- The default tool list of a toolkit is its curated `important` set, at most 30 tools. The rest of the API is reachable
  through `find_tools` and `call_tool`, so a toolkit with hundreds of operations never floods an agent.
- `switchboard link <client> <toolkit> [--account ca_x] [--max-scope write] [--max-risk medium]` restricts a named
  client to the toolkits it is linked to, within a scope and risk ceiling, optionally as one bound account. Listing and
  calling are both filtered. With no link in the table every caller is allowed; once one client is linked a named
  client that is not in the table is refused.

```yaml
# example values only
clients:
  assistant-a: { servers: ["youtube", "gmail", "drive"], max_scope: write, max_risk: medium }
  assistant-b: { servers: ["slack"], max_scope: read, max_risk: low }
```

## 8. Verification and honest counts

Every action row carries a `VerificationState`. A research checklist of one row per provider action is imported as
`mapped` or `unmapped`; only an owner-run live probe, recorded with the date and the account that proved it, moves a
row to `live_verified`. The dashboard and `switchboard coverage` call a row **working** only in that state:

| State | Meaning |
|---|---|
| `unmapped`, `mapped` | no reviewed endpoint mapping / a reviewed mapping (a plan, not a test) |
| `mock_tested` | a mock contract suite passed, not the real provider |
| `live_verified` | an owner-run probe passed against the real provider |
| `blocked_by_platform` | the platform gates it (an audit, a paid tier): never counted |
| `declined`, `deprecated` | not built on purpose / marked deprecated by the source |

A registered or imported count is not a working count. A line that claims `live_verified` with no account or no date
is ignored when counting, and so is a line stamped with an account of a seeded provider (section 9).

## 9. Seeded provider breadth

The curated definitions cover the priority platforms by hand. For breadth, the project also ships **seeds**:
`src/connectors/providers/seed/*.json`, one candidate definition per provider, derived from the auth settings of the
MIT-licensed [Activepieces](https://github.com/activepieces/activepieces) community pieces at a pinned commit.

- **Facts only.** A static extractor (`scripts/extract-activepieces-auth.mjs`) parses each piece's TypeScript with the
  compiler API and reads URLs, scope names and field names. It never executes piece code, never follows an import out
  of the piece's own folder, and copies no description, label or code. See `NOTICE` for the licence.
- **Assumptions are written down.** What the source does not state (where the client secret travels, the scope
  separator, whether refresh tokens rotate, how an API key is attached) is assumed and listed in each seed's notes.
  The `api_hosts` of a seed are candidates harvested from the piece's request URLs.
- **A seed enables Connect and nothing more.** It is marked `verification: "unverified_seed"`, has no toolkits and no
  identity probe, and an account connected through it is stamped the same way. It can never be counted as working.
- **Curated wins.** A seed whose slug is a curated slug, or a toolkit a curated provider owns, is shadowed and never
  returned. Writing your own `<SWITCHBOARD_HOME>/providers/<slug>.json` for a seeded slug replaces the seed.
- `switchboard providers list --seeds` and the dashboard's Connectors page list them. Which modes this build can
  connect (OAuth 2, client credentials, API key, bearer, basic) and which it cannot (custom multi-field
  authentication, OAuth 1) is shown on every row.

## 10. Security rules

1. Tokens are sealed with the vault key (AES-256-GCM) and never appear in the audit log, logs, any `/api/*` response,
   error text or command output. Errors are scrubbed of the secrets a flow handled before they leave the module.
2. A provider's credentials go only to its declared `api_hosts`, over https (loopback allowed for a local mock), through
   the outbound SSRF guard. A redirect to another origin drops the credential.
3. Client secrets are vault references. A string that is not a stored secret is refused and never echoed.
4. Uploads are limited to an allowlist and a denylist of sensitive paths; an upload cannot reach outside by symlink.
5. Actions that publish, send or delete are classified by verb and name and can only be tightened by an overlay.
   Outward-facing actions are high risk. High risk and `proxy_request` need a human approval.
6. A kill switch refuses every call. A per-client link caps scope and risk and binds the account.
7. Generated toolkit definitions are written to your machine at sync time and are never committed.
8. Seeds are treated as less trusted than curated definitions: no probe, no toolkits, wildcard hosts need at least two
   labels, and they are never counted as working.
9. No scraping, no cookie or stealth-token modes, no browser automation of a platform. Official APIs only; a platform
   restriction notice is a reason to disable that toolkit at once.
10. The admin API behind the dashboard needs the owner session and, on every change, the CSRF header.

## 11. Per-platform route

"Shipped" means a toolkit built from the provider's public specification and overlay is in this repository.
"Definition" means the provider's authentication is defined and a connected account works, but no toolkit of actions
is shipped yet. Action counts are what the importers produced from the public specifications when last measured
(`node scripts/live-sync-check.mjs` re-measures them; the specifications can change).

| Platform | Authentication | Route | Status |
|---|---|---|---|
| YouTube | OAuth 2 (Google) | Google Discovery document, overlay, resumable upload recipe | Shipped, 83 actions |
| Gmail | OAuth 2 (Google) | Google Discovery document, overlay | Shipped, 79 actions |
| Google Drive | OAuth 2 (Google) | Google Discovery document, overlay | Shipped, 64 actions |
| X | OAuth 2 with PKCE | OpenAPI document, overlay; the API tier is billed by X | Shipped, 239 actions |
| Slack | Bot token (OAuth needs an https redirect) | Swagger 2.0 document, curated overlay | Shipped, 174 actions |
| Notion | Integration token | OpenAPI document, overlay | Shipped, 24 actions |
| GitHub | Fine-grained token or OAuth app | Definition; use the connected account from a mounted GitHub MCP server through `${oauth:github}` | Definition |
| ElevenLabs | API key | Definition and a credit-free probe; generation stays behind whatever guard you run | Definition |
| Facebook Pages | OAuth 2 (Meta) | Definition; recipes for feed, photos and resumable video are planned | Definition |
| Instagram | OAuth 2 (Meta), professional accounts only | Definition; container, poll and publish recipes need media staging | Definition |
| LinkedIn | OAuth 2 | Definition; the posts API needs a `Linkedin-Version` header | Definition |
| TikTok | OAuth 2 (https redirect) | Definition; content posting recipes are planned | Definition |

Account injection into a mounted stdio MCP server happens at spawn, so only long-lived tokens (personal access tokens,
bot tokens) are safe there; a remote HTTP server resolves the reference on every call and sees refreshed tokens.

## 12. What you create at each platform, and why no shared app is possible

Every OAuth client belongs to a developer account with its own consent screen and, for sensitive scopes, the
provider's review. A hosted router works because it owns reviewed apps and holds their secrets. A self-hosted
program cannot, so you create the app and Switchboard prints the steps (`switchboard providers show <provider>`) and
checks the result. Details and commands: [OWNER_SETUP.md](../connectors/OWNER_SETUP.md).

| Platform | You create | Known limit (label) | If skipped |
|---|---|---|---|
| Google | A Cloud project with the YouTube, Gmail and Drive APIs enabled, a consent screen, a Desktop OAuth client | A project in Testing publishing status gets refresh tokens that expire in 7 days unless only name, email and profile scopes are requested (Observed, Google identity documentation, 2026-10-23) | Gmail, Drive and YouTube stop working every 7 days |
| Meta | A developer app with Facebook Login for Business and the Instagram API with Instagram login; a linked Instagram professional account | In Development mode only role users can use the app (Observed, Meta app modes page). Whether your own admin account needs App Review is Inferred, not stated. Publishing limits are stated as 100 or 50 posts per 24 hours in different places: check `content_publishing_limit`. | No Facebook or Instagram toolkit |
| LinkedIn | A developer app tied to a Company Page, with the products that grant the scopes you need | `w_member_social` and `r_organization_admin` cannot be combined; `r_member_social` is restricted to approved users (Observed). Organization posting approval path: UNVERIFIED | No LinkedIn toolkit |
| TikTok | A developer app with the Content Posting API; a verified domain only for pull-from-URL | An unaudited client can post only with `SELF_ONLY` privacy, from private accounts, for at most 5 users in 24 hours (Observed, TikTok content sharing guidelines). Public posting needs an audit you submit. | Public TikTok posting stays impossible until audited |
| X | A developer account and app with OAuth 2 and PKCE, and a paid API tier | Analytics returns 403 below Enterprise (Observed). Current prices: UNVERIFIED. This is the one place "no subscription" cannot hold: X charges for the API itself. | No X toolkit |
| Slack | A Slack app in your workspace; paste the bot token | The OAuth redirect must be https; a loopback http redirect is rejected | No Slack toolkit |
| Notion | An internal integration token; share pages with the integration | none | No Notion access |
| GitHub | A fine-grained token, or an OAuth app (loopback redirect allowed) | none | No GitHub access |
| ElevenLabs | An API key you enter yourself | The free plan is non-commercial | n/a |

## 13. Limits of this document

Platform limits above were read from each provider's public documentation on the date shown and can change; every
claim marked UNVERIFIED was not confirmed, and nothing here has been verified against a live provider account. The
honest state of any one action is its `VerificationState`, not this page.
