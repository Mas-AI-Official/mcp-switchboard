# Connectors: provider auth, connected accounts, connect flows (phase P1)

Status: implemented on `vnext/connectors`. Architecture and phases: the local-Composio ADR (section 6 to 9);
this page records what P1 built and where it lives. Phase P2 (execution pipeline, importers, exposure, file
handling) and later are not built here.

## What exists

| Piece | File | Notes |
|---|---|---|
| Provider definitions (data) | `src/connectors/providers/*.json` | 13 bundled: google, github, slack, notion, linear, meta-facebook, meta-instagram, linkedin, tiktok, x, elevenlabs, higgsfield, buffer. Validated by `src/connectors/schemas/provider.schema.json` (Ajv, pinned). `npm run build` copies both folders to `dist/connectors/`. |
| Registry | `src/connectors/providers.ts` | Bundled definitions cannot be overridden. The owner's own definitions go in `<SWITCHBOARD_HOME>/providers/<slug>.json` (new slugs only). A bad file is reported in `issues` and skipped. |
| Auth configs | `src/connectors/authconfigs.ts` | `connectors/authconfigs.json`. Secrets are vault references only; a string that is not a stored vault secret is refused and never echoed. The old vault names `oauth_<provider>_client_id/_secret` still work as a virtual `legacy:<provider>` config. |
| Accounts | `src/connectors/accounts.ts` | `connectors/accounts.json`. Tokens sealed with the vault key. Statuses INITIALIZING, INITIATED, ACTIVE, FAILED, EXPIRED, INACTIVE, REVOKED (a failed or cancelled connect never reaches the file, so the first three and FAILED describe flow outcomes). Several accounts per provider, a per-provider default, atomic writes, re-read when the file changes. |
| Connect flows | `src/connectors/oauthflow.ts` | OAuth2 code (+PKCE per quirk), client credentials, API key, bearer or PAT, basic, token import. Pending authorizations live 10 minutes in `connectors/pending.json` (verifier sealed), so any process on the dashboard port can finish a flow another process began. |
| Token client | `src/connectors/tokenclient.ts` | The one place app credentials go on the wire. Every quirk is a field of the definition. |
| Identity probe | `src/connectors/probe.ts` | Runs on connect (a failing probe fails the connect) and from `accounts probe`. |
| CLI | `src/connectors/cli.ts` | `connect`, `accounts`, `authconfig`, `providers`. |
| Gateway handle | `src/oauth.ts` | Keeps `beginAuth`, `completeAuth`, `accessToken`, `catalog`, `disconnect`; delegates to the engine. `${oauth:provider}` resolves to the provider's default account, `${oauth:provider/label}` to another. |

## Behaviour worth knowing

- Refresh is single flight per account, proactive (a margin before expiry, never more than half the token's
  lifetime) and reactive (one 401). A rotated refresh token is written atomically before the new access token is
  returned. `invalid_grant` marks the account EXPIRED in the same call, writes one `account_expired` audit row and
  returns `SB_ACCOUNT_EXPIRED` with the reconnect command. Nothing retries on its own.
- `AccountStore.authFetch` is the authenticated-call primitive P2 builds on: the credential is injected per the
  definition's `inject` block, the URL host must be in the provider's `api_hosts`, and a redirect to another origin
  never carries the credential.
- Seam for the principals work: `AccountStore.setBindingResolver(({ provider, client }) => accountRef)` picks the
  account per client; the default is the provider's default account.
- Lifecycle events (`account_connected`, `account_expired`, `account_disabled`, `account_enabled`,
  `account_revoked`) are rows in the hash-chained audit log under server `connectors`. No row carries a credential.
- A migration of an existing `oauth.json` runs once (marker in `accounts.json`) and leaves the file untouched.

## Not here

Dashboard pages for accounts and auth configs, the execution pipeline, spec importers, recipes, file staging,
per-client account binding in config, daily canary probes, OAuth 1.0a and `custom` auth modes (the schema names
them; the engine refuses them), and the provider breadth beyond these 13.

Oracle: `npm run verify:connectors-core`.
