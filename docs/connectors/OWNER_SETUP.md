# Owner setup: what you create at each platform

Switchboard connects to a provider with an OAuth app or an API key that **you** own. It cannot ship a shared app:
a client secret in an open-source program would be public, and a provider's review of a consent screen belongs to
the developer who submitted it. This page lists, per platform, what to create, the exact commands, the limits you
will meet, and how to check that the connection is real.

`switchboard providers show <provider>` prints the same steps for the version you have installed, and the
dashboard's **Connectors** page shows them in a dialog when you press **Connect** on a provider that has no
registered app yet.

## The same four commands everywhere

```bash
# 1. put the client id and secret in the local vault (pipe them in so they stay out of your shell history)
printf '%s' '<client-id>'     | switchboard vault set <name>_client_id
printf '%s' '<client-secret>' | switchboard vault set <name>_client_secret

# 2. register the app by reference (the vault names, never the values)
switchboard authconfig add <provider> --client-id-ref <name>_client_id --client-secret-ref <name>_client_secret

# 3. connect (opens the consent page; the loopback callback finishes the flow; the identity probe runs)
switchboard connect <provider> --account <label>

# 4. look at the result
switchboard accounts list
switchboard accounts probe <provider>/<label>
```

A provider that uses an API key or token needs no app: `switchboard connect <provider> --token-stdin` and paste it.

The redirect URI to register is the dashboard's loopback callback, `http://127.0.0.1:<port>/oauth/callback` (the
port from your config, 8088 by default), unless a section below says the provider needs https. For an https
redirect, put a tunnel in front of the callback and register it:
`switchboard authconfig add <provider> ... --redirect-uri https://<your-tunnel>/oauth/callback`.

Your own account's token is only as good as its lifetime. Run `switchboard accounts list` after a day, after a
week, and after the first expiry; an account that cannot refresh is marked `EXPIRED` and the error prints the exact
reconnect command.

Labels used below: **Observed** means read from the provider's public documentation on the date shown;
**UNVERIFIED** means not confirmed. Check the provider's current documentation before relying on either.

## Google (YouTube, Gmail, Drive)

You create: a Google Cloud project, the three APIs enabled, an OAuth consent screen, and a **Desktop app** OAuth
client.

1. Create or pick a Google Cloud project: <https://console.cloud.google.com/apis/credentials>.
2. Enable the YouTube Data API v3, the Gmail API and the Google Drive API for it.
3. Configure the OAuth consent screen, then move it **out of Testing** publishing status (see the limit below).
4. Create an OAuth client ID of type Desktop app and copy the client id and secret. A Desktop client accepts a
   loopback redirect on any free port without registering it.
5. Store and register them, then connect with the scopes you need:

```bash
printf '%s' '<client-id>'     | switchboard vault set google_client_id
printf '%s' '<client-secret>' | switchboard vault set google_client_secret
switchboard authconfig add google --client-id-ref google_client_id --client-secret-ref google_client_secret
switchboard connect google --account work --scopes @youtube,@gmail,@drive
switchboard toolkits sync google && switchboard toolkits enable gmail
```

Limit: a project whose publishing status is **Testing** gets refresh tokens that expire after 7 days unless only name,
email and profile scopes are requested (Observed, Google identity documentation, 2026-10-23). If you skip step 3,
the Google toolkits silently stop working every week. Whether an unverified production consent screen or, for a
Workspace organization, an Internal one is better for you: UNVERIFIED, decide at setup.

Check: connect, then run `switchboard accounts probe google/work` eight days later; it must still refresh.

## Meta (Facebook Pages and Instagram)

You create: a Meta developer app, and a linked Instagram professional (Business or Creator) account for Instagram.

Facebook Pages (provider `meta-facebook`):

1. Create a developer app and add Facebook Login for Business (or Facebook Login): <https://developers.facebook.com/apps/>.
2. Add yourself as an app admin. In Development mode only people with a role on the app can use it.
3. Register the redirect URI under Valid OAuth Redirect URIs.
4. Store and register the app id and secret, then connect:

```bash
printf '%s' '<app-id>'     | switchboard vault set meta_app_id
printf '%s' '<app-secret>' | switchboard vault set meta_app_secret
switchboard authconfig add meta-facebook --client-id-ref meta_app_id --client-secret-ref meta_app_secret
switchboard connect meta-facebook --account brand-page --scopes pages_show_list,pages_manage_posts,pages_read_engagement
```

Instagram (provider `meta-instagram`):

1. In the same developer app add the Instagram product with **Instagram API setup with Instagram login**.
2. Add the professional account as a tester or role user. A personal Instagram account cannot use the API.
3. Register the redirect URI under the Instagram business login settings.
4. Store and register the Instagram app id and secret, then connect:

```bash
printf '%s' '<instagram-app-id>'     | switchboard vault set ig_app_id
printf '%s' '<instagram-app-secret>' | switchboard vault set ig_app_secret
switchboard authconfig add meta-instagram --client-id-ref ig_app_id --client-secret-ref ig_app_secret
switchboard connect meta-instagram --account brand --scopes instagram_business_basic,instagram_business_content_publish
```

Limits: Live mode exposes only App Review approved permissions (Observed, Meta app modes page, 2026-10-23); whether
your own admin account needs App Review is Inferred, not stated. The content publishing limit is given as 100 posts
per 24 hours in one section of Meta's documentation and 50 in another: read `content_publishing_limit` before
publishing. Access tokens are about 60 days and are traded or refreshed by the engine (Observed); whether an
exchange of a still-valid token resets the full lifetime is UNVERIFIED, so trust the expiry date `accounts show`
prints. Instagram images must be reachable at a public JPEG URL unless the app uses resumable upload, which is what
the media stage (`switchboard expose`) is for. Whether Meta accepts an http loopback redirect in Development mode is
UNVERIFIED: if the console refuses it, use an https tunnel.

## LinkedIn

You create: a developer app tied to a Company Page, with the products that grant the scopes you need.

1. Create the app: <https://www.linkedin.com/developers/apps>. Organization posting also needs an admin role on the Page.
2. On the Products tab request the products that grant your scopes (Sign In with LinkedIn using OpenID Connect for
   `openid`, `profile`, `email`; Share on LinkedIn for `w_member_social`). The scopes the app may use are on its Auth tab.
3. On the Auth tab add the redirect URL.
4. Store, register and connect:

```bash
printf '%s' '<client-id>'     | switchboard vault set linkedin_client_id
printf '%s' '<client-secret>' | switchboard vault set linkedin_client_secret
switchboard authconfig add linkedin --client-id-ref linkedin_client_id --client-secret-ref linkedin_client_secret
switchboard connect linkedin --account personal --scopes openid,profile,email,w_member_social
```

Limits (Observed, LinkedIn and Microsoft Learn documentation, 2026-10-23): `w_member_social` and
`r_organization_admin` cannot be combined; `r_member_social` is restricted to approved users; access tokens live 60
days and programmatic refresh tokens go only to a limited set of partners, so an expired token means a new consent.
The posts API needs a `Linkedin-Version: YYYYMM` header on every call. UNVERIFIED: the approval path for
organization posting, and whether LinkedIn accepts an http loopback redirect (use an https tunnel if it does not).
Use the official API only: no browser automation.

## TikTok

You create: a developer app with Login Kit and the Content Posting API. A verified domain is needed only for
"pull from URL" uploads.

1. Create the app: <https://developers.tiktok.com/apps/>.
2. Register an **https** redirect URI that forwards to your gateway (static, no query or fragment, under 512
   characters). TikTok requires https, so run a tunnel to the loopback callback and register its URL.
3. Store, register (with the tunnel URL) and connect:

```bash
printf '%s' '<client-key>'    | switchboard vault set tiktok_client_key
printf '%s' '<client-secret>' | switchboard vault set tiktok_client_secret
switchboard authconfig add tiktok --client-id-ref tiktok_client_key --client-secret-ref tiktok_client_secret --redirect-uri https://<your-tunnel>/oauth/callback
switchboard connect tiktok --account brand --scopes user.info.basic,video.publish
```

Limits (Observed, TikTok content sharing guidelines, 2026-10-23): an **unaudited** client can post only with
`SELF_ONLY` privacy, from private accounts, for at most 5 users in 24 hours. Public posting needs an audit that you
submit. Access tokens last 24 hours and refresh tokens 365 days.

## X

You create: a developer account, a project and app with OAuth 2.0 and PKCE, and a paid API access tier. The API itself
is billed by X: this is the one platform where "no subscription" cannot hold.

1. Create the app: <https://developer.x.com/en/portal/dashboard>.
2. In the app's user authentication settings enable OAuth 2.0 and add the callback URL.
3. Copy the OAuth 2.0 Client ID and Client Secret from Keys and Tokens.
4. Store, register and connect:

```bash
printf '%s' '<client-id>'     | switchboard vault set x_client_id
printf '%s' '<client-secret>' | switchboard vault set x_client_secret
switchboard authconfig add x --client-id-ref x_client_id --client-secret-ref x_client_secret
switchboard connect x --account brand --scopes tweet.read,tweet.write,users.read,offline.access
```

Limits: a refresh token is issued only with the `offline.access` scope; an access token otherwise lasts two hours
(Observed, X OAuth 2.0 documentation, 2026-10-23). Analytics returns 403 below the Enterprise tier (Observed). Current
prices: UNVERIFIED. Whether the console accepts an http loopback callback is UNVERIFIED.

## Slack

You create: a Slack app in your workspace. Use the **bot token**: Slack requires an https redirect for OAuth and
rejects a loopback http callback.

1. Create the app: <https://api.slack.com/apps>, Create New App.
2. Under OAuth and Permissions add the bot scopes the agents need (for example `channels:read`, `chat:write`) and
   install the app to the workspace.
3. Copy the Bot User OAuth Token (it starts with `xoxb-`) and connect:

```bash
switchboard connect slack --token-stdin      # paste the token, or pipe it in
switchboard toolkits sync slack && switchboard toolkits enable slack
```

For browser OAuth instead, front the callback with an https tunnel and register it with
`switchboard authconfig add slack ... --redirect-uri https://<your-tunnel>/oauth/callback`, then
`switchboard connect slack --auth oauth2`.

## Notion

You create: an internal integration and a token. Nothing else; Notion refuses calls to pages not shared with it.

1. Create an internal integration: <https://www.notion.so/profile/integrations>. Copy its token from the Configuration tab.
2. Share each page or database the agents need with the integration.
3. Connect:

```bash
switchboard connect notion --token-stdin
switchboard toolkits sync notion && switchboard toolkits enable notion
```

A public integration (OAuth) works too: register its client with `switchboard authconfig add notion ...` and run
`switchboard connect notion --auth oauth2`.

## GitHub

You create: a fine-grained personal access token, or an OAuth app.

1. Token (simplest): <https://github.com/settings/personal-access-tokens>. Limit it to the repositories and permissions
   the agents need, then `switchboard connect github --auth pat --token-stdin`.
2. OAuth app (browser consent): <https://github.com/settings/developers>, New OAuth App, callback URL = the loopback
   redirect. GitHub lets the registered loopback callback use any port.
3. Store, register and connect an OAuth app:

```bash
printf '%s' '<client-id>'     | switchboard vault set gh_client_id
printf '%s' '<client-secret>' | switchboard vault set gh_client_secret
switchboard authconfig add github --client-id-ref gh_client_id --client-secret-ref gh_client_secret
switchboard connect github
```

GitHub reports a failed token exchange as HTTP 200 with an `error` field; the engine reads the body. To use the account
from a mounted GitHub MCP server, reference it as `${oauth:github}` in that server's headers.

## ElevenLabs

You create: an API key in your account settings (<https://elevenlabs.io/app/settings/api-keys>), with a monthly credit limit
you are willing to spend. You enter the key yourself; nobody else needs to see it.

```bash
switchboard connect elevenlabs --token-stdin
switchboard accounts probe elevenlabs
```

The probe calls `GET /v1/models`, which reads the model list and spends no credits. The free plan is non-commercial.
This definition holds and probes the account; it does not wire generation actions.

## Linear, Higgsfield, Buffer

- **Linear**: create an OAuth application (Settings, API), register its callback URL, then the four commands above with
  provider `linear`.
- **Higgsfield**: create an API key in the console (a key id and a secret) and connect with
  `switchboard connect higgsfield --field key_id=${vault:higgsfield_key_id} --field key_secret=${vault:higgsfield_key_secret}`
  after storing each with `switchboard vault set`. No identity probe is defined, so the account is stored but not
  verified until a real call succeeds.
- **Buffer**: simplest is a personal API key (`switchboard connect buffer --token-stdin`); OAuth needs PKCE and a
  registered app (`--auth oauth2`).

## Seeded providers (unverified candidates)

The dashboard and `switchboard providers list --seeds` also show several hundred **seeds**: candidate definitions derived
from the MIT-licensed Activepieces community pieces (see `NOTICE`). A seed gives you the Connect flow for a provider
nobody has hand-checked yet. Treat it as a starting point:

1. Open the provider in the dashboard (Connectors page, Details) and read its notes: they list what the source did not
   state and was assumed (where the client secret travels, the scope separator, how a key is attached) and where the
   `api_hosts` came from. Check them against the provider's own documentation.
2. Create the OAuth app or key at the provider as above and connect. The account is stored and stamped
   `unverified_seed`.
3. A seed cannot be probed, has no toolkits, and is never counted as working. To promote a provider, write your own
   `<SWITCHBOARD_HOME>/providers/<slug>.json` (it replaces the seed), add an identity probe, reconnect, probe, and only
   then record a live check with `switchboard coverage --mark <row> --state live_verified --account <ca_id>`.

## When something fails

| You see | Meaning | Do |
|---|---|---|
| `needs an OAuth app that you register first` | no auth config for that provider | follow the section above, then connect again |
| `requires an HTTPS redirect URI` | the provider rejects an http loopback callback | start a tunnel, register it, pass `--redirect-uri` |
| `identity probe failed` | the credential was issued but the provider refused the probe | nothing was stored; check scopes and the app's mode (Development or Live) |
| `SB_ACCOUNT_EXPIRED` | the refresh token was refused or the token cannot be renewed | run the printed `switchboard connect ...` command |
| a seed shows `Connect unavailable` | its authentication is `custom` or OAuth 1, which this build does not drive | use a curated provider, or wait for that mode |
| `403` with a restriction or policy notice | the platform restricted the app or account | disable that toolkit at once and read the notice; never work around it |
