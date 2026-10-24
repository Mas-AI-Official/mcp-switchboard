# Provider cost comparison: local integrations vs a hosted integration platform

Scope: the money cost of connecting agents to third-party platforms with Switchboard's local connectors versus a hosted
integration platform. Vendor figures were observed on 2026-10-23; prices and quotas move, so re-check the source before
relying on a number. Labels: Observed (read on a vendor page or doc on the date above), Read in code (this repository),
Per doc (a repo design page), Inferred, UNVERIFIED (a price or quota not sourced; no number given), Unknown (anything else
not checked). See also [OWNER_SETUP.md](connectors/OWNER_SETUP.md) for per-platform setup facts.

## 1. Grounded facts

| Item | Figure | Source | Date observed |
|---|---|---|---|
| Hosted platform, Hobby plan | $0, 100,000 tool calls per month cap | https://composio.dev/pricing | 2026-10-23 |
| Hosted platform, Pro plan | $29 per month, plus $0.0003 per call over the allowance (allowance size: UNVERIFIED) | https://composio.dev/pricing | 2026-10-23 |
| Switchboard software | $0 (Apache-2.0, self-hosted); no billing meter or call cap. Calls are counted in a local Usage view (`GET /api/usage`) and never billed or capped by a plan. | `package.json`, `LICENSE`, `src/audit.ts`, `src/dashboard.ts` | read in code |
| Platform API fees charged by the platforms | apply when you register your own app; whether the hosted platform passes them through: UNVERIFIED | section 3 | 2026-10-23 |

## 2. What the comparison does and does not say

- Switchboard replaces the hosted platform's subscription line, not the platforms' own API charges, which you pay under
  your own app (Per doc, LOCAL_TOOLKITS section 12). The hosted side's handling of those charges is UNVERIFIED.
- With the Hobby plan at $0 and 100,000 calls a month, going local saves $0 for a user inside that cap (Inferred).
- For a Pro user the saving is at least the $29 base fee, plus any per-call overage (Inferred). The overage rate is
  $0.0003 per call above the allowance; with the allowance unknown, the total is UNVERIFIED and there is no $29 ceiling.
- So the case for running locally is mostly not dollars at small scale. The other reasons: tokens are sealed at rest in a
  local vault and sent only to the provider's declared API hosts by the built-in connectors, per-agent account binding, and
  the on/off, risk and approval controls of the gateway. The limits: a same-user process on the machine is not contained
  ([THREAT_MODEL.md](THREAT_MODEL.md) section 1), and a token injected into a mounted MCP server goes to that server.

### Reading the cap

100,000 calls a month is about 3,333 calls a day averaged over 30 days (computed: 100,000 divided by 30). A single agent
doing interactive work is unlikely to approach that; a batch job or polling loop could (Inferred; no usage was measured).
Switchboard has no plan cap, but it has governor limits (`per_minute`, `per_hour`, `per_day`, `cost_per_*`,
`src/governor.ts`) so a loop is bounded by your own configuration. Those limits are token buckets held in memory: a
gateway restart resets them, and `per_day` is a refilling bucket, not a calendar-day counter.

### Where each option fits

| Situation | Leaning | Why |
|---|---|---|
| Inside the Hobby cap, tokens may live with a third party | Hosted, $0 | No saving from local at this scale (Inferred) |
| Needs the Pro plan and you can run a local process | Local saves at least $29 per month | Software cost is $0 (read in code); overage UNVERIFIED |
| Tokens must not sit with a third party | Local, accepting the same-user limit in THREAT_MODEL section 1 | Custody, not price, decides |
| A platform gates you (TikTok audit, X paid tier) | Local does not remove the gate; hosted side: Unknown, not checked | LOCAL_TOOLKITS section 12 says a hosted router works because it owns reviewed apps (Per doc) |
| You cannot spend setup time on developer apps | Hosted may be faster | Most OAuth platforms need your own developer app locally (Per doc); Slack, Notion, GitHub and ElevenLabs take a bot token, integration token, fine-grained token or API key |

## 3. Costs that remain when you run locally

Covers the providers read so far; the repo ships 13 curated provider definitions.

| Platform | Cost or gate Switchboard does not remove | Label |
|---|---|---|
| X | X charges for API access. Price list: UNVERIFIED. The claim that Analytics returns 403 below Enterprise has no source URL here (it comes from `LOCAL_TOOLKITS.md` section 12, which marks it Observed without a link). | Per doc (charges, 403), UNVERIFIED (prices, source) |
| TikTok | Public posting needs TikTok's app audit that you submit. An unaudited client can post only with `SELF_ONLY` privacy, from private accounts, for at most 5 users in 24 hours. | Per doc (TikTok content sharing guidelines, read 2026-10-23) |
| Google | A Cloud project in Testing status gets refresh tokens that expire in 7 days unless only name, email and profile scopes are requested. Cost of leaving Testing: UNVERIFIED. | Per doc (7 days), UNVERIFIED (cost) |
| Meta | Development mode limits use to role users; whether your own admin needs App Review is not stated. | Per doc (modes), Inferred (review) |
| LinkedIn | Some scopes are restricted to approved users; organization posting approval path. | Per doc (restriction), UNVERIFIED (path) |
| ElevenLabs | The free plan is non-commercial; paid plan cost: UNVERIFIED. | Per doc (non-commercial) |
| Buffer, Higgsfield, Linear | Pricing not read. Higgsfield is a balance-based generation API. | UNVERIFIED |
| Slack, Notion, GitHub | No platform fee found in the notes read; none is asserted. | Unknown |

Most OAuth platforms need you to register your own developer app, because an open-source program cannot ship a client
secret or hold a provider's review (LOCAL_TOOLKITS section 12). Slack takes a bot token, Notion an integration token, GitHub a
fine-grained token or an OAuth app, ElevenLabs an API key. That is time cost, not a subscription.

## 4. Other cost lines, not priced here

| Line | Status |
|---|---|
| Your engineering and setup time per platform | UNVERIFIED (no measured figure) |
| Hosting, if you run the gateway on a server instead of your own machine | UNVERIFIED |
| A tunnel for platforms that fetch media from a public URL | UNVERIFIED (`cloudflared`, `ngrok` and `tailscale` are named in `src/expose.ts`; no price was read) |
| Hosted platform price changes after 2026-10-23 | Unknown |

## 5. Limits of this page

- Only two vendor price points plus one overage rate are quoted, all from one page read on one date; the pricing page was read for its first 100,000 characters only.
- No usage was measured, so the cap discussion is arithmetic and reasoning, not a forecast.
- Nothing here has been checked against a live provider account.

## 6. How to update this page

1. Re-read the vendor pricing page and each platform's API pricing page.
2. Replace the figure, the source URL and the date together. Keep UNVERIFIED for anything not read.
3. Do not add a number from memory.
