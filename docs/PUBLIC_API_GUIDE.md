# Public API tools: shared catalog and executor

Optional, consented access to vetted public APIs that need no key, for MAS-AI apps (MeetingOPS, ClipPilot, Daena and
others). Apps embed it. No gateway process, no install step, no account, no paid fallback.

## Pieces

| File | Role |
|---|---|
| `publicapi/catalog.v1.json` | The one manifest: providers, hosts, terms, commercial-use status, rate limits, tool templates, result shapes. Hand-curated; every entry checked against the provider's own terms and a live call. |
| `publicapi/conformance.v1.json` | Language-neutral test vectors: request planning, refusals, result shaping. Every executor port must pass all of them with zero network. |
| `src/publicapi.ts` | Generic TypeScript executor (`PublicApiClient`, `planCall`, `shapeResult`), exported from the package. |
| `scripts/verify-publicapi.mjs` | Oracle: conformance, catalog hygiene, consent flow, failure mapping. `PUBLICAPI_LIVE=1` adds one real call per provider. |

There is no provider-specific code anywhere. A provider is a JSON entry. Ports in other languages (MeetingOPS has a
Python one in `meetingops/publicapi/`) are about 300 lines and are held to the same vectors.

## Status values

`VERIFIED_FREE` (free, commercial use allowed, live call passed), `FREE_TIER` (free up to a cap or with reserved
rights), `RESTRICTED` (works without a key but terms forbid our use, such as non-commercial only), `PAID`,
`UNAVAILABLE`, `UNVERIFIED`. Only the first two can ever run in a commercial app. A provider listed in
public-apis/public-apis is `UNVERIFIED` until someone reads its terms and makes a live call.

## Catalog 2026.11.05 (verified 2026-11-05)

| Provider | Status | Usable commercially | Apps |
|---|---|---|---|
| Frankfurter exchange rates | VERIFIED_FREE | yes | meetingops, daena |
| Wikipedia page summary | VERIFIED_FREE | yes, CC BY-SA attribution shown | meetingops, daena, clippilot |
| Wikidata entity search | VERIFIED_FREE | yes, CC0 | meetingops, daena, clippilot |
| Wikimedia Commons media search | VERIFIED_FREE | yes, per-file licence and author returned | clippilot, daena |
| Openverse images | FREE_TIER | conditional: provider may charge for commercial use; slow and one 504 on a cold call | clippilot |
| Nager.Date holidays | RESTRICTED | no, free API is private or non-profit only | shown in meetingops, daena with the reason |
| MusicBrainz | RESTRICTED | no, commercial plan required | shown in clippilot with the reason |
| Open-Meteo weather | RESTRICTED | no, free tier is non-commercial | shown in meetingops, daena with the reason |
| Free Dictionary API | UNVERIFIED | unknown, no terms published | never enabled |

Time zones need no API: use the OS or IANA tzdata locally.

## Guarantees (all enforced before any network)

1. No request before the user picks Enable recommended or Customize. Not now, master off and provider off all refuse locally.
2. RESTRICTED, UNVERIFIED, PAID and UNAVAILABLE providers cannot be enabled in a commercial app, and nothing is offered outside the provider's `apps` list.
3. Arguments are validated: unknown arguments refused, every string has a `max_length` (so meeting text cannot be pasted through), types, patterns and ranges checked.
4. HTTPS only, host allowlist per provider, redirects re-checked hop by hop, 1 MB response cap, provider timeout.
5. Local rate limit (minimum interval) and daily quota per provider, counted in the app's own settings file.
6. Every result carries provider, URL, attribution, licence and fetch time.
7. No keys exist in the catalog; the oracle fails on anything key-like.

Stable error codes: `UNKNOWN_PROVIDER`, `UNKNOWN_TOOL`, `PROVIDER_UNAVAILABLE`, `CONSENT_REQUIRED`,
`PROVIDER_DISABLED`, `INVALID_ARGS`, `HOST_NOT_ALLOWED`, `RATE_LIMITED`, `OFFLINE`, `TIMEOUT`, `UPSTREAM_ERROR`, `BAD_RESPONSE`.

## Adding the module to another app

1. Pick an app id, add it to the `apps` (and, if it fits, `recommended_for`) of the providers it should offer, and add a conformance case if behaviour changes.
2. TypeScript or Node: `new PublicApiClient({ app: { id, commercial: true }, store: fileStateStore(<app data dir>/publicapi.json) })`.
   Other languages: vendor both JSON files, port the executor, pin the files' sha256 in a test (see MeetingOPS `tests/test_meetingops_publicapi.py`), run the vectors.
3. UI: on first launch, if `needsPrompt()`, show "Enable free public information tools?" with Enable recommended, Customize, Not now. Settings shows the master switch, one switch per provider with its status, reason, terms link and usage, and the lookup box.
4. Only pass values the user typed into the lookup box. Never route transcripts, recordings, documents or contacts into a call.

## Adding a provider

Read the provider's own terms page and docs (not a directory), make a live call, record the URLs and the date in the
entry, choose a status honestly, then run `npm run build && npm run verify:publicapi` and `PUBLICAPI_LIVE=1`.
Re-vendor the two JSON files into every port and update their pins.
