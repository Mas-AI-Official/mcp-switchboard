# MCP Switchboard — Roadmap

Principle: **ship the smallest thing that is already differentiated.** The MVP had to be
local-first + per-tool toggle on day one — that alone beats "paste 10 server configs by hand."

Status legend: ✅ shipped (in the working alpha) · 🔜 next · 🗓 later.

## Phase 0 — Frame ✅
Name, vision, architecture, competitive read, config schema. Done — see
[VISION.md](VISION.md), [BLUEPRINT.md](BLUEPRINT.md), [COMPETITIVE.md](COMPETITIVE.md).

## Phase 1 — MVP gateway ✅ *(shipped)*
**Goal:** `switchboard serve` → mount existing MCP servers → one endpoint → toggle per server/tool.
- [x] CLI `switchboard serve` starts the local gateway.
- [x] `switchboard.config.yaml`: list `npx` + `binary` + `remote` upstream servers.
- [x] Aggregated MCP endpoint (stdio + Streamable HTTP), `namespaced` tool exposure.
- [x] Enable/disable per server **and** per tool.
- [x] BYO API keys via local encrypted vault (`${vault:...}` / `${env:...}` refs).
- [x] Web dashboard: list servers, toggle ON/OFF (live mount/unmount + persist), copy MCP URL.
- **Differentiator present from day one:** local-first + granular enable.

## Phase 2 — Governance & scopes ✅ *(shipped)*
- [x] `read / write / full` classification per tool (name/verb inference + per-tool overrides).
- [x] Approval gates on `write`/`full` (interactive confirm, fail-closed).
- [x] Append-only audit log + dashboard viewer.
- The MAS-AI-native moat: local credentials **+** a real governance layer.

## Phase 3 — Auth & catalog ✅ *(shipped)*
- [x] OAuth-per-provider, done locally — **5 providers wired**: Google, GitHub, Slack, Notion, Linear
      (`src/oauth.ts`: PKCE where supported, per-provider authorize/token URLs, scope separators,
      loopback redirect). Hand-rolled on Node's built-in `crypto` — **no Nango, zero native deps**;
      tokens are sealed in the same AES-256-GCM vault as BYO keys.
- [x] Curated catalog UI: browse providers → one-click **Connect** → provider login → token sealed →
      row flips to **connected** (`src/console.ts` catalog card + `/api/catalog` · `/api/connect/:provider`
      · `/oauth/callback` in `src/dashboard.ts`). CLI parity: `switchboard catalog` + `switchboard connect <provider>`.
- *BYO keys via the vault still work unchanged; managed OAuth is now the headline path for the 5 providers.*
- **Cut (still deferred):** hosted/team sync.

## Phase 4 — app2mcp ✅ *(shipped)*
- [x] OpenAPI/Swagger import → in-process MCP server, generated at mount (`src/openapi.ts`,
      linked via the SDK's `InMemoryTransport` — no extra process, no FastMCP dependency).
      Supports OpenAPI 3.x **and** Swagger 2.0; `base_url` override for relative/host-less specs.
- [x] Verb→scope inference (`GET/HEAD/OPTIONS/TRACE`→read, `POST/PUT/PATCH`→write, `DELETE`→full)
      threaded into the **same governance engine** — proven live: a generated `deletepet` is denied
      under a `read` ceiling. Per-operation enable via the standard per-tool toggle.
- [ ] Postman / cURL import — *still deferred* (OpenAPI covers the 80%).
- **Honest scope:** spec-in → MCP-out. Still explicitly NOT "any app with no API." A config that
  references `app2mcp` **without** a resolvable spec still fails closed.

## Phase 5 — Scale & optional hosted 🗓 *(later)*
- [x] `search` tool-exposure mode (`find_tools` / `call_tool`) for large catalogs — **already shipped**
      ahead of schedule (it was the cheapest answer to the context-wall risk).
- [ ] Optional open-core hosted tier: team policy, SSO, managed OAuth — the free local core stays headline.

## Standing risks (revisit every phase)
1. **Crowded space** (Composio/Pipedream/Arcade/Klavis/ACI). → Win on local-first + governance + UX,
   NOT catalog size. (Most rivals are cloud-first and store your tokens server-side — see
   [COMPETITIVE.md](COMPETITIVE.md).)
2. **Integration maintenance treadmill.** → Mitigated by *mounting* existing servers, not owning them.
3. **Too-many-tools context blowup.** → Namespacing + enable-gating (Phase 1) **and** `search` mode
   (shipped early). Risk largely retired.
4. **Auth is the hard 80%.** → BYO-keys first (cheap, safe, shipped); OAuth deferred to Phase 3 with
   Nango as the escape hatch.
5. **Scope creep into "the magic any-app converter."** → Locked non-goal. Spec-in only; fails closed.
