# Switchboard — Roadmap

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

## Phase 3 — Auth & catalog 🔜 *(next)*
- [ ] OAuth-per-provider, done locally (start with 5: Google, GitHub, Slack, Notion, Linear).
      Evaluate embedding **Nango** (source-available unified auth) vs hand-rolling.
- [ ] Curated catalog UI: browse → one-click connect → login → enabled.
- *Today:* BYO keys via the vault, plus `remote` servers you've pre-authed. Managed OAuth is the gap.
- **Cut:** hosted/team sync.

## Phase 4 — app2mcp 🗓 *(later)*
- [ ] OpenAPI/Swagger import → generated MCP server (lean on FastMCP/openapi-mcp-style generators).
- [ ] Verb→scope inference; per-operation enable.
- [ ] Postman / cURL import.
- **Honest scope:** spec-in → MCP-out. Explicitly NOT "any app with no API." The `app2mcp` source
  **fails closed today** (throws on mount) so nothing is silently half-exposed before this lands.

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
