# MCP Switchboard — Vision & Positioning

## The problem

The agent ecosystem standardized on **MCP** for tool access. But connecting agents to real apps
is still painful in two ways:

- **N×M wiring.** Every agent client configures every server separately. No central on/off,
  no shared policy, no audit.
- **The hosted tax.** The easy fix (Composio, Pipedream Connect) is to let a SaaS hold your
  OAuth tokens and proxy your calls. Convenient, but you've handed a third party standing
  access to your GitHub/Gmail/Slack. For security-conscious users and regulated teams that's a
  non-starter.

## The product

A single **local process** + **dashboard** that sits between your agents and your apps:

- Mounts existing MCP servers (and generates new ones from API specs).
- Exposes **one MCP endpoint** to all agent clients.
- Lets you **toggle apps ON/OFF**, log in, and set **read / write / full** access per app and
  per tool — from a dashboard.
- Keeps every credential in a **local encrypted vault**. Nothing leaves the machine.

## Who it's for

1. **Developers running multiple agent clients** who are tired of re-pasting server configs.
2. **Security/privacy-conscious users & small teams** who refuse to hand tokens to a SaaS.
3. **Builders** who want to expose their own internal API to agents in minutes (app2mcp).

## Positioning vs the field

| Player | Model | The gap we exploit |
|---|---|---|
| **Composio** | Hosted, managed auth, big catalog | Your tokens on their servers; not local-first |
| **Pipedream Connect** | Hosted, embeddable auth, huge catalog | Same — centralized credentials, SaaS-bound |
| **Arcade.dev** | Tool-calling platform w/ scoped auth | Hosted-leaning; we're self-hosted + governance-first |
| **Klavis / ACI.dev** | OSS MCP integrations, self-hostable | Closest neighbors — we differentiate on **governance + dashboard UX + app2mcp**, not catalog size |
| **MetaMCP / mcp-proxy** | OSS aggregator plumbing | Plumbing without the vault, policy layer, or login UX — we sit on top |
| **Nango** | OSS unified OAuth engine | Not an MCP product — a component we can *use*, not compete with |

*(This table is the pre-research read; [COMPETITIVE.md](COMPETITIVE.md) gets the grounded version.)*

## Differentiation pillars (the moat)

1. **Local-first / BYO-creds** — structural, not copyable by hosted players.
2. **Aggregate, don't re-implement** — mount existing servers + OpenAPI→MCP. Kills the
   integration-maintenance treadmill that is every competitor's real cost.
3. **Governance** — per-tool scopes + approval gates + audit log. On-brand for MAS-AI/Daena.
4. **One filtered endpoint + tool-search** — solves the "100 servers = 1000 tools = context
   blowup" problem that naive aggregators ignore.
5. **Dashboard that a non-CLI human can use** — toggle, login, scope. The "operator console."

## Non-goals (say no, loudly)

- ❌ Re-implementing 300 integrations from scratch (that's the competitors' cost sink, not ours).
- ❌ Being a hosted token vault on day one (that *becomes* Composio — the thing we're reacting to).
- ❌ "Point it at any app with no API and it just works." Magic we can't ship. The honest version
  is **spec-in → MCP-out** (OpenAPI / Postman / cURL).

## Business shape

- **Free OSS core** is the wedge — recommend **Apache-2.0** (friendly to embedding → adoption).
  (AGPL would protect against hosted clones but throttles developer adoption; decide before launch.)
- Later, optional **open-core**: hosted sync / team policy / SSO / managed OAuth for orgs that
  *want* the convenience — but the free local-first core stays the headline.
