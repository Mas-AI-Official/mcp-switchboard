# Switchboard — Competitive Landscape

> **Status:** grounded. The table below is researched against primary sources (linked at the
> bottom). Where a fact could not be verified, it is labelled **unverified** rather than asserted.

## The one axis that separates Switchboard from the field

**Where do the OAuth tokens / API keys live?** Almost every hosted aggregator stores your
credentials **on their cloud**, encrypted at rest, and injects them server-side at call time. Your
tokens transit their infrastructure. Switchboard keeps them in a **local AES-256-GCM vault on your
own machine** — there is no cloud, because there is no "us." That is the sharpest, most defensible
difference; the catalog size is not.

## Landscape

| Player | OSS vs hosted | Where creds / OAuth tokens live | MCP support | License | #1 difference vs. local-first self-hosted Switchboard |
|---|---|---|---|---|---|
| **Composio** | SDKs are OSS; the tool-router + auth is a **hosted service** | **Composio's cloud** (encrypted at rest, injected server-side) | Hosted MCP server + SDK ("MCP gateway") | MIT *(SDKs only)* | Core brokering is cloud SaaS — your tokens transit their infra unless you buy a VPC tier |
| **Pipedream Connect** | Hosted / proprietary | **Pipedream's cloud** (per-user, all calls proxied through them) | Hosted MCP server (managed auth) | Proprietary *(no OSS edition — unverified)* | Fully managed; you cannot self-host the auth/proxy layer |
| **Arcade.dev** | OSS framework + hosted runtime | Hosted: Arcade cloud · self-host: tokens validated by **your** OAuth 2.1 resource server | Both: hosted catalog + self-hostable servers (`arcade-mcp`) | MIT *(framework)* | A dev framework/runtime for building secure tools, not a turnkey local vault + dashboard aggregator |
| **Klavis AI** | OSS (Strata) + hosted | Hosted MCP: **Klavis cloud** (multi-tenant OAuth) · self-host images exist | Both: hosted servers + self-hostable Strata image | Apache-2.0 | OAuth/multi-tenant designed cloud-first; self-host is the secondary path |
| **ACI.dev (Aipolabs)** | OSS | Self-host stores creds **locally**, but the self-host catalog is limited; the full 600+ is **cloud-only** | Unified MCP server + SDK | Apache-2.0 | Closest peer — but its full catalog is gated to hosted; Switchboard ships full BYO with no hosted dependency |
| **MetaMCP / mcp-proxy / mcgravity** | OSS aggregator plumbing | **Local / your machine** (wherever you configure) | Aggregate many MCP servers → one endpoint | mcp-proxy MIT · mcgravity Apache-2.0 · MetaMCP *(unverified)* | Plumbing, not product — no opinionated encrypted vault + governance scopes + BYO-credential UX |
| **Nango** | Source-available | **Your infra if self-hosted** (managed OAuth, token store, refresh) | Auth engine first; MCP server only on **paid** tiers | Elastic License v2 *(source-available, not OSI)* | An auth/integration engine to *embed*, not an MCP aggregator product — a build-vs-buy component, not a rival |

## Other local-first / self-hosted MCP gateways

- **Docker MCP Gateway/Toolkit** — OSS, runs MCP servers in isolated containers; secrets via Docker
  Desktop stay local. The strongest local-first rival; container-centric, not a BYO-credential
  dashboard.
- **Gate22 (by ACI.dev)** — OSS MCP gateway / control-plane focused on team governance + audit of
  tool access.
- **Bifrost (Maxim AI)** — self-hostable single-binary AI gateway with native MCP; a
  performance / enterprise-governance angle.
- **mcphub** — referenced as a registry/catalog; a distinct self-hosted aggregator product by this
  name could **not be verified**.

## Corrections to earlier assumptions

1. **Composio is *not* a self-hostable OSS aggregator.** Only its SDKs are MIT; the router +
   credential brokering is a hosted SaaS with tokens on their cloud. Positioning it as "OSS you can
   self-host" would be inaccurate.
2. **Nango is *not* really an MCP product.** It's a source-available (Elastic License — *not* true
   OSI/OSS) auth/proxy engine; the MCP server is a paid add-on. Treat it as an embeddable component,
   not a head-to-head competitor.
3. **ACI.dev's self-host catalog is heavily reduced** vs. its 600+ hosted tools. Verify before
   claiming it's a full local-first equal.

## The bet (now grounded)

The catalog is **not** the moat — every hosted player already has a bigger one and pays to keep it
working. The defensible white space for a solo/OSS builder is the **combination** of
**local-first credentials + a governance/policy layer + a human-usable dashboard**, built as an
**aggregator** that rides the existing MCP-server ecosystem instead of re-implementing it. The
research sharpens this: the hosted incumbents are differentiated *away* from us precisely on
credential custody (theirs) and self-hostability (partial or paid). Switchboard's lane — full BYO,
zero-custody, governed, self-hosted, free — is genuinely under-occupied; ACI.dev's local mode is the
nearest neighbour, and even it gates its real catalog behind the cloud.

## Sources

Composio: [per-user OAuth](https://composio.dev/content/per-user-oauth-for-ai-agents) ·
[authenticating tools](https://docs.composio.dev/docs/authenticating-tools) ·
[MCP gateway](https://composio.dev/content/what-is-mcp-gateway) ·
[repo (MIT, SDKs)](https://github.com/ComposioHQ/composio) ·
Pipedream: [Connect MCP](https://pipedream.com/docs/connect/mcp/developers) ·
Arcade: [arcade-mcp](https://github.com/arcadeai/arcade-mcp), [secure your MCP server](https://docs.arcade.dev) ·
Klavis: [repo (Apache-2.0)](https://github.com/Klavis-AI/klavis) ·
ACI.dev: [repo (Apache-2.0)](https://github.com/aipotheosis-labs/aci), [Gate22 / self-host docs](https://aci.dev) ·
MetaMCP: [repo](https://github.com/metatool-ai/metamcp) ·
mcp-proxy: [repo (MIT)](https://github.com/sparfenyuk/mcp-proxy) ·
mcgravity: [repo (Apache-2.0)](https://github.com/tigranbs/mcgravity) ·
Nango: [repo (Elastic License v2)](https://github.com/NangoHQ/nango), [pricing](https://nango.dev/pricing) ·
Docker: [MCP gateway docs](https://docs.docker.com/ai/mcp-catalog-and-toolkit/mcp-gateway) ·
Bifrost: [top open-source MCP gateways](https://getmaxim.ai).

**Caveats / unverified:** Pipedream Connect having no OSS edition (assumed proprietary, not
explicitly confirmed); MetaMCP's exact license string (repo says open-source, LICENSE not read);
"mcphub" as a real distinct aggregator product. Everything else is sourced above.
