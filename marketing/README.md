# MCP Switchboard — Launch Marketing Pack

Ready-to-post launch artifacts for **mcp-switchboard**. Every file was adversarially fact-checked
against the repo `README.md` before landing here — no fabricated metrics, no "production-ready" claims.
Status everywhere is **working alpha** (zero stars, zero known production users at launch).

**Ground facts (do not drift):**
- npm package: pending publication as `mcp-switchboard`; CLI command after install: `switchboard`
- Current install: `npm install -g https://github.com/Mas-AI-Official/mcp-switchboard/releases/download/v0.1.0/mcp-switchboard-0.1.0.tgz` → `switchboard init && switchboard serve` (Node ≥ 18.18)
- Repo / "the address": https://github.com/Mas-AI-Official/mcp-switchboard
- License Apache-2.0 · by MAS-AI Technologies · dashboard at http://127.0.0.1:8088
- Catalog: real count is 4,776 toolkits → say **"4,700+"** in copy

## Artifacts

| File | Channel | What it is |
|---|---|---|
| [show-hn.md](show-hn.md) | Hacker News | Show HN title + problem-first body + author's first comment (invites criticism) |
| [product-hunt.md](product-hunt.md) | Product Hunt | Tagline, description, gallery captions, maker comment |
| [reddit-localllama.md](reddit-localllama.md) | r/LocalLLaMA | Offline/local-LLM-angle post (council against a local model, zero keys) |
| [reddit-selfhosted.md](reddit-selfhosted.md) | r/selfhosted | Self-hosted credential-custody angle vs metered cloud |
| [x-thread.md](x-thread.md) | X / Threads / Bluesky | 10-tweet launch thread (N×M→N×1, both Claude + ChatGPT) |
| [blog-launch.md](blog-launch.md) | dev.to / Hashnode / blog | Long-form launch write-up (problem, design, oracle approach) |
| [registry-submissions.md](registry-submissions.md) | Registries + directories | **Highest star-leverage.** awesome-mcp-servers PR line, official MCP registry `server.json` + `mcp-publisher` steps, mcp.so / glama.ai / pulsemcp / mcpservers.org blurbs, LinkedIn post, prioritized submission checklist |
| [video/switchboard-launch-video.md](video/switchboard-launch-video.md) | Short-form video | 9:16 ContentOps render staged for approval, plus grounded storyboard, VO, SRT cues, thumbnail, and platform captions |
| [launch-readiness.md](launch-readiness.md) | Release gate | Verified checks, caveats, and approval-gated launch sequence |

## Suggested launch order (highest leverage first)

1. **Repo hygiene first (trivial):** add GitHub topics `mcp`, `model-context-protocol`, `mcp-server`, `aggregator`, `gateway`, `self-hosted`, `governance` to the repo's About → passive discovery.
2. **awesome-mcp-servers PR** (`punkpeye/awesome-mcp-servers`, Aggregators section) — biggest stars-per-minute. Read its CONTRIBUTING first.
3. **Show HN** — be present in comments, invite criticism, label it alpha.
4. **Official MCP registry** — publish `server.json` via `mcp-publisher` (canonical listing other directories crawl). Fill the real published npm version — do not hardcode.
5. **r/LocalLLaMA + r/selfhosted** — technical, no marketing tone.
6. **X thread + LinkedIn post** — same day as Show HN.
7. **Product Hunt** — broader, less-technical wave; prepare gallery.
8. **Directory blurbs** (mcp.so, glama.ai, pulsemcp, mcpservers.org) — paste-ready in registry-submissions.md.
9. **Video** — review the queued ContentOps render, approve it if acceptable, then distribute through the gated publisher.

## Honesty guardrails (apply to every post)

- It's a **working alpha**, just launched. Never "production-ready", "battle-tested", or "enterprise-grade".
- Zero stars, zero known users, no benchmarks against named competitors — never invent metrics, downloads, testimonials, or funding.
- Composio/Pipedream are positioned as *good SaaS that custodies tokens + meters calls*, not "bad" — MCP Switchboard is the self-hosted, governed alternative.
- Every feature mentioned is in the README; don't add features that aren't.

> **Posting is outward-facing** — these go out under your identity to your accounts. Nothing here is auto-posted;
> they're prepared for you (or an operator-approved ContentOps browser post) to publish.

