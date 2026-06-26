# MCP Switchboard — Registry & Directory Submission Pack

Everything below is ready to paste. Repo URL is fixed: `https://github.com/Mas-AI-Official/mcp-switchboard`. npm package is `mcp-switchboard`; the CLI command after install is `switchboard`. License Apache-2.0. Status: **working alpha** — keep that label in every blurb; do not imply more.

> Honesty note for whoever submits these: MCP Switchboard just launched (zero stars, zero known production users). Do not add star counts, download numbers, testimonials, or "first/only" claims. Every feature mentioned here is in the README; do not add features that aren't.

---

## awesome-mcp-servers entry

Most fitting section: **Aggregators** (some forks call the same idea "Gateways / Proxies"). MCP Switchboard mounts many existing MCP servers behind one governed endpoint, which is exactly what that section is for — not a single-integration server.

Exact one-line list entry (the repo's format is `- [name](url) - description.`):

```markdown
- [MCP Switchboard](https://github.com/Mas-AI-Official/mcp-switchboard) - Local-first, governed MCP aggregator: re-expose all your MCP servers behind one endpoint with a local AES-256-GCM key vault, per-tool read/write/full policy, fail-closed approval gates, and an append-only audit log — shared by both Claude and ChatGPT.
```

If a category emoji prefix is required by the specific fork (several awesome-mcp-servers repos prepend language/scope icons), match the neighbouring rows in that section rather than inventing one.

PR steps:
1. Pick the canonical list. The most-starred is `punkpeye/awesome-mcp-servers`; there are active forks (`appcypher/awesome-mcp-servers`, `wong2/awesome-mcp-servers`). Submit to the one whose CONTRIBUTING you can satisfy; the high-traffic `punkpeye` list is the priority. Verify the current contribution rules at https://github.com/punkpeye/awesome-mcp-servers (read its CONTRIBUTING before editing).
2. Fork the repo, create a branch (e.g. `add-switchboard`).
3. Find the **Aggregators** section (or **Gateways / Proxies** if that's how the fork names it) and insert the line above in **alphabetical order** within the section.
4. Keep the description to one line; respect the repo's exact dash-and-period format (`- [name](url) - text.`).
5. Open a PR titled `Add MCP Switchboard (MCP aggregator/gateway)`. In the body, note it's an Apache-2.0, local-first MCP aggregator and link the repo. Confirm you followed the list's formatting/linting rules (some lists run a markdown linter in CI — run it locally first if provided).

---

## Official MCP registry (registry.modelcontextprotocol.io)

Goal: publish a `server.json` describing MCP Switchboard as an npm-distributed MCP server so it appears in the official registry (which also feeds the catalog MCP Switchboard itself ingests).

`server.json` metadata fields to fill:

```json
{
  "$schema": "https://static.modelcontextprotocol.io/schemas/2025-07-09/server.schema.json",
  "name": "io.github.Mas-AI-Official/mcp-switchboard",
  "description": "Local-first, governed MCP aggregator: re-expose all your MCP servers behind one endpoint with a local AES-256-GCM vault, per-tool read/write/full policy, fail-closed approval gates, and an append-only audit log — usable by both Claude and ChatGPT.",
  "repository": {
    "url": "https://github.com/Mas-AI-Official/mcp-switchboard",
    "source": "github"
  },
  "version": "<your-published-npm-version>",
  "packages": [
    {
      "registryType": "npm",
      "identifier": "mcp-switchboard",
      "version": "<your-published-npm-version>",
      "transport": { "type": "stdio" }
    }
  ]
}
```

Notes on the fields:
- `name` must be a namespaced reverse-DNS identifier you own. The GitHub namespace (`io.github.<owner>/<server>`) is authenticated via the GitHub login in the publisher CLI, so `io.github.Mas-AI-Official/mcp-switchboard` is the natural choice.
- `identifier` in `packages` is the **npm package name `mcp-switchboard`** (not the `switchboard` CLI alias).
- `version` must match the actual published npm version of `mcp-switchboard` — read it from the package (or `npm view mcp-switchboard version`) and fill both `version` fields with that exact string; bump it on each release. Do not hardcode a guessed version.
- The registry validates that the npm package actually exists and (depending on current rules) that it carries an `mcp-name` marker tying it back to the `name` above — confirm the exact validation requirement when you publish.

Publishing steps with the `mcp-publisher` CLI:
1. Install the publisher CLI (`mcp-publisher`). Confirm the current install method and command name at https://github.com/modelcontextprotocol/registry (the registry repo documents the canonical install + flow).
2. From the repo root: `mcp-publisher init` to scaffold a `server.json`, then edit it to match the fields above.
3. Authenticate: `mcp-publisher login github` (GitHub OAuth — this is what authorizes the `io.github.Mas-AI-Official/*` namespace).
4. Ensure `mcp-switchboard` is already published to npm and, if the registry requires it, that the package metadata includes the `mcp-name` linkage to your `server.json` `name`.
5. Publish: `mcp-publisher publish`.
6. Verify the listing resolves on registry.modelcontextprotocol.io.

> The official registry's schema, namespace rules, and CLI commands change as it matures — **verify the current process and exact field names at https://github.com/modelcontextprotocol/registry before publishing** rather than trusting any single command above.

---

## Directory listings

Ready-to-paste blurbs. Each is title + 1–2 sentence description + repo URL + install. Adjust field labels to match each site's submission form.

### mcp.so

**Title:** MCP Switchboard — local-first governed MCP aggregator

**Description:** Run one local process that re-exposes all your MCP servers behind one governed endpoint, so both Claude and ChatGPT reach the same tools through the same local AES-256-GCM vault, the same read/write/full policy, the same fail-closed approval gates, and the same append-only audit log. Free, self-hosted, Apache-2.0, no per-call meter. Working alpha.

**Repo:** https://github.com/Mas-AI-Official/mcp-switchboard

**Install:**
```bash
npm install -g mcp-switchboard
switchboard init && switchboard serve   # or: npx mcp-switchboard serve   (Node >= 18.18)
```

### glama.ai

**Title:** MCP Switchboard

**Description:** A local-first, governed MCP aggregator/proxy. It collapses N-clients × M-apps wiring into N × 1: mount your MCP servers once behind a single endpoint with bring-your-own keys in a local vault, per-tool governance, approval gates, and an audit log — then wire Claude Desktop / Claude Code / Cursor / VS Code / Codex in one command with `switchboard install <client>`.

**Repo:** https://github.com/Mas-AI-Official/mcp-switchboard

**Install:**
```bash
npm install -g mcp-switchboard
switchboard init && switchboard serve   # zero-install: npx mcp-switchboard serve
```

### pulsemcp.com

**Title:** MCP Switchboard — one governed MCP endpoint for Claude and ChatGPT

**Description:** MCP Switchboard is a self-hosted MCP aggregator that puts a governance layer (per-tool on/off, read/write/full scopes, fail-closed approval gates, append-only audit log) in front of all your MCP servers, with credentials sealed in a local AES-256-GCM vault. Browse 4,700+ toolkits in the embedded dashboard, flip one on, and connect any MCP client. Apache-2.0, working alpha.

**Repo:** https://github.com/Mas-AI-Official/mcp-switchboard

**Install:**
```bash
npm install -g mcp-switchboard
switchboard init && switchboard serve   # dashboard at http://127.0.0.1:8088
```

### mcpservers.org

**Title:** MCP Switchboard

**Description:** Local-first, governed MCP aggregator — one local endpoint that re-exposes every MCP server you run, with a local encrypted vault for your keys, per-tool policy, approval gates, and an audit log. Can also run a cross-provider "council" fully offline against an auto-detected local LLM (no account or API key required). Apache-2.0.

**Repo:** https://github.com/Mas-AI-Official/mcp-switchboard

**Install:**
```bash
npm install -g mcp-switchboard
switchboard init && switchboard serve   # or npx mcp-switchboard serve
```

> Submission process for each directory varies (PR to a GitHub repo, a web form, or auto-crawl from npm/the official registry). Verify the current submission path per site — e.g. for PulseMCP and mcp.so check their "submit" / "add server" link, and for glama.ai confirm whether listing is automatic from the npm package or requires a form.

---

## LinkedIn launch post

> Just open-sourced **MCP Switchboard** — a local-first, governed MCP aggregator.
>
> The problem it solves: if you use both Claude and ChatGPT (plus Cursor, Claude Code, VS Code, your own agents), every client has to be wired to every tool by hand — N clients × M apps — and the easy hosted shortcut parks your OAuth tokens on someone else's server and meters every call.
>
> MCP Switchboard collapses that N×M into N×1. You run **one** local process that re-exposes all your MCP servers behind **one** governed endpoint. Add it once in Claude and once in ChatGPT, and both reach the same tools through:
>
> • a local **AES-256-GCM vault** for your keys — zero token custody, nothing parked on a vendor server
> • per-tool **read / write / full** scopes and **approval gates that fail closed**
> • an **append-only audit log** of every call
> • per-client profiles, rate limits, spend budgets, and a circuit breaker — on your own hardware
>
> A few things I'm happy with:
> • Browse 4,700+ toolkits in an embedded dashboard, flip one on, and `switchboard install <client>` wires Claude Desktop / Claude Code / Cursor / VS Code / Codex in **one command**.
> • It runs **fully offline** — the cross-provider council can run against an auto-detected local LLM with no account and no API key.
> • Pure TypeScript/Node, exactly 5 runtime dependencies, zero native dependencies, and every feature is backed by deterministic verification oracles (~1,150 automated checks).
>
> Positioning honestly: hosted tool routers like Composio and Pipedream are great SaaS, but they custody your tokens and meter your calls. MCP Switchboard is the **self-hosted, governed alternative** — free, Apache-2.0, keys and governance and audit all on your machine.
>
> It's an early **working alpha** — just launched, no production users yet. I'd genuinely value technical criticism.
>
> Repo: https://github.com/Mas-AI-Official/mcp-switchboard
> Install: `npm install -g mcp-switchboard` then `switchboard init && switchboard serve`
>
> #MCP #ModelContextProtocol #OpenSource #LLM #AIagents #SelfHosted

---

## Submission priority checklist

Ordered by star-leverage, highest first.

| Destination | URL | Effort | Star-leverage | Notes |
|---|---|---|---|---|
| awesome-mcp-servers (punkpeye) | https://github.com/punkpeye/awesome-mcp-servers | Low | Very high | One-line PR into **Aggregators**. Highest-traffic discovery list; biggest star driver per minute spent. Read its CONTRIBUTING first; submit to active forks too. |
| Show HN | https://news.ycombinator.com/showhn.html | Low | Very high | Problem-first, humble title (e.g. "Show HN: MCP Switchboard – self-hosted, governed MCP aggregator for Claude and ChatGPT"). Be present in comments, invite criticism, no buzzwords. State it's a working alpha. |
| Official MCP registry | https://github.com/modelcontextprotocol/registry | Medium | High | Publish `server.json` via `mcp-publisher` (npm pkg `mcp-switchboard`). Canonical listing that other directories crawl. Verify current CLI/schema first. |
| r/LocalLLaMA | https://www.reddit.com/r/LocalLLaMA/ | Low | High | Lead with the offline angle: council against an auto-detected local LLM, zero keys, nothing leaves the box. Technical, no marketing tone. |
| r/selfhosted | https://www.reddit.com/r/selfhosted/ | Low | High | Lead with local-first credential custody + self-hosted governance vs metered cloud. Apache-2.0, runs on your hardware. |
| Product Hunt | https://www.producthunt.com/ | Medium | Medium-High | Benefit-led but truthful launch. Good for a broader (less technical) wave. Prepare gallery + the one-liner; label it alpha. |
| pulsemcp.com | https://www.pulsemcp.com/ | Low | Medium | Paste the PulseMCP blurb above. Verify submit path (form vs crawl). Well-trafficked MCP directory. |
| mcp.so | https://mcp.so/ | Low | Medium | Paste the mcp.so blurb above. Confirm submit/add-server flow. |
| glama.ai | https://glama.ai/mcp/servers | Low | Medium | May auto-list from npm/official registry; submit the glama blurb if a form exists. |
| mcpservers.org | https://mcpservers.org/ | Low | Medium | Paste the mcpservers.org blurb. Verify submission method (often a GitHub PR). |
| X (Twitter) | https://x.com/ | Low | Medium | Thread version of the LinkedIn post; lead with N×M→N×1 and "both Claude and ChatGPT." Truthful, benefit-led, link the repo. |
| GitHub topic tags `mcp` / `model-context-protocol` | https://github.com/Mas-AI-Official/mcp-switchboard (repo ▸ About ▸ topics) | Trivial | Medium | Add `mcp`, `model-context-protocol`, plus `mcp-server`, `aggregator`, `gateway`, `self-hosted`, `governance`. Passive discovery via topic browsing; do this first since it's near-zero effort. |
| dev.to / Hashnode cross-post | https://dev.to/ · https://hashnode.com/ | Medium | Low-Medium | Cross-post a deeper write-up (the N×M problem, the governance/vault design, the ~1,150-check oracle approach). Canonical-link back to the repo/README. Long-tail SEO, slower burn. |
