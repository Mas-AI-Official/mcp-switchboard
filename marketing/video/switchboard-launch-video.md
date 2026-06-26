# MCP Switchboard — Launch Video Package (ready to produce)

**Project:** MCP Switchboard — a local-first, governed MCP aggregator
**Repo (the "address"):** https://github.com/Mas-AI-Official/mcp-switchboard
**Install:** `npm install -g mcp-switchboard` → `switchboard init && switchboard serve`
**License:** Apache-2.0 · **By:** MAS-AI Technologies · **Status:** working alpha

> Everything below is grounded in the README + verified facts. No fabricated metrics, no
> "production-ready" claims. This is a **working alpha** that just launched with zero stars —
> the video sells the *idea and architecture*, not invented traction.

---

## 1. Format & intent

| Field | Value |
|---|---|
| Aspect | 9:16 vertical (1080×1920) — primary; a 16:9 cut is optional for YouTube/LinkedIn |
| Length | ~50 seconds (8 scenes) |
| Platforms | X, LinkedIn, YouTube Shorts, TikTok, Instagram Reels, Threads, Bluesky |
| Tone | Calm, technical, confident. Dev-to-dev. No hype-bro energy. |
| Goal | One idea sticks: *one local, governed endpoint that gives **both** Claude and ChatGPT the same tools — keys never leave your machine.* CTA = star the repo / try it. |
| Brand palette | Dark slate background `#0F1419`, gold accent `#D4A843`, teal accent `#2DD4BF` (matches the MAS-AI / Daena design language for cross-brand consistency) |

---

## 2. The one-line hook (thumbnail + first 2 seconds)

> **"Claude and ChatGPT. Same tools. One endpoint on *your* machine."**

Alt hooks (A/B):
- "Your AI tools are wired N×M. Here's the N×1 fix."
- "Stop handing your API keys to a SaaS router."

---

## 3. Shot-by-shot storyboard

Each scene: on-screen visual + on-screen text (burned-in caption) + voiceover (VO).
**TTS note:** if any VO is synthesized, spell the maker as **"Mass A.I Technologies"** in the VO text
(edge-tts multilingual voices mis-pronounce "MAS-AI" as Spanish *más*). Keep "MCP Switchboard" as-is.

### Scene 1 — Cold open / the problem (0:00–0:06)
- **Visual:** A messy tangle of lines — 4 client icons (Claude, ChatGPT, Cursor, "your agent") each drawing separate lines to 6 app icons (GitHub, Slack, Gmail, Notion, Stripe, Linear). The mess pulses red.
- **On-screen text:** `Every client wires every app. Again. And again.`
- **VO:** "Every AI client you use re-wires every tool, separately. It's N times M, and it never ends."

### Scene 2 — The second problem: custody (0:06–0:12)
- **Visual:** An API key icon flies from your laptop up into a cloud labeled "Hosted router" and gets a little padlock stamped by *them*, not you.
- **On-screen text:** `And hosted routers hold your keys.`
- **VO:** "And the hosted routers that promise to fix it? They custody your keys and meter your calls."

### Scene 3 — Reveal MCP Switchboard (0:12–0:19)
- **Visual:** The tangle collapses into a clean hub. One box in the center labeled **MCP Switchboard** glows gold. All clients connect to it with ONE line each; it connects out to all apps.
- **On-screen text:** `MCP Switchboard — one local, governed endpoint.`
- **VO:** "MCP Switchboard collapses it to N times one. One local process. One governed endpoint."

### Scene 4 — Both Claude AND ChatGPT (0:19–0:26)
- **Visual:** Split screen — Claude on the left, ChatGPT on the right — both pointing arrows at the same MCP Switchboard hub, which fans out to the same row of app icons.
- **On-screen text:** `Claude + ChatGPT → the same tools.`
- **VO:** "Local clients connect directly. Claude on the web and ChatGPT custom connectors reach it through a built-in OAuth tunnel. Same tools, both sides."

### Scene 5 — Keys stay home (0:26–0:33)
- **Visual:** A laptop with a glowing vault inside it. Keys go INTO the local vault (AES-256-GCM label). A dotted line to any cloud is crossed out.
- **On-screen text:** `Keys live in a local AES-256-GCM vault. Zero custody.`
- **VO:** "Your keys stay in an encrypted vault on your machine. Nothing parked on someone else's server."

### Scene 6 — Governance (0:33–0:40)
- **Visual:** A control panel: per-tool toggles flipping on/off; three scope chips "read / write / full"; an "approval required" gate that blocks a write; an append-only audit log scrolling.
- **On-screen text:** `Per-tool toggles · read/write/full · approval gates · audit log.`
- **VO:** "Toggle any tool. Scope it read, write, or full. Gate the risky ones behind approval — fail closed. Every call is logged."

### Scene 7 — The catalog + offline (0:40–0:46)
- **Visual:** The embedded dashboard at `127.0.0.1:8088` — a searchable grid of toolkits ("4,700+"), one flips on; then a small "offline" badge lights up next to a local-LLM chip.
- **On-screen text:** `Browse 4,700+ toolkits. Runs fully offline on a local LLM.`
- **VO:** "Browse over four thousand seven hundred toolkits in the dashboard, flip one on, and wire your client in one command. It even runs fully offline against a local model."

### Scene 8 — CTA / the address (0:46–0:50)
- **Visual:** Clean end card on dark slate. Gold MCP Switchboard wordmark. The install command in monospace. The repo URL. A small "Apache-2.0 · working alpha" line.
- **On-screen text:**
  ```
  npm install -g mcp-switchboard
  github.com/Mas-AI-Official/mcp-switchboard
  Free · Apache-2.0 · self-hosted
  ⭐ Star it if this should exist
  ```
- **VO:** "Free, open source, self-hosted. Install it in one line. Link's on screen — star it if you think this should exist."

---

## 4. Full voiceover script (clean read, ~120 words, TTS-safe)

> Every AI client you use re-wires every tool, separately. It's N times M, and it never ends.
> And the hosted routers that promise to fix it? They custody your keys and meter your calls.
> MCP Switchboard collapses it to N times one. One local process. One governed endpoint.
> Local clients connect directly; Claude on the web and ChatGPT connectors reach it through a built-in OAuth tunnel. Same tools, both sides.
> Your keys stay in an encrypted vault on your machine. Nothing parked on someone else's server.
> Toggle any tool. Scope it read, write, or full. Gate the risky ones behind approval. Every call is logged.
> Browse over four thousand seven hundred toolkits, flip one on, wire your client in one command. It even runs fully offline.
> Free, open source, self-hosted. Link's on screen — star it if you think this should exist.

---

## 5. Burned-in subtitle file (SRT-ready cue list)

```
1  00:00:00,000 → 00:00:06,000  Every client wires every app. Again. And again.
2  00:00:06,000 → 00:00:12,000  And hosted routers hold your keys.
3  00:00:12,000 → 00:00:19,000  MCP Switchboard: one local, governed endpoint.
4  00:00:19,000 → 00:00:26,000  Claude + ChatGPT → the same tools.
5  00:00:26,000 → 00:00:33,000  Keys live in a local AES-256-GCM vault. Zero custody.
6  00:00:33,000 → 00:00:40,000  Per-tool toggles · read/write/full · approval gates · audit log.
7  00:00:40,000 → 00:00:46,000  Browse 4,700+ toolkits. Runs fully offline on a local LLM.
8  00:00:46,000 → 00:00:50,000  npm i -g mcp-switchboard · github.com/Mas-AI-Official/mcp-switchboard
```

---

## 6. Cover / thumbnail concept

- Dark slate. A single gold hub in the center with two labeled arrows feeding in: **Claude** and **ChatGPT**.
- Big text: **"One endpoint. Both AIs. Your keys stay home."**
- Bottom strip: `github.com/Mas-AI-Official/mcp-switchboard`

---

## 7. Distribution captions (per platform) — paste-ready, with the "address"

**X / Threads / Bluesky:**
> One local endpoint that gives **both Claude and ChatGPT** the same tools — and your API keys never leave your machine.
> Per-tool toggles, read/write/full scopes, approval gates, audit log. Free + open source (Apache-2.0). Working alpha.
> `npm i -g mcp-switchboard`
> → github.com/Mas-AI-Official/mcp-switchboard

**LinkedIn / YouTube Shorts description:**
> MCP Switchboard is a local-first, governed MCP aggregator. Instead of wiring every AI client to every tool (N×M), you run one local process that exposes one governed endpoint to all of them (N×1) — Claude, ChatGPT, Cursor, Claude Code, your own agents.
> Keys stay in a local AES-256-GCM vault (zero custody). Every tool has on/off toggles, read/write/full scopes, approval gates that fail closed, and an append-only audit log. Browse 4,700+ toolkits in the built-in dashboard; it even runs fully offline against a local LLM.
> Free, self-hosted, Apache-2.0. It's an early working alpha and feedback is very welcome.
> Install: npm install -g mcp-switchboard
> Repo: https://github.com/Mas-AI-Official/mcp-switchboard

**TikTok / Reels:**
> your AI tools are wired N×M. here's the N×1 fix 👇 one local endpoint for Claude AND ChatGPT, keys never leave your machine. free + open source. link in bio → github.com/Mas-AI-Official/mcp-switchboard #mcp #ai #opensource #selfhosted #claude #chatgpt

Hashtags (reuse): `#mcp #modelcontextprotocol #ai #opensource #selfhosted #claude #chatgpt #developertools #privacy`

---

## 8. How to actually render + post this (gated steps)

**Why not auto-rendered through ContentOps:** ContentOps' pipeline only auto-writes *clickbait scripts from scraped news items* and has no entry point to inject a bespoke, accurate product script — so it can't faithfully render this. This package is the accurate source of truth for whatever renderer you use.

Options to produce `final.mp4`:
1. **Manual/CapCut/Canva:** drop the 8 scenes + SRT + VO; fastest path to an honest cut.
2. **Motion tool (Figma/Canva MCP):** generate the 8 frames from the storyboard, animate the hub-collapse in Scene 3.
3. **AI render:** feed §3 storyboard + §4 VO to your video skill of choice.

**Then post (OUTWARD — needs your go + your logged-in Chrome):**
```
# after final.mp4 exists, queue the browser post for operator approval:
contentops_queue_browser_post(
  script_id=<id>,
  platforms=["x","linkedin","youtube_shorts","threads","bluesky","tiktok","instagram"],
  video_path="D:/Ideas/MCP Switchboard/marketing/video/final.mp4"
)
```
Posting uploads under your identity to your accounts — I will not auto-blast; it's queued for your approval.
