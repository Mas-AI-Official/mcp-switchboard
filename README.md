<div align="center">

# 🔌 Switchboard

**One governed MCP endpoint for every app your agents touch.**
**Local-first. Bring your own keys. Nothing leaves your machine.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-2dd4bf.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/Model_Context_Protocol-1.29-2dd4bf.svg)](https://modelcontextprotocol.io)
[![Node](https://img.shields.io/badge/node-%E2%89%A518.18-2dd4bf.svg)](https://nodejs.org)
[![Status](https://img.shields.io/badge/status-working_alpha-D4A843.svg)](#project-status)

</div>

---

## The 30-second pitch

You have N agents (Claude Desktop, Claude Code, Cursor, your own agents) and M apps
(GitHub, Notion, Slack, Gmail, an internal API). Wiring that up today is **N×M** pain: every
client configures every server by hand, and the "easy" hosted shortcut means **your OAuth
tokens live on someone else's server**.

Switchboard collapses **N×M into N×1**. You run one local process. A **dashboard** lets you
toggle apps **ON/OFF** and set each to **read / write / full**. Agents connect to **one MCP
endpoint** and see only what you allowed. Your credentials sit in a **local encrypted vault** —
there is no cloud, because there is no "us".

```
   Claude ─┐                          ┌─ github   (write,  delete_repo blocked)
   Cursor ─┼──▶  SWITCHBOARD  ──▶─────┼─ notion   (read)
   agents ─┘   one MCP endpoint       ├─ slack    (OFF)
              + policy + vault        └─ everything (read, approval-gated)
```

## Why it's different

|  | Switchboard | Hosted tool routers |
|---|---|---|
| **Where your tokens live** | A local AES-256 vault on **your** machine | Their cloud |
| **Integrations** | **Mounts existing MCP servers** — no treadmill | Hand-built, must be maintained |
| **Governance** | Per-tool `read/write/full` + approval gates + audit log | Usually all-or-nothing |
| **Context blow-up** | `search` mode → 2 meta-tools no matter how many servers | Dump every tool into context |
| **Cost** | Free, Apache-2.0, self-hosted | Metered SaaS |

The catalog is **not** the moat — hosted players already have bigger ones. The defensible
combination is **local credentials + a governance layer + a usable dashboard**, built as an
**aggregator** that rides the existing MCP ecosystem instead of re-implementing it.

## Quickstart

> Requires Node ≥ 18.18. Not yet on npm — run it from source.

```bash
git clone https://github.com/Masoud-Masoori/switchboard.git
cd switchboard
npm install
npm run build

# scaffold a config + the ~/.switchboard home directory
node dist/cli.js init

# mount everything and print the governed tool list (no credentials needed —
# the bundled @modelcontextprotocol/server-everything is a real test server)
node dist/cli.js list

# run it: stdio for local clients + an HTTP endpoint & dashboard
node dist/cli.js serve
```

Open the dashboard at **http://127.0.0.1:8088**, then point an agent at the MCP endpoint:

```bash
# Claude Code / Claude Desktop, stdio transport:
claude mcp add switchboard -- node /absolute/path/to/switchboard/dist/cli.js serve

# or the Streamable HTTP endpoint, for any HTTP MCP client:
#   http://127.0.0.1:8088/mcp
```

### Storing a secret (BYO keys)

Secrets never appear in your config — the config holds only `${vault:name}` **references**.

```bash
# pipe the value in so it stays out of your shell history
printf '%s' 'ghp_xxx' | node dist/cli.js vault set github_pat
node dist/cli.js vault list      # names only, never values
```

```yaml
# switchboard.config.yaml
servers:
  - id: github
    source: npx
    package: "@modelcontextprotocol/server-github"
    enabled: true
    policy: write
    credentials:
      GITHUB_TOKEN: ${vault:github_pat}   # resolved locally at mount time
    tools:
      delete_repo: { enabled: false }     # hard-block the destructive one
```

## CLI

| Command | What it does |
|---|---|
| `switchboard init` | Scaffold `switchboard.config.yaml` + the `~/.switchboard` home |
| `switchboard serve` | Run the gateway (stdio and/or HTTP, per config) |
| `switchboard dashboard` | Run only the HTTP endpoint + web console |
| `switchboard list` | Mount everything and print the governed tool list, then exit |
| `switchboard doctor` | Check Node, config, transports, and that every secret resolves |
| `switchboard vault set\|list\|rm <name>` | Manage locally-stored secrets |

Global flag: `-c, --config <path>` (default `switchboard.config.yaml`).
Once built and linked (`npm link`), the `switchboard` command replaces `node dist/cli.js`.

## How it works

```
   agent clients ──MCP──▶  GATEWAY  ──▶  ROUTER ──▶ POLICY ENGINE ──▶ REGISTRY ──▶ upstream
   (stdio + HTTP)          one server     namespaced/    read<write<     mounted     MCP servers
                                          flat/search    full + gates    clients     (npx / remote)
                                              │              │              ▲
                                          DASHBOARD       AUDIT LOG       VAULT
                                          (toggle/scope)  (append-only)   (AES-256-GCM, local)
```

Every call is classified (`read`/`write`/`full`), checked against the server's scope ceiling and
any per-tool override, optionally held for human approval, then forwarded — and **every verdict is
written to an append-only audit log**. Full walkthrough in **[docs/BLUEPRINT.md](docs/BLUEPRINT.md)**.

### Tool-exposure modes

Mount 30 servers and naive aggregation dumps ~600 tool schemas into your agent's context — accuracy
collapses, tokens explode. Switchboard offers three modes via `gateway.tool_exposure`:

- **`namespaced`** (default) — tools prefixed `github__create_issue`; only enabled servers exposed.
- **`flat`** — bare tool names (small setups; first server to claim a name wins).
- **`search`** — expose just two meta-tools, **`find_tools(query)`** and **`call_tool(name,args)`**.
  The agent searches; Switchboard returns only the relevant handful. The surface stays flat no
  matter how many servers you mount.

## Project status

**Working alpha.** Real and verified today: the aggregating gateway (stdio + Streamable HTTP), the
policy engine, all three tool-exposure modes, the encrypted vault, the approval gate, the audit log,
the dashboard, and the CLI. The full `find_tools → call_tool` round-trip works end-to-end through
the governed path.

On the roadmap: managed OAuth flows and **app2mcp** (OpenAPI→MCP generation) — see
**[docs/ROADMAP.md](docs/ROADMAP.md)**. `app2mcp` servers fail closed until then.

## Docs

- **[Blueprint](docs/BLUEPRINT.md)** — the as-built architecture, module by module
- [Vision & positioning](docs/VISION.md)
- [Architecture overview](docs/ARCHITECTURE.md)
- [Roadmap](docs/ROADMAP.md)
- [Competitive landscape](docs/COMPETITIVE.md)
- [Example config](switchboard.config.example.yaml) · [search-mode example](examples/switchboard.config.yaml)

## Security

- Credentials live only in `~/.switchboard/vault.json`, **AES-256-GCM** encrypted with a key in
  `~/.switchboard/vault.key`. Nothing is transmitted off the machine; the vault makes no network calls.
- The HTTP endpoint binds to **127.0.0.1** by default — local-first, not exposed to the network.
- Governance **fails closed**: a disabled server, an over-ceiling scope, or an unverifiable approval
  context all result in *deny*, not a silent allow.
- Found a vulnerability? Please report it privately (see [CONTRIBUTING.md](CONTRIBUTING.md)) rather
  than opening a public issue.

## Contributing

Issues and PRs welcome — see **[CONTRIBUTING.md](CONTRIBUTING.md)**. The project is deliberately
small and dependency-light (zero native deps); please keep it that way.

## License

[Apache-2.0](LICENSE) © MAS-AI Technologies.
