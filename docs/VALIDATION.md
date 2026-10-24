# Validation

How this project is verified. The verifiers are scripts (oracles) that compute their own verdict and exit non-zero on
failure, with no model in the loop. Related: [RUNBOOK.md](RUNBOOK.md), [THREAT_MODEL.md](THREAT_MODEL.md),
[MCP_SWITCHBOARD_BASELINE.md](MCP_SWITCHBOARD_BASELINE.md). Labels: Observed (read in code or recorded from a run),
Per doc, Inferred, Unknown.

## 1. Commands

| Command | What it does |
|---|---|
| `npm run build` | `tsc` then `scripts/copy-connector-assets.mjs`. Every oracle except `verify:registry` imports the compiled `dist/`, so build first. |
| `node scripts/run-oracles.mjs` | Runs every `verify:*` oracle in the `verify` chain of `package.json`, one by one, and prints one table (script, exit code, checks passed over total, seconds). It does not stop at the first failure. Options: `--only name1,name2`, `--json <file>`. Exit 0 only when every selected oracle exits 0. |
| `npm run verify` | build, `npm audit --audit-level=low`, then the chain in order; stops at the first failure. `prepublishOnly` runs it. |
| `npm run smoke:codex` | Not part of the chain. Reads the operator's real `~/.codex/config.toml` and asserts it holds `[mcp_servers.switchboard]` with the URL form (`http://127.0.0.1:8088/mcp`), so install Codex with `--mode http` first; binds port 8088, so it must be free. Then starts a gateway, calls tools from an `app2mcp` and an `http-tool` server over Streamable HTTP and checks both were audited as allowed. |
| `node scripts/live-sync-check.mjs` | Measures the connector importers against real public vendor specs. Needs the network. Not part of the chain. |

`run-oracles.mjs` redirects, per oracle, `HOME`, `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, `TEMP`, `TMP` and `SWITCHBOARD_HOME`
to a throwaway directory and removes variables ending in `_API_KEY`, `_API_SECRET`, `TOKEN`, `SECRET`, `PASSWORD` or
`CREDENTIALS`, plus `SWITCHBOARD_AUTO_APPROVE`, `SWITCHBOARD_PROFILE`, `SWITCHBOARD_TOKEN` and `SWITCHBOARD_INSECURE_APPROVAL`.
This is environment redirection, not an OS sandbox: it does not reset `CODEX_HOME`, `DSH_HOME`, `PATH` or similar (individual
oracles handle some), and `verify:oscrypt` calls the real Windows PowerShell DPAPI under the real user. Each oracle has a 300
second timeout. The check count is parsed from the oracle's own `N/N checks passed` line (`scripts/run-oracles.mjs`).

## 2. Verdict vocabulary

HELD, BREACHED and INCONCLUSIVE are a convention for reading results, not strings the scripts print. Oracles print PASS, FAIL
and sometimes SKIP lines and exit 0 or 1; `run-oracles.mjs` decides on the exit code alone.

- HELD: the checks ran and passed.
- BREACHED: a check failed (exit 1). Only this fails the gate.
- INCONCLUSIVE: a decisive fact was missing. Oracles report it as a SKIP line (no 127.0.0.2, no `.git` work tree, no Windows,
  a missing tool) and still exit 0, and `run-oracles.mjs` does not surface SKIPs. Read the SKIP lines to find INCONCLUSIVE results.

An oracle that proves a write landed does not prove the design choice was right.

## 3. Measured result

History: at commit `8e4bf44` an independent run reported

```text
oracles: 45/45 exit 0; checks: 4330/4330
```

Observed by that run; not re-run for this document. That total included checks that run only when optional local inputs exist
(the R1 checklist folder named by `SWITCHBOARD_R1_CHECKLISTS` for `verify:connectors-exec`, a `.git` work tree, 127.0.0.2,
Windows), so a clean checkout gives a lower check total; the exit-0 oracle count is the portable figure.

Current:

```text
oracles: 46/46 exit 0; checks: 4373/4373 at commit cdaa7a9
```

The chain now has 46 oracles (`verify:dualera` was added). Re-run the command and quote the new line, not an old one.

## 4. The oracles

The 46 entries are the `verify:*` scripts in the `verify` chain (`package.json`); purposes come from each script's header.

| Oracle | Purpose |
|---|---|
| `verify:oauth` | Built-in OAuth 2.1 plus PKCE authorization server, full flow on the real listener. |
| `verify:webhook` | Outbound webhook delivery through the real router decision path. |
| `verify:triggers` | Poll-first triggers against a mutating in-process MCP server. |
| `verify:modifiers` | Tool-shaping transforms (schema modifiers, `inject_args`, redaction). |
| `verify:httptool` | The `http-tool` source. |
| `verify:auth` | `auth_scheme` translation to headers and environment variables. |
| `verify:council` | Council relay with the local OpenAI-compatible provider. |
| `verify:catalog` | Toolkit catalog query layer. |
| `verify:registry` | Launch and registry metadata, no network and no build. |
| `verify:search` | BM25F tool ranker behind `find_tools`. |
| `verify:install` | Original `switchboard install` planning in `src/clients.ts`. |
| `verify:local-llm` | `switchboard local-llm` detection and wiring. |
| `verify:dashboard` | Dashboard JSON-API logic and trigger templates. |
| `verify:profiles` | Named profiles that hide servers or tools and lower scope. |
| `verify:limits` | Rate limits and spend budgets (governor). |
| `verify:breaker` | Per-server circuit breaker. |
| `verify:config` | Example config and the config loader. |
| `verify:audit` | Audit log and secret-safe I/O capture. |
| `verify:resources-prompts` | `resources/*` and `prompts/*` passthrough through the router. |
| `verify:health` | Health and observability surface. |
| `verify:retry` | Mount-retry backoff. |
| `verify:doctor` | Pre-flight `doctor` diagnosis. |
| `verify:vault` | Local credential vault. |
| `verify:router` | The governed call path every tool invocation takes. |
| `verify:openapi` | The `app2mcp` source from OpenAPI 3.x and Swagger 2.0. |
| `verify:expose` | `switchboard expose` tunnel command: logic and wiring scan. |
| `verify:http-security` | HTTP hardening (design 3.2) on the real listeners. |
| `verify:policy-hardening` | Classifier, child environment, kill switch, resources and prompts through policy (3.5, 3.6, 3.8, 3.10). |
| `verify:storage` | Durable local storage and atomic writes (3.9). |
| `verify:audit-chain` | Tamper-evident audit hash chain (3.7). |
| `verify:netguard` | Outbound SSRF guard and its use by http-tool, app2mcp, webhooks, OAuth and connector token calls, council, catalog, local-llm probe and remote MCP. The stdio bridge's request to the operator's own gateway is outside the guard. |
| `verify:dos-hardening` | Three regular-expression denial-of-service findings, pre-auth and hostile upstream. |
| `verify:approval-gate` | The older interactive approval gate, kept off the call path. |
| `verify:bridge` | Stdio bridge and the client key store (3.12). |
| `verify:oscrypt` | OS user-scope wrap (DPAPI) used by the key store and vault key. |
| `verify:principals` | Principals and clients (3.1). |
| `verify:approvals` | Out-of-band approvals and risk (3.3, 3.4). |
| `verify:hardening-2` | Eleven wave-2 review findings, each replayed (3.14). |
| `verify:hardening-3` | Wave-3 identity and approvals findings, each replayed (3.15). |
| `verify:installers` | `install` and `uninstall` for all eight clients (3.13). |
| `verify:connectors-core` | Connector core: provider data, auth configs, accounts, refresh, connect flows, probe. |
| `verify:connectors-exec` | Connector execution: toolkits, importers, sync, recipes, pipeline, files, media staging. |
| `verify:connectors-seed` | Seeded provider breadth and the Connectors admin surface. |
| `verify:file-refs` | Agent-supplied upload references (UNC and `file://host` refusal before any filesystem call). |
| `verify:integration` | Connector layer on a real gateway: principals, approvals, risk, owner session, `link` (3.16). |
| `verify:dualera` | Dual-era serving: MCP 2026-07-28 and the handshake era on one HTTP endpoint (43 checks per the maintainer's report). |

## 5. What this does not prove

- Passing oracles do not show isolation from another process of the same OS user ([THREAT_MODEL.md](THREAT_MODEL.md) section 1,
  design 3.15); `verify:hardening-3` and `verify:principals` replay specific attacks, not a containment guarantee. The audit
  chain is tamper evident, not tamper proof.
- Oracles run against local mocks and loopback fixtures. No provider account was touched; a working connector action is
  recorded only as `live_verified` ([CONNECTOR_CONTRACT.md](CONNECTOR_CONTRACT.md) section 8).
- DPAPI is covered by `verify:oscrypt` on Windows. The real Windows Hello prompt (`src/presence.ts`) is exercised by no oracle:
  the presence tests inject a provider. Unknown until checked by hand on a Windows machine with Hello enrolled.
- A pass shows the checked behaviour held on the machine that ran it; platform branches that did not run are SKIPs (section 2).
- The oracles do not replace an independent adversarial review. The design doc records which review findings each replays (3.14, 3.15).
