# Contributing to Switchboard

Thanks for your interest. Switchboard is a small, deliberately dependency-light
TypeScript project — contributions that keep it that way are the most welcome.

## Ground rules

- **Local-first stays local-first.** No feature may send credentials, tool calls, or
  telemetry off the machine by default. The vault never makes a network call.
- **Fail closed.** Governance defaults to the least privilege. A bug that *over*-exposes
  a tool is more serious than one that under-exposes it.
- **Zero native dependencies.** `npm install` must not require a C/C++ toolchain. The
  encrypted-file vault uses Node's built-in `crypto` for exactly this reason.
- **Aggregate, don't re-implement.** Switchboard mounts existing MCP servers. We do not
  ship hand-written integrations for individual SaaS apps.

## Dev setup

```bash
git clone https://github.com/Masoud-Masoori/switchboard.git
cd switchboard
npm install
npm run build          # tsc -> dist/
node dist/cli.js init  # scaffold a config + ~/.switchboard home
node dist/cli.js list  # mount everything and print the governed tool list
```

`npm run dev` runs `tsc --watch`. The bundled `@modelcontextprotocol/server-everything`
upstream is a real MCP server with no credentials — ideal for testing the full path.

## Project layout

| Path | What it is |
|---|---|
| `src/config.ts` | YAML load + zod validation (the on-disk contract) |
| `src/vault.ts` | AES-256-GCM local credential vault |
| `src/registry.ts` | Mounts upstream MCP servers, holds live clients |
| `src/policy.ts` | Scope inference + the read/write/full governance engine |
| `src/router.ts` | One governed tool surface; namespaced / flat / search modes |
| `src/approval.ts` | Fail-closed human approval gate |
| `src/audit.ts` | Append-only JSON audit log |
| `src/gateway.ts` | The downstream-facing MCP server (stdio + HTTP) |
| `src/dashboard.ts` + `src/console.ts` | HTTP endpoint + embedded web console |
| `src/cli.ts` | The `switchboard` command |

See [docs/BLUEPRINT.md](docs/BLUEPRINT.md) for the full as-built architecture.

## Before you open a PR

1. `npm run build` is clean (no TypeScript errors).
2. `node dist/cli.js doctor` passes against a representative config.
3. No secrets, keys, tokens, or personal paths in the diff. Check `git diff` by hand.
4. Match the existing code style — terse, commented at the "why", no speculative abstraction.

## Reporting security issues

Please **do not** open a public issue for a vulnerability. Email the maintainer
(see the repository profile) with details and a reproduction. Switchboard handles
credentials, so security reports are triaged first.

## License

By contributing you agree your contributions are licensed under the
[Apache License 2.0](LICENSE).
