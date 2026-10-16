# Opfence

**The open list of things your AI agent must never do without asking, and the tool that enforces it.**

Coding agents run with real cloud credentials. In April 2026 one deleted a startup's production database and its backups with a single API call. Opfence reads each request an agent makes (REST, GraphQL, AWS, MCP tool calls), looks the operation up in a tested catalog, and decides whether it runs, needs your approval, or is blocked.

> **Status: early development.** Nothing here is ready to protect real accounts yet. See [docs/BUILD_PLAN.md](docs/BUILD_PLAN.md) for what is built and what is next.

## What it is

- **Catalog:** versioned YAML rules per provider (Railway, Vercel, Supabase, GitHub, AWS and more) and per MCP server. Each operation gets a risk class: `read`, `write`, `delete`, `irreversible`, `money`, `credential` or `access`. Every verified rule has a recorded request that proves it matches.
- **Compiler:** `opfence export` turns the catalog into policy for NVIDIA OpenShell, Claude Code (permission rules and a PreToolUse hook) and MCP annotation overlays.
- **Runner:** `opfence run -- claude` starts a local proxy that holds your keys, enforces the catalog and asks before anything destructive. The approval card is written from the decoded request, never by the agent.

## Commands

| Command | Status |
| --- | --- |
| `opfence version` | available |
| `opfence catalog validate / list / providers`, `opfence explain`, `opfence test`, `opfence policy check` | available |
| `opfence export --target openshell / claude-code / mcp-annotations`, `opfence hook claude-code` | available |
| `opfence proxy` (enforcing HTTP and SOCKS5 proxy; approvals not yet), `opfence log [--verify]` | available (preview) |
| `opfence run -- <agent>`, `opfence init`, `opfence trust`, `opfence approve` | planned (stages 7–9) |

## Catalog

445 tested rules for Railway, Vercel, the Supabase MCP server, GitHub and AWS, each checked against the provider's own schema and replayed from a recorded request by `opfence test`. Browse them with `opfence catalog list`, or see why a request gets its decision with `opfence explain request.http`.

## Use with Claude Code

```sh
opfence export --target claude-code -o opfence-settings.json
```

Merge the result into `.claude/settings.json`. It installs a PreToolUse hook that decides every MCP tool call from the catalog, with its arguments (a `SELECT` through Supabase's `execute_sql` is allowed, a `DROP TABLE` needs confirmation), and adds ask rules for tools that are risky whatever their arguments. Map your production and development project ids in `opfence.yaml` so the hook knows which is which; until then everything counts as production.

For NVIDIA OpenShell, `opfence export --target openshell --environment production` writes network policies to merge into your sandbox policy.

## Build from source

```sh
go install github.com/rakeshnitb23/opfence/cmd/opfence@latest
# or, from a checkout
make build && ./bin/opfence version
```

Requires Go 1.26 or newer (the oldest Go release still getting security fixes).

## Documentation

- [docs/PLAN.md](docs/PLAN.md): the problem, the market, the threat model and the roadmap
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): how it works
- [docs/BUILD_PLAN.md](docs/BUILD_PLAN.md): build stages and progress
- [CONTRIBUTING.md](CONTRIBUTING.md): adding a catalog rule
- [SECURITY.md](SECURITY.md): reporting vulnerabilities

## Licence

Apache License 2.0, for both code and catalog, so any engine can embed the rules.
