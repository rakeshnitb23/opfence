# Opfence

**The open list of things your AI agent must never do without asking, and the tool that enforces it.**

Coding agents run with real cloud credentials. In April 2026 one deleted a startup's production database and its backups with a single API call. Opfence reads each request an agent makes (REST, GraphQL, AWS, MCP tool calls), looks the operation up in a tested catalog, and decides whether it runs, needs your approval, or is blocked.

> **Status: early development.** Nothing here is ready to protect real accounts yet. See [docs/BUILD_PLAN.md](docs/BUILD_PLAN.md) for what is built and what is next.

## What it is

- **Catalog:** versioned YAML rules per provider (Railway, Vercel, GitHub, AWS, Cloudflare, Fly.io, Render, Netlify, Neon, PlanetScale, MongoDB Atlas, Turso and more) and per MCP server. Each operation gets a risk class: `read`, `write`, `delete`, `irreversible`, `money`, `credential` or `access`. Every verified rule has a recorded request that proves it matches.
- **Compiler:** `opfence export` turns the catalog into policy for NVIDIA OpenShell, Claude Code (permission rules and a PreToolUse hook) and MCP annotation overlays.
- **Runner:** `opfence run -- claude` starts a local proxy that holds your keys, enforces the catalog and asks before anything destructive. The approval card is written from the decoded request, never by the agent.

## Commands

| Command | Status |
| --- | --- |
| `opfence version` | available |
| `opfence catalog validate / list / providers`, `opfence explain`, `opfence test`, `opfence policy check` | available |
| `opfence export --target openshell / claude-code / mcp-annotations`, `opfence hook claude-code` | available |
| `opfence proxy` (enforcing HTTP and SOCKS5 proxy), `opfence log [--verify]` | available (preview) |
| `opfence init [--undo]`, `opfence secrets list / rm` (keys into your keychain, placeholders in files) | available (preview) |
| `opfence approve` (answer held requests from another terminal; desktop dialogs) | available (preview) |
| `opfence phone setup / test / off` (approve from your phone with the ntfy app) | available (preview) |
| `opfence run -- claude` (Claude Code in its sandbox behind Opfence), `opfence run --srt -- codex / cursor-agent / gemini`, `opfence run --srt / --weak -- <command>`, `opfence trust [--uninstall]`, `opfence doctor` | available (preview) |
| `opfence hook codex` (Codex's PreToolUse and PermissionRequest hook, installed by `opfence run`) | available (preview) |

## Catalog

8,026 rules for Railway, Vercel, Supabase (its Management API, and each project's rows, storage, auth and edge functions), Google Cloud (Compute Engine, GKE, Cloud Run, Cloud Functions, App Engine, BigQuery and its SQL, Spanner, Storage, Cloud SQL, Secret Manager, IAM and Resource Manager), GitHub (its APIs and git over HTTPS), AWS, Cloudflare, Fly.io, Render, Netlify, Heroku (its Platform and Data APIs), Stripe, DigitalOcean, Neon, PlanetScale, MongoDB Atlas (and its App Services Admin API) and Turso, the SQL that Neon's and PlanetScale's serverless drivers send over HTTPS, and 29 MCP servers: Supabase, GitHub, Vercel, Railway, Cloudflare, Fly.io, Render, Netlify, Heroku, Stripe, DigitalOcean, Neon, PlanetScale, MongoDB, Turso, Firebase, Upstash, Sentry, Notion, Linear, Terraform and eight AWS Labs servers, each checked against the provider's own schema and replayed from a recorded request by `opfence test`. A nightly job (`opfence catalog check-sources`) compares the rules with the schemas providers publish, so a renamed or new endpoint shows up the night it ships. Browse them with `opfence catalog list`, or see why a request gets its decision with `opfence explain request.http`.

## Use with Claude Code

```sh
opfence export --target claude-code -o opfence-settings.json
```

Merge the result into `.claude/settings.json`. It installs a PreToolUse hook that decides every MCP tool call from the catalog, with its arguments (a `SELECT` through Supabase's `execute_sql` or Cloudflare's `d1_database_query` is allowed, a `DROP TABLE` needs confirmation; SQL is read as Postgres, MySQL or SQLite, whichever the server speaks, Redis commands through Upstash's MCP server one by one, and AWS CLI commands through the AWS API MCP server by the AWS rules they reach), and adds ask rules for tools that are risky whatever their arguments. Map your development and staging ids in your user config (`~/.config/opfence/config.yaml`) so the hook knows which is which; until then everything counts as production. A repository's `opfence.yaml` can only make decisions stricter, so it can mark ids as production but not as development.

## Use with Codex, Cursor or Gemini CLI

```sh
opfence run --srt -- codex
opfence run --srt -- cursor-agent
opfence run --srt -- gemini
```

Each runs inside Anthropic's sandbox runtime (`npm install -g @anthropic-ai/sandbox-runtime`) behind Opfence, with your keys as placeholders and its own sandbox turned off, since srt is the sandbox. Its model backend is tunnelled; everything else it or its tools reach goes through the catalog. For Codex, Opfence also installs its hook for this session only, so each local MCP tool call is decided with its arguments like in Claude Code, and passes the proxy settings to Codex's MCP servers. Nothing in `~/.codex` changes.

For NVIDIA OpenShell, `opfence export --target openshell --environment production` writes network policies to merge into your sandbox policy.

## Quick start

[docs/QUICKSTART.md](docs/QUICKSTART.md) goes from install to the first blocked call: see a decision with `opfence explain`, protect Claude Code's MCP tool calls, run an agent behind the proxy, and map your environments.

## Install

Release builds for macOS, Linux and Windows are attached to each [GitHub release](https://github.com/rakeshnitb23/opfence/releases), with a `checksums.txt` and signed build provenance (`gh attestation verify opfence_*.tar.gz --repo rakeshnitb23/opfence`).

## Build from source

```sh
go install github.com/rakeshnitb23/opfence/cmd/opfence@latest
# or, from a checkout
make build && ./bin/opfence version
```

Requires Go 1.26.9 or newer (Go 1.26 is the oldest release still getting security fixes; Vitess, which reads MySQL, needs .9).

## Documentation

The guides and a searchable catalog are also published at [rakeshnitb23.github.io/opfence](https://rakeshnitb23.github.io/opfence/) (built by `make site`).

- [docs/QUICKSTART.md](docs/QUICKSTART.md): from install to the first blocked call
- [docs/PLAN.md](docs/PLAN.md): the problem, the market, the threat model and the roadmap
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): how it works
- [docs/LIMITS.md](docs/LIMITS.md): what Opfence does not protect against
- [docs/BUILD_PLAN.md](docs/BUILD_PLAN.md): build stages and progress
- [CONTRIBUTING.md](CONTRIBUTING.md): adding a catalog rule
- [SECURITY.md](SECURITY.md): reporting vulnerabilities

## Licence

Apache License 2.0, for both code and catalog, so any engine can embed the rules.
