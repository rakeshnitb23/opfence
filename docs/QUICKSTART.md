# Quick start

From install to the first blocked call. Opfence is in early development: try it on test accounts, not on ones that matter.

## 1. Install

Download a release for macOS, Linux or Windows from the [releases page](https://github.com/rakeshnitb23/opfence/releases), or build it with Go 1.26.9 or newer:

```sh
go install github.com/rakeshnitb23/opfence/cmd/opfence@latest
opfence version
```

## 2. See a decision without running anything

`opfence explain` reads a saved HTTP request and shows how Opfence decides it. Save the request that deleted a production database in April 2026, a Railway volume deletion:

```sh
cat > delete-volume.http <<'EOF'
POST /graphql/v2 HTTP/1.1
Host: backboard.railway.com
Content-Type: application/json

{"query":"mutation { volumeDelete(volumeId: \"vol-123\") }"}
EOF
opfence explain delete-volume.http
```

```text
delete-volume.http
  POST backboard.railway.com/graphql/v2
  operation   graphql mutation volumeDelete
  rule        railway.volume.delete (verified)
  class       irreversible (rule class)
  environment production (default; map ids in ~/.config/opfence/config.yaml to change)
  decision    CONFIRM (default for irreversible in production)
  card        Delete Railway volume vol-123 and all data on it
```

*Confirm* means a person has to type the volume's id to let it through. The card is written from the decoded request, never by the agent. Browse every rule in the [catalog](../catalog/), or list them with `opfence catalog list`.

## 3. Protect Claude Code's MCP tool calls

The lightest setup: a hook decides each MCP tool call Claude Code makes, with its arguments.

```sh
opfence export --target claude-code -o opfence-settings.json
```

Merge the result into `.claude/settings.json`. A `SELECT` through Supabase's `execute_sql` is allowed; a `DROP TABLE` needs confirming. The hook only sees tool calls: for everything else an agent does (its own `curl`, the CLIs it runs), use step 4.

## 4. Run an agent behind the proxy

```sh
opfence init           # move API keys from .env and Claude Code's configs into your keychain
opfence trust          # let tools that ignore SSL_CERT_FILE trust Opfence's CA (macOS asks for your password)
opfence run -- claude  # Claude Code in its sandbox, every connection through Opfence
```

`opfence init` leaves placeholders of the same shape where the keys were, so the agent only ever sees placeholders and the proxy swaps the real key in for requests to that key's own API. `opfence init --undo` puts the real values back.

Requests that need approval show a desktop dialog. You can also answer them with `opfence approve` in another terminal, or on your phone after `opfence phone setup`. Check that the sandbox keeps the agent away from your keys with `opfence doctor`.

Other agents run in Anthropic's sandbox runtime (`npm install -g @anthropic-ai/sandbox-runtime`):

```sh
opfence run --srt -- codex
opfence run --srt -- cursor-agent
opfence run --srt -- gemini
```

## 5. Tell Opfence which ids are development

Until you map them, every project counts as production. Put mappings in your user config, `~/.config/opfence/config.yaml`:

```yaml
version: 1
environments:
  development:
    railway: { volumeId: [vol-123], environmentId: [e-dev-456] }
    supabase-mcp: { project_id: [devproj99] }
```

Now the volume deletion above only asks instead of needing confirmation. A repository's `opfence.yaml` can only make decisions stricter, because the agent can edit it: it can mark ids as production, add `ask` rules, or shorten the approval timeout, but not mark anything as development. `opfence policy check` shows how both files combine.

## Next

- [What Opfence does not protect against](LIMITS.md)
- [How it works](ARCHITECTURE.md)
- [Adding a catalog rule](../CONTRIBUTING.md)
