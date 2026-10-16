# Draft: OpenShell GitHub Discussion

**Title:** Would a tested catalog of operation-level rules be useful as importable provider profiles?

Hi OpenShell maintainers,

I'm building Opfence, an Apache-2.0 catalog that classifies cloud API and MCP operations by risk (`read`, `write`, `delete`, `irreversible`, `money`, `credential`, `access`), with a recorded request per rule that proves it matches. It starts with Railway, Vercel, Supabase MCP, GitHub and AWS.

OpenShell already supports exactly the matching this needs (GraphQL `operation_type` and `fields`, MCP `tool`, method and path), and the GitHub sandbox tutorial hand-writes `deny_rules` for `deleteRepository` and `deleteRef`. The provider profiles in `providers/` are host-level today. I'd like to generate operation-level policy from the catalog so users don't hand-write those rules for each provider.

Two questions:

1. Would you want this as importable provider profiles (or as a separate policy pack), and is there a format you'd prefer it in?
2. Are you planning operation-level content for provider profiles yourselves? If so, I'd rather contribute to that than duplicate it.

Because OpenShell is allow-list first, the catalog classifies every operation, not only dangerous ones, so it could also feed the RFC 0002 proposal flow (auto-approve safe writes, flag destructive ones).

Happy to share the exporter output for a provider of your choice. Thanks!
