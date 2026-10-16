# Draft: Agent Vault GitHub issue (send at Launch 1)

**Title:** Proposal: HTTP method and GraphQL operation matching for service rules

Agent Vault matches services by host and an optional path glob. Many cloud APIs put every operation behind one endpoint: Railway's `volumeDelete` (deletes a volume and its data) is a `POST /graphql/v2`, the same request shape as a harmless query. Host and path rules cannot tell them apart, so there is no way to let an agent read from Railway while blocking deletes.

Proposal:

1. Add an optional `methods` list to service endpoint rules.
2. Add optional GraphQL matching: `operation_type` (query, mutation) and root `fields`, evaluated on a parsed body (aliases resolved, batches expanded, fail closed on parse errors or oversized bodies).

With those two, Agent Vault could import the Opfence catalog (Apache-2.0, tested rules for Railway, Vercel, Supabase MCP, GitHub and AWS) directly. I'm happy to send a PR for either part if you're open to it.
