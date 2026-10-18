# Contributing to Opfence

Thanks for helping. The most valuable contribution is a catalog rule: one tested fact about which API operation is dangerous.

## Adding a catalog rule

1. Find or create the provider folder under `catalog/<provider>/`.
2. Add the operation to a rule file (see [docs/ARCHITECTURE.md §4](docs/ARCHITECTURE.md#4-catalog) for the format).
3. Capture a fixture: the raw HTTP request (headers and body) saved as `fixtures/<name>.http`. Replace every real token with a placeholder such as `opf_railway_EXAMPLE`. With mitmproxy, use "Copy as raw request". For an MCP server that runs locally (no host), save the tool call instead as `fixtures/<name>.json`: `{"description": "...", "tool": "<tool name>", "arguments": {...}}`.
4. Link a primary source (the provider's API reference, OpenAPI spec, GraphQL schema or MCP server source) in `sources`.
5. Run `opfence catalog validate` and `opfence test`.

A rule can be `status: verified` only when it has a fixture, a source and a `verified` date; otherwise use `community` or `draft`.

## Code

- Go, formatted with `gofmt -s`. Run `make check` (format, vet, race tests) before opening a PR, and `make lint` for staticcheck.
- New dependencies need a reason in [docs/ARCHITECTURE.md §2](docs/ARCHITECTURE.md#dependencies). Fewer is better in a security tool.
- Decoders must fail closed: when unsure, emit an `unknown` operation, never `read`.
- Every behaviour change comes with a test.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please do not open public issues for vulnerabilities, including rules that under-classify a dangerous operation.

## Licence

By contributing you agree that your contribution is licensed under the Apache License 2.0.
