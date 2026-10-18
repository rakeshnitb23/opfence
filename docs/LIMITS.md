# What Opfence does not protect against

Opfence reads the requests a coding agent makes to cloud APIs, decides each operation from a tested catalog, and keeps real API keys out of the agent's reach. This page lists what that does not cover, so you can decide what else you need. Each item says what happens instead.

## Ways around the proxy

- **Weak mode.** `opfence run --weak` sets proxy variables but no sandbox, so a program can ignore them and connect directly. Use it only for tools you trust; the banner and every approval card say the session is unsandboxed.
- **A sandbox setting that loosens it.** Opfence passes its settings to Claude Code with `--settings`; a managed or user settings file can still add allowed domains or unsandboxed commands. `opfence run` warns about the ones it knows, and `opfence doctor --probe` checks from inside the sandbox what an agent can actually reach.
- **Hosts on the passthrough list** (package registries and GitHub's download hosts) are tunnelled without inspection. A client can send a different `Host` header inside such a tunnel (domain fronting); Opfence checks the TLS server name, not what is inside the encrypted session. The built-in hosts are tunnelled on port 443 only; hosts you add yourself are tunnelled on any port without that check.
- **Hooks already in a project's Claude Code settings** run outside the sandbox with your access. Opfence keeps the sandbox from writing `.claude/settings.json` and `.claude/settings.local.json`, and warns about hooks it finds there, but it cannot tell whether hooks a repository arrived with, or the scripts they run, are safe.
- **Open mode** tunnels every host that is not in the catalog without inspecting it. Strict mode, the default, refuses them.
- **git over SSH** to github.com is refused rather than inspected. Use HTTPS remotes under `opfence run`.
- **Behind a corporate proxy**, the proxy resolves host names, so Opfence can only refuse private IP addresses written literally; a name that resolves to an internal address is the corporate proxy's decision.

## Requests Opfence cannot read fully

These are never forwarded silently; they become `unknown` (which asks by default) or are blocked:

- Request bodies over 64 KiB, except a git push, whose ref updates are read from the first 64 KiB.
- WebSocket and other protocol upgrades to API hosts (blocked).
- Compressed request bodies other than gzip and deflate.
- Signed git pushes (`git push --signed`).
- AWS requests made with a placeholder key that Opfence cannot re-sign: presigned URLs, SigV4A (multi-Region) signatures, uploads with signed chunks, and bodies over 16 MiB without a hash header. These are blocked with a message saying why.
- AWS requests made with a placeholder key to hosts their creators run rather than AWS: API Gateway (`execute-api`), load balancers, EC2 public names and VPC endpoints. Opfence does not send your real key's signature there, so IAM-authenticated calls to your own API Gateway need a key Opfence does not hold.
- Request bodies that are neither JSON, a form nor multipart (plain text, binary uploads), and bodies over 64 KiB (a large Cloudflare Worker upload): rules that look at body fields treat them as `unknown`.

## What a decision cannot see

- **Force pushes.** A forced `git push` sends the same command as a normal one. Pushes to `main`, `master` and tag moves are treated as the worse case (`delete`); a force push to a feature branch counts as a `write`.
- **State the API hides.** When the class depends on something Opfence cannot see (whether an S3 bucket is versioned, whether a DynamoDB batch contains deletes), the catalog assumes the worse case. That can ask more than necessary; it does not ask less.
- **Operations missing from the catalog** get the provider's default (safe HTTP methods and GraphQL queries are usually reads) or `unknown`. A new endpoint that a provider ships as a `GET` with side effects would be classified as a read until the catalog learns it.
- **SQL that hides its effect in the database.** `SELECT my_function()` is classed as a read unless the function is a known side-effect function or the same request creates it; a function, trigger or rule created earlier can do anything when it runs. A `WHERE` that reads a column counts as limiting even when it matches every row, apart from the obvious cases (`WHERE id = id`, `WHERE id IS NOT NULL`): `WHERE id > 0 OR id <= 0 OR id IS NULL` is a delete, not irreversible. Only Postgres SQL is read: tools that run SQLite or MySQL (Turso, PlanetScale's Vitess databases, Cloudflare D1) get a fixed class, so a harmless query through PlanetScale's write tool still needs confirming in production.
- **Secrets deep in a GraphQL query** are caught by field name (`graphql_secret_fields`, set for Fly.io). A secret field the list misses, or one on a provider without a list, is classified by the query's top-level field.
- **MongoDB filters.** An update with no filter or an empty one (`{}`) is irreversible; a filter that matches every document some other way (`{"_id": {"$exists": true}}`) is a write.
- **Phone approvals.** A push shows the operation, host, path and resource. It passes through the ntfy server (ntfy.sh unless you run your own) and through Google's or Apple's push service. Anyone who learns your push topic can answer requests, so treat it like a password: subscribe only on your phone, never in a browser or ntfy client on the computer the agent runs on (the agent could read the topic there), and `opfence phone setup --new-topics` replaces it. An ntfy access token given to `phone setup` travels in every push, because the buttons need it. A phone can deny a confirm but not approve it, and MCP tool calls the hook asks about are answered in Claude Code's own prompt, not on the phone. Each request costs two ntfy messages and ntfy.sh allows 250 a day per address without an account; an agent that keeps making requests that need approval can use that up (pushes are rate-limited to slow it down), after which requests are still held on your other channels. On iOS a push stays after the request ends, with buttons that no longer do anything.
- **Environments.** An operation is production unless your user config maps its ids to development or staging, so unmapped work asks more often, never less. A repository's `opfence.yaml` can only tighten.

## Credentials

- **Keys Opfence does not hold stay real.** Keys the agent gets some other way (`~/.aws/credentials`, AWS SSO and roles, the `gh` CLI's keyring, cloud CLI config files, SSH keys) are not placeholders. Requests made with them still go through the same decisions; only key hiding is lost. `opfence init` reads `.env` files and MCP configs in the repository, not your home directory.
- **MongoDB Atlas API keys** (the Digest key pair) cannot be held, because the client signs each request with the private key; service accounts can. A service account's sign-in (`POST /api/oauth/token`) mints a token the agent then holds, so it is `credential` and denied in production unless your policy allows it.
- **Keys in Cursor's and VS Code's MCP configs** are reported by `opfence init` but left in place, because `opfence run` does not start those editors' MCP servers behind the proxy.
- **Scrubbing** replaces real key values in responses with their placeholders, including URL-encoded and base64-encoded copies, but not keys that an API splits in other ways (base64 broken into lines, or the first and last two bytes of a base64-encoded key). On AWS, a ranged read of an S3 object that holds a key can return pieces of it unscrubbed, because S3's downloads in parts need `Range`; other APIs have it removed.
- **The keychain.** On macOS any process running as you that can run `/usr/bin/security` can read Opfence's keychain items, and on Linux any process that can reach the session D-Bus can read Secret Service items. The sandbox is what keeps the agent away from them; `opfence doctor --probe` checks that it does.
- **Allowed operations can still move data.** Opfence classifies operations; it does not inspect what data a permitted write carries. An agent allowed to write to a development database or upload to a bucket can put anything it can read there.

## Approvals

- **MCP tool calls Claude Code makes** are asked in Claude Code's own prompt, which cannot make you type the resource name, so a `confirm` there is a plain ask. Calls those servers then make to catalog APIs go through the proxy and get the full `confirm`.
- **A human can approve the wrong thing.** The card shows the decoded operation, its class, environment and resource, but names such as a branch or a resource label are chosen by whoever made the request. Read the resource, not only the verb.
- **Approval fatigue.** Every `ask` interrupts you. Map your development ids so routine work is allowed there, and keep production asking.

## Outside Opfence's reach

- **Damage on your own machine**: deleted files, local databases, Docker containers. That is the sandbox's job (its filesystem rules), not Opfence's.
- **Code that runs later**: scripts, CI workflows, migrations or infrastructure files the agent writes and that run outside an Opfence session. Review them like any other change.
- **A compromised machine or Opfence binary.** Opfence runs as you; anything that already runs as you outside the sandbox, or as root, can change it, its trust store entries or its keychain items.
