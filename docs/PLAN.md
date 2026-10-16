# Agent Credential Proxy — Research & Build Plan

Oct 16, 2026 · @ss

## Executive summary

Build **Tripline** (working name): an open, tested catalog of dangerous operations for cloud APIs and MCP servers, a compiler that turns it into policy for existing agent proxies, and a thin local runner for people who have none. The credential-proxy idea stays; the proxy engine itself is already built by NVIDIA, Infisical and a YC startup, so Tripline supplies what they all lack: knowing which calls are dangerous.

- **Catalog (the core asset):** versioned YAML rules per provider (Railway, Vercel, Supabase, GitHub, AWS, Stripe and more) and per popular MCP server. Each rule labels an operation as read, write, destructive, irreversible, money-moving or secret-revealing, with matchers for REST, GraphQL, AWS actions, MCP tools and CLI commands, plus recorded test requests.
- **Compiler:** one command exports the catalog to NVIDIA OpenShell policy, Infisical Agent Vault service rules, Claude Code permission rules and hooks, and Tripline's own format. Write once, enforce in any engine.
- **Runner:** `tripline run -- claude` starts a local proxy that holds the keys, enforces the catalog, and asks you before anything destructive. The approval card is written by the proxy from the decoded request, never by the agent. It plugs into Claude Code's sandbox through its bring-your-own-proxy setting; no container, server or database.
- **Who it is for:** solo developers and small teams pointing Claude Code, Cursor, Codex or custom agents at real cloud accounts, and the maintainers of agent proxies who need rules.
- **Why now:** an agent wiped PocketOS's production database in April 2026, and prompt injection stole keys from three major coding agents the same month. The engines exist; every user still hand-writes the rules.

**The v1 promise:** "Install in one minute. Your agent keeps working, never sees a key, and cannot delete, wipe or pay for anything without your tap." v1.0 scope (April 2027): 15 providers, 25 MCP servers, exports to OpenShell, Agent Vault and Claude Code, macOS and Linux, Claude Code first.

## Problem and evidence

Coding agents run with real, over-powered credentials in reach. They fail in two ways, and today's defenses act on the wrong layer for both.

**Failure 1 — a confused agent uses a key it should not have.**

- **PocketOS, April 2026:** a Cursor agent hit a credential mismatch on a staging task. It found an API token in an unrelated file, and that token had blanket permissions. It deleted the production database and its backups in one API call ([DZone](https://thenote.app/post/en/designing-safe-agent-permissions-why-least-privilege-must-exist-outside-the-ngfxtduant), [Cyber Security News](https://cybersecuritynews.com/ai-coding-agent-deletes-data/amp/)).
- **Replit, July 2025:** an agent ran destructive commands on a live database during a code freeze ([DEV](https://dev.to/joylo/why-replits-ai-agent-deleted-a-production-database-389p)).

**Failure 2 — prompt injection makes the agent leak keys.**

- **"Comment and Control", April 2026:** malicious PR titles and comments made Claude Code Security Review (CVSS 9.4), Gemini CLI Action and Copilot's coding agent leak CI secrets. The leak went out through GitHub's own API ([Waxell](https://waxell.ai/blog/ai-coding-agent-prompt-injection-cicd-2026)).
- **Google Antigravity, June 2026:** a poisoned web page made the agent dump its environment variables and send a key out inside an image URL. The approval prompt passed because the agent described the action to the user itself ([0DIN](https://0din.ai/blog/faking-the-pipeline-data-exfiltration-in-google-antigravity)).
- **Amazon Kiro, disclosed August 2026:** a crafted workspace made the agent read a key from `.env` and put it in a config URL ([Vibe Graveyard](https://vibegraveyard.ai/story/amazon-kiro-powers-secret-exfiltration/)).

**How big the problem is**

| Signal | Number | Source |
| --- | --- | --- |
| New hardcoded secrets on public GitHub, 2025 | 28.65M, up 34% | [GitGuardian via Passwork](https://passwork.pro/blog/the-state-of-secrets-sprawl-in-2026/) |
| AI-assisted commits leak secrets vs baseline | about 2× | [DevOps.com](https://devops.com/?p=199818) |
| Unique secrets in MCP config files, 2025 | 24,008 (2,117 valid) | [The Hacker News](https://thehackernews.com/2026/03/the-state-of-secrets-sprawl-2026-9.html?m=1) |
| Secrets valid in 2022 still valid in 2026 | 64% | [DevOps.com](https://devops.com/?p=199818) |
| Orgs with an AI agent security incident in 12 months | 65% | [CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-cisa-agentic-ai-guidance-practitioner-2026/) |
| Orgs confident their IAM can govern agents | 18% | [CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-cisa-agentic-ai-guidance-practitioner-2026/) |
| Orgs giving AI more access than a human doing the same job | 70% | [NHIMG](https://nhimg.org/?p=9135) |
| Developers using coding assistants or agents | 65.9% | [IT Brief / Stack Overflow 2026](https://itbrief.com.au/story/stack-overflow-survey-finds-developers-wary-of-ai-tools) |

**Why current defenses fail**

| Defense | Why it fails |
| --- | --- |
| Rules in the system prompt | The PocketOS agent knew the rules and broke them anyway. |
| Regex command guards | They match command text. A script or a raw API call never matches. |
| "Are you sure?" prompts | The agent writes the description the human approves, as in Antigravity. |
| Sandbox domain allowlists | Comment and Control leaked through GitHub, an allowed domain. |
| Sandbox alone | Anthropic says its sandbox is not a secrets manager; credentials need a proxy. |

**Design principle that follows:** if a secret never enters the sandbox, injection has nothing to steal. If a token's power is cut at the proxy, a confused agent cannot delete production.

## Prior art and landscape

The enforcement engines are built and well funded; the shared knowledge of which operations are dangerous is not. Every engine below asks the user to write their own rules.

| Tool | What it does | How it runs | What it lacks |
| --- | --- | --- | --- |
| [NVIDIA OpenShell](https://docs.nvidia.com/openshell/latest/about/overview.html) | Sandboxed agent runtime with YAML egress policy at method and path level, plus [GraphQL, MCP and JSON-RPC inspection](https://docs.nvidia.com/openshell/how-it-works/policies/schema), credential injection and [AWS re-signing](https://docs.nvidia.com/openshell/latest/providers/aws-sigv4) | Container per sandbox, gateway control plane | No shared rule catalog; policies are hand-written or LLM-generated from API docs |
| [Infisical Agent Vault](https://github.com/Infisical/agent-vault) | MITM credential broker; swaps placeholders for real keys; egress filtering by service and endpoint; `agent-vault run -- claude` | Single Go binary, SQLite; MIT; recommends a separate host | No operation-level rules, no approvals, no catalog |
| [OneCLI](https://www.ycombinator.com/launches/RoJ-onecli-your-ai-agents-shouldn-t-be-holding-raw-secrets) | Credential gateway matching host and path; [approvals for writes](https://onecli.sh) in its hosted product | One Docker container; Apache-2.0 core; YC S26 | Moving toward hosted "AI teammates" for business apps |
| [Cloudflare Outbound Workers](https://developers.cloudflare.com/changelog/post/2026-04-13-sandbox-outbound-workers-tls-auth/) | Credential injection and egress policy in code | Cloudflare Sandboxes only | Platform-locked |
| [Fly.io tokenizer](https://github.com/superfly/tokenizer) | Proxy that unseals encrypted secrets into requests | Server you deploy | A building block, no agent policy |
| [agent-airlock](https://github.com/es617/agent-airlock) | Allow/deny rules on GraphQL operations and MCP tool names | Local proxy | Users still write every rule |
| [httpjail](https://www.simonwillison.net/2025/Sep/19/httpjail) (Coder) | Process-level HTTP(S) filtering with JavaScript rules | Local CLI | No credentials, no catalog |
| [Anthropic sandbox-runtime](https://code.claude.com/docs/en/agent-sdk/secure-deployment) | OS-level file and network isolation for Claude Code | macOS Seatbelt, Linux bubblewrap | Accepts a [bring-your-own proxy](https://github.com/Electroid/sandbox-runtime) but holds no secrets |
| [Destructive Command Guard](https://skills.cat/skills/dicklesworthstone/destructive-command-guard), [AgentLint](https://pypi.org/project/agentlint/) | Block risky shell commands in Claude Code hooks | Hook | Text matching; bypassed by scripts and raw API calls |
| [Delego](https://pypi.org/project/delego/) | Policy and approval layer in front of a broker | Library | Broker is a stub; no provider knowledge |

**The gap Tripline fills**

- **Knowledge is re-invented per user.** To be safe, a user must already know that Railway's `volumeDelete` mutation is fatal or which Supabase MCP tools drop data. OpenShell even ships an agent skill that drafts policy from API docs, which shows the knowledge gap is real.
- **Rules are locked to one engine.** An OpenShell policy cannot be reused in Agent Vault or Claude Code hooks.
- **Nobody tests rules.** No engine ships recorded requests proving a rule catches what it claims.

Security has solved this shape of problem before: engines compete, while one shared rule repository becomes the standard (Sigma for SIEMs, nuclei-templates for scanners, gitleaks rules for secret scanning). Tripline aims to be that repository for agent actions, and partners with the engines instead of fighting them.

## Product definition

Tripline serves two audiences with one asset: developers who want a safe agent in a minute, and proxy maintainers who want rules they did not have to write.

**Target users**

| User | Situation | What they need from Tripline |
| --- | --- | --- |
| Solo developer | Runs Claude Code or Cursor against Railway, Vercel, Supabase or GitHub with keys in `.env` | `tripline run -- claude` and nothing else to learn |
| Small-team lead | Several people and agents share cloud accounts | One reviewed policy file in the repo, an audit log |
| Engine user (OpenShell, Agent Vault) | Already has a proxy, hand-writes YAML | `tripline export` to generate tested policy |
| MCP server author | Ships tools without clear risk labels | A catalog entry and a badge that says the server is classified |

**Jobs to be done**

1. Let my agent work on real infrastructure without any risk of irreversible loss.
2. Keep real keys out of the agent's reach, even if it is tricked.
3. Reuse a vetted policy instead of studying every API's dangerous calls.
4. Know afterwards exactly what my agent did with my accounts.

**v1 user stories**

- `tripline init` scans the repo, `.env` files and MCP configs, moves found secrets into the local store, and leaves placeholders behind.
- `tripline run -- claude` starts the proxy, configures Claude Code's sandbox to use it, and launches the agent.
- A destructive call pauses. A native notification and a terminal prompt show the proxy's own reading of it, for example "Railway `volumeDelete` · volume `pg-data` · environment `production`". No answer within 60 seconds means deny.
- `tripline export --target openshell` (and `--target agent-vault`, `--target claude-hooks`) writes policy for another engine.
- `tripline test` replays every rule's recorded requests and fails if any rule misses.
- `tripline log` lists every keyed request, its decision and who approved it.

**Non-goals for v1**

- Windows support (WSL works through the Linux path).
- Non-HTTP protocols: Postgres wire, SSH, raw TCP. Use hoop.dev for those.
- Detecting prompt injection in content. Tripline limits what an injected agent can do; it does not judge text.
- Teams features: identity providers, multi-tenant vaults, a hosted service.
- Replacing OpenShell or Agent Vault. Tripline exports to them.

## Architecture and technical design

The agent runs inside an OS sandbox whose only exit is the Tripline proxy; the proxy decodes each request, looks it up in the catalog, and only then attaches a real key.

```mermaid
flowchart LR
  subgraph SB["Sandbox: Claude Code sandbox or srt (Seatbelt / bubblewrap)"]
    A["Coding agent"] --> T["CLIs, SDKs, MCP clients<br/>hold placeholders only"]
  end
  T -- "HTTPS_PROXY: the only allowed exit" --> P
  subgraph TR["Tripline runner, outside the sandbox"]
    P["MITM proxy"] --> D["Decoders<br/>REST, GraphQL, AWS, MCP, git"]
    D --> E["Policy engine<br/>+ catalog"]
    E -- allow --> I["Injector<br/>placeholder swap, SigV4 re-sign"]
    E -- ask --> H["Approver<br/>terminal, desktop, phone"]
    H --> I
    E -- deny --> X["403 with rule id"]
    K[("OS keychain")] --> I
    I --> S["Response scrubber"]
    E --> L[("Audit log")]
  end
  I --> U["Provider APIs"]
```

The PocketOS request, replayed through Tripline:

```mermaid
sequenceDiagram
  participant Ag as Agent (sandboxed)
  participant Px as Tripline proxy
  participant You as You
  participant Api as Railway API
  Ag->>Px: POST /graphql/v2, Bearer tl_railway_ph_7f3a
  Px->>Px: Decode: mutation volumeDelete(volumeId)
  Px->>Px: Catalog: railway.volume.delete = irreversible, env = production
  Px->>You: Railway volumeDelete, volume pg-data, production [Approve once / Deny]
  You-->>Px: Deny, or no answer in 60 s
  Px-->>Ag: 403 {source: tripline, rule: railway.volume.delete}
  Note over Api: Never contacted. The real token never left the keychain.
```

**Components**

| Component | Responsibility | Key design decision |
| --- | --- | --- |
| MITM proxy | Terminate TLS for keyed hosts, pass others through or block | Intercept only hosts in the catalog or config; everything else is denied in strict mode |
| Decoders | Turn a request into an operation: method and path, GraphQL operation and root fields, AWS action, MCP tool name, git ref updates | Buffer at most 64 KiB of body; anything larger or unparseable fails closed |
| Policy engine | Map operation plus environment to allow, ask, deny or log | Unknown operations on a keyed host default to *ask* in v1 |
| Environment resolver | Decide whether a target is production | `tripline.yaml` maps project, environment and resource ids; read-only lookups fill gaps |
| Injector | Swap placeholders in headers, query, basic auth and JSON bodies; re-sign AWS SigV4 | Real values come from the OS keychain at request time and never touch disk |
| Approver | Ask a human | The card is written from the decoded request, never from agent text; a grant is single-use and bound to a hash of that exact operation |
| Response scrubber | Stop real secrets echoing back into model context | Replace any real secret bytes in a response with its placeholder |
| Audit log | Record every keyed request and decision | Append-only JSONL with a hash chain; bodies are never stored |
| Launcher | `tripline run -- <agent>` | Writes Claude Code sandbox settings or wraps other agents in Anthropic's `srt` |

**Sandbox integration**

- **Claude Code:** set `sandbox.enabled`, point [`sandbox.network.httpProxyPort`](https://claudeissues.com/issue/10653-bug-documentation-custom-proxy-configuration-example-missing-network-wrapper-blo) at Tripline, and add Tripline's data folder to `denyRead`. Anthropic's guide already says credentials should be [injected through a proxy](https://code.claude.com/docs/en/agent-sdk/secure-deployment).
- **Cursor, Codex, Gemini CLI, custom agents:** wrap the process in [sandbox-runtime](https://github.com/Electroid/sandbox-runtime) with Tripline as its proxy.
- **No sandbox available:** fall back to environment variables only and label it clearly as *weak mode*. Keys are still safe, because none are in the sandbox; only bypass of non-keyed egress is possible.

**Certificate trust: the hardest usability problem**

- Set the variables the main runtimes read: `SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `DENO_CERT`. This is the same list [Agent Vault's SDK](https://github.com/Infisical/agent-vault) sets.
- **Go CLIs on macOS ignore these.** `gh`, `supabase`, `terraform` and `flyctl` use the system keychain, so they [fail until the CA is trusted there](https://docs.rs/crate/httpjail/0.3.0/source/AGENTS.md); Claude Code's own proxy [hits the same bug](https://claudeissues.com/issue/26466-go-based-cli-tools-gh-terraform-etc-fail-with-tls-error-due-to-built-in-https-pr). `tripline trust` must install a name-constrained, per-user CA with one prompt and remove it cleanly on uninstall.
- Generate the CA per machine, keep its key in the keychain, and limit it with X.509 name constraints to catalog hosts where clients support that.

## Threat model and security design

Tripline assumes the agent may be confused or fully controlled by an attacker, and keeps two promises anyway: no real key leaves the host, and no catalogued destructive operation runs without a human.

**Who we defend against**

- **Confused agent:** no malice, wrong action, as at PocketOS and Replit.
- **Prompt-injected agent:** follows instructions hidden in a web page, issue, PR title or file.
- **Hostile code in the sandbox:** a malicious dependency or MCP server the agent installed.

**Attack paths and mitigations**

| # | Attack path | Mitigation |
| --- | --- | --- |
| 1 | Read keys from `.env`, configs or environment | `tripline init` moves them to the OS keychain; the sandbox denies reads of Tripline's folder and keychain access |
| 2 | Steal a placeholder | Worthless outside the proxy; the proxy also requires a per-session token, bound to localhost |
| 3 | Send a placeholder to an attacker host | Each placeholder is bound to its provider's hosts and is never injected anywhere else |
| 4 | Make an allowed API echo the key back | Response scrubber replaces real key bytes before the agent sees them |
| 5 | Use a legitimate key for a destructive call | Catalog classifies the operation; destructive or irreversible means ask or deny |
| 6 | Get approval for A, then run B | Grant is single-use and bound to a hash of the exact decoded operation and arguments |
| 7 | Mislead the human with a friendly description | The card is generated from the decoded request; agent text appears only under an "agent says (unverified)" label |
| 8 | Wear the human down with prompts | Reads never prompt; scoped grants such as "this resource, 10 minutes"; prompt-rate statistics in the log |
| 9 | Bypass the proxy | The sandbox only allows the proxy as an exit; in weak mode, bypass still yields no keys |
| 10 | Edit `tripline.yaml` to loosen policy | Repository policy can only tighten rules; loosening lives in user config outside the sandbox's write paths |
| 11 | Evade the decoder: GraphQL aliases, batching, persisted queries, compression | Real GraphQL parser, batch arrays expanded, unknown persisted-query hashes denied, bodies decompressed, size limit fails closed |
| 12 | Poison the catalog with a loosening rule | Signed releases, two-reviewer rule changes, `tripline update` shows a diff; local overrides always win |
| 13 | Steal the interception CA key | Key stays in the keychain, is per machine, and is name-constrained where clients allow |

**Explicitly out of scope for v1**

- A compromised host or kernel. If malware runs as the user outside the sandbox, Tripline cannot help.
- Leaking data (not keys) through allowed reads and writes, such as posting repository contents in a GitHub comment as in Comment and Control. v1 can mark comment and issue creation as *ask* in untrusted sessions, but full data-flow control is a later project.
- DNS tunnelling and raw TCP. These are the sandbox's job; document the gap honestly.

**Security process from day one:** a `SECURITY.md` with a private reporting address, fuzzing of every decoder in CI, and an external review of the proxy and approver before v1.0.

## Policy model and the catalog

The catalog labels operations; the user's policy decides what each label means in each environment. Keeping the two apart lets one tested catalog serve every user and every engine.

**Seven risk classes**

| Class | Meaning | Example |
| --- | --- | --- |
| `read` | No change to state | List Vercel projects |
| `write` | Creates or changes state, recoverable | Trigger a Railway deploy |
| `delete` | Removes something that can be restored | Delete a Supabase development branch |
| `irreversible` | Data or resources gone for good | Railway `volumeDelete`; RDS `DeleteDBInstance` with no final snapshot |
| `money` | Spends, refunds or moves money | Stripe refund |
| `credential` | Creates, reveals or rotates secrets | AWS IAM `CreateAccessKey` |
| `access` | Changes who can see or do what | Make a GitHub repository public |

**Default decisions (users can override)**

| Class | Development | Staging | Production |
| --- | --- | --- | --- |
| read | allow | allow | allow |
| write | allow | allow | ask |
| delete | allow | ask | ask |
| irreversible | ask | ask | ask + type the resource name |
| money | ask | ask | ask |
| credential | ask | ask | deny |
| access | ask | ask | ask |
| unknown operation | ask | ask | ask |

**A catalog rule**

```yaml
# catalog/railway/volume.yaml
provider: railway
hosts: [backboard.railway.com]
auth: { header: Authorization, scheme: Bearer, alt: [Team-Access-Token, Project-Access-Token] }
operations:
  - id: railway.volume.delete
    match: { graphql: { type: mutation, field: volumeDelete } }
    class: irreversible
    resource: { arg: volumeId, kind: volume }
    card: "Delete Railway volume {volumeId} and all data on it"
    status: verified          # verified | community | draft
    sources: ["https://docs.railway.com/integrations/api"]
    tests:
      - fixture: fixtures/railway/volume-delete.http
        expect: irreversible
```

**A user policy**

```yaml
# tripline.yaml (in the repo; may only tighten)
environments:
  production:
    railway:  { environments: [production] }
    vercel:   { projects: [web], target: production }
    supabase: { projects: [abcd1234] }
mode: strict            # deny hosts not in the catalog or config
approvals: { timeout: 60s, channels: [terminal, desktop] }
```

**First providers for v1**

| Provider | API style | Dangerous operations to catalog first |
| --- | --- | --- |
| [Railway](https://providers.apievangelist.com/providers/railway-app/) | One GraphQL endpoint at `backboard.railway.com/graphql/v2` | `volumeDelete`, `variableDelete` and the other delete mutations |
| [Vercel](https://vercel.com/docs/rest-api/projects/delete-a-project) | REST with a public OpenAPI spec | `DELETE /v9/projects/{idOrName}`, project pause, env var and domain removal |
| [Supabase MCP](https://github.com/supabase-community/mcp-server-supabase) | Remote MCP at `mcp.supabase.com/mcp` | `delete_branch`, `reset_branch`, `pause_project`, `apply_migration`, and `execute_sql` classified by its SQL |
| GitHub | REST plus git over HTTPS | Delete repository, change visibility, delete a branch or force-push via `git push` |
| AWS | SigV4 with Query and JSON protocols | RDS `DeleteDBInstance`, S3 `DeleteBucket`, EC2 `TerminateInstances`, IAM `CreateAccessKey` |

**How the catalog grows without one person writing it all**

1. **Draft automatically** from machine-readable sources: Vercel's [OpenAPI spec](https://vercel.com/docs/rest-api/projects/delete-a-project), Railway's GraphQL schema by introspection, and each MCP server's `tools/list`.
2. **Start from MCP annotations.** The spec already defines `readOnlyHint` and `destructiveHint`, but clients must [treat them as untrusted](https://stacklok.com/blog/tool-annotations-are-becoming-the-risk-vocabulary-for-agentic-systems-that-matters-more-than-it-might-seem/) from untrusted servers. Tripline's reviewed labels become the trusted overlay that tools like [Codex CLI already use to decide approvals](https://codex.danielvaughan.com/2026/04/12/mcp-tool-annotations-risk-vocabulary-codex-cli/).
3. **Review by a human, prove by a fixture.** A rule reaches `verified` only with a recorded request and a passing `tripline test`.
4. **SQL inside tools.** v1 classifies `execute_sql` by keyword with a fail-to-ask default (`DROP`, `TRUNCATE`, `DELETE` without `WHERE` are irreversible); v2 uses a real Postgres parser.

## Tech stack and repo structure

Write it in **Go**: one static binary for macOS and Linux, a mature TLS and HTTP standard library, and the same language as Infisical Agent Vault, which makes contributions and integrations easier.

| Need | Choice | Why |
| --- | --- | --- |
| MITM proxy | `net/http` + `crypto/tls` with a per-host leaf cert cache; `elazarl/goproxy` as a fallback | Full control over CONNECT handling and body buffering |
| GraphQL decoding | `vektah/gqlparser/v2` | Real parser; handles aliases, fragments and batches |
| AWS re-signing | `aws-sdk-go-v2` SigV4 signer | Official signer; copy OpenShell's documented chunked-upload limits |
| Secret discovery | `gitleaks` v8 as a library | Hundreds of tested detectors for `tripline init` |
| Key storage | `zalando/go-keyring` | macOS Keychain and Linux Secret Service, nothing on disk |
| Policy conditions | `google/cel-go` | Safe, fast expressions for advanced overrides |
| Terminal approvals | `charmbracelet/huh` | Clear prompts with minimal code |
| Phone approvals | [ntfy](https://ntfy.sh) with action buttons | Free, self-hostable push with no account |
| Config and schema | YAML plus JSON Schema | Editor autocomplete and CI validation for catalog PRs |
| Release | GoReleaser, Homebrew tap, GitHub build attestations, cosign | Verifiable binaries for a security tool |

**Licence:** Apache-2.0 for code and catalog, so open-source engines such as Agent Vault (MIT) and commercial vendors can embed the catalog without friction.

**Repository layout**

```text
tripline/
  cmd/tripline/          CLI entry point
  internal/proxy/        MITM, CA, connection handling
  internal/decode/       rest, graphql, aws, mcp, gitsmart, sql
  internal/policy/       classes, environment resolver, decisions
  internal/inject/       placeholders, header and body swap, SigV4
  internal/approve/      terminal, desktop, ntfy, single-use grants
  internal/store/        keychain, migration from .env and MCP configs
  internal/launch/       Claude Code settings, srt wrapper, CA variables
  internal/audit/        hash-chained JSONL
  internal/export/       openshell, agentvault, claudehooks, mcp-annotations
  schema/                JSON Schema for catalog and policy
  docs/
tripline-catalog/        separate repo: one folder per provider, rules + fixtures
```

The catalog lives in its own repository so contributors never touch proxy code, and so other engines can depend on it alone. The binary embeds a snapshot and `tripline update` pulls signed newer versions.

**CLI surface**

| Command | What it does |
| --- | --- |
| `tripline init` | Scan repo, `.env` and MCP configs; move secrets to the keychain; write placeholders and `tripline.yaml` |
| `tripline trust` | Create the per-machine CA and trust it, including the macOS keychain for Go CLIs; `--uninstall` removes it |
| `tripline run -- <agent>` | Start the proxy, configure the sandbox, launch the agent |
| `tripline doctor` | Check that the sandbox is active and each runtime trusts the CA |
| `tripline explain <file.http>` | Decode a saved request and show the rule and decision |
| `tripline test` | Replay every fixture; fail if any rule misses |
| `tripline export --target <engine>` | Write OpenShell policy, Agent Vault rules, Claude Code hooks or MCP annotation overlays |
| `tripline log` | Show keyed requests, decisions and approvals |
| `tripline update` | Fetch a signed catalog update and show the diff |

## Roadmap and milestones

Ship the catalog and exporters first, around 8 December 2026, and the local runner second, around 9 February 2027. The catalog is useful on day one to everyone already running OpenShell or Agent Vault, and it builds an audience before the hardest engineering starts. Dates assume one developer at about 25 hours a week, starting 19 October 2026.

```mermaid
gantt
  title Tripline roadmap (one developer, about 25 h a week)
  dateFormat YYYY-MM-DD
  axisFormat %d %b
  section Validate
  Interviews, competitor trials, schema v0        :a1, 2026-10-19, 14d
  Gate 1 go or no-go                              :milestone, g1, 2026-11-01, 0d
  section Catalog
  Decoders, explain and test, 60 rules            :a2, 2026-11-02, 21d
  Exporters for OpenShell, Agent Vault, MCP       :a3, 2026-11-23, 14d
  Launch 1 catalog and exporters                  :milestone, l1, 2026-12-08, 0d
  section Runner
  Proxy, CA trust, keychain, init                 :a4, 2026-12-07, 28d
  Approvals, sandbox launcher, audit log          :a5, 2027-01-04, 14d
  Hardening, fuzzing, SigV4, docs                 :a6, 2027-01-18, 21d
  Launch 2 Show HN v0.5                           :milestone, l2, 2027-02-09, 0d
  section v1.0
  15 providers, 25 MCP servers, phone, SQL        :a7, 2027-02-10, 56d
  External security review                        :a8, 2027-04-07, 21d
  v1.0                                            :milestone, v1, 2027-04-30, 0d
```

| Phase | Deliverables | Exit criteria |
| --- | --- | --- |
| 0 · Validate (2 weeks) | 10 user interviews; hands-on trials of OpenShell, Agent Vault and OneCLI; catalog schema v0; 20 hand-written rules | At least 5 of 10 interviewees describe the problem unprompted and agree to try a beta; one engine maintainer replies with interest |
| 1 · Catalog (3 weeks) | REST, GraphQL and MCP decoders; `tripline explain` and `tripline test`; 60 verified rules across Railway, Vercel, Supabase MCP, GitHub, AWS | Every rule has a fixture; CI fails on any miss; decoders fuzzed for 1 hour each |
| 2 · Exporters (2 weeks) | `tripline export` to OpenShell, Agent Vault and an MCP annotation overlay | OpenShell blocks the replayed PocketOS `volumeDelete` using only exported policy |
| **Launch 1** | Catalog repo, blog post, PRs or issues offering integration to OpenShell and Agent Vault | Posted; first outside contributor rule merged within 3 weeks |
| 3 · Runner (6 weeks, includes holidays) | MITM proxy, `tripline trust`, keychain store, `tripline init`, placeholder injection, terminal and desktop approvals, Claude Code launcher, audit log | `tripline run -- claude` works on macOS and Ubuntu with `gh`, `vercel`, `supabase` and Railway API calls |
| 4 · Harden (3 weeks) | Response scrubber, SigV4, `tripline doctor`, docs site, 2-minute demo video | No open high-severity issues; install-to-first-blocked-call under 5 minutes for 5 test users |
| **Launch 2** | Show HN, Reddit, Claude Code community | See Success metrics |
| 5 · v1.0 (11 weeks) | 15 providers, 25 MCP servers, ntfy phone approvals, Postgres SQL parser, srt launcher for Cursor and Codex, external security review | Review findings fixed; 3 or more regular outside catalog contributors |

The runner phase starts during the exporters phase on purpose: proxy and CA work does not depend on exporter design and is the longest pole.

## Launch and adoption plan

Lead with one story everyone already knows, the PocketOS deletion, and show it stopped in under 90 seconds. Launch twice: the catalog to engine users in December, the runner to every Claude Code user in February.

**Positioning**

- One line: *The open list of things your AI agent must never do without asking, and the tool that enforces it.*
- Against OpenShell and Agent Vault: "Keep your engine. We give it the rules."
- Against command guards: "We read the request, not the command text."

**Name: decide before Launch 1.** "Tripline" is already used on [PyPI by an agent-safety tool](https://pypi.org/project/tripline/) that includes a network proxy, and "Airlock" by [agent-airlock](https://github.com/es617/agent-airlock). Shortlist 5 names, then check the GitHub org, PyPI, npm, crates.io, Homebrew and a `.dev` domain for each. Prefer a short noun that works as a CLI command and suggests a list or a boundary.

**The hero demo (record it once, use it everywhere)**

1. A fresh repo that looks like PocketOS's stack, with a Railway token in a config file.
2. `tripline init` finds the token and moves it to the keychain.
3. Claude Code is asked to "clean up the staging volume" and reaches for `volumeDelete` on production.
4. The proxy's card appears, written from the decoded request; the user taps Deny; the agent reports it was blocked and why.
5. Final frame: the same rule exported to OpenShell, blocking the same call there.

**Channels, in order**

| When | Channel | Message |
| --- | --- | --- |
| Launch 1 | GitHub issues or PRs to OpenShell and Agent Vault | "Here are 60 tested rules in your format; want them upstream?" OpenShell already has an [open issue on MCP policy](https://github.com/NVIDIA/OpenShell/issues/1531) to build on |
| Launch 1 | MCP server authors | A PR adding correct `destructiveHint` annotations, plus a "classified" badge for their README |
| Launch 1 | Security newsletters and writers who cover agent sandboxing, such as [Simon Willison](https://www.simonwillison.net/2025/Sep/19/httpjail) | The catalog as a public good |
| Launch 2 | Show HN, Tuesday to Thursday, US morning | The 90-second demo and the honest threat model |
| Launch 2 | r/ClaudeAI, r/cursor, r/devops, r/netsec | Tailored posts, not cross-posts |
| Ongoing | MCP and agent meetups, including India's MCP community events | Talks built around the catalog data, such as "we classified 1,000 cloud operations" |

**Making contributors out of users**

- "Add a rule in 10 minutes" guide, a rule template, and a CI bot that runs the fixture and comments on the PR.
- One `good first issue` per uncovered provider, generated from that provider's OpenAPI or GraphQL schema.
- Credit every contributor in release notes and in the rule file itself.

**Docs that build trust:** a 30-second install in the README, the full threat model, and a page titled "What this does not protect against". For a security tool, honesty about limits is part of the product.

## Risks and mitigations

The biggest risk is that the engines build their own catalogs; the answer is to become their upstream before they need to.

| Risk | Likelihood | Impact | Mitigation |
| --- | --- | --- | --- |
| OpenShell or Agent Vault ship their own rule packs | Medium | High | Offer the catalog in their format at Launch 1; Apache-2.0 so adoption is free; consider moving the catalog to a neutral foundation once it has outside maintainers |
| Anthropic or OpenAI add credential injection to their sandboxes | Medium | Medium | The runner shrinks in importance, the catalog does not; add their sandbox as an export target |
| Catalog rots as APIs change | High | Medium | Nightly job diffs OpenAPI specs, GraphQL schemas and MCP `tools/list`, then opens issues; every rule shows a "last verified" date |
| Users feel safer than they are | Medium | High | Unknown operations ask by default; weak mode is labelled; a "What this does not protect against" page |
| Approval fatigue makes users click Approve blindly | High | High | Reads never prompt; scoped time-boxed grants; prompt-rate shown in `tripline log` |
| CA install blocked on managed laptops | Medium | Medium | `tripline doctor` explains each failure; per-runtime variable fallback; docs for IT admins |
| TLS edge cases: pinning, HTTP/3, WebSockets, gRPC | Medium | Medium | Intercept only catalog hosts; block HTTP/3 so clients fall back to TCP; WebSockets in v1.x |
| A vulnerability in Tripline itself | Medium | High | Fuzzed decoders, few dependencies, signed releases, `SECURITY.md`, external review before v1.0 |
| Solo-maintainer burnout | High | High | Catalog contributions are decentralised by design; recruit 2 co-maintainers by v1.0; strict scope |
| Name clash | Certain | Low | Rename before Launch 1 (see Launch) |
| Blame after data loss despite the tool | Low | Medium | Licence disclaimer; never promise a guarantee; publish the threat model |

## Success metrics

Success at six months means matching today's leading brokers on adoption (Agent Vault has [2.4k stars](https://github.com/Infisical/agent-vault), OneCLI [about 3k](https://onecli.sh)) while owning the one asset they lack. These are targets to steer by, not forecasts.

| Metric | 30 days after Launch 1 | 90 days | 180 days |
| --- | --- | --- | --- |
| Verified catalog rules | 100 | 250 | 600 |
| Providers / MCP servers covered | 5 / 5 | 8 / 12 | 15 / 25 |
| Outside contributors with a merged rule | 3 | 10 | 25 |
| Engines importing the catalog (merged integration) | 0, one in discussion | 1 | 2 |
| Upstream MCP annotation PRs merged | 2 | 8 | 20 |
| GitHub stars, catalog and runner combined | 300 | 1,500 | 4,000 |
| Runner downloads (releases plus Homebrew) | n/a | 1,000 | 5,000 |
| Public "it blocked a real mistake" reports | 0 | 1 | 3 |

**What not to measure:** no usage telemetry by default. A security tool that phones home loses trust; use download counts, GitHub activity and an opt-in survey instead.

**Leading indicator to watch weekly:** time from install to first blocked call for a new user. Target under 5 minutes; if it is higher, fix onboarding before adding providers.

## Next 14 days

Use the first two weeks to prove three things before writing the proxy: users feel the pain, engine maintainers want the catalog, and macOS certificate trust can be made painless. Gate 1 decision on Nov 1, 2026.

**Validate the demand**

- [ ] Days 1–3: install OpenShell, Agent Vault and OneCLI; run Claude Code through each; note setup time and confirm none ships provider rules.
- [ ] Days 1–7: interview 10 developers who use coding agents on real cloud accounts. Ask when an agent last touched production, where their keys live, and what would make them install a tool.
- [ ] Day 3: open a discussion on OpenShell and Agent Vault asking whether a tested, shared catalog of dangerous operations would be useful as an import.

**Prove the core asset**

- [ ] Days 4–8: write catalog schema v0 as YAML plus JSON Schema.
- [ ] Days 6–10: hand-write 20 rules (5 each for Railway, Vercel, Supabase MCP, GitHub), each with a fixture captured through mitmproxy.
- [ ] Days 8–12: Go spike of `tripline explain`: decode a saved GraphQL request and print the matched rule.

**De-risk the hardest engineering**

- [ ] Days 10–13: Go spike of a MITM proxy on macOS that `gh` and `supabase` CLIs trust after one keychain prompt.

**Decide**

- [ ] Day 14: shortlist names; write a one-page Gate 1 memo with interview results and maintainer replies; choose go, narrow (catalog only), or stop.

## Sources

**Incidents and evidence**

- [DZone: Designing safe agent permissions (PocketOS)](https://thenote.app/post/en/designing-safe-agent-permissions-why-least-privilege-must-exist-outside-the-ngfxtduant)
- [Cyber Security News: AI agent deletes production database](https://cybersecuritynews.com/ai-coding-agent-deletes-data/amp/)
- [DEV: Why Replit's agent deleted a production database](https://dev.to/joylo/why-replits-ai-agent-deleted-a-production-database-389p)
- [Waxell: Comment and Control prompt injection](https://waxell.ai/blog/ai-coding-agent-prompt-injection-cicd-2026)
- [0DIN: Data exfiltration in Google Antigravity](https://0din.ai/blog/faking-the-pipeline-data-exfiltration-in-google-antigravity)
- [Vibe Graveyard: Amazon Kiro secret exfiltration](https://vibegraveyard.ai/story/amazon-kiro-powers-secret-exfiltration/)
- [Passwork: GitGuardian State of Secrets Sprawl 2026 findings](https://passwork.pro/blog/the-state-of-secrets-sprawl-in-2026/)
- [DevOps.com: AI-assisted commits leak secrets at twice the rate](https://devops.com/?p=199818)
- [The Hacker News: State of Secrets Sprawl 2026](https://thehackernews.com/2026/03/the-state-of-secrets-sprawl-2026-9.html?m=1)
- [CSA: CISA agentic AI guidance](https://labs.cloudsecurityalliance.org/research/csa-research-note-cisa-agentic-ai-guidance-practitioner-2026/)
- [NHIMG: Least privilege for AI agents](https://nhimg.org/?p=9135)
- [IT Brief: Stack Overflow 2026 survey](https://itbrief.com.au/story/stack-overflow-survey-finds-developers-wary-of-ai-tools)

**Prior art**

- [NVIDIA OpenShell overview](https://docs.nvidia.com/openshell/latest/about/overview.html), [policy schema](https://docs.nvidia.com/openshell/how-it-works/policies/schema), [AWS SigV4](https://docs.nvidia.com/openshell/latest/providers/aws-sigv4), [MCP policy issue #1531](https://github.com/NVIDIA/OpenShell/issues/1531)
- [Infisical Agent Vault](https://github.com/Infisical/agent-vault)
- [OneCLI YC launch](https://www.ycombinator.com/launches/RoJ-onecli-your-ai-agents-shouldn-t-be-holding-raw-secrets), [OneCLI site](https://onecli.sh)
- [Cloudflare: credential injection for Sandboxes](https://developers.cloudflare.com/changelog/post/2026-04-13-sandbox-outbound-workers-tls-auth/)
- [Fly.io tokenizer](https://github.com/superfly/tokenizer)
- [agent-airlock](https://github.com/es617/agent-airlock)
- [Simon Willison on httpjail](https://www.simonwillison.net/2025/Sep/19/httpjail)
- [Delego](https://pypi.org/project/delego/)
- [Destructive Command Guard](https://skills.cat/skills/dicklesworthstone/destructive-command-guard), [AgentLint](https://pypi.org/project/agentlint/)
- [Tripline on PyPI (name clash)](https://pypi.org/project/tripline/)

**Technical references**

- [Claude Code secure deployment](https://code.claude.com/docs/en/agent-sdk/secure-deployment)
- [sandbox-runtime README](https://github.com/Electroid/sandbox-runtime)
- [Claude Code proxy settings issue](https://claudeissues.com/issue/10653-bug-documentation-custom-proxy-configuration-example-missing-network-wrapper-blo)
- [Go CLIs fail behind Claude Code's proxy](https://claudeissues.com/issue/26466-go-based-cli-tools-gh-terraform-etc-fail-with-tls-error-due-to-built-in-https-pr)
- [httpjail notes on macOS certificate trust](https://docs.rs/crate/httpjail/0.3.0/source/AGENTS.md)
- [Stacklok: MCP tool annotations](https://stacklok.com/blog/tool-annotations-are-becoming-the-risk-vocabulary-for-agentic-systems-that-matters-more-than-it-might-seem/)
- [Codex CLI and MCP annotations](https://codex.danielvaughan.com/2026/04/12/mcp-tool-annotations-risk-vocabulary-codex-cli/)
- [Railway public API](https://docs.railway.com/integrations/api), [Railway API profile](https://providers.apievangelist.com/providers/railway-app/)
- [Vercel: Delete a project](https://vercel.com/docs/rest-api/projects/delete-a-project)
- [Supabase MCP server](https://github.com/supabase-community/mcp-server-supabase)
