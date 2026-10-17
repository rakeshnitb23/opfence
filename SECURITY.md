# Security policy

Opfence sits between an AI agent and your cloud credentials, so a bug in it can be a security bug. Please report anything that could let an agent:

- obtain a real credential that Opfence holds,
- run an operation the catalog classifies as needing approval without one,
- make an approval card show something other than the request that runs,
- bypass the proxy or the Claude Code hook, or
- loosen policy from inside the repository.

## Reporting

Use GitHub's private vulnerability reporting on this repository (**Security → Report a vulnerability**). Please do not open a public issue for a vulnerability.

Include the Opfence version (`opfence version`), your OS, and a request or tool call that reproduces it; a `.http` file that `opfence explain` misclassifies is ideal.

We aim to acknowledge reports within 3 working days and to ship a fix or a mitigation for high-severity issues within 14 days. Reporters are credited in the release notes unless they ask not to be.

## Catalog misclassifications

A rule that classifies a dangerous operation as safer than it is (for example a delete labelled `read`) is treated as a vulnerability. Report it privately the same way. A rule that is stricter than it needs to be is a normal bug; open an issue.

## Scope

[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and the threat model in [docs/PLAN.md](docs/PLAN.md#threat-model-and-security-design) describe what Opfence defends against and what it does not (a compromised host, data exfiltration through allowed calls, non-HTTP protocols).
