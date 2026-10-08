# Architecture decision records

Short records of the decisions that shape this repository. Each has a status, the context, the decision
and its consequences.

| File | What it does |
|---|---|
| `0001-offline-first-synthetic-tenant.md` | Why everything runs offline on a fictional tenant |
| `0002-identity-graph-and-ease-weighted-paths.md` | Why privilege is modelled as a graph with ease-weighted paths |
| `0003-read-only-collectors-enforced-in-transport.md` | How read-only is enforced in code as well as permissions |
| `0004-dry-run-remediation-with-digest-bound-approvals.md` | Why remediation never applies changes |
| `0005-agent-explains-code-decides.md` | Why the agent only explains results computed by code |
| `0006-one-role-file-and-keyless-logging.md` | One role definition for both IaC stacks; no shared keys |
