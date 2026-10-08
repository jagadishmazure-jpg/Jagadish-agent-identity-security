# config

Everything a team would tune for its own tenant. Code reads these files; nothing here is secret.

| File | What it does |
|---|---|
| `scan.yaml` | Tenant, scan time, subscriptions in scope, emergency accounts, phishing-resistant methods, age thresholds and severity weights |
| `crown-jewels.yaml` | The four assets every path is measured against (Global Administrator, prod subscription control, prod secrets, the prod Foundry project) |
| `roles.yaml` | What each Entra and Azure role and each Graph permission lets you do, as graph edges with an ease score |
| `agent-purposes.yaml` | Allowed capabilities per agent purpose, used to spot tools an agent does not need |
| `approvers.yaml` | Who may approve remediation, which actions need two approvers, and the approval lifetime |
| `remediation-hints.yaml` | Team-specific answers the planner cannot infer (the right narrow scope, the new owner or sponsor) |
