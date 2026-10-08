# infra/bicep/modules

| File | What it does |
|---|---|
| `identity.bicep` | Reader identity and its environment-pinned GitHub federated credential |
| `reader-assignment.bicep` | Assigns the custom role on one subscription |
| `workspace.bicep` | Log Analytics without shared keys, with an audit diagnostic setting |
| `network.bicep` | Optional VNet with a delegated subnet and NSG |
| `job.bicep` | Optional Container Apps environment and scheduled job, logs through a diagnostic setting |
