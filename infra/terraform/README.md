# infra/terraform

See [docs/infra/terraform.md](../../docs/infra/terraform.md).

| File | What it does |
|---|---|
| `versions.tf` | Terraform and provider versions (azurerm, azuread) |
| `providers.tf` | Provider settings (Entra ID auth for state storage) |
| `backend.tf` | Remote state in Azure Storage with Entra ID auth |
| `variables.tf` | Inputs with validation; every optional part defaults to off |
| `locals.tf` | Names, tags, the shared role file, scan scopes, Graph permission list, job command |
| `main.tf` | Resource group, reader identity, GitHub federated credential, custom role and assignments, Log Analytics |
| `graph.tf` | Optional read-only Microsoft Graph application permissions |
| `job.tf` | Optional scheduled Container Apps job running as the reader identity |
| `network.tf` | Optional VNet, delegated subnet and NSG for the job |
| `outputs.tf` | Client ID, principal ID, role ID, workspace ID, job name |
| `envs/` | Per-environment variables and state keys |
| `tests/` | Offline plan tests with mocked providers |
| `.tflint.hcl` | tflint configuration (azurerm ruleset) |
