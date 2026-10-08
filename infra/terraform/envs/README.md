# infra/terraform/envs

| File | What it does |
|---|---|
| `dev.tfvars` | Dev: everything optional off |
| `prod.tfvars` | Prod: private networking on, longer retention, job and Graph grants still off |
| `dev.backend.hcl` | State key for dev |
| `prod.backend.hcl` | State key for prod |
