# infra/terraform/tests

| File | What it does |
|---|---|
| `plan.tftest.hcl` | Seven `terraform test` runs with mocked azurerm and azuread providers: read-only role, scopes, pinned federation, opt-in job, network and Graph grants, input validation |
