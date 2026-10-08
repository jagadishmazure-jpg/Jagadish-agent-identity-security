# Infrastructure docs

How the scanner would be deployed. Everything here is written, linted and tested offline; **nothing has
been deployed**.

| File | What it does |
|---|---|
| `reader-identity-and-role.md` | The managed identity, the read-only custom role and opt-in Graph permissions |
| `scan-job.md` | The optional scheduled Container Apps job and private networking |
| `terraform.md` | The Terraform stack and its plan tests |
| `bicep.md` | The Bicep stack with the same resources |
| `workflows.md` | CI, infra checks, CodeQL and the gated deploy and teardown |
