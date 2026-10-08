# .github/workflows

See [docs/infra/workflows.md](../../docs/infra/workflows.md). Every action is pinned to a commit SHA and every workflow starts with read-only permissions.

| File | What it does |
|---|---|
| `ci.yml` | Lint, tests, release gate, synthetic-data and doc drift, Bicep build, SBOM, gitleaks |
| `codeql.yml` | CodeQL for Python and for the workflows |
| `infra.yml` | terraform fmt, validate and test, tflint, checkov; plan only when OIDC variables exist |
| `deploy.yml` | Dev then prod with approval, Terraform or Bicep, OIDC only; gated off by `DEPLOY_ENABLED` |
| `teardown.yml` | Manual destroy of one environment; gated and confirmed by typing the environment name |
