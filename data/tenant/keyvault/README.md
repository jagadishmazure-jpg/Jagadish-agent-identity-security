# data/tenant/keyvault

Secret metadata as the Key Vault list-secrets call returns it. No secret value exists anywhere in the repository.

| File | What it does |
|---|---|
| `kv-kr-prod-secrets.json` | Production vault (RBAC, private): app secrets, the CRM API key, a database password |
| `kv-kr-agents.json` | Agent vault: a blueprint certificate backup |
| `kv-kr-nonprod.json` | Non-production vault on the legacy access-policy model |
