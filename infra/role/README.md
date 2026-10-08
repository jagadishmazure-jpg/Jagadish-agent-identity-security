# infra/role

| File | What it does |
|---|---|
| `identity-posture-reader.json` | The custom role: 19 read actions plus two data actions (secret metadata, agent definitions). Terraform reads it with `jsondecode(file())`, Bicep with `loadJsonContent()` |
