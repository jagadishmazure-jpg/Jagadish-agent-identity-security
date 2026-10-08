# Adopt this

How to try the scanner on your own tenant, safely and in order. **The live collectors have never been
run against a tenant from this repository.** Treat the first run as a test: use a non-production tenant
if you have one, read the code you are about to run, and keep the output private.

## 1. Run it offline first

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
idsec scan && idsec gate
```

Then validate your own exported files without any cloud access:

```bash
idsec collect --offline path/to/export --out data/mine
IDSEC_DATA=data/mine idsec scan
```

`--offline` checks that the eleven required files exist and parse before copying them.

## 2. Create the reader identity

Either deploy the [Terraform or Bicep stack](infra/README.md) (it creates a user-assigned managed
identity, the custom role and its assignments), or use an existing identity you control. The stacks are
written and tested offline; they have not been deployed.

### Azure: the custom "Identity Posture Reader" role

* 19 actions, all ending in `/read` (role assignments and definitions, PIM schedules, subscriptions and
  resource groups, and the resource types that carry identities).
* Data action `Microsoft.KeyVault/vaults/secrets/readMetadata/action`: secret names, dates and
  attributes. It cannot read secret values.
* Data action `Microsoft.CognitiveServices/accounts/AIServices/agents/read`: agent definitions.
  **Caveat:** it also allows reading threads and messages in the project. Assign it only on projects you
  intend to scan.

The definition is in `infra/role/identity-posture-reader.json`; `idsec iac role` prints a summary.

### Microsoft Graph application permissions (all read-only)

| Permission | Why |
|---|---|
| `User.Read.All` | Users, guests, account state |
| `GroupMember.Read.All` | Groups and memberships |
| `Application.Read.All` | Apps, service principals, owners, credentials, federated credentials, agent identities |
| `DelegatedPermissionGrant.Read.All` | Tenant-wide consent grants |
| `RoleManagement.Read.Directory` | Directory role assignments and PIM schedules |
| `Policy.Read.All` | Conditional Access policies |
| `AuditLog.Read.All` | `signInActivity` and authentication method registration |

**Licence caveat:** `signInActivity` needs Microsoft Entra ID P1 or P2. Without it, sign-in dates are
empty and the dormant-account rule evaluates nothing (it is then left out of the score rather than
passing).

Grant them with Terraform (`grant_graph_permissions = true`, needs a Privileged Role Administrator), or
once by hand, for example with the Azure CLI:

```bash
GRAPH_SP=$(az ad sp list --filter "displayName eq 'Microsoft Graph'" --query "[0].id" -o tsv)
SCANNER=<scanner principal object id>
for p in User.Read.All GroupMember.Read.All Application.Read.All DelegatedPermissionGrant.Read.All \
         RoleManagement.Read.Directory Policy.Read.All AuditLog.Read.All; do
  ROLE=$(az ad sp show --id "$GRAPH_SP" --query "appRoles[?value=='$p'].id | [0]" -o tsv)
  az rest --method POST \
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SCANNER/appRoleAssignments" \
    --body "{\"principalId\":\"$SCANNER\",\"resourceId\":\"$GRAPH_SP\",\"appRoleId\":\"$ROLE\"}"
done
```

That one-time grant is a write made by an administrator, not by the scanner.

## 3. Check the endpoints before the first run

The collectors use documented endpoints, but some are new. Before running, confirm against the current
Microsoft reference:

* The Foundry agents list for your project endpoint (`https://<account>.services.ai.azure.com/api/projects/<project>`) and its API version.
* The Entra Agent ID agent-identity type and the sponsors relationship in Microsoft Graph.
* PIM schedule endpoints for directory roles and Azure resources.
* The Key Vault secrets list API version.

If one differs, change the URL in `src/idsec/collectors/live.py`; the transport will still refuse
anything that is not a read.

## 4. Run the live collectors (read-only)

```bash
pip install -e ".[live]"            # azure-identity
export AZURE_CLIENT_ID=<scanner client id>   # when using a managed identity or workload identity
idsec collect --live --out data/live \
  --subscription <subscription id> \
  --vault <vault name> \
  --project <project resource id>=<project endpoint>
IDSEC_DATA=data/live idsec scan
IDSEC_DATA=data/live idsec report --out out/live
```

`DefaultAzureCredential` is used with interactive browser login disabled. Every request passes
`http.check` first: HTTPS only, Microsoft hosts only, GET only (plus the Resource Graph query POST).

Before the first live run, add Microsoft's public first-party tenant ID to `first_party_tenants` in
`config/scan.yaml` so Microsoft's own apps are not reported as external.

## 5. Review, then decide

* Read the findings and the plan (`idsec plan`, `idsec plan --show <id>`); nothing is applied.
* Use the snippets as a starting point for pull requests in the owning teams' infrastructure repositories.
* Adjust thresholds, crown jewels, agent purposes and approvers in `config/`.

## Data handling

* Scan output names privileged people and describes attack paths. Store it like other security findings,
  restrict access and delete it when no longer needed.
* No secret values are collected. Agent instructions and descriptions are collected because some rules and
  the explainer need them; they may contain business information.
* `data/live`, `out/` and `refs/` should never be committed; `out/` and `refs/` are already git-ignored,
  add your data folder too.

## Summary of the safe order

1. Offline demo and gate. 2. `--offline` with exported files. 3. Reader identity with read-only role and
Graph permissions. 4. Endpoint checks. 5. `--live` into a private folder. 6. Review; apply nothing
automatically.
