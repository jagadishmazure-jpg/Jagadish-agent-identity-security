#!/usr/bin/env bash
# Deployment steps used by .github/workflows/deploy.yml and teardown.yml. Each subcommand is
# idempotent and reads its inputs from the environment:
#   DEPLOY_TOOL   terraform | bicep
#   TARGET_ENV    dev | prod
#   LOCATION      Azure region (default eastus2)
#   ORG_SLUG      short name used in resource names (default kestrel)
#   ARM_* / AZURE_*  set by azure/login (OIDC) and the workflow env
#
#   deploy.sh provision   create/update the scanner stack, write rg/principal to $GITHUB_OUTPUT
#   deploy.sh smoke       identity present, custom role read-only and assigned, workspace keyless
#   deploy.sh destroy     tear the environment down (teardown workflow only)
#
# Never run from this repository so far: DEPLOY_ENABLED is not set.
set -euo pipefail

TOOL="${DEPLOY_TOOL:-terraform}"
ENV_NAME="${TARGET_ENV:?TARGET_ENV is required}"
LOCATION="${LOCATION:-eastus2}"
ORG="${ORG_SLUG:-kestrel}"
STACK="infra/terraform"
OUT="${GITHUB_OUTPUT:-/dev/stdout}"

log() { echo "::group::$*"; }
end() { echo "::endgroup::"; }

short_location() {
  case "$LOCATION" in eastus2) echo eus2 ;; westus2) echo wus2 ;; westeurope) echo weu ;; *) echo "::error::unsupported region $LOCATION" >&2; exit 1 ;; esac
}

tf_init() {
  : "${TFSTATE_RESOURCE_GROUP:?set repo/environment variable TFSTATE_RESOURCE_GROUP}"
  : "${TFSTATE_STORAGE_ACCOUNT:?set repo/environment variable TFSTATE_STORAGE_ACCOUNT}"
  terraform -chdir="$STACK" init -input=false \
    -backend-config="envs/${ENV_NAME}.backend.hcl" \
    -backend-config="resource_group_name=${TFSTATE_RESOURCE_GROUP}" \
    -backend-config="storage_account_name=${TFSTATE_STORAGE_ACCOUNT}" \
    -backend-config="container_name=${TFSTATE_CONTAINER:-tfstate}"
}

provision() {
  if [[ "$TOOL" == "terraform" ]]; then
    log "terraform apply ($ENV_NAME)"
    tf_init
    terraform -chdir="$STACK" apply -auto-approve -input=false -var-file="envs/${ENV_NAME}.tfvars" -var "location=${LOCATION}" -var "org_slug=${ORG}"
    rg=$(terraform -chdir="$STACK" output -raw resource_group_name)
    pid=$(terraform -chdir="$STACK" output -raw scanner_principal_id)
    end
  else
    log "bicep: az deployment sub create ($ENV_NAME)"
    private=false
    [[ "$ENV_NAME" == "prod" ]] && private=true
    outputs=$(az deployment sub create --name "idsec-${ENV_NAME}-${GITHUB_RUN_ID:-local}" \
      --location "$LOCATION" --template-file infra/bicep/main.bicep \
      --parameters environment="$ENV_NAME" location="$LOCATION" orgSlug="$ORG" privateNetworking="$private" \
      --query properties.outputs -o json)
    rg=$(jq -r .resourceGroupName.value <<<"$outputs")
    pid=$(jq -r .scannerPrincipalId.value <<<"$outputs")
    end
  fi
  { echo "resource_group=$rg"; echo "principal_id=$pid"; } >>"$OUT"
}

smoke() {
  : "${RESOURCE_GROUP:?}" "${PRINCIPAL_ID:?}"
  sub=$(az account show --query id -o tsv)
  n=$(az identity list -g "$RESOURCE_GROUP" --query "length(@)" -o tsv)
  [[ "$n" -ge 1 ]] || { echo "::error::reader identity missing"; exit 1; }
  role=$(az role assignment list --assignee "$PRINCIPAL_ID" --scope "/subscriptions/${sub}" --query "[0].roleDefinitionName" -o tsv)
  [[ "$role" == "Identity Posture Reader"* ]] || { echo "::error::expected the Identity Posture Reader assignment, found: ${role:-none}"; exit 1; }
  writes=$(az role definition list --name "$role" --query "[0].permissions[0].actions[?!ends_with(@, '/read')]" -o tsv)
  [[ -z "$writes" ]] || { echo "::error::custom role has non-read actions: $writes"; exit 1; }
  keys=$(az monitor log-analytics workspace list -g "$RESOURCE_GROUP" --query "[0].features.disableLocalAuth" -o tsv)
  [[ "$keys" == "true" ]] || { echo "::error::workspace still accepts shared keys"; exit 1; }
  echo "smoke checks passed: identity present, role '$role' read-only and assigned, workspace keyless"
}

destroy() {
  if [[ "$TOOL" == "terraform" ]]; then
    tf_init
    terraform -chdir="$STACK" destroy -auto-approve -input=false -var-file="envs/${ENV_NAME}.tfvars" -var "location=${LOCATION}" -var "org_slug=${ORG}"
  else
    suffix="${ORG}-${ENV_NAME}-$(short_location)"
    rg="rg-idsec-${suffix}-001"
    pid=$(az identity show -g "$rg" -n "id-idsec-scanner-${suffix}" --query principalId -o tsv 2>/dev/null || true)
    # The role definition and its assignments live at subscription scope, outside the resource group.
    [[ -n "$pid" ]] && az role assignment delete --assignee "$pid" --role "Identity Posture Reader (${suffix})" || true
    az role definition delete --name "Identity Posture Reader (${suffix})" || true
    az group delete --name "$rg" --yes
  fi
}

"$@"
