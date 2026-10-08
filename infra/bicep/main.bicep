// Bicep twin of infra/terraform: same resources, same names, same defaults. The custom role is
// loaded from the same JSON file Terraform reads, so the two cannot drift.
// Deploy: az deployment sub create --location eastus2 --template-file infra/bicep/main.bicep --parameters main.parameters.json
// Microsoft Graph application permissions are granted by Terraform (grant_graph_permissions) or by
// an administrator by hand; this template does not use the Graph Bicep extension.
targetScope = 'subscription'

@allowed(['dev', 'prod'])
param environment string

@allowed(['eastus2', 'westus2', 'westeurope'])
param location string = 'eastus2'

@description('Short lowercase name used in resource names.')
@minLength(2)
@maxLength(12)
param orgSlug string

@description('Subscriptions the scanner may read. Empty means the deployment subscription only.')
param scanSubscriptionIds array = []

@description('owner/repo allowed to sign in as the scanner through GitHub OIDC. Empty disables the federated credential.')
param githubRepository string = ''

param retentionInDays int = 30
param dailyQuotaGb int = 1

@description('Create the scheduled Container Apps job (needs scanImage).')
param enableScanJob bool = false
param scanImage string = ''
param scanSchedule string = '0 6 * * 1'
@description('Extra arguments for the job\'s collect step, e.g. --vault NAME --project ID=ENDPOINT.')
param scanCollectArgs string = ''
param privateNetworking bool = false
param vnetAddressSpace string = '10.42.0.0/24'

var shortLocation = {
  eastus2: 'eus2'
  westus2: 'wus2'
  westeurope: 'weu'
}
var suffix = '${orgSlug}-${environment}-${shortLocation[location]}'
var tags = {
  workload: 'idsec'
  environment: environment
  managed_by: 'bicep'
  data: 'identity-posture'
}
var role = loadJsonContent('../role/identity-posture-reader.json')
var scanIds = empty(scanSubscriptionIds) ? [subscription().subscriptionId] : scanSubscriptionIds
var scanScopes = [for id in scanIds: '/subscriptions/${id}']
var runJob = enableScanJob && !empty(scanImage)

resource rg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: 'rg-idsec-${suffix}-001'
  location: location
  tags: tags
}

module identity 'modules/identity.bicep' = {
  name: 'identity'
  scope: rg
  params: {
    suffix: suffix
    location: location
    tags: tags
    environment: environment
    githubRepository: githubRepository
  }
}

// Read actions only, plus secret metadata and agent definitions. Never secrets/getSecret.
resource reader 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(subscription().id, 'identity-posture-reader', suffix)
  properties: {
    roleName: '${role.roleName} (${suffix})'
    description: role.description
    type: 'CustomRole'
    assignableScopes: scanScopes
    permissions: [
      {
        actions: role.actions
        notActions: []
        dataActions: role.dataActions
        notDataActions: []
      }
    ]
  }
}

module assignments 'modules/reader-assignment.bicep' = [
  for id in scanIds: {
    name: 'reader-${uniqueString(id)}'
    scope: subscription(id)
    params: {
      principalId: identity.outputs.principalId
      roleDefinitionId: reader.id
    }
  }
]

module workspace 'modules/workspace.bicep' = {
  name: 'workspace'
  scope: rg
  params: {
    suffix: suffix
    location: location
    tags: tags
    retentionInDays: retentionInDays
    dailyQuotaGb: dailyQuotaGb
  }
}

module network 'modules/network.bicep' = if (runJob && privateNetworking) {
  name: 'network'
  scope: rg
  params: {
    suffix: suffix
    location: location
    tags: tags
    vnetAddressSpace: vnetAddressSpace
  }
}

module job 'modules/job.bicep' = if (runJob) {
  name: 'scan-job'
  scope: rg
  params: {
    suffix: suffix
    location: location
    tags: tags
    environment: environment
    workspaceName: workspace.outputs.name
    identityId: identity.outputs.id
    identityClientId: identity.outputs.clientId
    scanImage: scanImage
    scanSchedule: scanSchedule
    scanSubscriptionIds: join(scanIds, ',')
    scanCollectArgs: scanCollectArgs
    subnetId: (runJob && privateNetworking) ? network!.outputs.subnetId : ''
  }
}

output resourceGroupName string = rg.name
output scannerClientId string = identity.outputs.clientId
output scannerPrincipalId string = identity.outputs.principalId
output roleDefinitionId string = reader.id
output logAnalyticsWorkspaceId string = workspace.outputs.id
output scanJobName string = runJob ? job!.outputs.name : ''
