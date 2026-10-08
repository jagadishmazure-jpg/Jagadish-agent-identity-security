// Optional scheduled scan: a Container Apps job (no ingress) running as the reader identity.
// This repository does not build or publish the image.
param suffix string
param location string
param tags object
param environment string
param workspaceName string
param identityId string
param identityClientId string
param scanImage string
param scanSchedule string
param scanSubscriptionIds string
@description('Extra arguments for the collect step, e.g. --vault NAME --project ID=ENDPOINT.')
param scanCollectArgs string = ''
@description('Delegated subnet for an internal environment, or empty for the public consumption environment.')
param subnetId string = ''

var private = !empty(subnetId)
var collectStep = trim('idsec collect --live --out /tmp/tenant ${scanCollectArgs}')
var scanCommand = '${collectStep} && idsec scan && idsec soc-export'

resource law 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource cae 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: 'cae-idsec-${suffix}'
  location: location
  tags: tags
  properties: {
    appLogsConfiguration: {
      destination: 'azure-monitor'
    }
    vnetConfiguration: private ? { infrastructureSubnetId: subnetId, internal: true } : null
    workloadProfiles: private ? [{ name: 'Consumption', workloadProfileType: 'Consumption' }] : null
  }
}

// Platform logs go to the workspace through a diagnostic setting (Entra ID auth, no shared key).
resource caeLogs 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'diag-logs'
  scope: cae
  properties: {
    workspaceId: law.id
    logs: [{ categoryGroup: 'allLogs', enabled: true }]
  }
}

resource job 'Microsoft.App/jobs@2024-03-01' = {
  name: 'caj-idsec-scan-${environment}'
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: { '${identityId}': {} }
  }
  properties: {
    environmentId: cae.id
    configuration: {
      triggerType: 'Schedule'
      replicaTimeout: 1800
      replicaRetryLimit: 0
      scheduleTriggerConfig: {
        cronExpression: scanSchedule
        parallelism: 1
        replicaCompletionCount: 1
      }
    }
    template: {
      containers: [
        {
          name: 'scan'
          image: scanImage
          // collect read-only, score, and print SOC alert rows to the console log
          command: ['/bin/sh', '-c', scanCommand]
          resources: { cpu: json('0.5'), memory: '1Gi' }
          env: [
            { name: 'AZURE_CLIENT_ID', value: identityClientId }
            { name: 'IDSEC_DATA', value: '/tmp/tenant' }
            { name: 'IDSEC_SUBSCRIPTIONS', value: scanSubscriptionIds }
          ]
        }
      ]
    }
  }
}

output name string = job.name
