// Log Analytics workspace for job logs and scan results. Entra ID auth only (no shared keys),
// with its own audit log.
param suffix string
param location string
param tags object
param retentionInDays int
param dailyQuotaGb int

resource law 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: 'law-idsec-${suffix}'
  location: location
  tags: tags
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: retentionInDays
    workspaceCapping: { dailyQuotaGb: dailyQuotaGb }
    features: { disableLocalAuth: true }
  }
}

resource audit 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'diag-audit'
  scope: law
  properties: {
    workspaceId: law.id
    logs: [{ categoryGroup: 'audit', enabled: true }]
  }
}

output id string = law.id
output name string = law.name
