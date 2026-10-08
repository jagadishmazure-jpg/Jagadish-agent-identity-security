// Assigns the custom Identity Posture Reader role to the scanner on one subscription.
targetScope = 'subscription'

param principalId string
param roleDefinitionId string

resource assignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(subscription().id, principalId, roleDefinitionId)
  properties: {
    principalId: principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: roleDefinitionId
    description: 'Identity posture scanner (read-only)'
  }
}
