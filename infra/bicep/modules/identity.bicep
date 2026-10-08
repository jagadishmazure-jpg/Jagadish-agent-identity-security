// Reader identity: a user-assigned managed identity, plus a GitHub federated credential pinned to
// one protected environment when a repository is named. No secret is ever created.
param suffix string
param location string
param tags object
param environment string
param githubRepository string

resource scanner 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-idsec-scanner-${suffix}'
  location: location
  tags: tags
}

resource github 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2023-01-31' = if (!empty(githubRepository)) {
  parent: scanner
  name: 'github-${environment}'
  properties: {
    issuer: 'https://token.actions.githubusercontent.com'
    subject: 'repo:${githubRepository}:environment:${environment}'
    audiences: ['api://AzureADTokenExchange']
  }
}

output id string = scanner.id
output principalId string = scanner.properties.principalId
output clientId string = scanner.properties.clientId
