// Optional private networking: a VNet with a /27 subnet delegated to Container Apps and an NSG.
// Microsoft Graph and ARM are public endpoints; the job still needs outbound HTTPS to them.
param suffix string
param location string
param tags object
param vnetAddressSpace string

resource nsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: 'nsg-idsec-jobs-${suffix}'
  location: location
  tags: tags
}

resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: 'vnet-idsec-${suffix}'
  location: location
  tags: tags
  properties: {
    addressSpace: { addressPrefixes: [vnetAddressSpace] }
    subnets: [
      {
        name: 'snet-container-jobs'
        properties: {
          addressPrefix: cidrSubnet(vnetAddressSpace, 27, 0)
          networkSecurityGroup: { id: nsg.id }
          delegations: [{ name: 'container-apps', properties: { serviceName: 'Microsoft.App/environments' } }]
        }
      }
    ]
  }
}

output subnetId string = vnet.properties.subnets[0].id
