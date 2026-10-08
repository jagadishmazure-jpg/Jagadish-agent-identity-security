# Optional private networking (var.private_networking): the scan job runs in an internal Container
# Apps environment on a delegated subnet, so its egress follows your VNet routing and firewall.
# Microsoft Graph and ARM are public endpoints; the job still needs outbound HTTPS to them.
resource "azurerm_virtual_network" "this" {
  count               = local.run_job && var.private_networking ? 1 : 0
  name                = "vnet-idsec-${local.suffix}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  address_space       = [var.vnet_address_space]
  tags                = local.tags
}

resource "azurerm_subnet" "jobs" {
  count                = local.run_job && var.private_networking ? 1 : 0
  name                 = "snet-container-jobs"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this[0].name
  address_prefixes     = [cidrsubnet(var.vnet_address_space, 3, 0)]

  delegation {
    name = "container-apps"
    service_delegation {
      name    = "Microsoft.App/environments"
      actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
    }
  }
}

resource "azurerm_network_security_group" "jobs" {
  count               = local.run_job && var.private_networking ? 1 : 0
  name                = "nsg-idsec-jobs-${local.suffix}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.tags
}

resource "azurerm_subnet_network_security_group_association" "jobs" {
  count                     = local.run_job && var.private_networking ? 1 : 0
  subnet_id                 = azurerm_subnet.jobs[0].id
  network_security_group_id = azurerm_network_security_group.jobs[0].id
}
