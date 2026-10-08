# Optional: the scanner's read-only Microsoft Graph application permissions. Off by default because
# granting app roles needs a privileged deployer; the alternative is an admin granting them once by
# hand (docs/adopt-this.md lists the exact permissions and the az/Graph calls).
data "azuread_service_principal" "msgraph" {
  count     = var.grant_graph_permissions ? 1 : 0
  client_id = local.graph_app_id
}

resource "azuread_app_role_assignment" "graph" {
  for_each            = var.grant_graph_permissions ? local.graph_permissions : toset([])
  app_role_id         = data.azuread_service_principal.msgraph[0].app_role_ids[each.value]
  principal_object_id = azurerm_user_assigned_identity.scanner.principal_id
  resource_object_id  = data.azuread_service_principal.msgraph[0].object_id
}
