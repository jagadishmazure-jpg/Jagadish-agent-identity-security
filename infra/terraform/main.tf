data "azurerm_subscription" "current" {}

resource "azurerm_resource_group" "this" {
  name     = "rg-idsec-${local.suffix}-001"
  location = var.location
  tags     = local.tags
}

# ---------------------------------------------------------------------------------------------
# Reader identity: a user-assigned managed identity. Inside Azure the scan job uses it directly;
# from GitHub Actions it is reached through a federated credential pinned to one environment, so
# no secret exists anywhere.
# ---------------------------------------------------------------------------------------------
resource "azurerm_user_assigned_identity" "scanner" {
  name                = "id-idsec-scanner-${local.suffix}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.tags
}

resource "azurerm_federated_identity_credential" "github" {
  count                     = var.github_repository == "" ? 0 : 1
  name                      = "github-${var.environment}"
  user_assigned_identity_id = azurerm_user_assigned_identity.scanner.id
  audience                  = ["api://AzureADTokenExchange"]
  issuer                    = "https://token.actions.githubusercontent.com"
  subject                   = "repo:${var.github_repository}:environment:${var.environment}"
}

# ---------------------------------------------------------------------------------------------
# Custom read-only role, assignable only to the scanned subscriptions, assigned to the scanner.
# No write, delete or action verbs except the two metadata/agent read data actions.
# ---------------------------------------------------------------------------------------------
resource "azurerm_role_definition" "reader" {
  name              = "${local.role.roleName} (${local.suffix})"
  scope             = local.scan_scopes[0]
  description       = local.role.description
  assignable_scopes = local.scan_scopes

  permissions {
    actions      = local.role.actions
    data_actions = local.role.dataActions
  }
}

resource "azurerm_role_assignment" "reader" {
  for_each           = toset(local.scan_scopes)
  scope              = each.value
  role_definition_id = azurerm_role_definition.reader.role_definition_resource_id
  principal_id       = azurerm_user_assigned_identity.scanner.principal_id
  principal_type     = "ServicePrincipal"
  description        = "Identity posture scanner (read-only)"
}

# ---------------------------------------------------------------------------------------------
# Log Analytics: job logs and scan results. Entra ID auth only (no shared keys).
# ---------------------------------------------------------------------------------------------
resource "azurerm_log_analytics_workspace" "this" {
  name                         = "law-idsec-${local.suffix}"
  location                     = azurerm_resource_group.this.location
  resource_group_name          = azurerm_resource_group.this.name
  sku                          = "PerGB2018"
  retention_in_days            = var.retention_in_days
  daily_quota_gb               = var.daily_quota_gb
  local_authentication_enabled = false
  tags                         = local.tags
}

resource "azurerm_monitor_diagnostic_setting" "workspace_audit" {
  name                       = "diag-audit"
  target_resource_id         = azurerm_log_analytics_workspace.this.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id

  enabled_log {
    category_group = "audit"
  }
}
