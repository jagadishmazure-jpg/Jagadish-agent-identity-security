locals {
  short_location = {
    eastus2    = "eus2"
    westus2    = "wus2"
    westeurope = "weu"
  }
  suffix = "${var.org_slug}-${var.environment}-${local.short_location[var.location]}"

  tags = merge({
    workload    = "idsec"
    environment = var.environment
    managed_by  = "terraform"
    data        = "identity-posture"
  }, var.tags)

  # One role definition, shared with Bicep (loadJsonContent) so the two cannot drift.
  role = jsondecode(file("${path.module}/../role/identity-posture-reader.json"))

  scan_scopes = length(var.scan_subscription_ids) > 0 ? [for s in var.scan_subscription_ids : "/subscriptions/${s}"] : [data.azurerm_subscription.current.id]

  # Read-only Microsoft Graph application permissions the collectors need (src/idsec/collectors/live.py).
  graph_app_id = "00000003-0000-0000-c000-000000000000"
  graph_permissions = toset([
    "User.Read.All",
    "GroupMember.Read.All",
    "Application.Read.All",
    "DelegatedPermissionGrant.Read.All",
    "RoleManagement.Read.Directory",
    "Policy.Read.All",
    "AuditLog.Read.All",
  ])

  run_job      = var.enable_scan_job && var.scan_image != ""
  scan_command = trimspace("idsec collect --live --out /tmp/tenant ${var.scan_collect_args} && idsec scan && idsec soc-export")
}
