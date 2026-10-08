# Optional scheduled scan: a Container Apps job running as the reader identity. It has no ingress.
# Created only when enable_scan_job is true and scan_image is set; this repository does not build
# or publish an image.
resource "azurerm_container_app_environment" "this" {
  count                          = local.run_job ? 1 : 0
  name                           = "cae-idsec-${local.suffix}"
  location                       = azurerm_resource_group.this.location
  resource_group_name            = azurerm_resource_group.this.name
  log_analytics_workspace_id     = azurerm_log_analytics_workspace.this.id
  infrastructure_subnet_id       = var.private_networking ? azurerm_subnet.jobs[0].id : null
  internal_load_balancer_enabled = var.private_networking ? true : null
  tags                           = local.tags

  dynamic "workload_profile" {
    for_each = var.private_networking ? [1] : []
    content {
      name                  = "Consumption"
      workload_profile_type = "Consumption"
    }
  }
}

resource "azurerm_container_app_job" "scan" {
  count                        = local.run_job ? 1 : 0
  name                         = "caj-idsec-scan-${var.environment}"
  location                     = azurerm_resource_group.this.location
  resource_group_name          = azurerm_resource_group.this.name
  container_app_environment_id = azurerm_container_app_environment.this[0].id
  replica_timeout_in_seconds   = 1800
  replica_retry_limit          = 0
  tags                         = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.scanner.id]
  }

  schedule_trigger_config {
    cron_expression          = var.scan_schedule
    parallelism              = 1
    replica_completion_count = 1
  }

  template {
    container {
      name   = "scan"
      image  = var.scan_image
      cpu    = 0.5
      memory = "1Gi"
      args   = ["idsec", "collect", "--live", "--out", "/tmp/tenant"]

      env {
        name  = "AZURE_CLIENT_ID"
        value = azurerm_user_assigned_identity.scanner.client_id
      }
      env {
        name  = "IDSEC_SUBSCRIPTIONS"
        value = join(",", [for s in local.scan_scopes : trimprefix(s, "/subscriptions/")])
      }
    }
  }
}
