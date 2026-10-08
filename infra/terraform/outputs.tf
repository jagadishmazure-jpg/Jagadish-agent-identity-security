output "resource_group_name" {
  description = "Resource group holding the scanner resources."
  value       = azurerm_resource_group.this.name
}

output "scanner_client_id" {
  description = "Client ID of the reader identity (AZURE_CLIENT_ID for DefaultAzureCredential and azure/login)."
  value       = azurerm_user_assigned_identity.scanner.client_id
}

output "scanner_principal_id" {
  description = "Object ID of the reader identity (for granting Graph permissions by hand)."
  value       = azurerm_user_assigned_identity.scanner.principal_id
}

output "role_definition_id" {
  description = "Resource ID of the custom Identity Posture Reader role."
  value       = azurerm_role_definition.reader.role_definition_resource_id
}

output "log_analytics_workspace_id" {
  description = "Workspace receiving job logs."
  value       = azurerm_log_analytics_workspace.this.id
}

output "scan_job_name" {
  description = "Name of the scheduled scan job, or empty when not created."
  value       = local.run_job ? azurerm_container_app_job.scan[0].name : ""
}
