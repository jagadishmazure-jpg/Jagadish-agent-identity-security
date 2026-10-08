# Offline plan tests: mocked providers, no Azure credentials, nothing created.
#   terraform init -backend=false && terraform test
mock_provider "azurerm" {
  mock_data "azurerm_subscription" {
    defaults = {
      id              = "/subscriptions/00000000-0000-0000-0000-000000000002"
      subscription_id = "00000000-0000-0000-0000-000000000002"
    }
  }
}

mock_provider "azuread" {
  mock_data "azuread_service_principal" {
    defaults = {
      object_id = "00000000-0000-0000-0000-000000000010"
      app_role_ids = {
        "User.Read.All"                     = "00000000-0000-0000-0000-000000000011"
        "GroupMember.Read.All"              = "00000000-0000-0000-0000-000000000012"
        "Application.Read.All"              = "00000000-0000-0000-0000-000000000013"
        "DelegatedPermissionGrant.Read.All" = "00000000-0000-0000-0000-000000000014"
        "RoleManagement.Read.Directory"     = "00000000-0000-0000-0000-000000000015"
        "Policy.Read.All"                   = "00000000-0000-0000-0000-000000000016"
        "AuditLog.Read.All"                 = "00000000-0000-0000-0000-000000000017"
      }
    }
  }
}

# Values that are only known after apply, made available at plan time for the assertions.
override_resource {
  target          = azurerm_user_assigned_identity.scanner
  override_during = plan
  values = {
    id           = "/subscriptions/00000000-0000-0000-0000-000000000002/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-idsec-scanner"
    principal_id = "00000000-0000-0000-0000-000000000004"
    client_id    = "00000000-0000-0000-0000-000000000005"
  }
}

override_resource {
  target          = azurerm_role_definition.reader
  override_during = plan
  values = {
    role_definition_resource_id = "/subscriptions/00000000-0000-0000-0000-000000000002/providers/Microsoft.Authorization/roleDefinitions/00000000-0000-0000-0000-000000000006"
  }
}

run "dev_defaults" {
  command = plan

  variables {
    environment = "dev"
    org_slug    = "kestrel"
  }

  assert {
    condition     = azurerm_resource_group.this.name == "rg-idsec-kestrel-dev-eus2-001"
    error_message = "resource group follows the CAF naming pattern"
  }

  assert {
    condition     = alltrue([for a in azurerm_role_definition.reader.permissions[0].actions : endswith(a, "/read")])
    error_message = "the custom role grants read actions only"
  }

  assert {
    condition     = alltrue([for a in azurerm_role_definition.reader.permissions[0].data_actions : endswith(a, "/readMetadata/action") || endswith(a, "/agents/read")])
    error_message = "data actions are limited to secret metadata and agent definitions"
  }

  assert {
    condition     = !anytrue([for a in azurerm_role_definition.reader.permissions[0].data_actions : can(regex("secrets/getSecret", a))])
    error_message = "the scanner can never read a secret value"
  }

  assert {
    condition     = tolist(azurerm_role_definition.reader.assignable_scopes) == tolist(["/subscriptions/00000000-0000-0000-0000-000000000002"])
    error_message = "with no scan list, the role is assignable to the deployment subscription only"
  }

  assert {
    condition     = length(azurerm_role_assignment.reader) == 1
    error_message = "one assignment per scanned subscription"
  }

  assert {
    condition     = !azurerm_log_analytics_workspace.this.local_authentication_enabled
    error_message = "workspace accepts Entra ID auth only"
  }

  assert {
    condition     = length(azurerm_federated_identity_credential.github) == 0
    error_message = "no federated credential unless a repository is named"
  }

  assert {
    condition     = length(azurerm_container_app_job.scan) == 0 && length(azurerm_virtual_network.this) == 0
    error_message = "scan job and network are opt-in"
  }

  assert {
    condition     = length(azuread_app_role_assignment.graph) == 0
    error_message = "Graph permissions are opt-in"
  }
}

run "github_federation_is_pinned_to_an_environment" {
  command = plan

  variables {
    environment       = "prod"
    org_slug          = "kestrel"
    github_repository = "kestrelridge/identity-posture"
  }

  assert {
    condition     = azurerm_federated_identity_credential.github[0].subject == "repo:kestrelridge/identity-posture:environment:prod"
    error_message = "subject is pinned to the protected environment, never a branch pattern or pull_request"
  }
}

run "multiple_subscriptions" {
  command = plan

  variables {
    environment           = "dev"
    org_slug              = "kestrel"
    scan_subscription_ids = ["00000000-0000-0000-0000-0000000000a1", "00000000-0000-0000-0000-0000000000a2"]
  }

  assert {
    condition     = length(azurerm_role_assignment.reader) == 2 && length(azurerm_role_definition.reader.assignable_scopes) == 2
    error_message = "one assignment and one assignable scope per subscription"
  }
}

run "scan_job_needs_an_image" {
  command = plan

  variables {
    environment     = "dev"
    org_slug        = "kestrel"
    enable_scan_job = true
  }

  assert {
    condition     = length(azurerm_container_app_job.scan) == 0
    error_message = "no job without an image"
  }
}

run "scan_job_private" {
  command = plan

  variables {
    environment        = "prod"
    org_slug           = "kestrel"
    enable_scan_job    = true
    scan_image         = "example.azurecr.io/idsec:1"
    private_networking = true
  }

  assert {
    condition     = azurerm_container_app_job.scan[0].identity[0].type == "UserAssigned" && azurerm_container_app_job.scan[0].replica_retry_limit == 0
    error_message = "job runs as the reader identity and does not retry a failed scan"
  }

  assert {
    condition     = azurerm_container_app_environment.this[0].internal_load_balancer_enabled == true
    error_message = "private mode uses an internal environment"
  }

  assert {
    condition     = length(azurerm_subnet.jobs) == 1 && length(azurerm_network_security_group.jobs) == 1
    error_message = "private mode creates a delegated subnet with an NSG"
  }
}

run "graph_permissions_are_read_only" {
  command = plan

  variables {
    environment             = "dev"
    org_slug                = "kestrel"
    grant_graph_permissions = true
  }

  assert {
    condition     = length(azuread_app_role_assignment.graph) == 7
    error_message = "seven Graph application permissions"
  }

  assert {
    condition     = alltrue([for k, v in azuread_app_role_assignment.graph : can(regex("\\.Read(\\.|$)", k))])
    error_message = "every Graph permission is a Read permission"
  }
}

run "rejects_unknown_environment" {
  command = plan

  variables {
    environment = "staging"
    org_slug    = "kestrel"
  }

  expect_failures = [var.environment]
}
