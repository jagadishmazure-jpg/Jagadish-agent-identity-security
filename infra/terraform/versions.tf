terraform {
  required_version = ">= 1.9.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.8"
    }
    # Only for the optional Microsoft Graph application permissions (var.grant_graph_permissions).
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.4"
    }
  }
}
