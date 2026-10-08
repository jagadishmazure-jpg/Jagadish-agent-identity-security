variable "environment" {
  description = "Deployment environment."
  type        = string
  validation {
    condition     = contains(["dev", "prod"], var.environment)
    error_message = "environment must be dev or prod."
  }
}

variable "location" {
  description = "Azure region for the resource group, workspace and optional scan job."
  type        = string
  default     = "eastus2"
  validation {
    condition     = contains(["eastus2", "westus2", "westeurope"], var.location)
    error_message = "location must be one of eastus2, westus2, westeurope."
  }
}

variable "org_slug" {
  description = "Short lowercase name used in resource names."
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9]{1,11}$", var.org_slug))
    error_message = "org_slug must be 2-12 lowercase letters or digits, starting with a letter."
  }
}

variable "scan_subscription_ids" {
  description = "Subscriptions the scanner may read. Empty means the deployment subscription only."
  type        = list(string)
  default     = []
}

variable "github_repository" {
  description = "owner/repo allowed to sign in as the scanner through GitHub OIDC. Empty disables the federated credential."
  type        = string
  default     = ""
  validation {
    condition     = var.github_repository == "" || can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repository))
    error_message = "github_repository must look like owner/repo."
  }
}

variable "retention_in_days" {
  description = "Log Analytics retention for scan results and job logs."
  type        = number
  default     = 30
}

variable "daily_quota_gb" {
  description = "Log Analytics daily ingestion cap (GB)."
  type        = number
  default     = 1
}

variable "enable_scan_job" {
  description = "Create the scheduled Container Apps job that runs the scanner as the reader identity."
  type        = bool
  default     = false
}

variable "scan_image" {
  description = "Container image for the scan job (built and published by you; this repository does not publish one)."
  type        = string
  default     = ""
}

variable "scan_collect_args" {
  description = "Extra arguments for the job's collect step, e.g. --vault NAME --project ID=ENDPOINT."
  type        = string
  default     = ""
}

variable "scan_schedule" {
  description = "Cron expression (UTC) for the scan job."
  type        = string
  default     = "0 6 * * 1"
}

variable "private_networking" {
  description = "Run the scan job in an internal Container Apps environment inside a dedicated VNet."
  type        = bool
  default     = false
}

variable "vnet_address_space" {
  description = "Address space for the optional VNet (a /27 subnet is carved for the job environment)."
  type        = string
  default     = "10.42.0.0/24"
}

variable "grant_graph_permissions" {
  description = "Grant the scanner its read-only Microsoft Graph application permissions. Needs a deployer allowed to grant app roles (Privileged Role Administrator)."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Extra tags merged into every resource."
  type        = map(string)
  default     = {}
}
