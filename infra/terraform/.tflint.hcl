plugin "terraform" {
  enabled = true
  preset  = "recommended"
}

plugin "azurerm" {
  enabled = true
  version = "0.32.0"
  source  = "github.com/terraform-linters/tflint-ruleset-azurerm"
}

# This stack is created and destroyed by deploy.yml / teardown.yml and holds no tenant data of
# its own, so prevent_destroy would only block the teardown workflow.
rule "azurerm_resources_missing_prevent_destroy" {
  enabled = false
}
