terraform {
  required_providers {
    thoth = {
      source  = "atensecurity/thoth"
      version = ">= 0.1.0"
    }
  }
}

provider "thoth" {
  tenant_id  = var.tenant_id
  govapi_url = var.govapi_url
  token      = var.admin_bearer_token
}

# Placeholder example resources (to be implemented in provider)
# resource "thoth_tenant_settings" "this" {}
# resource "thoth_mdm_provider" "jamf" {}
