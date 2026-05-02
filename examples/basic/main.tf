terraform {
  required_version = ">= 1.5"

  required_providers {
    thoth = {
      source  = "atensecurity/thoth"
      version = "~> 0.1.1"
    }
  }
}

provider "thoth" {
  tenant_id          = var.tenant_id
  apex_domain        = var.apex_domain
  admin_bearer_token = var.admin_bearer_token
}

resource "thoth_tenant_settings" "tenant" {
  compliance_profile = var.compliance_profile
  shadow_low         = "allow"
  shadow_medium      = "step_up"
  shadow_high        = "block"
  shadow_critical    = "block"

  webhook_enabled = true
  webhook_url     = var.webhook_url
  webhook_secret  = var.webhook_secret

  siem_provider         = var.siem_provider
  siem_webhook_enabled  = true
  siem_webhook_url      = var.webhook_url
  siem_webhook_secret   = var.webhook_secret
  siem_webhook_provider = var.siem_provider
}

resource "thoth_mdm_provider" "jamf" {
  provider_name = "jamf"
  name          = "Jamf Pro"
  enabled       = true

  config_json = jsonencode({
    base_url      = var.jamf_base_url
    client_id     = var.jamf_client_id
    client_secret = var.jamf_client_secret
  })
}

resource "thoth_mdm_sync" "jamf_sync" {
  provider_name       = thoth_mdm_provider.jamf.provider_name
  wait_for_completion = true
  timeout_seconds     = 180
}

data "thoth_api_key_metrics" "metrics" {}

data "thoth_governance_tools" "tools" {
  window_hours = 24
  limit        = 100
}

resource "thoth_webhook_test" "delivery" {
  trigger = "initial"
}

resource "thoth_policy_sync" "tenant_policies" {
  trigger               = "post-bootstrap"
  wait_for_completion   = true
  poll_interval_seconds = 5
  timeout_seconds       = 180
}
