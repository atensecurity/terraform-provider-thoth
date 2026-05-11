terraform {
  required_version = ">= 1.5"

  required_providers {
    thoth = {
      source  = "atensecurity/thoth"
      version = ">= 0.1.9"
    }
  }
}

provider "thoth" {
  tenant_id   = var.tenant_id
  apex_domain = var.apex_domain
  # Auth resolves from THOTH_API_KEY (org-scoped).
}

resource "thoth_governance_settings" "tenant_policy" {
  compliance_profile = var.compliance_profile
  regulatory_regimes = var.regulatory_regimes
  shadow_low         = "allow"
  shadow_medium      = "step_up"
  shadow_high        = "block"
  shadow_critical    = "block"
}

resource "thoth_webhook_settings" "tenant_webhook" {
  webhook_enabled = true
  webhook_url     = var.webhook_url
  webhook_secret  = var.webhook_secret
}

resource "thoth_siem_settings" "tenant_siem" {
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

resource "thoth_policy_bundle" "standard_dlp_opa" {
  name             = "standard-dlp"
  description      = "Customer-agnostic purpose/sensitivity DLP baseline"
  framework        = "OPA"
  raw_policy       = file("${path.module}/policies/opa-standard-dlp.rego")
  enforcement_mode = "enforce"
}

resource "thoth_policy_bundle" "least_privilege_cedar" {
  name             = "least-privilege-analyst"
  description      = "Least-privilege analyst baseline for selected agents"
  framework        = "CEDAR"
  raw_policy       = file("${path.module}/policies/cedar-least-privilege-analyst.cedar")
  assignments      = ["agent:security-analyst-agent", "agent:coding-agent"]
  enforcement_mode = "enforce"
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
  trigger               = "post-bootstrap-with-sidecars"
  wait_for_completion   = true
  poll_interval_seconds = 5
  timeout_seconds       = 180

  depends_on = [
    thoth_policy_bundle.standard_dlp_opa,
    thoth_policy_bundle.least_privilege_cedar,
  ]
}
