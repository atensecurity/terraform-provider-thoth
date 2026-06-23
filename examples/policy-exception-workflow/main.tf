terraform {
  required_version = ">= 1.5"

  required_providers {
    thoth = {
      source  = "atensecurity/thoth"
      version = ">= 0.1.10"
    }
  }
}

provider "thoth" {
  tenant_id   = var.tenant_id
  apex_domain = var.apex_domain
  # Auth resolves from THOTH_API_KEY (org-scoped).
}

resource "thoth_policy_exception" "crm_export" {
  violation_id            = var.violation_id
  hold_token              = var.hold_token
  agent_id                = var.agent_id
  tool_name               = var.tool_name
  requested_by            = var.requested_by
  business_justification  = var.business_justification
  frequency_estimate      = var.frequency_estimate
  data_sensitivity        = var.data_sensitivity
  alternatives_considered = var.alternatives_considered
}

resource "thoth_policy_exception_review" "crm_export_review" {
  request_id         = thoth_policy_exception.crm_export.request_id
  review_decision    = var.review_decision
  reviewed_by        = var.security_reviewer
  review_notes       = var.review_notes
  owner              = var.policy_owner
  target_environment = var.target_environment
}

resource "thoth_policy_change_artifact_apply" "crm_export_apply" {
  request_id         = thoth_policy_exception.crm_export.request_id
  applied_by         = var.security_reviewer
  apply_channel      = "govapi"
  policy_format      = var.policy_format
  bundle_name        = "exception-${thoth_policy_exception.crm_export.request_id}"
  bundle_description = "Policy exception rollout for ${var.tool_name}"
  assignments        = ["all"]
  enforcement_mode   = var.enforcement_mode
  status             = "active"

  depends_on = [thoth_policy_exception_review.crm_export_review]
}

data "thoth_policy_exception" "current" {
  request_id = thoth_policy_exception.crm_export.request_id
}

data "thoth_policy_exceptions" "pending" {
  status = "pending"
  limit  = 100
  offset = 0
}

data "thoth_policy_change_artifact" "current" {
  request_id = thoth_policy_exception.crm_export.request_id
}

data "thoth_policy_change_artifacts" "env_artifacts" {
  target_environment = var.target_environment
  limit              = 100
  offset             = 0
}
