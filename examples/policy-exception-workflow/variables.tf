variable "tenant_id" {
  description = "Tenant slug used by GovAPI path scoping."
  type        = string
}

variable "apex_domain" {
  description = "Apex domain used for derived GovAPI host."
  type        = string
  default     = "atensecurity.com"
}

variable "violation_id" {
  description = "Violation ID being exception-reviewed."
  type        = string
}

variable "hold_token" {
  description = "Optional hold token for STEP_UP-linked exceptions."
  type        = string
  default     = ""
}

variable "agent_id" {
  description = "Agent ID that triggered the exception request."
  type        = string
  default     = "crm-agent"
}

variable "tool_name" {
  description = "Tool/action tied to the exception request."
  type        = string
  default     = "export_records"
}

variable "requested_by" {
  description = "Requester identity (for example Slack user id)."
  type        = string
}

variable "business_justification" {
  description = "Business reason for the exception."
  type        = string
}

variable "frequency_estimate" {
  description = "Expected frequency for this action."
  type        = string
  default     = "weekly"
}

variable "data_sensitivity" {
  description = "Data sensitivity touched by the action."
  type        = string
  default     = "financial"
}

variable "alternatives_considered" {
  description = "Alternative approaches evaluated before requesting exception."
  type        = string
  default     = ""
}

variable "security_reviewer" {
  description = "Security reviewer identity that approves/rejects requests."
  type        = string
}

variable "review_decision" {
  description = "Review decision for policy exception."
  type        = string
  default     = "approve"
}

variable "review_notes" {
  description = "Reviewer notes recorded in audit logs."
  type        = string
  default     = "Approved for controlled rollout via govapi apply channel."
}

variable "policy_owner" {
  description = "Owner metadata for generated policy artifacts."
  type        = string
  default     = "security-platform"
}

variable "target_environment" {
  description = "Target environment for artifact synthesis and apply."
  type        = string
  default     = "prod"
}

variable "policy_format" {
  description = "Preferred policy format for apply payload."
  type        = string
  default     = "rego"
}

variable "enforcement_mode" {
  description = "Policy bundle enforcement mode for applied artifact."
  type        = string
  default     = "enforce"
}
