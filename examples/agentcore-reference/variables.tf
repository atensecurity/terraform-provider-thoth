variable "tenant_id" {
  description = "Your Thoth workspace (tenant) ID."
  type        = string
}

variable "owner_email" {
  description = "The person responsible for the agent."
  type        = string
}

variable "pack_id" {
  description = <<-EOT
    The profile or compliance pack assigned to the agent. There is no profile
    named "healthcare": the profiles are safe-default, coding-agent,
    finance-operations and customer-support. The default is the HIPAA technical
    safeguards pack, which is a set of rules the agent is checked against, not
    a statement that a deployment is HIPAA compliant. Confirm the choice with
    your compliance team, and use "safe-default" if you want the baseline only.
  EOT
  type        = string
  default     = "hipaa-164-312"
}

variable "enforcement_mode" {
  description = "observe (record and allow everything) or enforce (decisions apply)."
  type        = string
  default     = "observe"

  validation {
    condition     = contains(["observe", "enforce"], var.enforcement_mode)
    error_message = "enforcement_mode must be observe or enforce."
  }
}

variable "key_ttl_seconds" {
  description = "How long the runtime key lasts. Rotate it before it expires."
  type        = number
  default     = 2592000 # 30 days
}
