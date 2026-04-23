variable "tenant_id" {
  description = "Tenant slug used in GovAPI routes."
  type        = string

  validation {
    condition     = length(trimspace(var.tenant_id)) > 0
    error_message = "tenant_id must be non-empty."
  }
}

variable "govapi_url" {
  description = "GovAPI base URL (must use HTTPS)."
  type        = string

  validation {
    condition     = can(regex("^https://", var.govapi_url))
    error_message = "govapi_url must start with https://."
  }
}

variable "bootstrap_script_path" {
  description = "Path (relative to module directory) to the shell wrapper that invokes thothctl bootstrap."
  type        = string
  default     = "../../scripts/thothctl_bootstrap.sh"
}

variable "thothctl_bin" {
  description = "thothctl binary path or command name available to Terraform runners."
  type        = string
  default     = "thothctl"
}

variable "admin_bearer_token" {
  description = "Admin bearer token used by thothctl to call GovAPI."
  type        = string
  default     = ""
  sensitive   = true
}

variable "admin_bearer_token_file" {
  description = "Path to file containing the admin bearer token (recommended over inline token)."
  type        = string
  default     = ""

  validation {
    condition = (
      length(trimspace(var.admin_bearer_token)) > 0 ||
      length(trimspace(var.admin_bearer_token_file)) > 0
    )
    error_message = "Set either admin_bearer_token or admin_bearer_token_file."
  }
}

variable "timeout_seconds" {
  description = "thothctl request timeout in seconds."
  type        = number
  default     = 20
}

variable "compliance_profile" {
  description = "Compliance profile applied to tenant settings."
  type        = string
  default     = "soc2"
}

variable "shadow_low" {
  description = "Default action for low-risk shadow decisions."
  type        = string
  default     = "allow"
}

variable "shadow_medium" {
  description = "Default action for medium-risk shadow decisions."
  type        = string
  default     = "step_up"
}

variable "shadow_high" {
  description = "Default action for high-risk shadow decisions."
  type        = string
  default     = "block"
}

variable "shadow_critical" {
  description = "Default action for critical-risk shadow decisions."
  type        = string
  default     = "block"
}

variable "tool_risk_overrides" {
  description = "List of KEY=RISK_TIER overrides sent as --tool-risk-override."
  type        = list(string)
  default     = []
}

variable "webhook_url" {
  description = "Optional outbound webhook URL."
  type        = string
  default     = ""

  validation {
    condition     = var.webhook_url == "" || can(regex("^https://", var.webhook_url))
    error_message = "webhook_url must be empty or start with https://."
  }
}

variable "webhook_secret" {
  description = "Optional webhook signing secret."
  type        = string
  default     = ""
  sensitive   = true
}

variable "webhook_enabled" {
  description = "Explicit webhook enabled flag. Null lets thothctl infer from webhook URL."
  type        = bool
  default     = null
  nullable    = true
}

variable "test_webhook" {
  description = "Whether to execute webhook test endpoint after settings update."
  type        = bool
  default     = false
}

variable "mdm_provider" {
  description = "Optional provider slug (jamf|intune|workspace_one|custom). Empty disables MDM upsert."
  type        = string
  default     = ""

  validation {
    condition = contains(
      ["", "jamf", "intune", "workspace_one", "custom"],
      lower(trimspace(var.mdm_provider))
    )
    error_message = "mdm_provider must be one of: jamf, intune, workspace_one, custom, or empty."
  }
}

variable "mdm_name" {
  description = "Optional display name for the MDM provider."
  type        = string
  default     = ""
}

variable "mdm_enabled" {
  description = "Optional MDM enabled flag. Null lets wrapper skip the CLI flag."
  type        = bool
  default     = null
  nullable    = true
}

variable "mdm_config_file" {
  description = "Optional path to JSON object file passed as --mdm-config-file."
  type        = string
  default     = ""
}

variable "start_mdm_sync" {
  description = "Start MDM provider sync immediately after upsert."
  type        = bool
  default     = false
}

variable "json_output" {
  description = "Return thothctl summary output as JSON."
  type        = bool
  default     = true
}

variable "trigger_version" {
  description = "Manual replay trigger. Change this value to force rerun even when config is unchanged."
  type        = string
  default     = "v1"
}
