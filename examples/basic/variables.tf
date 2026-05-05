variable "tenant_id" {
  description = "Tenant slug used by GovAPI path scoping."
  type        = string
}

variable "apex_domain" {
  description = "Apex domain used for derived GovAPI host."
  type        = string
  default     = "atensecurity.com"
}

variable "org_api_key" {
  description = "Org-level API key used for Thoth control-plane APIs in CI/CD."
  type        = string
  sensitive   = true
}

variable "compliance_profile" {
  description = "Compliance profile for default governance controls."
  type        = string
  default     = "soc2"
}

variable "siem_provider" {
  description = "SIEM provider slug."
  type        = string
  default     = "splunk"
}

variable "webhook_url" {
  description = "Webhook endpoint URL used for SIEM/SOAR delivery."
  type        = string
}

variable "webhook_secret" {
  description = "Webhook signing secret."
  type        = string
  sensitive   = true
}

variable "jamf_base_url" {
  description = "Jamf API base URL."
  type        = string
  default     = ""
}

variable "jamf_client_id" {
  description = "Jamf OAuth client ID."
  type        = string
  default     = ""
}

variable "jamf_client_secret" {
  description = "Jamf OAuth client secret."
  type        = string
  sensitive   = true
  default     = ""
}
