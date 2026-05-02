variable "apex_domain" {
  type        = string
  description = "Apex domain used for derived GovAPI host."
  default     = "atensecurity.com"
}

variable "tenant_id" {
  type        = string
  description = "Tenant slug."
}

variable "admin_bearer_token" {
  type        = string
  description = "Admin bearer token for GovAPI."
  ephemeral   = true
}

variable "compliance_profile" {
  type        = string
  description = "Tenant compliance profile."
  default     = "soc2"
}
