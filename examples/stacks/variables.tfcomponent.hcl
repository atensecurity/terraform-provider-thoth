variable "apex_domain" {
  type        = string
  description = "Apex domain used for derived GovAPI host."
  default     = "atensecurity.com"
}

variable "tenant_id" {
  type        = string
  description = "Tenant slug."
}

variable "compliance_profile" {
  type        = string
  description = "Tenant compliance profile."
  default     = "soc2"
}

variable "regulatory_regimes" {
  type        = list(string)
  description = "Explicit regulatory regimes for baseline pack auto-loading."
  default     = ["soc2"]
}
