variable "compliance_profile" {
  description = "Compliance profile for tenant settings"
  type        = string
}

variable "regulatory_regimes" {
  description = "Explicit regulatory regimes used for baseline pack auto-loading"
  type        = list(string)
  default     = ["soc2"]
}
