terraform {
  required_providers {
    thoth = {
      source = "atensecurity/thoth"
    }
  }
}

variable "tenant_id" {
  type        = string
  description = "Existing tenant to govern. Credentials come from provider environment variables."
}

provider "thoth" {
  tenant_id = var.tenant_id
}

resource "thoth_governance_settings" "assessment" {
  declared_regulatory_regimes = ["fedramp", "cmmc_l1", "iso_27001"]
  compliance_enforcement_mode = "observe"
}

output "compliance_coverage" {
  value = thoth_governance_settings.assessment.compliance_coverage
}

output "regimes_without_controls" {
  value = thoth_governance_settings.assessment.regimes_without_controls
}
