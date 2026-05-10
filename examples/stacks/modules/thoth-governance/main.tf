resource "thoth_governance_settings" "this" {
  compliance_profile = var.compliance_profile
  regulatory_regimes = var.regulatory_regimes
  shadow_low         = "allow"
  shadow_medium      = "step_up"
  shadow_high        = "block"
  shadow_critical    = "block"
}

output "tenant_settings_id" {
  description = "Settings resource ID"
  value       = thoth_governance_settings.this.id
}
