resource "thoth_tenant_settings" "this" {
  compliance_profile = var.compliance_profile
  shadow_low         = "allow"
  shadow_medium      = "step_up"
  shadow_high        = "block"
  shadow_critical    = "block"
}

output "tenant_settings_id" {
  description = "Settings resource ID"
  value       = thoth_tenant_settings.this.id
}
