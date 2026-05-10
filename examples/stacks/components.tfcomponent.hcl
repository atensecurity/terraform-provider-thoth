component "tenant_governance" {
  source = "./modules/thoth-governance"

  inputs = {
    compliance_profile = var.compliance_profile
    regulatory_regimes = var.regulatory_regimes
  }

  providers = {
    thoth = provider.thoth.main
  }
}

output "tenant_settings_id" {
  type        = string
  description = "Tenant settings resource ID"
  value       = component.tenant_governance.tenant_settings_id
}
