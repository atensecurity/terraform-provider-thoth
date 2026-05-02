output "tenant_settings_id" {
  description = "Tenant settings resource identifier."
  value       = thoth_tenant_settings.tenant.id
}

output "mdm_sync_job_status" {
  description = "Latest MDM sync status."
  value       = thoth_mdm_sync.jamf_sync.status
}

output "governance_tools_json" {
  description = "Tool telemetry snapshot in JSON."
  value       = data.thoth_governance_tools.tools.data_json
}
