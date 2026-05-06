output "tenant_governance_settings_id" {
  description = "Tenant governance settings resource identifier."
  value       = thoth_governance_settings.tenant_policy.id
}

output "mdm_sync_job_status" {
  description = "Latest MDM sync status."
  value       = thoth_mdm_sync.jamf_sync.status
}

output "governance_tools_json" {
  description = "Tool telemetry snapshot in JSON."
  value       = data.thoth_governance_tools.tools.data_json
}
