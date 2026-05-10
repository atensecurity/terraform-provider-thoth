output "tenant_governance_settings_id" {
  description = "Tenant governance settings resource identifier."
  value       = thoth_governance_settings.tenant_policy.id
}

output "mdm_sync_job_status" {
  description = "Latest MDM sync status."
  value       = thoth_mdm_sync.jamf_sync.status
}

output "policy_bundle_ids" {
  description = "Created policy bundle version IDs."
  value = {
    standard_dlp_opa      = thoth_policy_bundle.standard_dlp_opa.id
    least_privilege_cedar = thoth_policy_bundle.least_privilege_cedar.id
  }
}

output "governance_tools_json" {
  description = "Tool telemetry snapshot in JSON."
  value       = data.thoth_governance_tools.tools.data_json
}
