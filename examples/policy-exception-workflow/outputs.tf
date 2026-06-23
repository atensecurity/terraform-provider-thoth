output "policy_exception_request_id" {
  description = "Policy exception request identifier."
  value       = thoth_policy_exception.crm_export.request_id
}

output "policy_exception_status" {
  description = "Latest exception status after review."
  value       = thoth_policy_exception_review.crm_export_review.status
}

output "policy_change_artifact_apply_id" {
  description = "Synthetic apply operation identifier."
  value       = thoth_policy_change_artifact_apply.crm_export_apply.id
}

output "policy_change_artifact_json" {
  description = "Artifact payload snapshot for this request."
  value       = data.thoth_policy_change_artifact.current.data_json
}

output "pending_policy_exceptions_json" {
  description = "Current pending exception queue snapshot."
  value       = data.thoth_policy_exceptions.pending.data_json
}
