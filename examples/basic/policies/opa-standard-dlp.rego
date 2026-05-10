package thoth.policies.standard_dlp

# thoth_rule effect=BLOCK action_prefix=tool_call: purpose=customer-facing min_sensitivity=internal reason=Blocked_due_to_purpose_sensitivity_mismatch
# thoth_rule effect=STEP_UP action_prefix=tool_call: purpose=customer-facing min_sensitivity=internal reason=Customer_facing_access_requires_review
# thoth_rule effect=BLOCK min_behavioral_score=0.95 reason=Critical_behavioral_anomaly_block

default allow := true

# Guardrail: customer-facing requests must remain public only.
deny[msg] if {
  input.principal.id != ""
  startswith(input.action, "tool_call:")
  input.context.purpose == "customer-facing"
  input.context.sensitivity_label != "public"
  msg := "customer-facing purpose cannot retrieve internal or confidential data"
}

# Guardrail: very high anomaly score forces deterministic block.
deny[msg] if {
  input.principal.id != ""
  input.action != ""
  input.context.task_id != ""
  input.moses_metrics.behavioral_score >= 0.95
  msg := "critical behavioral anomaly"
}

allow if {
  not deny[_]
}
