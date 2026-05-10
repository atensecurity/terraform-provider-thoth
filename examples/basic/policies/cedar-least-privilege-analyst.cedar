// thoth_rule effect=STEP_UP action_prefix=tool_call:query_ purpose=internal min_sensitivity=confidential reason=High_sensitivity_query_requires_step_up
// thoth_rule effect=BLOCK action_prefix=tool_call:query_ purpose=customer-facing min_sensitivity=internal reason=Customer_facing_query_blocked_for_non_public_data

permit (
  principal,
  action,
  resource
)
when {
  context.principal_id != "" &&
  context.purpose == "internal" &&
  context.action != ""
};

forbid (
  principal,
  action,
  resource
)
when {
  context.purpose == "customer-facing" &&
  context.action != "" &&
  (
    context.sensitivity_label == "internal" ||
    context.sensitivity_label == "confidential" ||
    context.sensitivity_label == "restricted"
  )
};
