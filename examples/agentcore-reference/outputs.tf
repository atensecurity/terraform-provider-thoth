output "agent_id" {
  description = "Set THOTH_AGENT_ID to this in the AgentCore runtime."
  value       = thoth_agent.scheduler.agent_id
}

output "api_key_id" {
  description = "The key's ID. Revoke or rotate it by this ID."
  value       = thoth_agent_api_key.scheduler.key_id
}

# The key's plaintext, returned once on create. Marked sensitive so plans and
# logs hide it. Read it once with `terraform output -raw runtime_api_key`, store
# it in AWS Secrets Manager (or AgentCore Identity) and let the runtime read it
# there. Never put it in the image or in the runtime's plain environment settings.
output "runtime_api_key" {
  description = "The agent's runtime key. Store it in a secret store."
  value       = thoth_agent_api_key.scheduler.api_key
  sensitive   = true
}
