# A Strands agent on Amazon Bedrock AgentCore Runtime, governed by Thoth.
#
# This registers the agent, declares what its tools do, assigns a profile, sets
# observe mode and creates the runtime key. Every resource here exists in the
# provider today. Nothing here touches AWS: put the key in AWS Secrets Manager
# or AgentCore Identity yourself (see the output note) and read it at runtime.
#
# Reference. Verified locally with Strands; running on AgentCore Runtime is not
# yet verified end to end.

terraform {
  required_version = ">= 1.5"

  required_providers {
    thoth = {
      source  = "atensecurity/thoth"
      version = ">= 0.1.24"
    }
  }
}

provider "thoth" {
  tenant_id = var.tenant_id
  # Credentials come from THOTH_API_KEY (an org admin key) in the environment.
}

locals {
  agent_id = "clinic-scheduler"

  # What each tool of platform/public/thoth-agentcore-reference does. Decisions
  # use these confirmed effects, never a tool's name or a model's guess.
  tool_classes = {
    lookup_appointments   = ["read"]
    schedule_followup     = ["write"]
    send_referral_packet  = ["export"]
    export_patient_record = ["sensitive_data_access", "export"]
  }
}

resource "thoth_agent" "scheduler" {
  agent_id       = local.agent_id
  display_name   = "Clinic scheduler (AgentCore reference)"
  owner_email    = var.owner_email
  approved_scope = keys(local.tool_classes)
}

resource "thoth_tool_classification" "scheduler" {
  for_each = local.tool_classes

  agent_id  = thoth_agent.scheduler.agent_id
  tool_name = each.key
  classes   = each.value
}

# The profile or pack the agent's rules come from. See the note on var.pack_id.
resource "thoth_pack_assignment" "scheduler" {
  agent_id    = thoth_agent.scheduler.agent_id
  pack_id     = var.pack_id
  environment = "prod"
}

# Observe first: every call is evaluated and recorded, and every call runs.
# Switch to "enforce" after the observe summary shows the agent is ready.
resource "thoth_agent_enforcement" "scheduler" {
  agent_id         = thoth_agent.scheduler.agent_id
  enforcement_mode = var.enforcement_mode
}

# A runtime key for this agent only. It is returned once, on create, and is kept
# in Terraform state: use a remote state backend with encryption and restricted access.
resource "thoth_agent_api_key" "scheduler" {
  scope_target_id = thoth_agent.scheduler.agent_id
  name            = "agentcore-runtime"
  permissions     = ["execute"]
  ttl_seconds     = var.key_ttl_seconds
  jit_reason      = "AgentCore Runtime deployment of the reference agent"
}
