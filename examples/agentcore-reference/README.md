# AgentCore reference agent: Terraform

Registers the reference agent in `platform/public/thoth-agentcore-reference`
in Thoth: the agent, what its four tools do, the profile or pack assigned, observe
mode, and a key scoped to this agent.

Reference. Verified locally with Strands; running on AgentCore Runtime is not
yet verified end to end. This example never touches AWS.

```bash
export THOTH_API_KEY=...   # an org admin key
terraform init
terraform apply -var tenant_id=your-tenant -var owner_email=you@example.com
```

Then give the runtime its key without putting it in the image. The key is
returned once and is in Terraform state, so read it once and store it:

```bash
terraform output -raw runtime_api_key | aws secretsmanager create-secret \
  --name thoth/clinic-scheduler --secret-string file:///dev/stdin
```

Switch to enforcement after the observe summary shows the agent is ready:

```bash
terraform apply -var tenant_id=your-tenant -var owner_email=you@example.com -var enforcement_mode=enforce
```

`var.pack_id` defaults to the HIPAA technical safeguards pack. See its
description in `variables.tf` before relying on it.
