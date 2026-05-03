# terraform-provider-thoth

Terraform provider for Aten Security Thoth headless AI Governance Control Plane.

- Provider source: `registry.terraform.io/atensecurity/thoth`
- Terraform version: `>= 1.5`
- Plugin Framework implementation (Go)

## Documentation

- Terraform Registry: https://registry.terraform.io/providers/atensecurity/thoth/latest
- Aten Security docs: https://docs.atensecurity.com/docs/terraform-provider/
- Basic example: https://github.com/atensecurity/terraform-provider-thoth/tree/main/examples/basic

This provider exposes GovAPI-backed resources to manage:

- Tenant governance settings
- MDM provider integrations and sync jobs
- Browser policy providers/policies/enrollments
- JIT API keys
- Webhook delivery test execution

For runtime evidence exports, use the Thoth evidence-chain APIs:

- `GET /:tenant-id/thoth/evidence/chain`
- `GET /:tenant-id/thoth/sessions/:sessionId/evidence-bundle`

or CLI equivalents:

- `thothctl evidence chain --tenant-id <tenant> --json`
- `thothctl evidence bundle --tenant-id <tenant> --session-id <id> --output <file>`

## Quick Start

```hcl
terraform {
  required_version = ">= 1.5"

  required_providers {
    thoth = {
      source  = "atensecurity/thoth"
      version = "~> 0.1.1"
    }
  }
}

provider "thoth" {
  tenant_id               = var.tenant_id
  apex_domain             = "atensecurity.com" # optional, defaults to atensecurity.com
  admin_bearer_token      = var.admin_bearer_token
  request_timeout_seconds = 30
}

resource "thoth_tenant_settings" "this" {
  compliance_profile = "soc2"
  shadow_low         = "allow"
  shadow_medium      = "step_up"
  shadow_high        = "block"
  shadow_critical    = "block"

  webhook_enabled = true
  webhook_url     = var.webhook_url
  webhook_secret  = var.webhook_secret
}
```

When `api_base_url` is omitted, the provider derives it as:
`https://grid.<tenant_id>.<apex_domain>`.

See [`examples/basic`](https://github.com/atensecurity/terraform-provider-thoth/tree/main/examples/basic) for a full end-to-end example.

## Provider Resources

- `thoth_tenant_settings`
- `thoth_mdm_provider`
- `thoth_mdm_sync`
- `thoth_browser_provider`
- `thoth_browser_policy`
- `thoth_browser_enrollment`
- `thoth_api_key`
- `thoth_webhook_test`
- `thoth_policy_sync`
- `thoth_approval_decision`
- `thoth_pack_assignment`

## Provider Data Sources

- `thoth_tenant_settings`
- `thoth_governance_feed`
- `thoth_governance_tools`
- `thoth_api_key_metrics`
- `thoth_mdm_sync_job`

## Local Development

```bash
env GOCACHE=/tmp/gocache go mod tidy
env GOCACHE=/tmp/gocache go build ./...
env GOCACHE=/tmp/gocache go test ./...
```

## Release Automation

Provider release automation is defined for the public provider repository in:

- `.goreleaser.yml` (provider package/archive/signing layout)
- `.github/workflows/release.yml` (tag-triggered GitHub release flow)

Tag formats supported by the workflow:

- `v0.1.1`
- `v0.1.1-rc1`

## Governance And IP

- [Public Architecture Boundary](./PUBLIC_ARCHITECTURE_BOUNDARY.md)
- [Contributing](./CONTRIBUTING.md)
- [Security Policy](./SECURITY.md)
- [Trademark Notice](./TRADEMARKS.md)

## Notes

- `thoth_mdm_provider`, `thoth_browser_provider`, `thoth_browser_policy`, and `thoth_browser_enrollment` use API upsert semantics.
- For resources without hard delete endpoints, delete operations stop management in Terraform and, when possible, perform a safe disable/deactivate call.
