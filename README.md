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
      version = ">= 0.1.10"
    }
  }
}

provider "thoth" {
  tenant_id               = var.tenant_id
  apex_domain             = "atensecurity.com" # optional, defaults to atensecurity.com
  org_api_key             = var.org_api_key
  request_timeout_seconds = 30
}

resource "thoth_governance_settings" "this" {
  compliance_profile = "soc2"
  regulatory_regimes = ["soc2"]
  shadow_low         = "allow"
  shadow_medium      = "step_up"
  shadow_high        = "block"
  shadow_critical    = "block"
}

resource "thoth_webhook_settings" "webhook" {
  webhook_enabled = true
  webhook_url     = var.webhook_url
  webhook_secret  = var.webhook_secret
}
```

`compliance_profile` is a high-level preset for baseline defaults.
`regulatory_regimes` is the explicit obligations list used for automatic regulatory pack loading.
If `regulatory_regimes` is omitted, GovAPI falls back to profile-derived defaults and then `["soc2"]`.

When `api_base_url` is omitted, the provider derives it as:
`https://grid.<tenant_id>.<apex_domain>`.

See [`examples/basic`](https://github.com/atensecurity/terraform-provider-thoth/tree/main/examples/basic) for a full end-to-end example.

For legacy interactive workflows, `admin_bearer_token` and
`admin_bearer_token_file` remain supported.

For CI/CD, you can export `THOTH_API_KEY` (must be an org-scoped key) and
omit explicit auth fields.

`tenant_id` can also be omitted when `THOTH_TENANT_ID` is exported.

## Provider Resources

- `thoth_governance_settings`
- `thoth_webhook_settings`
- `thoth_siem_settings`
- `thoth_pam_settings`
- `thoth_mdm_provider`
- `thoth_mdm_sync`
- `thoth_browser_provider`
- `thoth_browser_policy`
- `thoth_browser_enrollment`
- `thoth_fleet_api_key`
- `thoth_endpoint_api_key`
- `thoth_agent_api_key`
- `thoth_fleet`
- `thoth_endpoint`
- `thoth_webhook_test`
- `thoth_evidence_backfill`
- `thoth_decision_field_backfill`
- `thoth_policy_sync`
- `thoth_policy_bundle`
- `thoth_approval_decision`
- `thoth_pack_assignment`
- `thoth_pack_assignment_bulk`

### Deterministic Controls via Terraform

Both `thoth_pack_assignment` and `thoth_pack_assignment_bulk` support first-class
deterministic control attributes:

- `mismatch_boost`
- `delegation_boost`
- `trust_floor`
- `critical_threshold`

These are translated into policy pack overrides under
`behavioral_controls` and applied through GovAPI during pack assignment.

For framework-native sidecar policies, use `thoth_policy_bundle` to manage
versioned OPA/Cedar bundles from inline policy or URI-backed policy objects,
with optional version pinning and hash verification (`source_uri`,
`s3_version_id`, `expected_hash`). By default, bundles target all assignments
and run in `enforce` mode. You can optionally scope assignments by:

- `all` (default)
- `agent:<agent-id>`
- `<agent-id>` (direct match)

## Provider Data Sources

- `thoth_approvals`
- `thoth_api_key_authorization`
- `thoth_api_keys`
- `thoth_billing_pricing`
- `thoth_billing_monthly_cost`
- `thoth_billing_invoices`
- `thoth_billing_artifacts`
- `thoth_billing_artifact`
- `thoth_billing_reports`
- `thoth_billing_report`
- `thoth_evidence_chain`
- `thoth_evidence_verify`
- `thoth_evidence_bundle`
- `thoth_fleets`
- `thoth_fleet`
- `thoth_tenant_settings`
- `thoth_endpoints`
- `thoth_endpoint_stats`
- `thoth_governance_feed`
- `thoth_governance_packs`
- `thoth_governance_pack_rules`
- `thoth_governance_pack_rule_versions`
- `thoth_governance_runtime_status`
- `thoth_governance_day7_report`
- `thoth_governance_reports_overview`
- `thoth_governance_cost_report`
- `thoth_report_data`
- `thoth_policy_bundles`
- `thoth_effective_policy_bundles`
- `thoth_governance_tools`
- `thoth_governance_evidence_slos`
- `thoth_api_key_metrics`
- `thoth_mdm_providers`
- `thoth_mdm_sync_job`
- `thoth_browser_providers`
- `thoth_browser_policies`
- `thoth_browser_enrollments`

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

- `v0.1.4`
- `v0.1.4-rc1`

## Governance And IP

- [Public Architecture Boundary](./PUBLIC_ARCHITECTURE_BOUNDARY.md)
- [Contributing](./CONTRIBUTING.md)
- [Security Policy](./SECURITY.md)
- [Trademark Notice](./TRADEMARKS.md)

## Notes

- `thoth_mdm_provider`, `thoth_browser_provider`, `thoth_browser_policy`, and `thoth_browser_enrollment` use API upsert semantics.
- For resources without hard delete endpoints, delete operations stop management in Terraform and, when possible, perform a safe disable/deactivate call.
