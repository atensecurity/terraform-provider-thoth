# thothctl_bootstrap Terraform Module

Runs `thothctl bootstrap` from Terraform to provision Thoth tenant governance
settings and optional MDM provider wiring without using the dashboard.

## What it does

- Applies `PUT /:tenant-id/thoth/settings`
- Optionally tests webhook delivery
- Optionally upserts `POST /:tenant-id/thoth/mdm/providers`
- Optionally starts provider sync

Execution is handled with `terraform_data` + `local-exec` using:
`scripts/thothctl_bootstrap.sh`.

## Usage

```hcl
module "thoth_bootstrap" {
  source = "../../modules/bootstrap"

  tenant_id  = var.tenant_id
  govapi_url = "https://govapi.example.com"

  # Prefer token file paths in CI runners.
  admin_bearer_token_file = "/run/secrets/thoth_admin_jwt"

  compliance_profile = "healthcare"
  shadow_low         = "allow"
  shadow_medium      = "step_up"
  shadow_high        = "block"
  shadow_critical    = "block"

  webhook_url     = "https://siem.example.com/hooks/thoth"
  webhook_secret  = var.webhook_secret
  webhook_enabled = true
  test_webhook    = true

  mdm_provider   = "jamf"
  mdm_name       = "Jamf Pro"
  mdm_enabled    = true
  mdm_config_file = "${path.module}/configs/jamf.json"
  start_mdm_sync = true

  # bump to replay bootstrap without changing config fields
  trigger_version = "2026-04-22.1"
}
```

## CI/GitOps notes

- The module intentionally does not store token secrets in outputs.
- Use `admin_bearer_token_file` with your runner secret mount whenever possible.
- Re-execution is driven by non-secret input drift plus `trigger_version`.
- Ensure `thothctl` is installed in the Terraform execution environment, or set
  `thothctl_bin` to an absolute path.
