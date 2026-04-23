# terraform-provider-thoth

Official Terraform artifacts for Thoth headless control-plane operations.

## What works today

Use the `modules/bootstrap` module to provision tenant governance settings,
SIEM/SOAR webhook routing, and MDM provider sync via `thothctl` in CI/GitOps.

### Customer quickstart

```bash
git clone https://github.com/atensecurity/terraform-provider-thoth.git
cd terraform-provider-thoth/examples/basic
terraform init
terraform apply
```

### Module install (Git source)

```hcl
module "thoth_bootstrap" {
  source = "github.com/atensecurity/terraform-provider-thoth//modules/bootstrap?ref=v0.1.0"

  tenant_id               = var.tenant_id
  govapi_url              = var.govapi_url
  admin_bearer_token_file = "/run/secrets/thoth_admin_jwt"

  compliance_profile = "soc2"
  shadow_low         = "allow"
  shadow_medium      = "step_up"
  shadow_high        = "block"
  shadow_critical    = "block"

  webhook_url     = var.siem_webhook_url
  webhook_secret  = var.siem_webhook_secret
  webhook_enabled = true
  test_webhook    = true
}
```

## Provider-native resources (in progress)

Planned resource set:

- `thoth_tenant_settings`
- `thoth_mdm_provider`
- `thoth_mdm_sync`
- `thoth_webhook_test`

Provider-native resources will be added with versioned release artifacts in this
repository.

## Example

See `examples/basic` for a starter layout.
