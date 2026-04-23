module "thoth_bootstrap" {
  source = "../../modules/bootstrap"

  tenant_id          = var.tenant_id
  govapi_url         = var.govapi_url
  admin_bearer_token = var.admin_bearer_token

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
