resource "terraform_data" "thothctl_bootstrap" {
  input = {
    tenant_id               = var.tenant_id
    govapi_url              = var.govapi_url
    bootstrap_script_path   = var.bootstrap_script_path
    thothctl_bin            = var.thothctl_bin
    timeout_seconds         = var.timeout_seconds
    compliance_profile      = var.compliance_profile
    shadow_low              = var.shadow_low
    shadow_medium           = var.shadow_medium
    shadow_high             = var.shadow_high
    shadow_critical         = var.shadow_critical
    webhook_url             = var.webhook_url
    webhook_enabled         = var.webhook_enabled
    test_webhook            = var.test_webhook
    tool_risk_overrides     = var.tool_risk_overrides
    mdm_provider            = var.mdm_provider
    mdm_name                = var.mdm_name
    mdm_enabled             = var.mdm_enabled
    mdm_config_file         = var.mdm_config_file
    start_mdm_sync          = var.start_mdm_sync
    json_output             = var.json_output
    admin_bearer_token_file = var.admin_bearer_token_file
    trigger_version         = var.trigger_version
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-c"]
    working_dir = path.module
    command     = var.bootstrap_script_path
    environment = {
      THOTHCTL_BIN                  = var.thothctl_bin
      THOTH_GOVAPI_URL              = var.govapi_url
      THOTH_TENANT_ID               = var.tenant_id
      THOTH_ADMIN_BEARER_TOKEN      = var.admin_bearer_token
      THOTH_ADMIN_BEARER_TOKEN_FILE = var.admin_bearer_token_file
      THOTH_TIMEOUT_SECONDS         = tostring(var.timeout_seconds)
      THOTH_COMPLIANCE_PROFILE      = var.compliance_profile
      THOTH_SHADOW_LOW              = var.shadow_low
      THOTH_SHADOW_MEDIUM           = var.shadow_medium
      THOTH_SHADOW_HIGH             = var.shadow_high
      THOTH_SHADOW_CRITICAL         = var.shadow_critical
      THOTH_WEBHOOK_URL             = var.webhook_url
      THOTH_WEBHOOK_SECRET          = var.webhook_secret
      THOTH_WEBHOOK_ENABLED         = var.webhook_enabled == null ? "" : tostring(var.webhook_enabled)
      THOTH_TEST_WEBHOOK            = tostring(var.test_webhook)
      THOTH_TOOL_RISK_OVERRIDES_CSV = join(",", var.tool_risk_overrides)
      THOTH_MDM_PROVIDER            = var.mdm_provider
      THOTH_MDM_NAME                = var.mdm_name
      THOTH_MDM_ENABLED             = var.mdm_enabled == null ? "" : tostring(var.mdm_enabled)
      THOTH_MDM_CONFIG_FILE         = var.mdm_config_file
      THOTH_MDM_START_SYNC          = tostring(var.start_mdm_sync)
      THOTH_JSON_OUTPUT             = tostring(var.json_output)
    }
  }
}
