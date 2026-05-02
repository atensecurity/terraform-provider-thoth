deployment "development" {
  inputs = {
    tenant_id          = "acme"
    apex_domain        = "atensecurity.com"
    admin_bearer_token = "replace-with-ephemeral-token"
    compliance_profile = "soc2"
  }
}
