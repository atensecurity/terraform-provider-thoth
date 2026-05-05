deployment "development" {
  inputs = {
    tenant_id          = "acme"
    apex_domain        = "atensecurity.com"
    org_api_key        = "replace-with-org-api-key"
    compliance_profile = "soc2"
  }
}
