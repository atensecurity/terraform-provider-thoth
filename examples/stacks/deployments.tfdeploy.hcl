deployment "development" {
  inputs = {
    tenant_id          = "acme"
    apex_domain        = "atensecurity.com"
    compliance_profile = "soc2"
    regulatory_regimes = ["soc2"]
  }
}
