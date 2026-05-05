required_providers {
  thoth = {
    source  = "atensecurity/thoth"
    version = "~> 0.1.1"
  }
}

provider "thoth" "main" {
  config {
    tenant_id   = var.tenant_id
    apex_domain = var.apex_domain
    org_api_key = var.org_api_key
  }
}
