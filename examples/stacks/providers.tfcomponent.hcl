required_providers {
  thoth = {
    source  = "atensecurity/thoth"
    version = "~> 0.1.6"
  }
}

provider "thoth" "main" {
  config {
    tenant_id   = var.tenant_id
    apex_domain = var.apex_domain
    # Auth resolves from THOTH_API_KEY (org-scoped).
  }
}
