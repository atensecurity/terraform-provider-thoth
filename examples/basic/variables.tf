variable "tenant_id" {
  type = string
}

variable "govapi_url" {
  type = string
}

variable "admin_bearer_token" {
  type      = string
  sensitive = true
}
