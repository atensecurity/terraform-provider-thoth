output "id" {
  description = "Resource ID for the thothctl bootstrap execution."
  value       = terraform_data.thothctl_bootstrap.id
}

output "input" {
  description = "Non-secret trigger input captured by terraform_data for drift and replay inspection."
  value       = terraform_data.thothctl_bootstrap.input
}

