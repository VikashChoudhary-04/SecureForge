output "application_name" {
description = "SecureCommerce application name."
value       = var.application_name
}

output "environment" {
description = "SecureCommerce deployment environment."
value       = var.environment
}

output "application_host" {
description = "Configured application host."
value       = var.application_host
}

output "application_port" {
description = "Configured application port."
value       = var.application_port
}

output "public_application" {
description = "Whether the application is intentionally configured for public exposure."
value       = var.application_host == "0.0.0.0"
}

output "storage_encryption" {
description = "Configured storage encryption state."
value       = var.storage_encryption
}

output "storage_public_access" {
description = "Configured storage public-access state."
value       = var.storage_public_access
}

output "permission_scope" {
description = "Configured permission scope for the laboratory role."
value       = var.permission_scope
}
