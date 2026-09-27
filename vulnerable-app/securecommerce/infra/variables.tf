variable "environment" {
description = "Deployment environment."
type        = string
default     = "lab"

validation {
condition     = length(trimspace(var.environment)) > 0
error_message = "Environment must not be empty."
}
}

variable "application_name" {
description = "Application name used by the SecureCommerce lab."
type        = string
default     = "securecommerce"

validation {
condition     = length(trimspace(var.application_name)) > 0
error_message = "Application name must not be empty."
}
}

variable "application_host" {
description = "Host address used by the deliberately public lab application."
type        = string
default     = "0.0.0.0"
}

variable "application_port" {
description = "Port exposed by the SecureCommerce lab application."
type        = number
default     = 5000

validation {
condition = (
var.application_port >= 1
&& var.application_port <= 65535
)
error_message = "Application port must be between 1 and 65535."
}
}

variable "storage_encryption" {
description = "Storage encryption setting used by the lab configuration."
type        = bool
default     = false
}

variable "storage_public_access" {
description = "Whether lab storage is intentionally configured as public."
type        = bool
default     = true
}

variable "permission_scope" {
description = "Permission scope assigned to the intentionally excessive lab role."
type        = string
default     = "*"
}
