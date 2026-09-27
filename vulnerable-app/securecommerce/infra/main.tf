terraform {
required_version = ">= 1.5.0"

required_providers {
null = {
source  = "hashicorp/null"
}
}
}

provider "null" {}

variable "environment" {
type    = string
default = "lab"
}

variable "application_name" {
type    = string
default = "securecommerce"
}

resource "null_resource" "securecommerce_lab" {
triggers = {
application = var.application_name
environment = var.environment
}
}

resource "null_resource" "public_application" {
triggers = {
description = "Intentionally public lab application"
host        = "0.0.0.0"
port        = "5000"
}
}

resource "null_resource" "insecure_storage" {
triggers = {
encryption = "disabled"
access     = "public"
purpose    = "SecureCommerce laboratory data"
}
}

resource "null_resource" "excessive_permissions" {
triggers = {
role        = "administrator"
permissions = "*"
resource    = "securecommerce"
}
}
