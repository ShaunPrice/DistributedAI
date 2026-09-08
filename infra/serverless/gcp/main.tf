# SPDX-License-Identifier: Apache-2.0
terraform {
  required_version = ">= 1.6"
  required_providers {
    google = { source = "hashicorp/google", version = ">= 6.0, < 8.0" }
  }
}
variable "project_id" { type = string }
variable "region" { type = string }
variable "name" { type = string }
variable "image" {
  type = string
  validation {
    condition     = can(regex("@sha256:[a-f0-9]{64}$", var.image))
    error_message = "Use an immutable container image digest."
  }
}
variable "service_account_email" {
  type        = string
  description = "Existing workload identity with access only to the referenced secrets and tenant KMS keys."
}
variable "vpc_connector" {
  type        = string
  description = "Existing Serverless VPC Access connector providing access to private PostgreSQL."
}
variable "public_url" {
  type        = string
  description = "Canonical externally routed HTTPS /mcp URL; configure domain mapping separately."
  validation {
    condition     = can(regex("^https://[^/]+/mcp$", var.public_url))
    error_message = "Use an HTTPS URL ending in /mcp."
  }
}
variable "secret_refs" {
  type        = map(object({ secret = string, version = string }))
  description = "Environment name to existing Secret Manager secret name and version. Never secret contents."
  validation {
    condition     = alltrue([for name in ["DATABASE_URL", "CONTENT_MASTER_KEY", "MANAGEMENT_KEY"] : contains(keys(var.secret_refs), name)])
    error_message = "Reference DATABASE_URL, CONTENT_MASTER_KEY and MANAGEMENT_KEY secrets."
  }
  validation {
    condition     = alltrue([for name in keys(var.secret_refs) : contains(["DATABASE_URL", "CONTENT_MASTER_KEY", "MANAGEMENT_KEY", "LOGIN_CLIENT_SECRET", "LOGIN_SUBJECTS", "OIDC_SUBJECTS", "KEY_PROVIDERS", "TENANT_KEY_PROVIDERS", "PLATFORM_ADMIN_TOKEN", "PLATFORM_SUBJECTS", "BILLING_PLAN_LIMITS", "BILLING_PRICES", "PAYMENT_PROVIDERS", "OIDC_CONNECTIONS"], name)])
    error_message = "Only documented application secret names may be referenced; bootstrap secrets belong in one-off setup jobs."
  }
  validation {
    condition     = alltrue([for ref in values(var.secret_refs) : can(regex("^projects/[^/]+/secrets/[^/]+$", ref.secret)) && can(regex("^(latest|[0-9]+)$", ref.version))])
    error_message = "Provide nonempty, correctly formatted managed secret references and versions."
  }
}
variable "configuration" {
  type    = map(string)
  default = {}
  validation {
    condition     = alltrue([for name in keys(var.configuration) : contains(["LOGIN_MODE", "LOGIN_ISSUER", "LOGIN_CLIENT_ID", "LOGIN_PROVIDER", "OIDC_ISSUER", "OIDC_JWKS_URL", "REQUESTS_PER_MINUTE", "BILLING_ENABLED"], name)])
    error_message = "Only non-secret identity and rate-limit configuration is accepted."
  }
}
variable "max_instances" {
  type    = number
  default = 3
  validation {
    condition     = var.max_instances >= 1 && var.max_instances <= 100 && floor(var.max_instances) == var.max_instances
    error_message = "Set a bounded whole-number maximum between 1 and 100."
  }
}
resource "google_cloud_run_v2_service" "api" {
  project             = var.project_id
  name                = var.name
  location            = var.region
  deletion_protection = true
  ingress             = "INGRESS_TRAFFIC_ALL"
  template {
    service_account                  = var.service_account_email
    timeout                          = "30s"
    max_instance_request_concurrency = 20
    scaling {
      min_instance_count = 0
      max_instance_count = var.max_instances
    }
    vpc_access {
      connector = var.vpc_connector
      egress    = "PRIVATE_RANGES_ONLY"
    }
    containers {
      image = var.image
      ports { container_port = 8090 }
      resources {
        limits            = { cpu = "1", memory = "512Mi" }
        cpu_idle          = true
        startup_cpu_boost = true
      }
      dynamic "env" {
        for_each = merge(var.configuration, {
          PUBLIC_URL    = var.public_url,
          ALLOWED_HOSTS = "${split("/", var.public_url)[2]},127.0.0.1:*,localhost:*",
          BIND_HOST     = "0.0.0.0"
        })
        content {
          name  = env.key
          value = env.value
        }
      }
      dynamic "env" {
        for_each = var.secret_refs
        content {
          name = env.key
          value_source {
            secret_key_ref {
              secret  = env.value.secret
              version = env.value.version
            }
          }
        }
      }
      startup_probe {
        initial_delay_seconds = 0
        period_seconds        = 3
        failure_threshold     = 20
        tcp_socket { port = 8090 }
      }
    }
  }
}
resource "google_cloud_run_v2_service_iam_member" "public_transport" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.api.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
output "service_uri" { value = google_cloud_run_v2_service.api.uri }
