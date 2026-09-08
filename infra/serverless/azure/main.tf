# SPDX-License-Identifier: Apache-2.0
terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = ">= 4.0, < 5.0" }
  }
}
variable "resource_group_name" { type = string }
variable "environment_id" {
  type        = string
  description = "Existing Container Apps environment with Consumption profile and private PostgreSQL routing."
}
variable "identity_id" {
  type        = string
  description = "Existing user-assigned workload identity with Key Vault Secrets User on referenced secrets and AcrPull if needed."
}
variable "name" { type = string }
variable "image" {
  type = string
  validation {
    condition     = can(regex("@sha256:[a-f0-9]{64}$", var.image))
    error_message = "Use an immutable container image digest."
  }
}
variable "registry_server" {
  type        = string
  default     = null
  description = "Optional private ACR hostname; existing identity must have AcrPull."
}
variable "public_url" {
  type        = string
  description = "Canonical externally routed HTTPS /mcp URL; configure certificate/domain separately."
  validation {
    condition     = can(regex("^https://[^/]+/mcp$", var.public_url))
    error_message = "Use an HTTPS URL ending in /mcp."
  }
}
variable "secret_refs" {
  type        = map(string)
  description = "Environment name to existing Key Vault secret URI, never contents."
  validation {
    condition     = alltrue([for name in ["DATABASE_URL", "CONTENT_MASTER_KEY", "MANAGEMENT_KEY"] : contains(keys(var.secret_refs), name)])
    error_message = "Reference DATABASE_URL, CONTENT_MASTER_KEY and MANAGEMENT_KEY secrets."
  }
  validation {
    condition     = alltrue([for name in keys(var.secret_refs) : contains(["DATABASE_URL", "CONTENT_MASTER_KEY", "MANAGEMENT_KEY", "LOGIN_CLIENT_SECRET", "LOGIN_SUBJECTS", "OIDC_SUBJECTS", "KEY_PROVIDERS", "TENANT_KEY_PROVIDERS", "PLATFORM_ADMIN_TOKEN", "PLATFORM_SUBJECTS", "BILLING_PLAN_LIMITS", "BILLING_PRICES", "PAYMENT_PROVIDERS", "OIDC_CONNECTIONS"], name)])
    error_message = "Only documented application secret names may be referenced; bootstrap secrets belong in one-off setup jobs."
  }
  validation {
    condition     = alltrue([for uri in values(var.secret_refs) : can(regex("^https://[^/]+/secrets/[^/]+(/[^/]+)?$", uri))])
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
resource "azurerm_container_app" "api" {
  name                         = var.name
  resource_group_name          = var.resource_group_name
  container_app_environment_id = var.environment_id
  revision_mode                = "Single"
  workload_profile_name        = "Consumption"
  identity {
    type         = "UserAssigned"
    identity_ids = [var.identity_id]
  }
  dynamic "registry" {
    for_each = var.registry_server == null ? [] : [var.registry_server]
    content {
      server   = registry.value
      identity = var.identity_id
    }
  }
  dynamic "secret" {
    for_each = var.secret_refs
    content {
      name                = replace(lower(secret.key), "_", "-")
      key_vault_secret_id = secret.value
      identity            = var.identity_id
    }
  }
  ingress {
    external_enabled           = true
    allow_insecure_connections = false
    target_port                = 8090
    transport                  = "http"
    traffic_weight {
      percentage      = 100
      latest_revision = true
    }
  }
  template {
    min_replicas = 0
    max_replicas = var.max_instances
    http_scale_rule {
      name                = "http-demand"
      concurrent_requests = "20"
    }
    container {
      name   = "api"
      image  = var.image
      cpu    = 0.5
      memory = "1Gi"
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
          name        = env.key
          secret_name = replace(lower(env.key), "_", "-")
        }
      }
      startup_probe {
        transport               = "TCP"
        port                    = 8090
        interval_seconds        = 3
        failure_count_threshold = 20
      }
    }
  }
}
output "service_fqdn" { value = azurerm_container_app.api.ingress[0].fqdn }
