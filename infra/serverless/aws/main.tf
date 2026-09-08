# SPDX-License-Identifier: Apache-2.0
terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 6.0, < 7.0" }
  }
}
variable "name" { type = string }
variable "image" {
  type        = string
  description = "ECR digest of deploy/Dockerfile.lambda, built for linux/amd64."
  validation {
    condition     = can(regex("@sha256:[a-f0-9]{64}$", var.image))
    error_message = "Use an immutable ECR container image digest."
  }
}
variable "subnet_ids" {
  type        = list(string)
  description = "Existing private subnets with database routing and Secrets Manager endpoint or controlled egress."
}
variable "security_group_ids" {
  type        = list(string)
  description = "Existing least-privilege security groups for database and identity/secret endpoint egress."
}
variable "secret_arns" {
  type        = map(string)
  description = "Environment names mapped to existing Secrets Manager ARNs, never contents."
  validation {
    condition     = alltrue([for name in ["DATABASE_URL", "CONTENT_MASTER_KEY", "MANAGEMENT_KEY"] : contains(keys(var.secret_arns), name)])
    error_message = "Reference DATABASE_URL, CONTENT_MASTER_KEY and MANAGEMENT_KEY secrets."
  }
  validation {
    condition     = alltrue([for name in keys(var.secret_arns) : contains(["DATABASE_URL", "CONTENT_MASTER_KEY", "MANAGEMENT_KEY", "LOGIN_CLIENT_SECRET", "LOGIN_SUBJECTS", "OIDC_SUBJECTS", "KEY_PROVIDERS", "TENANT_KEY_PROVIDERS", "PLATFORM_ADMIN_TOKEN", "PLATFORM_SUBJECTS", "BILLING_PLAN_LIMITS", "BILLING_PRICES", "PAYMENT_PROVIDERS", "OIDC_CONNECTIONS"], name)])
    error_message = "Only documented application secret names may be referenced; bootstrap secrets belong in one-off setup jobs."
  }
  validation {
    condition     = alltrue([for arn in values(var.secret_arns) : can(regex("^arn:[^:]+:secretsmanager:[^:]+:[0-9]{12}:secret:.+$", arn))])
    error_message = "Provide nonempty, correctly formatted managed secret references and versions."
  }
}
variable "secret_kms_key_arns" {
  type        = list(string)
  default     = []
  description = "Existing customer KMS keys encrypting referenced Secrets Manager secrets (if any)."
}
variable "tenant_kms_key_arns" {
  type        = list(string)
  default     = []
  description = "Existing tenant wrapping keys; only grant if AWS KMS BYOK is used."
}
variable "public_url" {
  type        = string
  default     = null
  description = "Optional canonical HTTPS /mcp custom URL; otherwise use API Gateway's HTTPS endpoint."
  validation {
    condition     = var.public_url == null ? true : can(regex("^https://[^/]+/mcp$", var.public_url))
    error_message = "Use an HTTPS URL ending in /mcp."
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
variable "max_concurrency" {
  type    = number
  default = 10
  validation {
    condition     = var.max_concurrency >= 1 && var.max_concurrency <= 100 && floor(var.max_concurrency) == var.max_concurrency
    error_message = "Set a bounded whole-number maximum between 1 and 100."
  }
}
resource "aws_apigatewayv2_api" "api" {
  name          = var.name
  protocol_type = "HTTP"
}
locals {
  public_url = coalesce(var.public_url, "${aws_apigatewayv2_api.api.api_endpoint}/mcp")
}
resource "aws_iam_role" "api" {
  name_prefix = "${var.name}-"
  assume_role_policy = jsonencode({ Version = "2012-10-17", Statement = [{
    Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole"
  }] })
}
resource "aws_cloudwatch_log_group" "api" {
  name              = "/aws/lambda/${var.name}"
  retention_in_days = 14
}
resource "aws_iam_role_policy" "api" {
  role = aws_iam_role.api.id
  policy = jsonencode({ Version = "2012-10-17", Statement = concat([
    { Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = values(var.secret_arns) },
    { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.api.arn}:*" },
    { Effect = "Allow", Action = ["ec2:CreateNetworkInterface", "ec2:DescribeNetworkInterfaces", "ec2:DescribeSubnets", "ec2:DeleteNetworkInterface", "ec2:AssignPrivateIpAddresses", "ec2:UnassignPrivateIpAddresses"], Resource = "*" }
    ], length(var.secret_kms_key_arns) == 0 ? [] : [
    { Effect = "Allow", Action = ["kms:Decrypt"], Resource = var.secret_kms_key_arns }
    ], length(var.tenant_kms_key_arns) == 0 ? [] : [
    { Effect = "Allow", Action = ["kms:Encrypt", "kms:Decrypt"], Resource = var.tenant_kms_key_arns }
  ]) })
}
resource "aws_lambda_function" "api" {
  function_name                  = var.name
  role                           = aws_iam_role.api.arn
  package_type                   = "Image"
  image_uri                      = var.image
  architectures                  = ["x86_64"]
  memory_size                    = 512
  timeout                        = 28
  reserved_concurrent_executions = var.max_concurrency
  vpc_config {
    subnet_ids         = var.subnet_ids
    security_group_ids = var.security_group_ids
  }
  environment {
    variables = merge(var.configuration, {
      PUBLIC_URL                = local.public_url,
      ALLOWED_HOSTS             = "${split("/", local.public_url)[2]},127.0.0.1:*,localhost:*",
      DISTRIBUTEDAI_SECRET_ARNS = jsonencode(var.secret_arns)
    })
  }
  depends_on = [aws_iam_role_policy.api]
}
resource "aws_apigatewayv2_integration" "api" {
  api_id                 = aws_apigatewayv2_api.api.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.api.invoke_arn
  payload_format_version = "2.0"
  timeout_milliseconds   = 29000
}
resource "aws_apigatewayv2_route" "all" {
  api_id    = aws_apigatewayv2_api.api.id
  route_key = "$default"
  target    = "integrations/${aws_apigatewayv2_integration.api.id}"
}
resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.api.id
  name        = "$default"
  auto_deploy = true
  default_route_settings {
    throttling_burst_limit = 20
    throttling_rate_limit  = 10
  }
}
resource "aws_lambda_permission" "gateway" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.api.execution_arn}/*"
}
output "mcp_url" { value = local.public_url }
output "workload_role_arn" { value = aws_iam_role.api.arn }
