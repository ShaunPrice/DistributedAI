terraform {
  required_version = ">= 1.6, < 2.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { Project = "DistributedAI" }
  }
}

variable "region" {
  type    = string
  default = "ap-southeast-2"
}
variable "domain" {
  type        = string
  description = "DNS name whose A record will point at the output IP. No URL scheme."
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]+\\.[a-z]{2,}$", var.domain))
    error_message = "Provide a lowercase DNS name."
  }
}
variable "image" {
  type        = string
  description = "Existing private ECR image in this region, pinned by sha256 digest; build/push before apply."
  validation {
    condition     = can(regex("^[0-9]{12}\\.dkr\\.ecr\\.[a-z0-9-]+\\.amazonaws\\.com/[a-z0-9/_-]+@sha256:[a-f0-9]{64}$", var.image))
    error_message = "Use an ECR image pinned by sha256 digest."
  }
}
variable "repository_arn" {
  type        = string
  description = "ARN of the ECR repository containing image; pull permission is limited to it."
}
variable "instance_type" {
  type    = string
  default = "t3.small"
}

data "aws_ssm_parameter" "ami" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}
resource "aws_vpc" "main" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}
resource "aws_subnet" "main" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.42.1.0/24"
}
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
}
resource "aws_route_table" "main" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
}
resource "aws_route_table_association" "main" {
  subnet_id      = aws_subnet.main.id
  route_table_id = aws_route_table.main.id
}
resource "aws_security_group" "main" {
  name_prefix = "distributedai-"
  vpc_id      = aws_vpc.main.id
  dynamic "ingress" {
    for_each = [80, 443]
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_iam_role" "host" {
  name_prefix = "distributedai-"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Action = "sts:AssumeRole", Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" } }]
  })
}
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.host.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
resource "aws_iam_role_policy" "ecr" {
  role = aws_iam_role.host.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["ecr:GetAuthorizationToken"], Resource = "*" },
      { Effect = "Allow", Action = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"], Resource = var.repository_arn }
    ]
  })
}
resource "aws_iam_instance_profile" "host" {
  name_prefix = "distributedai-"
  role        = aws_iam_role.host.name
}
resource "aws_instance" "main" {
  ami                         = data.aws_ssm_parameter.ami.value
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.main.id
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.main.id]
  iam_instance_profile        = aws_iam_instance_profile.host.name
  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
  root_block_device {
    volume_size = 30
    volume_type = "gp3"
    encrypted   = true
  }
  user_data = templatefile("${path.module}/bootstrap.sh.tftpl", {
    region   = var.region
    image    = var.image
    domain   = var.domain
    compose  = base64encode(file("${path.module}/../../compose.yaml"))
    internet = base64encode(file("${path.module}/../../compose.internet.yaml"))
    caddy    = base64encode(file("${path.module}/../../deploy/Caddyfile"))
    setup    = base64encode(file("${path.module}/../../scripts/setup.py"))
  })
  depends_on = [aws_route_table_association.main, aws_iam_role_policy.ecr, aws_iam_role_policy_attachment.ssm]
  lifecycle {
    prevent_destroy = true
  }
}
resource "aws_eip" "main" {
  domain   = "vpc"
  instance = aws_instance.main.id
}
output "public_ip" {
  value = aws_eip.main.public_ip
}
output "mcp_url" {
  value = "https://${var.domain}/mcp"
}
output "instance_id" {
  value = aws_instance.main.id
}
