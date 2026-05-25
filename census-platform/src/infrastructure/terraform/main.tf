##############################################################################
# Census Platform — Terraform Infrastructure
# Multi-region AWS deployment with disaster recovery
##############################################################################

terraform {
  required_version = ">= 1.7.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.0"
    }
  }

  backend "s3" {
    bucket         = "census-platform-tfstate"
    key            = "prod/terraform.tfstate"
    region         = "me-central-1"  # Middle East region
    encrypt        = true
    kms_key_id     = "arn:aws:kms:me-central-1:ACCOUNT_ID:key/KEY_ID"
    dynamodb_table = "census-tf-lock"
  }
}

# ─── Variables ───────────────────────────────────────────────────────────────

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "production"
}

variable "primary_region" {
  description = "Primary AWS region"
  type        = string
  default     = "me-central-1"  # UAE (closest to Iraq/Middle East)
}

variable "dr_region" {
  description = "Disaster recovery AWS region"
  type        = string
  default     = "eu-west-1"   # Ireland (GDPR compliant fallback)
}

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.r7g.2xlarge"
}

variable "eks_node_type" {
  description = "EKS worker node instance type"
  type        = string
  default     = "m7g.2xlarge"
}

# ─── Providers ───────────────────────────────────────────────────────────────

provider "aws" {
  region = var.primary_region
  alias  = "primary"

  default_tags {
    tags = {
      Project     = "CensusPlatform"
      Environment = var.environment
      ManagedBy   = "Terraform"
      DataClass   = "Confidential-Government"
    }
  }
}

provider "aws" {
  region = var.dr_region
  alias  = "dr"
}

# ─── KMS Keys ─────────────────────────────────────────────────────────────────

resource "aws_kms_key" "identity_db_key" {
  provider                = aws.primary
  description             = "Census Platform — Identity DB encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  multi_region            = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "Enable IAM User Permissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid    = "Allow RDS to use the key"
        Effect = "Allow"
        Principal = { Service = "rds.amazonaws.com" }
        Action = ["kms:GenerateDataKey", "kms:Decrypt"]
        Resource = "*"
      }
    ]
  })
}

resource "aws_kms_key" "census_db_key" {
  provider                = aws.primary
  description             = "Census Platform — Census DB encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

# ─── VPC ─────────────────────────────────────────────────────────────────────

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  providers = { aws = aws.primary }

  name = "census-platform-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["me-central-1a", "me-central-1b", "me-central-1c"]
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
  database_subnets = ["10.0.201.0/24", "10.0.202.0/24", "10.0.203.0/24"]

  enable_nat_gateway     = true
  single_nat_gateway     = false  # HA: one NAT per AZ
  enable_vpn_gateway     = false
  enable_dns_hostnames   = true
  enable_dns_support     = true

  # Flow logs for security auditing
  enable_flow_log                      = true
  create_flow_log_cloudwatch_iam_role  = true
  create_flow_log_cloudwatch_log_group = true

  tags = {
    "kubernetes.io/cluster/census-eks" = "shared"
  }
}

# ─── EKS Cluster ─────────────────────────────────────────────────────────────

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"

  providers = { aws = aws.primary }

  cluster_name    = "census-eks"
  cluster_version = "1.29"

  vpc_id                         = module.vpc.vpc_id
  subnet_ids                     = module.vpc.private_subnets
  cluster_endpoint_private_access = true
  cluster_endpoint_public_access  = false  # Only via VPN/bastion

  # Encryption for etcd (K8s secrets)
  cluster_encryption_config = {
    resources        = ["secrets"]
    provider_key_arn = aws_kms_key.identity_db_key.arn
  }

  # Managed node groups
  eks_managed_node_groups = {
    api_nodes = {
      name           = "census-api-nodes"
      instance_types = [var.eks_node_type]
      min_size       = 3
      max_size       = 20
      desired_size   = 6

      labels = { role = "api" }

      taints = []

      # Spot instances for 60% cost reduction (with on-demand fallback)
      capacity_type = "SPOT"
      spot_instance_types = [
        "m7g.2xlarge", "m6g.2xlarge", "m6i.2xlarge"
      ]
    }

    ml_nodes = {
      name           = "census-ml-nodes"
      instance_types = ["g4dn.xlarge"]  # GPU for face verification
      min_size       = 1
      max_size       = 5
      desired_size   = 2
      capacity_type  = "ON_DEMAND"

      labels = { role = "ml-inference" }
      taints = [{
        key    = "nvidia.com/gpu"
        value  = "true"
        effect = "NO_SCHEDULE"
      }]
    }
  }
}

# ─── RDS — Identity Database ─────────────────────────────────────────────────

resource "aws_db_instance" "identity_db" {
  provider = aws.primary

  identifier        = "census-identity-db"
  engine            = "postgres"
  engine_version    = "16.2"
  instance_class    = var.db_instance_class
  allocated_storage = 100
  storage_type      = "gp3"
  iops              = 3000

  db_name  = "identity"
  username = "census_admin"
  password = data.aws_secretsmanager_secret_version.db_password.secret_string

  # Encryption
  storage_encrypted = true
  kms_key_id        = aws_kms_key.identity_db_key.arn

  # Network
  db_subnet_group_name   = aws_db_subnet_group.census.name
  vpc_security_group_ids = [aws_security_group.identity_db.id]
  publicly_accessible    = false

  # HA
  multi_az               = true
  backup_retention_period = 30
  backup_window           = "02:00-03:00"
  maintenance_window      = "sun:04:00-sun:05:00"

  # Security
  deletion_protection         = true
  skip_final_snapshot         = false
  final_snapshot_identifier   = "census-identity-db-final"
  copy_tags_to_snapshot       = true
  performance_insights_enabled = true
  performance_insights_kms_key_id = aws_kms_key.identity_db_key.arn
  monitoring_interval         = 60
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  lifecycle {
    prevent_destroy = true
  }
}

# ─── RDS — Census (Demographic) Database ─────────────────────────────────────

resource "aws_db_instance" "census_db" {
  provider = aws.primary

  identifier        = "census-demographic-db"
  engine            = "postgres"
  engine_version    = "16.2"
  instance_class    = var.db_instance_class
  allocated_storage = 500
  storage_type      = "gp3"

  db_name  = "census"
  username = "census_admin"
  password = data.aws_secretsmanager_secret_version.db_password.secret_string

  storage_encrypted = true
  kms_key_id        = aws_kms_key.census_db_key.arn

  db_subnet_group_name   = aws_db_subnet_group.census.name
  vpc_security_group_ids = [aws_security_group.census_db.id]
  publicly_accessible    = false

  multi_az                = true
  backup_retention_period = 30
  deletion_protection     = true

  lifecycle {
    prevent_destroy = true
  }
}

# ─── ElastiCache — Redis ──────────────────────────────────────────────────────

resource "aws_elasticache_replication_group" "redis" {
  provider = aws.primary

  replication_group_id = "census-redis"
  description          = "Census Platform Redis cluster for OTP and rate limiting"

  node_type            = "cache.r7g.large"
  num_cache_clusters   = 3
  parameter_group_name = "default.redis7"
  engine_version       = "7.1"

  subnet_group_name  = aws_elasticache_subnet_group.census.name
  security_group_ids = [aws_security_group.redis.id]

  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                 = data.aws_secretsmanager_secret_version.redis_auth.secret_string

  automatic_failover_enabled = true
  multi_az_enabled           = true

  snapshot_retention_limit = 7
  snapshot_window          = "03:00-04:00"
}

# ─── WAF — Web Application Firewall ──────────────────────────────────────────

resource "aws_wafv2_web_acl" "census" {
  provider = aws.primary
  name     = "census-platform-waf"
  scope    = "REGIONAL"

  default_action {
    allow {}
  }

  # Block common attack patterns
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "RateLimitRule"
    priority = 2
    action { block {} }
    statement {
      rate_based_statement {
        limit              = 1000
        aggregate_key_type = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitMetric"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "CensusWAFMetric"
    sampled_requests_enabled   = true
  }
}

# ─── Outputs ─────────────────────────────────────────────────────────────────

output "eks_cluster_endpoint" {
  value     = module.eks.cluster_endpoint
  sensitive = true
}

output "identity_db_endpoint" {
  value     = aws_db_instance.identity_db.endpoint
  sensitive = true
}

output "census_db_endpoint" {
  value     = aws_db_instance.census_db.endpoint
  sensitive = true
}

output "redis_endpoint" {
  value     = aws_elasticache_replication_group.redis.primary_endpoint_address
  sensitive = true
}

# ─── Data Sources ─────────────────────────────────────────────────────────────

data "aws_caller_identity" "current" {}

data "aws_secretsmanager_secret_version" "db_password" {
  secret_id = "census-platform/db-password"
}

data "aws_secretsmanager_secret_version" "redis_auth" {
  secret_id = "census-platform/redis-auth"
}
