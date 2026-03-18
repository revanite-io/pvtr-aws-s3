terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

module "pvtr_aws_s3" {
  source = "../../terraform/modules/pvtr-aws-s3"

  region                    = var.region
  bucket_name               = var.bucket_name
  allowed_ips               = var.allowed_ips
  object_lock_mode          = var.object_lock_mode
  object_lock_retention_days = var.object_lock_retention_days
  log_retention_days        = var.log_retention_days
  tags                      = var.tags
}
