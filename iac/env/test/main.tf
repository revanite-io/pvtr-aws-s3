terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.38"
    }
  }
}

provider "aws" {
  region = var.region
}

module "pvtr_aws_s3" {
  source = "git::https://github.com/revanite-io/pvtr-terraform.git//modules/pvtr-aws-s3?ref=9f8ca38296b4ad4b264b997ff6427285ca7aafdb" # v0.1.0

  bucket_name               = var.bucket_name
  allowed_ips               = var.allowed_ips
  object_lock_mode          = var.object_lock_mode
  object_lock_retention_days = var.object_lock_retention_days
  log_retention_days        = var.log_retention_days
  tags                      = var.tags
}
