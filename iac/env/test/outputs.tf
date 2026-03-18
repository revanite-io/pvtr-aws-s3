output "bucket_arn" {
  description = "ARN of the main S3 bucket for the plugin's config"
  value       = module.pvtr_aws_s3.bucket_arn
}

output "bucket_name" {
  value = module.pvtr_aws_s3.bucket_name
}

output "log_bucket_name" {
  value = module.pvtr_aws_s3.log_bucket_name
}

output "kms_key_arn" {
  value = module.pvtr_aws_s3.kms_key_arn
}
