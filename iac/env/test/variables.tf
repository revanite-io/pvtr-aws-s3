variable "region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "bucket_name" {
  description = "S3 bucket name. If empty, auto-generated."
  type        = string
  default     = ""
}

variable "allowed_ips" {
  description = "List of IP addresses allowed to access the bucket (e.g. runner IP)"
  type        = list(string)
  default     = []
}

variable "object_lock_mode" {
  description = "Object Lock retention mode (COMPLIANCE or GOVERNANCE)"
  type        = string
  default     = "COMPLIANCE"
}

variable "object_lock_retention_days" {
  description = "Default Object Lock retention period in days"
  type        = number
  default     = 1
}

variable "log_retention_days" {
  description = "Number of days to retain objects in the log buckets"
  type        = number
  default     = 90
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default = {
    environment = "test"
    managed_by  = "terraform"
    project     = "pvtr-aws-s3"
  }
}
