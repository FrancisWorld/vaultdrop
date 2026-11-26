variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "bucket_name" {
  type = string
}

variable "trail_bucket_name" {
  type = string
}

variable "allowed_origins" {
  description = "Origins of the VaultDrop web UI; the browser PUTs/GETs presigned URLs from these."
  type        = list(string)
  default     = ["https://vaultdrop.example.invalid"]
}
