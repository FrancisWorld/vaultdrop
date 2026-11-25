output "bucket_name" {
  value = aws_s3_bucket.vaultdrop.id
}

output "kms_key_arn" {
  value = aws_kms_key.vaultdrop.arn
}

output "app_policy_arn" {
  value = aws_iam_policy.app.arn
}
