resource "aws_kms_key" "vaultdrop" {
  description             = "VaultDrop S3 object encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_s3_bucket" "vaultdrop" {
  bucket = var.bucket_name
}

resource "aws_s3_bucket_public_access_block" "vaultdrop" {
  bucket                  = aws_s3_bucket.vaultdrop.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "vaultdrop" {
  bucket = aws_s3_bucket.vaultdrop.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vaultdrop" {
  bucket = aws_s3_bucket.vaultdrop.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.vaultdrop.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "vaultdrop" {
  bucket = aws_s3_bucket.vaultdrop.id
  rule {
    id     = "expire-stale-multipart"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
  rule {
    id     = "expire-old-versions"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

resource "aws_s3_bucket_cors_configuration" "vaultdrop" {
  bucket = aws_s3_bucket.vaultdrop.id
  cors_rule {
    allowed_headers = ["*"]
    allowed_methods = ["PUT", "GET", "HEAD"]
    allowed_origins = ["https://replace-me.example"]
    expose_headers  = ["ETag"]
    max_age_seconds = 3600
  }
}

data "aws_iam_policy_document" "tls" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.vaultdrop.arn, "${aws_s3_bucket.vaultdrop.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "tls" {
  bucket = aws_s3_bucket.vaultdrop.id
  policy = data.aws_iam_policy_document.tls.json
}

resource "aws_s3_bucket" "trail" {
  bucket = var.trail_bucket_name
}

resource "aws_s3_bucket_public_access_block" "trail" {
  bucket                  = aws_s3_bucket.trail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "trail" {
  statement {
    sid       = "AWSCloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
  statement {
    sid       = "AWSCloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail" {
  bucket = aws_s3_bucket.trail.id
  policy = data.aws_iam_policy_document.trail.json
}

resource "aws_cloudtrail" "vaultdrop" {
  name                          = "vaultdrop-data-events"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = false
  include_global_service_events = false

  event_selector {
    read_write_type           = "All"
    include_management_events = false
    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.vaultdrop.arn}/"]
    }
  }
}

data "aws_iam_policy_document" "app" {
  statement {
    actions = [
      "s3:CreateMultipartUpload",
      "s3:UploadPart",
      "s3:CompleteMultipartUpload",
      "s3:AbortMultipartUpload",
      "s3:GetObject",
      "s3:HeadObject",
      "s3:DeleteObject",
    ]
    resources = ["${aws_s3_bucket.vaultdrop.arn}/*"]
  }
  statement {
    actions   = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"]
    resources = [aws_kms_key.vaultdrop.arn]
  }
}

resource "aws_iam_policy" "app" {
  name   = "vaultdrop-app"
  policy = data.aws_iam_policy_document.app.json
}
