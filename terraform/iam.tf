data "aws_iam_policy_document" "app" {
  statement {
    actions = [
      "s3:CreateMultipartUpload",
      "s3:UploadPart",
      "s3:CompleteMultipartUpload",
      "s3:AbortMultipartUpload",
      "s3:ListMultipartUploadParts",
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
