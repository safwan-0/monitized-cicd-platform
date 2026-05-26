# storage.tf
# ============================================================
# S3 bucket for storing pipeline artifacts
# Every deployment stores:
# - Terraform plan files
# - Security scan reports
# - Cost estimation reports
# - Post deploy verification results
# This becomes your audit trail — proof of every deployment
# ============================================================

# -----------------------------------------------------------
# KMS Key — encrypts everything in S3
# separate key for storage
# if this key is compromised only storage is affected
# not the entire account
# -----------------------------------------------------------
resource "aws_kms_key" "storage" {
  description             = "KMS key for pipeline artifact encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow S3 to use key"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow CloudWatch to use key"
        Effect = "Allow"
        Principal = {
          Service = "logs.${var.aws_region}.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "${var.environment}-storage-kms-key"
  }
}

resource "aws_kms_alias" "storage" {
  name          = "alias/${var.environment}-storage-key"
  target_key_id = aws_kms_key.storage.key_id
}

# -----------------------------------------------------------
# Artifacts bucket — stores everything the pipeline produces
# -----------------------------------------------------------
#checkov:skip=CKV_AWS_144:Cross-region replication not required
resource "aws_s3_bucket" "artifacts" {
  bucket        = "${var.environment}-cicd-artifacts-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = {
    Name = "${var.environment}-cicd-artifacts"
  }
}

# block all public access
# pipeline artifacts must never be publicly accessible
# contains security scan results and infrastructure details
resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket                  = aws_s3_bucket.artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# versioning — keeps every version of every artifact
# if a scan report is overwritten you can recover old version
# ransomware protection — cannot permanently delete
resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

# encryption — all artifacts encrypted with KMS
# scan reports contain security findings
# must not be readable if bucket is somehow accessed
resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.storage.arn
    }
    bucket_key_enabled = true
  }
}

# lifecycle policy — manages artifact retention
# keeps recent artifacts accessible
# moves old ones to cheaper storage
# deletes very old ones automatically
resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "artifact-lifecycle"
    status = "Enabled"

    filter {}

    # move to cheaper storage after 30 days
    # Infrequent Access = 40% cheaper than Standard
    # still immediately accessible when needed
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    # move to Glacier after 90 days
    # very cheap long term storage
    # takes hours to restore but rarely needed
    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    # delete after 365 days
    # one year of audit trail is sufficient
    # keeps storage costs minimal
    expiration {
      days = 365
    }

    # clean up old versions after 90 days
    # versioning keeps everything forever without this
    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    # clean up failed multipart uploads
    # large files upload in parts
    # failed uploads leave orphaned parts
    # this cleans them up after 7 days
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# bucket policy — enforces HTTPS only
# no unencrypted HTTP requests allowed
# anyone trying HTTP gets hard deny
resource "aws_s3_bucket_policy" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  depends_on = [aws_s3_bucket_public_access_block.artifacts]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonHTTPS"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.artifacts.arn,
          "${aws_s3_bucket.artifacts.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        # only the GitHub Actions role and runner
        # can read and write to this bucket
        # nobody else even if they have AWS access
        Sid    = "AllowPipelineAccess"
        Effect = "Allow"
        Principal = {
          AWS = [
            aws_iam_role.github_actions.arn,
            aws_iam_role.runner.arn
          ]
        }
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.artifacts.arn,
          "${aws_s3_bucket.artifacts.arn}/*"
        ]
      }
    ]
  })
}

# SNS topic for deployment notifications
# every deployment success or failure sends an email
# you always know what happened
resource "aws_sns_topic" "deployments" {
  name              = "${var.environment}-deployment-notifications"
  kms_master_key_id = aws_kms_key.storage.arn

  tags = {
    Name = "${var.environment}-deployment-notifications"
  }
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.deployments.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# log bucket for S3 access logs
# records every request to the artifacts bucket
# who accessed what and when
#checkov:skip=CKV_AWS_144:Cross-region replication not required
resource "aws_s3_bucket" "logs" {
  bucket        = "${var.environment}-cicd-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = {
    Name = "${var.environment}-cicd-logs"
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.storage.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "expire-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = 365
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_logging" "artifacts" {
  bucket        = aws_s3_bucket.artifacts.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "artifacts-access-logs/"
}
# SNS topic for S3 notifications
resource "aws_sns_topic" "s3_notifications" {
  name              = "${var.environment}-s3-notifications"
  kms_master_key_id = aws_kms_key.storage.arn

  tags = {
    Name = "${var.environment}-s3-notifications"
  }
}

resource "aws_sns_topic_policy" "s3_notifications" {
  arn = aws_sns_topic.s3_notifications.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action    = "SNS:Publish"
        Resource  = aws_sns_topic.s3_notifications.arn
        Condition = {
          ArnLike = {
            "aws:SourceArn" = aws_s3_bucket.artifacts.arn
          }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_notification" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  topic {
    topic_arn = aws_sns_topic.s3_notifications.arn
    events    = ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
  }

  depends_on = [aws_sns_topic_policy.s3_notifications]
}
