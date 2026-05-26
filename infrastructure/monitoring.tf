# monitoring.tf
# ============================================================
# Everything related to logging, monitoring and alerting
# Three things:
# 1. CloudTrail — logs every AWS API call
# 2. CloudWatch — metrics, logs, alarms
# 3. AWS Config — continuous compliance checking
# ============================================================

# -----------------------------------------------------------
# 1. CLOUDTRAIL
# Records every single AWS API call in your account
# Who did what, when, from where
# Essential for incident response
# If something goes wrong — CloudTrail tells you the story
# -----------------------------------------------------------

# CloudWatch log group for CloudTrail
# keeps logs searchable for 90 days
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${var.environment}-cicd"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.storage.arn

  tags = {
    Name = "${var.environment}-cloudtrail-logs"
  }
}

# IAM role that allows CloudTrail to write to CloudWatch
resource "aws_iam_role" "cloudtrail" {
  name = "${var.environment}-cloudtrail-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "${var.environment}-cloudtrail-role"
  }
}

resource "aws_iam_role_policy" "cloudtrail" {
  name = "${var.environment}-cloudtrail-policy"
  role = aws_iam_role.cloudtrail.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        # locked to specific log group
        # not wildcard *
        Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
      }
    ]
  })
}

# S3 bucket policy allowing CloudTrail to write logs
resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.logs.id

  depends_on = [aws_s3_bucket_public_access_block.logs]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.logs.arn}/cloudtrail/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# CloudTrail itself
resource "aws_cloudtrail" "main" {
  name                          = "${var.environment}-cicd-trail"
  s3_bucket_name                = aws_s3_bucket.logs.id
  s3_key_prefix                 = "cloudtrail"
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail.arn
  kms_key_id                    = aws_kms_key.storage.arn

  # specifically log S3 data events
  # records every GetObject and PutObject on artifacts bucket
  # know exactly who accessed what artifact when
  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type = "AWS::S3::Object"
      values = [
        "${aws_s3_bucket.artifacts.arn}/"
      ]
    }
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail]

  tags = {
    Name = "${var.environment}-cicd-trail"
  }
}

# -----------------------------------------------------------
# 2. CLOUDWATCH
# Metrics, logs and alarms for the runner and pipeline
# Alerts you when something goes wrong
# -----------------------------------------------------------

# log group for runner logs
# all pipeline job output goes here
resource "aws_cloudwatch_log_group" "runner" {
  name              = "/cicd/${var.environment}/runner"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.storage.arn

  tags = {
    Name = "${var.environment}-runner-logs"
  }
}

# alarm — alerts if runner CPU is too high
# high CPU during pipeline = something wrong
# possible cryptomining if runner is compromised
resource "aws_cloudwatch_metric_alarm" "runner_cpu" {
  alarm_name          = "${var.environment}-runner-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Runner CPU above 80% - possible cryptomining or runaway process"
  alarm_actions       = [aws_sns_topic.deployments.arn]
  ok_actions          = [aws_sns_topic.deployments.arn]

  dimensions = {
    InstanceId = aws_instance.runner.id
  }

  tags = {
    Name = "${var.environment}-runner-cpu-alarm"
  }
}

# alarm — alerts if runner status check fails
# means the runner EC2 is unhealthy
# pipeline jobs will fail until fixed
resource "aws_cloudwatch_metric_alarm" "runner_status" {
  alarm_name          = "${var.environment}-runner-status"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "StatusCheckFailed"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  alarm_description   = "Runner EC2 status check failed - instance may be down"
  alarm_actions       = [aws_sns_topic.deployments.arn]

  dimensions = {
    InstanceId = aws_instance.runner.id
  }

  tags = {
    Name = "${var.environment}-runner-status-alarm"
  }
}

# -----------------------------------------------------------
# 3. AWS CONFIG
# Continuously checks every resource against security rules
# If someone manually changes something in AWS console
# Config detects it and flags it as non-compliant
# This is drift detection — catches manual changes
# -----------------------------------------------------------

# IAM role for Config
resource "aws_iam_role" "config" {
  name = "${var.environment}-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "${var.environment}-config-role"
  }
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

# Config recorder — records all resource configurations
resource "aws_config_configuration_recorder" "main" {
  name     = "${var.environment}-config-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

# delivery channel — where Config sends findings
resource "aws_config_delivery_channel" "main" {
  name           = "${var.environment}-config-delivery"
  s3_bucket_name = aws_s3_bucket.logs.id
  s3_key_prefix  = "config"

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}

# Config rule — S3 buckets must not be public
# if someone makes a bucket public via console
# Config flags it immediately
resource "aws_config_rule" "s3_public_access" {
  name        = "s3-bucket-public-access-prohibited"
  description = "S3 buckets must block all public access"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Config rule — CloudTrail must be enabled
# detects if someone disables CloudTrail
# disabling CloudTrail = attacker covering tracks
resource "aws_config_rule" "cloudtrail_enabled" {
  name        = "cloudtrail-enabled"
  description = "CloudTrail must be enabled at all times"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Config rule — root account MFA enabled
resource "aws_config_rule" "root_mfa" {
  name        = "root-account-mfa-enabled"
  description = "Root account must have MFA enabled"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.main]
}

# Config rule — EC2 instances must not have public IPs
resource "aws_config_rule" "ec2_no_public_ip" {
  name        = "ec2-instance-no-public-ip"
  description = "EC2 instances must not have public IP addresses"

  source {
    owner             = "AWS"
    source_identifier = "EC2_INSTANCE_NO_PUBLIC_IP"
  }

  depends_on = [aws_config_configuration_recorder.main]
}
