# iam.tf
# ============================================================
# Identity and Access Management
# Three things live here:
# 1. OIDC provider — lets GitHub prove identity to AWS
# 2. GitHub Actions role — what the pipeline can do in AWS
# 3. EC2 runner role — what the runner EC2 can do
# ============================================================

# -----------------------------------------------------------
# 1. OIDC Provider
# Registers GitHub as a trusted identity provider in AWS
# Without this AWS doesn't know who GitHub is
# -----------------------------------------------------------
resource "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"

  # who is allowed to use this provider
  # sts.amazonaws.com = AWS Security Token Service
  # the service that issues temporary credentials
  client_id_list = ["sts.amazonaws.com"]

  # GitHub's certificate thumbprint
  # AWS uses this to verify tokens actually came from GitHub
  # if someone tries to forge a GitHub token
  # the thumbprint won't match — request rejected
  thumbprint_list = [
    data.tls_certificate.github.certificates[0].sha1_fingerprint
  ]

  tags = {
    Name = "${var.environment}-github-oidc"
  }
}

# -----------------------------------------------------------
# 2. GitHub Actions Role
# This is what the pipeline assumes when it runs
# Only GitHub Actions from your specific repo can use it
# -----------------------------------------------------------
resource "aws_iam_role" "github_actions" {
  name        = "${var.environment}-github-actions-role"
  description = "Role assumed by GitHub Actions via OIDC"

  # trust policy — who is allowed to assume this role
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          # only the OIDC provider we just created
          Federated = aws_iam_openid_connect_provider.github.arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            # only sts.amazonaws.com can use this
            "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          }
          StringLike = {
            # only YOUR repo on main branch
            # not any other repo
            # not any other branch
            "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.github_repo}:ref:refs/heads/main"
          }
        }
      }
    ]
  })

  tags = {
    Name = "${var.environment}-github-actions-role"
  }
}

# -----------------------------------------------------------
# GitHub Actions Policy
# Exactly what the pipeline is allowed to do
# Least privilege — only what is actually needed
# -----------------------------------------------------------
resource "aws_iam_policy" "github_actions" {
  name        = "${var.environment}-github-actions-policy"
  description = "Least privilege policy for GitHub Actions pipeline"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # Terraform needs these to manage infrastructure
        Sid    = "TerraformStateAccess"
        Effect = "Allow"
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
      },
      {
        # needs to read its own role
        Sid    = "ReadOwnRole"
        Effect = "Allow"
        Action = [
          "iam:GetRole",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies"
        ]
        Resource = [
          "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.environment}-*"
        ]
      },
      {
        # SNS for notifications
        Sid    = "SNSPublish"
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = [
          aws_sns_topic.deployments.arn
        ]
      },
      {
        # CloudWatch for logging
        Sid    = "CloudWatchLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "github_actions" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.github_actions.arn
}

# -----------------------------------------------------------
# 3. EC2 Runner Role
# This is what the EC2 runner server uses
# Needs SSM access to be managed without SSH
# -----------------------------------------------------------
resource "aws_iam_role" "runner" {
  name        = "${var.environment}-runner-role"
  description = "Role for EC2 self-hosted runner"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name = "${var.environment}-runner-role"
  }
}

# SSM managed policy — allows Systems Manager access
# this is how you connect to the runner without SSH
# no port 22 needed at all
resource "aws_iam_role_policy_attachment" "runner_ssm" {
  role       = aws_iam_role.runner.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# CloudWatch agent policy — sends runner metrics to CloudWatch
resource "aws_iam_role_policy_attachment" "runner_cloudwatch" {
  role       = aws_iam_role.runner.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# runner needs to read from S3 — downloads tools and scripts
resource "aws_iam_policy" "runner_s3" {
  name        = "${var.environment}-runner-s3-policy"
  description = "Allows runner to read from artifacts bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3ReadAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
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

resource "aws_iam_role_policy_attachment" "runner_s3" {
  role       = aws_iam_role.runner.name
  policy_arn = aws_iam_policy.runner_s3.arn
}

# instance profile — wrapper so EC2 can use the role
resource "aws_iam_instance_profile" "runner" {
  name = "${var.environment}-runner-profile"
  role = aws_iam_role.runner.name

  tags = {
    Name = "${var.environment}-runner-profile"
  }
}
