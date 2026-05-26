# outputs.tf
# ============================================================
# Prints important information after terraform apply
# Use these values to configure GitHub Actions secrets
# and verify deployment was successful
# ============================================================

output "runner_instance_id" {
  description = "EC2 runner instance ID - use for SSM connection"
  value       = aws_instance.runner.id
}

output "runner_private_ip" {
  description = "Runner private IP - inside VPC only"
  value       = aws_instance.runner.private_ip
}

output "github_actions_role_arn" {
  description = "Copy this ARN into GitHub Actions secret AWS_ROLE_ARN"
  value       = aws_iam_role.github_actions.arn
}

output "artifacts_bucket_name" {
  description = "S3 bucket where pipeline artifacts are stored"
  value       = aws_s3_bucket.artifacts.id
}

output "sns_topic_arn" {
  description = "SNS topic ARN for deployment notifications"
  value       = aws_sns_topic.deployments.arn
}

output "vpc_id" {
  description = "VPC ID where runner lives"
  value       = aws_vpc.main.id
}

output "connect_to_runner" {
  description = "Command to connect to runner via SSM - no SSH needed"
  value       = "aws ssm start-session --target ${aws_instance.runner.id} --region ${var.aws_region}"
}
