# compute.tf
# ============================================================
# EC2 self-hosted runner
# Lives in private subnet — no public IP, no SSH
# Managed via SSM — no port 22 needed
# IAM role attached — no hardcoded credentials
# ============================================================

# -----------------------------------------------------------
# Security group for runner
# No inbound rules at all
# SSM handles access without any open ports
# -----------------------------------------------------------
resource "aws_security_group" "runner" {
  name        = "${var.environment}-runner-sg"
  description = "Runner security group no inbound from internet"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "HTTPS outbound for GitHub and AWS services"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.environment}-runner-sg"
  }
}

# -----------------------------------------------------------
# EC2 Runner Instance
# -----------------------------------------------------------
resource "aws_instance" "runner" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = var.runner_instance_type
  subnet_id              = aws_subnet.runner.id
  vpc_security_group_ids = [aws_security_group.runner.id]
  iam_instance_profile   = aws_iam_instance_profile.runner.name

  # IMDSv2 enforced
  # prevents SSRF attacks stealing runner credentials
  # without this attacker can query metadata service
  # and steal the runner IAM role credentials
  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    http_endpoint               = "enabled"
  }

  # encrypted root volume
  # if someone gets physical access to disk
  # data is unreadable
  root_block_device {
    volume_size           = 30
    volume_type           = "gp3"
    encrypted             = true
    kms_key_id            = aws_kms_key.storage.arn
    delete_on_termination = true
  }

  # user data — runs automatically when EC2 starts
  # installs all tools the runner needs
  # calls the runner setup script
  user_data = base64encode(templatefile("${path.module}/../runner-setup/install-runner.sh", {
    github_org   = var.github_org
    github_repo  = var.github_repo
    environment  = var.environment
    aws_region   = var.aws_region
  }))

  tags = {
    Name = "${var.environment}-cicd-runner"
  }
}
resource "aws_instance" "runner" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = var.runner_instance_type
  subnet_id              = aws_subnet.runner.id
  vpc_security_group_ids = [aws_security_group.runner.id]
  iam_instance_profile   = aws_iam_instance_profile.runner.name
  monitoring             = true
  ebs_optimized          = true

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    http_endpoint               = "enabled"
  }

  root_block_device {
    volume_size           = 30
    volume_type           = "gp3"
    encrypted             = true
    kms_key_id            = aws_kms_key.storage.arn
    delete_on_termination = true
  }

  user_data = base64encode(templatefile("${path.module}/../runner-setup/install-runner.sh", {
    github_org  = var.github_org
    github_repo = var.github_repo
    environment = var.environment
    aws_region  = var.aws_region
  }))

  tags = {
    Name = "${var.environment}-cicd-runner"
  }
}
