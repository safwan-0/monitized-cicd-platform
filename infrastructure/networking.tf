resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.environment}-cicd-vpc"
  }
}

# -----------------------------------------------------------
# Private subnet — runner lives here
# no map_public_ip = runner has no public IP
# attacker cannot reach it directly from internet
# -----------------------------------------------------------
resource "aws_subnet" "runner" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.runner_subnet_cidr
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.environment}-runner-subnet"
  }
}

# -----------------------------------------------------------
# VPC Endpoints — lets runner talk to AWS services
# without going through internet
# free alternative to NAT Gateway ($45/month saved)
# -----------------------------------------------------------

# S3 endpoint — runner can access S3 privately
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.runner.id]

  tags = {
    Name = "${var.environment}-s3-endpoint"
  }
}

# SSM endpoint — lets you connect to runner without SSH
# no port 22 needed — more secure
resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.runner.id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true

  tags = {
    Name = "${var.environment}-ssm-endpoint"
  }
}

resource "aws_vpc_endpoint" "ssm_messages" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ssmmessages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.runner.id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true

  tags = {
    Name = "${var.environment}-ssmmessages-endpoint"
  }
}

resource "aws_vpc_endpoint" "ec2_messages" {
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.aws_region}.ec2messages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.runner.id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true

  tags = {
    Name = "${var.environment}-ec2messages-endpoint"
  }
}

# -----------------------------------------------------------
# Route table — controls where traffic goes
# no route to internet gateway
# runner cannot be reached from internet
# -----------------------------------------------------------
resource "aws_route_table" "runner" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.environment}-runner-rt"
  }
}

resource "aws_route_table_association" "runner" {
  subnet_id      = aws_subnet.runner.id
  route_table_id = aws_route_table.runner.id
}

# -----------------------------------------------------------
# Security group for runner
# no inbound from internet
# only outbound to AWS services via endpoints
# -----------------------------------------------------------
resource "aws_security_group" "runner" {
  name        = "${var.environment}-runner-sg"
  description = "Runner security group - no inbound from internet"
  vpc_id      = aws_vpc.main.id

  # no ingress rules at all
  # nobody can connect to the runner from outside
  # SSM handles access without open ports

  egress {
    description = "HTTPS to AWS services via endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.environment}-runner-sg"
  }
}

# security group for VPC endpoints
resource "aws_security_group" "endpoints" {
  name        = "${var.environment}-endpoints-sg"
  description = "Security group for VPC endpoints"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "HTTPS from runner only"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.runner.id]
  }

  egress {
    description = "HTTPS outbound"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.environment}-endpoints-sg"
  }
}
# default security group — restrict all traffic
# Checkov requires default SG to deny everything
resource "aws_default_security_group" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.environment}-default-sg-restricted"
  }
}

# VPC Flow Logs — required by Checkov
resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc/${var.environment}/flow-logs"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.storage.arn

  tags = {
    Name = "${var.environment}-vpc-flow-logs"
  }
}

resource "aws_iam_role" "vpc_flow_logs" {
  name = "${var.environment}-vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "vpc_flow_logs" {
  name = "${var.environment}-vpc-flow-logs-policy"
  role = aws_iam_role.vpc_flow_logs.id

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
        Resource = "${aws_cloudwatch_log_group.vpc_flow_logs.arn}:*"
      }
    ]
  })
}

resource "aws_flow_log" "main" {
  vpc_id          = aws_vpc.main.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.vpc_flow_logs.arn
  log_destination = aws_cloudwatch_log_group.vpc_flow_logs.arn

  tags = {
    Name = "${var.environment}-flow-log"
  }
}
