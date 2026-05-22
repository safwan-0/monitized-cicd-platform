data "aws_caller_identity" "current" {}


data "aws_region" "current" {}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

data "tls_certificate" "github" {
  url = "https://token.actions.githubusercontent.com"
}
