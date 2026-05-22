terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0, < 5.100.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

 
  default_tags {
    tags = {
      Project     = "monitized-cicd-platform"
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = "Safwan "
    }
  }
}

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0, < 5.100.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}
