variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "vpc_cidr" {
  description = "IP range for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "runner_subnet_cidr" {
  description = "IP range for runner subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "github_org" {
  description = "Your GitHub username or organisation"
  type        = string
}

variable "github_repo" {
  description = "GitHub repository name"
  type        = string
  default     = "monitized-cicd-platform"
}

variable "runner_instance_type" {
  description = "EC2 instance type for the runner"
  type        = string
  default     = "t3.micro"
}

variable "alert_email" {
  description = "Email for deployment notifications"
  type        = string
  sensitive   = true
}
