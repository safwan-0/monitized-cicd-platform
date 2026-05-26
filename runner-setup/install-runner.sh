#!/bin/bash
# ============================================================
# install-runner.sh
# Runs automatically when EC2 starts via user_data
# Installs GitHub Actions runner and all security tools
# No manual SSH needed — fully automated
# ============================================================

set -euo pipefail
# exit on error, undefined variables, pipe failures
# without these a failed command silently continues
# dangerous in setup scripts

LOG_FILE="/var/log/runner-setup.log"

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log "Starting runner setup"

# -----------------------------------------------------------
# System updates
# always update first — patches known vulnerabilities
# -----------------------------------------------------------
log "Updating system packages"
dnf update -y
dnf install -y \
  git \
  curl \
  unzip \
  python3 \
  python3-pip \
  docker \
  jq

# -----------------------------------------------------------
# Install security scanning tools
# -----------------------------------------------------------
log "Installing Checkov"
pip3 install checkov --break-system-packages

log "Installing tfsec"
curl -Lo /usr/local/bin/tfsec \
  https://github.com/aquasecurity/tfsec/releases/latest/download/tfsec-linux-amd64
chmod +x /usr/local/bin/tfsec

log "Installing Trivy"
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sh -s -- -b /usr/local/bin

log "Installing Bandit"
pip3 install bandit safety --break-system-packages

log "Installing ShellCheck"
dnf install -y ShellCheck

log "Installing Terraform"
dnf install -y yum-utils
yum-config-manager --add-repo \
  https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo
dnf install -y terraform

log "Installing Infracost"
curl -fsSL https://raw.githubusercontent.com/infracost/infracost/master/scripts/install.sh \
  | sh

# -----------------------------------------------------------
# Start Docker
# needed for container scanning
# -----------------------------------------------------------
log "Starting Docker"
systemctl enable docker
systemctl start docker
usermod -aG docker ec2-user

# -----------------------------------------------------------
# Create runner user
# runner should not run as root
# least privilege — dedicated user for runner process
# -----------------------------------------------------------
log "Creating runner user"
useradd -m -s /bin/bash runner
usermod -aG docker runner

# -----------------------------------------------------------
# Install GitHub Actions runner
# -----------------------------------------------------------
log "Installing GitHub Actions runner"
RUNNER_VERSION="2.317.0"
RUNNER_DIR="/home/runner/actions-runner"

mkdir -p "$RUNNER_DIR"
cd "$RUNNER_DIR"

curl -o runner.tar.gz -L \
  "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz"

tar xzf runner.tar.gz
rm runner.tar.gz

chown -R runner:runner "$RUNNER_DIR"

# -----------------------------------------------------------
# Get registration token from AWS SSM Parameter Store
# token stored securely — not hardcoded in script
# -----------------------------------------------------------
log "Getting registration token from SSM"
REGISTRATION_TOKEN=$(aws ssm get-parameter \
  --name "/${environment}/${github_repo}/runner-token" \
  --with-decryption \
  --region "${aws_region}" \
  --query "Parameter.Value" \
  --output text)

# -----------------------------------------------------------
# Configure and start runner
# -----------------------------------------------------------
log "Configuring runner"
sudo -u runner "$RUNNER_DIR/config.sh" \
  --url "https://github.com/${github_org}/${github_repo}" \
  --token "$REGISTRATION_TOKEN" \
  --name "${environment}-runner" \
  --labels "${environment},aws,security" \
  --unattended \
  --replace

log "Installing runner as service"
"$RUNNER_DIR/svc.sh" install runner
"$RUNNER_DIR/svc.sh" start

log "Runner setup complete"
