#!/bin/bash
# provision.sh — Main provisioning script for Lima VM
# Installs all required tools and scanners for Project Threat Scanner.
# Designed to be idempotent: checks before installing each component.
set -euo pipefail

LOG_PREFIX="[provision]"

log() {
    echo "${LOG_PREFIX} $(date '+%H:%M:%S') $*"
}

# ---------------------------------------------------------------------------
# System update
# ---------------------------------------------------------------------------
log "Updating apt package lists..."
sudo apt-get update -qq

# ---------------------------------------------------------------------------
# Git
# ---------------------------------------------------------------------------
if command -v git &>/dev/null; then
    log "Git already installed: $(git --version)"
else
    log "Installing Git..."
    sudo apt-get install -y -qq git
    log "Git installed: $(git --version)"
fi

# ---------------------------------------------------------------------------
# Docker
# ---------------------------------------------------------------------------
if command -v docker &>/dev/null; then
    log "Docker already installed: $(docker --version)"
else
    log "Installing Docker..."
    sudo apt-get install -y -qq ca-certificates curl gnupg lsb-release

    # Add Docker official GPG key and repo
    sudo install -m 0755 -d /etc/apt/keyrings
    if [ ! -f /etc/apt/keyrings/docker.asc ]; then
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo tee /etc/apt/keyrings/docker.asc >/dev/null
        sudo chmod a+r /etc/apt/keyrings/docker.asc
    fi

    if [ ! -f /etc/apt/sources.list.d/docker.list ]; then
        echo \
            "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
            $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
            sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
        sudo apt-get update -qq
    fi

    sudo apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    log "Docker installed: $(docker --version)"
fi

# Add current user to docker group (idempotent — adduser is a no-op if already a member)
if ! groups "$USER" | grep -q '\bdocker\b'; then
    log "Adding $USER to docker group..."
    sudo usermod -aG docker "$USER"
    log "User added to docker group. Note: group change takes effect on next login."
else
    log "User $USER already in docker group."
fi

# ---------------------------------------------------------------------------
# Python 3, pip, venv
# ---------------------------------------------------------------------------
if command -v python3 &>/dev/null && python3 -m pip --version &>/dev/null && python3 -c "import venv" 2>/dev/null; then
    log "Python 3 already installed: $(python3 --version)"
else
    log "Installing Python 3, pip, and venv..."
    sudo apt-get install -y -qq python3 python3-pip python3-venv
    log "Python 3 installed: $(python3 --version)"
fi

# ---------------------------------------------------------------------------
# Node.js 20.x LTS (via nodesource)
# ---------------------------------------------------------------------------
if command -v node &>/dev/null && node --version | grep -q '^v20\.'; then
    log "Node.js 20.x already installed: $(node --version)"
else
    log "Installing Node.js 20.x LTS..."
    # Remove any existing nodesource list to avoid conflicts
    sudo rm -f /etc/apt/sources.list.d/nodesource.list

    # Install via nodesource setup script
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y -qq nodejs
    log "Node.js installed: $(node --version), npm: $(npm --version)"
fi

# ---------------------------------------------------------------------------
# Rust toolchain (rustup)
# ---------------------------------------------------------------------------
if command -v rustc &>/dev/null; then
    log "Rust already installed: $(rustc --version)"
else
    log "Installing Rust toolchain via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --quiet
    # Source cargo env for the rest of this script
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
    log "Rust installed: $(rustc --version)"
fi

# Ensure cargo is on PATH for subsequent commands
if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
fi

# ---------------------------------------------------------------------------
# Go (latest stable via apt)
# ---------------------------------------------------------------------------
if command -v go &>/dev/null; then
    log "Go already installed: $(go version)"
else
    log "Installing Go..."
    sudo apt-get install -y -qq golang-go
    log "Go installed: $(go version)"
fi

# Ensure GOPATH/bin is on PATH
export PATH="${PATH}:$(go env GOPATH)/bin:/usr/local/go/bin"

# ---------------------------------------------------------------------------
# Claude Code
# ---------------------------------------------------------------------------
if command -v claude &>/dev/null; then
    log "Claude Code already installed."
else
    log "Installing Claude Code..."
    sudo npm install -g @anthropic-ai/claude-code
    log "Claude Code installed."
fi

# ---------------------------------------------------------------------------
# Security Scanners
# ---------------------------------------------------------------------------

# --- Syft (SBOM generator from Anchore) ---
if command -v syft &>/dev/null; then
    log "Syft already installed: $(syft version 2>/dev/null || echo 'version check skipped')"
else
    log "Installing Syft..."
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin
    log "Syft installed."
fi

# --- Grype (vulnerability scanner from Anchore) ---
if command -v grype &>/dev/null; then
    log "Grype already installed: $(grype version 2>/dev/null || echo 'version check skipped')"
else
    log "Installing Grype..."
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin
    log "Grype installed."
fi

# --- OSV-Scanner (Google's vulnerability scanner) ---
if command -v osv-scanner &>/dev/null; then
    log "OSV-Scanner already installed."
else
    log "Installing OSV-Scanner..."
    go install github.com/google/osv-scanner/cmd/osv-scanner@latest
    log "OSV-Scanner installed."
fi

# --- Semgrep (SAST) ---
if command -v semgrep &>/dev/null; then
    log "Semgrep already installed: $(semgrep --version 2>/dev/null || echo 'version check skipped')"
else
    log "Installing Semgrep..."
    python3 -m pip install --break-system-packages --ignore-installed semgrep
    log "Semgrep installed."
fi

# --- GuardDog (supply chain behavioral analysis) ---
if command -v guarddog &>/dev/null; then
    log "GuardDog already installed."
else
    log "Installing GuardDog..."
    python3 -m pip install --break-system-packages --ignore-installed guarddog
    # Initialize GuardDog's package cache (writes to dist-packages dir)
    guarddog --help >/dev/null 2>&1 || true
    log "GuardDog installed."
fi

# --- Gitleaks (secrets detection) ---
if command -v gitleaks &>/dev/null; then
    log "Gitleaks already installed: $(gitleaks version 2>/dev/null || echo 'version check skipped')"
else
    log "Installing Gitleaks..."
    go install github.com/zricethezav/gitleaks/v8@latest
    log "Gitleaks installed."
fi

# ---------------------------------------------------------------------------
# Create working directories
# ---------------------------------------------------------------------------
log "Creating working directories..."
sudo mkdir -p /opt/target
sudo mkdir -p /opt/deps
sudo mkdir -p /opt/scan-results
sudo mkdir -p /opt/security-reports

# Make directories writable by current user
sudo chown -R "$USER:$USER" /opt/target /opt/deps /opt/scan-results /opt/security-reports

log "Provisioning complete. All tools installed and directories created."
