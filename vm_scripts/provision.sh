#!/bin/bash
# provision.sh — Main provisioning script for Lima VM
# Installs all required tools and scanners for Thresher.
# Designed to be idempotent: checks before installing each component.
set -euo pipefail

LOG_PREFIX="[provision]"

log() {
    echo "${LOG_PREFIX} $(date '+%H:%M:%S') $*"
}

# ---------------------------------------------------------------------------
# Fix hostname resolution (Lima VMs may not have their hostname in /etc/hosts)
# ---------------------------------------------------------------------------
HOSTNAME=$(hostname)
if ! grep -q "$HOSTNAME" /etc/hosts 2>/dev/null; then
    log "Adding $HOSTNAME to /etc/hosts..."
    echo "127.0.0.1 $HOSTNAME" | sudo tee -a /etc/hosts >/dev/null
fi

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

# Ensure GOPATH/bin is on PATH for this script
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

# --- Checkov (IaC scanning: Dockerfile, Terraform, K8s, Helm, CloudFormation) ---
if command -v checkov &>/dev/null; then
    log "Checkov already installed: $(checkov --version 2>/dev/null || echo 'version check skipped')"
else
    log "Installing Checkov..."
    python3 -m pip install --break-system-packages --ignore-installed checkov
    log "Checkov installed."
fi

# --- Bandit (Python-specific SAST) ---
if command -v bandit &>/dev/null; then
    log "Bandit already installed: $(bandit --version 2>/dev/null || echo 'version check skipped')"
else
    log "Installing Bandit..."
    python3 -m pip install --break-system-packages --ignore-installed bandit
    log "Bandit installed."
fi

# --- Hadolint (Dockerfile linter with ShellCheck) ---
if command -v hadolint &>/dev/null; then
    log "Hadolint already installed: $(hadolint --version 2>/dev/null || echo 'version check skipped')"
else
    log "Installing Hadolint..."
    HADOLINT_ARCH="$(dpkg --print-architecture)"
    if [ "$HADOLINT_ARCH" = "arm64" ]; then HADOLINT_ARCH="arm64"; else HADOLINT_ARCH="x86_64"; fi
    curl -sSfL "https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-${HADOLINT_ARCH}" -o /usr/local/bin/hadolint
    sudo chmod +x /usr/local/bin/hadolint
    log "Hadolint installed."
fi

# --- Trivy (container image + IaC + vulnerability scanner) ---
if command -v trivy &>/dev/null; then
    log "Trivy already installed: $(trivy version 2>/dev/null | head -1 || echo 'version check skipped')"
else
    log "Installing Trivy..."
    curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin
    log "Trivy installed."
fi

# --- govulncheck (Go call-graph-aware vulnerability scanner) ---
if command -v govulncheck &>/dev/null; then
    log "govulncheck already installed."
else
    log "Installing govulncheck..."
    go install golang.org/x/vuln/cmd/govulncheck@latest
    log "govulncheck installed."
fi

# --- cargo-audit (Rust vulnerability scanner) ---
if command -v cargo-audit &>/dev/null; then
    log "cargo-audit already installed."
else
    log "Installing cargo-audit..."
    cargo install cargo-audit --quiet
    log "cargo-audit installed."
fi

# --- YARA (malware signature matching) ---
if command -v yara &>/dev/null; then
    log "YARA already installed: $(yara --version 2>/dev/null || echo 'version check skipped')"
else
    log "Installing YARA..."
    sudo apt-get install -y -qq yara
    log "YARA installed."
fi

# --- YARA community rules ---
YARA_RULES_DIR="/opt/yara-rules"
if [ -d "$YARA_RULES_DIR" ]; then
    log "YARA community rules already present."
else
    log "Downloading YARA community rules (hardened clone)..."
    sudo git clone \
        --depth=1 \
        --no-checkout \
        --single-branch \
        -c core.hooksPath=/dev/null \
        -c core.fsmonitor=false \
        -c protocol.file.allow=never \
        -c protocol.ext.allow=never \
        https://github.com/Yara-Rules/rules.git "$YARA_RULES_DIR"
    cd "$YARA_RULES_DIR" && sudo GIT_LFS_SKIP_SMUDGE=1 GIT_TERMINAL_PROMPT=0 git checkout
    cd /
    log "YARA community rules installed to $YARA_RULES_DIR"
fi

# --- capa (binary capability detection from Mandiant) ---
if command -v capa &>/dev/null; then
    log "capa already installed."
else
    log "Installing capa..."
    sudo apt-get install -y -qq unzip
    if python3 -m pip install --break-system-packages --ignore-installed flare-capa 2>&1; then
        log "capa installed."
    else
        log "WARNING: capa installation failed (optional, continuing without it)."
    fi
fi

# --- ClamAV (open source antivirus) ---
if command -v clamscan &>/dev/null; then
    log "ClamAV already installed: $(clamscan --version 2>/dev/null | head -1 || echo 'version check skipped')"
else
    log "Installing ClamAV..."
    sudo apt-get install -y -qq clamav clamav-daemon
    # Stop the daemon (we only need clamscan for on-demand scanning)
    sudo systemctl stop clamav-freshclam 2>/dev/null || true
    sudo systemctl stop clamav-daemon 2>/dev/null || true
    # Update virus definitions
    log "Updating ClamAV virus definitions..."
    sudo freshclam --quiet 2>/dev/null || true
    log "ClamAV installed."
fi

# --- ScanCode Toolkit (license compliance) ---
# Requires libicu-dev for pyicu. Heavy install (~500MB).
# Non-fatal: scancode is optional and has complex native dependencies.
if command -v scancode &>/dev/null; then
    log "ScanCode already installed."
else
    log "Installing ScanCode Toolkit dependencies..."
    sudo apt-get install -y -qq pkg-config libicu-dev || true
    log "Installing ScanCode Toolkit..."
    if python3 -m pip install --break-system-packages --ignore-installed scancode-toolkit 2>&1; then
        log "ScanCode installed."
    else
        log "WARNING: ScanCode installation failed (optional, continuing without it)."
    fi
fi

# ---------------------------------------------------------------------------
# Copy Go-installed binaries into /usr/local/bin so they're on PATH
# for non-login SSH sessions (limactl shell uses bash -c).
# We copy instead of symlink because go install runs as root and
# /root/go/bin is not accessible to the SSH user.
# ---------------------------------------------------------------------------
GOPATH_BIN="$(go env GOPATH)/bin"
for bin in osv-scanner gitleaks govulncheck; do
    if [ -f "${GOPATH_BIN}/${bin}" ]; then
        sudo cp "${GOPATH_BIN}/${bin}" /usr/local/bin/
        sudo chmod +x "/usr/local/bin/${bin}"
        log "Copied ${bin} -> /usr/local/bin/"
    fi
done

# Copy cargo-installed binaries
CARGO_BIN="$HOME/.cargo/bin"
for bin in cargo-audit; do
    if [ -f "${CARGO_BIN}/${bin}" ]; then
        sudo cp "${CARGO_BIN}/${bin}" /usr/local/bin/
        sudo chmod +x "/usr/local/bin/${bin}"
        log "Copied ${bin} -> /usr/local/bin/"
    fi
done

# ---------------------------------------------------------------------------
# Create working directories
# ---------------------------------------------------------------------------
log "Creating working directories..."
sudo mkdir -p /opt/target
sudo mkdir -p /opt/deps
sudo mkdir -p /opt/scan-results
sudo mkdir -p /opt/security-reports

# Make directories writable by any user (the SSH user that runs scans
# differs from the sudo context that runs this script)
sudo chmod -R 777 /opt/target /opt/deps /opt/scan-results /opt/security-reports

log "Provisioning complete. All tools installed and directories created."
