# Thresher scanner image
# All security scanning tools + language runtimes + Claude Code
# Entrypoint: python3 -m thresher.harness

FROM ubuntu:24.04

ARG TARGETARCH

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/usr/local/go/bin:/root/.cargo/bin:${PATH}"

# ── System packages ─────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build tools
    build-essential \
    curl \
    wget \
    git \
    unzip \
    ca-certificates \
    gnupg \
    # Python
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    # Java (for some scanners)
    default-jre-headless \
    # ClamAV
    clamav \
    clamav-daemon \
    # YARA
    yara \
    # Misc runtime deps
    libssl-dev \
    libffi-dev \
    libicu-dev \
    pkg-config \
    file \
    && rm -rf /var/lib/apt/lists/*

# ── Node.js 20 ───────────────────────────────────────────────────────────────
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# ── Go 1.22 ──────────────────────────────────────────────────────────────────
RUN case "${TARGETARCH}" in \
        amd64) GOARCH=amd64 ;; \
        arm64) GOARCH=arm64 ;; \
        *) GOARCH=amd64 ;; \
    esac \
    && curl -fsSL "https://go.dev/dl/go1.22.4.linux-${GOARCH}.tar.gz" \
       | tar -C /usr/local -xz

# ── Rust stable ──────────────────────────────────────────────────────────────
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable --profile minimal \
    && /root/.cargo/bin/rustup component add clippy

# ── uv (fast Python package installer) ──────────────────────────────────────
RUN curl -LsSf https://astral.sh/uv/install.sh | sh \
    && ln -s /root/.local/bin/uv /usr/local/bin/uv

# ── Python security scanners ─────────────────────────────────────────────────
ENV UV_BREAK_SYSTEM_PACKAGES=1
# libmagic from apt (scancode's typecode-libmagic has no arm64 wheels)
RUN apt-get update && apt-get install -y --no-install-recommends libmagic1 \
    && rm -rf /var/lib/apt/lists/*

RUN uv pip install --system --no-cache \
    semgrep \
    bandit \
    checkov \
    guarddog \
    scancode-toolkit-mini

# ── Go-based scanners ────────────────────────────────────────────────────────
# govulncheck
RUN go install golang.org/x/vuln/cmd/govulncheck@latest

# ── Rust-based scanners ──────────────────────────────────────────────────────
# cargo-audit
RUN /root/.cargo/bin/cargo install cargo-audit

# ── Syft (SBOM generator) ────────────────────────────────────────────────────
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \
    | sh -s -- -b /usr/local/bin

# ── Grype (vulnerability scanner) ───────────────────────────────────────────
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \
    | sh -s -- -b /usr/local/bin

# ── Trivy ────────────────────────────────────────────────────────────────────
RUN case "${TARGETARCH}" in \
        amd64) TRIVY_ARCH=64bit ;; \
        arm64) TRIVY_ARCH=ARM64 ;; \
        *) TRIVY_ARCH=64bit ;; \
    esac \
    && TRIVY_VERSION=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4 | sed 's/v//') \
    && curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz" \
       | tar -C /usr/local/bin -xz trivy

# ── Gitleaks ─────────────────────────────────────────────────────────────────
RUN GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4 | sed 's/v//') \
    && case "${TARGETARCH}" in \
        amd64) GITLEAKS_ARCH=x64 ;; \
        arm64) GITLEAKS_ARCH=arm64 ;; \
        *) GITLEAKS_ARCH=x64 ;; \
    esac \
    && curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz" \
       | tar -C /usr/local/bin -xz gitleaks

# ── OSV-Scanner ──────────────────────────────────────────────────────────────
RUN go install github.com/google/osv-scanner/cmd/osv-scanner@latest \
    && cp /root/go/bin/osv-scanner /usr/local/bin/osv-scanner

# ── Hadolint ─────────────────────────────────────────────────────────────────
RUN case "${TARGETARCH}" in \
        amd64) HADOLINT_ARCH=x86_64 ;; \
        arm64) HADOLINT_ARCH=arm64 ;; \
        *) HADOLINT_ARCH=x86_64 ;; \
    esac \
    && curl -fsSL "https://github.com/hadolint/hadolint/releases/download/v2.14.0/hadolint-Linux-${HADOLINT_ARCH}" \
       -o /usr/local/bin/hadolint \
    && chmod +x /usr/local/bin/hadolint

# ── Claude Code ──────────────────────────────────────────────────────────────
RUN npm install -g @anthropic-ai/claude-code

# ── Non-root user ─────────────────────────────────────────────────────────────
RUN userdel -r ubuntu 2>/dev/null || true \
    && useradd -m -s /bin/bash -u 1000 thresher

# ── Pre-populate vulnerability databases ─────────────────────────────────────
# Downloaded at build time into a shared read-only location so the container
# doesn't need to re-download at runtime (which caused tmpfs exhaustion).
# Grype DB: ~200-600MB expanded, Trivy DB: ~500-800MB.
# Failures are non-fatal (no network in some build environments).
RUN mkdir -p /opt/vuln-db/grype /opt/vuln-db/trivy
ENV GRYPE_DB_CACHE_DIR=/opt/vuln-db/grype
ENV TRIVY_CACHE_DIR=/opt/vuln-db/trivy
RUN grype db update || true
RUN trivy image --download-db-only --no-progress --cache-dir /opt/vuln-db/trivy debian:latest 2>/dev/null || true
RUN freshclam 2>/dev/null || true
RUN chown -R thresher:thresher /opt/vuln-db

# ── Directory structure ───────────────────────────────────────────────────────
RUN mkdir -p \
        /output \
        /opt/scan-results \
        /opt/target \
        /opt/deps \
        /home/thresher/.claude \
    && chown -R thresher:thresher \
        /output \
        /opt/scan-results \
        /opt/target \
        /opt/deps \
        /home/thresher/.claude

# ── Custom rules ──────────────────────────────────────────────────────────────
COPY rules/ /opt/rules/
COPY templates/ /opt/templates/

# ── Thresher application (last layer — changes most often) ───────────────────
COPY pyproject.toml /app/pyproject.toml
COPY src/ /app/src/
RUN uv pip install --system --no-cache /app

USER thresher

ENTRYPOINT ["python3", "-m", "thresher.harness"]
