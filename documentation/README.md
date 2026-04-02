# Thresher Documentation

Welcome to the documentation for **Thresher** — an AI-powered supply chain security scanner for evaluating open source packages before adoption.

## Table of Contents

### Core Documentation

- [Project Overview](overview.md) — What this project does, why it exists, and who it's for
- [Getting Started](getting-started.md) — Installation, configuration, and first scan
- [Architecture](architecture.md) — System design, component layout, and data flow
- [Security Model](security-model.md) — Isolation layers, firewall rules, and threat containment
- [AI Agent Loop](agent-loop.md) — How the Analyst and Adversarial agents work
- [Scoring and Reports](scoring-and-reports.md) — Priority computation, EPSS/KEV enrichment, and output formats
- [InfoSec Background](infosec-background.md) — Supply chain security concepts, attack taxonomy, and further reading

### Scanner Documentation

- [Scanner Overview](scanners.md) — Summary of all 16 scanners and how they work together

Each scanner has detailed documentation with usage, output format, and debugging guidance:

| Scanner | Category | Documentation |
|---------|----------|---------------|
| Syft | SBOM | [docs/scanners/syft.md](scanners/syft.md) |
| Grype | SCA | [docs/scanners/grype.md](scanners/grype.md) |
| OSV-Scanner | SCA + Malicious Packages | [docs/scanners/osv.md](scanners/osv.md) |
| Trivy | SCA + IaC | [docs/scanners/trivy.md](scanners/trivy.md) |
| Semgrep | SAST | [docs/scanners/semgrep.md](scanners/semgrep.md) |
| Bandit | SAST (Python) | [docs/scanners/bandit.md](scanners/bandit.md) |
| Checkov | IaC | [docs/scanners/checkov.md](scanners/checkov.md) |
| Hadolint | IaC (Docker) | [docs/scanners/hadolint.md](scanners/hadolint.md) |
| GuardDog | Supply Chain | [docs/scanners/guarddog.md](scanners/guarddog.md) |
| Gitleaks | Secrets | [docs/scanners/gitleaks.md](scanners/gitleaks.md) |
| YARA | Malware Signatures | [docs/scanners/yara.md](scanners/yara.md) |
| capa | Binary Analysis | [docs/scanners/capa.md](scanners/capa.md) |
| govulncheck | SCA (Go) | [docs/scanners/govulncheck.md](scanners/govulncheck.md) |
| cargo-audit | SCA (Rust) | [docs/scanners/cargo-audit.md](scanners/cargo-audit.md) |
| ScanCode | License Compliance | [docs/scanners/scancode.md](scanners/scancode.md) |
| ClamAV | Antivirus | [docs/scanners/clamav.md](scanners/clamav.md) |
