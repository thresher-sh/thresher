# Scanner Overview

Thresher runs 16 deterministic security scanners in a two-phase pipeline inside the Lima VM.

## Execution Pipeline

```
Phase 1 (sequential):
  └── Syft → SBOM (CycloneDX JSON)

Phase 2 (15 scanners in parallel via ThreadPoolExecutor):
  ├── Grype          (reads SBOM from Phase 1)
  ├── OSV-Scanner
  ├── Trivy
  ├── Semgrep
  ├── Bandit
  ├── Checkov
  ├── Hadolint
  ├── GuardDog
  ├── Gitleaks
  ├── YARA
  ├── capa
  ├── govulncheck
  ├── cargo-audit
  ├── ScanCode
  └── ClamAV
```

Syft runs first because Grype needs the SBOM it produces. All other scanners are independent and run concurrently.

## Scanner Summary

| # | Tool | Category | Language/Ecosystem | What It Catches |
|---|------|----------|--------------------|-----------------|
| 1 | [Syft](scanners/syft.md) | SBOM | All | Software bill of materials (feeds Grype) |
| 2 | [Grype](scanners/grype.md) | SCA | All | Known CVEs via SBOM matching |
| 3 | [OSV-Scanner](scanners/osv.md) | SCA + MAL | All | CVEs + malicious package advisories (MAL-*) |
| 4 | [Trivy](scanners/trivy.md) | SCA + IaC | All | Container CVEs, IaC misconfigs |
| 5 | [Semgrep](scanners/semgrep.md) | SAST | Multi-language | Code vulnerabilities, dangerous patterns |
| 6 | [Bandit](scanners/bandit.md) | SAST | Python | Python security anti-patterns |
| 7 | [Checkov](scanners/checkov.md) | IaC | Docker/TF/K8s/Helm | IaC misconfigurations |
| 8 | [Hadolint](scanners/hadolint.md) | IaC | Docker | Dockerfile best practices + ShellCheck |
| 9 | [GuardDog](scanners/guarddog.md) | Supply Chain | Python/npm | Typosquatting, exfiltration behaviors |
| 10 | [Gitleaks](scanners/gitleaks.md) | Secrets | All | Hardcoded API keys, tokens, credentials |
| 11 | [YARA](scanners/yara.md) | Malware | All | Known malware signatures |
| 12 | [capa](scanners/capa.md) | Binary Analysis | Binaries | Capabilities in compiled executables |
| 13 | [govulncheck](scanners/govulncheck.md) | SCA | Go | Go vulns with call-graph analysis |
| 14 | [cargo-audit](scanners/cargo-audit.md) | SCA | Rust | Rust vulns from RustSec database |
| 15 | [ScanCode](scanners/scancode.md) | License | All | License compliance from file contents |
| 16 | [ClamAV](scanners/clamav.md) | Antivirus | All | Known virus and malware signatures |

## Category Breakdown

### SCA (Software Composition Analysis)
- **Grype**: SBOM-based CVE matching (Anchore database)
- **OSV-Scanner**: Multi-database CVE matching + malicious package detection
- **Trivy**: Broad SCA + IaC (Aqua Security)
- **govulncheck**: Go-specific with call-graph analysis (reduced false positives)
- **cargo-audit**: Rust-specific (RustSec advisory database)

Why multiple SCA tools? Each uses different vulnerability databases and detection strategies. Grype is SBOM-based, OSV covers malicious packages (MAL-* advisories), govulncheck uses call-graph analysis to filter unreachable vulnerabilities, and Trivy covers container images.

### SAST (Static Application Security Testing)
- **Semgrep**: Multi-language rules from the Semgrep registry (`--config auto`)
- **Bandit**: Python-specific patterns (pickle, weak crypto, shell injection, exec/eval)

### IaC (Infrastructure as Code)
- **Checkov**: Multi-framework (Docker, Terraform, K8s, Helm, CloudFormation)
- **Hadolint**: Dockerfile-specific (includes ShellCheck for RUN instructions)
- **Trivy**: Also covers IaC misconfigurations

### Supply Chain
- **GuardDog**: Behavioral analysis of package source for exfiltration, typosquatting

### Secrets
- **Gitleaks**: Pattern-based secrets detection with 100+ built-in rules

### Malware
- **YARA**: Community malware rules (signature matching)
- **ClamAV**: Open source antivirus (signature database)
- **capa**: Binary capability analysis (MITRE ATT&CK mapping)

### License
- **ScanCode**: Detects licenses from file contents (not just manifests), flags copyleft

## Error Handling

All scanners follow the same error handling pattern:

1. **Exit code interpretation**: Most scanners use exit 0 for "clean" and exit 1 for "findings found". Both are valid. Other exit codes indicate real errors.
2. **Exception isolation**: If a scanner throws an unexpected exception, it's caught and logged. The scan continues with remaining scanners.
3. **Error aggregation**: Errors are stored in `ScanResults.errors` and included in the report.
4. **Graceful degradation**: A scanner failure doesn't crash the pipeline. The report notes which scanners failed and why.

## De-duplication

Multiple scanners often detect the same vulnerability (e.g., Grype and OSV-Scanner both find CVE-2024-1234 in the same package). The aggregation step:

1. Groups findings by `(cve_id, package_name)`
2. Keeps the "richer" finding (more fields populated: CVSS, description, fix version, etc.)
3. Non-CVE findings are always included (can't be de-duplicated)

## Adding a New Scanner

Each scanner is a Python module in `src/thresher/scanners/` with:

1. A `run_<tool>(vm_name, target_dir, output_dir) -> ScanResults` function
2. A `parse_<tool>_output(raw) -> list[Finding]` function
3. Registration in `runner.py`'s `parallel_tasks` list

The scanner executes via SSH inside the VM and must be installed during provisioning (`vm_scripts/provision.sh`).
