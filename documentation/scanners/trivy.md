# Trivy — SCA + IaC Scanning

## Overview

[Trivy](https://github.com/aquasecurity/trivy) is Aqua Security's comprehensive security scanner. In this pipeline, it's used in filesystem mode to detect vulnerabilities in dependencies and IaC misconfigurations.

**Category**: SCA + IaC
**Source file**: `src/thresher/scanners/trivy.py`
**Runs in**: Phase 2 (parallel)

## Command Executed

```bash
trivy fs --format json --output <output_dir>/trivy.json <target_dir> 2>/dev/null
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No vulnerabilities found |
| 1 | Vulnerabilities found (valid) |
| Other | Error |

## Output Parsing

Trivy outputs JSON with a `Results` array (capital R). Each result contains a `Vulnerabilities` array.

- **Severity mapping**: `CRITICAL` → `critical`, `HIGH` → `high`, `MEDIUM` → `medium`, `LOW` → `low`, else → `info`
- **Title construction**: `"{vuln_id}: {title}"` if title exists, else `"{vuln_id} in {package}@{version}"`
- **Category**: Always `sca`
- **CVSS score**: Not extracted (set to `None`) — CVSS is handled by Grype which has richer data

## What Makes Trivy Unique

Trivy covers both vulnerability detection and IaC scanning in one tool:

- **OS packages**: Detects vulnerabilities in system-level packages (apt, apk, rpm)
- **Language packages**: Python, Node, Go, Rust, Java, Ruby, and more
- **IaC**: Dockerfiles, Terraform, Kubernetes manifests, CloudFormation
- **Secrets**: Can also detect secrets (though Gitleaks handles this in our pipeline)

## Debugging

### Trivy finds different CVEs than Grype

This is expected. Trivy and Grype use different vulnerability databases:
- Trivy: Aqua Security's aggregated database
- Grype: Anchore's aggregated database

The de-duplication step merges overlapping findings.

### Trivy is slow

**Causes**:
- Database download on first run (~100MB)
- Large codebase with many files
- VM resource constraints

**Debug**:
```bash
# Check if database is downloaded
limactl shell <vm-name> -- trivy image --download-db-only

# Run with timing
limactl shell <vm-name> -- time trivy fs --format json /opt/target

# Check VM disk space
limactl shell <vm-name> -- df -h
```

### Trivy fails to start

**Causes**:
- Database download failed (network/firewall)
- Insufficient disk space for database

**Debug**:
```bash
# Check Trivy version
limactl shell <vm-name> -- trivy version

# Manual database download
limactl shell <vm-name> -- trivy image --download-db-only

# Check connectivity
limactl shell <vm-name> -- curl -I https://ghcr.io
```

### No IaC findings

**Causes**:
- No IaC files in the target repo (Dockerfiles, Terraform, K8s manifests)
- Trivy fs mode may not scan IaC by default in all versions

**Debug**:
```bash
# Check for IaC files
limactl shell <vm-name> -- find /opt/target -name "Dockerfile*" -o -name "*.tf" -o -name "*.yaml" | head -20

# Run Trivy with explicit IaC scanning
limactl shell <vm-name> -- trivy fs --scanners vuln,misconfig --format json /opt/target
```
