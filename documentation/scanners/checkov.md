# Checkov — IaC Security Scanning

## Overview

[Checkov](https://github.com/bridgecrewio/checkov) scans infrastructure-as-code (IaC) files for security misconfigurations. It supports Dockerfiles, Terraform, Kubernetes, Helm, CloudFormation, and more.

**Category**: IaC
**Source file**: `src/thresher/scanners/checkov.py`
**Runs in**: Phase 2 (parallel)

## Command Executed

```bash
checkov -d <target_dir> -o json --quiet > <output_dir>/checkov.json 2>/dev/null
```

- `-d`: Directory to scan
- `-o json`: JSON output
- `--quiet`: Suppress progress output

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All checks pass |
| 1 | Failures found (valid) |
| Other | Error |

## Output Parsing

Checkov's output format varies:
- **Single framework**: Returns a dict with `results.failed_checks`
- **Multiple frameworks**: Returns a list of dicts (one per framework)

The parser normalizes both formats to a list and iterates over all framework results.

- **Severity**: Always `medium` (all IaC misconfigurations treated uniformly)
- **Title**: `"{check_id}: {check_type}"` (e.g., `"CKV_DOCKER_3: Ensure HEALTHCHECK is set"`)
- **Description**: Includes resource name and guideline URL
- **Line number**: From first element of `file_line_range` array
- **Category**: Always `iac`

### Example Finding

```json
{
  "id": "checkov-0",
  "source_tool": "checkov",
  "category": "iac",
  "severity": "medium",
  "title": "CKV_DOCKER_3: Ensure that a user for the container has been created",
  "description": "Resource: /opt/target/Dockerfile. Guideline: https://docs.prismacloud.io/...",
  "file_path": "/opt/target/Dockerfile",
  "line_number": 1
}
```

## What It Catches

### Dockerfile Checks (CKV_DOCKER_*)
- Running as root user
- Missing HEALTHCHECK
- Using ADD instead of COPY
- Using latest tag
- Exposing unnecessary ports

### Terraform Checks (CKV_AWS_*, CKV_GCP_*, CKV_AZURE_*)
- Unencrypted storage (S3, EBS, RDS)
- Overly permissive IAM policies
- Missing logging/monitoring
- Public access to resources
- Missing encryption in transit

### Kubernetes Checks (CKV_K8S_*)
- Privileged containers
- Missing resource limits
- Running as root
- Missing network policies
- Writable root filesystem

### Helm / CloudFormation
- Similar security checks adapted for each format

## Debugging

### No IaC findings

**Causes**:
- No IaC files in the target repo
- Checkov doesn't recognize the file format
- All checks pass

**Debug**:
```bash
# Check for IaC files
limactl shell <vm-name> -- find /opt/target -name "Dockerfile*" -o -name "*.tf" -o -name "*.yaml" -o -name "*.yml" | head -20

# Run Checkov manually
limactl shell <vm-name> -- checkov -d /opt/target -o json

# List supported frameworks
limactl shell <vm-name> -- checkov --list
```

### Output format issues

**Symptom**: Parse errors in scan results.

**Causes**:
- Checkov version changed output format
- Mix of dict and list output

**Debug**:
```bash
# Check raw output format
limactl shell <vm-name> -- checkov -d /opt/target -o json --quiet 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); print(type(d))"
```

### Checkov is slow

**Causes**:
- Large number of IaC files
- Checkov downloads policy updates on each run
- Memory-intensive for large Terraform projects

**Debug**:
```bash
# Run with timing
limactl shell <vm-name> -- time checkov -d /opt/target -o json --quiet

# Check Checkov version
limactl shell <vm-name> -- checkov --version
```

### Overlap with Hadolint

Both Checkov and Hadolint scan Dockerfiles, but they check different things:
- **Checkov**: Security-focused checks (user, healthcheck, secrets)
- **Hadolint**: Best practices + ShellCheck on RUN instructions

Having both provides complementary coverage.
