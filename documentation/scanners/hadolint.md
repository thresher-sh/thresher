# Hadolint — Dockerfile Linting

## Overview

[Hadolint](https://github.com/hadolint/hadolint) is a Dockerfile linter that checks for best practices and runs ShellCheck on `RUN` instructions. It catches Dockerfile anti-patterns that general IaC scanners miss.

**Category**: IaC (Docker-specific)
**Source file**: `src/thresher/scanners/hadolint.py`
**Runs in**: Phase 2 (parallel)

## Command Executed

Two-phase execution:

```bash
# Phase 1: Find all Dockerfiles
find <target_dir> -name "Dockerfile*" -not -path "*/.git/*" 2>/dev/null

# Phase 2: Lint them (only if Dockerfiles found)
hadolint --format json <dockerfile1> <dockerfile2> ... > <output_dir>/hadolint.json 2>/dev/null
```

If no Dockerfiles are found, returns empty findings immediately.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No linting issues |
| 1 | Issues found (valid) |
| Other | Error |

## Output Parsing

Hadolint outputs a JSON array of lint results.

- **Severity mapping**: `error` → `high`, `warning` → `medium`, `info` → `low`, `style` → `low`
- **Title**: `"{code}: {message}"` (e.g., `"DL3008: Pin versions in apt get install"`)
- **Category**: Always `iac`

### Example Finding

```json
{
  "id": "hadolint-0",
  "source_tool": "hadolint",
  "category": "iac",
  "severity": "medium",
  "title": "DL3008: Pin versions in apt get install",
  "file_path": "/opt/target/Dockerfile",
  "line_number": 5
}
```

## What It Catches

### Hadolint Rules (DL*)

| Rule | Severity | What It Checks |
|------|----------|----------------|
| DL3000 | error | Use absolute WORKDIR |
| DL3001 | info | Don't install unnecessary packages |
| DL3002 | warning | Last user should not be root |
| DL3003 | warning | Use WORKDIR instead of cd |
| DL3006 | warning | Always tag image version |
| DL3007 | warning | Don't use latest tag |
| DL3008 | warning | Pin versions in apt-get install |
| DL3009 | info | Delete apt-get lists |
| DL3013 | warning | Pin versions in pip install |
| DL3018 | warning | Pin versions in apk add |
| DL3025 | warning | Use JSON form for CMD |
| DL3027 | warning | Don't use apt, use apt-get |
| DL4006 | warning | Set SHELL for pipe operations |

### ShellCheck Rules (SC*)

Hadolint runs ShellCheck on `RUN` instructions, catching shell scripting issues:

| Rule | What It Checks |
|------|----------------|
| SC2086 | Double quote to prevent globbing and word splitting |
| SC2046 | Quote command substitution |
| SC2006 | Use $(...) instead of backticks |
| SC1091 | Not following sourced file |

## Debugging

### No findings for a project with Dockerfiles

**Causes**:
- Dockerfiles not named `Dockerfile*` (custom naming)
- All Dockerfiles follow best practices
- Find command didn't match

**Debug**:
```bash
# Check for Dockerfiles manually
limactl shell <vm-name> -- find /opt/target -name "Dockerfile*" -not -path "*/.git/*"

# Run Hadolint manually on a specific file
limactl shell <vm-name> -- hadolint --format json /opt/target/Dockerfile
```

### Hadolint not found

**Debug**:
```bash
limactl shell <vm-name> -- which hadolint
limactl shell <vm-name> -- hadolint --version
```

Hadolint is installed as a static binary during provisioning. Rebuild the base VM if missing.

### Non-Docker projects

If the target repo has no Dockerfiles, Hadolint returns empty findings with exit code 0. This is normal and expected.
