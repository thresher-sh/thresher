# Gitleaks — Secrets Detection

## Overview

[Gitleaks](https://github.com/gitleaks/gitleaks) scans repositories for hardcoded secrets like API keys, tokens, passwords, and private keys. It uses 100+ built-in regex rules to identify credentials that should be in environment variables or a secrets manager.

**Category**: Secrets
**Source file**: `src/thresher/scanners/gitleaks.py`
**Runs in**: Phase 2 (parallel)

## Command Executed

```bash
gitleaks detect --source <target_dir> --report-format json --report-path <output_dir>/gitleaks.json --no-banner 2>/dev/null
```

- `--source`: Directory to scan
- `--report-format json`: JSON output
- `--report-path`: Output file
- `--no-banner`: Suppress startup banner

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No leaks found (returns empty findings immediately) |
| 1 | Leaks detected (parses output) |
| Other | Error |

**Important**: Exit code 0 means Gitleaks didn't even create an output file. The parser returns early with empty findings.

## Output Parsing

Gitleaks outputs a JSON array of leak objects.

- **Severity**: Always `high`
- **Category**: Always `secrets`
- **Title**: `"Secret detected in {file}: {description}"`
- **Match redaction**: Only the first 20 characters of the match are included, followed by `"..."` to avoid leaking the full secret in the report
- **Metadata**: Commit hash, author, date are included in the description

### Example Finding

```json
{
  "id": "gitleaks-0",
  "source_tool": "gitleaks",
  "category": "secrets",
  "severity": "high",
  "title": "Secret detected in config/prod.env: AWS Access Key",
  "description": "AWS Access Key found. Commit: abc123, Author: dev@example.com, Date: 2024-01-15. Match: AKIAIOSFODNN7EXAM...",
  "file_path": "/opt/target/config/prod.env",
  "line_number": 3
}
```

## What It Catches

### Secret Types (Built-in Rules)

| Category | Examples |
|----------|----------|
| **Cloud provider keys** | AWS access keys, GCP service account keys, Azure credentials |
| **API tokens** | GitHub tokens, Slack tokens, Stripe keys, Twilio SIDs |
| **Passwords** | Hardcoded passwords in config files, connection strings |
| **Private keys** | SSH private keys, TLS/SSL certificates, PGP keys |
| **Database credentials** | Connection strings with embedded passwords |
| **OAuth secrets** | Client secrets, refresh tokens |
| **Generic secrets** | High-entropy strings matching known patterns |

## Debugging

### No findings when secrets are expected

**Causes**:
- Secrets don't match any built-in Gitleaks rules
- Secrets are in files Gitleaks doesn't scan
- `.gitleaksignore` file is suppressing findings

**Debug**:
```bash
# Run Gitleaks manually with verbose output
limactl shell <vm-name> -- gitleaks detect --source /opt/target --report-format json --verbose

# Check for .gitleaksignore
limactl shell <vm-name> -- cat /opt/target/.gitleaksignore 2>/dev/null

# Check Gitleaks version
limactl shell <vm-name> -- gitleaks version
```

### False positives

**Symptom**: Gitleaks flags example keys, test fixtures, or documentation.

**Common false positives**:
- Example API keys in documentation (e.g., `AKIAIOSFODNN7EXAMPLE`)
- Test fixtures with dummy credentials
- Base64-encoded non-secret data that looks like high-entropy strings

The AI Adversarial agent typically downgrades these. In `--skip-ai` mode, review the file path and context manually.

### Match redaction

The report intentionally truncates secret values to 20 characters. To see the full match, check the raw Gitleaks output:

```bash
limactl shell <vm-name> -- cat /opt/scan-results/gitleaks.json
```

**Warning**: The raw output contains full secret values. Handle with care.

### Gitleaks scans git history

By default, `gitleaks detect` scans the current state of files (not git history, since the repo is cloned with `--depth=1`). Secrets that were committed and then removed won't be detected in shallow clones.
