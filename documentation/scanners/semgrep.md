# Semgrep — SAST Code Analysis

## Overview

[Semgrep](https://github.com/semgrep/semgrep) is a fast, multi-language static analysis tool that finds code vulnerabilities using pattern-matching rules. It supports 30+ languages and uses the community rule registry (`--config auto`) for broad coverage.

**Category**: SAST
**Source file**: `src/thresher/scanners/semgrep.py`
**Runs in**: Phase 2 (parallel)

## Command Executed

```bash
semgrep scan --config auto --json <target_dir> > <output_dir>/semgrep.json 2>/dev/null
```

`--config auto` downloads and applies the full Semgrep community rule set.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (findings may or may not exist) |
| 1 | Valid (only meaningful with `--error` flag, which we don't use) |
| Other | Error |

## Output Parsing

Semgrep outputs JSON with a `results` array of hits.

- **Severity mapping**: `ERROR` → `high`, `WARNING` → `medium`, `INFO` → `low`
- **CWE handling**: Can be a list or string; joined with commas if multiple
- **Title**: Includes CWE references when present (e.g., `"CWE-78: semgrep.python.injection.os-command"`)
- **Category**: Always `sast`

### Example Finding

```json
{
  "id": "semgrep-0",
  "source_tool": "semgrep",
  "category": "sast",
  "severity": "high",
  "title": "CWE-78: semgrep.python.injection.os-command",
  "description": "User input is passed to os.system() without sanitization",
  "file_path": "/opt/target/app/utils.py",
  "line_number": 42
}
```

## What It Catches

Semgrep's `auto` config includes thousands of rules covering:

- **Injection**: SQL injection, command injection, XSS, LDAP injection
- **Deserialization**: Unsafe pickle, yaml.load, JSON deserialization
- **Cryptography**: Weak algorithms (MD5, SHA1), hardcoded keys
- **Authentication**: Missing auth checks, insecure session handling
- **SSRF**: Server-side request forgery patterns
- **Path traversal**: Unvalidated file paths
- **Race conditions**: TOCTOU bugs
- **Language-specific**: Python eval/exec, JavaScript prototype pollution, Go SQL injection

## Debugging

### No findings when vulnerabilities are expected

**Causes**:
- Language not supported by Semgrep community rules
- Specific pattern not covered by existing rules
- Rule download failed (network issue)

**Debug**:
```bash
# Run Semgrep manually with verbose output
limactl shell <vm-name> -- semgrep scan --config auto --json /opt/target 2>&1 | head -50

# Check which rules were loaded
limactl shell <vm-name> -- semgrep scan --config auto --json /opt/target 2>&1 | grep "rules loaded"

# Check Semgrep version
limactl shell <vm-name> -- semgrep --version
```

### Semgrep is slow

**Symptom**: Takes more than 5-10 minutes.

**Causes**:
- Large codebase (Semgrep analyzes every file)
- Many rules loaded from `--config auto`
- VM memory constraints (Semgrep can be memory-intensive)

**Debug**:
```bash
# Check file count
limactl shell <vm-name> -- find /opt/target -type f | wc -l

# Run with timing and metrics
limactl shell <vm-name> -- semgrep scan --config auto --json --time /opt/target

# Check VM memory
limactl shell <vm-name> -- free -h
```

### Rule download fails

**Symptom**: Error about failing to fetch rules.

**Causes**:
- `semgrep.dev` not reachable (firewall issue)
- Semgrep registry is down

**Debug**:
```bash
# Test connectivity
limactl shell <vm-name> -- curl -I https://semgrep.dev

# Try with a local rule instead
limactl shell <vm-name> -- semgrep scan --config "p/default" --json /opt/target
```

### Too many false positives

Semgrep `--config auto` can be noisy. The Adversarial AI agent helps filter these, but if running with `--skip-ai`, you'll need to manually review SAST findings. Context matters — a `pickle.loads()` call in a test file is different from one in a web handler.
