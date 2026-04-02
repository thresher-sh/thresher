# Bandit — Python SAST

## Overview

[Bandit](https://github.com/PyCQA/bandit) is a Python-specific static analysis tool that finds common security issues in Python code. It's designed to find security problems that Semgrep's generic rules might miss.

**Category**: SAST (Python-specific)
**Source file**: `src/thresher/scanners/bandit.py`
**Runs in**: Phase 2 (parallel)

## Command Executed

```bash
bandit -r <target_dir> -f json -o <output_dir>/bandit.json 2>/dev/null
```

- `-r`: Recursive scan
- `-f json`: JSON output format
- `-o`: Output file path

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No issues found |
| 1 | Issues detected (valid, not an error) |
| Other | Error |

## Output Parsing

Bandit outputs JSON with a `results` array of issues.

- **Severity mapping**: `HIGH` → `high`, `MEDIUM` → `medium`, `LOW` → `low`, else → `low`
- **Title**: `"{test_id}: {test_name}"` (e.g., `"B301: pickle"`)
- **Description**: Includes confidence level (e.g., `"[HIGH confidence] Using pickle.loads..."`)
- **Category**: Always `sast`

### Example Finding

```json
{
  "id": "bandit-0",
  "source_tool": "bandit",
  "category": "sast",
  "severity": "high",
  "title": "B301: pickle",
  "description": "[HIGH confidence] Pickle and modules that wrap it can be made to execute arbitrary commands during unpickling.",
  "file_path": "/opt/target/app/cache.py",
  "line_number": 23
}
```

## What It Catches

Bandit has built-in tests (B-codes) for Python-specific anti-patterns:

| Test ID | Name | Risk |
|---------|------|------|
| B101 | assert_used | Assertions stripped in optimized bytecode |
| B102 | exec_used | Arbitrary code execution |
| B103 | set_bad_file_permissions | World-writable files |
| B104 | hardcoded_bind_all_interfaces | Binding to 0.0.0.0 |
| B105-B107 | hardcoded_password_* | Hardcoded passwords |
| B110 | try_except_pass | Silenced exceptions |
| B301 | pickle | Unsafe deserialization |
| B302 | marshal | Unsafe deserialization |
| B303 | md5/sha1 | Weak cryptographic hash |
| B305 | cipher | Weak cipher |
| B307 | eval | Arbitrary code execution |
| B311 | random | Non-cryptographic randomness |
| B320 | xml | XML external entity (XXE) |
| B501 | request_with_no_cert_validation | TLS verification disabled |
| B602 | subprocess_popen_with_shell_equals_true | Shell injection |
| B605 | start_process_with_a_shell | Shell injection |
| B608 | hardcoded_sql_expressions | SQL injection |
| B701 | jinja2_autoescape_false | XSS via Jinja2 |

## Debugging

### No findings for Python project

**Causes**:
- No `.py` files in target directory
- All code uses safe patterns
- Bandit skipped files due to encoding issues

**Debug**:
```bash
# Run Bandit manually
limactl shell <vm-name> -- bandit -r /opt/target -f json

# Check for Python files
limactl shell <vm-name> -- find /opt/target -name "*.py" | wc -l

# Run with verbose output
limactl shell <vm-name> -- bandit -r /opt/target -f json -v
```

### False positives on test files

**Symptom**: Many findings in test files (e.g., `assert` usage, `eval` in tests).

This is expected — Bandit scans all Python files including tests. The report includes the file path, so test-file findings can be triaged accordingly. The AI Adversarial agent often downgrades test-file findings.

### Bandit not installed

**Symptom**: Exit code -1 with "command not found" error.

**Debug**:
```bash
# Check installation
limactl shell <vm-name> -- which bandit
limactl shell <vm-name> -- pip3 show bandit

# Reinstall
limactl shell <vm-name> -- pip3 install bandit
```

### Non-Python projects

Bandit only scans Python files. For non-Python projects, it will return 0 findings with exit code 0. This is normal — Semgrep handles multi-language SAST.
