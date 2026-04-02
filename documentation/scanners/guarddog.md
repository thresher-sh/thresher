# GuardDog — Supply Chain Behavioral Analysis

## Overview

[GuardDog](https://github.com/DataDog/guarddog) is DataDog's supply chain security tool that analyzes packages for malicious behaviors. It detects typosquatting, data exfiltration, and other supply chain attack patterns by examining package source code and metadata.

**Category**: Supply Chain
**Source file**: `src/thresher/scanners/guarddog.py`
**Runs in**: Phase 2 (parallel)

## Command Executed

```bash
guarddog scan <target_dir> --output-format json > <output_dir>/guarddog.json 2>/dev/null
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean (no suspicious behaviors) |
| 1 | Findings detected (valid — version-dependent behavior) |
| Other | Error |

## Output Parsing

GuardDog has a flexible output format that varies between versions:

- Can be a dict of `{package_name: results}` or a list of results
- Results may have a `"results"` key with sub-results or be a flat list
- Matches can be dicts with `location`/`message` fields, or plain strings

The parser handles all these formats defensively with `isinstance` checks.

- **Severity**: Always `high` (supply chain risks are high-impact by nature)
- **Category**: Always `supply_chain`

### Example Finding

```json
{
  "id": "guarddog-0",
  "source_tool": "guarddog",
  "category": "supply_chain",
  "severity": "high",
  "title": "exfiltration-dns: DNS exfiltration pattern detected",
  "description": "Suspicious DNS query construction found in setup.py at line 15",
  "file_path": "/opt/target/setup.py",
  "line_number": 15
}
```

## What It Catches

### Malicious Behavior Detection

| Rule | What It Detects |
|------|-----------------|
| `exfiltration-dns` | DNS-based data exfiltration |
| `exfiltration-http` | HTTP-based data exfiltration |
| `cmd-overwrite` | Overwriting system commands |
| `code-execution` | Dynamic code execution (eval, exec) |
| `download-executable` | Downloading and executing binaries |
| `shady-links` | Suspicious URLs in code |
| `steganography` | Hidden data in non-code files |
| `typosquatting` | Package name similarity to popular packages |

### Typosquatting Detection

GuardDog compares package names against popular packages in PyPI and npm registries, flagging names that are suspiciously similar:

```
requests  →  reqeusts (edit distance: 1)
lodash    →  l0dash   (character substitution)
```

## Debugging

### No findings for a suspicious package

**Causes**:
- GuardDog's rules don't cover the specific attack pattern
- Package uses novel obfuscation that evades rule-based detection
- GuardDog scanned the wrong directory

**Debug**:
```bash
# Run GuardDog manually
limactl shell <vm-name> -- guarddog scan /opt/target --output-format json

# Check GuardDog version and available rules
limactl shell <vm-name> -- guarddog --version

# Scan a specific package from PyPI
limactl shell <vm-name> -- guarddog pypi scan <package-name>
```

### Parse errors

**Symptom**: JSON parse failures in scan results.

**Causes**:
- GuardDog version changed output format
- Error messages mixed into stdout

**Debug**:
```bash
# Check raw output
limactl shell <vm-name> -- guarddog scan /opt/target --output-format json 2>/dev/null

# Check for stderr output
limactl shell <vm-name> -- guarddog scan /opt/target --output-format json 2>&1 | tail -20
```

### GuardDog is slow

**Causes**:
- Large number of package files to analyze
- Network calls for typosquatting comparisons

**Debug**:
```bash
limactl shell <vm-name> -- time guarddog scan /opt/target --output-format json 2>/dev/null
```

### Relationship to AI Analyst

GuardDog and the AI Analyst agent have overlapping coverage for supply chain attacks. GuardDog uses deterministic rules while the AI agent uses reasoning. Together they catch more than either alone:

- GuardDog excels at: typosquatting, known exfiltration patterns, install hook analysis
- AI Analyst excels at: novel obfuscation, contextual analysis, intent determination
