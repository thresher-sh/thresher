# ScanCode — License Compliance

## Overview

[ScanCode](https://github.com/nexB/scancode-toolkit) detects licenses by analyzing actual file contents rather than just reading package manifest declarations. This catches cases where the declared license differs from the actual license in the code.

**Category**: License
**Source file**: `src/thresher/scanners/scancode.py`
**Runs in**: Phase 2 (parallel)

## Command Executed

```bash
scancode --license --json-pp <output_dir>/scancode.json <target_dir> -n 4 --timeout 120 2>/dev/null
```

- `--license`: License detection mode
- `--json-pp`: Pretty-printed JSON output
- `-n 4`: Use 4 parallel workers
- `--timeout 120`: Per-file timeout of 120 seconds

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan complete (may have findings) |
| 1 | Scan complete with issues (valid) |
| Other | Error |

## Output Parsing

ScanCode outputs JSON with a `files` array. The parser handles two output formats:

### New format (ScanCode v32+)
- `detected_license_expression` or `detected_license_expression_spdx` on each file

### Old format
- `licenses` array on each file with license objects containing `key` and `spdx_license_key`

### Copyleft Detection

Only **copyleft licenses** are reported as findings. The parser checks for these prefixes (case-insensitive):
- `GPL` (all variants: GPL-2.0, GPL-3.0, etc.)
- `AGPL`
- `LGPL`
- `SSPL`
- `EUPL`
- `MPL`
- `CPAL`
- `OSL`

Permissive licenses (MIT, BSD, Apache, etc.) are **not reported** as findings.

- **Severity**: Always `medium`
- **Category**: Always `license`

### Example Finding

```json
{
  "id": "scancode-0",
  "source_tool": "scancode",
  "category": "license",
  "severity": "medium",
  "title": "Copyleft license detected: GPL-3.0-only",
  "description": "File /opt/target/lib/parser.c contains GPL-3.0-only license",
  "file_path": "/opt/target/lib/parser.c"
}
```

## Why License Scanning Matters

### Copyleft vs Permissive

| License Type | Examples | Obligation |
|-------------|----------|------------|
| **Copyleft** | GPL, AGPL, LGPL | Derivative works must use the same license |
| **Permissive** | MIT, BSD, Apache 2.0 | Minimal restrictions, can use in proprietary code |

If you're building proprietary software and accidentally include a GPL-licensed dependency, you may be legally required to open-source your entire project.

### Why Content-Based Detection?

Package manifests can declare the wrong license:
- `package.json` says MIT, but a vendored file is GPL
- License changed between versions but metadata wasn't updated
- Third-party code was copied in without license attribution

ScanCode reads the actual license text in each file, catching these discrepancies.

## Debugging

### No findings

**Causes**:
- No copyleft licenses in the project (common for modern open-source projects using MIT/Apache)
- ScanCode didn't detect the license format
- Files were too large or timed out

**Debug**:
```bash
# Run ScanCode manually
limactl shell <vm-name> -- scancode --license --json-pp /tmp/scancode.json /opt/target -n 4 --timeout 120

# Check output
limactl shell <vm-name> -- python3 -c "
import json
with open('/tmp/scancode.json') as f:
    data = json.load(f)
for f in data.get('files', []):
    expr = f.get('detected_license_expression') or f.get('detected_license_expression_spdx')
    if expr:
        print(f['path'], '->', expr)
" | head -20
```

### ScanCode is slow

ScanCode is one of the slower scanners. For large repositories:

**Causes**:
- Many files to scan (ScanCode examines every file)
- Large binary files
- Complex license texts

**Debug**:
```bash
# Count files
limactl shell <vm-name> -- find /opt/target -type f | wc -l

# Run with fewer workers and more timeout
limactl shell <vm-name> -- scancode --license --json-pp /tmp/sc.json /opt/target -n 2 --timeout 300
```

### Output format issues

**Symptom**: Parse errors.

**Cause**: ScanCode version difference (v30 vs v32+ output format change).

**Debug**:
```bash
# Check version
limactl shell <vm-name> -- scancode --version

# Check output structure
limactl shell <vm-name> -- python3 -c "
import json
with open('/opt/scan-results/scancode.json') as f:
    data = json.load(f)
if data.get('files'):
    print(list(data['files'][0].keys()))
"
```
