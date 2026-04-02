# OSV-Scanner — SCA + Malicious Package Detection

## Overview

[OSV-Scanner](https://github.com/google/osv-scanner) is Google's vulnerability scanner that queries the Open Source Vulnerabilities (OSV) database. Its key differentiator is support for **MAL-*** advisories — malicious package detections that other SCA tools miss.

**Category**: SCA + Malicious Packages
**Source file**: `src/thresher/scanners/osv.py`
**Runs in**: Phase 2 (parallel)

## Command Executed

```bash
osv-scanner scan --format json <target_dir> > <output_dir>/osv.json 2>/dev/null
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No vulnerabilities (clean) |
| 1 | Vulnerabilities found (valid) |
| Other | Error |

## Output Parsing

OSV outputs JSON with a `results` array containing packages and their vulnerabilities.

### Key Parsing Details

- **MAL-* handling**: Advisories prefixed with `MAL-` indicate **known malicious packages**. These are always marked as `critical` severity with `supply_chain` category.
- **Regular CVEs**: Standard vulnerabilities get `sca` category with severity derived from CVSS score.
- **Severity scoring**: 9.0+ = critical, 7.0+ = high, 4.0+ = medium, 0.1+ = low, else = info
- **CVSS parsing**: Extracts score from `database_specific` or `severity` array. Vector strings are stored but not parsed (no CVSS calculator library).

### Example Finding (Malicious Package)

```json
{
  "id": "osv-MAL-2024-1234-0",
  "source_tool": "osv-scanner",
  "category": "supply_chain",
  "severity": "critical",
  "cve_id": "MAL-2024-1234",
  "title": "MAL-2024-1234: Malicious package detected",
  "package_name": "reqeusts",
  "package_version": "1.0.0"
}
```

## Why OSV-Scanner Alongside Grype?

| Feature | Grype | OSV-Scanner |
|---------|-------|-------------|
| CVE detection | Yes | Yes |
| Malicious package detection (MAL-*) | No | **Yes** |
| Database | Anchore (aggregated) | OSV (Google) |
| Input | SBOM | Directory scan |

OSV-Scanner catches malicious packages that Grype cannot detect because they don't have CVE IDs — they have MAL-* identifiers in the OSV database.

## Debugging

### No findings for a project with known vulns

**Causes**:
- Target directory doesn't contain recognized manifest files
- OSV database doesn't have the specific advisory
- Package names differ between ecosystems

**Debug**:
```bash
# Run OSV-Scanner manually
limactl shell <vm-name> -- osv-scanner scan --format json /opt/target

# Check what manifest files exist
limactl shell <vm-name> -- find /opt/target -name "requirements*.txt" -o -name "package*.json" -o -name "go.mod" -o -name "Cargo.lock"

# Check OSV-Scanner version
limactl shell <vm-name> -- osv-scanner --version
```

### MAL-* advisories not detected

**Symptom**: Known malicious package not flagged.

**Causes**:
- Advisory not yet in OSV database
- Package name mismatch (case sensitivity, version)
- Malicious version not in lock file

**Debug**:
```bash
# Check OSV API directly for a specific package
limactl shell <vm-name> -- curl -s "https://api.osv.dev/v1/query" -d '{"package":{"name":"suspicious-pkg","ecosystem":"PyPI"}}'
```

### JSON parse errors

**Symptom**: `errors` field in ScanResults contains "Failed to parse" message.

**Causes**:
- OSV-Scanner wrote error messages to stdout (should go to stderr, but some versions mix them)
- Corrupted output file

**Debug**:
```bash
# Check raw output
limactl shell <vm-name> -- cat /opt/scan-results/osv.json

# Run with verbose output
limactl shell <vm-name> -- osv-scanner scan --format json /opt/target 2>&1
```
