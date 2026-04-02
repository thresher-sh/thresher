# cargo-audit — Rust Vulnerability Scanning

## Overview

[cargo-audit](https://github.com/rustsec/rustsec/tree/main/cargo-audit) scans Rust projects for vulnerabilities using the [RustSec Advisory Database](https://rustsec.org/). It checks `Cargo.lock` for dependencies with known security advisories.

**Category**: SCA (Rust-specific)
**Source file**: `src/thresher/scanners/cargo_audit.py`
**Runs in**: Phase 2 (parallel)

## Command Executed

```bash
# Phase 1: Check if this is a Rust project
[ -f <target_dir>/Cargo.lock ] && echo exists

# Phase 2: Run cargo-audit (only if Cargo.lock exists)
cd <target_dir> && cargo-audit audit --json > <output_dir>/cargo-audit.json 2>/dev/null
```

If `Cargo.lock` doesn't exist, returns empty findings immediately.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No vulnerabilities found |
| 1 | Vulnerabilities found (valid) |
| Other | Error |

## Output Parsing

cargo-audit outputs JSON with a `vulnerabilities.list` array.

Per vulnerability:
- **Advisory**: ID, title, description, URL, severity
- **Package**: name, version
- **Fix version**: First element of `versions.patched` array
- **Severity mapping**: `critical` → `critical`, `high` → `high`, `medium` → `medium`, `low` → `low`, `informational`/`none` → `info`
- **Description**: Includes reference URL if present
- **Category**: Always `sca`

### Example Finding

```json
{
  "id": "cargo-audit-0",
  "source_tool": "cargo-audit",
  "category": "sca",
  "severity": "high",
  "cve_id": "CVE-2024-1234",
  "title": "RUSTSEC-2024-0001: Memory safety issue in example-crate",
  "description": "Use-after-free in example-crate's buffer handling. Reference: https://rustsec.org/advisories/RUSTSEC-2024-0001",
  "package_name": "example-crate",
  "package_version": "0.5.2",
  "fix_version": "0.5.3"
}
```

## RustSec Advisory Database

The [RustSec Advisory Database](https://github.com/rustsec/advisory-db) contains:
- Memory safety vulnerabilities (use-after-free, buffer overflow, data races)
- Denial of service vulnerabilities
- Cryptographic weaknesses
- Unmaintained crate warnings
- Yanked crate advisories

Advisory IDs use the format `RUSTSEC-YYYY-NNNN`. Many also have CVE IDs.

## Debugging

### No findings for a Rust project with known vulns

**Causes**:
- `Cargo.lock` is missing (only `Cargo.toml` present)
- Advisory not yet in RustSec database
- Vulnerable version not in lock file

**Debug**:
```bash
# Check Cargo.lock exists
limactl shell <vm-name> -- ls -la /opt/target/Cargo.lock

# Run cargo-audit manually
limactl shell <vm-name> -- bash -c "cd /opt/target && cargo-audit audit --json"

# Check database freshness
limactl shell <vm-name> -- cargo-audit fetch
```

### Cargo.lock missing

**Symptom**: Empty findings, exit code 0.

**Cause**: Some Rust libraries don't commit `Cargo.lock` (it's in `.gitignore` for libraries per Cargo convention). Without `Cargo.lock`, cargo-audit can't determine exact dependency versions.

**Workaround**: The dependency download step (`cargo vendor`) may generate `Cargo.lock` in the deps directory, but cargo-audit looks specifically at `<target_dir>/Cargo.lock`.

### cargo-audit not installed

**Debug**:
```bash
limactl shell <vm-name> -- which cargo-audit
limactl shell <vm-name> -- cargo-audit --version

# Reinstall
limactl shell <vm-name> -- cargo install cargo-audit
```

### Non-Rust projects

cargo-audit checks for `Cargo.lock` before running. Non-Rust projects get empty findings immediately. This is normal.
