# ClamAV — Antivirus Scanning

## Overview

[ClamAV](https://www.clamav.net/) is an open-source antivirus engine that detects known viruses, malware, trojans, and other malicious software using signature databases. It's the traditional "antivirus" layer in the scanner pipeline.

**Category**: Antivirus / Malware
**Source file**: `src/thresher/scanners/clamav.py`
**Runs in**: Phase 2 (parallel)

## Command Executed

```bash
clamscan -r --infected --no-summary <target_dir> > <output_dir>/clamav.txt 2>/dev/null
```

- `-r`: Recursive scan
- `--infected`: Only show infected files (reduces output noise)
- `--no-summary`: Skip summary statistics (cleaner output for parsing)

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean (no viruses found) — returns empty findings immediately |
| 1 | Virus(es) found (parses output) |
| 2 | Error occurred (logged as warning) |

## Output Parsing

ClamAV outputs plain text in the format:

```
/path/to/file: VirusName FOUND
```

Parsing:
- Lines containing `"FOUND"` are processed
- Split on rightmost `":"` (rsplit) to handle file paths containing colons
- File path = text before the colon
- Virus name = text between the colon and `" FOUND"`
- **Severity**: Always `critical`
- **Category**: Always `malware`

### Example Finding

```json
{
  "id": "clamav-0",
  "source_tool": "clamav",
  "category": "malware",
  "severity": "critical",
  "title": "ClamAV: Trojan.GenericKD.12345 in suspicious.bin",
  "description": "ClamAV detected Trojan.GenericKD.12345 in /opt/target/bin/suspicious.bin",
  "file_path": "/opt/target/bin/suspicious.bin"
}
```

## Signature Database

ClamAV uses virus signature databases that are updated regularly:
- **daily.cvd/cld**: Daily updated signatures
- **main.cvd/cld**: Main signature database
- **bytecode.cvd/cld**: Bytecode signatures for complex detection

The database is downloaded from `database.clamav.net` (whitelisted in the VM firewall) during VM provisioning.

## ClamAV vs YARA

Both detect malware, but through different approaches:

| Feature | ClamAV | YARA |
|---------|--------|------|
| **Approach** | Signature database (automated) | Rule-based (community-written) |
| **Database** | ClamAV signatures (~1M+ signatures) | Community YARA rules (focused) |
| **Strength** | Broad coverage of known malware | Targeted detection of specific families |
| **Format** | Binary signatures, hash matching | Pattern matching with conditions |
| **False positives** | Lower (well-maintained database) | Higher (community rules vary in quality) |

Having both provides defense in depth — ClamAV catches broadly known malware while YARA catches specific malware families and patterns.

## Debugging

### No findings (expected for most projects)

Most legitimate open-source projects won't trigger ClamAV. A clean scan is the normal case.

### ClamAV finds something

**First**: Don't panic. Check what was found:

```bash
# See the full ClamAV output
limactl shell <vm-name> -- cat /opt/scan-results/clamav.txt

# Check the specific file
limactl shell <vm-name> -- file /opt/target/path/to/flagged/file

# Get more details
limactl shell <vm-name> -- clamscan --debug /opt/target/path/to/flagged/file
```

**Common false positives**:
- EICAR test files (antivirus test strings)
- Security research samples included in the repo
- Legitimate tools that use techniques ClamAV flags (e.g., packers, self-extracting archives)

### ClamAV database not updated

**Symptom**: ClamAV runs but might miss recent malware.

```bash
# Check database age
limactl shell <vm-name> -- clamscan --version

# Update database
limactl shell <vm-name> -- freshclam
```

### ClamAV exit code 2 (error)

**Causes**:
- Insufficient memory for scanning
- Corrupt database
- Permission issues

**Debug**:
```bash
# Run with debug output
limactl shell <vm-name> -- clamscan -r --debug /opt/target 2>&1 | tail -30

# Check database integrity
limactl shell <vm-name> -- clamscan --debug 2>&1 | grep -i database

# Check memory
limactl shell <vm-name> -- free -h
```

### ClamAV is slow

ClamAV loads its entire signature database into memory on each run. For large repos:

```bash
# Check scan time
limactl shell <vm-name> -- time clamscan -r --infected --no-summary /opt/target

# Check how many files
limactl shell <vm-name> -- find /opt/target -type f | wc -l
```

The `--infected` and `--no-summary` flags help by reducing I/O, but ClamAV's startup time (loading signatures) is fixed.
