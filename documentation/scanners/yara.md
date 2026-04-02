# YARA — Malware Signature Detection

## Overview

[YARA](https://github.com/VirusTotal/yara) is a pattern-matching tool used to identify and classify malware. It matches files against community-maintained rule sets that describe known malware families, packers, and suspicious patterns.

**Category**: Malware
**Source file**: `src/thresher/scanners/yara_scanner.py`
**Runs in**: Phase 2 (parallel)

## Command Executed

```bash
# Phase 1: Check rules directory exists
[ -d /opt/yara-rules ] && echo exists

# Phase 2: Run YARA rules against target
for f in /opt/yara-rules/malware/MALW_*.yar /opt/yara-rules/packers/*.yar; do
  yara -r "$f" <target_dir> 2>/dev/null | grep -v '/.git/';
done > <output_dir>/yara.txt
```

- `-r`: Recursive scan into subdirectories
- Filters out `.git/` matches to avoid false positives
- Runs multiple rule categories: malware signatures and packer detection

## Exit Codes

Exit codes from individual YARA executions are suppressed (errors on specific rule files don't stop the scan). The output content is what matters.

## Output Parsing

YARA outputs plain text with one match per line:

```
rule_name /path/to/matched/file
```

- Lines are split on whitespace
- First token = rule name, second = file path
- Lines with fewer than 2 parts are skipped
- **Severity**: Always `critical` (YARA matches against malware rules are high-priority)
- **Category**: Always `malware`

### Example Finding

```json
{
  "id": "yara-0",
  "source_tool": "yara",
  "category": "malware",
  "severity": "critical",
  "title": "YARA match: MALW_Emotet",
  "description": "YARA rule MALW_Emotet matched file /opt/target/bin/suspicious.exe",
  "file_path": "/opt/target/bin/suspicious.exe"
}
```

## Rule Sets

The YARA rules are installed at `/opt/yara-rules` during VM provisioning. The scanner uses:

### Malware Rules (`MALW_*.yar`)
Known malware family signatures including:
- Banking trojans (Emotet, TrickBot, Dridex)
- Ransomware (WannaCry, Ryuk, LockBit)
- Remote access trojans (Agent Tesla, NjRAT)
- Cryptominers
- Webshells

### Packer Rules (`packers/*.yar`)
Detection of executable packers and obfuscators:
- UPX
- ASPack
- Themida
- Custom packers

Packed binaries aren't inherently malicious, but legitimate software rarely uses uncommon packers.

## Debugging

### No findings

**Causes**:
- No malware present (this is the expected case)
- YARA rules directory doesn't exist
- Rules don't cover the specific malware variant
- Target has no binary or executable files

**Debug**:
```bash
# Check rules directory
limactl shell <vm-name> -- ls /opt/yara-rules/

# Check rule count
limactl shell <vm-name> -- find /opt/yara-rules -name "*.yar" | wc -l

# Run YARA manually against a specific file
limactl shell <vm-name> -- yara -r /opt/yara-rules/malware/MALW_*.yar /opt/target/

# Check YARA version
limactl shell <vm-name> -- yara --version
```

### Rules directory missing

**Symptom**: Scanner returns empty findings with no errors.

**Cause**: YARA rules weren't downloaded during provisioning.

**Fix**:
```bash
# Rebuild base VM
thresher stop
thresher build
```

### False positives

YARA rules can match on:
- Antivirus signature databases included in the project
- Security research samples
- Hex patterns that coincidentally match malware signatures

The AI Adversarial agent helps evaluate these in context.

### Performance

YARA is generally fast. If it's slow, check:
```bash
# Count files being scanned
limactl shell <vm-name> -- find /opt/target -type f | wc -l

# Check for very large binary files
limactl shell <vm-name> -- find /opt/target -type f -size +10M
```
