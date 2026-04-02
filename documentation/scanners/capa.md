# capa — Binary Capability Analysis

## Overview

[capa](https://github.com/mandiant/capa) is Mandiant's tool for identifying capabilities in executable files. It tells you what a binary *can do* — networking, file encryption, persistence, anti-analysis — and maps findings to MITRE ATT&CK techniques.

**Category**: Binary Analysis
**Source file**: `src/thresher/scanners/capa_scanner.py`
**Runs in**: Phase 2 (parallel)

## Command Executed

Three-phase execution:

```bash
# Phase 1: Find executable files
find <target_dir> -path '*/.git' -prune -o -type f -executable -print 2>/dev/null

# Phase 2: Find shared libraries and DLLs
find <target_dir> -path '*/.git' -prune -o -type f \( -name "*.so" -o -name "*.dll" -o -name "*.exe" \) -print 2>/dev/null

# Phase 3: Analyze each binary
capa --format json <binary_path> > <output>.<binary_name> 2>/dev/null
```

Each binary is analyzed independently. Failures on one binary don't stop analysis of others.

## Exit Codes

Per binary:

| Code | Meaning |
|------|---------|
| 0 | Analysis complete |
| Non-zero | Skipped (unsupported format, not a PE/ELF/etc.) — logged at debug level |

## Output Parsing

capa outputs JSON per binary with a `rules` dict of matched capabilities.

- **Severity based on namespace**:
  - `malware` → `critical`
  - `anti-analysis` → `high`
  - Everything else → `medium`
- **MITRE ATT&CK mapping**: Extracted from `meta.attack` array (handles both dict and string formats)
- **Category**: Always `binary_analysis`

### Example Finding

```json
{
  "id": "capa-0",
  "source_tool": "capa",
  "category": "binary_analysis",
  "severity": "high",
  "title": "capa: receive data via HTTP (T1071.001)",
  "description": "Binary /opt/target/bin/tool has capability: receive data via HTTP. Namespace: communication/http. ATT&CK: T1071.001 - Application Layer Protocol: Web Protocols",
  "file_path": "/opt/target/bin/tool"
}
```

## What It Detects

### Capability Categories

| Namespace | Severity | Examples |
|-----------|----------|----------|
| `malware` | Critical | Ransomware behavior, dropper functionality, keylogging |
| `anti-analysis` | High | VM detection, debugger evasion, sandbox detection, packing |
| `communication` | Medium | HTTP requests, DNS queries, socket operations |
| `persistence` | Medium | Registry modification, scheduled tasks, service creation |
| `collection` | Medium | Clipboard access, screen capture, file enumeration |
| `cryptography` | Medium | Encryption, hashing, key generation |
| `data-manipulation` | Medium | Encoding, compression, serialization |

### MITRE ATT&CK Techniques

capa maps capabilities to [MITRE ATT&CK](https://attack.mitre.org/) technique IDs:

| Technique | Description |
|-----------|-------------|
| T1071.001 | Application Layer Protocol: Web Protocols |
| T1059.001 | Command and Scripting Interpreter: PowerShell |
| T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys |
| T1055 | Process Injection |
| T1027 | Obfuscated Files or Information |
| T1497 | Virtualization/Sandbox Evasion |

## Debugging

### No findings

**Causes**:
- No binary/executable files in the target (most common — source-only projects)
- capa doesn't support the binary format (e.g., .NET assemblies, Java JARs)
- Binaries are too small or stripped

**Debug**:
```bash
# Check for binaries
limactl shell <vm-name> -- find /opt/target -type f -executable -not -path "*/.git/*" | head -20

# Check for shared libraries
limactl shell <vm-name> -- find /opt/target -name "*.so" -o -name "*.dll" -o -name "*.exe" | head -20

# Run capa manually on a specific binary
limactl shell <vm-name> -- capa --format json /opt/target/bin/executable
```

### capa fails on a binary

**Symptom**: Non-zero exit code for a specific binary, but others succeed.

**Causes**:
- Unsupported format (capa supports PE, ELF, shellcode, .NET)
- Corrupt binary
- Binary too large for analysis

**Debug**:
```bash
# Check binary format
limactl shell <vm-name> -- file /opt/target/bin/executable

# Run capa with verbose output
limactl shell <vm-name> -- capa -v /opt/target/bin/executable
```

### Performance

capa can be slow on large binaries. Each binary is analyzed independently — if one takes long, others continue.

```bash
# Check binary sizes
limactl shell <vm-name> -- find /opt/target -type f -executable -exec ls -lh {} \; | sort -k5 -h
```

### Most projects have no binaries

Source-only repositories (Python, JavaScript, etc.) won't have executable files. capa returns empty findings — this is normal. capa is most useful for projects that include compiled tools, pre-built libraries, or bundled executables.
