# Grype — SCA Vulnerability Scanning

## Overview

[Grype](https://github.com/anchore/grype) is a vulnerability scanner that matches packages in an SBOM against multiple vulnerability databases. It's the primary SCA (Software Composition Analysis) tool in the pipeline.

**Category**: SCA
**Source file**: `src/thresher/scanners/grype.py`
**Runs in**: Phase 2 (parallel, after Syft completes)
**Depends on**: Syft SBOM output

## Command Executed

```bash
grype sbom:<sbom_path> -o json > <output_dir>/grype.json
```

The `sbom:` prefix tells Grype to read a CycloneDX SBOM file instead of scanning a directory.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No vulnerabilities found |
| 1 | Vulnerabilities found (this is valid, not an error) |
| Other | Real failure |

## Output Parsing

Grype outputs JSON with a `matches` array. Each match is parsed into a `Finding`:

- **Severity mapping**: `Critical` → `critical`, `High` → `high`, `Medium` → `medium`, `Low` → `low`, `Negligible`/`Unknown` → `info`
- **CVSS score**: Extracts the highest CVSS score when multiple entries exist
- **Fix version**: From `vulnerability.fix.versions`
- **Description**: Falls back to `vulnerability.dataSource` if description is empty
- **Category**: Always `sca`

### Example Finding

```json
{
  "id": "grype-CVE-2024-1234-0",
  "source_tool": "grype",
  "category": "sca",
  "severity": "critical",
  "cvss_score": 9.8,
  "cve_id": "CVE-2024-1234",
  "title": "CVE-2024-1234 in requests@2.25.0",
  "package_name": "requests",
  "package_version": "2.25.0",
  "fix_version": "2.31.0"
}
```

## Vulnerability Databases

Grype uses the Anchore vulnerability database, which aggregates from:
- NVD (National Vulnerability Database)
- GitHub Security Advisories
- Alpine SecDB
- Amazon Linux ALAS
- Debian Security Tracker
- Red Hat CVE database
- Ubuntu CVE Tracker
- And more

The database is downloaded/updated when Grype runs. The domain `grype.anchore.io` is whitelisted in the VM firewall for this purpose.

## Debugging

### No findings when vulnerabilities are expected

**Symptom**: Grype returns 0 findings for a project with known vulnerable dependencies.

**Causes**:
- Syft SBOM is empty or incomplete (check Syft output first)
- Grype database is outdated
- Package names/versions don't match database entries (ecosystem mismatch)

**Debug**:
```bash
# Check the SBOM has components
limactl shell <vm-name> -- cat /opt/scan-results/sbom.json | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d.get('components',[])),'components')"

# Run Grype manually against the SBOM
limactl shell <vm-name> -- grype sbom:/opt/scan-results/sbom.json -o json

# Check Grype database status
limactl shell <vm-name> -- grype db status

# Force database update
limactl shell <vm-name> -- grype db update
```

### Grype fails with non-0/1 exit code

**Symptom**: Error in scan results, Grype reports failure.

**Causes**:
- SBOM file doesn't exist (Syft failed)
- Grype database download failed (network/firewall issue)
- Corrupt database

**Debug**:
```bash
# Check if SBOM exists
limactl shell <vm-name> -- ls -la /opt/scan-results/sbom.json

# Check network connectivity to Grype DB
limactl shell <vm-name> -- curl -I https://grype.anchore.io

# Re-download database
limactl shell <vm-name> -- grype db update
```

### Grype is slow

**Symptom**: Takes more than a few minutes for a typical project.

**Causes**:
- Very large SBOM (thousands of components)
- Database download in progress
- VM resource constraints

**Debug**:
```bash
# Check SBOM size
limactl shell <vm-name> -- wc -l /opt/scan-results/sbom.json

# Check VM resources
limactl shell <vm-name> -- top -bn1 | head -5
```

### Duplicate findings with OSV-Scanner

Grype and OSV-Scanner often find the same CVEs. This is expected — the aggregation step de-duplicates by `(cve_id, package_name)` and keeps the richer finding.
