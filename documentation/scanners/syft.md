# Syft — SBOM Generation

## Overview

[Syft](https://github.com/anchore/syft) generates a Software Bill of Materials (SBOM) for the target project. It identifies all packages, libraries, and dependencies and outputs them in CycloneDX JSON format. Syft doesn't find vulnerabilities itself — it produces the inventory that Grype uses for vulnerability matching.

**Category**: SBOM
**Source file**: `src/thresher/scanners/syft.py`
**Runs in**: Phase 1 (before all other scanners — Grype depends on it)

## Command Executed

```bash
syft <target_dir> -o cyclonedx-json > <output_dir>/sbom.json
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| Non-zero | Error (logged as warning) |

## Output

Syft produces a CycloneDX JSON SBOM. It does **not** generate vulnerability findings — its output is consumed by Grype.

The SBOM path is stored in `ScanResults.metadata["sbom_path"]` and passed to Grype in Phase 2.

### Example SBOM Structure

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "components": [
    {
      "type": "library",
      "name": "requests",
      "version": "2.31.0",
      "purl": "pkg:pypi/requests@2.31.0"
    }
  ]
}
```

## What It Detects

Syft identifies components from:

- Python: `requirements.txt`, `pyproject.toml`, `setup.py`, `Pipfile.lock`, installed packages
- Node: `package.json`, `package-lock.json`, `yarn.lock`
- Go: `go.mod`, `go.sum`
- Rust: `Cargo.toml`, `Cargo.lock`
- Java: `pom.xml`, JAR files
- Ruby: `Gemfile.lock`
- Container images: Distro packages (apt, apk, rpm)
- And many more ecosystems

## Debugging

### Syft produces empty SBOM

**Symptom**: SBOM has no components, or Grype finds nothing.

**Causes**:
- Target directory is empty or has no recognized package files
- Syft doesn't support the project's ecosystem
- Dependencies weren't downloaded (check sandbox step)

**Debug**:
```bash
# SSH into the VM and run Syft manually
limactl shell <vm-name> -- syft /opt/target -o cyclonedx-json

# Check what files exist in target
limactl shell <vm-name> -- ls -la /opt/target

# Check if dependency download succeeded
limactl shell <vm-name> -- ls -la /opt/deps/
```

### Syft hangs or times out

**Symptom**: Phase 1 takes unusually long.

**Causes**:
- Very large repository or dependency tree
- Docker image scanning (if Dockerfiles are present, Syft may try to pull images)
- Disk I/O bottleneck in VM

**Debug**:
```bash
# Check VM resources
limactl shell <vm-name> -- free -h
limactl shell <vm-name> -- df -h
```

### Syft version mismatch

**Symptom**: Unexpected output format or missing fields.

**Debug**:
```bash
limactl shell <vm-name> -- syft version
```

Syft is installed during VM provisioning. Rebuild the base VM to get the latest version:
```bash
thresher-stop
thresher-build
```

## Relationship to Other Scanners

Syft's SBOM is the **input** for Grype. If Syft fails or produces an empty SBOM, Grype will find no vulnerabilities. All other scanners are independent of Syft.
