# govulncheck — Go Vulnerability Scanning

## Overview

[govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) is Go's official vulnerability scanner. Its key advantage is **call-graph analysis** — it only reports vulnerabilities in functions your code actually calls, dramatically reducing false positives compared to SCA tools that flag all vulnerable packages.

**Category**: SCA (Go-specific)
**Source file**: `src/thresher/scanners/govulncheck.py`
**Runs in**: Phase 2 (parallel)

## Command Executed

```bash
# Phase 1: Check if this is a Go project
[ -f <target_dir>/go.mod ] && echo exists

# Phase 2: Run govulncheck (only if go.mod exists)
cd <target_dir> && govulncheck -json ./... > <output_dir>/govulncheck.json 2>/dev/null
```

If `go.mod` doesn't exist, returns empty findings immediately.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No reachable vulnerabilities |
| 1 | Reachable vulnerabilities found (valid) |
| Other | Error |

## Output Parsing

govulncheck outputs **NDJSON** (newline-delimited JSON) — one JSON object per line.

The parser looks for objects with a `"finding"` key, which contain:
- **OSV ID**: Vulnerability identifier (e.g., `GO-2024-1234` or `CVE-2024-5678`)
- **Trace**: Call chain showing how vulnerable code is reached
- **Package and function**: The specific vulnerable function call

Parsing details:
- Non-JSON lines are skipped
- Objects without `"finding"` key are skipped
- If the OSV ID starts with `CVE-`, it's used as the `cve_id`
- **Severity**: Always `high` (govulncheck only reports reachable vulns, which are high-impact)
- **Category**: Always `sca`

### Example Finding

```json
{
  "id": "govulncheck-0",
  "source_tool": "govulncheck",
  "category": "sca",
  "severity": "high",
  "cve_id": "CVE-2024-5678",
  "title": "govulncheck: GO-2024-1234",
  "description": "Call trace: main.go → http.ListenAndServe → net/http.Server.Serve (vulnerable function)",
  "package_name": "net/http"
}
```

## What Makes govulncheck Special

### Call-Graph Analysis

Most SCA tools flag any dependency with a known CVE. govulncheck goes further:

```
Traditional SCA:
  "Your project uses net/http v1.20 which has CVE-2024-5678" → Finding

govulncheck:
  "Your project calls net/http.Server.Serve which is affected by CVE-2024-5678,
   and your code reaches it via main.go → handler.go → ListenAndServe" → Finding

  "Your project uses net/http v1.20 but does NOT call the vulnerable function" → No finding
```

This means govulncheck has a much lower false positive rate than Grype or OSV-Scanner for Go projects.

### Vulnerability Database

govulncheck uses the [Go Vulnerability Database](https://vuln.go.dev/) maintained by the Go team. The domain `vuln.go.dev` is whitelisted in the VM firewall.

## Debugging

### No findings for a Go project with known vulns

**Causes**:
- Vulnerable function is not reachable from your code (this is govulncheck's feature, not a bug)
- `go.mod` is missing or malformed
- Go module cache issues

**Debug**:
```bash
# Check go.mod exists
limactl shell <vm-name> -- cat /opt/target/go.mod

# Run govulncheck manually
limactl shell <vm-name> -- bash -c "cd /opt/target && govulncheck -json ./..."

# Run without call-graph analysis (shows all vulns including unreachable)
limactl shell <vm-name> -- bash -c "cd /opt/target && govulncheck -mode binary ./..." 2>&1 || true
```

### govulncheck fails

**Causes**:
- Missing `go.mod` (not a Go module project)
- Go version mismatch
- Missing dependencies (need `go mod download` first)

**Debug**:
```bash
# Check Go version
limactl shell <vm-name> -- go version

# Check if modules need downloading
limactl shell <vm-name> -- bash -c "cd /opt/target && go mod download"

# Check for build errors
limactl shell <vm-name> -- bash -c "cd /opt/target && go build ./..." 2>&1 | head -20
```

### NDJSON parse issues

**Symptom**: Findings not extracted from output.

**Debug**:
```bash
# Check raw output format
limactl shell <vm-name> -- cat /opt/scan-results/govulncheck.json | head -20

# Count finding lines
limactl shell <vm-name> -- grep -c '"finding"' /opt/scan-results/govulncheck.json
```

### Non-Go projects

govulncheck checks for `go.mod` before running. Non-Go projects get empty findings immediately. This is normal.
