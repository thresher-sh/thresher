# Scoring and Reports

## Finding Normalization

All 16 scanners produce output in different formats. The pipeline normalizes every finding into a common `Finding` dataclass so they can be de-duplicated, enriched, and prioritized uniformly.

### Normalized Finding Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier (e.g., `grype-CVE-2024-1234-0`) |
| `source_tool` | string | Scanner that found it (e.g., `grype`, `semgrep`) |
| `category` | string | `sca`, `sast`, `supply_chain`, `secrets`, `iac`, `malware`, `binary_analysis`, `license` |
| `severity` | string | `critical`, `high`, `medium`, `low`, `info` |
| `cvss_score` | float or null | CVSS v3 score (0.0-10.0) |
| `cve_id` | string or null | CVE identifier (e.g., `CVE-2024-1234`) |
| `title` | string | Human-readable one-line summary |
| `description` | string | Detailed description with context |
| `file_path` | string or null | Path to affected file |
| `line_number` | int or null | Affected line number |
| `package_name` | string or null | Affected dependency |
| `package_version` | string or null | Installed version |
| `fix_version` | string or null | Version that fixes the issue |
| `raw_output` | dict | Original scanner output (preserved for debugging) |

### De-duplication

Multiple scanners often detect the same CVE. The aggregation step de-duplicates by `(cve_id, package_name)`:

- If two findings share the same CVE ID and package name, they're duplicates
- The finding with more populated fields ("richer" detail) is kept
- Findings without a CVE ID are always included (can't be de-duplicated)
- Final list is sorted by severity (critical first)

## Enrichment

After scanning, findings are enriched with two external data sources:

### EPSS (Exploit Prediction Scoring System)

**Source**: [FIRST EPSS API](https://api.first.org/data/v1/epss)

EPSS provides a probability score (0.0 to 1.0) representing the likelihood that a CVE will be exploited in the wild in the next 30 days. Higher scores mean the vulnerability is more likely to be actively exploited.

- CVE IDs are batched in groups of 100
- Scores are fetched from the FIRST API (whitelisted in the VM firewall)
- API failures are non-fatal — findings proceed without EPSS data

### CISA KEV (Known Exploited Vulnerabilities)

**Source**: [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

The KEV catalog lists vulnerabilities that CISA has confirmed are being actively exploited in the wild. Presence in the KEV catalog is the strongest signal that a vulnerability is dangerous.

- The full catalog is downloaded as JSON
- Each finding's CVE ID is checked against the catalog
- KEV presence triggers automatic **P0** priority

## Priority Computation

Each finding receives a composite priority based on multiple signals:

### Priority Levels

| Priority | Criteria | What It Means |
|----------|----------|---------------|
| **P0** | In CISA KEV (actively exploited), OR AI confidence ≥90 for exfiltration/backdoor/trojan/RCE | **Emergency** — actively exploited or almost certainly malicious |
| **Critical** | CVSS ≥ 9.0, OR EPSS > 0.9, OR AI risk 9-10 confirmed by adversarial | **Severe** — high-impact vulnerability with high exploitation likelihood |
| **High** | CVSS 7.0-8.9, OR EPSS > 0.75, OR AI risk 7-8 | **Important** — significant risk requiring attention |
| **Medium** | CVSS 4.0-6.9, OR EPSS > 0.5, OR AI risk 4-6 | **Notable** — moderate risk, should be reviewed |
| **Low** | Everything else | **Informational** — low risk, track but don't block |

### Priority Decision Logic

The priority function evaluates signals in order, returning the first match:

```
1. CVE in CISA KEV? → P0
2. AI confidence ≥90 for exfiltration/backdoor? → P0
3. CVSS ≥ 9.0? → Critical
4. EPSS > 0.9? → Critical
5. AI risk 9-10 + adversarial confirmed? → Critical
6. CVSS 7.0-8.9? → High
7. EPSS > 0.75? → High
8. AI risk 7-8? → High
9. CVSS 4.0-6.9? → Medium
10. EPSS > 0.5? → Medium
11. AI risk 4-6? → Medium
12. Everything else → Low
```

### Recommendation Logic

The final recommendation is based on the highest-priority finding:

| Highest Finding | Recommendation |
|-----------------|---------------|
| Any P0 or Critical | **DO NOT USE** |
| High (no P0/Critical) | **USE WITH CAUTION** |
| Medium or below only | **GO** |

## Report Output

Reports are written to `<output-dir>/<repo-name>-<timestamp>/`:

### executive-summary.md

A concise report with:
- **Recommendation**: GO / USE WITH CAUTION / DO NOT USE
- **Top findings**: The most critical issues found
- **Risk summary**: Counts by priority level
- **Scanner coverage**: Which scanners ran and what they found

### detailed-report.md

Comprehensive findings grouped by priority:

```markdown
## Priority P0 (2 findings)
### CVE-2024-1234 in example-lib@1.2.3
- Source: grype (SCA)
- CVSS: 9.8 | EPSS: 0.95 | In CISA KEV: Yes
- Description: Remote code execution via...
- Fix: Upgrade to 1.2.4
...

## Priority Critical (5 findings)
...

## Priority High (12 findings)
...
```

Each finding includes source tool, CVSS/EPSS/KEV status, description, and remediation guidance.

### findings.json

Machine-readable JSON array of all enriched findings:

```json
[
  {
    "id": "grype-CVE-2024-1234-0",
    "source_tool": "grype",
    "category": "sca",
    "severity": "critical",
    "cvss_score": 9.8,
    "cve_id": "CVE-2024-1234",
    "title": "CVE-2024-1234 in example-lib@1.2.3",
    "description": "Remote code execution via deserialization",
    "package_name": "example-lib",
    "package_version": "1.2.3",
    "fix_version": "1.2.4",
    "epss_score": 0.95,
    "in_kev": true,
    "composite_priority": "P0"
  }
]
```

### sbom.json

CycloneDX software bill of materials generated by Syft. Lists every component (dependency) identified in the target project with version, license, and package URL (purl).

### scan-results/

Directory containing raw output from each scanner. Useful for debugging or for feeding into other tools:

```
scan-results/
├── syft.json
├── grype.json
├── osv.json
├── trivy.json
├── semgrep.json
├── bandit.json
├── checkov.json
├── hadolint.json
├── guarddog.json
├── gitleaks.json
├── yara.txt
├── capa.json
├── govulncheck.json
├── cargo-audit.json
├── scancode.json
└── clamav.txt
```
