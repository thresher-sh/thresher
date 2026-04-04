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

## Report Generation

Report generation is the final stage of the scan pipeline. It takes enriched findings from all scanners and AI agents and produces a set of report artifacts inside the VM. The report directory is then copied to the host via `ssh_copy_from_safe()`.

### Generation Paths

There are two report generation paths depending on whether AI is enabled:

**Agent path** (default): A Claude Code headless agent runs inside the VM and synthesizes all findings into narrative markdown reports. The agent reads the enriched findings JSON and produces `executive-summary.md`, `detailed-report.md`, and `synthesis-findings.md`. If the agent fails, Thresher falls back to the template path automatically.

**Template path** (`--skip-ai`): Jinja2 templates render the markdown reports directly from enriched finding data. Deterministic and fast, but the narrative prose is less sophisticated than agent-generated content.

**HTML report** (always): After either path completes, an HTML report (`report.html`) is always generated using a Jinja2 template. This is the primary report artifact — the CLI prints its path at the end of a scan. When agent narratives are available, they are read from the VM and embedded into the HTML report. When they aren't (template path or agent failure), the HTML template generates its own prose.

### Report Generation Flow

```
enriched findings + AI findings
         │
         ├── Agent path ──────────────> executive-summary.md
         │   (Claude headless in VM)    detailed-report.md
         │                              synthesis-findings.md
         │
         ├── Template path ───────────> executive-summary.md
         │   (Jinja2 on host,           detailed-report.md
         │    fallback or --skip-ai)    synthesis-findings.md
         │
         └── HTML report ─────────────> report.html (primary artifact)
             (always runs,
              incorporates agent
              narratives if available)
```

### Template Context

Both template paths (markdown and HTML) share the same context builder (`_build_template_context`). Key context fields:

| Field | Description |
|-------|-------------|
| `risk_assessment` | GO / CAUTION / DO NOT USE |
| `priority_counts` | Finding counts by priority level |
| `top_findings` | Top 10 findings sorted by composite priority |
| `findings_by_priority` | All findings grouped by priority |
| `scanner_finding_counts` | Scanner-only counts by priority |
| `ai_finding_counts` | AI-only counts by priority |
| `ai_findings_grouped` | AI findings grouped by priority (for card rendering) |
| `upgrade_packages` | Deduplicated packages with available fix versions |
| `agent_executive_summary` | Agent narrative HTML (None if unavailable) |
| `agent_synthesis` | Agent synthesis narrative HTML (None if unavailable) |

### HTML Report Safety

The HTML template uses a separate Jinja2 `Environment` with HTML autoescaping enabled. All user-controlled content (repo URLs, finding titles, file paths, descriptions) is automatically escaped to prevent XSS. Agent narratives are markdown converted to HTML via the `markdown` library and marked safe with `Markup()` so they render correctly without double-escaping.

## Report Output

Reports are written to `<output-dir>/<scan-id>/`:

### report.html (primary artifact)

Self-contained HTML report with all CSS inline. Dark-themed, responsive design with these sections:

- **Verdict**: GO (green) / CAUTION (amber) / DO NOT USE (red) with finding count badges
- **Executive Summary**: Agent-generated narrative when available, template prose otherwise. Includes required mitigations for P0/Critical/High findings.
- **Findings Distribution**: Visual bar chart showing scanner and AI finding counts by severity
- **Scanner Findings**: Top 10 findings table with severity, CVE, and CVSS
- **AI Analyst Findings**: Cards grouped by severity with confidence scores and analyst attribution. Critical/High shown as full cards, Medium/Low in a collapsible section.
- **Dependency Upgrades**: Table of packages with current and fixed versions (conditional — only shown when upgrades are available)
- **Pipeline Details**: Collapsible section listing all scanners and AI personas used

Conditional sections (trust assessment, remediation PR) render only when their data is available, keeping the report clean for scans that don't produce that data.

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

### synthesis-findings.md

The synthesis agent's own analysis of how findings were merged, prioritized, and evaluated across scanner and AI tracks. Includes agreements/disagreements between the two analysis approaches and reasoning for priority elevation or downgrade decisions.

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

## Templates

Report templates live in `src/thresher/report/templates/`:

| Template | Format | Purpose |
|----------|--------|---------|
| `report.html.j2` | HTML | Primary report artifact — polished, self-contained |
| `executive_summary.md.j2` | Markdown | Executive summary (fallback for `--skip-ai`) |
| `detailed_report.md.j2` | Markdown | Full findings report (fallback for `--skip-ai`) |

The HTML template uses the same CSS design system as the Thresher website (dark theme, JetBrains Mono + Inter fonts, violet accent). Google Fonts are linked for host-side viewing but fall back gracefully to system fonts.
