---
name: apply-report
description: Use when applying a Thresher security scan report to a repository to fix vulnerabilities. Triggered by user wanting to remediate findings from a scan report, fix security issues in a repo based on scan output, or create a security remediation PR.
---

# Apply Thresher Report

Apply findings from a Thresher security scan report to a target repository, fix the issues, and generate remediation documentation.

## Gather Inputs

Ask the user for these four inputs (use AskUserQuestion for any not provided):

1. **Report path** — absolute path to the thresher report directory (contains `executive-summary.md`, `detailed-report.md`, `findings.json`, `scan-results/`)
2. **Repo path** — absolute path to the target repository to fix
3. **Findings to ignore** — list of finding IDs, CVEs, or titles to skip (can be empty)
4. **Additional instructions** — any extra context (priority order, scope limits, etc.)

## Read and Analyze Report

### Phase 1: Anchor documents

Read these first — they are the authoritative source of what to fix:

1. `executive-summary.md` — overall assessment, recommendation, top findings
2. `detailed-report.md` — full findings with severity, CVEs, remediation guidance
3. `findings.json` — machine-readable findings with CVSS, EPSS, file paths

### Phase 2: Cross-reference sub-findings

Read ALL files in `scan-results/` directory:

- `analyst-*-findings.md` — AI analyst findings (may contain issues not in main report)
- `adversarial-findings.md` — adversarial verification
- Scanner JSON files (`grype.json`, `semgrep.json`, `gitleaks.json`, etc.)

Compare sub-findings against the detailed report. Flag any finding from scan-results that is HIGH or CRITICAL severity but missing from the main report — these need to be included in the remediation.

### Phase 3: Build remediation list

Compile the full list of findings to fix, excluding ignored ones. Group by category:

- **Dependency vulnerabilities** — CVE-based, need version bumps
- **Application security** — code-level fixes (XSS, SQLi, IDOR, etc.)
- **Secrets** — leaked credentials, API keys
- **CI/CD** — GitHub Actions hardening, permission fixes
- **IaC/Config** — Dockerfile, Terraform, K8s misconfigurations

## Create Tasks and Fix

Use TaskCreate to create a task for each finding or logical group of findings. Mark each in_progress when starting, completed when done.

**Task grouping guidelines:**
- Group dependency upgrades by ecosystem (all npm deps in one task, all pip in another)
- Each application security fix gets its own task
- Group CI/CD fixes by workflow file
- Secrets fixes get individual tasks

**For each task:**
1. Mark in_progress
2. Navigate to the repo path
3. Apply the fix (version bump, code change, config update)
4. Verify the fix doesn't break anything (run tests if available)
5. Mark completed

**Fix priority order:** Critical > High > Medium. Within same severity, fix dependency vulns first (lowest risk of breaking changes), then secrets, then app security, then CI/CD.

## CONTRIBUTOR ADHERENCE

Look to see if there are any CONTRIBUTING or CODE_OF_CONDUCT files or similar to see if we need to do any thing special before raising a PR.

## Generate PR Documentation

After all fixes are applied:

### Step 1: Determine output filename

Format: `{OrgName}_{RepoName}_{PRNumber}.md`

If PR number isn't known yet, use `{OrgName}_{RepoName}_draft.md` and tell the user to rename after PR creation.

### Step 2: Write PR report

Create a new file in `docs/data/prs/` (relative to the thresher project root) following the template structure in `docs/data/pr-template.md`.

Fill in all placeholders with actual data from the remediation work. Include:
- Link to the PR
- Scan date
- Counts by severity
- Dependency upgrade table with package names, versions, CVEs
- Application security fixes with file paths and descriptions
- Secrets remediation details
- CI/CD hardening details
- Scan context (tool list, total findings)
- Known remaining items not addressed

### Step 3: Update remediations.json

Read `docs/data/remediations.json` (relative to the thresher project root) and append a new entry to the `remediations` array:

```json
{
  "repo": "OrgName/RepoName",
  "repo_url": "https://github.com/OrgName/RepoName",
  "pr_number": 0,
  "pr_url": "",
  "report_url": "data/prs/{filename}.md",
  "scan_date": "YYYY-MM-DD",
  "findings": {
    "total_deterministic": 0,
    "total_ai": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "supply_chain": 0,
    "malicious_code": 0,
    "cisa_kev": 0
  },
  "remediations": {
    "dependency_upgrades": 0,
    "app_security_fixes": 0,
    "secrets_remediated": 0,
    "ci_cd_hardening": 0
  }
}
```

Recalculate the `totals` block by summing across all entries in the array.

Tell the user to update `pr_number` and `pr_url` after the PR is created.

## Report Structure Reference

```
report-directory/
  executive-summary.md        # Overall assessment, recommendation, top 10
  detailed-report.md          # Full findings by severity with remediation
  findings.json               # Machine-readable findings
  sbom.json                   # CycloneDX SBOM
  scan-results/
    analyst-{N}-{name}-findings.md   # 8 AI analyst reports
    analyst-{N}-{name}-findings.json # AI analyst structured data
    adversarial-findings.md          # Adversarial verification
    grype.json, semgrep.json, ...    # Raw scanner output
```
