# AI Agent Loop

This document explains how the two AI analysis agents work, what they investigate, and how their findings feed into the final report.

## Overview

The AI analysis is an optional phase (`--skip-ai` disables it) that uses two Claude Code agents running headless inside the VM. The agents are independent — the first investigates the code with no prior context, and the second challenges the first's findings to reduce false positives.

```
Analyst Agent ────▶ High-risk findings ────▶ Adversarial Agent ────▶ Verified findings
(paranoid researcher)  (risk_score >= 4)      (defense attorney)      (confirmed/downgraded)
```

## Agent 1: Analyst

**Role**: Paranoid, adversarial security researcher who assumes every repository is guilty until proven innocent.

**Location**: `src/thresher/agents/analyst.py`

**System prompt**: `ANALYST_SYSTEM_PROMPT` in `src/thresher/agents/prompts.py`

### What It Investigates

The Analyst examines three categories of threats:

#### 1. Supply Chain Attacks
- Malicious code injected into dependencies or build tooling
- Typosquatted or hijacked package names
- Compromised CI/CD pipelines (`.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`)
- Malicious install hooks (`setup.py`, `postinstall`, `.pth` files)
- Dependency confusion attacks
- Pinned dependencies pointing to known-vulnerable or backdoored versions

#### 2. Malicious Code by the Author
- Backdoors, data exfiltration, credential harvesting
- Obfuscated code: base64/hex encoding, `eval`/`exec` chains, dynamic imports, `chr()` assembly, `marshal`/`pickle` loads
- Hidden network activity: HTTP requests to hardcoded IPs, DNS exfiltration, reverse shells
- Environment harvesting: reading env vars, `~/.ssh/*`, `~/.aws/*`, wallet files, browser profiles
- Conditional execution based on hostname, username, CI environment
- Steganographic payloads in non-code files
- Code that behaves differently than its documentation describes

#### 3. Dangerous Dependencies
- Reads all manifest files to understand the dependency tree
- Identifies high-value targets: crypto libraries, auth libraries, HTTP clients, serialization libraries
- Checks for unusual dependencies that don't match the project's stated purpose
- Flags dependencies from non-standard registries or git URLs
- Reports unpinned dependencies and missing lock files as attack surface

### How It Works

1. **Understand the project** — Reads README, config files, directory structure
2. **Map the codebase** — Uses Glob and Grep to survey all files
3. **Examine high-risk areas** — CI/CD configs, build hooks, entry points, files with obfuscation patterns, scripts directories
4. **Deep investigation** — For anything suspicious, reads the full file and analyzes context
5. **Risk scoring** — Rates each finding 0-10:
   - 0: No suspicious patterns
   - 1-3: Minor concerns (common patterns that look odd out of context)
   - 4-6: Moderate concerns requiring human review
   - 7-8: Strong indicators of malicious intent
   - 9-10: Almost certainly malicious

### Tools Available

| Tool | Purpose |
|------|---------|
| Read | Read file contents |
| Glob | Find files by pattern |
| Grep | Search file contents |

The Analyst **cannot** execute code, write files, or access the network (beyond the Claude API call itself).

### Output Format

```json
{
  "project_summary": "What this project does and its overall risk posture",
  "files_analyzed": 42,
  "high_risk_count": 3,
  "investigation_areas": [
    "CI/CD: Reviewed 5 GitHub Actions workflows for supply chain risks",
    "Dependencies: Analyzed pyproject.toml — 12 direct deps, all from PyPI",
    "Build hooks: Checked setup.py, Makefile, Dockerfile — no install-time code execution",
    "Entry points: Reviewed 3 package __init__.py files — standard imports only"
  ],
  "findings": [
    {
      "file_path": "/opt/target/path/to/file.py",
      "risk_score": 7,
      "findings": [
        {
          "pattern": "base64_exec",
          "description": "Base64-encoded string decoded and passed to exec()",
          "line_numbers": [14, 15, 16],
          "severity": "high",
          "confidence": 85
        }
      ],
      "reasoning": "Detailed explanation of what was found and why it's concerning"
    }
  ]
}
```

### Key Design Decisions

- **No scanner context**: The Analyst gets no findings from the deterministic scanners. It investigates independently to avoid anchoring bias and to catch things scanners miss.
- **Trust nothing**: The prompt explicitly instructs the agent not to trust comments, variable names, README claims, or author-stated intentions.
- **Flag aggressively**: False positives are acceptable; false negatives are not. That's what the Adversarial agent is for.

## Agent 2: Adversarial

**Role**: Defense attorney for code. Attempts to construct benign explanations for each finding and only confirms those that survive scrutiny.

**Location**: `src/thresher/agents/adversarial.py`

**System prompt**: `ADVERSARIAL_SYSTEM_PROMPT` in `src/thresher/agents/prompts.py`

### Input

Receives only high-risk findings from the Analyst (risk_score >= 4). Low-risk findings pass through without adversarial review.

### How It Works

For each finding:

1. **Read the flagged file** at the specified path and line numbers
2. **Attempt benign explanation**:
   - Is this a common, well-known pattern in this ecosystem?
   - Is the "obfuscation" actually minification or bundling output?
   - Is the network call to a known, legitimate API?
   - Is there a documented reason in the project's README or docs?
   - Is the pattern standard for the framework being used?
3. **Evaluate the explanation honestly**:
   - Would a senior security engineer accept this?
   - Does it account for ALL suspicious aspects, or only some?
   - Is there a simpler malicious explanation that fits better?
4. **Render verdict**:
   - **confirmed**: Finding stands. No convincing benign explanation.
   - **downgraded**: Likely false positive. Strong, specific benign explanation. Revised risk score provided.

### Output Format

```json
{
  "verification_summary": "Brief summary of adversarial review results",
  "total_reviewed": 5,
  "confirmed_count": 3,
  "downgraded_count": 2,
  "results": [
    {
      "file_path": "/opt/target/path/to/file.py",
      "original_risk_score": 7,
      "verdict": "confirmed",
      "revised_risk_score": 7,
      "benign_explanation_attempted": "Could be a build artifact or minified code",
      "reasoning": "The base64 string decodes to a shell command that downloads and executes a remote script. No legitimate build tool produces this pattern.",
      "confidence": 90
    }
  ]
}
```

### Key Design Decisions

- **Genuine adversarial process**: The agent must actually attempt to disprove each finding, not rubber-stamp them.
- **Honest evaluation**: The prompt requires the agent to assess whether its own benign explanation holds up under scrutiny.
- **Reads actual code**: The Adversarial agent reads the flagged file directly — it doesn't rely solely on the Analyst's description.

## How AI Findings Feed Into the Report

1. **Analyst findings** with `risk_score >= 4` are sent to the Adversarial agent
2. **Adversarial verdicts** determine the final status:
   - `confirmed` findings keep their risk score
   - `downgraded` findings get a revised (lower) risk score
3. **Priority computation** uses AI findings alongside scanner findings:
   - AI confidence >= 90 for exfiltration/backdoor → **P0**
   - AI risk 9-10 confirmed by adversarial → **Critical**
   - AI risk 7-8 → **High**
   - AI risk 4-6 → **Medium**
4. **Report includes** both scanner and AI findings, clearly labeled by source

## Output Parsing

The agents output JSON, but Claude Code may wrap it in various formats. The parser handles:

- Direct JSON objects
- Stream-JSON (newline-delimited JSON)
- JSON inside markdown code blocks (`` ```json ... ``` ``)
- JSON embedded in prose text (extracted via regex/brace matching)

This robustness ensures the pipeline doesn't fail if the agent's output format varies slightly between runs.

## Cost and Performance

- **Model**: Configurable via `thresher.toml` (`model = "sonnet"` by default)
- **Typical runtime**: 3-8 minutes for both agents combined
- **Typical cost**: A few dollars per scan (depends on repo size and number of findings)
- **Skip with**: `--skip-ai` for free, deterministic-only scans
