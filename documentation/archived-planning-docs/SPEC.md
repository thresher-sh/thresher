# Project Threat Scanner — Multi-Stage Specification

**Purpose:** A personal tool to evaluate whether an open source package is safe to use. Scan a target repo and its dependencies for known vulnerabilities, malicious code, and supply chain risks. Produce a static report with a go/no-go recommendation.

**Core architecture:** Lima VM (macOS isolation) > Docker (dependency install sandbox) > Deterministic scanners + AI analysis (2 agents max) > Static report.

---

## Stage 1: Lima VM Foundation

Build the isolated VM environment that everything else runs inside. This is the bedrock — if this is wrong, nothing else matters.

### Deliverables
- Lima VM creation script (idempotent, scripted, one command)
- `vz` backend on Apple Silicon, Ubuntu LTS guest
- `--plain --mount-none` for full isolation
- iptables egress firewall (whitelist: Claude API, GitHub, package registries, vulnerability DBs)
- SSH access only — no shared folders, no port forwarding
- Provisioning script that installs: Docker, git, Python, Node.js, Rust toolchain (for cargo-audit)
- `./scan.sh <repo-url>` wrapper on the host that creates VM, provisions, and hands off
- VM teardown (`limactl delete`) after scan or on demand

### Decided
- **Ephemeral VMs only.** Fresh VM per scan, `limactl delete` after. No reuse, no snapshots, no cross-contamination.

### Also decided
- **Lima confirmed.** Firecracker is a pain on macOS. Lima with `vz` backend is the choice.

### Open questions

1. **Resource allocation.** The research doc suggests 4 CPU / 8GB RAM / 50GB disk. Claude Code + Docker + scanners inside a VM is heavy. Do you have a sense of what your machine can spare? (How much RAM/CPU does your Mac have?) We could also make these configurable via env vars.

2. **Package registry access during scan.** The iptables whitelist needs to allow `pypi.org`, `registry.npmjs.org`, `crates.io`, etc. during dependency download, then ideally tighten further during analysis. Should we do a two-phase firewall (permissive during download, locked down during analysis) or keep it simple with a single whitelist?

3. **Claude API key injection.** The key needs to get into the VM without being stored in any config file. Options: pass via SSH environment variable at invocation time, or use Lima's `--env` flag. Do you have a preference? Do you use multiple API keys or just one?

---

## Stage 2: Docker-in-VM Dependency Sandbox

Build the nested isolation layer that handles untrusted dependency installation.

### Deliverables
- Dockerfile for dependency install container (per-ecosystem: Python, Node, Rust, Go, etc.)
- Container runs with `--network=none` after package download phase
- Volume-mount strategy: installed packages exported read-only to the VM host filesystem
- Capture install-time stdout/stderr/strace as scan artifacts (malicious install scripts leave traces)
- Handle multi-ecosystem projects (e.g., a project with both `requirements.txt` and `package.json`)

### Decided
- **Source-only downloads.** `pip download --no-binary :all:`, `npm pack`, etc. No executing install scripts. Safer and simpler. Install-time behavioral analysis deferred.

### Also decided
- **Transitive dependency depth: configurable, default 2.** Direct deps + their direct deps by default. Configurable via CLI flag (e.g., `--depth 3`) for deeper analysis when needed.
- **Ecosystem coverage: detect and adapt.** No hardcoded language constraint. The scanner detects what the target project uses (package.json, requirements.txt, Cargo.toml, go.mod, etc.) and provisions accordingly. MVP must handle whatever the scanned project throws at it.
- **strace / runtime tracing deferred.** Source-only downloads means no install-time behavior to trace.

### Open questions

1. *(None remaining for this stage.)*

---

## Stage 3: Deterministic Scanner Layer

Install and orchestrate the traditional security scanning tools.

### Deliverables
- Install scripts for each tool inside the VM provisioning
- Per-tool runner scripts that output normalized JSON to `/opt/scan-results/`
- Parallel execution where tools are independent
- Correct sequencing where tools depend on each other (Syft SBOM before Grype)
- Tool exit code handling (some tools exit non-zero on findings — that's not an error)

### Scanner selection to confirm

The research doc lists 14 tools. For a lean MVP targeting personal use:

| Tool | Category | Include in MVP? |
|------|----------|-----------------|
| **Syft** | SBOM generation | Yes — feeds Grype |
| **Grype** | SCA (known CVEs) | Yes — core |
| **OSV-Scanner** | SCA (CVEs + MAL entries) | Yes — catches malicious packages Grype misses |
| **Semgrep** | SAST (code vulns) | Yes — fast, broad language coverage |
| **GuardDog** | Supply chain behavioral | Yes — key differentiator for malicious code |
| **Gitleaks** | Secrets detection | Yes — lightweight, fast |
| **Bandit** | Python SAST | Maybe — Semgrep covers most of this |
| **pip-audit** | Python SCA | Maybe — overlaps with Grype/OSV |
| **npm audit** | Node SCA | Maybe — overlaps with Grype/OSV |
| **cargo-audit** | Rust SCA | Defer — add with Rust ecosystem support |
| **OWASP Dep-Check** | SCA (broad) | Defer — heavy, overlaps with Grype+OSV |
| **CodeQL** | Deep SAST | Defer — slow, better for scheduled deep scans |
| **Checkov** | IaC scanning | Defer — not source code focused |
| **Packj** | Behavioral + strace | Defer or Stage 2 — depends on strace decision |

### Questions to discuss

1. **How lean is the MVP scanner set?** The "Yes" column above gives us 6 tools. That's already solid coverage. Should Bandit stay (it's Python-specific and you may scan a lot of Python) or is Semgrep sufficient? Same question for pip-audit / npm audit — they're native and fast but overlap.

2. **Semgrep rulesets.** Semgrep has 20,000+ community rules. Running `--config auto` grabs a curated set. Should we also include the supply-chain-specific rulesets, or keep it to `auto` for the MVP and tune later?

3. **GitHub Actions / CI workflow scanning.** You agreed this is in scope since it's part of the source code. None of the listed tools specifically scan for Actions misconfigs (pwn requests, secret exposure in logs, `pull_request_target` abuse). Semgrep has some rules for this. Should we add a dedicated check or rely on the AI agent to catch these?

4. **Tool version pinning.** Do we pin scanner versions in the provisioning script (reproducible but needs maintenance) or always install latest (current results but could break)?

---

## Stage 4: AI Analysis Layer (2 Agents)

The non-deterministic layer — Claude reading code and reasoning about intent.

### Deliverables
- **Agent 1 — Triage + Focused Analysis:** Reads deterministic scanner output, identifies high-risk surfaces (install hooks, entry points, obfuscated code, flagged files), then does deep code analysis on those targets. Also reads files that scanners can't reason about (binary blobs in source trees, unusual file types in unexpected places). Uses `git blame` for provenance context.
- **Agent 2 — Adversarial Verification:** Takes all findings with risk >= 4 from Agent 1 and the deterministic scanners. Attempts to construct benign explanations. Findings that survive become confirmed. Findings that don't get downgraded with reasoning.
- System prompts for each agent
- Structured JSON output schema for findings
- Comment/metadata stripping for re-analysis of suspicious files

### Decided
- **Conservative triage.** Minimize token costs. Agent 1 focuses on files flagged by deterministic tools + known high-risk file types (.pth, setup.py, postinstall scripts, __init__.py, build scripts, CI configs). No brute-force reading of every file.
- **Headless only for MVP.** Interactive mode deferred to a later stage.

### Also decided
- **Sonnet for both agents.** Cost-effective, fast. Opus available as a future option if needed.
- **Two agents confirmed.** Agent 1 analyzes, Agent 2 adversarially verifies.

### Open questions

1. **Context window management.** Large files or many flagged files could blow the context window. Strategy options:
   - Hard cap: skip files over N lines with a note in the report
   - Chunking: split large files and analyze in pieces (risks missing cross-section patterns)
   - Summarize first: have the agent skim and summarize before deep-diving
   What feels right?

---

## Stage 5: Report Synthesis and Output

Merge everything into a single static artifact.

### Deliverables
- Synthesis logic that merges deterministic + AI findings
- De-duplication (same issue found by multiple tools)
- Composite risk scoring: CVSS + EPSS + CISA KEV + AI confidence
- Output files:
  - `executive-summary.md` — go/no-go recommendation, top findings, overall risk level
  - `findings.json` — structured, machine-readable, every finding with scores and sources
  - `detailed-report.md` — full findings with code references, reasoning, tool attribution
  - `sbom.json` — CycloneDX SBOM of the scanned project
- All output written to `/opt/security-reports/<timestamp>/` inside the VM

### Decided
- **Agent-driven synthesis.** A Claude agent synthesizes the final report — either directly writing it or generating a synthesis script. The agent can reason about conflicting findings and write a coherent narrative, which a pure script can't do.

### Open questions

1. **Report retrieval.** Report stays in the VM, retrieved via `scp`. Should the host-side CLI automatically scp the report out at the end (breaks the "nothing returns to host" purity) or leave it manual? Pragmatically, you'll always want to pull it out. A single `scp` of a report directory seems safe — it's text/JSON, not executable code.

2. **EPSS/KEV enrichment.** This requires API calls to `api.first.org` and checking the CISA KEV catalog. Should this happen inside the VM (needs network access to these APIs during synthesis) or on the host side as a post-processing step after retrieving findings.json?

3. **Risk threshold for the go/no-go.** The executive summary should give a clear recommendation. What's your threshold? For example:
   - Any P0/Critical finding = **DO NOT USE**
   - High findings only = **USE WITH CAUTION** (list mitigations)
   - Medium and below = **ACCEPTABLE RISK**
   Or do you want to define this yourself per scan?

---

## Stage 6: CLI UX and Hardening

Make it pleasant to use day-to-day.

### Deliverables
- Clean CLI interface: `./scan.sh <repo-url> [options]`
- Options: `--interactive`, `--skip-ai` (deterministic only, cheap fast scan), `--verbose`
- Progress output to the terminal (which tool is running, percent complete)
- Error handling (network failures, tool crashes, API rate limits)
- Configuration file for: API key, default VM resources, scanner selection
- Validation suite: run scanner against known-malicious packages to verify detection

### Decided
- **Python CLI.** User's strongest language. argparse/click for argument parsing, subprocess for Lima/SSH orchestration.

### Open questions

1. **The validation suite — how important is this early on?** Datadog publishes a malicious-software-packages-dataset. We could build a test harness that runs the scanner against known-bad packages and checks detection rates. This is valuable for tuning prompts and catching regressions. Build it in Stage 6 or sooner?

2. **Scan resumability.** If a scan fails halfway (API rate limit, VM crash), should we support resuming from where it left off? Or is re-running from scratch acceptable given scans are one-shot?

3. **Logging and debugging.** When something goes wrong, how much do you want to see? Options:
   - Minimal: just the final report or error message
   - Verbose flag: shows tool-by-tool output
   - Full debug: saves all intermediate artifacts (raw tool JSON, agent transcripts, iptables logs)

---

## Proposed Build Order

```
Stage 1 (Lima VM)          ← foundation, build first
  ↓
Stage 2 (Docker sandbox)   ← depends on VM being solid
  ↓
Stage 3 (Scanners)         ← can partially parallel with Stage 2
  ↓
Stage 4 (AI agents)        ← needs scanner output to triage from
  ↓
Stage 5 (Report)           ← needs all findings
  ↓
Stage 6 (CLI + hardening)  ← polish layer, iterative
```

Each stage should be independently testable. Stage 1 done = you can SSH into an isolated VM. Stage 3 done = you get deterministic scan results without any AI. Stage 4 done = full scan works end to end.
