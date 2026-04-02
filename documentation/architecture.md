# Architecture

## System Layers

```
Host (macOS, Apple Silicon)
│
├── CLI (thresher)
│   ├── Config loader (thresher.toml + CLI args + env vars)
│   ├── Tmux UI orchestration
│   └── Report output to host filesystem
│
└── Lima VM (ephemeral, vz backend, Ubuntu 24.04 ARM64)
    │
    ├── Egress Firewall (iptables whitelist, 18 domains)
    │
    ├── Docker Engine
    │   └── Dependency download containers (per-ecosystem)
    │       ├── python:3.12-slim
    │       ├── node:20-slim
    │       ├── rust:slim
    │       └── golang:1.22-slim
    │
    ├── Deterministic Scanners (16 tools, parallel execution)
    │   ├── Phase 1: Syft (SBOM generation)
    │   └── Phase 2: 15 scanners in parallel
    │
    └── AI Analysis Agents (Claude Code headless, optional)
        ├── Agent 1: Analyst (independent code investigation)
        └── Agent 2: Adversarial (false positive reduction)
```

## Component Map

```
src/thresher/
├── cli.py                    # Entry point, tmux UI, orchestration
├── config.py                 # TOML config + CLI override + env vars
│
├── vm/
│   ├── lima.py               # VM create/start/stop/destroy/provision
│   ├── ssh.py                # SSH exec/copy/write via limactl
│   └── firewall.py           # iptables rule generation
│
├── docker/
│   └── sandbox.py            # Ecosystem detection, Docker dep downloads
│
├── scanners/
│   ├── models.py             # Finding + ScanResults dataclasses
│   ├── runner.py             # Orchestration (phase 1 → phase 2 parallel)
│   ├── syft.py               # SBOM generation
│   ├── grype.py              # SCA (CVEs via SBOM)
│   ├── osv.py                # SCA + malicious packages
│   ├── trivy.py              # SCA + IaC
│   ├── semgrep.py            # SAST (multi-language)
│   ├── bandit.py             # SAST (Python)
│   ├── checkov.py            # IaC security
│   ├── hadolint.py           # Dockerfile linting
│   ├── guarddog.py           # Supply chain behavioral analysis
│   ├── gitleaks.py           # Secrets detection
│   ├── yara_scanner.py       # Malware signatures
│   ├── capa_scanner.py       # Binary capability analysis
│   ├── govulncheck.py        # Go vulnerabilities (call-graph)
│   ├── cargo_audit.py        # Rust vulnerabilities
│   ├── scancode.py           # License compliance
│   └── clamav.py             # Antivirus
│
├── agents/
│   ├── prompts.py            # System prompts for both agents
│   ├── analyst.py            # AI security researcher agent
│   └── adversarial.py        # AI false-positive verifier agent
│
└── report/
    ├── scoring.py            # EPSS/KEV enrichment, priority computation
    └── synthesize.py         # Report generation orchestration
```

## Execution Flow

### Phase 1: Setup

```
CLI parses args + loads thresher.toml
    │
    ├── Load/validate config (ScanConfig)
    ├── Resolve API credentials (env var or Keychain OAuth)
    ├── Start tmux session (if enabled)
    │
    ▼
VM Lifecycle
    │
    ├── Check for existing base VM (thresher-base)
    │   ├── Exists + running → reuse
    │   ├── Exists + stopped → start
    │   └── Doesn't exist → create + provision
    │
    ├── Create ephemeral VM (thresher-<timestamp>) from base
    ├── Wait for SSH readiness (poll)
    └── Apply firewall rules
```

### Phase 2: Target Preparation

```
Clone target repository
    │
    ├── git clone --depth=1 <repo-url> /opt/target
    │
    ▼
Dependency Download
    │
    ├── Detect ecosystems (scan for manifest files)
    │   ├── requirements.txt / pyproject.toml / setup.py → Python
    │   ├── package.json → Node
    │   ├── Cargo.toml → Rust
    │   └── go.mod → Go
    │
    ├── For each ecosystem:
    │   ├── Pull Docker image
    │   ├── Mount source read-only, deps volume read-write
    │   └── Download source-only (no install scripts)
    │       ├── Python: pip download --no-binary :all:
    │       ├── Node: npm pack
    │       ├── Rust: cargo vendor
    │       └── Go: go mod vendor
    │
    └── Monorepo support: finds all package directories recursively
```

### Phase 3: Scanning

```
Scanner Orchestration (runner.py)
    │
    ├── Phase 1: Syft → SBOM (CycloneDX JSON)
    │   └── sbom.json stored at /opt/scan-results/sbom.json
    │
    └── Phase 2: ThreadPoolExecutor(max_workers=15)
        ├── Grype (reads SBOM from Phase 1)
        ├── OSV-Scanner
        ├── Trivy
        ├── Semgrep
        ├── Bandit
        ├── Checkov
        ├── Hadolint
        ├── GuardDog
        ├── Gitleaks
        ├── YARA
        ├── capa
        ├── govulncheck
        ├── cargo-audit
        ├── ScanCode
        └── ClamAV

    All scanners:
    ├── Execute via SSH (ssh_exec)
    ├── Write raw output to /opt/scan-results/<tool>.json
    ├── Parse output into normalized Finding objects
    └── Return ScanResults (findings + errors + metadata)

    Aggregation:
    ├── Collect all findings from all scanners
    ├── De-duplicate by (CVE ID, package name)
    │   └── Keep the richer finding (more fields populated)
    └── Sort by severity (critical → high → medium → low → info)
```

### Phase 4: AI Analysis (Optional)

```
Agent 1: Analyst
    │
    ├── Runs Claude Code headless inside VM via SSH
    ├── Tools available: Read, Glob, Grep (no execution)
    ├── No prior context from scanners (independent investigation)
    ├── Investigates: supply chain, malicious code, dangerous deps
    └── Outputs: JSON with risk_score (0-10) per file + reasoning

    ▼
Agent 2: Adversarial
    │
    ├── Receives high-risk findings from Analyst (risk_score >= 4)
    ├── For each finding:
    │   ├── Read the flagged file
    │   ├── Attempt benign explanation
    │   ├── Evaluate explanation honestly
    │   └── Verdict: confirmed or downgraded (with revised score)
    └── Outputs: JSON with verdicts and revised risk scores
```

### Phase 5: Enrichment and Reporting

```
Scoring & Enrichment
    │
    ├── Collect CVE IDs from all findings
    ├── Fetch EPSS scores (FIRST API, batched by 100)
    ├── Fetch CISA KEV catalog
    ├── Compute composite priority per finding:
    │   ├── P0: In KEV, or AI confidence ≥90 for exfiltration/backdoor
    │   ├── Critical: CVSS ≥9, EPSS >0.9, or AI risk 9-10 confirmed
    │   ├── High: CVSS 7-8.9, EPSS >0.75, or AI risk 7-8
    │   ├── Medium: CVSS 4-6.9, EPSS >0.5, or AI risk 4-6
    │   └── Low: everything else
    │
    ▼
Report Generation
    │
    ├── executive-summary.md (GO / CAUTION / DO NOT USE)
    ├── detailed-report.md (all findings by priority)
    ├── findings.json (machine-readable)
    ├── sbom.json (CycloneDX)
    └── scan-results/*.json (raw scanner outputs)

    ▼
Cleanup
    │
    ├── Copy report from VM to host
    ├── Destroy ephemeral VM
    └── Print summary + report path
```

## Data Model

### Finding (normalized scanner output)

```python
@dataclass
class Finding:
    id: str                     # Unique identifier (e.g., "grype-CVE-2024-1234-0")
    source_tool: str            # Scanner that produced this (e.g., "grype")
    category: str               # sca, sast, supply_chain, secrets, iac, malware,
                                # binary_analysis, license
    severity: str               # critical, high, medium, low, info
    cvss_score: float | None    # CVSS v3 score (0.0-10.0)
    cve_id: str | None          # CVE identifier if applicable
    title: str                  # Human-readable summary
    description: str            # Detailed description
    file_path: str | None       # Affected file
    line_number: int | None     # Affected line
    package_name: str | None    # Affected package
    package_version: str | None # Installed version
    fix_version: str | None     # Version that fixes the issue
    raw_output: dict            # Original scanner output (preserved)
```

### ScanResults (per-scanner output)

```python
@dataclass
class ScanResults:
    tool_name: str                      # Scanner name
    execution_time_seconds: float       # How long the scan took
    exit_code: int                      # Process exit code
    findings: list[Finding] = []        # Normalized findings
    errors: list[str] = []             # Error messages
    raw_output_path: str | None = None # Path to raw output file
    metadata: dict = {}                # Scanner-specific metadata
```

## Communication Paths

All communication between the host and the VM happens over SSH via `limactl shell`:

```
Host ──SSH──▶ VM
  │              │
  ├── ssh_exec() ──▶ Run commands, stream stdout/stderr
  ├── ssh_copy_to() ──▶ Copy files host → VM
  ├── ssh_copy_from() ──▶ Copy files VM → host
  └── ssh_write_file() ──▶ Write content to VM file (injection-safe)
```

Environment variables (API keys) are passed via SSH environment, never written to disk inside the VM.

## Threading Model

- **Scanner execution**: `ThreadPoolExecutor` with one thread per scanner (15 concurrent)
- **Dependency downloads**: Sequential per ecosystem (Docker containers)
- **AI agents**: Sequential (Analyst runs first, Adversarial runs second with Analyst's output)
- **EPSS API calls**: Sequential batched requests (100 CVEs per batch)
