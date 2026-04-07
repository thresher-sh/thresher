# Architecture

## System Layers

```
Host
│
├── CLI (thresher) — thin launcher
│   ├── Config loader (thresher.toml + CLI args + env vars)
│   ├── Launch mode selector (Lima+Docker / Docker / Direct)
│   └── Tmux UI orchestration
│
├── Launcher (picks where harness runs)
│   ├── Lima+Docker (default) — VM + iptables + container
│   ├── Docker (--docker) — container sandbox only
│   └── Direct (--no-vm) — local subprocess (dev mode)
│
└── Harness (self-contained pipeline, mode-agnostic)
    │
    ├── Hamilton DAG Pipeline
    │   ├── Hardened git clone (4-phase, Python)
    │   ├── AI pre-dep discovery (optional)
    │   ├── Dependency resolution (source-only)
    │   ├── SBOM generation (Syft)
    │   ├── 22 scanners (parallel via ThreadPoolExecutor)
    │   ├── 8 AI analyst agents (parallel, optional)
    │   ├── Adversarial verification (optional)
    │   ├── EPSS/KEV enrichment
    │   └── Report synthesis
    │
    └── Output → /output (volume-mounted or local)
```

## Component Map

```
src/thresher/
├── cli.py                    # CLI: arg parsing, launch mode dispatch
├── config.py                 # ScanConfig, LimitsConfig (JSON serialization)
├── branding.py               # Terminal UI styling
│
├── harness/
│   ├── __init__.py
│   ├── __main__.py           # Entrypoint: python -m thresher.harness
│   ├── pipeline.py           # Hamilton DAG definition (all stages)
│   ├── clone.py              # 4-phase hardened git clone (Python)
│   ├── deps.py               # Ecosystem detection + source-only download
│   ├── scanning.py           # Scanner orchestration (ThreadPoolExecutor)
│   └── report.py             # Report validation + enrichment + generation
│
├── launcher/
│   ├── direct.py             # --no-vm: subprocess on host
│   ├── docker.py             # --docker: container with security hardening
│   └── lima.py               # default: Lima VM + Docker inside it
│
├── scanners/
│   ├── models.py             # Finding + ScanResults dataclasses
│   ├── runner.py             # Legacy orchestration (replaced by harness)
│   ├── syft.py               # SBOM generation
│   ├── grype.py              # SCA (CVEs via SBOM)
│   ├── osv.py                # SCA + malicious packages
│   ├── trivy.py              # SCA + IaC
│   ├── semgrep.py            # SAST (multi-language)
│   ├── bandit.py             # SAST (Python)
│   ├── checkov.py            # IaC security
│   ├── hadolint.py           # Dockerfile linting
│   ├── guarddog.py           # Supply chain behavioral analysis
│   ├── guarddog_deps.py      # GuardDog on dep source code
│   ├── gitleaks.py           # Secrets detection
│   ├── yara_scanner.py       # Malware signatures
│   ├── capa_scanner.py       # Binary capability analysis
│   ├── govulncheck.py        # Go vulnerabilities (call-graph)
│   ├── cargo_audit.py        # Rust vulnerabilities
│   ├── scancode.py           # License compliance
│   ├── clamav.py             # Antivirus
│   ├── entropy.py            # Obfuscation/encoded payload detection
│   ├── install_hooks.py      # Install script detection
│   ├── deps_dev.py           # OpenSSF Scorecard, typosquatting
│   ├── registry_meta.py      # Maintainer changes, anomalies
│   └── semgrep_supply_chain.py # Custom supply-chain rules
│
├── agents/
│   ├── prompts.py            # System prompts for agents
│   ├── analyst.py            # Single analyst agent runner
│   ├── analysts.py           # Parallel 8-agent orchestration
│   ├── adversarial.py        # Adversarial verification
│   ├── predep.py             # Pre-dep hidden dependency discovery
│   └── definitions/          # YAML persona definitions
│
├── report/
│   ├── scoring.py            # EPSS/KEV enrichment, priority computation
│   └── synthesize.py         # Report generation orchestration
│
└── vm/
    ├── lima.py               # Lima VM lifecycle (create/start/stop)
    └── firewall.py           # iptables rules (Lima mode only)

docker/
├── Dockerfile                # Single image: harness + all scanner tools
```

## Execution Flow

### Phase 1: Launch

```
CLI parses args + loads thresher.toml
    │
    ├── Load/validate config (ScanConfig)
    ├── Resolve API credentials (env var or Keychain OAuth)
    ├── Serialize config to JSON
    ├── Start tmux session (if enabled)
    │
    ▼
Launcher (based on --docker / --no-vm / default)
    │
    ├── Direct: subprocess.run(python -m thresher.harness --config ...)
    ├── Docker: docker run thresher:latest --config ...
    └── Lima+Docker: limactl shell → docker run thresher:latest ...
```

### Phase 2: Harness Pipeline (Hamilton DAG)

```
Clone target repository (hardened 4-phase clone)
    │
    ├── Phase 1: git clone --no-checkout --depth=1 (hooks disabled)
    ├── Phase 2: Sanitize .git/config (rewrite with safe settings)
    ├── Phase 3: Checkout with all filters disabled
    └── Phase 4: Post-checkout validation (symlinks, path traversal)
    │
    ▼
Dependency Resolution
    │
    ├── Detect ecosystems (manifest files)
    ├── AI pre-dep discovery (hidden deps, optional)
    ├── Source-only downloads per ecosystem:
    │   ├── Python: pip download --no-binary :all:
    │   ├── Node: npm pack
    │   ├── Rust: cargo vendor
    │   └── Go: go mod vendor
    └── Generate dep_manifest.json
    │
    ▼
Scanning (22 tools, parallel via ThreadPoolExecutor)
    │
    ├── Syft → SBOM (sequential, required before Grype)
    └── 21 scanners in parallel (subprocess.run per tool)
    │
    ▼
AI Analysis (optional, skip_ai bypasses)
    │
    ├── 8 analyst agents in parallel (independent investigation)
    └── Adversarial agent verifies high-risk findings
    │
    ▼
Enrichment & Report
    │
    ├── EPSS/KEV enrichment
    ├── Report synthesis (template or AI)
    ├── Report validation (extension whitelist, size limits)
    └── Output → /output directory
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

The harness is self-contained — it runs the full pipeline and writes output to a directory. Communication varies by launch mode:

```
Direct:  CLI → subprocess → harness (same filesystem)
Docker:  CLI → docker run → harness (volume mount for output)
Lima:    CLI → limactl shell → docker run → harness (copy report to host)
```

Config flows one way: CLI serializes `ScanConfig` to JSON, harness deserializes it. The harness never reads `thresher.toml` directly.

Credentials are passed via environment variables (`-e ANTHROPIC_API_KEY`), never written to disk.

## Threading Model

- **Scanner execution**: `ThreadPoolExecutor` with one thread per scanner (15 concurrent)
- **AI analysts**: `ThreadPoolExecutor` with 8 parallel analyst agents
- **Dependency downloads**: Sequential per ecosystem
- **Adversarial verification**: Sequential (runs after all analysts complete)
- **EPSS API calls**: Sequential batched requests (100 CVEs per batch)
