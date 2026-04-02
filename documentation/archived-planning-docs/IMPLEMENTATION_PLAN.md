# Implementation Plan

Reference: [SPEC.md](./SPEC.md) for full stage details and open questions.

---

## Project Structure

```
project-threat-scanner/
├── README.md
├── pyproject.toml                  # Python project config (click, etc.)
├── SPEC.md
├── IMPLEMENTATION_PLAN.md
├── src/
│   └── threat_scanner/
│       ├── __init__.py
│       ├── cli.py                  # Click-based CLI entry point
│       ├── config.py               # Config loading (env vars, config file, CLI args)
│       ├── vm/
│       │   ├── __init__.py
│       │   ├── lima.py             # Lima VM create/provision/destroy
│       │   ├── ssh.py              # SSH command execution helper
│       │   └── firewall.py         # iptables rule generation
│       ├── docker/
│       │   ├── __init__.py
│       │   └── sandbox.py          # Docker container mgmt for dep install
│       ├── scanners/
│       │   ├── __init__.py
│       │   ├── runner.py           # Scanner orchestration (parallel execution)
│       │   ├── syft.py             # SBOM generation
│       │   ├── grype.py            # SCA
│       │   ├── osv.py              # SCA + MAL
│       │   ├── semgrep.py          # SAST
│       │   ├── guarddog.py         # Supply chain behavioral
│       │   └── gitleaks.py         # Secrets
│       ├── agents/
│       │   ├── __init__.py
│       │   ├── prompts.py          # System prompts for Agent 1 and Agent 2
│       │   ├── analyst.py          # Agent 1: triage + code analysis
│       │   └── adversarial.py      # Agent 2: adversarial verification
│       └── report/
│           ├── __init__.py
│           ├── synthesize.py       # Agent-driven synthesis orchestration
│           ├── scoring.py          # CVSS + EPSS + KEV composite scoring
│           └── templates/          # Report markdown templates
│               ├── executive_summary.md.j2
│               └── detailed_report.md.j2
├── vm_scripts/
│   ├── provision.sh                # Runs inside VM: installs all tools
│   ├── firewall.sh                 # Runs inside VM: configures iptables
│   ├── run_scanners.sh             # Runs inside VM: executes deterministic layer
│   └── download_deps.sh            # Runs inside VM/Docker: source-only dep download
├── lima/
│   └── scanner.yaml                # Lima VM template (vz, resources, no mounts)
└── tests/
    ├── test_cli.py
    ├── test_vm_lifecycle.py
    ├── test_scanner_parsing.py
    └── fixtures/
        └── sample_scanner_output/  # Known-good JSON output for parser tests
```

---

## Stage 1: Lima VM Foundation

### Step 1.1 — Python project scaffolding
- `pyproject.toml` with dependencies: `click`, `pyyaml`, `jinja2`
- `src/threat_scanner/cli.py` — Click CLI with `scan` command
- Basic arg parsing: `threat-scan <repo-url> [--depth N] [--verbose] [--skip-ai]`

### Step 1.2 — Lima VM template
- `lima/scanner.yaml` — Lima config file defining:
  - `vmType: vz` (Apple Virtualization Framework)
  - CPU, memory, disk (configurable via CLI args, defaults: 4 CPU / 8GB / 50GB)
  - `mountType: none` (no host mounts)
  - `plain: true` (no guest agent, no port forwarding)
  - Ubuntu LTS base image
- `src/threat_scanner/vm/lima.py`:
  - `create_vm()` — `limactl create` from template
  - `start_vm()` — `limactl start`
  - `destroy_vm()` — `limactl delete -f`
  - `vm_status()` — check if running

### Step 1.3 — SSH execution layer
- `src/threat_scanner/vm/ssh.py`:
  - `ssh_exec(vm_name, command)` — run a command inside the VM via `limactl shell`
  - `ssh_copy_to(vm_name, local_path, remote_path)` — scp file into VM
  - `ssh_copy_from(vm_name, remote_path, local_path)` — scp file out of VM
  - Handles stdout/stderr capture, exit codes, timeouts

### Step 1.4 — VM provisioning script
- `vm_scripts/provision.sh` — installs inside the VM:
  - Docker (via apt)
  - Python 3, pip
  - Node.js, npm
  - Rust toolchain (rustup)
  - Go
  - Git
  - Claude Code (`npm install -g @anthropic-ai/claude-code`)
  - Scanners: Syft, Grype, OSV-Scanner, Semgrep, GuardDog, Gitleaks
- Script is idempotent (checks before installing)

### Step 1.5 — Firewall configuration
- `vm_scripts/firewall.sh` — iptables rules:
  - Default OUTPUT DROP
  - Allow: Claude API, GitHub, package registries (pypi.org, registry.npmjs.org, crates.io, proxy.golang.org), vulnerability DBs (api.first.org, services.nvd.nist.gov)
  - Allow DNS (UDP 53)
  - LOG all blocked connections
- `src/threat_scanner/vm/firewall.py` — Python helper to generate/apply rules

### Step 1.6 — End-to-end lifecycle test
- `threat-scan https://github.com/some/tiny-repo` should:
  1. Create VM
  2. Provision tools
  3. Clone repo
  4. Print "VM ready, repo cloned" (scanners not wired yet)
  5. Destroy VM

### Milestone: Can create, provision, and destroy a Lima VM with one command.

---

## Stage 2: Docker-in-VM Dependency Sandbox

### Step 2.1 — Dependency detection
- `src/threat_scanner/scanners/runner.py` — detect which ecosystems the target project uses by checking for:
  - `requirements.txt`, `setup.py`, `pyproject.toml`, `Pipfile` → Python
  - `package.json`, `package-lock.json`, `yarn.lock` → Node
  - `Cargo.toml`, `Cargo.lock` → Rust
  - `go.mod`, `go.sum` → Go
  - `Gemfile`, `Gemfile.lock` → Ruby
  - etc.

### Step 2.2 — Source-only download scripts
- `vm_scripts/download_deps.sh` — per-ecosystem source-only download:
  - Python: `pip download --no-binary :all: --no-deps -d /opt/deps/python/ -r requirements.txt`
  - Node: `npm pack <package>` for each dep, extract to `/opt/deps/node/`
  - Rust: `cargo vendor` to `/opt/deps/rust/`
  - Go: `go mod vendor` to `/opt/deps/go/`
- Runs inside a Docker container with `--network` access during download, then container is destroyed

### Step 2.3 — Transitive dependency resolution
- Resolve the dependency tree up to configurable depth (default 2)
- For Python: `pip download` naturally grabs transitive deps; filter to depth N by parsing dependency metadata
- For Node: parse `package-lock.json` for the resolved tree, download only to depth N
- Store a manifest: `dep_manifest.json` listing every downloaded dep with name, version, ecosystem, depth level, filesystem path

### Step 2.4 — Docker isolation
- `src/threat_scanner/docker/sandbox.py`:
  - Build a minimal Docker image per ecosystem (just the package manager + tools)
  - Run download inside Docker container
  - Volume-mount `/opt/deps/` out as read-only after download completes
  - Container gets `--network=none` after download phase (or: run download, stop container, mount output)

### Milestone: Can clone a repo, detect its ecosystems, download all deps (source-only, 2 levels deep) inside Docker, and have them available at `/opt/deps/` for scanning.

---

## Stage 3: Deterministic Scanner Layer

### Step 3.1 — Scanner runner framework
- `src/threat_scanner/scanners/runner.py`:
  - `run_all_scanners(target_dir, scan_output_dir)` — orchestrates all scanners
  - Runs independent scanners in parallel (subprocess with `asyncio.gather` or `concurrent.futures`)
  - Handles sequencing: Syft must complete before Grype
  - Captures exit codes (many scanners exit non-zero when findings exist — that's not a failure)
  - Each scanner writes JSON to `/opt/scan-results/<tool>.json`

### Step 3.2 — Individual scanner wrappers
Each wrapper in `src/threat_scanner/scanners/` handles:
- Building the CLI command
- Parsing the JSON output into a normalized finding format
- Error handling for tool-specific quirks

**Execution order:**
```
                 Syft (SBOM)
                    │
                    ▼
    ┌───────────────┼───────────────┐
    │               │               │
  Grype          Semgrep        GuardDog
  (needs SBOM)   (parallel)    (parallel)
    │               │               │
    └───────┬───────┘               │
            │                       │
       OSV-Scanner              Gitleaks
       (parallel)              (parallel)
```

### Step 3.3 — Normalized finding format
All scanner output gets parsed into a common schema:

```json
{
  "id": "grype-CVE-2024-1234",
  "source_tool": "grype",
  "category": "sca|sast|supply_chain|secrets",
  "severity": "critical|high|medium|low|info",
  "cvss_score": 9.1,
  "cve_id": "CVE-2024-1234",
  "title": "Remote code execution in package-name",
  "description": "...",
  "file_path": "/opt/target/src/foo.py",
  "line_number": 42,
  "package_name": "package-name",
  "package_version": "1.2.3",
  "fix_version": "1.2.4",
  "raw_output": { }
}
```

### Step 3.4 — Scanner output aggregation
- Merge all normalized findings into `/opt/scan-results/all_findings.json`
- Basic de-duplication: same CVE + same package = one finding (keep the richest detail)

### Milestone: Can run all 6 deterministic scanners against a cloned repo, get normalized JSON output, and have aggregated findings ready for AI analysis.

---

## Stage 4: AI Analysis Layer

### Step 4.1 — System prompts
- `src/threat_scanner/agents/prompts.py`:
  - `ANALYST_SYSTEM_PROMPT` — Agent 1: triage + focused code analysis
  - `ADVERSARIAL_SYSTEM_PROMPT` — Agent 2: adversarial verification
  - Prompts include the structured output schema, risk rating scale, and analysis framework from the research doc
  - Agent 1 prompt includes instruction to use `git blame` for provenance

### Step 4.2 — Triage logic (determines what Agent 1 reads)
- `src/threat_scanner/agents/analyst.py`:
  - Collect all files flagged by deterministic scanners
  - Add known high-risk file types: `setup.py`, `setup.cfg`, `__init__.py`, `.pth`, `postinstall`, `preinstall`, CI/CD configs (`.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`)
  - Add all entry points identified by Syft/SBOM
  - Add files with anomalous characteristics (binary content in source directories, high entropy strings)
  - Build the file list, pass to Agent 1

### Step 4.3 — Agent 1: Triage + Code Analysis
- Invoke Claude Code headless inside the VM:
  ```bash
  claude -p "<analyst prompt with file list and scanner findings>" \
    --model sonnet \
    --allowedTools "Read,Glob,Grep,Bash(git blame)" \
    --output-format json \
    --max-turns 30
  ```
- Agent reads each triaged file, applies the analysis framework
- For files scoring risk >= 4: strips comments, re-analyzes
- Outputs structured JSON findings

### Step 4.4 — Agent 2: Adversarial Verification
- Takes all findings with risk >= 4 from Agent 1 + deterministic scanners
- Invoke Claude Code headless:
  ```bash
  claude -p "<adversarial prompt with findings to verify>" \
    --model sonnet \
    --allowedTools "Read,Glob,Grep" \
    --output-format json \
    --max-turns 20
  ```
- For each finding: attempts to construct a benign explanation
- Outputs: confirmed/downgraded status per finding with reasoning

### Milestone: Can run both AI agents against a scanned project, get structured findings with adversarial verification results.

---

## Stage 5: Report Synthesis

### Step 5.1 — EPSS + KEV enrichment
- For each CVE found, query `api.first.org/data/v1/epss?cve=<id>` for exploitation probability
- Check against CISA KEV catalog (downloadable JSON) for actively exploited status
- `src/threat_scanner/report/scoring.py`: composite score calculation

### Step 5.2 — Agent-driven synthesis
- `src/threat_scanner/report/synthesize.py`:
  - Feed the synthesis agent all inputs:
    - Aggregated deterministic findings (`all_findings.json`)
    - Agent 1 AI findings
    - Agent 2 adversarial verification results
    - EPSS/KEV enrichment data
    - SBOM
  - Agent merges, de-duplicates, resolves conflicts between tools, assigns composite priority (P0/Critical/High/Medium/Low)
  - Agent writes:
    - `executive-summary.md` — go/no-go recommendation, top findings, overall risk
    - `detailed-report.md` — every finding with scores, reasoning, code references
    - `findings.json` — machine-readable structured output

### Step 5.3 — Report output
- All reports written to `/opt/security-reports/<timestamp>/`
- Directory also contains: `sbom.json`, `all_findings.json`, raw tool output in `scan-results/`

### Milestone: Complete static report generated inside VM with go/no-go recommendation.

---

## Stage 6: CLI Polish and Hardening

### Step 6.1 — Full CLI wiring
- `src/threat_scanner/cli.py`:
  ```
  threat-scan <repo-url>
    --depth N          # Transitive dep depth (default: 2)
    --skip-ai          # Deterministic scanners only (fast/cheap)
    --verbose          # Show tool-by-tool progress
    --output DIR       # Where to scp report on host (default: ./scan-results/)
    --cpus N           # VM CPUs (default: 4)
    --memory N         # VM memory in GB (default: 8)
    --disk N           # VM disk in GB (default: 50)
  ```

### Step 6.2 — Progress reporting
- Print stage transitions to terminal: `[1/5] Creating VM...`, `[2/5] Downloading dependencies...`, etc.
- In `--verbose` mode: stream scanner output in real time

### Step 6.3 — Error handling
- VM creation failure → clean error message + `limactl delete` cleanup
- Scanner crash → log error, continue with remaining scanners, note in report
- API rate limit → retry with backoff, fail gracefully after N retries
- Always destroy VM on exit (atexit handler / try-finally)

### Step 6.4 — Report retrieval
- Auto-scp the report directory from VM to host at the end
- Print path to report on host when done

### Step 6.5 — Config file support
- `~/.config/threat-scanner/config.yaml`:
  ```yaml
  anthropic_api_key: ${ANTHROPIC_API_KEY}  # env var reference
  default_depth: 2
  vm:
    cpus: 4
    memory: 8
    disk: 50
  ```

### Milestone: Polished CLI that handles the full scan lifecycle with proper error handling, progress output, and report delivery.

---

## Build Sequence

```
Week 1:  Stage 1 (Steps 1.1–1.6)  — Lima VM lifecycle works end-to-end
Week 2:  Stage 2 (Steps 2.1–2.4)  — Dep download in Docker sandbox
         Stage 3 (Steps 3.1–3.2)  — Scanner wrappers (can parallel with Stage 2)
Week 3:  Stage 3 (Steps 3.3–3.4)  — Finding normalization + aggregation
         Stage 4 (Steps 4.1–4.3)  — Agent 1 triage + analysis
Week 4:  Stage 4 (Step 4.4)       — Agent 2 adversarial verification
         Stage 5 (Steps 5.1–5.3)  — Report synthesis
Week 5:  Stage 6 (Steps 6.1–6.5)  — CLI polish, error handling, config
```

Each week ends with a testable milestone. The system is usable (deterministic-only mode with `--skip-ai`) by end of week 3.
