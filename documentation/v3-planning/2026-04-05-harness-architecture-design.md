# Thresher v0.4.0: CLI/Harness Architecture Redesign

## Overview

Restructure Thresher from "host CLI orchestrating into a Lima VM via SSH" to
"self-contained harness that runs anywhere, launched by a thin CLI." The harness
uses Apache Hamilton to define the scan pipeline as a DAG. A single Docker image
contains everything needed to run a scan. The CLI becomes a launcher that decides
*where* to run the harness (direct, Docker, or Lima+Docker).

### Scope

This design covers:
- CLI/Harness split
- Single Docker image
- Hamilton pipeline DAG
- Three launch modes (direct, Docker, Lima+Docker)
- Shell script elimination (replaced by Python)
- Scanner and agent refactoring (SSH removal)
- Security model changes

Out of scope (future v0.4.x work):
- Remote runners (AWS/GCP/DO/Azure)
- Ephemeral credentials
- Multi-harness support (Codex, pi.dev, OpenCode)
- AI gateways (OpenRouter, LiteLLM)

---

## Architecture

```
                        +--------------------+
                        |   User / CICD      |
                        +---------+----------+
                                  |
                     thresher scan <url> [flags]
                                  |
                        +---------v----------+
                        |       CLI          |
                        |   (host-side)      |
                        |                    |
                        | - parse args       |
                        | - load config      |
                        | - select mode      |
                        | - launch harness   |
                        | - stream logs      |
                        | - collect report   |
                        +---------+----------+
                                  |
               +------------------+------------------+
               |                  |                  |
      +--------v--------+ +------v--------+ +-------v--------+
      |  Direct Mode    | | Docker Mode   | | Lima+Docker    |
      |  (--no-vm)      | | (--docker)    | | (default)      |
      |                 | |               | |                |
      | harness runs    | | docker run    | | lima start     |
      | as subprocess   | | thresher      | | docker run     |
      | on host         | | image         | | inside VM      |
      +--------+--------+ +------+--------+ +-------+--------+
               |                  |                  |
               +------------------+------------------+
                                  |
                        +---------v----------+
                        |      Harness       |
                        |                    |
                        | - Hamilton DAG     |
                        | - clone repo       |
                        | - resolve deps     |
                        | - run scanners     |
                        | - run AI agents    |
                        | - adversarial      |
                        | - synthesize       |
                        | - write report     |
                        |   to /output       |
                        +--------------------+
```

### Key Principles

1. **The harness is mode-agnostic.** It does not know or care whether it is
   running on bare metal, in Docker, or in Lima+Docker. It runs the pipeline
   and writes the report to its output path.

2. **The CLI owns launch mode selection.** It reads config/flags, decides how
   to launch the harness, and handles mode-specific plumbing (Docker volume
   mounts, Lima SSH, etc.).

3. **Config flows one way.** CLI resolves the final config (TOML + env + flags),
   passes it to the harness as a serialized JSON blob. The harness never reads
   CLI flags or thresher.toml directly.

4. **Logs go to stdout/stderr.** The CLI captures them however is appropriate
   for the launch mode (docker logs -f, subprocess pipe, SSH stream).

---

## Hamilton Pipeline (DAG)

The harness pipeline is a single Hamilton DAG. Each stage is a Python function
whose parameter names wire the dependencies automatically. Hamilton
auto-parallelizes independent stages.

```
                    repo_url, config
                         |
                    +----v-----+
                    |  clone   |
                    +----+-----+
                         | cloned_path
              +----------+----------+
              |                     |
     +--------v--------+   +-------v--------+
     |  predep_agent   |   |  detect_eco    |
     |  (if AI on)     |   |  systems       |
     +--------+--------+   +-------+--------+
              | hidden_deps        | ecosystems
              +----------+---------+
                    +----v-----+
                    | resolve  |
                    |  deps    |
                    +----+-----+
                         | deps_path
                    +----v-----+
                    |  sbom    |
                    | (syft)   |
                    +----+-----+
                         | sbom_path
                         |
          (scanners run in parallel, varying deps)
          sbom_path deps:     cloned_path deps:     both:
            grype               semgrep              osv
                                bandit               trivy
                                gitleaks             guarddog-deps
                                entropy
                                install-hooks
                                clamav
                                yara
                                capa
                                checkov
                                hadolint
                                scancode
                                cargo-audit
                                govulncheck
                                deps-dev
                                registry-meta
                                guarddog
                                semgrep-sc
                         |
                         | scan_results (aggregated)
              +----------+----------+
              |                     |
     +--------v--------+           |
     |  analyst_agents |           |
     |  (8 parallel)   |           |
     +--------+--------+           |
              | analyst_findings   |
     +--------v--------+           |
     |  adversarial    |           |
     +--------+--------+           |
              | verified_findings  |
              +----------+---------+
                    +----v-----+
                    | enrich   |
                    |(EPSS/KEV)|
                    +----+-----+
                         | enriched
                    +----v-----+
                    |synthesize|
                    | report   |
                    +----+-----+
                         |
                    /output/
```

### Pipeline Code Structure

```python
# harness/pipeline.py

def cloned_path(repo_url: str, config: dict) -> str:
    """Clone repo using hardened git clone."""
    return safe_clone(repo_url, "/opt/target")

def ecosystems(cloned_path: str) -> list[str]:
    """Detect package ecosystems in the cloned repo."""
    return detect_ecosystems(cloned_path)

def hidden_deps(cloned_path: str, config: dict) -> dict:
    """Pre-dep agent discovers hidden dependencies."""
    if config.get("skip_ai"):
        return {}
    return run_predep_agent(cloned_path, config)

def deps_path(cloned_path: str, ecosystems: list[str],
              hidden_deps: dict, config: dict) -> str:
    """Resolve and download dependencies as source-only."""
    return resolve_deps(cloned_path, ecosystems, hidden_deps, config)

def sbom_path(cloned_path: str) -> str:
    """Generate SBOM with Syft."""
    return run_syft(cloned_path, "/opt/scan-results")

# Scanners declare their actual dependencies via parameter names.
# Hamilton auto-parallelizes scanners that don't depend on each other.

# SBOM-dependent scanners
def grype_results(sbom_path: str, output_dir: str) -> ScanResults:
    ...

# Source-dependent scanners
def semgrep_results(cloned_path: str, output_dir: str) -> ScanResults:
    ...
def bandit_results(cloned_path: str, output_dir: str) -> ScanResults:
    ...

# Source + deps scanners
def osv_results(cloned_path: str, deps_path: str, output_dir: str) -> ScanResults:
    ...
def trivy_results(cloned_path: str, deps_path: str, output_dir: str) -> ScanResults:
    ...

# ... one function per scanner (22 total) ...

def scan_results(grype_results: ScanResults,
                 osv_results: ScanResults, ...) -> list[ScanResults]:
    """Aggregate all scanner results."""
    return [grype_results, osv_results, ...]

def analyst_findings(cloned_path: str, deps_path: str,
                     scan_results: list[ScanResults],
                     config: dict) -> list[dict]:
    """Run 8 analyst agents in parallel. Depends on scan_results
    to ensure scanners complete first (agents read scanner output
    from disk)."""
    ...

def verified_findings(analyst_findings: list[dict],
                      cloned_path: str, config: dict) -> list[dict]:
    """Adversarial agent verifies high-risk findings."""
    ...

def enriched_findings(scan_results: list[ScanResults],
                      verified_findings: list[dict]) -> dict:
    """EPSS/KEV enrichment and priority scoring."""
    ...

def report_path(enriched_findings: dict, scan_results: list[ScanResults],
                config: dict) -> str:
    """Synthesize final report."""
    ...
```

Hamilton auto-parallelizes independent scanners. Scanners declare their actual
dependencies via parameter names — some depend on `sbom_path` (Grype), some on
`cloned_path` (Semgrep, Bandit, etc.), some on both `cloned_path` and `deps_path`
(OSV, Trivy). Hamilton resolves the graph and runs independent scanners
concurrently. The `skip_ai` config flag causes AI stages to short-circuit
(return empty results) — the DAG still runs. There are 22 scanner modules total.

---

## Project Structure

```
src/thresher/
|-- cli.py                    # Host CLI: arg parsing, launch mode, UI
|-- config.py                 # ScanConfig, LimitsConfig (shared)
|-- branding.py               # Terminal UI styling (unchanged)
|
|-- harness/
|   |-- __init__.py
|   |-- __main__.py           # Entrypoint: python -m thresher.harness
|   |-- pipeline.py           # Hamilton DAG definition
|   |-- clone.py              # Hardened git clone (replaces safe_clone.sh)
|   |-- deps.py               # Ecosystem detection + source-only download
|   |                         #   (replaces detect.sh, download_*.sh, run.sh)
|   |-- scanning.py           # Scanner orchestration wrapper
|   +-- report.py             # Report synthesis + enrichment
|
|-- scanners/
|   |-- models.py             # Finding, ScanResults (unchanged)
|   |-- grype.py              # Each scanner: remove SSH, call subprocess
|   |-- osv.py
|   |-- trivy.py
|   |-- semgrep.py
|   |-- ...                   # (all 22 scanner modules)
|   +-- entropy.py
|
|-- agents/
|   |-- analyst.py            # Refactored: no SSH, direct claude invocation
|   |-- analysts.py           # Parallel orchestration (8 agents)
|   |-- adversarial.py        # Refactored: no SSH, direct invocation
|   |-- predep.py             # Refactored: no SSH, direct invocation
|   |-- prompts.py            # System prompts (unchanged)
|   +-- definitions/          # YAML persona definitions (unchanged)
|       |-- 01-paranoid.yaml
|       +-- ...
|
|-- report/
|   |-- synthesize.py         # Template rendering (unchanged logic)
|   +-- scoring.py            # EPSS/KEV enrichment (unchanged logic)
|
|-- launcher/
|   |-- __init__.py
|   |-- direct.py             # --no-vm: run harness as subprocess
|   |-- docker.py             # --docker: docker run with volume mounts
|   +-- lima.py               # default: lima VM + docker inside it
|
+-- vm/
    |-- lima.py               # Simplified: create/start/stop VM,
    |                         #   pull docker image, run container
    +-- firewall.py           # iptables rules (Lima mode only)

docker/
|-- Dockerfile                # Single image: CLI + harness + all tools
+-- entrypoint.sh             # Minimal: detect mode, exec harness or CLI

rules/semgrep/                # Custom rules (unchanged, copied into image)

vm_scripts/                   # Drastically reduced:
|-- firewall.sh               #   iptables setup (Lima only)
+-- lockdown.sh               #   sudo restriction (Lima only)

tests/
|-- unit/
|   |-- test_pipeline.py      # Hamilton DAG wiring tests
|   |-- test_clone.py         # safe_clone Python tests
|   |-- test_deps.py          # dependency resolution tests
|   |-- test_scanners/        # scanner module tests (updated)
|   +-- test_agents/          # agent tests (updated, no SSH mocks)
|-- integration/
|   +-- test_harness.py       # End-to-end harness tests
+-- e2e/                      # Full scan tests (needs tools installed)
```

---

## Dockerfile

Single image serving all modes. Layers ordered for cache efficiency.

```dockerfile
FROM ubuntu:24.04

# -- System deps --
RUN apt-get update && apt-get install -y \
    git curl wget jq ca-certificates \
    python3 python3-pip python3-venv \
    && rm -rf /var/lib/apt/lists/*

# -- Language runtimes (for dependency resolution) --
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
    sh -s -- -y --default-toolchain stable
ARG TARGETARCH
RUN wget https://go.dev/dl/go1.22.linux-${TARGETARCH}.tar.gz \
    && tar -C /usr/local -xzf go*.tar.gz && rm go*.tar.gz

# -- Security scanners --
RUN pip install semgrep bandit checkov guarddog
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh
# ... trivy, osv-scanner, gitleaks, clamav, yara, capa,
#     hadolint, scancode, cargo-audit, govulncheck, etc.

# -- Claude Code (for AI agents) --
RUN npm install -g @anthropic-ai/claude-code

# -- Non-root user --
RUN useradd -m -s /bin/bash thresher
RUN mkdir -p /output /opt/scan-results /opt/target /opt/deps \
    && chown -R thresher:thresher /output /opt/scan-results /opt/target /opt/deps

# -- Custom rules --
COPY rules/ /opt/rules/

# -- Thresher (changes most often, last layer) --
COPY src/ /opt/thresher/src/
COPY pyproject.toml /opt/thresher/
RUN pip install /opt/thresher/

# -- Report output mount point --
VOLUME /output

USER thresher
ENTRYPOINT ["python", "-m", "thresher.harness"]
```

**Scanner databases and writable directories:** The `--read-only` container flag
means scanner databases must be pre-populated at image build time. The Dockerfile
must run `grype db update`, `trivy --download-db-only`, `freshclam`, etc. during
build. At runtime, scanners that need writable cache dirs get tmpfs mounts:

```
--tmpfs /tmp:rw,noexec,nosuid,size=1g \
--tmpfs /home/thresher/.cache:rw,size=512m \
```

With `--read-only`, the entire overlay filesystem is immutable. All writable
directories must be explicit tmpfs mounts at runtime:

```
--tmpfs /opt/target:rw,size=2g \
--tmpfs /opt/scan-results:rw,size=1g \
--tmpfs /opt/deps:rw,size=2g \
```

- **Base: Ubuntu 24.04** — matches current VM, wide scanner compatibility.
- **Default entrypoint is the harness.** Override for CLI mode.
- **Thresher code is the last layer** for fast rebuilds during development.
- **No Docker-in-Docker** — no Docker daemon inside the container.
- **Multi-arch:** linux/amd64 + linux/arm64 via `docker buildx build --platform linux/amd64,linux/arm64`. The `ARG TARGETARCH` in the Dockerfile handles arch-specific downloads.
- **Expected size:** ~2-3GB (all scanners pre-installed, pulled once and cached).

---

## Launch Modes

### Direct Mode (`--no-vm`)

Dev mode. Assumes all tools installed locally.

```
thresher scan <url> --no-vm

CLI:
  1. Resolve config (toml + env + flags)
  2. Write config to temp file
  3. subprocess.run(["python", "-m", "thresher.harness",
       "--config", config_path, "--repo", url, "--output", output_dir])
  4. Stream stdout/stderr to terminal (or tmux panes)
  5. Report lands directly in output_dir
```

### Docker Mode (`--docker`)

Container isolation, no VM. Good for Linux, CI.

```
thresher scan <url> --docker

CLI:
  1. Resolve config
  2. docker run \
       -v <output_dir>:/output \
       -v <config_path>:/config/config.json:ro \
       -e ANTHROPIC_API_KEY \
       -e CLAUDE_CODE_OAUTH_TOKEN \
       --rm --read-only \
       --tmpfs /tmp:rw,noexec,nosuid,size=1g \
       --tmpfs /home/thresher/.cache:rw,size=512m \
       --tmpfs /opt/target:rw,size=2g \
       --tmpfs /opt/scan-results:rw,size=1g \
       --tmpfs /opt/deps:rw,size=2g \
       --cap-drop=ALL \
       --security-opt=no-new-privileges \
       --user thresher \
       thresher:latest \
       --config /config/config.json --repo <url>
  3. Stream logs via docker logs -f
  4. Report lands in output_dir via volume mount
```

### Lima+Docker Mode (default on macOS)

Full isolation with egress firewall.

```
thresher scan <url>

CLI:
  1. Resolve config
  2. Ensure Lima VM exists and is running
     - If no base VM: create from template, start
     - Lima template is minimal: Ubuntu + Docker only
     - Pull/load thresher Docker image into VM
  3. Apply iptables egress firewall
  4. lima docker run \
       -v /opt/reports:/output \
       -v /opt/config.json:/config/config.json:ro \
       -e ANTHROPIC_API_KEY \
       -e CLAUDE_CODE_OAUTH_TOKEN \
       --rm --read-only \
       --tmpfs /tmp:rw,noexec,nosuid,size=1g \
       --tmpfs /home/thresher/.cache:rw,size=512m \
       --tmpfs /opt/target:rw,size=2g \
       --tmpfs /opt/scan-results:rw,size=1g \
       --tmpfs /opt/deps:rw,size=2g \
       --cap-drop=ALL \
       --security-opt=no-new-privileges \
       --user thresher \
       thresher:latest \
       --config /config/config.json --repo <url>
  5. Stream logs via lima docker logs -f
  6. Copy /opt/reports from VM to host output_dir
```

### Lima Provisioning (vastly simplified)

Old provision.sh (~500 lines):
- Install git, Python, Node, Rust, Go
- Install 22 scanners, Claude Code
- Build scanner-deps image
- Copy safe_clone.sh, firewall, lockdown scripts
- Set up iptables, lockdown sudo

New (~50 lines):
- Install Docker
- Pull thresher Docker image
- Set up iptables
- Lockdown sudo

---

## Scanner Module Refactoring

Mechanical change — replace SSH calls with direct subprocess calls.

**Before:**
```python
def run_grype(vm_name: str, target_dir: str, output_dir: str) -> ScanResults:
    cmd = f"grype sbom:{output_dir}/sbom.json -o json > {output_dir}/grype.json"
    result = ssh_exec(vm_name, cmd)
    return ScanResults(scanner="grype", exit_code=result.exit_code, ...)
```

**After:**
```python
def run_grype(target_dir: str, output_dir: str) -> ScanResults:
    result = subprocess.run(
        ["grype", f"sbom:{output_dir}/sbom.json", "-o", "json"],
        capture_output=True, timeout=300
    )
    Path(f"{output_dir}/grype.json").write_bytes(result.stdout)
    return ScanResults(scanner="grype", exit_code=result.returncode, ...)
```

Per-scanner changes:
- Remove `vm_name` parameter
- Replace `ssh_exec()` with `subprocess.run()`
- Remove SSH semaphore acquisition
- Write output files directly

Unchanged:
- `parse_<tool>_output()` functions
- `ScanResults` / `Finding` dataclasses
- Error handling patterns
- Tool commands themselves

---

## Agent Refactoring

Same pattern — remove SSH, call Claude Code directly.

**Before:**
```python
def run_analyst(vm_name: str, config: ScanConfig, persona: dict) -> None:
    prompt = build_prompt(persona)
    ssh_write_file(vm_name, "/tmp/analyst_prompt.txt", prompt)
    ssh_exec(vm_name,
        "echo $API_KEY > /dev/shm/.key && "
        "claude -p /tmp/analyst_prompt.txt --model ...")
    return None  # nothing leaves VM
```

**After:**
```python
def run_analyst(config: ScanConfig, persona: dict,
                target_dir: str, output_dir: str) -> dict:
    prompt = build_prompt(persona)
    prompt_path = Path(f"/tmp/analyst_{persona['name']}_prompt.txt")
    prompt_path.write_text(prompt)

    env = os.environ.copy()
    # API key already in env (ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN)

    subprocess.run([
        "claude", "-p", str(prompt_path),
        "--model", config.model,
        "--allowedTools", "Read,Glob,Grep",
        "--output-dir", output_dir
    ], env=env, timeout=config.agent_timeout)

    findings_path = Path(output_dir) / f"analyst-{persona['number']}-findings.json"
    return json.loads(findings_path.read_text())
```

Key changes:
- **Agents now return data** — no VM boundary, harness is the trust boundary.
  Hamilton wires return values to downstream stages.
- **No tmpfs ceremony** — API key from environment, ephemeral to the container.
- **Stop hooks for output validation** — still work, unchanged.
- **Agent definitions and prompts** — unchanged YAML and prompt files.

---

## Config and Entrypoints

### Config Flow

```
thresher.toml + ENV + CLI flags
         |
    CLI resolves final ScanConfig
         |
    Serialized to JSON
         |
    +-------------------------------------------+
    | Direct: passed as --config <file>          |
    | Docker: mounted as -v config.json:/config  |
    | Lima:   mounted as -v config.json:/config  |
    +-------------------------------------------+
         |
    Harness deserializes to ScanConfig
    (harness never reads thresher.toml directly)
```

### ScanConfig Changes

```python
@dataclass
class ScanConfig:
    repo_url: str
    model: str = "sonnet"
    depth: int = 2
    output_dir: str = "/output"
    skip_ai: bool = False
    high_risk_dep: bool = False
    tmux: bool = False
    verbose: bool = False

    # New
    launch_mode: str = "lima"  # lima | docker | direct

    # Existing
    vm: VMConfig = ...
    limits: LimitsConfig = ...
    analysts: AnalystConfig = ...
    adversarial: AdversarialConfig = ...
```

### Entrypoints

```toml
# pyproject.toml [project.scripts]
thresher = "thresher.cli:main"              # Host CLI
thresher-harness = "thresher.harness:main"  # Harness entrypoint (new)

# Legacy
thresher-build = "thresher.cli:build_entry"
thresher-stop = "thresher.cli:stop_entry"
```

### CLI Commands

```
thresher scan <url>              # Default: Lima+Docker
thresher scan <url> --docker     # Docker only, no VM
thresher scan <url> --no-vm      # Direct, dev mode
thresher build                   # Build Docker image (replaces VM build)
thresher stop                    # Stop Lima VM (if running)
thresher list                    # List available Docker images from releases
thresher import <source>         # Pull/load Docker image
thresher export                  # Export Docker image for distribution
```

`thresher build` changes meaning: builds the Docker image locally instead of
provisioning a Lima VM.

---

## Credential Handling

The harness supports two authentication methods:

1. **ANTHROPIC_API_KEY** — passed as environment variable to the container.
2. **CLAUDE_CODE_OAUTH_TOKEN** — OAuth token, also passed as environment variable.

The harness checks for both and uses whichever is available. The CLI passes
them through via `docker run -e` or subprocess environment.

No tmpfs pattern, no disk writes. The key lives in process memory within an
ephemeral container (`--rm`).

---

## Files Deleted

| File | Replaced By |
|------|-------------|
| `src/thresher/vm/ssh.py` | Direct subprocess calls |
| `src/thresher/vm/safe_io.py` | `harness/report.py` validation |
| `src/thresher/docker/sandbox.py` | `harness/deps.py` |
| `vm_scripts/provision.sh` | `docker/Dockerfile` |
| `vm_scripts/safe_clone.sh` | `harness/clone.py` |
| `vm_scripts/download_deps.sh` | `harness/deps.py` |
| `vm_scripts/run_scanners.sh` | `harness/scanning.py` |
| `vm_scripts/validate_*_output.sh` | Stop hooks |
| `docker/scripts/run.sh` | `harness/deps.py` |
| `docker/scripts/detect.sh` | `harness/deps.py` |
| `docker/scripts/download_*.sh` | `harness/deps.py` |
| `docker/scripts/manifest.sh` | `harness/deps.py` |
| `docker/scripts/build_manifest.py` | `harness/deps.py` |
| `docker/Dockerfile.scanner-deps` | `docker/Dockerfile` |

## Files Simplified

| File | Change |
|------|--------|
| `src/thresher/vm/lima.py` | ~400 lines to ~100. Start/stop VM, pull image, run container |
| `src/thresher/vm/firewall.py` | Unchanged but only used in Lima mode |
| `src/thresher/cli.py` | Loses orchestration logic, becomes launch mode dispatcher |

---

## Security Model

### Isolation Tiers by Launch Mode

```
Most isolated:  Lima+Docker  (iptables + container sandbox)
Middle:         Docker only   (container sandbox, no egress fw)
Least isolated: Direct/no-vm  (process isolation only)
```

### Lima+Docker (4 layers)

1. Lima VM isolation (Apple Virtualization.framework)
2. Egress firewall (iptables domain whitelist)
3. Container sandbox (read-only, cap-drop=ALL, no-new-privileges)
4. Source-only deps + hardened clone

### Docker Only (3 layers)

1. Container sandbox (read-only, cap-drop=ALL, no-new-privileges)
2. Source-only deps + hardened clone
3. Ephemeral container (--rm)

Docker mode has **no egress firewall**. The container has unrestricted network
access. This is acceptable because: (a) the container needs network for git
clone, dependency downloads, scanner DB updates, and API calls; (b) source-only
downloads prevent install script execution regardless of network policy; (c)
Docker mode targets Linux servers and CI environments that are already ephemeral;
(d) users who need egress restriction should use Lima+Docker mode.

### Direct Mode (1 layer)

1. Source-only deps + hardened clone
2. (Dev mode -- user accepts the risk)

### Removed Layers and Justification

| Removed | Justification |
|---------|---------------|
| Nested Docker sandbox | Dep download is a pipeline stage with same source-only protections. No install scripts run. |
| `safe_io.py` boundary | No VM-to-host copy. Report is volume-mounted. Container is the boundary. |
| SSH semaphore | No SSH. Direct subprocess calls. |
| tmpfs API key | Env var in ephemeral container. Key in process memory, never on disk. |
| `lockdown.sh` sudo | Docker: no sudo, runs as non-root. Lima: lockdown still applies to VM. |

### Preserved Protections

- Hardened git clone (all 4 phases, now in Python)
- Source-only dependency downloads (no install scripts)
- Agent tool restrictions (Read, Glob, Grep only)
- Stop hook output validation
- Report file type/size validation (moves into `harness/report.py`):
  - JSON size cap (configurable via `limits.max_json_size_mb`)
  - File type whitelist (`.json`, `.md`, `.txt`, `.csv`, `.log`, `.sarif`, `.html`)
  - Per-file size cap (`limits.max_file_size_mb`)
  - Total report size cap (`limits.max_copy_size_mb`)
  - Symlink detection and rejection
  - Path traversal detection
- Agent output validation:
  - Stop hooks validate JSON schema before agent completion (unchanged)
  - `harness/report.py` applies `max_json_size_mb` cap when reading agent findings
  - Malformed JSON from agents is logged and treated as empty findings (scan continues)
- Egress firewall in Lima mode

### Container Hardening (Docker and Lima+Docker modes)

```
docker run \
  --rm \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=1g \
  --tmpfs /home/thresher/.cache:rw,size=512m \
  --tmpfs /opt/target:rw,size=2g \
  --tmpfs /opt/scan-results:rw,size=1g \
  --tmpfs /opt/deps:rw,size=2g \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --user thresher \
  -v <output>:/output \
  -v <config>:/config/config.json:ro \
  -e ANTHROPIC_API_KEY \
  -e CLAUDE_CODE_OAUTH_TOKEN \
  thresher:latest
```

---

## Test Strategy

| Test Area | Approach |
|-----------|----------|
| Hamilton DAG wiring | `test_pipeline.py` — verify stage dependencies, skip_ai short-circuits |
| Hardened clone | `test_clone.py` — all 4 phases, symlink removal, path traversal detection |
| Dependency resolution | `test_deps.py` — ecosystem detection, source-only download commands |
| Scanner modules | `test_scanner_*.py` — mock subprocess instead of ssh_exec |
| Agent modules | `test_agents/*.py` — mock subprocess, assert return values (not None) |
| Harness integration | `test_harness.py` — full pipeline with mocked tools |
| Launch modes | `test_launcher_*.py` — verify correct docker/subprocess commands |
| Lima simplified | `test_lima.py` — simplified to match new lima.py |

Deleted tests: `test_ssh.py`, `test_safe_io.py`, `test_sandbox.py`

---

## Migration Notes

- Scanner modules are mechanical refactors (SSH to subprocess) -- high volume,
  low risk per file, good for parallel implementation.
- Agent refactoring is similar but also changes return types (None to dict).
- The Hamilton DAG is new code, not a refactor.
- The launcher package is new code.
- The harness entrypoint and `__main__.py` are new code.
- `harness/clone.py` is a port of `safe_clone.sh` to Python.
- `harness/deps.py` is a port of `docker/scripts/*.sh` to Python. Internally
  organized as:
  - `detect_ecosystems(path)` — scan for manifest files (replaces `detect.sh`)
  - `download_python(path, deps_dir)` — `pip download --no-binary :all:` (replaces `download_python.sh`)
  - `download_node(path, deps_dir)` — `npm pack` (replaces `download_node.sh`)
  - `download_rust(path, deps_dir)` — `cargo vendor` (replaces `download_rust.sh`)
  - `download_go(path, deps_dir)` — `go mod vendor` (replaces `download_go.sh`)
  - `download_hidden(hidden_deps, deps_dir)` — process predep findings (replaces `download_hidden.sh`)
  - `build_manifest(deps_dir)` — generate dep_manifest.json (replaces `manifest.sh` + `build_manifest.py`)
  - `resolve_deps(path, ecosystems, hidden_deps, config)` — top-level orchestrator that calls the above
- Existing test fixtures (scanner output samples) remain valid.
