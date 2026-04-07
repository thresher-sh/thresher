# Thresher — Development Guide

## !IMPORTANT!

Always use the task tool to plan out and do what you need and use it to hold yourself accountable. You get a cookie everytime you do this.. yum!

## What This Is

Supply chain security scanner. Scans open source repos for vulnerabilities,
malicious code, and supply chain attacks using 22 deterministic scanners +
8 AI analyst agents. Three launch modes: Lima+Docker (max isolation),
Docker (container sandbox), or direct (dev mode).

## Project Structure

```
src/thresher/
  cli.py              Thin CLI launcher — arg parsing, launch mode dispatch
  config.py           ScanConfig, VMConfig, LimitsConfig, load_config()
  branding.py         Terminal UI styling

  harness/            Self-contained scan pipeline (mode-agnostic)
    __init__.py
    __main__.py       Entrypoint: python -m thresher.harness --config ...
    pipeline.py       Hamilton DAG definition (all pipeline stages)
    clone.py          4-phase hardened git clone (Python port of safe_clone.sh)
    deps.py           Ecosystem detection + source-only dependency download
    scanning.py       Scanner orchestration (ThreadPoolExecutor, 22 scanners)
    report.py         Report validation, enrichment, generation

  launcher/           Launch mode implementations
    direct.py         --no-vm: subprocess on host (dev mode)
    docker.py         --docker: container with security hardening
    lima.py           default: Lima VM + Docker inside it

  agents/
    predep.py         Stage 1: pre-dep hidden dependency discovery
    analyst.py        Single analyst agent runner
    analysts.py       Parallel 8-agent orchestration
    adversarial.py    Adversarial verification of analyst findings
    prompts.py        System prompts for agents
    definitions/      YAML persona definitions (8 analysts)

  scanners/
    runner.py         Legacy orchestration (replaced by harness/scanning.py)
    models.py         Finding, ScanResults dataclasses
    (22 scanner modules — grype, osv, trivy, semgrep, etc.)

  report/
    synthesize.py     Report generation (agent or template)
    scoring.py        EPSS/KEV enrichment

  vm/
    lima.py           Lima VM lifecycle (create/start/stop — simplified)
    firewall.py       iptables rules (Lima mode only)

docker/
  Dockerfile          Single image: harness + all scanner tools
rules/semgrep/        Custom Semgrep supply-chain rules
lima/thresher.yaml    Lima VM template
```

## Architecture: CLI → Launcher → Harness

The CLI is a thin launcher. It resolves config, picks a launch mode,
and delegates to the harness. The harness is mode-agnostic — it runs
the same Hamilton DAG pipeline regardless of where it's running.

```
CLI (host) → Launcher (direct/docker/lima) → Harness (pipeline)
```

Config flows one way: CLI serializes ScanConfig to JSON, harness
deserializes it. The harness never reads thresher.toml directly.

## Security Model

**Three isolation tiers (most → least):**

1. **Lima+Docker** (default) — VM + iptables firewall + container sandbox
2. **Docker** (`--docker`) — container sandbox (`--read-only`, `--cap-drop=ALL`)
3. **Direct** (`--no-vm`) — process isolation only (dev mode)

**Protections in all modes:**
- 4-phase hardened git clone (hooks disabled, config sanitized, symlinks removed)
- Source-only dependency downloads (no install scripts)
- Report validation (extension whitelist, size limits, symlink rejection)
- Credentials via environment variables only (never written to disk)

**Container hardening (Docker and Lima modes):**
- `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`
- tmpfs mounts for writable directories
- Non-root `thresher` user

## Scanner Modules Pattern

Every scanner module uses direct subprocess calls:

```python
def run_<tool>(target_dir, output_dir) -> ScanResults:
    # 1. subprocess.run(["<tool>", ...], capture_output=True, timeout=300)
    # 2. Write stdout to output_dir/<tool>.json
    # 3. Return ScanResults with metadata
```

The `parse_<tool>_output()` functions exist for report synthesis —
they are NOT called during the scan pipeline.

## Agent Pattern

Agents run Claude Code headless via subprocess:

```python
def run_<agent>(config, target_dir, output_dir) -> dict:
    # 1. Write prompt to /tmp/<agent>_prompt.txt
    # 2. subprocess.run(["claude", "-p", ...])
    # 3. Parse JSON output
    # 4. Return findings dict (agents return data directly)
```

API key comes from environment (ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN).

## Configurable Limits

All size limits live in `thresher.toml` under `[limits]`:

```toml
[limits]
max_json_size_mb = 10    # JSON parse cap
max_file_size_mb = 50    # per-file in report
max_copy_size_mb = 500   # total report size
max_stdout_mb = 50       # subprocess stdout cap
```

## CLI Commands

```
thresher scan <repo_url>            # Scan (default: Lima+Docker)
thresher scan <url> --docker        # Scan in Docker (no VM)
thresher scan <url> --no-vm         # Scan directly on host (dev)
thresher build                      # Build the Docker image
thresher stop                       # Stop all VMs and tmux session
thresher list                       # List available images from releases
thresher import <source>            # Import image (latest, version, URL, file)
thresher export                     # Export image for distribution
thresher                            # Show help
```

Key flags (on `scan`): `--skip-ai`, `--high-risk-dep`, `--docker`,
`--no-vm`, `--tmux`, `--verbose`, `--branch`, `--depth`, `--output`

## Testing

```bash
python -m pytest tests/unit/ tests/integration/ -v   # Full suite
python -m pytest tests/unit/test_<module>.py -v       # Single module
python -m pytest -m e2e                                # E2E (needs Docker)
```

**Run tests after every change.** The full unit+integration suite takes <2s.

Test conventions:
- Scanner tests verify parse functions with fixture data
- Scanner run tests mock subprocess.run
- Agent tests mock subprocess.run, verify data returns (not None)
- Harness tests mock _build_driver for Hamilton DAG
- Launcher tests verify correct subprocess/docker commands
- Report tests verify validation (symlinks, extensions, size limits)

## Pipeline Flow (Hamilton DAG)

```
1. Load config (CLI serializes ScanConfig to JSON)
2. Launch harness (direct subprocess / Docker / Lima+Docker)
3. Clone repo (4-phase hardened clone in Python)
4. Pre-dep discovery agent (if AI enabled) → hidden_deps dict
5. Detect ecosystems + download dependencies (source-only)
6. Generate SBOM (Syft)
7. Run 22 scanners in parallel (ThreadPoolExecutor)
8. 8 AI analyst agents in parallel (if AI enabled)
9. Adversarial verification of high-risk findings
10. EPSS/KEV enrichment
11. Report synthesis → /output directory
```

## Common Gotchas

- **Hamilton DAG**: pipeline.py functions use parameter names for dependency
  wiring. Renaming a parameter changes the DAG graph.
- **Lazy imports in pipeline.py**: All node functions use lazy imports to
  avoid circular imports and allow the DAG to build even if downstream
  modules aren't installed.
- **Container paths**: `/opt/scan-results`, `/opt/target`, `/opt/deps` are
  inside the container — these are fine.
- **Host-side output**: `./thresher-reports` is the default host directory.
- **Stop hooks**: The predep agent uses a Claude Code stop hook to validate
  JSON output schema. Check `stop_hook_active` to prevent infinite loops.
- **High-risk deps**: Hidden dependencies classified as `risk: "high"` are
  NOT downloaded by default. Use `--high-risk-dep` to opt in. Skipped
  entries are written to `skipped_high_risk.json` for the report.
- **Config serialization**: ScanConfig.to_json() excludes credentials
  (anthropic_api_key, oauth_token). Credentials flow via env vars.

## Adding a New Scanner

1. Create `src/thresher/scanners/<tool>.py` with `run_<tool>()` and
   `parse_<tool>_output()`
2. `run_<tool>()` calls subprocess.run, returns ScanResults
3. Add to `harness/scanning.py` `_get_scanner_tasks()` list
4. Add to `_resolve_scanner_kwargs()` if it needs special parameters
5. Add tests in `tests/unit/test_<tool>.py`
6. Update `tests/integration/test_scanner_pipeline.py` mock count

## Adding a New Agent

1. Create `src/thresher/agents/<name>.py`
2. Use subprocess to call claude with API key from environment
3. Return findings dict (agents return data directly)
4. If structured output needed, add a stop hook for schema validation
5. Wire into `harness/pipeline.py` at the correct DAG stage

## Git Conventions

- `documentation/v3-planning/`: reference specs for current architecture
- `documentation/archived-planning-docs/`: old specs, do not modify
- `docs/`: GitHub Pages site (index.html, branding.html) — not dev docs
- Config files: `thresher.toml` (active), `thresher.toml.example` (template)

## Testing

- Always add and update tests anytime you change code
