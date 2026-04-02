# Thresher — Development Guide

## !IMPORTANT!

Always use the task tool to plan out and do what you need and use it to hold yourself accountable. You get a cookie everytime you do this.. yum!

## What This Is

Supply chain security scanner. Scans open source repos for vulnerabilities,
malicious code, and supply chain attacks using 20 deterministic scanners +
AI analyst agents inside an isolated Lima VM.

## Project Structure

```
src/thresher/
  cli.py              Main entry point, scan orchestration
  config.py           ScanConfig, VMConfig, LimitsConfig, load_config()
  agents/
    predep.py         Stage 1: pre-dep hidden dependency discovery
    analyst.py        Stage 2: independent AI security researcher
    adversarial.py    Stage 2: adversarial verification of analyst findings
    prompts.py        System prompts for agents
  scanners/
    runner.py         Orchestrates all 20 scanners in parallel
    models.py         Finding, ScanResults dataclasses
    entropy.py        Obfuscation/encoded payload detection (runs in VM)
    install_hooks.py  Install script detection (runs in VM)
    semgrep_supply_chain.py  Custom supply-chain rules on deps
    guarddog_deps.py  GuardDog on dependency source code
    (14 more scanner modules)
  docker/
    sandbox.py        Thin wrapper — invokes scanner-docker in VM
  vm/
    lima.py           VM lifecycle, provisioning
    ssh.py            ssh_exec, ssh_copy_to, ssh_copy_from
    safe_io.py        Boundary hardening: safe_json_loads, validate_copied_tree
  report/
    synthesize.py     Report generation (agent or template)
    scoring.py        EPSS/KEV enrichment
docker/                Container build context for scanner-deps image
  Dockerfile.scanner-deps
  scripts/             run.sh, detect.sh, download_*.sh, manifest.sh
rules/semgrep/         Custom Semgrep supply-chain rules
vm_scripts/            Scripts copied into the VM during provisioning
lima/thresher.yaml     Lima VM template
```

## The #1 Rule: VM Trust Boundary

**Nothing leaves the VM except log lines and the final report copy.**

- Scanner results stay in `/opt/scan-results/` inside the VM
- AI findings stay in `/opt/scan-results/` inside the VM
- Dependency manifests stay in the VM
- The ONLY data that crosses VM→host is:
  1. Log lines via ssh_exec stdout streaming (for tmux UI)
  2. The final report directory via `ssh_copy_from_safe()` at scan end
- Never `cat` a file from the VM to parse it on the host
- Never pass structured findings data as function return values to the host
- If you need data to flow between pipeline stages, write it to a file
  in the VM and have the next stage read it there

**When adding new features, ask: "Does this data need to leave the VM?" The answer is almost always no.**

## Security Hardening Layers

These are implemented and must not be weakened:

1. **Network hardening** — zero sudo for scan user, scanner-docker wrapper,
   hostResolver DNS control, iptables DNS pinning
2. **Source download** — safe_clone.sh with 4-phase defense (no-checkout,
   config lockdown, filtered checkout, post-validation)
3. **Host boundary** — safe_json_loads (size-bounded), ssh_copy_from_safe
   (staging + validation), stdout cap, API key tmpfs pattern
4. **Dependency container** — single image, single invocation, no arguments,
   --network=none, --read-only, --cap-drop=ALL

## Scanner Modules Pattern

Every scanner module follows the same pattern:

```python
def run_<tool>(vm_name, target_dir, output_dir) -> ScanResults:
    # 1. Run the tool inside the VM (writes to output_dir/<tool>.json)
    # 2. Check exit code
    # 3. Return ScanResults with metadata ONLY (no findings)
    # NEVER cat the output file back to the host
```

The `parse_<tool>_output()` functions exist for in-VM use by the report
synthesis agent — they are NOT called during the scan pipeline.

## Agent Pattern

Agents run as Claude Code headless inside the VM:

```python
def run_<agent>(vm_name, config) -> None:
    # 1. Write prompt to /tmp/<agent>_prompt.txt via ssh_write_file
    # 2. Write API key to /dev/shm/.api_key (tmpfs, read-and-delete)
    # 3. Invoke claude -p ... via ssh_exec
    # 4. Write findings to /opt/scan-results/<agent>-findings.json in VM
    # 5. Return None — no data returned to host
```

## Configurable Limits

All size limits live in `thresher.toml` under `[limits]`:

```toml
[limits]
max_json_size_mb = 10    # safe_json_loads cap
max_file_size_mb = 50    # per-file in report copy
max_copy_size_mb = 500   # total report copy
max_stdout_mb = 50       # ssh_exec stdout before kill
```

These are read via `config.active_limits` (module-level singleton).
When adding new limits, add to `LimitsConfig` in config.py and load
from the `[limits]` table.

## CLI Commands

```
thresher scan <repo_url>  # Scan a repository
thresher build            # Build/rebuild the base VM image
thresher stop             # Stop all VMs and tmux session
thresher                  # Show help with available commands
```

Key flags (on `scan`): `--skip-ai`, `--high-risk-dep`, `--tmux`, `--verbose`

Legacy entry points `thresher-build` and `thresher-stop` still work.

## Testing

```bash
python -m pytest tests/unit/ tests/integration/ -v   # Full suite
python -m pytest tests/unit/test_<module>.py -v       # Single module
python -m pytest -m e2e                                # E2E (needs Lima)
```

**Run tests after every change.** The full unit+integration suite takes <1s.

Test conventions:
- Scanner tests verify parse functions with fixture data
- Agent tests mock ssh_exec and verify:
  - Correct files written to VM
  - API key uses tmpfs pattern
  - Return value is None (no data leaves VM)
- Lima tests verify provisioning copies all hardening scripts
- safe_io tests verify boundary validation (symlinks, size limits, etc.)

## Pipeline Flow

```
1. Load config (thresher.toml + CLI + env)
2. Start/create VM
3. Provision VM (tools + firewall + lockdown)
4. Clone repo (safe_clone.sh)
5. Pre-dep discovery agent (if AI enabled) → hidden_deps.json in VM
6. Dependency resolution (scanner-docker container)
7. Run 20 scanners in parallel (results stay in VM)
8. AI analyst agent → analyst-findings.json in VM
9. Adversarial agent → adversarial-findings.json in VM
10. Report synthesis → report files in VM
11. Copy report to host (ssh_copy_from_safe with validation)
12. Stop/destroy VM
```

## Common Gotchas

- **Circular imports**: safe_io.py and ssh.py use `_limits()` with lazy
  import to avoid circular dependency with config.py
- **scanner-docker stays named scanner-docker**: it's an internal VM
  detail, not user-facing, so it wasn't renamed during the name change
- **VM-internal paths**: `/opt/scan-results`, `/opt/target`, `/opt/deps`,
  `/home/scanner/work` are all inside the VM — these are fine
- **Host-side output**: `./thresher-reports` is the host directory
- **Stop hooks**: The predep agent uses a Claude Code stop hook to validate
  JSON output schema before allowing the agent to finish. Check
  `stop_hook_active` to prevent infinite loops.
- **High-risk deps**: Hidden dependencies classified as `risk: "high"` are
  NOT downloaded by default. Use `--high-risk-dep` to opt in. Skipped
  entries are written to `skipped_high_risk.json` for the report.

## Adding a New Scanner

1. Create `src/thresher/scanners/<tool>.py` with `run_<tool>()` and
   `parse_<tool>_output()`
2. `run_<tool>()` executes the tool in the VM, returns ScanResults
   (metadata only, no findings)
3. Add to `runner.py` parallel_tasks list
4. Add tests in `tests/unit/test_<tool>.py`
5. Update `tests/integration/test_scanner_pipeline.py` mock count

## Adding a New Agent

1. Create `src/thresher/agents/<name>.py`
2. Use tmpfs API key pattern (write to /dev/shm, read-and-delete)
3. Write output to `/opt/scan-results/<name>-findings.json` in VM
4. Return None — no data to host
5. If structured output needed, add a stop hook for schema validation
6. Wire into `cli.py` at the correct pipeline stage

## Git Conventions

- `scanner-docker` wrapper: do not rename (internal VM detail)
- `documentation/v2-planning/`: reference specs, do not modify during implementation
- `docs/`: GitHub Pages site (index.html, branding.html) — not dev docs
- Config files: `thresher.toml` (active), `thresher.toml.example` (template)

## Testing

- Always add and update tests anytime you change code
