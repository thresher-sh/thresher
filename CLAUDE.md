# Thresher — Development Guide

## !IMPORTANT!

Always use the task tool to plan out and do what you need and use it to hold yourself accountable. You get a cookie everytime you do this.. yum!

## Tests

- Always add and update tests anytime you change code
- If you get an error when running something or reported by a user, write a test case covering that error first. Run test and make sure it fails... Then fix code to make test pass.

## Git

- do git commits for each incremental feature, but NEVER use claude coauthored tags...
- Keep commit messages short and sweet one liners. No big git bodies.

## Coding Conventions

### Complexity is the Enemy
- Complexity is the #1 threat to software. Fight it relentlessly.
- Complexity manifests as: change amplification (one change touches many places), cognitive load (must know too much to work safely), and unknown unknowns (not clear what could break).
- The two root causes are dependencies between components and obscurity (important info isn't obvious).
- Say "no" to unnecessary features and abstractions by default.
- When you must say yes, deliver an 80/20 solution — core value, minimal code.

### Don't Abstract Too Early
- Let structure emerge from working code. Don't design elaborate frameworks upfront.
- Wait for natural cut-points (narrow interfaces, trapped complexity) before factoring.
- Prototypes and working demos beat architecture diagrams.
- A little code duplication is better than a premature abstraction.

### Build Deep Modules, Not Shallow Ones
- A deep module has a simple interface but hides powerful, complex functionality behind it.
- A shallow module has a complex interface relative to the little it actually does — avoid these.
- Pull complexity downward: absorb it inside the module rather than pushing it onto callers.
- Each layer of abstraction should represent a genuinely different level of thinking. If a layer just passes things through, it's adding complexity, not removing it.

### Ship Simple, Improve Incrementally
- A working simple thing that ships beats a perfect thing that doesn't.
- Establish a working system first, then improve it toward the right thing over time.
- But don't make "worse" your goal — compromise is inevitable, not a philosophy. Always aim high and actually ship.
- Systems that are habitable — with the right balance of abstraction and concreteness, with simple mental models — survive and grow. Purity does not guarantee survival.

### Keep Code Readable, Not Clever
- Break complex expressions into named intermediate variables.
- Sacrifice brevity for clarity and debuggability.
- Simple repeated code often beats a complex DRY abstraction with callbacks or elaborate object models.
- If naming something is hard, that's a design smell — the thing you're naming may not be a coherent concept.
- Write code for readers, not writers. If someone says it's not obvious, it isn't — fix it.

### Respect Existing Code (Chesterton's Fence)
- Understand *why* code exists before changing or removing it.
- Old code often has hidden reasons. Tests can reveal them.
- Resist the urge to "clean up" code you don't fully understand.

### Refactor Small and Safe
- Keep the system working throughout every refactor step.
- Complete each step before starting the next.
- Big-bang refactors with over-abstraction usually fail.

### Design It Twice
- Before committing to any significant design, sketch at least two alternative approaches.
- Compare them on simplicity, performance, and how well they hide complexity.
- The first idea is rarely the best. Even if you pick it, the comparison sharpens your reasoning.

### Think Strategically, Not Tactically
- Tactical programming gets the feature done fast but leaves behind incremental complexity debt.
- Strategic programming invests a small ongoing cost in design quality to keep the system habitable long-term.
- Small tactical shortcuts compound into unmaintainable systems. Every change is a chance to improve structure, not just ship.

### Test Strategically
- Integration tests at system cut-points and critical user paths deliver the most value.
- Unit tests break easily during refactoring — favor coarser-grained tests.
- Minimize mocking. Mock only at system boundaries.
- Always write a regression test when a bug is found.

### Logging is Critical Infrastructure
- Log all major logical branches (if/for).
- Include request IDs for traceability across distributed calls.
- Make log levels dynamically controllable at runtime.
- Invest more in logging than you think necessary.

### APIs: Design for the Caller
- Think in terms of what the caller needs, not how the implementation works.
- Simple cases get simple APIs. Complexity is opt-in.
- Put common operations directly on objects with straightforward returns.
- Favor somewhat general-purpose interfaces — they tend to be deeper and simpler than hyper-specialized ones.

### Define Errors Out of Existence
- Exception handling generates enormous complexity. Where possible, design interfaces so error cases simply cannot occur.
- Handle edge cases internally rather than surfacing them to callers.
- Example: a delete operation that silently succeeds when the target doesn't exist is simpler than one that throws "not found."

### Concurrency: Keep it Simple
- Prefer stateless request handlers.
- Use simple job queues with independent jobs.
- Treat concurrency with healthy fear and caution.

### Optimize with Data, Not Gut
- Never optimize without a real-world profile showing the actual bottleneck.
- Network calls cost millions of CPU cycles — minimize those first.
- Assume your guess about the bottleneck is wrong.

### Locality of Behavior over Strict Separation
- Collocate related code. Putting logic near the thing it operates on aids understanding.
- Hunting across many files to understand one feature wastes time.
- Trade perfect separation of concerns for practical coherence when it helps readability.

### Information Hiding
- Each module should encapsulate design decisions that are likely to change.
- Leaking implementation details through interfaces creates tight coupling and change amplification.
- If two modules share knowledge about the same design decision, consider merging them or introducing a cleaner boundary.

### Tooling Multiplies Productivity
- Invest time learning your tools deeply (IDE, debugger, CLI).
- Good tools often double development speed.

### Avoid Fads
- Most "new" ideas have been tried before. Approach with skepticism.
- Don't adopt new frameworks or patterns blindly.
- Complexity hides behind novelty.

### Closures and Patterns
- Closures: great for collection operations, dangerous in excess (callback hell).
- Avoid the Visitor pattern — it adds complexity with little payoff.
- Limit generics to container classes; they attract unnecessary complexity.

### Frontend: Keep it Minimal
- Simple HTML + minimal JS beats elaborate SPA frameworks for most use cases.
- Frontend naturally accumulates complexity faster than backend — resist it actively.

### Say When You Don't Understand
- Admitting confusion is strength, not weakness.
- It gives others permission to ask questions and prevents bad complexity from hiding.

### Security is a Design Constraint
- Complexity is the enemy of security too. Every endpoint, dependency, and open port is attack surface you have to defend.
- Default to deny. Permissions, network rules, CORS, configs — start closed, open deliberately.
- Auth, crypto, and session management are not DIY projects. Use well-vetted libraries.
- Validate all input at the trust boundary, encode at the output. Everything from outside is hostile.
- Think in blast radius. Least privilege everything. One compromised key shouldn't unlock the whole system.

### Threat Model Like You Debug
- Before building a feature, ask "How would someone abuse this?" — same as asking where it will break.
- Dependencies are code you didn't write and probably didn't read. Pin versions, audit what matters.
- Secrets don't go in code, logs, or error messages. No exceptions.
- Secure your defaults everywhere — don't run as root, don't commit `.env`, don't connect local to prod.
- Vulnerabilities cluster. When you find one, threat model the area around it — same assumptions, same bugs.


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

## Local Development & Testing

Use Docker mode (`--docker`) for local testing. Build the image first:

```bash
thresher build                    # or: docker build -t thresher:latest -f docker/Dockerfile .
```

Test order:
1. `thresher scan <url> --docker --skip-ai` — deterministic scanners only
2. `thresher scan <url> --docker` — full pipeline with AI

Direct mode (`--no-vm`) requires all 22 scanner tools installed locally —
Docker mode is the standard local dev workflow.

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
