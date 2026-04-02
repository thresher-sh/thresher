# Thresher

AI-powered supply chain security scanner. Scans open source repositories and their dependencies for known vulnerabilities, malicious code, secrets, obfuscation, and supply chain risks inside an isolated VM. Produces a go/no-go report.

**This is WIP. No guarantee to catch anything. Use at your own risk.**

## How It Works

```
Host (macOS)
  └── Lima VM (ephemeral, firewalled, zero-sudo)
        ├── Hardened git clone (safe_clone.sh)
        ├── AI pre-dep discovery (finds hidden dependency sources)
        ├── Docker container (dependency resolution, single invocation)
        ├── 20 deterministic scanners (parallel)
        ├── AI analyst agents (8 personas, adversarial verification)
        └── Report synthesis
```

1. **Isolate** -- Ephemeral Lima VM with 3-layer network hardening (zero sudo, DNS pinning, iptables whitelist). No shared folders, no port forwarding.
2. **Clone** -- Hardened 4-phase git clone: no-checkout fetch, config lockdown, filtered checkout, post-validation (symlink removal, .gitattributes inspection).
3. **Discover** -- AI agent scans source for hidden dependencies (git clones in Makefiles, curl in Dockerfiles, submodules) that standard package files miss.
4. **Resolve** -- Single Docker container detects ecosystems (Python, Node, Rust, Go), downloads deps source-only, writes manifest. No install scripts executed.
5. **Scan** -- 20 scanners in parallel: SCA, SAST, supply chain behavioral analysis, entropy/obfuscation detection, install hook analysis, malware signatures, license compliance.
6. **Analyze** -- AI analyst + adversarial verification. Findings stay inside the VM.
7. **Report** -- Enriches with EPSS/KEV, synthesizes report with go/no-go recommendation.
8. **Cleanup** -- Destroys the VM. Nothing persists.

All scan data stays inside the VM until the final report copy. Nothing crosses the trust boundary except log lines and the finished report.

## Requirements

- macOS with Apple Silicon
- [Lima](https://lima-vm.io) (`brew install lima`)
- [tmux](https://github.com/tmux/tmux) (`brew install tmux`) -- optional, for split-pane UI
- Python 3.11+
- `ANTHROPIC_API_KEY` env var or `claude login` session (unless `--skip-ai`)

## Disk Usage

The VM needs ~15 GB. Configurable via `thresher.toml` or `--disk`. With a 15 GB image you'll have ~2 GB for source code and dependencies.

## Install

```bash
pip install -e .
```

## Usage

```bash
# Full scan with AI analysis
thresher https://github.com/owner/repo

# Deterministic scanners only (no API key needed)
thresher https://github.com/owner/repo --skip-ai

# Custom VM resources
thresher https://github.com/owner/repo --cpus 8 --memory 16 --disk 100

# Download high-risk hidden dependencies (binaries, tarballs)
thresher https://github.com/owner/repo --high-risk-dep
```

With [uv](https://docs.astral.sh/uv/):

```bash
uv run thresher https://github.com/owner/repo --skip-ai
```

### CLI Commands

| Command | Description |
|---------|-------------|
| `thresher <url>` | Scan a repository |
| `thresher-build` | Build/rebuild the cached base VM image |
| `thresher-stop` | Stop all VMs and tmux session |

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--depth N` | 2 | Transitive dependency depth |
| `--skip-ai` | off | Deterministic scanners only |
| `--high-risk-dep` | off | Download high-risk hidden deps (binaries, tarballs) |
| `--verbose` | off | Show detailed tool output |
| `--output DIR` | `./thresher-reports` | Report output directory |
| `--cpus N` | 4 | VM CPU count |
| `--memory N` | 8 | VM memory in GiB |
| `--disk N` | 50 | VM disk in GiB |
| `--tmux` | off | Enable tmux split-pane UI |

### Tmux UI

Pass `--tmux` or set `tmux = true` in config to launch in a tmux split-pane (left: scan, right: logs).

| Key | Action |
|-----|--------|
| `Ctrl-b h/l` | Switch panes |
| `Ctrl-b z` | Zoom pane (toggle) |
| `Ctrl-b [` | Scroll mode (`q` to exit) |
| `Ctrl-b q` | Quit session |

### Configuration

Copy `thresher.toml.example` to `thresher.toml`. CLI flags override config values.

```toml
model = "sonnet"
depth = 2
output_dir = "./thresher-reports"
tmux = false

[vm]
cpus = 4
memory = 8
disk = 50

[limits]
max_json_size_mb = 10    # Max JSON payload from VM
max_file_size_mb = 50    # Max file in report copy
max_copy_size_mb = 500   # Max total report copy
max_stdout_mb = 50       # Max stdout before kill
```

## Scanners (20)

| Tool | Category | What It Catches |
|------|----------|-----------------|
| Syft | SBOM | Bill of materials (feeds Grype) |
| Grype | SCA | Known CVEs in dependencies |
| OSV-Scanner | SCA + MAL | CVEs and malicious package advisories |
| Trivy | SCA | Container/filesystem CVEs |
| govulncheck | SCA (Go) | Go vulns with call-graph reachability |
| cargo-audit | SCA (Rust) | Rust vulns from RustSec |
| Semgrep | SAST | Code vulnerabilities and dangerous patterns |
| Semgrep (supply-chain) | Behavioral | Custom rules on dep source: exfil, download-and-exec, encoded payloads |
| Bandit | SAST (Python) | Python security anti-patterns |
| GuardDog | Supply Chain | Suspicious package behaviors on manifests |
| GuardDog (deps) | Supply Chain | Behavioral heuristics on actual dep source code |
| Install Hooks | Install Hook | Detects preinstall/postinstall scripts with network/shell activity |
| Entropy | Obfuscation | High-entropy strings, base64 blobs, hex escapes, JS obfuscator patterns, eval-of-decoded |
| Gitleaks | Secrets | Hardcoded API keys, tokens, credentials |
| Checkov | IaC | Dockerfile/Terraform/K8s misconfigurations |
| Hadolint | IaC (Docker) | Dockerfile best practices |
| YARA | Malware | Known malware signatures |
| ClamAV | Antivirus | Virus and malware signatures |
| capa | Binary Analysis | Capabilities in compiled binaries |
| ScanCode | License | License compliance from file contents |

## Output

Reports in the output directory:

- `executive-summary.md` -- Go / Caution / Do Not Use recommendation
- `detailed-report.md` -- All findings by priority with remediation
- `findings.json` -- Machine-readable findings (CVSS, EPSS, KEV, AI scores)
- `sbom.json` -- CycloneDX SBOM
- `scan-results/` -- Raw scanner output

### Priority Levels

| Priority | Criteria |
|----------|----------|
| **P0** | CISA KEV (actively exploited), or AI-confirmed exfiltration/backdoor |
| **Critical** | CVSS >= 9.0, EPSS > 90th percentile, or AI risk 9-10 confirmed |
| **High** | CVSS 7.0-8.9, EPSS > 75th percentile, or AI risk 7-8 |
| **Medium** | CVSS 4.0-6.9, EPSS > 50th percentile, or AI risk 4-6 |
| **Low** | Everything else |

Any P0/Critical = **DO NOT USE**. High only = **CAUTION**. Medium and below = **GO**.

## Security Model

- **VM isolation**: Lima with `vz` backend, `--plain`, no mounts, no port forwards
- **Zero sudo**: Scan user can only run one hardcoded Docker wrapper via sudoers
- **3-layer network**: iptables whitelist + hostResolver DNS control + DNS pinning to host gateway
- **Hardened clone**: 4-phase safe_clone.sh neutralizes all known git code execution vectors
- **Dependency sandbox**: Single Docker container, `--network=none`, `--read-only`, `--cap-drop=ALL`
- **Source-only downloads**: `pip download --no-binary`, `npm pack`, `cargo vendor`
- **Host boundary**: Staging directory with symlink removal, path traversal rejection, size limits, extension allowlist
- **API key handling**: tmpfs read-and-delete pattern, never in shell environment
- **Ephemeral**: VM destroyed after each scan

## License

MIT
