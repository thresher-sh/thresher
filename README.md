# Project Threat Scanner

AI-powered supply chain security scanner for evaluating open source packages before adoption. Scans a target repository and its dependencies for known vulnerabilities, malicious code, secrets, and supply chain risks, then produces a static go/no-go report.

## Disclaimer

This is WIP, no guarantee to catch anything. It is best effort, and use at your own risk. 

## Disk Usage Notice

VM it creates needs about **15gb** of free disk space to operate on your mac. It's downloading a lot of tools and databases for scanners etc... You also need to have space to download the repos you expect to scan, if you do a **15gb** image (Configurable in the `scanner.toml` file) you'll end up with about `2gb` of space inside the container to download source code and dependencies with.

## How It Works

```
Host (macOS)
  └── Lima VM (ephemeral, firewalled)
        ├── Docker containers (dependency download sandbox)
        ├── Deterministic scanners (Syft, Grype, OSV-Scanner, Semgrep, GuardDog, Gitleaks)
        └── AI analysis agents (Claude Code headless)
              ├── Agent 1: Triage + focused code analysis
              └── Agent 2: Adversarial verification (reduce false positives)
```

1. **Isolate** -- Spins up an ephemeral Lima VM with egress firewall (whitelisted domains only). No shared folders, no port forwarding.
2. **Download** -- Detects ecosystems (Python, Node, Rust, Go) and downloads dependencies source-only inside Docker containers. No install scripts executed.
3. **Scan** -- Runs 6 deterministic scanners in parallel, producing a normalized findings set.
4. **Analyze** -- (Optional) Two Claude Code agents perform deep code analysis on high-risk files, then adversarially verify findings to reduce false positives.
5. **Report** -- Enriches findings with EPSS scores and CISA KEV status, computes composite priority, and generates a static report with a clear recommendation.
6. **Cleanup** -- Destroys the VM. Nothing persists.

## Requirements

- macOS with Apple Silicon
- [Lima](https://lima-vm.io) (`brew install lima`)
- [tmux](https://github.com/tmux/tmux) (`brew install tmux`) — optional, for split-pane UI with live logs
- Python 3.11+
- AI credentials (unless using `--skip-ai`) — one of:
  - `ANTHROPIC_API_KEY` environment variable, **or**
  - An active Claude login session (`claude login`) — the OAuth token is read from the macOS Keychain automatically

## Install

```bash
pip install -e .
```

## Usage

```bash
# Full scan with AI analysis
threat-scan https://github.com/owner/repo

# Deterministic scanners only (no API key needed, faster, cheaper)
threat-scan https://github.com/owner/repo --skip-ai

# Customize VM resources and dependency depth
threat-scan https://github.com/owner/repo --cpus 8 --memory 16 --disk 100 --depth 3

# Specify output directory
threat-scan https://github.com/owner/repo --output ./my-report
```

### Running without installing

If you use [uv](https://docs.astral.sh/uv/), you can run directly from the source tree without installing:

```bash
uv run threat-scan https://github.com/owner/repo --skip-ai
```

`uv run` automatically resolves dependencies and makes the `threat-scan` entry point available without a separate install step.

### Tmux UI

By default, scans launch in a tmux split-pane layout: scan progress on the left, live logs on the right.

| Key | Action |
|-----|--------|
| `Ctrl-b h` | Switch to left pane (scan) |
| `Ctrl-b l` | Switch to right pane (logs) |
| `Ctrl-b z` | Zoom current pane full-screen (toggle) |
| `Ctrl-b [` | Scroll mode (`q` to exit) |
| `Ctrl-b q` | Quit — kills scan and closes tmux |

To disable tmux, use `--no-tmux` or set `tmux = false` in `scanner.toml`. If tmux is not installed, the scan runs normally without it.

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--depth N` | 2 | Transitive dependency depth |
| `--skip-ai` | off | Deterministic scanners only (no AI agents) |
| `--verbose` | off | Show detailed tool output |
| `--output DIR` | `./scan-results` | Host directory for report output |
| `--cpus N` | 4 | VM CPU count |
| `--memory N` | 8 | VM memory in GiB |
| `--disk N` | 50 | VM disk in GiB |
| `--no-tmux` | off | Disable tmux split-pane UI |

### Configuration

Copy `scanner.toml.example` to `scanner.toml` in the project root to customize defaults. CLI flags override these values.

```toml
model = "sonnet"
depth = 2
output_dir = "./scan-results"
tmux = true

[vm]
cpus = 4
memory = 8   # GB
disk = 50    # GB
```

## Output

Reports are written to the output directory:

- `executive-summary.md` -- Go / Caution / Do Not Use recommendation with top findings
- `detailed-report.md` -- All findings grouped by priority with remediation guidance
- `findings.json` -- Machine-readable findings with CVSS, EPSS, KEV, and AI scores
- `sbom.json` -- CycloneDX SBOM of the scanned project

### Priority Levels

| Priority | Criteria |
|----------|----------|
| **P0** | In CISA KEV (actively exploited), or AI-confirmed exfiltration/backdoor |
| **Critical** | CVSS >= 9.0, EPSS > 90th percentile, or AI risk 9-10 confirmed |
| **High** | CVSS 7.0-8.9, EPSS > 75th percentile, or AI risk 7-8 |
| **Medium** | CVSS 4.0-6.9, EPSS > 50th percentile, or AI risk 4-6 |
| **Low** | Everything else |

### Recommendation Logic

- Any **P0** or **Critical** finding --> **DO NOT USE**
- **High** findings only --> **USE WITH CAUTION**
- **Medium** and below only --> **GO**

## Scanners

| Tool | Category | What It Catches |
|------|----------|-----------------|
| Syft | SBOM | Bill of materials (feeds Grype) |
| Grype | SCA | Known CVEs in dependencies |
| OSV-Scanner | SCA + MAL | CVEs and malicious package advisories |
| Trivy | SCA + IaC | Container image CVEs, IaC misconfigurations |
| Semgrep | SAST | Code vulnerabilities and dangerous patterns |
| Bandit | SAST (Python) | Python-specific security anti-patterns (pickle, weak crypto, shell injection) |
| Checkov | IaC | Dockerfile, Terraform, K8s, Helm, CloudFormation misconfigurations |
| Hadolint | IaC (Docker) | Dockerfile best practices + ShellCheck on RUN instructions |
| GuardDog | Supply Chain | Suspicious package behaviors (typosquatting, exfiltration) |
| Gitleaks | Secrets | Hardcoded API keys, tokens, credentials |
| YARA | Malware | Known malware signatures via community rules |
| capa | Binary Analysis | Capabilities in compiled binaries (networking, crypto, persistence) |
| govulncheck | SCA (Go) | Go vulnerabilities with call-graph analysis (reduced false positives) |
| cargo-audit | SCA (Rust) | Rust vulnerabilities from the RustSec advisory database |
| ClamAV | Antivirus | Known virus and malware signatures |
| ScanCode | License | License compliance from file contents, not just manifests |

## Security Model

- **VM isolation**: Lima VM with `vz` backend, `--plain`, no mounts, no port forwarding
- **Egress firewall**: iptables whitelist -- only Claude API, GitHub, package registries, and vulnerability databases are reachable
- **Dependency sandbox**: Docker containers inside the VM for untrusted dependency downloads
- **Source-only downloads**: `pip download --no-binary`, `npm pack`, `cargo vendor` -- no install scripts executed
- **Ephemeral**: Fresh VM per scan, force-deleted after. No cross-contamination between scans
- **Credential handling**: API key or OAuth token passed via SSH environment variables, never written to disk. `ANTHROPIC_API_KEY` takes precedence if both are available

## License

MIT
