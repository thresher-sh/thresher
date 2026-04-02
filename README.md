```
                                          ___/|
                              ___________/    |
                   __________/                |
               ___/    _____                  |
           ___/   \___/     \                 |
       ___/                  \         ______/
   ___/         _              \______/
  /          __/ \__    ___----~
 |      ,__-~      \--~
 |     /    _,                  T H R E S H E R
  \___/  __/
     |  /                       Separate the safe
     |_/                        from the dangerous.
      ~
```

Supply chain security scanner. 22 deterministic scanners + 8 AI analyst personas inside a hardened, ephemeral VM. Produces a go/no-go report.

> **WIP.** No guarantee to catch anything. Use at your own risk.

---

## Install

```bash
pip install -e .

# Import a pre-built VM image (fast — ~30 seconds)
thresher import latest

# Or build your own (~10 minutes)
thresher build
```

```bash
thresher scan https://github.com/owner/repo
```

---

## What It Does

```
Host (macOS)
  └── Lima VM (ephemeral, firewalled, zero-sudo)
        ├── Hardened git clone (safe_clone.sh)
        ├── AI pre-dep discovery (hidden dependency sources)
        ├── Docker container (dependency resolution)
        ├── 22 deterministic scanners (parallel)
        ├── 8 AI analyst agents + adversarial verification
        └── Report synthesis
```

| Step | What Happens |
|------|-------------|
| **Isolate** | Ephemeral VM. 3-layer network hardening. No mounts, no ports. |
| **Clone** | 4-phase hardened clone. Neutralizes all known git execution vectors. |
| **Discover** | AI finds hidden deps (git clones in Makefiles, curl in Dockerfiles, submodules). |
| **Resolve** | Single Docker container. Source-only downloads. No install scripts. |
| **Scan** | 22 scanners: SCA, SAST, behavioral, entropy, install hooks, malware, license. |
| **Analyze** | 8 AI personas investigate in parallel. Adversarial verification reduces false positives. |
| **Report** | EPSS/KEV enrichment. Go / Caution / Do Not Use recommendation. |
| **Cleanup** | VM destroyed. Nothing persists. |

All scan data stays inside the VM until the final report copy.

---

## The 8 Analysts

Each runs as a Claude Code headless agent inside the VM with specialized tools.

| # | Persona | Core Question |
|---|---------|--------------|
| 1 | **The Paranoid** | Is this code malicious? |
| 2 | **The Behaviorist** | Is there an unreported vulnerability? |
| 3 | **The Investigator** | Is this code trustworthy? |
| 4 | **Pentester: Vulns** | What vulnerabilities are we inheriting? |
| 5 | **Pentester: App Surface** | How do users break in? |
| 6 | **Pentester: Memory** | Can this be corrupted at runtime? |
| 7 | **Infra Auditor** | Is this safe to deploy? |
| 8 | **The Shadowcatcher** | What is this code hiding? |

---

## 22 Scanners

| Tool | What It Catches |
|------|-----------------|
| Syft | SBOM generation (feeds Grype) |
| Grype | Known CVEs in dependencies |
| OSV-Scanner | CVEs + malicious package advisories (MAL-*) |
| Trivy | Container/filesystem CVEs |
| govulncheck | Go vulns with call-graph reachability |
| cargo-audit | Rust vulns from RustSec |
| Semgrep | Code vulnerabilities and dangerous patterns |
| Semgrep (supply-chain) | Custom rules on dep source: exfil, download-and-exec, encoded payloads |
| Bandit | Python security anti-patterns |
| GuardDog | Suspicious behaviors on manifests |
| GuardDog (deps) | Behavioral heuristics on actual dep source code |
| Install Hooks | preinstall/postinstall with network/shell activity |
| Entropy | High-entropy strings, base64, hex escapes, JS obfuscator patterns, eval-of-decoded |
| deps.dev | OpenSSF Scorecard, typosquatting, version history anomalies |
| Registry Metadata | Maintainer changes, tarball size spikes, install script introduction |
| Gitleaks | Hardcoded API keys, tokens, credentials |
| Checkov | Dockerfile/Terraform/K8s misconfigurations |
| Hadolint | Dockerfile best practices |
| YARA | Known malware signatures |
| ClamAV | Virus and malware signatures |
| capa | Capabilities in compiled binaries |
| ScanCode | License compliance from file contents |

---

## Usage

```bash
# Full scan with AI analysis
thresher scan https://github.com/owner/repo

# Deterministic scanners only (no API key needed)
thresher scan https://github.com/owner/repo --skip-ai

# Custom VM resources
thresher scan https://github.com/owner/repo --cpus 8 --memory 16 --disk 100

# Download high-risk hidden dependencies (binaries, tarballs)
thresher scan https://github.com/owner/repo --high-risk-dep

# With tmux split-pane UI (scan left, logs right)
thresher scan https://github.com/owner/repo --tmux
```

With [uv](https://docs.astral.sh/uv/):

```bash
uv run thresher scan https://github.com/owner/repo --skip-ai
```

### Commands

| Command | What It Does |
|---------|-------------|
| `thresher scan <url>` | Scan a repository |
| `thresher build` | Build/rebuild the cached base VM image |
| `thresher stop` | Stop all VMs and tmux session |
| `thresher list` | List available pre-built VM images from releases |
| `thresher import <source>` | Import a pre-built VM image (skip the build) |
| `thresher export` | Export your base VM image for distribution |

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--depth N` | 2 | Transitive dependency depth |
| `--skip-ai` | off | Deterministic scanners only |
| `--high-risk-dep` | off | Download high-risk hidden deps |
| `--verbose` | off | Detailed tool output |
| `--output DIR` | `./thresher-reports` | Report output directory |
| `--cpus N` | 4 | VM CPU count |
| `--memory N` | 8 | VM memory in GiB |
| `--disk N` | 50 | VM disk in GiB |
| `--tmux` | off | Tmux split-pane UI |

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
max_json_size_mb = 10
max_file_size_mb = 50
max_copy_size_mb = 500
max_stdout_mb = 50
```

---

## Output

```
~~~~~~~~~~~_/|~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

FINDINGS

P0  CRIT  HIGH  MED   LOW
 0     2      5     12    23

Report: ./thresher-reports/example-repo-20260401/

~~~~~~~~~~~_/|~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
```

Reports in the output directory:

| File | Contents |
|------|----------|
| `executive-summary.md` | Go / Caution / Do Not Use recommendation |
| `detailed-report.md` | All findings by priority with remediation |
| `findings.json` | Machine-readable (CVSS, EPSS, KEV, AI scores) |
| `sbom.json` | CycloneDX SBOM |
| `scan-results/` | Raw scanner output |

### Priority Levels

| Priority | Criteria |
|----------|----------|
| **P0** | CISA KEV (actively exploited), or AI-confirmed exfiltration/backdoor |
| **Critical** | CVSS >= 9.0, EPSS > 90th percentile, or AI risk 9-10 |
| **High** | CVSS 7.0-8.9, EPSS > 75th percentile, or AI risk 7-8 |
| **Medium** | CVSS 4.0-6.9, EPSS > 50th percentile, or AI risk 4-6 |
| **Low** | Everything else |

P0 or Critical = **DO NOT USE**. High only = **CAUTION**. Medium and below = **GO**.

---

## Security Model

| Layer | What It Does |
|-------|-------------|
| **VM isolation** | Lima `vz` backend, `--plain`, no mounts, no port forwards |
| **Zero sudo** | Scan user can only run one hardcoded Docker wrapper |
| **3-layer network** | iptables whitelist + hostResolver DNS + gateway pinning |
| **Hardened clone** | 4-phase safe_clone.sh (all git execution vectors neutralized) |
| **Dep sandbox** | `--network=none`, `--read-only`, `--cap-drop=ALL` |
| **Source-only** | `pip download --no-binary`, `npm pack`, `cargo vendor` |
| **Host boundary** | Staging dir, symlink removal, path traversal rejection, size limits |
| **API key** | tmpfs read-and-delete, never in shell environment |
| **Ephemeral** | VM destroyed after each scan |

---

## Requirements

- macOS with Apple Silicon
- [Lima](https://lima-vm.io) (`brew install lima`)
- Python 3.11+
- `ANTHROPIC_API_KEY` or `claude login` (unless `--skip-ai`)
- [tmux](https://github.com/tmux/tmux) (`brew install tmux`) -- optional

The VM needs ~30 GB disk. Configurable via `--disk` or `thresher.toml`.

---

## License

MIT
