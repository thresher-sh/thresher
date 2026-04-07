[Join Discord](https://discord.gg/VVt9qmkcnr) -- [Website: thresher.sh](https://thresher.sh)

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

Supply chain security scanner. 22 deterministic scanners + 8 AI analyst personas inside a hardened container. Three isolation modes: Lima+Docker (max security), Docker (container sandbox), or direct (dev mode). Produces a go/no-go report.

> **Disclaimer:** Thresher is provided "as is" without warranty of any kind. It does not guarantee detection of all vulnerabilities, malicious code, or supply chain threats. Results should not be treated as a substitute for professional security audits. No vm isolation is guaranteed safe, Use at your own risk.

---

## Install

```bash
brew tap thresher-sh/thresher
brew install thresher
```

Or with pip:

```bash
pip install -e .
```

Then build the Docker image:

```bash
thresher build
```

```bash
thresher scan https://github.com/owner/repo
```

---

## What It Does

```
Host
  └── CLI (thin launcher — picks where to run)
        │
        ├── Lima+Docker (default on macOS — max isolation)
        │     └── iptables firewall + container sandbox
        ├── Docker (--docker — container sandbox, no VM)
        └── Direct (--no-vm — dev mode, runs on host)
              │
              └── Harness (Hamilton DAG pipeline)
                    ├── Hardened git clone (4-phase, Python)
                    ├── AI pre-dep discovery (hidden dependency sources)
                    ├── Dependency resolution (source-only, no install scripts)
                    ├── 22 deterministic scanners (parallel)
                    ├── 8 AI analyst agents + adversarial verification
                    └── Report synthesis → /output
```

| Step | What Happens |
|------|-------------|
| **Launch** | CLI picks mode: Lima+Docker (firewall + container), Docker (container), or direct (dev). |
| **Clone** | 4-phase hardened clone. Neutralizes all known git execution vectors. |
| **Discover** | AI finds hidden deps (git clones in Makefiles, curl in Dockerfiles, submodules). |
| **Resolve** | Source-only downloads. No install scripts. |
| **Scan** | 22 scanners: SCA, SAST, behavioral, entropy, install hooks, malware, license. |
| **Analyze** | 8 AI personas investigate in parallel. Adversarial verification reduces false positives. |
| **Report** | EPSS/KEV enrichment. Go / Caution / Do Not Use recommendation. |

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
# Full scan — Lima+Docker (default, max isolation)
thresher scan https://github.com/owner/repo

# Docker container only (no VM, good for Linux/CI)
thresher scan https://github.com/owner/repo --docker

# Direct mode (dev — runs on host, no container)
thresher scan https://github.com/owner/repo --no-vm

# Deterministic scanners only (no API key needed)
thresher scan https://github.com/owner/repo --skip-ai

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
| `thresher build` | Build the Thresher Docker image |
| `thresher stop` | Stop all VMs and tmux session |
| `thresher list` | List available pre-built images from releases |
| `thresher import <source>` | Import a pre-built image (skip the build) |
| `thresher export` | Export your image for distribution |

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--docker` | off | Run in Docker (no VM) |
| `--no-vm` | off | Run directly on host (dev mode) |
| `--depth N` | 2 | Transitive dependency depth |
| `--skip-ai` | off | Deterministic scanners only |
| `--high-risk-dep` | off | Download high-risk hidden deps |
| `--verbose` | off | Detailed tool output |
| `--output DIR` | `./thresher-reports` | Report output directory |
| `--cpus N` | 4 | VM CPU count (Lima mode) |
| `--memory N` | 8 | VM memory in GiB (Lima mode) |
| `--disk N` | 50 | VM disk in GiB (Lima mode) |
| `--tmux` | off | Tmux split-pane UI |
| `--branch` | default | Git branch to scan |

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

**Three isolation tiers (most → least):**

| Mode | Isolation |
|------|-----------|
| **Lima+Docker** (default) | VM + iptables firewall + container sandbox |
| **Docker** (`--docker`) | Container sandbox (`--read-only`, `--cap-drop=ALL`, `--no-new-privileges`) |
| **Direct** (`--no-vm`) | Process isolation only (dev mode) |

**Protections (all modes):**

| Layer | What It Does |
|-------|-------------|
| **Hardened clone** | 4-phase Python clone (hooks disabled, config sanitized, symlinks removed) |
| **Source-only deps** | `pip download --no-binary`, `npm pack`, `cargo vendor` — no install scripts |
| **Container hardening** | `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, tmpfs mounts |
| **Report validation** | Extension whitelist, size limits, symlink rejection, path traversal detection |
| **Credentials** | Environment variables only, never written to disk |

**Lima+Docker additional layers:**

| Layer | What It Does |
|-------|-------------|
| **VM isolation** | Lima `vz` backend, Apple Virtualization.framework |
| **Egress firewall** | iptables whitelist (18 domains), all other egress dropped |

---

## Requirements

**All modes:**
- Python 3.11+
- Docker
- `ANTHROPIC_API_KEY` or `claude login` (unless `--skip-ai`)

**Lima+Docker mode (default, macOS):**
- macOS with Apple Silicon
- [Lima](https://lima-vm.io) (`brew install lima`)

**Direct mode (`--no-vm`, dev):**
- All 22 scanner tools installed locally

**Optional:**
- [tmux](https://github.com/tmux/tmux) (`brew install tmux`) — for split-pane UI

---

## License

MIT
