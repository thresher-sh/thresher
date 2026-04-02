# Security Model

This document describes the isolation and containment strategy used to safely analyze untrusted code.

## Threat Model

The target repository is **untrusted**. It may contain:

- Malicious install scripts that execute on dependency installation
- Code that exfiltrates data when imported or executed
- Dependencies that are typosquatted or compromised
- Binaries with embedded malware or reverse shells

The security model assumes the worst case: the target is actively hostile. Every isolation layer is designed to prevent untrusted code from reaching the host machine or exfiltrating data.

## Isolation Layers

### Layer 1: Lima VM

The entire scan runs inside a [Lima](https://lima-vm.io) virtual machine using the `vz` backend (Apple's Virtualization.framework on Apple Silicon).

**VM Configuration** (`lima/thresher.yaml`):

| Setting | Value | Purpose |
|---------|-------|---------|
| `plain: true` | No shared folders | Prevents VM from accessing host filesystem |
| `mounts: []` | No mount points | No host directories visible inside VM |
| `networks: []` | No network sharing | VM has its own network stack |
| Backend | `vz` | Native Apple Silicon virtualization |
| OS | Ubuntu 24.04 LTS (ARM64) | Minimal attack surface |

**Key property**: The VM has **no access** to the host filesystem. Files are transferred explicitly via SSH (`ssh_copy_to` / `ssh_copy_from`).

### Layer 2: Egress Firewall

The VM's outbound network traffic is restricted by iptables rules to a whitelist of 18 domains. All other outbound traffic is dropped and logged.

**Whitelisted Domains** (`vm_scripts/firewall.sh`):

| Domain | Purpose |
|--------|---------|
| `api.anthropic.com` | Claude API (AI agents) |
| `github.com`, `api.github.com` | Clone target repos |
| `pypi.org`, `files.pythonhosted.org` | Python packages |
| `registry.npmjs.org` | npm packages |
| `crates.io`, `static.crates.io` | Rust packages |
| `proxy.golang.org` | Go modules |
| `api.first.org` | EPSS exploitation scores |
| `services.nvd.nist.gov` | NVD vulnerability data |
| `toolbox-data.anchore.io`, `grype.anchore.io` | Grype vulnerability DB |
| `api.osv.dev` | OSV vulnerability DB |
| `semgrep.dev`, `metrics.semgrep.dev` | Semgrep rules |
| `ghcr.io`, `pkg-containers.githubusercontent.com` | Container images |
| `vuln.go.dev` | Go vulnerability DB |
| `database.clamav.net` | ClamAV virus signatures |

**Firewall rules**:
- DNS (port 53) is allowed for domain resolution
- HTTP/HTTPS to whitelisted IPs only
- All other egress is **DROP** with logging
- Domain names are resolved to IPs at firewall setup time

**What this prevents**: If malicious code executes inside the VM, it cannot phone home to arbitrary C2 servers, exfiltrate data to attacker-controlled domains, or download additional payloads from non-whitelisted sources.

### Layer 3: Docker Dependency Sandbox

Dependencies are downloaded inside Docker containers running within the VM. This adds a second containment layer around the most dangerous phase: fetching untrusted packages.

**Sandbox properties**:
- Source code is mounted **read-only** into the container
- Dependencies are written to a separate **read-write** volume
- Optional `--network=none` after the download phase
- Containers are `--rm` (auto-removed after execution)

### Layer 4: Source-Only Downloads

Dependencies are downloaded as source archives without executing install scripts:

| Ecosystem | Command | Why It's Safe |
|-----------|---------|---------------|
| Python | `pip download --no-binary :all:` | No wheel installation, no `setup.py` execution |
| Node | `npm pack` | Downloads tarball without running `postinstall` |
| Rust | `cargo vendor` | Downloads source, no build.rs execution |
| Go | `go mod vendor` | Downloads source, no `go generate` execution |

**What this prevents**: Many supply chain attacks rely on install hooks (`setup.py`, `postinstall.sh`, `build.rs`) that execute arbitrary code during `pip install` or `npm install`. By downloading source-only, these hooks never run.

### Layer 5: Ephemeral VMs

Each scan uses a fresh VM instance. After the scan completes:

1. The report is copied from the VM to the host via SSH
2. The VM is force-deleted (`limactl delete --force`)
3. The VM's disk image is destroyed

**What this prevents**: Cross-contamination between scans. Even if malicious code persists inside the VM filesystem, it is destroyed and cannot affect the next scan.

The base VM (`thresher-base`) is preserved for reuse to avoid re-provisioning, but it contains only tools — never target code or dependencies.

### Layer 6: Credential Handling

- **API keys** are passed to the VM via SSH environment variables, never written to disk
- `ANTHROPIC_API_KEY` environment variable takes precedence
- Fallback: OAuth token from macOS Keychain (`claude login` session)
- Credentials exist in VM memory only during the scan

**What this prevents**: If an attacker gains filesystem access inside the VM, they cannot find credentials on disk. Credentials only exist in process memory for the duration of the scan.

## What the AI Agents Can and Cannot Do

The Claude Code agents run inside the VM with restricted tool access:

| Capability | Analyst | Adversarial |
|-----------|---------|-------------|
| Read files | Yes | Yes |
| Search files (Glob/Grep) | Yes | Yes |
| Execute code | **No** | **No** |
| Network access | Claude API only | Claude API only |
| Write files | **No** | **No** |
| Access host filesystem | **No** | **No** |

The agents analyze code by reading and searching — they never execute it.

## Attack Surface Summary

| Vector | Mitigation |
|--------|-----------|
| Malicious install scripts | Source-only downloads (no execution) |
| Code execution in VM | VM isolation (no host access) |
| Data exfiltration from VM | Egress firewall whitelist |
| Cross-scan contamination | Ephemeral VMs (destroyed after scan) |
| Credential theft | Environment-only, never on disk |
| Host filesystem access | Lima plain mode (no mounts) |
| AI agent exploitation | Read-only tools, no code execution |
| Network-based attacks | iptables DROP all non-whitelisted |

## Limitations

- The egress firewall resolves domains to IPs at setup time. If a whitelisted domain's IP changes during a scan, new IPs won't be allowed.
- The `vz` backend relies on Apple's Virtualization.framework. VM escape vulnerabilities in the hypervisor would bypass all isolation.
- Source-only downloads prevent install-time attacks, but import-time attacks (code that runs when the module is loaded) are still possible if the code were ever imported. The scanners analyze code statically — they don't import it.
- The base VM is reused across scans. If it were compromised (e.g., via a tool update), subsequent scans would inherit the compromise. Rebuild with `thresher stop && thresher build` if concerned.
