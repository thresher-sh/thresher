# Security Model

This document describes the isolation and containment strategy used to safely analyze untrusted code.

## Threat Model

The target repository is **untrusted**. It may contain:

- Malicious install scripts that execute on dependency installation
- Code that exfiltrates data when imported or executed
- Dependencies that are typosquatted or compromised
- Binaries with embedded malware or reverse shells

The security model assumes the worst case: the target is actively hostile. Every isolation layer is designed to prevent untrusted code from reaching the host machine or exfiltrating data.

## Isolation Tiers

Thresher supports three launch modes with different isolation levels:

```
Most isolated:  Lima+Docker  (VM + iptables firewall + container sandbox)
Middle:         Docker only   (container sandbox, no egress firewall)
Least isolated: Direct/no-vm  (process isolation only, dev mode)
```

### Lima+Docker Mode (default on macOS)

**4 layers of isolation:**

1. **Lima VM** — Apple Virtualization.framework (`vz` backend), no shared folders, no port forwards
2. **Egress Firewall** — iptables whitelist (18 domains), all other outbound traffic dropped
3. **Container Sandbox** — `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, non-root user
4. **Source-only deps** — no install scripts execute

### Docker Mode (`--docker`)

**3 layers of isolation:**

1. **Container Sandbox** — same hardening as Lima mode (`--read-only`, `--cap-drop=ALL`, `--no-new-privileges`)
2. **Source-only deps** — no install scripts execute
3. **Ephemeral container** — `--rm` (auto-removed)

Docker mode has **no egress firewall**. The container has unrestricted network access. This is acceptable because source-only downloads prevent install script execution, and Docker mode targets Linux servers and CI environments.

### Direct Mode (`--no-vm`)

**1 layer of isolation:**

1. **Source-only deps** — no install scripts execute

Dev mode. User accepts the risk. All scanner tools must be installed locally.

## Container Hardening (Docker and Lima+Docker modes)

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

## Egress Firewall (Lima+Docker mode only)

The VM's outbound network traffic is restricted by iptables rules to a whitelist of 18 domains.

**Whitelisted Domains**:

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

## Source-Only Downloads (all modes)

Dependencies are downloaded as source archives without executing install scripts:

| Ecosystem | Command | Why It's Safe |
|-----------|---------|---------------|
| Python | `pip download --no-binary :all:` | No wheel installation, no `setup.py` execution |
| Node | `npm pack` | Downloads tarball without running `postinstall` |
| Rust | `cargo vendor` | Downloads source, no build.rs execution |
| Go | `go mod vendor` | Downloads source, no `go generate` execution |

**What this prevents**: Many supply chain attacks rely on install hooks (`setup.py`, `postinstall.sh`, `build.rs`) that execute arbitrary code during `pip install` or `npm install`. By downloading source-only, these hooks never run.

## Credential Handling

- **API keys** are passed via environment variables (`docker run -e`), never written to disk
- `ANTHROPIC_API_KEY` environment variable takes precedence
- Fallback: OAuth token from macOS Keychain (`claude login` session)
- In Docker/Lima modes, credentials exist only in container process memory (`--rm`)
- No tmpfs ceremony needed — ephemeral container is the boundary

**What this prevents**: If an attacker gains filesystem access inside the container, they cannot find credentials on disk. The read-only filesystem and `--rm` flag ensure nothing persists.

## Report Validation (all modes)

The harness validates all report output before writing:

| Check | Action |
|-------|--------|
| Symlinks | Removed (filesystem escape vector) |
| File extensions | Whitelist: `.json`, `.md`, `.txt`, `.csv`, `.log`, `.sarif`, `.html` |
| File size | Per-file cap (default 50MB) |
| Total size | Report directory cap (default 500MB) |
| Executable bits | Stripped from all files |
| Path traversal | Detected and rejected |

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
