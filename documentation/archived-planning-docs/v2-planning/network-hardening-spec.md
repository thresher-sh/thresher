# Network Hardening Spec

Hardens the VM's network isolation so that even if malware executes inside the VM, it cannot modify egress controls or escape to unauthorized destinations.

## Problem

The current egress firewall (`vm_scripts/firewall.sh`) uses iptables inside the VM with an OUTPUT DROP policy and a whitelist of approved domains. This works, but the scan user likely has `NOPASSWD: ALL` sudo access (standard in Lima VMs), which means malware running as the scan user can:

1. `sudo iptables -F` — flush all firewall rules
2. `sudo ip link` / `sudo ifconfig` — manipulate network interfaces
3. `sudo` anything else — full root access

The iptables rules are only as strong as the privilege boundary protecting them.

## Solution: Three-Layer Defense

### Layer 1: Zero Sudo + Docker Wrapper

After provisioning completes, the scan user has **no sudo access and no docker group membership**. The only way to invoke Docker is through a root-owned wrapper script with a single hardcoded sudoers entry.

**Where**: `vm_scripts/lockdown.sh` (executed as final provisioning step), `vm_scripts/scanner-docker` (the wrapper)

**What the scan user can do**: Run `sudo /usr/local/bin/scanner-docker` — nothing else.

**What gets denied**: Everything. No `iptables`, `ip`, `ifconfig`, `ufw`, `route`, `systemctl`, `apt`, `dpkg`, `docker` (direct), shell escapes, or any other privileged command.

**Docker wrapper** (`/usr/local/bin/scanner-docker`, owned `root:root`, mode `755`):

```bash
#!/bin/bash
set -euo pipefail

exec /usr/bin/docker run --rm \
  --network=none \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  -v "/home/scanner/work:/work" \
  scanner-deps:latest /scripts/run.sh
```

No arguments, no flags, no choices. The wrapper runs exactly one container with hardened flags. All logic for detecting project type, resolving dependencies, running language-specific tools, etc. lives inside the container's `/scripts/run.sh`. The VM side never makes decisions about what happens inside the container.

**Sudoers** (`/etc/sudoers.d/scanner-lockdown`):

```bash
# Remove default Lima NOPASSWD:ALL, allow only the wrapper
scanner ALL=(root) NOPASSWD: /usr/local/bin/scanner-docker
```

**Ordering**: The lockdown is written AFTER all provisioning and firewall setup is complete, since those scripts use `sudo` extensively. The wrapper and sudoers entry are the final step before scanning begins.

**Important**: The lockdown applies to the scan user only. Provisioning runs as root (via sudo before lockdown), so the base image build is unaffected.

**Attack surface**: The scan user's only privileged action is invoking a fixed, root-owned script that accepts no input. To escape, an attacker would need to modify the wrapper itself (requires root) or exploit Docker with all capabilities dropped and no network.

### Layer 2: Lima hostResolver (Host-Side DNS Control)

Lima's `hostResolver` runs a DNS server on the **host machine** that resolves names for the VM. The VM cannot tamper with it.

**Where**: `lima/scanner.yaml`

**Current config**:
```yaml
hostResolver:
  enabled: null  # defaults to true
```

**New config**:
```yaml
hostResolver:
  enabled: true
  hosts:
    # Only approved domains resolve. The host resolver handles these
    # lookups using the host's native DNS, running outside the VM.
    # Malware inside the VM cannot modify these mappings.
    api.anthropic.com: api.anthropic.com
    github.com: github.com
    api.github.com: api.github.com
    pypi.org: pypi.org
    files.pythonhosted.org: files.pythonhosted.org
    registry.npmjs.org: registry.npmjs.org
    crates.io: crates.io
    static.crates.io: static.crates.io
    proxy.golang.org: proxy.golang.org
    api.first.org: api.first.org
    services.nvd.nist.gov: services.nvd.nist.gov
    toolbox-data.anchore.io: toolbox-data.anchore.io
    grype.anchore.io: grype.anchore.io
    api.osv.dev: api.osv.dev
    semgrep.dev: semgrep.dev
    metrics.semgrep.dev: metrics.semgrep.dev
    ghcr.io: ghcr.io
    pkg-containers.githubusercontent.com: pkg-containers.githubusercontent.com
    vuln.go.dev: vuln.go.dev
    database.clamav.net: database.clamav.net
```

**Note on hostResolver.hosts behavior**: The `hosts` map in Lima's hostResolver defines static name-to-address mappings served by the host-side DNS. The exact filtering behavior (whether unlisted domains still resolve via passthrough or are blocked) needs to be validated during implementation. If `hostResolver` passes through unlisted domains to upstream DNS, this layer serves as a known-good resolution source but does NOT block arbitrary domain lookups on its own — iptables remains the enforcement layer. See [Open Questions](#open-questions).

### Layer 3: Tightened iptables (DNS Pinning to hostResolver)

Modify the firewall rules so the VM can ONLY use the Lima hostResolver for DNS — no external DNS servers.

**Where**: `vm_scripts/firewall.sh`

**Current DNS rules**:
```bash
# Allows DNS to ANY destination
sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
```

**New DNS rules**:
```bash
# Lima hostResolver runs on the host gateway (192.168.5.2 for user-mode,
# or the vzNAT gateway). Only allow DNS to that address.
HOST_GW="192.168.5.2"  # Lima's host.lima.internal

sudo iptables -A OUTPUT -p udp --dport 53 -d "$HOST_GW" -j ACCEPT
sudo iptables -A OUTPUT -p tcp --dport 53 -d "$HOST_GW" -j ACCEPT
# Block DNS to all other destinations (caught by default DROP policy,
# but explicit rule for logging)
sudo iptables -A OUTPUT -p udp --dport 53 -j LOG --log-prefix "BLOCKED_DNS: " --log-level 4
sudo iptables -A OUTPUT -p udp --dport 53 -j DROP
sudo iptables -A OUTPUT -p tcp --dport 53 -j LOG --log-prefix "BLOCKED_DNS: " --log-level 4
sudo iptables -A OUTPUT -p tcp --dport 53 -j DROP
```

**What this prevents**: Malware cannot use an external DNS server (e.g., `8.8.8.8`) to resolve C2 domains. All DNS queries must go through the host-side resolver, which the VM cannot modify.

## How the Layers Work Together

| Attack | Layer 1 (wrapper + zero sudo) | Layer 2 (hostResolver) | Layer 3 (iptables) |
|--------|-------------------------------|----------------------|-------------------|
| `sudo iptables -F` | Blocked (no sudo except wrapper) | N/A | N/A |
| `sudo docker run --privileged` | Blocked (no direct docker access) | N/A | N/A |
| Resolve C2 domain via external DNS | N/A | N/A | Blocked (DNS only to hostResolver) |
| Resolve C2 domain via hostResolver | N/A | Depends on passthrough behavior (see open questions) | Blocked (IP not in whitelist) |
| Connect to C2 by raw IP | N/A | N/A | Blocked (IP not in whitelist) |
| `sudo ip link set` to manipulate interface | Blocked (no sudo except wrapper) | N/A | N/A |
| Modify `/etc/resolv.conf` to use rogue DNS | N/A | Queries still go to hostResolver gateway | Blocked (DNS to non-gateway dropped) |
| Escape via Docker container | Blocked (--cap-drop=ALL, --network=none, --read-only, no-new-privileges) | N/A | N/A |

Even if any single layer is bypassed, the other two still hold.

## Implementation Order

The changes apply at different points in the lifecycle:

### Base Image Build (`threat-scan-build`)

1. `provision.sh` runs as root — installs all tools, builds `scanner-deps:latest` image (unchanged)
2. `firewall.sh` runs as root — applies whitelist rules with tightened DNS pinning (**modified**)
3. **NEW**: `lockdown.sh` runs as root — installs `/usr/local/bin/scanner-docker` wrapper, writes sudoers lockdown, removes scan user from docker group
4. Base VM stopped and saved

### Scan Runtime (`threat-scan`)

1. Start base VM (firewall + sudoers lockdown + wrapper already baked in)
2. Clone repo into `/home/scanner/work`
3. `sudo /usr/local/bin/scanner-docker` — container detects project type, resolves deps, runs all scanning logic via `/scripts/run.sh`
4. Run AI analysis (iptables allows `api.anthropic.com`)
5. Copy report, stop VM

### Lima YAML (`scanner.yaml`)

Updated at project level — takes effect when base image is created.

## Files Modified

| File | Change |
|------|--------|
| `lima/scanner.yaml` | Add `hostResolver` config with approved domain mappings |
| `vm_scripts/firewall.sh` | Pin DNS to Lima hostResolver gateway, block external DNS |
| `vm_scripts/scanner-docker` (new) | Root-owned wrapper — single hardcoded `docker run` with no arguments |
| `vm_scripts/lockdown.sh` (new) | Install wrapper, strip all sudo except wrapper, remove docker group |
| `src/threat_scanner/vm/lima.py` | Call `lockdown.sh` as final provisioning step |

## Open Questions

1. **hostResolver passthrough**: Does Lima's hostResolver pass through DNS queries for domains NOT listed in `hosts`, or does it only resolve listed entries? If it passes through, the `hosts` map is additive (not a whitelist) and iptables remains the sole egress enforcement. Need to test or read Lima source to confirm.

2. **Lima host gateway IP**: The gateway IP (`192.168.5.2` for user-mode networking) may differ depending on network mode. If we switch to `vzNAT: true`, the gateway address changes. The firewall script should detect the gateway dynamically rather than hardcoding it.

3. **Base VM reuse**: The sudoers lockdown is baked into the base image. If a future provisioning change requires broader sudo, the base must be rebuilt. This is acceptable since `threat-scan-build` already handles full rebuilds.

## Testing

1. **Sudoers**: SSH into a locked-down VM, verify `sudo iptables -L` is denied, verify `sudo docker ps` is denied, verify `sudo /usr/local/bin/scanner-docker` works
2. **Wrapper isolation**: Verify the container runs with `--network=none`, `--read-only`, `--cap-drop=ALL` (inspect running container)
3. **DNS pinning**: From inside the VM, verify `dig @8.8.8.8 evil.com` is blocked, verify `dig api.anthropic.com` resolves
4. **Egress**: Verify `curl https://api.anthropic.com` succeeds, verify `curl https://evil.com` fails
5. **Full scan**: Run a complete scan against a known-good repo, confirm all scanners and AI analysis still work
6. **Attack simulation**: Place a script in a test repo that attempts `sudo iptables -F` and `sudo docker run --privileged`, verify both fail and the scan completes normally
