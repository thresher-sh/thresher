# V2 Planning

Specs and research for the next major version of Project Threat Scanner. V1 is a working system — VM-isolated, multi-scanner, AI-analyzed. V2 makes it a security research shop in a box.

**Status**: Discovery / WIP. Nothing here is implemented yet.

---

## TLDR: What V2 Brings

V1 answers "does this project have known vulnerabilities?" V2 answers "should I trust this code?"

The difference: V1 runs 16 scanners that match against known-bad databases (CVEs, malware signatures, static rules). V2 adds behavioral analysis, package intelligence, hardened isolation, and an 8-analyst AI architecture that reasons about what the scanners can't see — novel malicious code, supply chain manipulation, trust signals, and attack surface.

---

## Architecture Changes

### Hardened VM Isolation

| Spec | What It Does |
|------|-------------|
| [Network Hardening](network-hardening-spec.md) | Three-layer defense: zero sudo + Docker wrapper, Lima hostResolver DNS control, iptables pinned to host gateway. Scan user has no privilege escalation path — can only invoke one hardcoded Docker command. |
| [Host Boundary Hardening](host-boundary-hardening.md) | Everything copied back from the VM is untrusted. Staging directory with symlink removal, path traversal rejection, size limits, extension allowlist. Bounded JSON parsing (10 MB cap). SSH stdout capped at 50 MB. API key exposure reduced via tmpfs read-and-delete. |
| [Source Download Hardening](source-download.md) | Git clone split into fetch + sanitize + checkout. Neutralizes `.gitattributes` filter execution, `core.fsmonitor` command injection, LFS smudge filters, template hooks. Post-checkout validation removes symlinks, flags suspicious gitattributes. |

### Containerized Dependency Resolution

| Spec | What It Does |
|------|-------------|
| [Dependency Resolution](dependency-resolution.md) | All dep detection and download logic moves into a single `scanner-deps` Docker container. One image, one entrypoint (`/scripts/run.sh`), zero arguments. Container detects project type, resolves deps, writes manifest. `sandbox.py` simplifies from 500+ lines of per-ecosystem Docker orchestration to a single `ssh_exec("sudo /usr/local/bin/scanner-docker")` call. |

### Upgraded Scanner Pipeline

| Spec | What It Does |
|------|-------------|
| [Improved Scanner](improved-scanner.md) | Three new detection layers beyond CVE matching. **Layer 1**: Custom Semgrep rules for supply chain behavioral patterns (download-and-execute, env var exfil, encoded payloads) + entropy/obfuscation analysis + install hook detection. **Layer 2**: deps.dev integration (Scorecard, typosquatting, version history) + registry metadata checks (maintainer changes, download ratios, tarball size spikes). **Layer 3**: GuardDog on actual dependency source code, not just manifests. Pipeline goes from 3 phases to 7. |

### 8-Analyst AI Architecture

| Spec | What It Does |
|------|-------------|
| [New Agents](new_agents/spec.md) | Two-stage AI: Stage 1 pre-dep agent identifies all dependency files. Stage 2 runs 8 parallel analyst personas, each with specialized tooling and a distinct security question. |
| [Watch Zones](watch-zones.md) | 10-zone taxonomy of what a security researcher evaluates. Zones 1-7 (CVEs, SAST, IaC, malware, behavioral, metadata, license) are the tooling domain. Zones 8-10 (repo health, cross-signal correlation, dark corners) are the AI analyst domain. |

---

## The 8 Analysts

All run in parallel after scanners complete. Each gets scanner output + source access + specialized CLI tools.

| # | Persona | Core Question | Key Tools |
|---|---------|--------------|-----------|
| 1 | **The Paranoid** | Is this code malicious? | `ast-grep`, `xxd`, `strings`, `base64` |
| 2 | **The Behaviorist** | Is there an unreported vulnerability? | `ast-grep`, `tree-sitter`, `semgrep` |
| 3 | **The Investigator** | Is this code trustworthy? | `git log/blame`, `jq`, `curl`, `cloc` |
| 4 | **Pentester: Vulns** | What vulnerabilities are we inheriting? | `ast-grep`, `semgrep`, `jq` |
| 5 | **Pentester: App Surface** | How do users break in? | `ast-grep`, `semgrep`, `openssl` |
| 6 | **Pentester: Memory** | Can this be corrupted at runtime? | `ast-grep`, `objdump`, `readelf`, `nm` |
| 7 | **Infra Auditor** | Is this safe to deploy? | `jq`, `shellcheck`, `python3 yaml` |
| 8 | **The Shadowcatcher** | What is this code hiding? | `ast-grep`, `tree-sitter`, `binwalk`, `exiftool` |

Analyst output feeds into Adversarial verification then Judge synthesis (existing pipeline).

---

## What V2 Catches That V1 Misses

| Attack | V1 | V2 |
|--------|----|----|
| Known CVE in dependency | Caught (5 scanners) | Same |
| `event-stream` style maintainer takeover | Missed | Registry metadata flags ownership change + Investigator analyst profiles trust |
| `ua-parser-js` hijack with cryptominer | Missed | Entropy scanner flags obfuscated payload + Paranoid analyst traces execution |
| Typosquatting (`crossenv` vs `cross-env`) | Partial (GuardDog Levenshtein) | deps.dev typosquatting endpoint + download count ratio |
| Dependency confusion (internal name on public registry) | Missed | Registry metadata checks |
| `preinstall` curl to attacker domain | Missed | Install hook scanner flags it as critical + Paranoid analyst reviews |
| Backdoor in vendored dependency source | Missed | GuardDog + custom Semgrep on actual dep source code |
| Unicode/homoglyph attack (Trojan Source) | Missed | Shadowcatcher with `python3 unicodedata` inspection |
| Polyglot file (PNG that's also a ZIP) | Missed | Shadowcatcher with `binwalk` |
| Git history manipulation hiding past malicious commits | Missed | Shadowcatcher with `git reflog` + `git fsck` |
| Low-severity CVE + reachable + high EPSS = critical chain | Missed (reported individually) | Pentester: Vulns correlates signals into attack chains |
| REST API failing OWASP Top 10 | Missed | Pentester: App Surface maps endpoints and auth flows |
| Unsafe C extension with buffer overflow | Missed | Pentester: Memory with `objdump` + `readelf` |
| `sudo iptables -F` by malware in VM | Possible | Zero sudo + Docker wrapper (network hardening) |
| Malicious files in scan results escaping to host | Possible | Staging dir + symlink removal + size limits (host boundary) |
| Git clone executing attacker's smudge filter | Possible | Split fetch/checkout + neutered config (source download) |

---

## Research

| Doc | What It Covers |
|-----|---------------|
| [Rebuild Research](rebuild-research.md) | Deep dive on how Socket.dev, Phylum, Sonatype, Snyk detect threats. CVE scanning vs behavioral analysis. Open-source tooling landscape. Reference architecture for a supply chain security system. |
| [Sources](sources.md) | 500+ research URLs across 40 search queries covering detection methodologies, data sources, and tooling. |

---

## Implementation Priority

1. **Network hardening** — zero sudo + Docker wrapper. Highest security impact, smallest code change.
2. **Source download hardening** — safe clone script. Prevents code execution during git clone.
3. **Host boundary hardening** — sanitize `ssh_copy_from`. Prevents VM escape via crafted files.
4. **Dependency resolution container** — single image, single invocation. Simplifies `sandbox.py` dramatically.
5. **Custom Semgrep rules** — supply chain behavioral patterns. Highest detection impact, lowest effort.
6. **Install hook + entropy scanners** — new detection modules. Pure Python, no external deps.
7. **deps.dev + registry metadata** — package intelligence. API integration + firewall whitelist updates.
8. **GuardDog on dep source** — one-line change, big detection uplift.
9. **Provision.sh additions** — `ast-grep`, `tree-sitter`, `binwalk`, `exiftool`, `jq`, etc. for analyst tooling.
10. **8-analyst architecture** — parallel AI agents with specialized personas and toolkits.
