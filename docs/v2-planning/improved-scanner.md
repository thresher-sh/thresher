# Improved Scanner Spec

Upgrades the pre-AI scanning pipeline from primarily CVE-matching into a layered detection system that catches intentional malicious code — not just known vulnerabilities.

## Current State

We have 16 scanner modules in two phases:

| Category | Tools | What They Catch |
|----------|-------|-----------------|
| **SCA (CVE matching)** | Grype, OSV-Scanner, Trivy, govulncheck, cargo-audit | Known vulnerabilities with CVE IDs |
| **SAST** | Semgrep (auto config), Bandit | Insecure code patterns (eval, SQL injection, etc.) |
| **Supply chain** | GuardDog | Malicious package behaviors (static heuristics) |
| **Secrets** | Gitleaks | Hardcoded API keys, credentials in git history |
| **Malware signatures** | YARA, ClamAV, capa | Known malware patterns, binary capabilities |
| **IaC** | Checkov, Hadolint | Dockerfile/Terraform misconfigurations |
| **License** | ScanCode | Copyleft license detection |
| **SBOM** | Syft | Dependency enumeration (feeds Grype) |

### Detection Gaps

The current tooling is strong on **reactive CVE scanning** (5 tools) and **known malware signatures** (YARA, ClamAV). It's weak on catching **novel malicious code** — the kind that has no CVE and no signature yet.

| Attack Type | Current Detection | Gap |
|-------------|------------------|-----|
| Known CVE in dependency | Grype, OSV, Trivy, govulncheck, cargo-audit | None — well covered |
| Typosquatting (fake package) | GuardDog (Levenshtein heuristics) | No download count ratio checks, no deps.dev cross-reference |
| Install script attack (preinstall/postinstall doing exfiltration) | GuardDog (static rules) | No dynamic analysis — we don't actually run install scripts in a sandbox |
| Obfuscated payload (base64 → eval, high-entropy strings) | Semgrep (limited), GuardDog (limited) | No entropy analysis, no dedicated obfuscation detection |
| Dependency confusion (private name published publicly) | None | No namespace/scope validation |
| Maintainer account takeover (new publisher on popular package) | None | No maintainer history tracking |
| Network exfiltration in dependency code | GuardDog (static pattern match) | No runtime behavioral analysis |
| Steganographic or encoded C2 in data files | YARA (signature only) | No entropy/statistical analysis of non-code files |

**The core gap**: We rely on tools that match against known-bad patterns (signatures, CVEs, static rules). We have nothing that answers "what does this code actually *do*?" from a behavioral standpoint.

## Solution: Three New Detection Layers

### Layer 1: Enhanced Static Behavioral Analysis

Upgrade the static analysis to detect suspicious *behavior patterns* in dependency source code, not just known-bad signatures. This runs against the downloaded dependency source in `/work/deps/` (per the dependency-resolution spec, all deps are source-only archives).

#### 1a. Custom Semgrep Rules for Supply Chain Patterns

The current Semgrep runs with `--config auto`, which uses the community ruleset. Add a custom ruleset targeting supply chain attack patterns specifically.

**New**: `rules/semgrep/supply-chain.yaml`

Target patterns:
- **Install script hooks**: `preinstall`/`postinstall` in `package.json` that invoke shell commands or download URLs
- **Environment variable exfiltration**: Code that reads `process.env` / `os.environ` and sends the values over HTTP/DNS
- **Download-and-execute**: `fetch()`/`urllib`/`http.get()` piped to `eval()`/`exec()`/`child_process.exec()`
- **Encoded payload execution**: `atob()`/`Buffer.from(*, 'base64')`/`base64.b64decode()` flowing to `eval`/`exec`
- **Filesystem access to sensitive paths**: Reads from `~/.ssh`, `~/.npmrc`, `~/.aws`, `~/.gnupg`, `~/.gitconfig`
- **Process spawning from data handlers**: `child_process.exec` or `subprocess.run` called from JSON parse callbacks or event handlers
- **Dynamic `require()`/`import()`**: Non-literal module loading (computed strings passed to import)

These are the patterns Socket.dev's "70+ behavioral signals" detect statically. We can replicate the most impactful ones as Semgrep rules.

**Execution**: Run as a second Semgrep pass against `/work/deps/` (the downloaded dependency source), separate from the existing Semgrep pass against the target repo.

#### 1b. Entropy and Obfuscation Analysis

Add a lightweight scanner that identifies obfuscated or high-entropy content in dependency source files.

**New module**: `src/threat_scanner/scanners/entropy.py`

What it detects:
- **High-entropy strings**: Strings with Shannon entropy > 4.5 bits/char and length > 40 (likely encoded payloads, encrypted data, or obfuscated code)
- **Base64 blobs**: Regex for base64-encoded content > 100 chars that decodes to valid UTF-8 or begins with common magic bytes
- **Hex-encoded payloads**: Long hex strings (> 64 chars) in source code
- **Minified code with suspicious markers**: Single-line JS/Python files > 10KB (legitimate minification exists, but in a dependency's source tarball it's unusual)

**Implementation**: Pure Python — walks the extracted dependency source, applies heuristics, produces findings. No external tool needed. Runs inside the scanner-deps container as part of `/scripts/run.sh`.

This is the "entropy analysis for obfuscation detection" from the rebuild research's Stage 2 analysis pipeline.

#### 1c. Install Script Detection

Dedicated analysis of package manager install hooks — the single most common npm malware vector.

**New module**: `src/threat_scanner/scanners/install_hooks.py`

What it detects:
- **npm**: `preinstall`, `postinstall`, `preuninstall` scripts in `package.json` that invoke `node`, `sh`, `bash`, `curl`, `wget`, or reference URLs
- **Python**: `setup.py` with `cmdclass` overrides (custom install commands), `pyproject.toml` build scripts that execute shell commands
- **Rust**: `build.rs` that downloads files or executes network calls
- **Go**: No install hooks (safe by design)

**Severity logic**:
- Install script exists and does network I/O → **critical**
- Install script exists and spawns shell → **high**
- Install script exists but appears benign (e.g., compiles native extension) → **medium** (flag for AI review)

**Implementation**: Parses manifest files from downloaded deps, extracts script content, applies pattern matching. No execution needed.

### Layer 2: Package Metadata Intelligence

Cross-reference dependency metadata against external data sources to detect supply chain manipulation signals that don't appear in the code itself.

#### 2a. deps.dev Integration

Google's Open Source Insights API provides package metadata, Scorecard results, and typosquatting detection with no authentication required.

**New module**: `src/threat_scanner/scanners/deps_dev.py`

What it queries per dependency:
- **OpenSSF Scorecard**: Overall score and individual checks (branch protection, code review, CI, dependency pinning). Low scores (< 4) on critical packages are flagged.
- **Typosquatting endpoint**: `/v3alpha/systems/{system}/packages/{name}:similarlyNamedPackages` — flags packages that are near-matches to popular packages with vastly different download counts
- **Version history**: Publication timestamps, gap detection (dormant package suddenly active), version anomalies (patch on old major version with high usage — a takeover signal)
- **Maintainer count**: Packages with a single maintainer and no Scorecard data are higher risk

**Rate limiting**: deps.dev has no auth requirement but should be queried in batches. The dep manifest from the dependency-resolution container provides the full list.

**Where it runs**: Host side, after dependency resolution but before AI analysis. The VM's firewall already whitelists the deps.dev domain (needs to be added if not present).

#### 2b. Registry Metadata Checks

Query package registries directly for signals that deps.dev doesn't cover.

**New module**: `src/threat_scanner/scanners/registry_meta.py`

What it checks:
- **npm**: `registry.npmjs.org/{package}` — maintainer list, publish timestamps, download counts, `scripts` field presence, tarball size changes between versions
- **PyPI**: `pypi.org/pypi/{package}/json` — `vulnerabilities` field (sourced from OSV), author email domain validity, release date patterns

**Key signals**:
- Maintainer changed between versions (possible account takeover)
- Download count < 100 with name similar to package with downloads > 100,000 (typosquatting)
- Version published from different author email than all previous versions
- Sudden introduction of install scripts in a version that previously had none
- Tarball size increase > 10x between versions (possible payload injection)

**Where it runs**: Inside the scanner-deps container (has network access for dependency downloads, can query registries at the same time).

### Layer 3: Dependency Source Scanning (GuardDog on Actual Source)

The current GuardDog runs against the *target repository's manifest files* (`guarddog scan {target_dir}`). This checks which packages are declared, but doesn't analyze the actual downloaded dependency source code.

**Change**: Run GuardDog a second time against the extracted dependency source archives in `/work/deps/`.

```bash
# Current: scan the target repo manifests
guarddog scan /work/target --output-format json

# New: also scan the actual downloaded dependency source
for ecosystem_dir in /work/deps/*/; do
    guarddog scan "$ecosystem_dir" --output-format json
done
```

This catches behavioral patterns (base64-to-eval, env var exfiltration, download-and-execute) in the actual dependency code, not just metadata. GuardDog's Semgrep-based heuristics are already good at this — we're just not pointing it at the right files.

## Updated Scanner Pipeline

### Phase 1: SBOM Generation (sequential)
1. **Syft** — enumerate dependencies → CycloneDX SBOM

### Phase 2: Dependency Resolution (sequential)
2. **scanner-docker wrapper** — detect ecosystems, download source-only deps, write manifest (per dependency-resolution spec)

### Phase 3: Vulnerability Scanning (parallel)
3. **Grype** — CVE scan against SBOM
4. **OSV-Scanner** — CVE + malicious package IDs (MAL-*)
5. **Trivy** — filesystem CVE scan
6. **govulncheck** — Go-specific reachability analysis
7. **cargo-audit** — Rust-specific advisory scan

### Phase 4: Static Analysis — Target Repo (parallel)
8. **Semgrep** (auto config) — security patterns in target code
9. **Bandit** — Python-specific security linting
10. **Gitleaks** — secrets in git history
11. **Checkov** — IaC misconfiguration
12. **Hadolint** — Dockerfile linting

### Phase 5: Supply Chain Analysis — Dependencies (parallel)
13. **Semgrep** (custom supply-chain rules) — behavioral patterns in dep source
14. **GuardDog** (target manifests) — existing manifest-level checks
15. **GuardDog** (dep source) — behavioral heuristics on actual dep code
16. **Install hook analysis** — detect and classify install scripts
17. **Entropy analysis** — obfuscation and encoded payload detection
18. **deps.dev / registry metadata** — Scorecard, typosquatting, maintainer signals

### Phase 6: Malware Detection (parallel)
19. **YARA** — known malware signatures
20. **ClamAV** — antivirus signatures
21. **capa** — binary capability analysis

### Phase 7: License Compliance (parallel)
22. **ScanCode** — copyleft license detection

### Then → AI Analysis (existing)

## New Finding Categories

The `models.py` Finding categories need expansion:

| Category | Current | New |
|----------|---------|-----|
| `sca` | Yes | — |
| `sast` | Yes | — |
| `supply_chain` | Yes | — |
| `secrets` | Yes | — |
| `iac` | Yes | — |
| `malware` | Yes | — |
| `binary_analysis` | Yes | — |
| `license` | Yes | — |
| `behavioral` | — | **New** — code does something suspicious (exfil, shell spawn, encoded exec) |
| `obfuscation` | — | **New** — high entropy, base64 blobs, minified payloads |
| `metadata` | — | **New** — maintainer changes, typosquatting signals, low Scorecard |
| `install_hook` | — | **New** — install script analysis results |

## What This Catches That We Currently Miss

| Attack Scenario | New Detection Layer | How |
|----------------|-------------------|-----|
| `event-stream` (maintainer takeover + injected stealer) | Registry metadata | Maintainer change between versions flagged; deps.dev Scorecard drop |
| `ua-parser-js` (hijack + cryptominer) | Entropy + Semgrep supply-chain rules | Obfuscated payload detected; download-and-execute pattern in install script |
| `colors`/`faker` protestware | Install hooks + behavioral Semgrep | Infinite loop in postinstall; process.exit in data handler |
| Typosquatting (`crossenv` vs `cross-env`) | deps.dev typosquatting endpoint | Name similarity + download count disparity |
| Dependency confusion (internal name on public registry) | Registry metadata | Package with < 10 downloads, recently published, name matches common internal patterns |
| Base64-encoded C2 in test fixture | Entropy analysis | High-entropy string > 40 chars in non-binary file flagged |
| `preinstall` curl to attacker domain | Install hook analysis + Semgrep supply-chain | Script detected with network I/O → critical finding |
| Backdoor in vendored dependency (not in any vuln DB) | GuardDog on dep source + behavioral Semgrep | Shell execution pattern detected in dep code |

## Network Requirements

New external API calls that need firewall whitelist entries:

| Domain | Purpose |
|--------|---------|
| `api.deps.dev` | OpenSSF Scorecard, typosquatting, version history |
| `registry.npmjs.org` | npm package metadata |
| `pypi.org` | PyPI package metadata |

These need to be added to the Lima `hostResolver` config and the iptables whitelist in `vm_scripts/firewall.sh` (per the network hardening spec).

## What This Does NOT Add (and Why)

| Capability | Why Not |
|-----------|---------|
| **Dynamic sandbox execution** (run install scripts, trace syscalls) | Requires gVisor or Firecracker inside the VM — significant complexity. The static behavioral analysis catches 80%+ of the same patterns without execution risk. Revisit in v3. |
| **Real-time registry monitoring** (watch for new malicious packages) | We scan on-demand, not continuously. We're not a registry firewall. |
| **ML-based anomaly detection** (Sonatype-style unsupervised models) | Requires training data and infrastructure we don't have. The AI analysis layer downstream serves a similar purpose using LLM reasoning instead. |
| **SLSA provenance verification** | Most packages don't publish provenance yet. Low signal-to-noise. |
| **Full dependency graph resolution** | deps.dev provides this — we query it rather than building our own resolver. |

## Files Modified/Created

| File | Change |
|------|--------|
| `rules/semgrep/supply-chain.yaml` (new) | Custom Semgrep rules for supply chain behavioral patterns |
| `src/threat_scanner/scanners/entropy.py` (new) | Entropy and obfuscation analysis module |
| `src/threat_scanner/scanners/install_hooks.py` (new) | Install script detection and classification |
| `src/threat_scanner/scanners/deps_dev.py` (new) | deps.dev API integration (Scorecard, typosquatting, version history) |
| `src/threat_scanner/scanners/registry_meta.py` (new) | Registry metadata checks (npm, PyPI) |
| `src/threat_scanner/scanners/runner.py` | Add Phase 5 (supply chain analysis on deps), reorder phases |
| `src/threat_scanner/scanners/models.py` | Add `behavioral`, `obfuscation`, `metadata`, `install_hook` categories |
| `src/threat_scanner/scanners/guarddog.py` | Add second pass against dep source directory |
| `src/threat_scanner/scanners/semgrep.py` | Add second pass with custom supply-chain rules against deps |
| `docker/scripts/run.sh` | Run entropy analysis and install hook detection inside container |
| `lima/scanner.yaml` | Add `api.deps.dev`, `registry.npmjs.org`, `pypi.org` to hostResolver |
| `vm_scripts/firewall.sh` | Whitelist new API domains |

## Implementation Order

1. **Custom Semgrep rules** (`supply-chain.yaml`) — highest impact, lowest effort. Write rules, add a second Semgrep pass in the runner.
2. **Install hook analysis** — parse manifests for install scripts, classify by risk. Small focused module.
3. **GuardDog on dep source** — one-line change to run GuardDog against `/work/deps/` in addition to `/work/target`.
4. **Entropy analysis** — pure Python module, no external dependencies.
5. **deps.dev integration** — API calls with JSON parsing, add firewall rules.
6. **Registry metadata checks** — similar to deps.dev but queries registries directly. Can be phased by ecosystem (npm first, then PyPI).
7. **Update Finding model** — add new categories, update runner phases.
8. **Integration testing** — run against known-malicious package samples (Socket.dev publishes sample malware packages for testing).

## Open Questions

1. **Where does metadata scanning run?** deps.dev and registry metadata queries need network access. Options: (a) inside the scanner-deps container before `--network=none` takes effect, (b) from the VM directly (already has firewalled network), (c) from the host (no VM boundary but simpler). Recommendation: from the VM, since the firewall whitelist already controls egress.

2. **Custom Semgrep rules maintenance**: Who maintains the supply-chain ruleset? We could start with a curated set and evolve based on AI analysis feedback — when the AI flags something the static scanners missed, consider whether a Semgrep rule could catch it next time.

3. **Scoring integration**: How do the new finding categories feed into the composite priority scoring in `scoring.py`? Proposal: `behavioral` and `install_hook` findings with network/exfil indicators get automatic `high` or `critical` composite priority. `metadata` findings (Scorecard, typosquatting) get `medium` unless combined with other signals.

4. **Performance budget**: The current 15-scanner parallel phase completes in the time of the slowest scanner (~2-3 minutes). Adding Phase 5 with API calls to deps.dev and registries could add network latency. Batch and parallelize API calls aggressively.
