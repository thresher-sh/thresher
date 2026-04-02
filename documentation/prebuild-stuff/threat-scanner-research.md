# Project Threat Scanner: Architecture and Implementation Guide

**Lima + Claude Code + GuardDog form the optimal stack for an AI-powered supply chain security scanner on macOS — but the real differentiator is Claude acting as both orchestrator and direct code analyst.** This system layers deterministic scanning tools (SCA, SAST, behavioral analysis) with non-deterministic AI-driven code review, where Claude agents read and reason about every file in a project and its resolved dependencies, hunting for malicious patterns that no rule set could anticipate. The architecture runs entirely inside an isolated VM with strict network egress controls, uses Claude Code's headless mode with sub-agent orchestration to coordinate both tool execution and direct code analysis, and produces a unified risk report scored against CVSS v4.0, EPSS, and CISA KEV data.

---

## Why Trivy is excluded from this stack

Trivy is explicitly excluded. On February 28, 2026, an autonomous bot called hackerbot-claw exploited a misconfigured `pull_request_target` workflow in Trivy's GitHub Actions, extracting a privileged Personal Access Token. Aqua Security rotated credentials but the rotation was not atomic — the attackers retained access to tokens that survived the process.

Three weeks later, on March 19, 2026, the same group (TeamPCP) used those surviving credentials to execute one of the most sophisticated supply chain attacks ever documented against a security tool. They force-pushed 76 of 77 version tags in `aquasecurity/trivy-action` to malicious commits containing an infostealer. Simultaneously, they published a trojanized Trivy binary as v0.69.4 across GitHub Releases, GHCR, Docker Hub, and package repositories. Every CI/CD pipeline referencing Trivy by version tag began executing attacker-controlled code that harvested runner secrets, cloud credentials, SSH keys, and npm tokens.

On March 22, 2026, a third wave hit — the attackers pushed additional malicious Docker Hub images (v0.69.5, v0.69.6) using separately compromised Docker Hub credentials, bypassing all GitHub-based controls. They then used a stolen service account token bridging two GitHub organizations to deface all 44 repositories in Aqua's `aquasec-com` organization, exposing proprietary source code. Stolen npm tokens were weaponized to propagate CanisterWorm across dozens of npm packages.

Two breaches in under a month, with incomplete remediation enabling cascading compromise, disqualifies Trivy from any trust-sensitive security scanning pipeline. Grype and OSV-Scanner provide equivalent or superior SCA coverage without this risk.

---

## The two-layer scanning philosophy: deterministic + non-deterministic

This is the core architectural insight: **deterministic tools catch what is known; Claude agents catch what is novel.** Running only static rule-based scanners is like defending a castle with a list of known attackers' faces — it works until someone shows up in disguise. Running only AI analysis risks hallucinations and missed patterns that simple regex would catch instantly. You need both.

**Layer 1 — Deterministic scanning** uses traditional open-source tools that match against known vulnerability databases, rule sets, and behavioral signatures. These are fast, reproducible, and have zero false-negative rates for their specific rule sets. They form the floor of the analysis.

**Layer 2 — Non-deterministic AI analysis** uses Claude agents to read, comprehend, and reason about source code the way a human security researcher would. Claude traces data flows, understands intent behind obfuscation, evaluates whether code behavior matches its stated purpose, and catches the novel zero-day patterns that no deterministic tool has rules for. This is the ceiling of the analysis — the part that finds the xz-utils backdoor before Andres Freund notices a 500ms latency anomaly.

The two layers feed into a synthesis agent that cross-references findings, de-duplicates, and scores everything into a unified report.

---

## Layer 1: deterministic scanning toolkit (14 tools)

A single scanner catches roughly 60–65% of vulnerabilities in a codebase. Running complementary tools across four categories — SCA, SAST, supply chain behavioral analysis, and secrets detection — closes the gap.

### Software Composition Analysis (known CVEs in dependencies)

**Grype** (Anchore, Apache 2.0) pairs with **Syft** for an SBOM-first workflow: Syft generates a CycloneDX SBOM across 24 ecosystems, then Grype scans it with composite EPSS + KEV + CVSS risk scoring and OpenVEX support. **OSV-Scanner** (Google, Apache 2.0) adds call-graph reachability analysis that reduces false positives by determining whether vulnerable code paths are actually invoked, and its database includes `MAL` entries for known malicious packages. Running both catches significantly more than either alone.

Language-specific scanners fill ecosystem gaps: **pip-audit** for Python, **npm audit** for Node.js, **cargo-audit** for Rust. **OWASP Dependency-Check** provides broad coverage with its NVD-backed database across Java, .NET, Python, Ruby, and Node.js.

### Static Analysis (code vulnerabilities)

**Semgrep** (LGPL-2.1 core) runs in 10–30 seconds across 30+ languages with 20,000+ community rules including supply-chain-specific rulesets. **Bandit** catches Python-specific patterns Semgrep misses (hardcoded passwords, weak crypto, shell injection via AST analysis). **CodeQL** (free for open source) provides the deepest semantic analysis with cross-file taint tracking — best reserved for scheduled deep scans. **Checkov** (Apache 2.0) covers Terraform, CloudFormation, Kubernetes, and Dockerfiles with 750+ built-in policies.

### Supply chain behavioral analysis (malicious code detection)

Most SCA tools only match known CVE identifiers — they cannot detect a newly published typosquatting package or an import-time credential harvester. Three tools specifically target malicious behavior:

**GuardDog** (Datadog, Apache 2.0) uses Semgrep and YARA rules to detect typosquatting, obfuscated exfiltration, base64-encoded payloads, suspicious install scripts, and environment variable theft across PyPI, npm, Go, RubyGems, and GitHub Actions. It achieved 94.38% accuracy on npm in WWW '26 benchmarks and has identified 19,171+ malicious packages.

**Packj** (AGPL-3.0) uniquely combines static analysis, dynamic sandboxed installation tracing (via strace), and metadata checks. It detects repo-vs-package code mismatches, expired maintainer email domains, and missing 2FA. Its sandbox catches install-time payloads that static tools miss.

**Heisenberg** (AppOmni, open source) checks supply chain health via the deps.dev API — flagging typosquatting, deprecated packages, and suspiciously fresh publications (<24 hours old).

### Secrets detection

**Gitleaks** scans git history and current files for API keys, tokens, passwords, and certificates using regex patterns.

---

## Layer 2: non-deterministic AI code analysis (the differentiator)

This is where Project Threat Scanner diverges from every existing tool. Claude doesn't just orchestrate scanners — it reads the code itself. Every file. Every dependency. Like a team of paranoid security researchers with infinite patience.

### Why AI code analysis catches what tools miss

The LiteLLM attack embedded triple-nested base64-encoded credential harvesting inside `proxy_server.py`. A `.pth` file placed in `site-packages/` executed on every Python interpreter startup — no import required. The payload collected SSH keys, AWS/GCP/Azure credentials, Kubernetes secrets, and cryptocurrency wallets, encrypted them with a hardcoded 4096-bit RSA key, and exfiltrated to an attacker-controlled domain.

The xz-utils backdoor hid in binary "test" files only present in release tarballs, not GitHub source. It hooked OpenSSH's `RSA_public_decrypt` via glibc IFUNC resolvers to enable unauthenticated remote code execution. Two years of social engineering preceded it. No scanner had a rule for it because it was entirely novel.

These attacks share a trait: they require *understanding* code, not matching patterns. An LLM reading the xz-utils build scripts could reason that test fixtures shouldn't contain compressed executables that get injected into shared libraries. An LLM reading a `setup.py` can understand that base64-decoding a string and passing it to `exec()` at install time is suspicious regardless of what specific string it decodes.

Research validates this approach. The LAMPS system (2026) uses a multi-agent LLM pipeline — package retrieval, file extraction, classification, and verdict aggregation — achieving strong detection rates on malicious PyPI packages. Apiiro's Logical Code Patterns (LCPs) use LLMs to capture the semantic essence of code behavior and cluster it against known malicious patterns in a vector database. Anthropic's own Claude Code Security, using Opus 4.6, found over 500 previously unknown vulnerabilities in production open-source codebases, including bugs undetected for decades.

### The AI analysis pipeline: how Claude reads every file

The non-deterministic scanning layer operates as a multi-phase pipeline with specialized sub-agents. Each phase has its own system prompt, tool restrictions, and output schema.

**Phase 1: Project Reconnaissance Agent**

This agent inventories the target project — mapping directory structure, identifying entry points, understanding the build system, cataloging all dependency declarations (package.json, requirements.txt, Cargo.toml, go.mod, etc.), and identifying the language/framework stack. It produces a structured manifest that guides all subsequent agents.

```
System prompt: "You are a software architect performing a security reconnaissance.
Map the project structure, identify all dependency declarations, entry points,
build scripts, CI/CD configs, and deployment manifests. Output a structured
JSON manifest. Do NOT execute any code."

Tools allowed: Read, Glob, Grep
```

**Phase 2: Dependency Resolution and Download Agent**

This agent resolves the full transitive dependency tree and downloads all dependency source code into a staging directory for analysis. It uses the project's native package manager (npm, pip, cargo, etc.) to install dependencies locally, then extracts or locates the actual source files.

```
System prompt: "You are a dependency resolver. Install all project dependencies
into an isolated directory. For each dependency, record: name, version,
registry source, SHA hash, and filesystem path to its source code.
Flag any dependency that: has no source repository, was published <7 days ago,
has a single maintainer, or shows version number anomalies."

Tools allowed: Read, Bash (restricted to package manager commands)
```

**Phase 3: File-by-File Code Analysis Agents (parallelized)**

This is the heart of the system. Multiple sub-agents (up to 7 simultaneously via Claude Code's Task tool) each receive batches of source files and analyze them for malicious intent. Each agent applies a consistent analytical framework:

```
System prompt: "You are a senior security researcher specializing in supply chain
attacks. For each file, analyze:

1. INTENT ANALYSIS: What is this code supposed to do? Does the actual behavior
   match the stated/implied purpose? Flag mismatches.

2. SUSPICIOUS PATTERNS: Look for but do not limit yourself to:
   - Import-time or install-time code execution (setup.py, __init__.py, .pth files)
   - Obfuscation: base64/hex encoding, eval/exec chains, dynamic imports,
     string concatenation to build function calls, chr() assembly
   - Network activity: HTTP requests, DNS lookups, socket connections,
     especially to hardcoded IPs or unusual domains
   - Environment harvesting: reading env vars, ~/.ssh/*, ~/.aws/*, tokens,
     credentials, wallet files
   - File system writes outside expected directories
   - Process spawning, especially shells or interpreters
   - Steganographic payloads in non-code files (images, test fixtures, fonts)
   - IFUNC/LD_PRELOAD/dlopen patterns that hook system libraries
   - Conditional execution based on hostname, username, or environment
     (targeting specific victims)

3. DEPENDENCY PROVENANCE: For dependency files, assess:
   - Does the code match what you'd expect from the package description?
   - Are there files that don't belong (binary blobs, .pth files, extra scripts)?
   - Is there a mismatch between the GitHub repo code and the published package?

4. RISK RATING: Rate each file 0-10:
   0: No suspicious patterns whatsoever
   1-3: Minor concerns (e.g., dynamic imports for legitimate metaprogramming)
   4-6: Moderate concerns requiring human review
   7-8: Strong indicators of malicious intent
   9-10: Almost certainly malicious (active exfiltration, backdoor, trojan)

Output structured JSON per file with: path, risk_score, findings[], reasoning."

Tools allowed: Read, Grep
```

Critical design decisions for this phase:

- **Strip comments and normalize identifiers before analysis for high-risk files.** Research shows LLMs are susceptible to "confirmation bias" — misleading comments can cause false negatives. When a file triggers initial suspicion (risk ≥ 4), a second-pass analysis strips all comments and variable names, analyzing purely behavioral patterns.

- **Batch sizes tuned to context window.** Each sub-agent receives files in batches sized to fit within the context window with room for analysis output. Small files (< 500 lines) can be batched 5-10 at a time; larger files get individual analysis.

- **Cross-file analysis for connected components.** After individual file analysis, a dedicated agent examines connections between flagged files — tracing imports, data flows, and execution chains across module boundaries.

**Phase 4: Adversarial Verification Agent (Red Team)**

Every finding with risk ≥ 4 from Phase 3 goes through adversarial verification. This agent's job is to *disprove* the finding — to argue that the code is benign. This mirrors Claude Code Security's approach where each finding undergoes an adversarial pass that re-examines results before surfacing them.

```
System prompt: "You are a defense attorney for code. For each flagged finding,
attempt to construct a legitimate explanation. Consider:
- Is this a common pattern in this ecosystem? (e.g., webpack plugins need eval)
- Is the obfuscation for minification, not concealment?
- Is the network call to a known legitimate API?
- Is there a clear, documented reason for this behavior?

If you cannot construct a convincing benign explanation, the finding stands.
If you can, downgrade the risk score and document your reasoning.
You must be HONEST — do not invent justifications that don't hold up."

Tools allowed: Read, Grep, Bash (curl for checking if domains are legitimate)
```

**Phase 5: Dependency Comparison Agent**

For every external dependency, this agent compares the installed (registry-published) version against the source code in the linked GitHub/GitLab repository. Mismatches between published packages and their stated source repos are a key indicator of supply chain compromise — this is exactly how the LiteLLM attack worked (malicious versions published to PyPI had no corresponding GitHub release).

```
System prompt: "You are a forensic analyst specializing in package provenance.
For each dependency:
1. Compare the installed package files against the Git repository at the
   declared version tag
2. Flag any files present in the package but absent from the repo
3. Flag any code differences between repo and package, especially in
   setup.py, __init__.py, and entry points
4. Check package metadata: publication date, maintainer changes,
   version number anomalies (skipped versions, rapid re-releases)"

Tools allowed: Read, Grep, Bash (git clone, diff)
```

**Phase 6: Synthesis Agent**

The final agent merges all findings from both layers — deterministic tool output and AI analysis — into a unified, de-duplicated report. Where the AI analysis and tool findings agree, confidence is boosted. Where they disagree, both perspectives are presented with reasoning.

### Handling AI limitations: the confirmation bias problem

Recent research (2026) demonstrates that adversarial framing in commit messages and PR descriptions can cause LLMs to miss vulnerabilities — succeeding 35% of the time against interactive assistants and 88% against autonomous agents in real project configurations. However, the same research found that metadata redaction and explicit debiasing instructions restored detection in 94%+ of cases.

Project Threat Scanner addresses this through architectural countermeasures:

- **Metadata redaction**: The code analysis agents never see commit messages, PR descriptions, or README content during behavioral analysis. They analyze raw code in isolation.
- **Comment stripping on re-analysis**: Files flagged at risk ≥ 4 get a second pass with all comments removed. Research from Endor Labs showed that misleading comments (e.g., "This code seems benign since it only downloads additional code") can fool LLMs into classifying malware as harmless.
- **Adversarial verification**: Every significant finding must survive an agent actively trying to disprove it.
- **Ensemble approach**: The AI analysis is one signal among many. If GuardDog flags a package as malicious and the AI says it's fine, that disagreement itself is surfaced as a finding.

---

## Lima replaces Vagrant for Apple Silicon isolation

VirtualBox on Apple Silicon remains immature and buggy — VirtualBox 7.1+ added ARM64 host support but performance lags significantly, and Vagrant box availability for ARM64 is scarce. Firecracker requires Linux KVM and cannot run natively on macOS. OrbStack explicitly states it does not provide isolation for untrusted code.

**Lima** (CNCF Incubating, Apache 2.0, v2.1) is the clear winner. It uses the Apple Virtualization Framework (`vz` backend) for near-native performance, provides a fully scriptable CLI (`limactl`), and has purpose-built flags for security isolation: `--plain` disables the guest agent and all port forwarding, `--mount-none` disables all host directory mounts.

```bash
# Install Lima
brew install lima

# Create an isolated scanning VM — no mounts, no port forwarding
limactl create --name=scanner \
  --vm-type=vz \
  --cpus=4 \
  --memory=8GiB \
  --disk=50GiB \
  --mount-none \
  --plain \
  --tty=false \
  template://ubuntu-lts

limactl start scanner
```

With `--plain`, the VM is accessible only via SSH. Inside the VM, iptables rules enforce strict network egress — allowing only the Claude API (`api.anthropic.com`), GitHub (`github.com`), vulnerability databases (`api.first.org`, `services.nvd.nist.gov`), and package managers during provisioning:

```bash
iptables -P OUTPUT DROP
iptables -A OUTPUT -p tcp --dport 443 -d api.anthropic.com -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -d github.com -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -d api.first.org -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT  # DNS resolution
iptables -A OUTPUT -j LOG --log-prefix "BLOCKED: " --log-level 4
iptables -A OUTPUT -j DROP
```

This ensures scanned code cannot phone home — even if a malicious package attempts to exfiltrate data during dependency installation for the comparison agent, the iptables rules block all non-whitelisted connections. Blocked connection attempts are logged as an additional signal (exfiltration attempt detection).

**Tart** (Cirrus Labs, Fair Source License) is the runner-up, offering OCI registry-based VM image distribution and Packer integration. **VMware Fusion** (now free) provides the best traditional Vagrant integration on Apple Silicon via `vagrant-vmware-desktop` plugin with ARM64 boxes.

---

## Claude Code orchestrates both layers

Claude Code's headless mode (`-p` flag) transforms it into a fully scriptable CLI tool that works without user interaction. Combined with the Agent SDK and sub-agent Task tool, it becomes the orchestration brain of the entire scanning pipeline.

### Headless execution

```bash
claude -p "Analyze scan results in /opt/scan-results/ and generate a security report" \
  --allowedTools "Read,Glob,Grep,Bash" \
  --output-format json \
  --max-turns 20
```

### Multi-turn phased scanning

A `--session-id` maintains context across invocations:

```bash
# Phase 1: Deterministic tools
claude -p "Run all deterministic scanners" --session-id "audit-001" > phase1.json

# Phase 2: AI code analysis
claude -p "Begin non-deterministic code analysis" --resume --session-id "audit-001" > phase2.json

# Phase 3: Synthesis
claude -p "Generate final risk report" --continue --output-format json > phase3.json
```

### Sub-agent orchestration via Task tool

The Task tool spawns specialized sub-agents, each with its own context window and tool restrictions. Up to 7 sub-agents run simultaneously. The architecture maps directly to the scanning phases:

```
              Orchestrator Agent
             /    |    |    |    \
         Recon  Dep    SAST  SCA  Secrets
         Agent  Resolver Agent Agent Agent
                  |
           ┌──────┴──────┐
           │  Downloaded  │
           │ Dependencies │
           └──────┬──────┘
                  |
     ┌────────────┼────────────┐
     |            |            |
  AI Code     AI Code     AI Code
  Analyst 1   Analyst 2   Analyst N
  (files 1-50) (files 51-100) (files N...)
     |            |            |
     └────────────┼────────────┘
                  |
          Adversarial Verifier
                  |
          Dep Comparison Agent
                  |
          Synthesis Agent → Final Report
```

### The Claude Agent SDK for programmatic control

```python
from claude_agent_sdk import query, ClaudeAgentOptions

# Run a code analysis sub-agent
async for message in query(
    prompt="Analyze all Python files in /opt/target/src/ for malicious patterns. "
           "Strip comments before analysis. Output structured JSON findings.",
    options=ClaudeAgentOptions(
        allowed_tools=["Read", "Glob", "Grep"],
        system_prompt=SECURITY_ANALYST_PROMPT,
        output_format="json",
        json_schema=finding_schema,
    ),
):
    process(message)
```

### Skills for reusable security workflows

A `SKILL.md` file in `.claude/skills/` defines instructions Claude loads automatically. The security-audit skill would instruct Claude to apply the Phase 3 analysis framework, check EPSS percentiles, cross-reference CISA KEV, and apply CVSS v4.0 scoring. The community `awesome-claude-skills` repository includes pre-built skills for CodeQL/Semgrep analysis, variant analysis, and vulnerability detection.

### OpenClaw and the loop-until-done pattern

**OpenClaw** (247k GitHub stars) provides session management, effort control, and NDJSON streaming for long-running agent tasks. The **ClaudeClaw** pattern implements loop-until-done orchestration where the agent works on heartbeats — checking progress, re-evaluating strategy, and continuing until the analysis is complete rather than stopping after a single prompt response. For Project Threat Scanner, this pattern ensures the AI code analysis phase doesn't bail out early on a large codebase — it keeps working through every file until complete.

The **ECC Tools / AgentShield** project demonstrates the red-team/blue-team/auditor pipeline pattern directly applicable here — using three Opus 4.6 agents where an attacker finds exploit chains, a defender evaluates protections, and an auditor synthesizes both into a prioritized risk assessment.

---

## Risk scoring: CVSS + EPSS + KEV + AI confidence

Raw scanner output plus AI findings would overwhelm. The report layer must de-duplicate, enrich, and prioritize.

### Scoring frameworks

**CVSS v4.0** measures severity with separate impact metrics for vulnerable and subsequent systems, plus new Attack Requirements and expanded User Interaction metrics. Scores map to None (0.0), Low (0.1–3.9), Medium (4.0–6.9), High (7.0–8.9), and Critical (9.0–10.0).

**EPSS** predicts the probability a CVE will be exploited in the wild within 30 days. Only 2–7% of vulnerabilities are ever exploited. Available via REST API (`api.first.org/data/v1/epss?cve=CVE-2024-0001`), updated daily.

**CISA KEV** is the authoritative list of actively exploited CVEs. Any finding in KEV is emergency-priority regardless of CVSS score.

**AI Confidence Score** (new for this system) rates how confident the AI analysis is in each finding on a 0-100 scale. Findings where deterministic tools and AI analysis agree get boosted confidence. Findings from AI-only analysis include the adversarial verification outcome.

### Composite prioritization

| Priority | Criteria | SLA |
|----------|----------|-----|
| **P0 — Emergency** | In CISA KEV, or AI confidence ≥ 90 for active exfiltration/backdoor | Immediate |
| **Critical** | CVSS ≥ 9.0, or EPSS > 90th percentile, or AI risk 9-10 confirmed by adversarial pass | 24-48 hours |
| **High** | CVSS 7.0–8.9, EPSS > 75th, or AI risk 7-8 | 1 week |
| **Medium** | CVSS 4.0–6.9, EPSS > 50th, or AI risk 4-6 | 30 days |
| **Low** | CVSS 0.1–3.9, EPSS < 50th, AI risk 1-3 | 90 days |

### SBOM and provenance

**Syft** generates CycloneDX (preferred for security — native VEX support) and SPDX (ISO/IEC 5962:2021 for compliance). **OpenSSF Scorecard** evaluates the target project's security practices with 18+ automated checks. **SLSA** framework levels assess build provenance integrity.

### De-duplication

**DefectDojo** (OWASP Flagship) parses output from 200+ scanners and provides automated de-duplication, typically reducing 500 raw findings to ~150 unique issues.

---

## End-to-end architecture

```
HOST (macOS)                              VM (Ubuntu on Lima)
════════════                              ═══════════════════════════════

1. limactl create --plain                 VM boots, provisions tools
   --mount-none scanner                   (Node.js, Claude Code, Semgrep,
                                          Syft, Grype, GuardDog, Bandit,
2. limactl shell scanner --               Gitleaks, Checkov, Packj,
   "bash /opt/scripts/run-scan.sh         OSV-Scanner, pip-audit)
    https://github.com/org/repo"          Configures iptables firewall

                                     ─── DETERMINISTIC LAYER ───
                                     3.   git clone --depth=1 target repo
                                     4.   Syft → SBOM (CycloneDX + SPDX)
                                     5.   Grype → SCA vulnerabilities
                                     6.   OSV-Scanner → CVE + MAL entries
                                     7.   Semgrep → SAST findings
                                     8.   Bandit → Python-specific issues
                                     9.   GuardDog → malicious package detection
                                     10.  Gitleaks → secrets scan
                                     11.  Checkov → IaC misconfigurations

                                     ─── NON-DETERMINISTIC LAYER ───
                                     12.  Claude Agent: Project recon + manifest
                                     13.  Claude Agent: Resolve & download all deps
                                     14.  Claude Agents (x7 parallel): Read every
                                          file in project + deps, analyze for
                                          malicious intent, rate risk 0-10
                                     15.  Claude Agent: Adversarial verification
                                          of all findings risk ≥ 4
                                     16.  Claude Agent: Compare installed deps
                                          vs source repos for mismatches
                                     17.  EPSS enrichment via API

                                     ─── SYNTHESIS ───
                                     18.  Claude Agent: Merge deterministic +
                                          AI findings, de-duplicate, score,
                                          generate final report at
                                          /opt/security-reports/scan-latest/

14. scp report from VM               ←   Report stays in VM until retrieved
    (manual SSH retrieval only)            No shared folders, no auto-return

15. limactl delete scanner           →   VM destroyed, no residual data
```

### The orchestration script

The scan script inside the VM runs all deterministic tools first (parallel where possible), stores raw JSON output per tool, then launches the non-deterministic AI layer:

```bash
#!/bin/bash
# run-scan.sh — executed inside the Lima VM

REPO_URL=$1
SCAN_DIR="/opt/security-reports/$(date +%Y%m%d-%H%M%S)"
TARGET_DIR="/opt/target"

mkdir -p ${SCAN_DIR}/{scan-results,ai-analysis,sbom,final-report}

# Clone target
git clone --depth=1 ${REPO_URL} ${TARGET_DIR}

# === DETERMINISTIC LAYER (parallel where possible) ===
syft ${TARGET_DIR} -o cyclonedx-json > ${SCAN_DIR}/sbom/cyclonedx.json &
grype sbom:${SCAN_DIR}/sbom/cyclonedx.json -o json > ${SCAN_DIR}/scan-results/grype.json &
semgrep scan --config auto --json ${TARGET_DIR} > ${SCAN_DIR}/scan-results/semgrep.json &
bandit -r ${TARGET_DIR} -f json > ${SCAN_DIR}/scan-results/bandit.json &
gitleaks detect --source ${TARGET_DIR} --report-format json > ${SCAN_DIR}/scan-results/gitleaks.json &
wait

guarddog scan ${TARGET_DIR} --output-format json > ${SCAN_DIR}/scan-results/guarddog.json
osv-scanner scan --format json ${TARGET_DIR} > ${SCAN_DIR}/scan-results/osv.json

# === NON-DETERMINISTIC LAYER ===
claude -p "You are the orchestrator for a comprehensive security analysis.

PHASE 1: Read the project manifest and scan results in ${SCAN_DIR}/scan-results/.
PHASE 2: Resolve all dependencies and download their source code to /opt/deps/.
PHASE 3: Spawn sub-agents to analyze EVERY file in ${TARGET_DIR} and /opt/deps/
          for malicious patterns. Use the Task tool to run up to 7 parallel
          file analysis agents. Each agent should strip comments for files
          scoring risk >= 4 and re-analyze.
PHASE 4: Run adversarial verification on all findings with risk >= 4.
PHASE 5: Compare installed dependency packages against their source repositories.
PHASE 6: Synthesize ALL deterministic tool results AND AI analysis into a
          unified report with composite risk scores. Write to:
          ${SCAN_DIR}/final-report/report.md
          ${SCAN_DIR}/final-report/findings.json
          ${SCAN_DIR}/final-report/executive-summary.md" \
  --allowedTools "Read,Glob,Grep,Bash,Task" \
  --max-turns 50 \
  --output-format text
```

### Security design principles

- **No shared folders** between host and VM (`--mount-none`)
- **No auto-return** of files — all output stays in the VM
- **Network egress whitelisted** to Claude API, GitHub, and vulnerability databases only
- **All blocked connections logged** via iptables LOG target — blocked exfiltration attempts become findings
- **Ephemeral VMs** — `limactl delete` destroys all scan artifacts
- **API key via environment variable**, never stored in configuration files
- **Dependency installation happens inside the VM** behind the firewall — even if malicious install scripts try to phone home, they're blocked

---

## What this catches that nothing else does

| Attack Pattern | Deterministic Tools | AI Code Analysis | Both Together |
|---|---|---|---|
| Known CVE in dependency | ✅ Grype, OSV-Scanner | ❌ Not its job | ✅ |
| Typosquatting package name | ✅ GuardDog, Heisenberg | ✅ Package name analysis | ✅✅ High confidence |
| Base64-obfuscated exfiltration | ✅ GuardDog (YARA rules) | ✅ Decodes and reasons about payload | ✅✅ |
| Novel exfiltration technique (no rule exists) | ❌ | ✅ Understands intent | ✅ |
| .pth file auto-execution | ⚠️ Packj may catch | ✅ Flags unexpected .pth files | ✅✅ |
| Binary blob in test fixtures (xz-utils pattern) | ❌ | ✅ Flags non-code files in code paths | ✅ |
| IFUNC/LD_PRELOAD hooking | ❌ | ✅ Understands system-level implications | ✅ |
| Registry-vs-repo code mismatch | ❌ | ✅ Comparison agent | ✅ |
| Conditional targeting (specific hostname/user) | ❌ | ✅ Flags conditional execution patterns | ✅ |
| Compromised maintainer (social engineering) | ❌ | ⚠️ Can flag unusual code changes | ⚠️ Limited |
| Hallucinated/slopsquatted package names | ❌ | ✅ Validates package legitimacy | ✅ |

---

## Implementation roadmap

**Phase 1 (MVP — 1-2 weeks):** Lima VM + shell script running Grype, Semgrep, and GuardDog. Single Claude Code headless invocation synthesizing tool results into a report. Proves the isolation model and basic orchestration.

**Phase 2 (AI Analysis — 2-4 weeks):** Add the non-deterministic layer. Implement the six-agent pipeline. Start with project source files only (no dependency source analysis yet). Tune prompts against known-malicious packages from Datadog's malicious-software-packages-dataset.

**Phase 3 (Full Pipeline — 4-6 weeks):** Add dependency resolution and source download. Implement the comparison agent. Add adversarial verification. Integrate EPSS/KEV enrichment. Build the composite scoring system.

**Phase 4 (Hardening — ongoing):** Add OpenClaw loop-until-done patterns for large codebases. Implement DefectDojo for cross-tool de-duplication. Add continuous monitoring mode with cron scheduling. Build a validation suite using known supply chain attacks to measure detection rates.

---

## Conclusion

The fundamental insight is that deterministic scanning and non-deterministic AI analysis are complementary, not competing. Grype catches CVE-2024-3094 after it's catalogued; Claude catches the *next* xz-utils before anyone knows it exists. GuardDog matches known obfuscation patterns; Claude understands *why* someone would obfuscate code in a utility library. The two-layer architecture, running inside a Lima VM with strict isolation, creates a scanning system that is both thorough (deterministic floor) and creative (AI ceiling).

Three decisions matter most. First, **Lima with `--plain --mount-none`** provides stronger, simpler isolation than Vagrant + VirtualBox on Apple Silicon. Second, **Claude as both orchestrator and analyst** — not just running tools but reading every file — is the differentiator that catches novel supply chain attacks before they have signatures. Third, **adversarial verification of AI findings** (the red-team/blue-team pattern) addresses the known weakness of LLM confirmation bias, ensuring the non-deterministic layer's findings are trustworthy enough to act on.
