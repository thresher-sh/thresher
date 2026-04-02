# InfoSec Background

A primer on the security concepts, attack types, and industry standards that Thresher is designed to detect and report on. This document is for anyone who wants to understand the "why" behind the tool's design.

## Supply Chain Security

### What Is a Software Supply Chain?

Your application doesn't exist in isolation. It depends on:

- **Direct dependencies** — packages you explicitly import
- **Transitive dependencies** — packages your dependencies depend on
- **Build tools** — compilers, bundlers, CI/CD pipelines
- **Registries** — PyPI, npm, crates.io, Go proxy
- **Infrastructure** — container images, cloud services

Each of these is a link in your software supply chain. An attacker who compromises any link can inject malicious code into your application without touching your source code.

### Why Supply Chain Attacks Matter

Supply chain attacks are asymmetric: one compromised package can affect thousands of downstream consumers. Notable incidents:

| Incident | Year | Impact |
|----------|------|--------|
| **SolarWinds** (SUNBURST) | 2020 | Backdoor in build system affected 18,000+ organizations including US government agencies |
| **event-stream** | 2018 | npm package maintainer transferred ownership to attacker who injected cryptocurrency theft code |
| **ua-parser-js** | 2021 | Popular npm package hijacked to install cryptominers and credential stealers |
| **PyPI malware campaigns** | 2022-present | Hundreds of typosquatted packages on PyPI targeting developers |
| **xz utils** (CVE-2024-3094) | 2024 | Multi-year social engineering campaign to backdoor a core Linux compression library |
| **Codecov** | 2021 | CI tool compromise led to credential theft from thousands of repos |

### Attack Taxonomy

#### Typosquatting

Registering package names that are slight misspellings of popular packages:

```
requests  →  reqeusts, request, python-requests
lodash    →  lodahs, l0dash
```

When a developer makes a typo in `pip install` or `npm install`, they get the attacker's package instead. **GuardDog** is specifically designed to detect this.

#### Dependency Confusion

Exploiting the priority order of package registries. If a company uses a private registry with a package called `internal-auth`, an attacker can publish a package with the same name on the public registry with a higher version number. Package managers may prefer the public version.

#### Install Hook Attacks

Injecting malicious code into lifecycle scripts that run during package installation:

| Ecosystem | Hook | File |
|-----------|------|------|
| Python | `setup.py` execution | `setup.py`, `.pth` files |
| Node | `postinstall`, `preinstall` | `package.json` scripts |
| Rust | `build.rs` | Build script |

This is why Thresher downloads dependencies as **source only** without executing install hooks.

#### Backdoors and Data Exfiltration

Code that secretly:
- Sends environment variables, SSH keys, or API tokens to an attacker
- Opens a reverse shell for remote access
- Executes base64-encoded payloads
- Phones home to a C2 (command and control) server
- Activates only on specific hostnames, usernames, or in CI environments (targeted execution)

The AI Analyst agent specifically hunts for these patterns.

#### CI/CD Pipeline Compromise

Attackers target:
- GitHub Actions workflows with `pull_request_target` (runs with repo secrets on untrusted PR code)
- Unpinned action versions (`uses: action@main` instead of `uses: action@v1.2.3`)
- Self-hosted runners that persist state between jobs
- Build scripts that download and execute remote resources

## Vulnerability Scoring Systems

### CVSS (Common Vulnerability Scoring System)

CVSS is the industry standard for rating vulnerability severity. Version 3.1 produces a score from 0.0 to 10.0:

| Score Range | Severity |
|-------------|----------|
| 9.0 - 10.0 | Critical |
| 7.0 - 8.9 | High |
| 4.0 - 6.9 | Medium |
| 0.1 - 3.9 | Low |
| 0.0 | None |

CVSS measures the **potential impact** of a vulnerability — how bad it could be if exploited. It does **not** measure how likely exploitation is.

### EPSS (Exploit Prediction Scoring System)

EPSS complements CVSS by estimating the **probability** that a vulnerability will be exploited in the wild in the next 30 days. Scores range from 0.0 to 1.0 (0% to 100%).

| EPSS Score | Meaning |
|------------|---------|
| > 0.9 | Very high exploitation likelihood |
| 0.75 - 0.9 | High exploitation likelihood |
| 0.5 - 0.75 | Moderate exploitation likelihood |
| < 0.5 | Lower exploitation likelihood |

**Why both CVSS and EPSS?** A vulnerability can have a high CVSS score (severe impact) but low EPSS score (unlikely to be exploited) — for example, a complex attack that requires physical access. Conversely, a medium-CVSS vulnerability with a high EPSS score is more urgent because it's actively being exploited.

Thresher uses both signals in its [priority computation](scoring-and-reports.md).

### CISA KEV (Known Exploited Vulnerabilities)

The [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) is maintained by the US Cybersecurity and Infrastructure Security Agency. It lists vulnerabilities that are **confirmed to be actively exploited** in the wild.

A CVE in the KEV catalog is the strongest signal that immediate action is needed. Thresher assigns **P0 priority** (the highest) to any finding in the KEV catalog.

## Scanner Categories

### SCA (Software Composition Analysis)

SCA tools identify known vulnerabilities in your dependencies by comparing package names and versions against vulnerability databases:

- **NVD** (National Vulnerability Database) — US government CVE database
- **OSV** (Open Source Vulnerabilities) — Google's multi-ecosystem vulnerability database
- **GitHub Advisory Database** — Curated advisories from GitHub
- **RustSec** — Rust-specific advisory database
- **Go Vulnerability Database** — Go-specific advisories with call-graph analysis

Tools in this project: **Grype**, **OSV-Scanner**, **Trivy**, **govulncheck**, **cargo-audit**

### SAST (Static Application Security Testing)

SAST tools analyze source code for vulnerability patterns without executing it:

- SQL injection
- Cross-site scripting (XSS)
- Command injection
- Insecure deserialization
- Weak cryptography
- Path traversal

Tools in this project: **Semgrep**, **Bandit**

### IaC (Infrastructure as Code) Security

IaC scanners check configuration files for security misconfigurations:

- Docker: Running as root, using `latest` tag, exposing unnecessary ports
- Terraform: Missing encryption, overly permissive IAM policies
- Kubernetes: Privileged containers, missing network policies
- CloudFormation: Unencrypted storage, public access

Tools in this project: **Checkov**, **Hadolint**, **Trivy**

### Secrets Detection

Scanning for hardcoded credentials that should be in environment variables or a secrets manager:

- API keys (AWS, GCP, Stripe, etc.)
- Passwords and tokens
- Private keys (SSH, TLS)
- Database connection strings

Tool in this project: **Gitleaks**

### Malware Detection

Identifying known malware signatures and suspicious binary capabilities:

- **Signature-based**: Matching against databases of known malware patterns (YARA rules, ClamAV signatures)
- **Behavioral**: Identifying capabilities like networking, file encryption, persistence mechanisms (capa)

Tools in this project: **YARA**, **capa**, **ClamAV**

### Supply Chain Analysis

Tools specifically designed to detect supply chain attack patterns:

- Suspicious package behaviors (exfiltration during install)
- Typosquatting detection
- Unusual dependency patterns

Tool in this project: **GuardDog**

### License Compliance

Detecting licenses that may conflict with your project's licensing:

- **Copyleft licenses** (GPL, AGPL, LGPL) require derivative works to use the same license
- **Permissive licenses** (MIT, BSD, Apache 2.0) allow most uses
- Detection from actual file contents, not just manifests (which can be wrong)

Tool in this project: **ScanCode**

## SBOM (Software Bill of Materials)

An SBOM is a formal, machine-readable inventory of all components in a software project. Think of it as an ingredient list for software. The **CycloneDX** format (used by Syft in this project) includes:

- Component name, version, and package URL (purl)
- License information
- Dependency relationships
- Hash values for integrity verification

SBOMs are increasingly required by regulation (e.g., US Executive Order 14028) and are essential for supply chain transparency.

## The MITRE ATT&CK Framework

[MITRE ATT&CK](https://attack.mitre.org/) is a knowledge base of adversary tactics and techniques. The **capa** scanner in this project maps binary capabilities to ATT&CK techniques, helping identify what a binary *can do* (e.g., "T1071: Application Layer Protocol" means the binary can communicate over HTTP).

## Further Reading

### Supply Chain Security
- [SLSA (Supply-chain Levels for Software Artifacts)](https://slsa.dev/) — Framework for supply chain integrity
- [OpenSSF Scorecard](https://securityscorecards.dev/) — Automated security health checks for open source
- [Sigstore](https://www.sigstore.dev/) — Cryptographic signing for software artifacts
- [NIST SSDF](https://csrc.nist.gov/Projects/ssdf) — Secure Software Development Framework

### Vulnerability Management
- [NVD](https://nvd.nist.gov/) — National Vulnerability Database
- [FIRST EPSS](https://www.first.org/epss/) — Exploit Prediction Scoring System
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) — Known Exploited Vulnerabilities
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document) — Scoring methodology

### Offensive Research (for defenders)
- [Backstabber's Knife Collection](https://dasfreak.github.io/Backstabbers-Knife-Collection/) — Catalog of malicious packages
- [Socket.dev Blog](https://socket.dev/blog) — Supply chain attack analysis
- [Phylum Research](https://blog.phylum.io/) — Malicious package detection research
