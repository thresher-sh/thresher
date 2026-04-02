# Watch Zones

The complete taxonomy of areas a security researcher evaluates when assessing an open-source package or repository. Organized from the most commonly tooled (top) to the least automated and most judgment-dependent (bottom).

These zones inform what our scanners detect, what our AI analysts should reason about, and what falls in the gaps between the two.

---

## Zone 1: Known Vulnerabilities

The reactive layer. Matching dependency versions against disclosed flaws.

| Signal | What To Look For |
|--------|-----------------|
| CVE matches | Direct hits in NVD, OSV, GHSA for declared dependencies |
| Transitive CVEs | Vulnerabilities in dependencies-of-dependencies not in the manifest |
| Reachability | Whether the vulnerable function is actually called (vs. dead code) |
| Fix availability | Whether a patched version exists and how far behind the project is |
| EPSS score | Probability the CVE is being actively exploited in the wild |
| CISA KEV status | Whether the CVE is in the Known Exploited Vulnerabilities catalog |
| Advisory lag | CVEs assigned but not yet enriched in NVD — incomplete severity data |

**Covered by**: Grype, OSV-Scanner, Trivy, govulncheck, cargo-audit, EPSS/KEV enrichment

---

## Zone 2: Code Quality & Security Patterns

Static analysis of the source code itself — what the target project wrote.

| Signal | What To Look For |
|--------|-----------------|
| Injection sinks | SQL injection, command injection, XSS, template injection, LDAP injection |
| Dangerous functions | `eval()`, `exec()`, `pickle.loads()`, `yaml.load()`, `torch.load()`, `unserialize()` |
| Hardcoded secrets | API keys, passwords, tokens, private keys embedded in source |
| Secrets in git history | Credentials committed and later removed (still in history) |
| Insecure cryptography | Weak algorithms (MD5, SHA1 for signing), hardcoded IVs, ECB mode |
| Path traversal | User-controlled input in file paths without sanitization |
| Deserialization | Untrusted data passed to deserializers (pickle, Java serialization, PHP unserialize) |
| Race conditions | TOCTOU bugs in file operations, unprotected shared state |
| Error handling | Stack traces leaked to users, catch-all exception swallowing |

**Covered by**: Semgrep, Bandit, Gitleaks

---

## Zone 3: Infrastructure & Configuration

Misconfigurations in deployment artifacts that weaken the security posture.

| Signal | What To Look For |
|--------|-----------------|
| Dockerfile issues | Running as root, unverified base images, secrets in build args, no health checks |
| Terraform/IaC misconfig | Public S3 buckets, overly permissive IAM, unencrypted storage, open security groups |
| Kubernetes misconfig | Privileged containers, hostPath mounts, missing network policies, default service accounts |
| CI/CD pipeline risks | Secrets in env vars, unpinned actions, script injection via PR titles/branch names |
| Exposed ports/services | Debug endpoints, admin panels, database ports in Docker Compose |

**Covered by**: Checkov, Hadolint

---

## Zone 4: Malware & Known-Bad Signatures

Pattern matching against databases of known malicious artifacts.

| Signal | What To Look For |
|--------|-----------------|
| Virus signatures | Known malware families (trojans, cryptominers, RATs) |
| Malware YARA patterns | Byte sequences, string patterns, structural markers from known campaigns |
| Packed/obfuscated binaries | UPX, custom packers, anti-analysis techniques in executables |
| Binary capabilities | Network access, keylogging, privilege escalation, file encryption in compiled binaries |
| Known malicious package IDs | OSV MAL-* identifiers for packages confirmed malicious by registries |

**Covered by**: ClamAV, YARA, capa, OSV-Scanner (MAL-* IDs)

---

## Zone 5: Dependency Behavioral Analysis

What the dependency code actually *does* — the behavioral layer that catches novel attacks with no CVE or signature.

| Signal | What To Look For |
|--------|-----------------|
| Network access in library code | `fetch()`, `http.request()`, `urllib`, `net.connect()` in packages that shouldn't need networking (parsers, formatters, validators) |
| Environment variable harvesting | Reads `process.env` / `os.environ` and sends values anywhere (HTTP, DNS, file write) |
| Filesystem access to sensitive paths | Reads `~/.ssh/*`, `~/.npmrc`, `~/.aws/credentials`, `~/.gnupg`, `~/.gitconfig`, `~/.docker/config.json` |
| Shell execution | `child_process.exec`, `subprocess.run`, `os.system`, `Runtime.exec` in library code |
| Download-and-execute | HTTP fetch piped to `eval`, `exec`, `Function()`, file write + execute |
| Dynamic code loading | Computed strings in `require()`, `import()`, `__import__()`, `importlib`, `dlopen` |
| Encoded/obfuscated payloads | Base64, hex, or unicode-escaped strings decoded at runtime and executed |
| Steganographic data | High-entropy content hidden in image files, comments, or data fixtures |
| Install script behavior | `preinstall`/`postinstall` hooks that do network I/O, spawn shells, or access credentials |
| Prototype pollution | `__proto__`, `constructor.prototype` manipulation in JS dependencies |
| Monkey-patching | Runtime modification of built-in types, standard library functions, or global state |

**Covered by**: GuardDog (partial), planned: custom Semgrep supply-chain rules, entropy analysis, install hook scanner

---

## Zone 6: Package Metadata & Supply Chain Signals

Signals that come from *around* the code — the registry, the maintainers, the publishing patterns — not from the code itself.

| Signal | What To Look For |
|--------|-----------------|
| Typosquatting | Package name 1-2 chars from a popular package, vastly lower download count |
| Dependency confusion | Internal/private package name published on public registry |
| Maintainer takeover | Ownership changed between versions, especially on high-download packages |
| Ghost accounts | Publisher with no other packages, no profile, created recently |
| Version anomalies | Patch release on old major version with high usage (targeting pinned users) |
| Publication timing | Package published and updated within minutes (automated attack tooling) |
| Install script introduction | Version N had no install scripts, version N+1 suddenly does |
| Tarball size spike | Package archive 10x larger than previous version (payload injection) |
| Registry/source mismatch | Package on npm/PyPI doesn't match the linked GitHub repo source |
| Expired maintainer domains | Author email domain is purchasable — potential account recovery attack |
| OpenSSF Scorecard | Low scores on branch protection, code review, CI, dependency pinning |
| Single-maintainer risk | Critical dependency with one maintainer, no org backing, no 2FA |

**Covered by**: GuardDog (Levenshtein only), planned: deps.dev integration, registry metadata checks

---

## Zone 7: License & Legal Compliance

Not a security vulnerability, but a legal and operational risk.

| Signal | What To Look For |
|--------|-----------------|
| Copyleft contamination | GPL, AGPL, LGPL, SSPL dependencies in proprietary projects |
| License changes | Dependency changed license between versions (e.g., MIT → SSPL) |
| Missing licenses | Dependencies with no declared license (legally ambiguous) |
| Conflicting licenses | Incompatible license combinations in the dependency tree |
| Export-controlled code | Cryptographic implementations subject to export restrictions |

**Covered by**: ScanCode

---

## Zone 8: Repository Health & Trust Signals

Indicators of whether the project is actively maintained and follows security best practices. Not vulnerabilities per se, but risk multipliers.

| Signal | What To Look For |
|--------|-----------------|
| Commit velocity | Has development stalled? Last commit 2+ years ago on a security-sensitive library |
| Issue/PR responsiveness | Security issues reported but unaddressed for months |
| Contributor diversity | Bus factor — does the project survive one person leaving? |
| Release hygiene | Tagged releases vs. commit-only, changelog maintenance, semantic versioning adherence |
| Security policy | Does the project have SECURITY.md? A vulnerability disclosure process? |
| Branch protection | Are PRs required? Code review? CI gates? |
| Dependency freshness | How far behind are the project's own dependencies? |
| Recent dependency additions | New deps added in the last 30-90 days — freshest links in the chain, least battle-tested |
| Fork/star trajectory | Sudden spikes in stars (star-farming for legitimacy) or abandonment patterns |
| CI/CD integrity | Signed commits, reproducible builds, pinned CI action versions |

**Covered by**: Partially via deps.dev/Scorecard. Mostly **uncovered by tooling** — this is where AI analyst reasoning adds the most value.

---

## Zone 9: Contextual & Cross-Signal Analysis

Findings that only emerge when correlating signals across zones. No single tool catches these — they require reasoning across the full picture.

| Signal | What To Look For |
|--------|-----------------|
| Low-severity CVE + reachable + no fix + high EPSS | Individually "medium" signals that together form a critical risk |
| New dependency + single maintainer + install scripts + network access | Individually flagged by different tools but the *combination* is the story |
| Test files with real credentials | Gitleaks finds a key, but is it a test fixture or a real leak? Context matters |
| Vendored code drift | Vendored copy of a library that's been modified — are the modifications benign? |
| Build artifact in source | Compiled binary committed to repo — is it the build output or injected? capa + git blame tells the story |
| Protestware vs. malware | Code that's intentionally destructive but politically motivated — different risk profile and response |
| Security theater | Project has SECURITY.md and Scorecard badges but the actual code has critical issues |
| Dependency depth risk | Vulnerability 4 levels deep in the transitive tree — who's responsible for updating? |
| Time-bomb patterns | Code that activates after a date check, counter threshold, or specific environment variable |
| Geographic/targeting logic | Code that checks locale, timezone, IP range, or hostname before executing payloads |

**Covered by**: Nothing automated. This is the **primary job of the AI analysis layer** — correlating findings across all zones and surfacing risks that no individual scanner can see.

---

## Zone 10: The Dark Corners

Things a paranoid researcher checks that almost no tooling covers and most reports don't mention. These are the "what if" scenarios that separate a surface-level scan from a real assessment.

| Signal | What To Look For |
|--------|-----------------|
| Unicode/homoglyph attacks | Identifiers that look identical but use different Unicode characters (Trojan Source) — `if (аccess)` where `а` is Cyrillic |
| Bidirectional text overrides | Right-to-left Unicode markers that make code appear different than it executes |
| Compiler/interpreter exploits | Source that's benign to read but exploits parser bugs in specific compiler versions |
| Git history manipulation | Force-pushed history that rewrites commits to hide past malicious code |
| Dead code with side effects | Functions that appear unused but are triggered via reflection, decorators, metaclasses, or import-time side effects |
| Import-time execution | Python modules that run code at import (top-level network calls, file writes) — never called explicitly |
| Confusable file extensions | `readme.txt.exe`, `.js` vs `.mjs` vs `.cjs` serving different content, `.py` vs `.pyw` |
| Polyglot files | Files that are valid in multiple formats simultaneously (PDF+ZIP, JS+HTML) used to bypass type checks |
| Supply chain of the supply chain | The build tools used to produce the dependency — compromised compilers (Thompson attack), tainted CI environments |
| Data-only payloads | Malicious content in JSON fixtures, CSV test data, image EXIF metadata, font files — no "code" to scan |
| Timing side channels | Code that leaks information through execution timing rather than explicit data flow |
| DNS-based exfiltration | Encoding stolen data as DNS subdomain queries — bypasses HTTP-based network monitoring |
| Delayed/staged payloads | First version is clean (passes review), second version introduces the payload after gaining trust |

**Covered by**: Almost nothing. Some caught by Semgrep Trojan Source rules. Most require **human or AI judgment** combined with deep source review.

---

## Coverage Map

How our scanner pipeline (current + planned) maps to these zones:

| Zone | Current Coverage | Planned (v2) Coverage | Remaining Gap |
|------|-----------------|----------------------|---------------|
| 1. Known Vulnerabilities | **Strong** (5 CVE scanners + EPSS/KEV) | Same | Advisory lag |
| 2. Code Quality | **Good** (Semgrep + Bandit + Gitleaks) | Same | Taint analysis depth |
| 3. Infrastructure | **Good** (Checkov + Hadolint) | Same | CI/CD pipeline analysis |
| 4. Malware Signatures | **Good** (YARA + ClamAV + capa) | Same | Signature freshness |
| 5. Dependency Behavior | **Weak** (GuardDog on manifests only) | **Strong** (Semgrep custom rules + GuardDog on source + entropy + install hooks) | Dynamic/runtime analysis |
| 6. Package Metadata | **Minimal** (GuardDog Levenshtein) | **Good** (deps.dev + registry metadata) | Private registry support |
| 7. License | **Good** (ScanCode) | Same | License change detection |
| 8. Repo Health | **None** | **Partial** (Scorecard via deps.dev) | Most signals need AI reasoning |
| 9. Cross-Signal | **None** | **AI analysts** (multi-analyst architecture) | Depends on analyst prompt quality |
| 10. Dark Corners | **Minimal** (YARA for some) | **AI analysts** (paranoid analyst) | Fundamentally hard to automate |

Zones 1-7 are the **tooling domain** — automatable, deterministic, fast.
Zones 8-10 are the **analyst domain** — require judgment, context, and the ability to reason across signals.

The AI analysis layer exists specifically to cover Zones 8-10 and to perform the cross-signal correlation in Zone 9 that no individual scanner can do.
