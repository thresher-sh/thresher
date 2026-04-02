Current agent path:


Analyst -> Advisarial -> Judge

We will move into new paths, spli tinto two stages (One ran before dependency resolution and before behavioral/static scanning).

## Two Stage Agent

Stage 1: Pre Dependency Resolatuion

Agent is ran to identify all additional dependency resolution files:

- git clones
- dockerfiles
- npm, pypi, etc..

Outputs into defined format: (Enforced by stop hook in claude code hooks, that forces output to match specific format before allowing agent to stop)

This is then ran into the new source and dependency download to resolve those dependencies.



Stage 2: Post Static and Behavioral

Multi Analyst Run:

- Analyst 1 = Current paronoid analyst (Is this code malicous)
- Analyst 2 = looks for behavioral patterns that could indicate unknown cve (Is this code malicious)
- Analyst 3 = Looks at repo statistics and analysis (commit velocity, newset packages added to its depdency tree that could indicate recent supply chain attack, general activity to build trustworthyness etc.) (Is this code trustworth?)
- Analyst 7 = Looks at infrastructure components and potential issues, vulnerabilities, exploits, etc. (Is this code safe?)
- Analyst 4 = Pentester 1 = Vulnerabilities (Is this code risky?)
- Analyst 5 = Pentester 2 = Applicaiton Endpoints (Is this code risky?)
- Analyst 6 = Pentester 3 = Memory Exploiter (Is this code risky?)


(Pentester persona's are looking for if we include these libraries or this package into our system, how could someone exploit them and use them to break ours. For example (Just one example that pentester 2 could look at is the application exposes a REST API but fails the top ten owasp areas...))... So if we were to use it in our app, then that would open us up to threat by the top ten OWASP problems...


===== INSERT BELOW HERE =====

## Stage 2 Analyst Definitions

All analysts run in parallel after deterministic scanners complete. Each receives the full scanner output plus access to the source code and dependency source. Each answers a different core question from a different persona. Together they cover Watch Zones 1-10.

---

### Analyst 1 — The Paranoid (Malice Hunter)

**Core question**: *Is this code malicious?*

**Persona**: A threat intelligence analyst who has personally reverse-engineered supply chain attacks. Assumes every package is guilty until proven innocent. Has seen event-stream, ua-parser-js, colors/faker, and knows exactly what those attacks looked like before anyone flagged them.

**Watch Zones**: 5 (Dependency Behavior), 10 (Dark Corners)

**What they review**:
- Scanner findings from GuardDog, entropy analysis, install hook detection, custom Semgrep supply-chain rules
- Dependency source code directly — especially files flagged by behavioral scanners
- Patterns the scanners can't catch: import-time side effects, dead code triggered by reflection/metaclasses, time-bomb conditions, geographic targeting logic, delayed/staged payloads
- Obfuscated code that the entropy scanner flagged — manually assess whether it's legitimate minification or an encoded payload
- Data files (JSON fixtures, CSV, images) for embedded payloads

**Output**: List of findings with risk score, confidence, evidence (file paths + line numbers), and a plain-language explanation of what the code does and why it's suspicious.

---

### Analyst 2 — The Behaviorist (Unknown CVE Hunter)

**Core question**: *Is this code doing something dangerous that nobody has reported yet?*

**Persona**: A security researcher who specializes in finding 0-days by reading source code. Doesn't care about known CVEs — those are already caught by scanners. Focuses on patterns that *should* be vulnerabilities but don't have a CVE yet.

**Watch Zones**: 2 (Code Quality), 5 (Dependency Behavior), 9 (Cross-Signal)

**What they review**:
- Source code for unsafe patterns that Semgrep/Bandit didn't catch — subtle injection sinks, deserialization with untrusted input, race conditions, logic flaws
- Dependency code for dangerous APIs used in unexpected contexts (a "date formatting" library that opens network sockets)
- Taint paths that static analysis missed — data flowing from user input to dangerous sinks through multiple function calls
- Monkey-patching or prototype pollution in dependencies that could undermine the target project's own security measures
- Code that technically "works" but has incorrect security assumptions (e.g., HMAC comparison without constant-time equality)

**Output**: Findings with severity, affected code paths, potential exploit scenario, and whether a CVE should exist for this.

---

### Analyst 3 — The Investigator (Trust & Provenance)

**Core question**: *Is this code trustworthy?*

**Persona**: An open-source intelligence analyst who profiles projects and maintainers the way an investigator profiles suspects. Doesn't read code — reads signals around the code.

**Watch Zones**: 6 (Package Metadata), 8 (Repo Health)

**What they review**:
- deps.dev Scorecard results, registry metadata, maintainer history from scanner output
- Commit velocity and patterns — is the project alive? Has development suddenly stopped or changed hands?
- Dependency freshness — how far behind is the project on its own deps? Stale deps = unpatched vulns
- Recent dependency additions — new packages added in last 90 days are the freshest (and riskiest) links
- Contributor diversity — bus factor analysis. One maintainer with no org backing on a critical dep is a risk
- Release hygiene — tagged releases, changelogs, semantic versioning, or just random commits?
- Security policy — SECURITY.md, vulnerability disclosure process, responsiveness to past reports
- Typosquatting and dependency confusion signals from metadata scanners
- Signs of maintainer takeover — ownership changes, email domain changes, sudden activity on dormant packages

**Output**: Trust assessment per dependency (high/medium/low confidence), risk factors, and specific packages that warrant closer inspection by other analysts.

---

### Analyst 4 — The Pentester: Vulnerability Analyst

**Core question**: *If we use this, what vulnerabilities are we inheriting?*

**Persona**: A penetration tester who just got handed the target's dependency list and told "find what's exploitable." Thinks in terms of attack chains, not individual CVEs.

**Watch Zones**: 1 (Known Vulnerabilities), 9 (Cross-Signal)

**What they review**:
- All CVE scanner output (Grype, OSV, Trivy, govulncheck, cargo-audit) — but with *attacker reasoning*, not just severity sorting
- Reachability — is the vulnerable function actually called? Can it be reached from a public interface?
- Exploit chain construction — a medium-severity deserialization bug + a low-severity SSRF = a critical chain
- EPSS + KEV correlation — vulnerabilities with active exploitation in the wild get priority regardless of CVSS
- Fix availability and upgrade path — is there a patch? How breaking is the upgrade? Is the project likely to release one?
- Transitive dependency depth — a critical CVE buried 4 levels deep that nobody will update

**Output**: Prioritized vulnerability report with exploit scenarios, attack chains, and actionable remediation steps (upgrade X to Y, or migrate away from Z).

---

### Analyst 5 — The Pentester: Application Surface

**Core question**: *If we expose this to users, how do they break in?*

**Persona**: A web application pentester who specializes in API security, auth bypasses, and OWASP Top 10. Evaluates the code as if it's about to be deployed behind a public endpoint.

**Watch Zones**: 2 (Code Quality), 3 (Infrastructure), 9 (Cross-Signal)

**What they review**:
- REST/GraphQL/gRPC endpoint definitions — authentication, authorization, input validation, rate limiting
- OWASP Top 10 mapping: injection, broken auth, sensitive data exposure, XXE, broken access control, security misconfiguration, XSS, insecure deserialization, known vulns (already scanned), insufficient logging
- Authentication and session management — JWT validation, token storage, session fixation, credential handling
- File upload handling — type validation, path construction, size limits, storage location
- CORS, CSP, and security header configuration
- Error handling that leaks stack traces, internal paths, or database schemas
- Admin/debug endpoints that shouldn't be exposed in production
- Semgrep and Bandit findings contextualized — is this finding actually reachable from an HTTP request?

**Output**: Attack surface map with entry points, risk per endpoint, OWASP category mapping, and specific exploitation scenarios.

---

### Analyst 6 — The Pentester: Memory & Runtime Exploiter

**Core question**: *Can this code be corrupted at runtime?*

**Persona**: A low-level exploit developer who thinks in terms of memory layouts, type confusion, and runtime guarantees. Focuses on native code, C extensions, unsafe blocks, and FFI boundaries.

**Watch Zones**: 2 (Code Quality), 4 (Malware Signatures — capa output), 10 (Dark Corners)

**What they review**:
- Native extensions (C/C++ code in Python packages, N-API/node-gyp in npm, cgo in Go, unsafe blocks in Rust)
- Buffer handling — overflow, underflow, off-by-one in any native code
- Memory management — use-after-free, double-free, dangling pointers in C extensions
- Type confusion — unsafe casts, union type abuse, `ctypes` misuse in Python
- capa findings — binary capabilities flagged by Mandiant's tool, contextualized with reasoning
- Unsafe Rust — `unsafe` blocks, raw pointer manipulation, transmute calls
- FFI boundaries — where managed and unmanaged memory meet (Python's ctypes, Node's ffi-napi, Go's cgo)
- Integer overflow/truncation that leads to undersized allocations
- Format string vulnerabilities in logging or string construction
- Regex DoS (ReDoS) — catastrophic backtracking patterns in user-facing regex

**Output**: Memory safety assessment, exploitable conditions with severity, and whether the code is safe to run in a shared process or needs isolation.

---

### Analyst 7 — The Infrastructure Auditor

**Core question**: *Is this code safe to deploy?*

**Persona**: A DevSecOps engineer who reviews infrastructure-as-code, CI/CD pipelines, container configurations, and deployment patterns. Thinks about what happens when this code runs in production, not just what the code does logically.

**Watch Zones**: 3 (Infrastructure), 7 (License), 9 (Cross-Signal)

**What they review**:
- Checkov and Hadolint findings — contextualized with deployment risk assessment
- Dockerfile security — base image provenance, multi-stage build hygiene, secret leakage in layers, running as root
- CI/CD pipeline files (.github/workflows, .gitlab-ci.yml, Jenkinsfile) — unpinned actions, script injection, secret handling, self-hosted runner risks
- Kubernetes manifests — privilege escalation paths, network policy gaps, RBAC overprovisioning
- Terraform/CloudFormation — public exposure, encryption gaps, IAM overreach
- Docker Compose — exposed ports, host mounts, network mode, privileged containers
- License compliance — ScanCode findings assessed for legal risk in the user's context (is copyleft contamination a real problem here?)
- Dependency on external services — what happens when a CDN, API, or registry goes down?

**Output**: Deployment risk assessment, infrastructure findings prioritized by blast radius, and specific hardening recommendations.

---

### Analyst 8 — The Shadowcatcher (Dark Corners Specialist)

**Core question**: *What is this code hiding?*

**Persona**: A malware reverse engineer who specializes in evasion techniques, steganography, and code that's designed to not look suspicious. The analyst who reads the code the other analysts skimmed past.

**Watch Zones**: 10 (Dark Corners), 5 (Dependency Behavior)

**What they review**:
- Unicode and homoglyph attacks (Trojan Source) — identifiers that look identical but aren't (`а` vs `a`, `е` vs `e`)
- Bidirectional text overrides — right-to-left markers that make code display differently than it executes
- Polyglot files — files valid in multiple formats (JS+HTML, PDF+ZIP) used to bypass type checks
- Confusable file extensions — `.js` vs `.mjs`, `.py` vs `.pyw`, double extensions
- Dead code that isn't dead — functions triggered by decorators, metaclasses, `__init_subclass__`, import hooks, atexit handlers, signal handlers, or `__del__`
- Import-time execution — top-level code in Python modules that runs on `import` without being called
- Git history anomalies — force-pushed rewrites, commits that appeared and disappeared, unusual author patterns
- Data-only payloads — suspicious content in non-code files (JSON, CSV, images, fonts, WASM blobs)
- DNS-based exfiltration patterns — code constructing DNS queries with data-encoding in subdomain labels
- Delayed/staged payload indicators — version N is clean, version N+1 adds the hook (cross-reference with registry metadata)

**Output**: Stealth threat assessment — findings that other analysts would miss because the code is specifically designed to evade detection. Each finding explains the evasion technique used and why it's suspicious.

---

## How Analysts Map to Watch Zones

| Watch Zone | Primary Analyst | Supporting Analysts |
|------------|----------------|-------------------|
| 1. Known Vulnerabilities | Analyst 4 (Pentester: Vulns) | — |
| 2. Code Quality | Analyst 2 (Behaviorist) | Analyst 5 (App Surface), Analyst 6 (Memory) |
| 3. Infrastructure | Analyst 7 (Infra Auditor) | Analyst 5 (App Surface) |
| 4. Malware Signatures | Analyst 1 (Paranoid) | Analyst 6 (Memory — for capa) |
| 5. Dependency Behavior | Analyst 1 (Paranoid) | Analyst 2 (Behaviorist), Analyst 8 (Shadowcatcher) |
| 6. Package Metadata | Analyst 3 (Investigator) | — |
| 7. License | Analyst 7 (Infra Auditor) | — |
| 8. Repo Health | Analyst 3 (Investigator) | — |
| 9. Cross-Signal | Analyst 4 (Pentester: Vulns) | Analyst 2, 5, 7 (all cross-reference) |
| 10. Dark Corners | Analyst 8 (Shadowcatcher) | Analyst 1 (Paranoid) |

## Analyst Toolkits

Each analyst is a Claude Code headless agent with access to `Read`, `Glob`, `Grep`, `Bash`, and `Write`. But raw file reading isn't enough — each persona needs specialized CLI tools installed in the VM to do real investigation. These tools are what separate "read the scanner JSON" from "actually investigate."

### Shared Tools (All Analysts)

Every analyst gets these. They're the baseline for any code investigation.

| Tool | What It Does | Already Installed? |
|------|-------------|-------------------|
| `jq` | Parse, filter, and query scanner JSON output. Every analyst reads scanner results. | No — **add to provision.sh** |
| `grep` / `rg` (ripgrep) | Fast content search across source and deps | grep yes, rg no — **add ripgrep** |
| `ast-grep` | **Structural code search across all languages.** Tree-sitter based pattern matching — like Semgrep but for ad-hoc investigation. Agents write a pattern (`ast-grep -p 'eval($$$)' -l js`), get structural matches. Covers Python, JS, TS, Go, Rust, C, C++, Java, and more. This is the primary code investigation tool for every analyst. | No — **add to provision.sh** |
| `tree-sitter` CLI | Raw AST generation for any supported language. Dumps full syntax trees for deep structural analysis. Heavier than `ast-grep` — used when an analyst needs to walk the complete tree, not just search for patterns. Reserved for complex investigations (full call graph tracing, scope analysis, control flow mapping). | No — **add to provision.sh** |
| `find` | File discovery by name, type, size, permissions | Yes |
| `wc` | Line/file counts for scale assessment | Yes |
| `file` | Identify file types by magic bytes, not extensions. Critical for detecting misnamed files, polyglots. | Yes (coreutils) |
| `git` | History analysis — log, blame, shortlog, diff, show | Yes |
| `python3` | Scripting for custom analysis (AST parsing, JSON processing, entropy calculation, Unicode inspection). Also has `py-tree-sitter` bindings for programmatic AST traversal when the CLI isn't enough. | Yes |
| `tree` | Directory structure visualization | No — **add to provision.sh** |

#### `ast-grep` vs `tree-sitter` CLI — When to use which

| Use Case | Tool | Example |
|----------|------|---------|
| "Find all calls to `exec()` with a variable argument" | `ast-grep` | `ast-grep -p 'exec($VAR)' -l python /work/deps/` |
| "Find all Flask routes" | `ast-grep` | `ast-grep -p '@app.route($$$)' -l python /opt/target/` |
| "Find unsafe blocks in Rust deps" | `ast-grep` | `ast-grep -p 'unsafe { $$$ }' -l rust /work/deps/rust/` |
| "Find dynamic require with computed string" | `ast-grep` | `ast-grep -p 'require($VAR)' -l js /work/deps/node/` |
| "Build a full call graph for this module" | `tree-sitter` | `tree-sitter parse file.py` → agent walks the tree programmatically |
| "Map all variable scopes to find shadowing" | `tree-sitter` | Full AST dump, agent traces identifier bindings |
| "Understand control flow across try/except/finally" | `tree-sitter` | Full AST dump, agent maps control flow edges |
| "Dump the AST of an obfuscated file for manual analysis" | `tree-sitter` | `tree-sitter parse obfuscated.js` → agent reads the structure the code is hiding |

**Rule of thumb**: `ast-grep` for searching (most investigations). `tree-sitter` for understanding (deep dives on specific suspicious files).

### Analyst 1 — The Paranoid (Malice Hunter)

Needs to decode things, look inside things, and trace what code actually does at runtime.

| Tool | Why They Need It |
|------|-----------------|
| `ast-grep` | Find import-time execution, decorator side effects, metaclass hooks, dynamic code loading across all languages in dependency source |
| `base64` | Decode base64 payloads found by entropy scanner to see what's inside |
| `xxd` | Hex dump of suspicious files — see raw bytes, find embedded content in data files |
| `strings` | Extract readable strings from binary files, images, WASM blobs, compiled assets |
| `node --print` | Evaluate JS expressions to understand obfuscated code (in isolated context, no network) |
| `unzip` / `tar` | Inspect contents of nested archives found inside dependencies |

**Provision additions**: `xxd` (from `xxd` or `vim-common`), `strings` (from `binutils`)

### Analyst 2 — The Behaviorist (Unknown CVE Hunter)

Needs to trace data flow and understand code structure deeper than grep can.

| Tool | Why They Need It |
|------|-----------------|
| `ast-grep` | Primary investigation tool — trace data flow patterns, find taint paths, locate dangerous API usage across all languages. "Find every path where user input reaches `exec()`" |
| `semgrep` | Run custom one-off taint queries with Semgrep's dataflow engine when `ast-grep` pattern matching isn't enough |
| `tree-sitter` | Full AST dump for deep call graph tracing on specific suspicious files — when `ast-grep` finds the entry point but the agent needs to trace the full control flow |
| `diff` | Compare versions of dependency code if multiple versions are present |
| `openssl` | Verify cryptographic implementations — check certificate handling, cipher usage |

**Provision additions**: Semgrep already installed. `openssl` likely already present.

### Analyst 3 — The Investigator (Trust & Provenance)

Doesn't read code — reads metadata, history, and signals. Needs git forensics and data querying.

| Tool | Why They Need It |
|------|-----------------|
| `git log` / `git shortlog` | Commit velocity, contributor count, activity patterns, last commit date |
| `git blame` | Who wrote what, when. Detect ownership changes at the code level |
| `git log --diff-filter=A` | Find when specific files were added (new dependencies, new scripts) |
| `jq` | Parse and query deps.dev results, registry metadata JSON, dep manifests |
| `curl` | (Read-only) Query deps.dev API, registry APIs for metadata not already fetched by scanners. Bounded by VM firewall whitelist. |
| `date` / `python3 datetime` | Calculate time deltas — how long since last commit, how old is this maintainer account |
| `wc -l` / `cloc` | Codebase size assessment — is this package suspiciously small or large for what it claims to do? |

**Provision additions**: `cloc` (count lines of code). `curl` already installed.

### Analyst 4 — The Pentester: Vulnerability Analyst

Needs to cross-reference CVE data and verify reachability in source.

| Tool | Why They Need It |
|------|-----------------|
| `jq` | Filter and correlate findings across 5 CVE scanners — find overlaps, unique hits, severity disagreements |
| `ast-grep` | Verify reachability — "is the vulnerable function in package X actually called from the target code?" Structural search beats grep for this — catches aliased imports, re-exports, wrapper functions |
| `semgrep` | Taint analysis queries when reachability needs dataflow tracing beyond pattern matching |
| `python3` | Script to correlate EPSS scores, KEV status, CVSS, and reachability into a prioritized attack chain |
| `git log --all --oneline` | Check if vulnerable dependency versions were recently updated (or have been pinned for years) |

**Provision additions**: None — all already available.

### Analyst 5 — The Pentester: Application Surface

Needs to map HTTP endpoints, auth flows, and input handling.

| Tool | Why They Need It |
|------|-----------------|
| `ast-grep` | Map endpoint definitions structurally — `ast-grep -p '@app.route($$$)' -l python`, `ast-grep -p 'router.$METHOD($PATH, $$$)' -l js`, `ast-grep -p 'http.HandleFunc($$$)' -l go`. Also find auth decorator patterns, middleware chains, input validation callsites |
| `jq` | Parse OpenAPI/Swagger specs if present in the repo |
| `semgrep` | Run OWASP-focused taint queries — "find all SQL queries built with string concatenation from request params" |
| `openssl` | Inspect TLS configuration, certificate handling code, JWT signing implementations |

**Provision additions**: None beyond shared tools.

### Analyst 6 — The Pentester: Memory & Runtime Exploiter

This analyst needs the heaviest specialized tooling. They're looking at compiled code, native extensions, and low-level constructs.

| Tool | Why They Need It |
|------|-----------------|
| `ast-grep` | Find unsafe boundaries in source — `ast-grep -p 'unsafe { $$$ }' -l rust`, `ast-grep -p 'ctypes.$FUNC($$$)' -l python`, `ast-grep -p 'cgo.$$$' -l go`. Structural search catches unsafe patterns that grep misses (e.g., unsafe nested inside macro expansions) |
| `xxd` / `hexdump` | Hex view of binaries, shared libraries, compiled extensions. See actual byte patterns. |
| `objdump -d` | Disassemble native code — C extensions (.so/.dll), compiled Go binaries, Rust release builds |
| `readelf` | Inspect ELF headers, sections, symbols, dynamic linking. Find suspicious sections, unexpected symbols. |
| `nm` | List symbols in object files — find exported functions, understand what a native extension exposes |
| `strings` | Extract readable strings from compiled binaries — hardcoded URLs, paths, credentials |
| `size` | Section size breakdown — unusually large .data or .rodata sections may contain embedded payloads |
| `ldd` | Show shared library dependencies of binaries — what dynamic libraries does this pull in? |
| `file` | Confirm file types — is this .so actually an ELF? Is this .node file a valid shared library? |

**Provision additions**: `binutils` (provides `objdump`, `readelf`, `nm`, `size`, `strings`). Likely already partially installed but should be explicit.

### Analyst 7 — The Infrastructure Auditor

Needs to understand deployment configurations and CI/CD pipelines.

| Tool | Why They Need It |
|------|-----------------|
| `jq` | Parse Checkov JSON output, Hadolint output, ScanCode license findings |
| `python3 -c "import yaml"` | Parse Kubernetes manifests, Docker Compose files, GitHub Actions workflows (YAML is the lingua franca of IaC) |
| `grep -rn` | Find exposed ports, environment variable references, secret mounting patterns across all config files |
| `shellcheck` | Lint shell scripts referenced in Dockerfiles and CI pipelines — catch injection risks in build scripts |
| `git log -- '*.yml' '*.yaml'` | Track changes to CI/CD and IaC files — when did this workflow change? Who changed it? |

**Provision additions**: `shellcheck`. PyYAML likely already available via pip.

### Analyst 8 — The Shadowcatcher (Dark Corners Specialist)

Needs the deepest inspection tools. This analyst looks at what code is *hiding*, so they need tools that reveal what's beneath the surface.

| Tool | Why They Need It |
|------|-----------------|
| `ast-grep` | Find hidden execution paths — `ast-grep -p 'def __init_subclass__($$$)' -l python`, `ast-grep -p 'Object.defineProperty($$$)' -l js`, `ast-grep -p 'atexit.register($$$)' -l python`. Catches dead-code-that-isn't-dead: functions triggered by implicit language hooks, decorators, metaclasses |
| `tree-sitter` | Full AST dump of obfuscated files — when code is deliberately unreadable, the syntax tree reveals what it actually does. Agents use this to trace control flow through minified or encoded source |
| `xxd` | Hex dump — see raw bytes of any file. Find null bytes in text files, embedded binaries in images, hidden content. |
| `hexdump -C` | Canonical hex+ASCII view — spot encoded payloads, unusual byte sequences in "text" files |
| `binwalk` | **Critical** — scan files for embedded content. Finds ZIP archives inside PNGs, ELF binaries inside data files, hidden filesystems. This is the polyglot detector. |
| `exiftool` | Read metadata from images, PDFs, fonts. Find GPS coordinates, embedded comments, creation tool info, hidden fields in media files. |
| `python3 -c "import unicodedata"` | Inspect Unicode codepoints character-by-character. Detect homoglyphs (Cyrillic а vs Latin a), bidi overrides, zero-width characters. |
| `strings` | Extract readable strings from any file — images, fonts, WASM, compiled code |
| `file -i` | MIME type detection by magic bytes — expose mismatched extensions (a .txt that's actually ELF, a .png that's actually a ZIP) |
| `od -c` | Octal/character dump — see control characters, escape sequences, null bytes that are invisible in normal text display |
| `git log --all --oneline --graph` | Visualize branch history — detect force-push rewrites, detached commits, unusual merge patterns |
| `git reflog` | See actions that modified HEAD — detect history manipulation (reset, rebase, amend) that cleaned up traces |
| `git fsck` | Check repository integrity — find dangling commits, unreachable objects that may contain deleted malicious code |
| `python3 -c "import hashlib"` | Hash files to detect modifications to vendored code — compare against known-good hashes |
| `base64 -d` | Decode base64 payloads for manual inspection |
| `zlib-flate -uncompress` | Decompress zlib streams found embedded in files (common in polyglots and steganographic payloads) |
| `entropy` (custom script) | Calculate per-file Shannon entropy — find encrypted or compressed blobs hidden in source trees |

**Provision additions**: `binwalk`, `exiftool` (`libimage-exiftool-perl`), `zlib-flate` (from `qpdf`)

---

## Provision.sh Additions Summary

New packages to add for analyst tooling:

```bash
# Analyst investigation tools (apt)
sudo apt-get install -y -qq \
    jq \
    ripgrep \
    tree \
    cloc \
    binutils \
    xxd \
    binwalk \
    libimage-exiftool-perl \
    shellcheck \
    qpdf

# ast-grep — structural code search (primary AST tool for all analysts)
cargo install ast-grep --quiet

# tree-sitter CLI — raw AST generation for deep analysis
cargo install tree-sitter-cli --quiet
```

`ast-grep` is the primary code investigation tool across all analysts. `tree-sitter` CLI is for deep-dive AST dumps when agents need the full syntax tree. Both install via cargo (Rust toolchain already present in the VM).

Total disk: ~80 MB. These transform the analysts from "read files and guess" to "actually investigate."

---

## Claude Code `allowedTools` Per Analyst

Each analyst runs as a Claude Code headless agent. The `--allowedTools` flag controls what they can do. All analysts get Read/Glob/Grep/Bash/Write. The difference is what they're *instructed* to use Bash for — the tools above are what their prompts tell them to leverage.

| Analyst | allowedTools | Bash Used For |
|---------|-------------|---------------|
| 1 (Paranoid) | Read, Glob, Grep, Bash | `ast-grep`, `base64`, `xxd`, `strings`, `file`, `node --print` |
| 2 (Behaviorist) | Read, Glob, Grep, Bash | `ast-grep`, `tree-sitter`, `semgrep`, `diff`, `openssl` |
| 3 (Investigator) | Read, Glob, Grep, Bash | `git log/blame/shortlog`, `jq`, `curl` (firewalled), `cloc` |
| 4 (Pentester: Vulns) | Read, Glob, Grep, Bash | `ast-grep`, `semgrep`, `jq`, `python3`, `git log` |
| 5 (Pentester: App) | Read, Glob, Grep, Bash | `ast-grep`, `semgrep`, `jq`, `openssl` |
| 6 (Pentester: Memory) | Read, Glob, Grep, Bash | `ast-grep`, `objdump`, `readelf`, `nm`, `xxd`, `strings`, `ldd`, `size` |
| 7 (Infra Auditor) | Read, Glob, Grep, Bash | `jq`, `shellcheck`, `python3 -c "import yaml"`, `git log` |
| 8 (Shadowcatcher) | Read, Glob, Grep, Bash | `ast-grep`, `tree-sitter`, `binwalk`, `exiftool`, `xxd`, `od`, `git reflog/fsck`, `python3 unicodedata`, `file -i` |

**Note**: No analyst gets `Write` access to source or deps directories. They write only their findings output file. They should not modify the code they're investigating.

## Analyst Execution

All 8 analysts run **in parallel**. Each receives:
- Full scanner output (all tools, all findings)
- Access to source code (`/opt/target`) and dependency source (`/work/deps`)
- The dependency manifest with package metadata
- deps.dev / registry metadata results

Each outputs a structured findings document. These feed into the existing **Adversarial → Judge** pipeline for verification and final synthesis.