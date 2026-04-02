# Project Overview

## What Is This?

Thresher is a command-line tool that evaluates open source packages for security risks before you adopt them. It combines 16 deterministic security scanners with AI-powered code analysis to produce a static go/no-go report.

Think of it as a security review pipeline you can run against any GitHub repository. Instead of manually auditing code, dependency trees, and known vulnerabilities, you point this tool at a repo URL and get back a prioritized findings report with a clear recommendation: **GO**, **USE WITH CAUTION**, or **DO NOT USE**.

## Why Does It Exist?

Supply chain attacks are one of the fastest-growing threats in software security. Attackers compromise upstream packages to gain access to downstream consumers — your applications, your CI pipelines, your production environments.

Traditional approaches have gaps:

- **SCA tools** (Grype, OSV-Scanner) catch known CVEs but miss zero-day malicious code
- **SAST tools** (Semgrep, Bandit) find code-level vulnerabilities but don't evaluate supply chain risk
- **Manual review** is thorough but doesn't scale

This project layers all three approaches — known vulnerability databases, static analysis, and AI-driven code investigation — inside an isolated VM so that untrusted code never touches your host machine.

## Who Is It For?

- **Developers** evaluating new dependencies before adding them to a project
- **Security engineers** performing package vetting as part of a supply chain security program
- **Open source maintainers** auditing contributions and dependencies
- **Anyone** who wants a second opinion before running `npm install sketchy-package`

## What Does It Scan For?

| Threat Category | Examples |
|----------------|----------|
| **Known vulnerabilities** | CVEs in dependencies (via Grype, OSV-Scanner, Trivy, govulncheck, cargo-audit) |
| **Malicious code** | Backdoors, data exfiltration, obfuscated payloads (via AI agents, YARA, ClamAV) |
| **Supply chain attacks** | Typosquatting, dependency confusion, malicious install hooks (via GuardDog, AI agents) |
| **Secrets** | Hardcoded API keys, tokens, credentials (via Gitleaks) |
| **Code vulnerabilities** | Injection, insecure deserialization, weak crypto (via Semgrep, Bandit) |
| **IaC misconfigurations** | Insecure Dockerfiles, Terraform, K8s manifests (via Checkov, Hadolint, Trivy) |
| **License risks** | Copyleft licenses that may conflict with your project (via ScanCode) |
| **Binary threats** | Suspicious capabilities in compiled binaries (via capa) |

## How Does It Work (High Level)?

```
1. ISOLATE  →  Spin up ephemeral Lima VM with egress firewall
2. CLONE    →  Clone target repo inside the VM
3. DOWNLOAD →  Fetch dependencies source-only in Docker containers
4. SCAN     →  Run 16 scanners in parallel
5. ANALYZE  →  AI agents investigate code independently (optional)
6. VERIFY   →  Adversarial agent challenges AI findings to reduce false positives
7. ENRICH   →  Add EPSS exploitation scores and CISA KEV status
8. REPORT   →  Generate prioritized findings with go/no-go recommendation
9. CLEANUP  →  Destroy the VM. Nothing persists.
```

See [Architecture](architecture.md) for the full technical breakdown.

## Key Design Decisions

- **Static reports, not dashboards** — Output is markdown and JSON files you can commit, review, and share. No running services.
- **VM isolation** — Untrusted code runs inside a Lima VM. No shared folders, no port forwarding, egress firewall whitelist.
- **Source-only dependency downloads** — `pip download --no-binary`, `npm pack`, `cargo vendor`. No install scripts execute.
- **AI is optional** — Use `--skip-ai` for free, deterministic-only scans. AI analysis requires an Anthropic API key.
- **Cost-conscious** — The AI agents use Claude (sonnet by default). A typical scan costs a few dollars in API usage.
- **Minimal agent count** — Two AI agents (analyst + adversarial verifier), not a swarm. Keeps costs and complexity down.
