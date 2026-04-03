https://github.com/coderabbitai/git-worktree-runner/pull/162


# Security Remediation Summary

Based on automated security scan findings from [Thresher](https://thresher.sh) (scan date: 2026-04-03), this PR resolves **0 Critical**, **4 High**, and **6 Medium** severity findings — including hook trust model hardening, shell injection fixes, CI/CD supply chain hardening, and code-level security improvements.

## Dependency Upgrades (0 packages)

No package-manager dependencies exist in this project. The entire dependency surface consists of GitHub Actions used only in CI.

## Application Security Fixes

### High

- **HIGH-001/002/003: Hook trust model for .gtrconfig hooks** — `lib/hooks.sh`, `lib/commands/init.sh` — Hooks from `.gtrconfig` files (committed to repositories) now require explicit user approval via `git gtr trust` before execution. Trust is cached per content hash in `~/.config/gtr/trusted/`. Applies to all hook execution paths: `run_hooks()`, `run_hooks_export()`, and postCd hooks in generated shell functions (bash, zsh, fish).
- **HIGH-004: Shell injection via editor/AI adapter eval** — `lib/adapters.sh` — Replaced `eval "$GTR_EDITOR_CMD"` and `eval "$GTR_AI_CMD"` with array-based dispatch (`read -ra` + `"${arr[@]}"`). Added shell metacharacter validation (`;`, `` ` ``, `$(`, `|`, `&`, `>`, `<`) for config-supplied command names in the generic fallback path.

### Medium

- **MED-001: Path traversal in adapter file sourcing** — `lib/adapters.sh` — Added validation in `_load_adapter()` to reject adapter names containing `/`, `..`, or `\` before constructing file paths.
- **MED-002/003/006: Unpinned GitHub Actions + missing permissions** — `.github/workflows/lint.yml`, `.github/workflows/homebrew.yml` — Pinned `actions/checkout` and `mislav/bump-homebrew-formula-action` to full commit SHAs. Added `permissions: read-all` at the top level of both workflow files.
- **MED-004: Unquoted glob expansion in rm -rf** — `lib/copy.sh` — Added validation to reject overly broad exclude suffixes (`*`, `**`, `.*`). Added `.git` directory protection in the exclude loop to prevent accidental removal.
- **MED-005: Shell injection in spawn_terminal_in** — `lib/platform.sh` — Applied `printf '%q'` escaping to `$cmd` and `$path` for Linux and Windows terminal emulator invocations.
- **MED-007: Indirect eval in cfg_default** — `lib/config.sh` — Replaced `eval "value=\${${env_name}:-}"` with `printenv "$env_name"` to eliminate eval from the config path.

### Low

- **LOW-001: Dead eval branch in prompt_input** — `lib/ui.sh` — Replaced `eval "$var_name=\"$input\""` with `printf -v "$var_name" '%s' "$input"`.
- **LOW-002: IFS global mutation** — `lib/args.sh` — Replaced manual IFS save/restore with `local IFS='|'` for automatic scoping.

## Secrets Remediation

- No secrets were detected in the codebase.

## GitHub Actions Hardening

- Pinned `actions/checkout@v4` to SHA `34e114876b0b11c390a56381ad16ebd13914f8d5` in lint.yml (3 occurrences)
- Pinned `mislav/bump-homebrew-formula-action@v3` to SHA `56a283fa15557e9abaa4bdb63b8212abc68e655c` in homebrew.yml
- Added `permissions: read-all` to both lint.yml and homebrew.yml to enforce least-privilege token access

## Scan Context

- **Scanner:** [Thresher](https://thresher.sh) multi-tool security scan (grype, trivy, osv-scanner, semgrep, gitleaks, checkov, YARA) + 8 AI security analysts
- **Total findings:** 4 deterministic + 45 AI analyst findings
- **Malicious code detected:** None
- **CISA KEV entries:** 0

## Known Remaining Items (not addressed in this PR)

These were flagged by AI analysts but require deeper architectural changes or stakeholder decisions:

- LOW-003: TOCTOU symlink race in CoW copy fallback cleanup (`lib/copy.sh`) — requires microsecond race window + local write access; extremely low risk
- LOW-004: World-readable cache files (`lib/commands/init.sh`) — cache contains only shell function definitions, not sensitive data
- LOW-009: Low bus factor / single primary maintainer — organizational concern, not a code fix
- LOW-010: No SECURITY.md — recommend adding a vulnerability disclosure process
- LOW-012/013: Version bump cadence and shallow clone — informational only
- Hooks still use `eval` for execution — the trust model gates access but does not sandbox execution; a future sandboxing mechanism could further reduce risk
