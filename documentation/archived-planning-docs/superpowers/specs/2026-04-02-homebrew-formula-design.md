# Homebrew Formula Design — Custom Tap

**Date:** 2026-04-02
**Status:** Approved

## Summary

Create a custom Homebrew tap (`thresher-sh/homebrew-thresher`) so users can install thresher via:

```bash
brew tap thresher-sh/thresher
brew install thresher
```

## Decisions

- **Custom tap**, not Homebrew core (thresher doesn't yet meet the 75-star notability threshold)
- **Lima as recommended dependency** — declared in formula so it installs by default, plus a runtime check in the CLI as fallback
- **Pinned Python dependency versions** — manually updated on each release
- **Manual release workflow** — no CI automation for now

## Tap Repository

**Repo:** `thresher-sh/homebrew-thresher` on GitHub

```
thresher-sh/homebrew-thresher/
  Formula/
    thresher.rb
  README.md
```

## Formula Specification

### Metadata

| Field     | Value                                                                        |
|-----------|------------------------------------------------------------------------------|
| Name      | `thresher`                                                                   |
| Homepage  | `https://github.com/thresher-sh/thresher`                                   |
| URL       | `https://github.com/thresher-sh/thresher/archive/refs/tags/v1.0.0-alpha.tar.gz` |
| SHA256    | Computed from tarball at release time (see maintenance workflow)              |
| License   | MIT                                                                          |
| Desc      | AI-powered supply chain security scanner for open source packages            |

> **Note:** The URL references `v1.0.0-alpha`, the planned first Homebrew-distributed release. The current pyproject.toml version is `0.2.0`.

### Dependencies

| Dependency    | Type        | Notes                                          |
|---------------|-------------|-------------------------------------------------|
| `python@3.13` | required   | Build and runtime                              |
| `lima`        | recommended | Installs by default; CLI also checks at runtime |

### Python Resource Blocks (Pinned)

| Package    | Version | Notes                    |
|------------|---------|--------------------------|
| click      | 8.3.1   | CLI framework            |
| jinja2     | 3.1.6   | Template engine          |
| markupsafe | 3.0.3   | Transitive dep of jinja2 |
| pyyaml     | 6.0.3   | Config parsing           |

### Install Method

Uses Homebrew's `virtualenv_install_with_resources` helper:
1. Creates an isolated Python virtualenv
2. Installs pinned PyPI dependencies from resource blocks
3. Installs thresher into the virtualenv
4. Symlinks entry points into `bin/` (`thresher`, `thresher-build`, `thresher-stop`)

### Post-Install Caveats

The formula will display caveats telling users:
- Lima must be installed (auto-installed if using recommended dep)
- Run `thresher build` before first scan to provision the VM

### Test Block

Runs `thresher --help` and asserts expected output is present.

## User Experience

```bash
# Install
brew tap thresher-sh/thresher
brew install thresher

# Use
thresher scan <repo_url>

# Update
brew update && brew upgrade thresher
```

## Release & Maintenance Workflow

When cutting a new thresher release:

1. Tag and publish a GitHub release on `thresher-sh/thresher`
2. Get the SHA256 of the new source tarball:
   ```bash
   curl -sL https://github.com/thresher-sh/thresher/archive/refs/tags/<tag>.tar.gz | shasum -a 256
   ```
3. Update `Formula/thresher.rb` in the tap repo — bump the `url` and `sha256`
4. If Python deps changed, update the `resource` blocks with new versions and SHA256 hashes
   (get hashes from PyPI: `https://pypi.org/pypi/<package>/<version>/json` → `digests.sha256`)

## Future Considerations

- **Automated bump workflow:** GitHub Actions on the main repo can auto-PR the tap repo on new releases
- **Homebrew core submission:** Once thresher meets the 75-star threshold, submit the formula to homebrew-core
- **Bottles:** Pre-built bottles for faster installs (not needed initially since source build is fast for a pure Python package)
