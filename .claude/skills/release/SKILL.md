---
name: release
description: Use when cutting a release, bumping version numbers, tagging a release, publishing to GitHub Releases, or updating the Homebrew formula. Triggered by user wanting to release a new version, bump versions, or run /release.
---

# Release

Bump version across all files, run tests, push, create a GitHub Release with auto-generated notes, then update and push the Homebrew formula.

## Gather Inputs

Ask the user for:

1. **New version** — semver string (e.g., `0.3.0`). Do not include the `v` prefix in the version string itself; the skill adds `v` for tags/URLs where needed.
2. **Homebrew formula repo path** — absolute path to the local clone of the homebrew-thresher repo. Check conversation memory first. After first ask, save the path to memory so future releases skip this question.

## Step 1: Detect Current Version

Read `pyproject.toml` and extract the `version` field. This is the old version string that will be replaced.

## Step 2: Find All Version References

Grep the entire repo for the old version string. Exclude these directories from replacement:

- `documentation/archived-planning-docs/` (historical, do not modify)
- `.git/`
- `uv.lock` (regenerated automatically in Step 4)

Present the full list of files and matching lines to the user. Wait for confirmation before proceeding. The user may exclude additional files.

## Step 3: Replace Versions

Replace the old version string with the new version in all confirmed files. Use exact string replacement, not regex, to avoid partial matches.

## Step 4: Regenerate Lock File

Run:
```bash
uv lock
```

This updates `uv.lock` to reflect the new version in `pyproject.toml`.

## Step 5: Run Tests

Run:
```bash
python -m pytest tests/unit/ tests/integration/ -v
```

**If tests fail, STOP.** Report the failures to the user. Do not commit, tag, push, or update the Homebrew formula. The user must fix the failures before retrying.

## Step 6: Commit Version Bump

Stage all changed files (including `uv.lock`) and commit:

```
bump version to vX.Y.Z
```

Do not push yet.

## Step 7: Push and Create GitHub Release

1. Push the commit to the remote:
   ```bash
   git push
   ```

2. Create a GitHub Release with auto-generated notes:
   ```bash
   gh release create vX.Y.Z --generate-notes --target main
   ```

   This creates the git tag, publishes the release, and generates release notes from commits since the last tag.

## Step 8: Update Homebrew Formula

1. Download the release tarball and compute its sha256:
   ```bash
   curl -sL https://github.com/thresher-sh/thresher/archive/refs/tags/vX.Y.Z.tar.gz -o /tmp/thresher-vX.Y.Z.tar.gz
   shasum -a 256 /tmp/thresher-vX.Y.Z.tar.gz
   ```

2. In the Homebrew formula repo, update `Formula/thresher.rb`:
   - Update the `url` line to reference the new tag (`vX.Y.Z`)
   - Update the `sha256` line with the computed hash

3. Read the formula file before editing to confirm the current state.

## Step 9: Commit and Push Homebrew Formula

In the Homebrew formula repo:

```bash
git add Formula/thresher.rb
git commit -m "thresher vX.Y.Z"
git push
```

## Step 10: Report

Tell the user:
- Version bumped from old to new
- GitHub Release URL (from `gh release create` output)
- Homebrew formula updated and pushed
- Remind them to run `brew update && brew upgrade thresher` to verify

## Failure Modes

- **Tests fail at Step 5**: Stop entirely. Do not commit or push.
- **`gh release create` fails**: The tag may or may not exist. Report the error. User can retry manually with `gh release create`.
- **Tarball download fails**: The release may not be ready yet. Wait a few seconds and retry once. If still failing, report and let user handle.
- **Homebrew push fails**: Report the error. The main repo release is already done and safe.
