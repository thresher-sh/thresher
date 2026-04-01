#!/bin/bash
# safe_clone.sh — Hardened git clone that prevents code execution.
# Splits clone into fetch + sanitize + checkout to neutralize all known
# git code execution vectors (.gitattributes filters, core.fsmonitor,
# LFS smudge filters, template hooks, etc.).
set -euo pipefail

REPO_URL="${1:?Usage: safe_clone.sh <REPO_URL> <TARGET_DIR>}"
TARGET_DIR="${2:?Usage: safe_clone.sh <REPO_URL> <TARGET_DIR>}"

LOG_PREFIX="[safe_clone]"
log() { echo "${LOG_PREFIX} $(date '+%H:%M:%S') $*"; }

# ── Phase 1: Fetch without checkout ─────────────────────────────────
# --no-checkout: prevents implicit checkout (no filters/hooks fire)
# --depth=1: shallow clone (minimize attack surface in history)
# --single-branch: only fetch the default branch
# -c configs: override all known code execution vectors
log "Fetching repository (no checkout)..."
git clone \
    --no-checkout \
    --depth=1 \
    --single-branch \
    -c core.hooksPath=/dev/null \
    -c core.fsmonitor=false \
    -c core.fsmonitorHookVersion=0 \
    -c receive.fsckObjects=true \
    -c fetch.fsckObjects=true \
    -c transfer.fsckObjects=true \
    -c protocol.file.allow=never \
    -c protocol.ext.allow=never \
    -c submodule.recurse=false \
    -c diff.external= \
    -c merge.renormalize=false \
    "$REPO_URL" "$TARGET_DIR"

# ── Phase 2: Neutralize repo-level config ────────────────────────────
# The cloned .git/config could contain malicious settings.
# Overwrite it with a minimal safe config.
log "Locking down repo config..."
cd "$TARGET_DIR"

# Preserve remote URL and branch info, nuke everything else
REMOTE_URL=$(git config --get remote.origin.url || echo "$REPO_URL")
DEFAULT_BRANCH=$(git symbolic-ref --short HEAD 2>/dev/null || echo "main")

cat > .git/config << GITCONFIG
[core]
    repositoryformatversion = 0
    filemode = true
    bare = false
    logallrefupdates = false
    hooksPath = /dev/null
    fsmonitor = false
    symlinks = false
    protectNTFS = true
    protectHFS = true
[remote "origin"]
    url = ${REMOTE_URL}
    fetch = +refs/heads/*:refs/remotes/origin/*
[branch "${DEFAULT_BRANCH}"]
    remote = origin
    merge = refs/heads/${DEFAULT_BRANCH}
[filter "lfs"]
    smudge = true
    clean = true
    required = false
[submodule]
    recurse = false
    active = false
GITCONFIG

# ── Phase 3: Checkout with filters disabled ──────────────────────────
# GIT_LFS_SKIP_SMUDGE: prevents git-lfs from running smudge filters
# The filter.lfs overrides above set smudge/clean to "true" (the unix
# command that succeeds and does nothing) so even if LFS is installed,
# no filter code executes.
log "Checking out working tree..."
GIT_LFS_SKIP_SMUDGE=1 \
GIT_TERMINAL_PROMPT=0 \
    git checkout

# ── Phase 4: Post-checkout validation ────────────────────────────────
log "Validating working tree..."

# 4a. Remove symlinks (they could point outside the repo)
SYMLINK_COUNT=0
while IFS= read -r -d '' symlink; do
    log "WARNING: Removing symlink: ${symlink}"
    rm -f "$symlink"
    SYMLINK_COUNT=$((SYMLINK_COUNT + 1))
done < <(find "$TARGET_DIR" -type l -print0 2>/dev/null)

if [ "$SYMLINK_COUNT" -gt 0 ]; then
    log "Removed ${SYMLINK_COUNT} symlink(s) from repository"
fi

# 4b. Check .gitattributes for suspicious filter definitions
if [ -f "$TARGET_DIR/.gitattributes" ]; then
    # Look for filter= directives that aren't "lfs"
    SUSPICIOUS_FILTERS=$(grep -n 'filter=' "$TARGET_DIR/.gitattributes" \
        | grep -v 'filter=lfs' || true)
    if [ -n "$SUSPICIOUS_FILTERS" ]; then
        log "WARNING: Suspicious .gitattributes filters detected:"
        log "$SUSPICIOUS_FILTERS"
        # Don't fail — just log. The filters are already neutered by config.
    fi
fi

# 4c. Check for .gitmodules (submodules not initialized, but flag it)
if [ -f "$TARGET_DIR/.gitmodules" ]; then
    log "WARNING: Repository contains .gitmodules (submodules not initialized)"
fi

# 4d. Verify no files escaped the target directory (path traversal)
ESCAPED=$(find "$TARGET_DIR" -name '*..*' -o -path '*/../*' 2>/dev/null || true)
if [ -n "$ESCAPED" ]; then
    log "WARNING: Suspicious paths detected: ${ESCAPED}"
fi

log "Clone complete: ${TARGET_DIR}"
