# Source Download Hardening Spec

Hardens the `git clone` of the target repository to prevent malicious repos from executing code during clone or checkout.

## Problem

The current clone at `cli.py:250`:

```python
safe_url = shlex.quote(config.repo_url)
stdout, stderr, rc = ssh_exec(vm_name, f"git clone --depth=1 {safe_url} /opt/target")
```

This is a bare `git clone --depth=1`. While `shlex.quote` prevents shell injection in the URL, git itself has several code execution vectors that fire during a normal clone:

### Attack Vectors

| Vector | How It Works | Fires On Clone? |
|--------|-------------|-----------------|
| **`.gitattributes` filter** | Repo defines `*.txt filter=evil`. If `git config filter.evil.smudge` is set to a command, it executes during checkout. | Yes — during the implicit checkout after clone |
| **`.gitattributes` with `diff`/`merge` drivers** | Custom diff or merge drivers configured as executable commands | No — only on diff/merge operations |
| **`core.fsmonitor`** | Repo-level `.gitconfig` or `includeIf` can set `core.fsmonitor` to a command that runs on any git operation | Yes — if repo config is honored |
| **Git LFS smudge filter** | If `git-lfs` is installed and `.gitattributes` has `filter=lfs`, the LFS smudge filter runs during checkout | Yes — if git-lfs is installed in the VM |
| **`.gitmodules` submodules** | Can point to malicious repos. With `--recursive`, they'd be cloned and their hooks/filters would fire too | No — we don't use `--recursive`. But the `.gitmodules` file is still cloned and could be processed later |
| **`post-checkout` hook** | `.git/hooks/post-checkout` would fire after clone | No — hooks from the remote are not copied by `git clone`. Only template hooks apply |
| **Git template hooks** | If the system has hooks in `$(git --exec-path)/../share/git-core/templates/hooks/`, they fire on `git init` (which clone runs internally) | Possible — depends on VM's git template config |
| **`core.hooksPath`** | If globally configured to point to a directory with hooks, those fire | Possible — depends on VM's git config |
| **Symlinks in repo** | Repo can contain symlinks that point to `/etc/passwd` etc. — if scanners follow them, they read unexpected files | Yes — symlinks are checked out |
| **Filenames with path traversal** | Git supports filenames like `../../../.bashrc` on some platforms | Partially — modern git blocks the worst cases, but platform-dependent |

The most dangerous vector is **`.gitattributes` filters** because:
1. The attacker controls the `.gitattributes` file in their repo
2. `git clone` does an implicit checkout after fetching
3. During checkout, git processes `.gitattributes` and applies any configured filters
4. While the attacker can't set `git config filter.evil.smudge` remotely, they can exploit filters that are already configured on the system (like `lfs`)

### Secondary Clone

The YARA rules clone at `provision.sh:280` is lower risk since it's a hardcoded URL to a known repo, but should still be hardened for consistency:

```bash
sudo git clone --depth=1 https://github.com/Yara-Rules/rules.git "$YARA_RULES_DIR"
```

## Solution: Defense-in-Depth Clone

### Step 1: Separate Fetch from Checkout

Split `git clone` into `git clone --no-checkout` + controlled `git checkout`. This prevents any filters, hooks, or smudge commands from firing during the initial download.

### Step 2: Neutralize All Execution Vectors

Override git config at clone time to disable every known code execution path.

### Step 3: Post-Checkout Validation

After checkout, scan the working tree for dangerous content (symlinks, path traversal, gitattributes with suspicious filters) before any scanners touch it.

## Implementation

### New Script: `vm_scripts/safe_clone.sh`

A hardened clone script that runs inside the VM. Called from `cli.py` instead of the inline `git clone`.

```bash
#!/bin/bash
# safe_clone.sh — Hardened git clone that prevents code execution
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
```

### Changes to `cli.py`

Replace the inline clone with a call to the safe clone script:

```python
# Current (cli.py:249-252):
safe_url = shlex.quote(config.repo_url)
stdout, stderr, rc = ssh_exec(vm_name, f"git clone --depth=1 {safe_url} /opt/target")

# New:
safe_url = shlex.quote(config.repo_url)
stdout, stderr, rc = ssh_exec(
    vm_name,
    f"bash /tmp/safe_clone.sh {safe_url} /opt/target",
    timeout=300,
)
```

The `safe_clone.sh` script is copied into the VM during provisioning alongside `provision.sh` and `firewall.sh`.

### Changes to `provision.sh`

Harden the YARA rules clone (line 280):

```bash
# Current:
sudo git clone --depth=1 https://github.com/Yara-Rules/rules.git "$YARA_RULES_DIR"

# New:
sudo git clone \
    --depth=1 \
    --no-checkout \
    --single-branch \
    -c core.hooksPath=/dev/null \
    -c core.fsmonitor=false \
    -c protocol.file.allow=never \
    https://github.com/Yara-Rules/rules.git "$YARA_RULES_DIR"
cd "$YARA_RULES_DIR" && sudo GIT_LFS_SKIP_SMUDGE=1 git checkout
```

Less critical than the target repo clone (hardcoded trusted URL), but defense in depth.

### Changes to `lima.py`

Copy `safe_clone.sh` into the VM during provisioning:

```python
ssh_copy_to(vm_name, str(_VM_SCRIPTS_DIR / "safe_clone.sh"), "/tmp/safe_clone.sh")
```

## How Each Vector Is Mitigated

| Vector | Mitigation |
|--------|-----------|
| `.gitattributes` filter (smudge/clean) | `filter.lfs.smudge=true` (no-op), `GIT_LFS_SKIP_SMUDGE=1`, no other filters configured in locked-down config |
| `core.fsmonitor` command execution | `core.fsmonitor=false` set at clone time, rewritten in repo config |
| Git template hooks | `core.hooksPath=/dev/null` — no hooks directory to read from |
| `core.hooksPath` in repo config | Repo config overwritten in Phase 2 with `hooksPath = /dev/null` |
| Git LFS smudge filter | `GIT_LFS_SKIP_SMUDGE=1` env var + `filter.lfs.smudge=true` (unix true command) |
| Submodule recursive clone | `submodule.recurse=false`, `--single-branch`, no `--recursive` flag |
| `protocol.file.allow` local file access | Set to `never` — blocks `file://` protocol |
| `protocol.ext.allow` external protocol handler | Set to `never` — blocks `ext::` protocol |
| Symlinks pointing outside repo | Removed in Phase 4, `core.symlinks=false` in locked-down config |
| Path traversal in filenames | `core.protectNTFS=true`, `core.protectHFS=true`, Phase 4 path check |
| `fsckObjects` bypass (malformed objects) | `receive/fetch/transfer.fsckObjects=true` — rejects malformed git objects |
| Interactive prompts (credential phishing) | `GIT_TERMINAL_PROMPT=0` — no interactive prompts |
| Malicious repo-level `.git/config` | Overwritten in Phase 2 with known-safe minimal config |

## What This Does NOT Mitigate

| Vector | Why Not | Residual Risk |
|--------|---------|---------------|
| Malicious source code (the thing we're scanning) | That's the whole point — we *want* to check out the code to scan it | Contained by VM isolation + all other hardening specs |
| Extremely large repos (resource exhaustion) | `--depth=1` limits history, but working tree could still be large | Consider a `--filter=blob:limit=50m` flag to reject huge blobs |
| Git protocol-level exploits (CVE in git itself) | Can't defend against zero-days in git | VM isolation is the boundary |

## Files Modified/Created

| File | Change |
|------|--------|
| `vm_scripts/safe_clone.sh` (new) | Hardened clone script with 4-phase defense |
| `src/threat_scanner/cli.py` | Replace inline `git clone` with `safe_clone.sh` invocation |
| `src/threat_scanner/vm/lima.py` | Copy `safe_clone.sh` into VM during provisioning |
| `vm_scripts/provision.sh` | Harden YARA rules clone |
| `tests/e2e/test_full_scan.py` | Update test clone to use `safe_clone.sh` |

## Implementation Order

1. Write `safe_clone.sh`
2. Update `lima.py` to copy it into the VM
3. Update `cli.py` to call it instead of inline clone
4. Harden the YARA clone in `provision.sh`
5. Update e2e test
6. Test against repos with `.gitattributes` filters, symlinks, and `.gitmodules`

## Open Questions

1. **Blob size limit**: Should we add `--filter=blob:limit=50m` to reject individual files over 50 MB? This would prevent resource exhaustion from repos with huge binaries, but could break scanning of repos that legitimately contain large files. The scanners (capa, YARA, ClamAV) specifically look at binary files, so filtering them out could create blind spots.

2. **Submodule scanning**: We currently don't clone submodules at all. Should we? Some repos put significant code in submodules. If we do, each submodule needs the same safe-clone treatment (recursive safe clone). This adds complexity and broadens the attack surface — probably a v3 consideration.

3. **Sparse checkout**: For very large monorepos, we could use `git sparse-checkout` to only check out relevant paths (e.g., directories containing dependency manifests + source code, skip vendored assets). This reduces both attack surface and scan time, but requires knowing what to include.
