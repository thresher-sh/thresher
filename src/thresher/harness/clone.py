"""
clone.py — Hardened git clone (Python port of safe_clone.sh).

Implements 4-phase defense against code execution during clone:
  1. Fetch without checkout (--no-checkout + -c flags neutralize all vectors)
  2. Sanitize .git/config (overwrite with minimal safe config)
  3. Checkout with filters disabled (GIT_LFS_SKIP_SMUDGE=1)
  4. Post-checkout validation (symlinks, .gitattributes, .gitmodules, paths)
"""

import logging
import os
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

# All -c flags required to neutralize git code execution vectors.
_SAFE_CLONE_FLAGS = [
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.fsmonitor=false",
    "-c", "core.fsmonitorHookVersion=0",
    "-c", "receive.fsckObjects=true",
    "-c", "fetch.fsckObjects=true",
    "-c", "transfer.fsckObjects=true",
    "-c", "protocol.file.allow=never",
    "-c", "protocol.ext.allow=never",
    "-c", "submodule.recurse=false",
    "-c", "diff.external=",
    "-c", "merge.renormalize=false",
]

# Env vars that prevent code execution during clone/checkout.
_SAFE_ENV_BASE = {
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_LFS_SKIP_SMUDGE": "1",
}


def _safe_env() -> dict:
    """Return OS env merged with safe git env vars."""
    env = dict(os.environ)
    env.update(_SAFE_ENV_BASE)
    return env


def safe_clone(repo_url: str, target_dir: str, branch: str = "") -> str:
    """
    Hardened git clone using 4-phase defense.

    Args:
        repo_url:   Repository URL to clone.
        target_dir: Directory to clone into (must not exist yet).
        branch:     Optional branch name. Defaults to the remote's HEAD.

    Returns:
        target_dir (str) on success.

    Raises:
        RuntimeError: If any git subprocess exits non-zero.
    """
    # ── Phase 1: Fetch without checkout ─────────────────────────────────
    logger.info("[safe_clone] Fetching repository (no checkout): %s", repo_url)

    clone_cmd = [
        "git", "clone",
        "--no-checkout",
        "--depth=1",
        "--single-branch",
    ]
    if branch:
        clone_cmd += ["--branch", branch]
        logger.info("[safe_clone] Using branch: %s", branch)

    clone_cmd += _SAFE_CLONE_FLAGS
    clone_cmd += [repo_url, target_dir]

    result = subprocess.run(clone_cmd, env=_safe_env(), capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(
            f"[safe_clone] git clone failed (exit {result.returncode}): {result.stderr}"
        )

    # ── Phase 2: Sanitize .git/config ───────────────────────────────────
    logger.info("[safe_clone] Locking down repo config...")
    _sanitize_git_config(target_dir, repo_url, branch or "main")

    # ── Phase 3: Checkout with filters disabled ──────────────────────────
    logger.info("[safe_clone] Checking out working tree...")
    checkout_result = subprocess.run(
        ["git", "checkout"],
        cwd=target_dir,
        env=_safe_env(),
        capture_output=True,
        text=True,
    )
    if checkout_result.returncode != 0:
        raise RuntimeError(
            f"[safe_clone] git checkout failed (exit {checkout_result.returncode}): "
            f"{checkout_result.stderr}"
        )

    # ── Phase 4: Post-checkout validation ────────────────────────────────
    logger.info("[safe_clone] Validating working tree...")
    _post_checkout_validate(target_dir)

    logger.info("[safe_clone] Clone complete: %s", target_dir)
    return target_dir


def _sanitize_git_config(target_dir: str, repo_url: str, branch: str) -> None:
    """
    Phase 2: Overwrite .git/config with a minimal safe configuration.

    Preserves only the remote URL and branch tracking info.  All other
    settings (hooks, fsmonitor, filters, submodules, etc.) are replaced
    with hardened defaults.
    """
    git_config_path = Path(target_dir) / ".git" / "config"

    safe_config = f"""\
[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = false
\thooksPath = /dev/null
\tfsmonitor = false
\tsymlinks = false
\tprotectNTFS = true
\tprotectHFS = true
[remote "origin"]
\turl = {repo_url}
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "{branch}"]
\tremote = origin
\tmerge = refs/heads/{branch}
[filter "lfs"]
\tsmudge = true
\tclean = true
\trequired = false
[submodule]
\trecurse = false
\tactive = false
"""
    git_config_path.write_text(safe_config)


def _post_checkout_validate(target_dir: str) -> None:
    """
    Phase 4: Validate the checked-out working tree.

    Checks performed:
    - 4a. Remove all symlinks (could point outside the repo).
    - 4b. Warn on suspicious .gitattributes filter= entries (non-lfs).
    - 4c. Warn if .gitmodules is present (submodules not initialized).
    - 4d. Warn on suspicious path names (path traversal indicators).
    """
    root = Path(target_dir)

    # 4a. Remove symlinks ─────────────────────────────────────────────────
    symlink_count = 0
    for path in root.rglob("*"):
        if path.is_symlink():
            logger.warning("[safe_clone] Removing symlink: %s", path)
            path.unlink()
            symlink_count += 1

    if symlink_count > 0:
        logger.info("[safe_clone] Removed %d symlink(s) from repository", symlink_count)

    # 4b. Check .gitattributes for non-lfs filter= entries ─────────────────
    gitattributes = root / ".gitattributes"
    if gitattributes.exists():
        suspicious = []
        for line in gitattributes.read_text(errors="replace").splitlines():
            if "filter=" in line and "filter=lfs" not in line:
                suspicious.append(line)
        if suspicious:
            logger.warning(
                "[safe_clone] Suspicious .gitattributes filters detected:\n%s",
                "\n".join(suspicious),
            )

    # 4c. Warn on .gitmodules ─────────────────────────────────────────────
    if (root / ".gitmodules").exists():
        logger.warning(
            "[safe_clone] Repository contains .gitmodules (submodules not initialized)"
        )

    # 4d. Detect path traversal indicators ────────────────────────────────
    escaped = []
    for path in root.rglob("*"):
        name = path.name
        if ".." in name or name.startswith(".") and ".." in str(path.relative_to(root)):
            escaped.append(str(path))

    if escaped:
        logger.warning(
            "[safe_clone] Suspicious paths detected: %s", ", ".join(escaped)
        )
