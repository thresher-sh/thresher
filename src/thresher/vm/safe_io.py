"""Host boundary hardening: safe I/O for data crossing the VM boundary.

Every byte that comes back from the VM is untrusted input. This module
provides size-bounded JSON parsing, validated file copies, and report
structure verification.
"""

from __future__ import annotations

import json
import logging
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any

from thresher.vm.ssh import SSHError

logger = logging.getLogger(__name__)


def _limits():
    """Get the active limits config (lazy import to avoid circular deps)."""
    from thresher.config import active_limits
    return active_limits

# Allowed file extensions in report output
ALLOWED_EXTENSIONS = {".json", ".md", ".txt", ".csv", ".log", ".sarif", ".html"}

# Expected files in a complete report
EXPECTED_REPORT_FILES = [
    "findings.json",
    "executive-summary.md",
    "detailed-report.md",
]


# ---------------------------------------------------------------------------
# Bounded JSON parsing
# ---------------------------------------------------------------------------

def safe_json_loads(
    text: str,
    source: str = "unknown",
) -> dict[str, Any] | list[Any] | None:
    """Parse JSON with size limit and error containment.

    Args:
        text: Raw JSON string (typically from ssh_exec stdout).
        source: Label for logging (e.g. "grype output").

    Returns:
        Parsed JSON, or None if parsing fails.

    Raises:
        SSHError: If the payload exceeds the size limit.
    """
    if len(text) > _limits().max_json_size_bytes:
        raise SSHError(
            f"JSON payload from VM too large ({len(text)} bytes) "
            f"from source: {source}"
        )
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        logger.error("Failed to parse JSON from source: %s", source)
        return None


# ---------------------------------------------------------------------------
# Validated file copy from VM
# ---------------------------------------------------------------------------

def validate_copied_tree(root: Path) -> None:
    """Walk a directory tree and reject or neutralize dangerous content.

    Called on a staging directory after ``limactl copy -r`` completes but
    before files are moved to their final destination.

    Raises:
        SSHError: If path traversal is detected or size limits are exceeded.
    """
    total_size = 0

    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)

        # Reject path traversal
        if ".." in relative.parts:
            raise SSHError(f"Path traversal detected in VM output: {relative}")

        # Remove symlinks
        if path.is_symlink():
            logger.warning("Removing symlink from VM output: %s", relative)
            path.unlink()
            continue

        if path.is_file():
            # Check individual file size
            size = path.stat().st_size
            if size > _limits().max_file_size_bytes:
                raise SSHError(
                    f"File too large from VM: {relative} ({size} bytes)"
                )
            total_size += size

            # Check total size
            if total_size > _limits().max_copy_size_bytes:
                raise SSHError(
                    f"Total copy size exceeds {_limits().max_copy_size_bytes} bytes"
                )

            # Check extension
            if path.suffix.lower() not in ALLOWED_EXTENSIONS:
                logger.warning(
                    "Removing unexpected file type from VM output: %s",
                    relative,
                )
                path.unlink()
                continue

            # Strip executable bits
            current_mode = path.stat().st_mode
            path.chmod(
                current_mode & ~(stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            )


def ssh_copy_from_safe(
    vm_name: str, remote_path: str, local_path: str
) -> None:
    """Copy from VM into a staging directory, validate, then move to dest.

    This is the hardened replacement for ``ssh_copy_from`` when receiving
    untrusted data from the VM.

    Args:
        vm_name: Name of the Lima VM.
        remote_path: Path inside the VM.
        local_path: Final destination path on the host.

    Raises:
        SSHError: If validation fails (path traversal, size limits, etc.).
    """
    from thresher.vm.ssh import ssh_copy_from

    staging = Path(tempfile.mkdtemp(prefix="vm-copy-"))
    try:
        ssh_copy_from(vm_name, remote_path, str(staging))
        validate_copied_tree(staging)
        # Move validated files to final destination
        shutil.copytree(staging, local_path, dirs_exist_ok=True)
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def validate_report_structure(report_dir: Path) -> None:
    """Verify the copied report contains expected files.

    Logs warnings for missing or unexpected files but does not raise —
    a partial report is better than no report.
    """
    present = {
        p.relative_to(report_dir)
        for p in report_dir.rglob("*")
        if p.is_file()
    }

    expected = {Path(f) for f in EXPECTED_REPORT_FILES}
    missing = expected - present
    if missing:
        logger.warning("Report missing expected files: %s", missing)

    # Known file prefixes in a valid report
    known_prefixes = {
        "scan-results/",
        "findings.json",
        "executive-summary.md",
        "detailed-report.md",
        "synthesis-findings.md",
        "sbom.json",
        "synthesis_input.md",
    }

    for f in present:
        if not any(str(f).startswith(p) for p in known_prefixes):
            logger.warning("Unexpected file in report: %s", f)
