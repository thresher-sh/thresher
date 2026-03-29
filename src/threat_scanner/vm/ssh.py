"""SSH execution helpers for communicating with Lima VMs."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path
from typing import NamedTuple


class SSHError(Exception):
    """Raised when an SSH operation fails."""


class SSHResult(NamedTuple):
    """Result from an SSH command execution."""

    stdout: str
    stderr: str
    exit_code: int


def ssh_exec(
    vm_name: str,
    command: str,
    timeout: int = 300,
    env: dict[str, str] | None = None,
) -> SSHResult:
    """Run a command inside the Lima VM via limactl shell.

    Args:
        vm_name: Name of the Lima VM.
        command: Shell command to execute inside the VM.
        timeout: Timeout in seconds (default 300).
        env: Optional environment variables to set in the remote shell.

    Returns:
        SSHResult with stdout, stderr, and exit_code attributes.

    Raises:
        SSHError: If the command times out or limactl itself fails.
    """
    # Build the full command with exported env vars so they propagate
    # through &&-chained commands and subshells.
    if env:
        exports = " ".join(
            f"export {k}={_shell_quote(v)};" for k, v in env.items()
        )
        full_command = f"{exports} {command}"
    else:
        full_command = command

    cmd = ["limactl", "shell", vm_name, "bash", "-c", full_command]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise SSHError(
            f"Command timed out after {timeout}s in VM '{vm_name}': {command}"
        ) from exc
    except FileNotFoundError as exc:
        raise SSHError(
            "limactl not found. Is Lima installed?"
        ) from exc

    return SSHResult(result.stdout, result.stderr, result.returncode)


def ssh_copy_to(vm_name: str, local_path: str, remote_path: str) -> None:
    """Copy a file from the host into the Lima VM.

    Uses limactl copy to transfer files via SSH.

    Args:
        vm_name: Name of the Lima VM.
        local_path: Path on the host filesystem.
        remote_path: Destination path inside the VM.

    Raises:
        SSHError: If the copy fails.
        FileNotFoundError: If the local file does not exist.
    """
    local = Path(local_path)
    if not local.exists():
        raise FileNotFoundError(f"Local file not found: {local_path}")

    cmd = ["limactl", "copy", local_path, f"{vm_name}:{remote_path}"]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        raise SSHError(
            f"Copy to VM '{vm_name}' timed out: {local_path} -> {remote_path}"
        ) from exc
    except FileNotFoundError as exc:
        raise SSHError("limactl not found. Is Lima installed?") from exc

    if result.returncode != 0:
        raise SSHError(
            f"Failed to copy {local_path} to {vm_name}:{remote_path}: {result.stderr}"
        )


def ssh_copy_from(vm_name: str, remote_path: str, local_path: str) -> None:
    """Copy a file or directory from the Lima VM to the host.

    Uses limactl copy with -r flag to support recursive directory copies.

    Args:
        vm_name: Name of the Lima VM.
        remote_path: Path inside the VM.
        local_path: Destination path on the host filesystem.

    Raises:
        SSHError: If the copy fails.
    """
    # Ensure the local destination directory exists
    local = Path(local_path)
    local.mkdir(parents=True, exist_ok=True)

    cmd = ["limactl", "copy", "-r", f"{vm_name}:{remote_path}", local_path]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired as exc:
        raise SSHError(
            f"Copy from VM '{vm_name}' timed out: {remote_path} -> {local_path}"
        ) from exc
    except FileNotFoundError as exc:
        raise SSHError("limactl not found. Is Lima installed?") from exc

    if result.returncode != 0:
        raise SSHError(
            f"Failed to copy {vm_name}:{remote_path} to {local_path}: {result.stderr}"
        )


def ssh_write_file(vm_name: str, content: str, remote_path: str) -> None:
    """Write string content to a file inside the VM safely.

    Writes to a local temp file and copies via SSH, avoiding heredoc
    injection issues with untrusted content.

    Args:
        vm_name: Name of the Lima VM.
        content: File content to write.
        remote_path: Destination path inside the VM.

    Raises:
        SSHError: If the copy fails.
    """
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".tmp", delete=False
    ) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        ssh_copy_to(vm_name, tmp_path, remote_path)
    finally:
        os.unlink(tmp_path)


def _shell_quote(value: str) -> str:
    """Quote a string for safe inclusion in a shell command."""
    return "'" + value.replace("'", "'\\''") + "'"
