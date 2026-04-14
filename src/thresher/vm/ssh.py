"""SSH execution helpers for communicating with Lima VMs."""

from __future__ import annotations

import logging
import os
import re
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Callable, NamedTuple

logger = logging.getLogger(__name__)

# Module-level semaphore to limit concurrent SSH sessions and avoid
# SSH mux contention (ControlSocket collisions, session request failures).
# Default of 8 is overridden by config.limits.max_concurrent_ssh when
# load_config() is called.
_ssh_semaphore = threading.Semaphore(8)


def _init_ssh_semaphore(max_concurrent: int) -> None:
    """Re-initialise the SSH semaphore with a new concurrency limit.

    Called by load_config() after reading the limits table so the
    configured value takes effect before any scans start.
    """
    global _ssh_semaphore
    _ssh_semaphore = threading.Semaphore(max_concurrent)


# Patterns for credential redaction in log output
_CREDENTIAL_PATTERNS = [
    # Anthropic OAuth tokens
    (re.compile(r"sk-ant-oat01-[A-Za-z0-9_-]+"), "sk-ant-oat01-****"),
    # Anthropic API keys
    (re.compile(r"sk-ant-api[A-Za-z0-9_-]+"), "sk-ant-api****"),
]

# Pattern for printf payloads writing to tmpfs credentials
_PRINTF_TMPFS_PATTERN = re.compile(
    r"(printf\s+'%s'\s+)'[^']*'(\s*>\s*/dev/shm/)"
)


def _redact_credentials(text: str) -> str:
    """Mask API tokens and tmpfs credential payloads in log output.

    This is applied to logged representations only — never to the
    actual command passed to subprocess.
    """
    # Redact printf payloads targeting /dev/shm/
    text = _PRINTF_TMPFS_PATTERN.sub(r"\1'[REDACTED]'\2", text)
    # Redact known credential patterns
    for pattern, replacement in _CREDENTIAL_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


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
    on_stdout: "Callable[[str], None] | None" = None,
) -> SSHResult:
    """Run a command inside the Lima VM via limactl shell.

    Streams stdout and stderr to the logger in real time so they appear
    in the log pane, while still capturing full output for the caller.

    Args:
        on_stdout: Optional callback invoked with each stdout line.
                   Used for progress tracking during long operations.
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

    # Log a short label (first 80 chars of the command, no secrets)
    label = _redact_credentials(command[:80])
    logger.info("vm:%s> %s", vm_name, label)

    cmd = ["limactl", "shell", vm_name, "bash", "-c", full_command]

    # Throttle concurrent SSH sessions to avoid mux contention
    # (ControlSocket collisions, "session request failed" errors).
    _ssh_semaphore.acquire()
    logger.debug("SSH session acquired for: %s", command[:80])

    try:
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError as exc:
            raise SSHError(
                "limactl not found. Is Lima installed?"
            ) from exc

        stdout_lines: list[str] = []
        stderr_lines: list[str] = []

        # Maximum stdout we'll accumulate before killing the process.
        # Prevents a compromised VM from exhausting host memory.
        # Read from config if available, otherwise use default.
        try:
            from thresher.config import active_limits
            max_stdout_bytes = active_limits.max_stdout_bytes
        except ImportError:
            max_stdout_bytes = 50 * 1024 * 1024  # 50 MB fallback

        try:
            import selectors
            import time

            sel = selectors.DefaultSelector()
            sel.register(proc.stdout, selectors.EVENT_READ)
            sel.register(proc.stderr, selectors.EVENT_READ)

            stdout_size = 0
            try:
                deadline = time.monotonic() + timeout
                while sel.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        proc.kill()
                        proc.wait()
                        raise SSHError(
                            f"Command timed out after {timeout}s in VM '{vm_name}': {command}"
                        )
                    events = sel.select(timeout=min(remaining, 1.0))
                    for key, _ in events:
                        line = key.fileobj.readline()  # type: ignore[union-attr]
                        if not line:
                            sel.unregister(key.fileobj)
                            continue
                        stripped = line.rstrip("\n")
                        if key.fileobj is proc.stdout:
                            stdout_size += len(line)
                            if stdout_size > max_stdout_bytes:
                                proc.kill()
                                proc.wait()
                                raise SSHError(
                                    f"VM output exceeded {max_stdout_bytes} bytes, "
                                    f"killed process in '{vm_name}'"
                                )
                            stdout_lines.append(line)
                            logger.info("  %s", _redact_credentials(stripped))
                            if on_stdout:
                                on_stdout(_redact_credentials(stripped))
                        else:
                            stderr_lines.append(line)
                            logger.warning("  %s", _redact_credentials(stripped))
            finally:
                sel.close()

            proc.wait()
            return SSHResult("".join(stdout_lines), "".join(stderr_lines), proc.returncode)
        finally:
            # Ensure pipes are closed to avoid ResourceWarnings
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()
    finally:
        _ssh_semaphore.release()


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
