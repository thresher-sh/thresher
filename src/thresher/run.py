"""Unified subprocess runner for all of Thresher.

Every subprocess call in the codebase goes through run(). This gives us:
- Streaming output (never blocks waiting for process to finish)
- Consistent logging (verbose = every line, quiet = start/finish only)
- Retry with backoff for flaky network operations
- One mock target for tests: thresher.run._popen
"""

from __future__ import annotations

import logging
import subprocess
import threading
import time
from typing import Any

logger = logging.getLogger(__name__)

# Global verbose flag — set by CLI at startup
_verbose = False

# Global stdout cap — set by CLI/harness at startup from config.limits
_max_stdout_bytes = 50 * 1024 * 1024  # default 50 MB


def set_verbose(enabled: bool) -> None:
    """Set global verbose mode. Called once by CLI at startup."""
    global _verbose
    _verbose = enabled


def set_max_stdout(limit_bytes: int) -> None:
    """Set max stdout bytes before killing a subprocess. 0 = unlimited."""
    global _max_stdout_bytes
    _max_stdout_bytes = limit_bytes


def _popen(*args: Any, **kwargs: Any) -> subprocess.Popen:
    """Thin wrapper for tests to mock."""
    return subprocess.Popen(*args, **kwargs)


def run(
    cmd: list[str],
    *,
    label: str = "",
    timeout: int = 300,
    ok_codes: tuple[int, ...] = (0,),
    **kwargs: Any,
) -> subprocess.CompletedProcess:
    """Run a command with streaming output and structured logging.

    Args:
        cmd: Command and arguments (list form, never shell).
        label: Human-readable name for log messages (default: cmd[0]).
        timeout: Seconds before killing the process.
        ok_codes: Exit codes considered success (default: (0,)).
        **kwargs: Passed to Popen (env, cwd, etc).

    Returns:
        CompletedProcess with stdout captured as bytes.
    """
    label = label or cmd[0]

    # Don't pass these through to Popen
    kwargs.pop("capture_output", None)
    kwargs.pop("timeout", None)

    logger.info("[%s] starting", label)
    logger.debug("[%s] cmd: %s", label, " ".join(cmd))

    proc = _popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **kwargs,
    )

    # Drain stderr in a background thread to prevent deadlocks
    stderr_chunks: list[bytes] = []

    def _drain_stderr():
        for raw_line in proc.stderr:
            stderr_chunks.append(raw_line)
            line = raw_line.decode(errors="replace").rstrip()
            if line:
                logger.debug("[%s:stderr] %s", label, line)

    stderr_thread = threading.Thread(target=_drain_stderr, daemon=True)
    stderr_thread.start()

    stdout_chunks: list[bytes] = []
    stdout_size = 0
    try:
        for raw_line in proc.stdout:
            stdout_chunks.append(raw_line)
            stdout_size += len(raw_line)
            if _max_stdout_bytes and stdout_size > _max_stdout_bytes:
                proc.kill()
                proc.wait()
                logger.warning(
                    "[%s] killed — stdout limit exceeded (%d bytes > %d byte limit)",
                    label, stdout_size, _max_stdout_bytes,
                )
                break
            line = raw_line.decode(errors="replace").rstrip()
            if line:
                if _verbose:
                    logger.info("[%s] %s", label, line)
                else:
                    logger.debug("[%s] %s", label, line)
        else:
            proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        logger.warning("[%s] killed after %ds timeout", label, timeout)

    stderr_thread.join(timeout=5)
    stdout = b"".join(stdout_chunks)
    stderr = b"".join(stderr_chunks)

    if proc.returncode in ok_codes:
        logger.info("[%s] done (exit %d)", label, proc.returncode)
    else:
        logger.warning("[%s] failed (exit %d)", label, proc.returncode)

    return subprocess.CompletedProcess(
        args=cmd,
        returncode=proc.returncode,
        stdout=stdout,
        stderr=stderr,
    )


def retry(
    cmd: list[str],
    *,
    label: str = "",
    timeout: int = 300,
    attempts: int = 3,
    ok_codes: tuple[int, ...] = (0,),
    **kwargs: Any,
) -> subprocess.CompletedProcess:
    """Run with exponential backoff retry.

    Same interface as run(), plus attempts parameter.
    """
    label = label or cmd[0]
    delay = 2
    last_result = None
    last_exc = None

    for attempt in range(1, attempts + 1):
        try:
            result = run(cmd, label=label, timeout=timeout, ok_codes=ok_codes, **kwargs)
            if result.returncode in ok_codes:
                return result
            last_result = result
            logger.warning("[%s] attempt %d/%d failed (exit %d)", label, attempt, attempts, result.returncode)
        except Exception as exc:
            last_exc = exc
            logger.warning("[%s] attempt %d/%d raised: %s", label, attempt, attempts, exc)

        if attempt < attempts:
            logger.info("[%s] retrying in %ds...", label, delay)
            time.sleep(delay)
            delay *= 2

    if last_exc is not None:
        raise last_exc
    return last_result
