"""Dependency resolution via the scanner-deps container.

All ecosystem detection, dependency downloading, and manifest generation
is handled by a single Docker container (scanner-deps:latest) invoked
through the locked-down scanner-docker wrapper. Nothing leaves the VM —
the manifest and deps stay inside for scanners and agents to consume.
"""

from __future__ import annotations

import logging
import time

from thresher.config import ScanConfig

logger = logging.getLogger(__name__)

# Retry configuration for transient network failures
# (npm getaddrinfo EAI_AGAIN, cargo vendor DNS errors, etc.)
_MAX_RETRIES = 3
_RETRY_DELAYS = [5, 15, 45]  # seconds — exponential backoff


def download_dependencies(vm_name: str, config: ScanConfig) -> None:
    """Invoke the scanner-docker wrapper to resolve dependencies.

    The container detects ecosystems, downloads source-only deps, and
    writes dep_manifest.json — all in a single invocation with no
    arguments. Everything stays inside the VM.

    Retries up to 3 times with exponential backoff on transient failures
    (DNS resolution, network timeouts). A DNS health check runs between
    retries to surface connectivity issues early.

    Args:
        vm_name: Name of the Lima VM.
        config: Scan configuration.

    Raises:
        RuntimeError: If dependency resolution fails after all retries.
    """
    from thresher.vm.ssh import ssh_exec

    # Ensure working directories exist and copy target repo to
    # the container's expected mount location (all inside the VM)
    ssh_exec(vm_name, (
        "sudo mkdir -p /opt/thresher/work/target /opt/thresher/work/deps && "
        "sudo cp -r /opt/target/* /opt/thresher/work/target/ 2>/dev/null || true"
    ))

    for attempt in range(1, _MAX_RETRIES + 1):
        # Single invocation — the wrapper and container handle everything
        stdout, stderr, exit_code = ssh_exec(
            vm_name,
            "sudo /usr/local/bin/scanner-docker",
            timeout=600,
        )

        if exit_code == 0:
            if attempt > 1:
                logger.info(
                    "Dependency resolution succeeded on attempt %d/%d",
                    attempt, _MAX_RETRIES,
                )
            break

        is_transient = _is_transient_failure(stderr)

        if attempt < _MAX_RETRIES and is_transient:
            delay = _RETRY_DELAYS[attempt - 1]
            logger.warning(
                "Dependency resolution failed (attempt %d/%d, exit %d), "
                "retrying in %ds: %s",
                attempt, _MAX_RETRIES, exit_code, delay,
                stderr[:200],
            )

            # DNS health check between retries to surface connectivity issues
            _dns_health_check(vm_name)

            time.sleep(delay)
        else:
            if not is_transient:
                logger.warning(
                    "Dependency resolution failed with non-transient error "
                    "(attempt %d/%d), not retrying",
                    attempt, _MAX_RETRIES,
                )
            raise RuntimeError(
                f"Dependency resolution failed after {attempt} attempt(s) "
                f"(exit {exit_code}): {stderr}"
            )

    # Copy resolved deps to /opt/deps so scanners can find them (all inside VM)
    ssh_exec(vm_name, "sudo cp -r /opt/thresher/work/deps/* /opt/deps/ 2>/dev/null || true")

    logger.info("Dependency resolution complete")


def _is_transient_failure(stderr: str) -> bool:
    """Check if the failure looks like a transient network issue."""
    transient_markers = [
        "EAI_AGAIN",           # npm DNS resolution
        "ETIMEDOUT",           # npm connection timeout
        "ECONNRESET",          # npm connection reset
        "ECONNREFUSED",        # npm connection refused
        "getaddrinfo",         # General DNS failure
        "network error",       # cargo vendor
        "timed out",           # General timeout
        "Could not resolve",   # curl/wget DNS
        "Name or service not known",  # Linux DNS
        "Temporary failure in name resolution",  # Linux DNS
    ]
    stderr_lower = stderr.lower()
    return any(marker.lower() in stderr_lower for marker in transient_markers)


def _dns_health_check(vm_name: str) -> None:
    """Run a DNS lookup inside the VM and log the result.

    This helps diagnose whether the VM has working DNS connectivity
    between dependency download retries.
    """
    from thresher.vm.ssh import ssh_exec

    try:
        stdout, stderr, rc = ssh_exec(
            vm_name,
            "nslookup registry.npmjs.org",
            timeout=15,
        )
        if rc == 0:
            logger.info("DNS health check OK: registry.npmjs.org resolved")
        else:
            logger.warning(
                "DNS health check FAILED (exit %d): %s",
                rc, stderr[:200],
            )
    except Exception as exc:
        logger.warning("DNS health check error: %s", exc)
