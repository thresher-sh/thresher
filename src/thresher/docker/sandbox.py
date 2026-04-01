"""Dependency resolution via the scanner-deps container.

All ecosystem detection, dependency downloading, and manifest generation
is handled by a single Docker container (scanner-deps:latest) invoked
through the locked-down scanner-docker wrapper. Nothing leaves the VM —
the manifest and deps stay inside for scanners and agents to consume.
"""

from __future__ import annotations

import logging

from thresher.config import ScanConfig

logger = logging.getLogger(__name__)


def download_dependencies(vm_name: str, config: ScanConfig) -> None:
    """Invoke the scanner-docker wrapper to resolve dependencies.

    The container detects ecosystems, downloads source-only deps, and
    writes dep_manifest.json — all in a single invocation with no
    arguments. Everything stays inside the VM.

    Args:
        vm_name: Name of the Lima VM.
        config: Scan configuration.

    Raises:
        RuntimeError: If dependency resolution fails.
    """
    from thresher.vm.ssh import ssh_exec

    # Ensure working directories exist and copy target repo to
    # the container's expected mount location (all inside the VM)
    ssh_exec(vm_name, (
        "sudo mkdir -p /home/scanner/work/target /home/scanner/work/deps && "
        "sudo cp -r /opt/target/* /home/scanner/work/target/ 2>/dev/null || true"
    ))

    # Single invocation — the wrapper and container handle everything
    stdout, stderr, exit_code = ssh_exec(
        vm_name,
        "sudo /usr/local/bin/scanner-docker",
        timeout=600,
    )

    if exit_code != 0:
        raise RuntimeError(f"Dependency resolution failed (exit {exit_code}): {stderr}")

    # Copy resolved deps to /opt/deps so scanners can find them (all inside VM)
    ssh_exec(vm_name, "sudo cp -r /home/scanner/work/deps/* /opt/deps/ 2>/dev/null || true")

    logger.info("Dependency resolution complete")
