"""Syft scanner wrapper -- generates CycloneDX SBOM."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from threat_scanner.scanners.models import ScanResults
from threat_scanner.vm.ssh import ssh_exec

logger = logging.getLogger(__name__)


def run_syft(vm_name: str, target_dir: str, output_dir: str) -> ScanResults:
    """Run Syft to generate a CycloneDX JSON SBOM.

    Syft produces an SBOM, not vulnerability findings, so the returned
    ScanResults will have an empty findings list.  The SBOM path is stored
    in ``metadata["sbom_path"]`` for downstream consumers (e.g. Grype).

    Args:
        vm_name: Name of the Lima VM to run inside.
        target_dir: Path to the cloned repository inside the VM.
        output_dir: Directory inside the VM where scan artifacts are written.

    Returns:
        ScanResults with metadata containing the SBOM path.
    """
    sbom_path = f"{output_dir}/sbom.json"
    cmd = f"syft {target_dir} -o cyclonedx-json > {sbom_path}"

    start = time.monotonic()
    try:
        result = ssh_exec(vm_name, cmd)
        elapsed = time.monotonic() - start

        # Syft exit 0 on success.  Any non-zero is a real error.
        if result.exit_code != 0:
            logger.warning("Syft exited with code %d: %s", result.exit_code, result.stderr)
            return ScanResults(
                tool_name="syft",
                execution_time_seconds=elapsed,
                exit_code=result.exit_code,
                errors=[f"Syft failed (exit {result.exit_code}): {result.stderr}"],
            )

        return ScanResults(
            tool_name="syft",
            execution_time_seconds=elapsed,
            exit_code=0,
            raw_output_path=sbom_path,
            metadata={"sbom_path": sbom_path},
        )

    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.exception("Syft execution failed")
        return ScanResults(
            tool_name="syft",
            execution_time_seconds=elapsed,
            exit_code=-1,
            errors=[f"Syft execution error: {exc}"],
        )
