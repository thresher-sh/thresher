"""Syft scanner wrapper -- generates CycloneDX SBOM."""

from __future__ import annotations

import logging
import subprocess
import time
from pathlib import Path
from typing import Any

from thresher.scanners.models import ScanResults

logger = logging.getLogger(__name__)


def run_syft(target_dir: str, output_dir: str) -> ScanResults:
    """Run Syft to generate a CycloneDX JSON SBOM.

    Syft produces an SBOM, not vulnerability findings, so the returned
    ScanResults will have an empty findings list.  The SBOM path is stored
    in ``metadata["sbom_path"]`` for downstream consumers (e.g. Grype).

    Args:
        target_dir: Path to the cloned repository.
        output_dir: Directory where scan artifacts are written.

    Returns:
        ScanResults with metadata containing the SBOM path.
    """
    sbom_path = f"{output_dir}/sbom.json"

    start = time.monotonic()
    try:
        result = subprocess.run(
            ["syft", target_dir, "-o", "cyclonedx-json"],
            capture_output=True,
            timeout=300,
        )
        Path(sbom_path).write_bytes(result.stdout)
        elapsed = time.monotonic() - start

        # Syft exit 0 on success.  Any non-zero is a real error.
        if result.returncode != 0:
            logger.warning("Syft exited with code %d: %s", result.returncode, result.stderr.decode())
            return ScanResults(
                tool_name="syft",
                execution_time_seconds=elapsed,
                exit_code=result.returncode,
                errors=[f"Syft failed (exit {result.returncode}): {result.stderr.decode()}"],
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
