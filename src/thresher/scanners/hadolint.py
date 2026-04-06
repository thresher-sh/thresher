"""Hadolint scanner wrapper -- Dockerfile linting."""

from __future__ import annotations

import logging
import subprocess
import time
from pathlib import Path
from typing import Any

from thresher.scanners.models import Finding, ScanResults

logger = logging.getLogger(__name__)

_LEVEL_MAP: dict[str, str] = {
    "error": "high",
    "warning": "medium",
    "info": "low",
    "style": "low",
}


def run_hadolint(target_dir: str, output_dir: str) -> ScanResults:
    """Run Hadolint to lint Dockerfiles in the target directory.

    First finds all Dockerfiles, then runs Hadolint on each.  If no
    Dockerfiles are found, returns empty results.

    Args:
        target_dir: Path to the repository.
        output_dir: Directory for scan artifacts.

    Returns:
        ScanResults with parsed Finding objects.
    """
    output_path = f"{output_dir}/hadolint.json"

    start = time.monotonic()
    try:
        # Find Dockerfiles in the target directory.
        dockerfiles = [
            str(p)
            for p in Path(target_dir).rglob("Dockerfile*")
            if ".git" not in p.parts
        ]
        elapsed = time.monotonic() - start

        if not dockerfiles:
            logger.info("No Dockerfiles found, skipping Hadolint")
            return ScanResults(
                tool_name="hadolint",
                execution_time_seconds=elapsed,
                exit_code=0,
                findings=[],
            )

        # Run Hadolint on all discovered Dockerfiles.
        result = subprocess.run(
            ["hadolint", "--format", "json"] + dockerfiles,
            capture_output=True,
            timeout=300,
        )
        Path(output_path).write_bytes(result.stdout)
        elapsed = time.monotonic() - start

        # Hadolint exits 0 = no issues, 1 = issues found.
        if result.returncode not in (0, 1):
            logger.warning("Hadolint exited with code %d: %s", result.returncode, result.stderr.decode())
            return ScanResults(
                tool_name="hadolint",
                execution_time_seconds=elapsed,
                exit_code=result.returncode,
                errors=[f"Hadolint failed (exit {result.returncode}): {result.stderr.decode()}"],
            )

        return ScanResults(
            tool_name="hadolint",
            execution_time_seconds=elapsed,
            exit_code=result.returncode,
            raw_output_path=output_path,
        )

    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.exception("Hadolint execution failed")
        return ScanResults(
            tool_name="hadolint",
            execution_time_seconds=elapsed,
            exit_code=-1,
            errors=[f"Hadolint execution error: {exc}"],
        )


def parse_hadolint_output(raw: list[dict[str, Any]]) -> list[Finding]:
    """Parse Hadolint JSON output into normalized Finding objects.

    Args:
        raw: Parsed JSON list from Hadolint's ``--format json`` output.

    Returns:
        List of normalized Finding objects.
    """
    findings: list[Finding] = []

    for idx, item in enumerate(raw):
        code = item.get("code", "unknown")
        message = item.get("message", "")
        level = item.get("level", "info")
        file_path = item.get("file")
        line_number = item.get("line")

        severity = _LEVEL_MAP.get(level, "low")

        title = f"{code}: {message}"
        finding_id = f"hadolint-{code}-{idx}"

        findings.append(
            Finding(
                id=finding_id,
                source_tool="hadolint",
                category="iac",
                severity=severity,
                cvss_score=None,
                cve_id=None,
                title=title,
                description=message,
                file_path=file_path,
                line_number=line_number,
                package_name=None,
                package_version=None,
                fix_version=None,
                raw_output=item,
            )
        )

    return findings
