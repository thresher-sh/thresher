"""Checkov scanner wrapper -- Infrastructure-as-Code security scanning."""

from __future__ import annotations

import logging
import subprocess
import time
from pathlib import Path
from typing import Any

from thresher.scanners.models import Finding, ScanResults

logger = logging.getLogger(__name__)


def run_checkov(target_dir: str, output_dir: str) -> ScanResults:
    """Run Checkov to detect IaC misconfigurations.

    Checkov exits with code 0 when all checks pass and code 1 when
    failures are found.  Both are valid scan results.

    Args:
        target_dir: Path to the repository.
        output_dir: Directory for scan artifacts.

    Returns:
        ScanResults with parsed Finding objects.
    """
    output_path = f"{output_dir}/checkov.json"

    start = time.monotonic()
    try:
        result = subprocess.run(
            ["checkov", "-d", target_dir, "-o", "json", "--quiet"],
            capture_output=True,
            timeout=300,
        )
        Path(output_path).write_bytes(result.stdout)
        elapsed = time.monotonic() - start

        # Exit 0 = pass, 1 = failures found.  Other codes are errors.
        if result.returncode not in (0, 1):
            logger.warning("Checkov exited with code %d: %s", result.returncode, result.stderr.decode())
            return ScanResults(
                tool_name="checkov",
                execution_time_seconds=elapsed,
                exit_code=result.returncode,
                errors=[f"Checkov failed (exit {result.returncode}): {result.stderr.decode()}"],
            )

        return ScanResults(
            tool_name="checkov",
            execution_time_seconds=elapsed,
            exit_code=result.returncode,
            raw_output_path=output_path,
        )

    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.exception("Checkov execution failed")
        return ScanResults(
            tool_name="checkov",
            execution_time_seconds=elapsed,
            exit_code=-1,
            errors=[f"Checkov execution error: {exc}"],
        )


def parse_checkov_output(raw: Any) -> list[Finding]:
    """Parse Checkov JSON output into normalized Finding objects.

    Checkov output can be a single dict or a list of dicts (one per
    framework scanned).

    Args:
        raw: Parsed JSON from Checkov's ``-o json`` output.

    Returns:
        List of normalized Finding objects.
    """
    findings: list[Finding] = []

    # Normalize to a list of framework result dicts.
    if isinstance(raw, dict):
        frameworks = [raw]
    elif isinstance(raw, list):
        frameworks = raw
    else:
        logger.error("Unexpected Checkov output type: %s", type(raw))
        return findings

    idx = 0
    for framework_result in frameworks:
        results = framework_result.get("results", {})
        failed_checks = results.get("failed_checks", [])

        for check in failed_checks:
            check_id = check.get("check_id", "unknown")
            check_type = check.get("check_type", "")
            check_result = check.get("check_result", {}).get("result", "FAILED")
            file_path = check.get("file_path")
            line_range = check.get("file_line_range", [])
            resource = check.get("resource", "")
            guideline = check.get("guideline", "")

            line_number = line_range[0] if line_range else None

            title = f"{check_id}: {check_type}" if check_type else check_id
            description_parts = [f"Resource: {resource}"]
            if guideline:
                description_parts.append(f"Guideline: {guideline}")
            description = "; ".join(description_parts)

            finding_id = f"checkov-{check_id}-{idx}"
            idx += 1

            findings.append(
                Finding(
                    id=finding_id,
                    source_tool="checkov",
                    category="iac",
                    severity="medium",
                    cvss_score=None,
                    cve_id=None,
                    title=title,
                    description=description,
                    file_path=file_path,
                    line_number=line_number,
                    package_name=None,
                    package_version=None,
                    fix_version=None,
                    raw_output=check,
                )
            )

    return findings
