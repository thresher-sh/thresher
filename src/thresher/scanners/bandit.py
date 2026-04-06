"""Bandit scanner wrapper -- Python SAST analysis."""

from __future__ import annotations

import logging
import subprocess
import time
from pathlib import Path
from typing import Any

from thresher.scanners.models import Finding, ScanResults

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, str] = {
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}


def run_bandit(target_dir: str, output_dir: str) -> ScanResults:
    """Run Bandit to detect security issues in Python code.

    Bandit exits with code 0 when no issues are found and code 1 when
    issues are detected.  Both are valid scan results.

    Args:
        target_dir: Path to the repository.
        output_dir: Directory for scan artifacts.

    Returns:
        ScanResults with parsed Finding objects.
    """
    output_path = f"{output_dir}/bandit.json"

    start = time.monotonic()
    try:
        result = subprocess.run(
            ["bandit", "-r", target_dir, "-f", "json"],
            capture_output=True,
            timeout=300,
        )
        Path(output_path).write_bytes(result.stdout)
        elapsed = time.monotonic() - start

        # Exit 0 = no issues, 1 = issues found.  Other codes are errors.
        if result.returncode not in (0, 1):
            logger.warning("Bandit exited with code %d: %s", result.returncode, result.stderr.decode())
            return ScanResults(
                tool_name="bandit",
                execution_time_seconds=elapsed,
                exit_code=result.returncode,
                errors=[f"Bandit failed (exit {result.returncode}): {result.stderr.decode()}"],
            )

        return ScanResults(
            tool_name="bandit",
            execution_time_seconds=elapsed,
            exit_code=result.returncode,
            raw_output_path=output_path,
        )

    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.exception("Bandit execution failed")
        return ScanResults(
            tool_name="bandit",
            execution_time_seconds=elapsed,
            exit_code=-1,
            errors=[f"Bandit execution error: {exc}"],
        )


def parse_bandit_output(raw: dict[str, Any]) -> list[Finding]:
    """Parse Bandit JSON output into normalized Finding objects.

    Args:
        raw: Parsed JSON dict from Bandit's ``-f json`` output.

    Returns:
        List of normalized Finding objects.
    """
    findings: list[Finding] = []
    results = raw.get("results", [])

    for idx, issue in enumerate(results):
        test_id = issue.get("test_id", "unknown")
        test_name = issue.get("test_name", "")
        file_path = issue.get("filename")
        line_number = issue.get("line_number")
        severity_raw = issue.get("issue_severity", "LOW")
        confidence = issue.get("issue_confidence", "")
        issue_text = issue.get("issue_text", "")

        severity = _SEVERITY_MAP.get(severity_raw.upper(), "low")

        title = f"{test_id}: {test_name}"
        description = f"{issue_text} (confidence: {confidence})"

        finding_id = f"bandit-{test_id}-{idx}"

        findings.append(
            Finding(
                id=finding_id,
                source_tool="bandit",
                category="sast",
                severity=severity,
                cvss_score=None,
                cve_id=None,
                title=title,
                description=description,
                file_path=file_path,
                line_number=line_number,
                package_name=None,
                package_version=None,
                fix_version=None,
                raw_output=issue,
            )
        )

    return findings
