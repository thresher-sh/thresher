"""Semgrep supply-chain scanner -- runs custom rules against dependency source."""

from __future__ import annotations

import logging
import subprocess
import time
from pathlib import Path
from typing import Any

from thresher.scanners.models import Finding, ScanResults

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, str] = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}

DEPS_DIR = "/opt/deps"
RULES_PATH = "/opt/rules/semgrep/supply-chain.yaml"


def run_semgrep_supply_chain(output_dir: str) -> ScanResults:
    """Run Semgrep with custom supply-chain rules against /opt/deps/.

    Uses the supply-chain.yaml rules file instead of ``--config auto``.
    Findings remain in output_dir.

    Args:
        output_dir: Directory for scan artifacts.

    Returns:
        ScanResults with execution metadata only (findings stay in output_dir).
    """
    output_path = f"{output_dir}/semgrep-supply-chain.json"

    start = time.monotonic()
    try:
        result = subprocess.run(
            ["semgrep", "scan", "--config", RULES_PATH, "--json", DEPS_DIR],
            capture_output=True,
            timeout=600,
        )
        Path(output_path).write_bytes(result.stdout)
        elapsed = time.monotonic() - start

        if result.returncode not in (0, 1):
            logger.warning(
                "Semgrep supply-chain exited with code %d: %s",
                result.returncode,
                result.stderr.decode(),
            )
            return ScanResults(
                tool_name="semgrep-supply-chain",
                execution_time_seconds=elapsed,
                exit_code=result.returncode,
                errors=[
                    f"Semgrep supply-chain failed (exit {result.returncode}): "
                    f"{result.stderr.decode()}"
                ],
            )

        return ScanResults(
            tool_name="semgrep-supply-chain",
            execution_time_seconds=elapsed,
            exit_code=result.returncode,
            raw_output_path=output_path,
        )

    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.exception("Semgrep supply-chain execution failed")
        return ScanResults(
            tool_name="semgrep-supply-chain",
            execution_time_seconds=elapsed,
            exit_code=-1,
            errors=[f"Semgrep supply-chain execution error: {exc}"],
        )


def parse_semgrep_supply_chain_output(raw: dict[str, Any]) -> list[Finding]:
    """Parse Semgrep supply-chain JSON output into normalized Finding objects.

    Args:
        raw: Parsed JSON dict from Semgrep's ``--json`` output.

    Returns:
        List of normalized Finding objects.
    """
    findings: list[Finding] = []
    results = raw.get("results", [])

    for hit in results:
        check_id = hit.get("check_id", "unknown")
        extra = hit.get("extra", {})

        severity_raw = extra.get("severity", "INFO")
        severity = _SEVERITY_MAP.get(severity_raw.upper(), "info")

        message = extra.get("message", "")
        metadata = extra.get("metadata", {})

        file_path = hit.get("path")
        start_info = hit.get("start", {})
        line_number = start_info.get("line")

        finding_id = f"semgrep-sc-{check_id}"

        findings.append(
            Finding(
                id=finding_id,
                source_tool="semgrep-supply-chain",
                category="behavioral",
                severity=severity,
                cvss_score=None,
                cve_id=None,
                title=check_id,
                description=message,
                file_path=file_path,
                line_number=line_number,
                package_name=None,
                package_version=None,
                fix_version=None,
                raw_output=hit,
            )
        )

    return findings
