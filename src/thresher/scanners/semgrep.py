"""Semgrep scanner wrapper -- SAST code vulnerability scanning."""

from __future__ import annotations

import logging
import time
from typing import Any

from thresher.scanners.models import Finding, ScanResults
from thresher.vm.safe_io import safe_json_loads
from thresher.vm.ssh import ssh_exec

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, str] = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


def run_semgrep(vm_name: str, target_dir: str, output_dir: str) -> ScanResults:
    """Run Semgrep SAST scan with the auto config ruleset.

    Semgrep exits with code 0 on success (findings or not), code 1 on
    findings when ``--error`` is used (we do not use it), and other codes
    for real errors.

    Args:
        vm_name: Name of the Lima VM.
        target_dir: Path to the repository inside the VM.
        output_dir: Directory for scan artifacts inside the VM.

    Returns:
        ScanResults with parsed Finding objects.
    """
    output_path = f"{output_dir}/semgrep.json"
    cmd = f"semgrep scan --config auto --json {target_dir} > {output_path} 2>/dev/null"

    start = time.monotonic()
    try:
        result = ssh_exec(vm_name, cmd, timeout=600)
        elapsed = time.monotonic() - start

        # Semgrep exit 0 = success, 1 = findings with --error (not used here).
        # Other non-zero codes are real failures.
        if result.exit_code not in (0, 1):
            logger.warning("Semgrep exited with code %d: %s", result.exit_code, result.stderr)
            return ScanResults(
                tool_name="semgrep",
                execution_time_seconds=elapsed,
                exit_code=result.exit_code,
                errors=[f"Semgrep failed (exit {result.exit_code}): {result.stderr}"],
            )

        cat_result = ssh_exec(vm_name, f"cat {output_path}")
        raw = safe_json_loads(cat_result.stdout, source="semgrep output")
        if raw is None:
            return ScanResults(
                tool_name="semgrep",
                execution_time_seconds=elapsed,
                exit_code=result.exit_code,
                errors=["Failed to parse Semgrep JSON output"],
                raw_output_path=output_path,
            )

        findings = parse_semgrep_output(raw)
        return ScanResults(
            tool_name="semgrep",
            execution_time_seconds=elapsed,
            exit_code=result.exit_code,
            findings=findings,
            raw_output_path=output_path,
        )

    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.exception("Semgrep execution failed")
        return ScanResults(
            tool_name="semgrep",
            execution_time_seconds=elapsed,
            exit_code=-1,
            errors=[f"Semgrep execution error: {exc}"],
        )


def parse_semgrep_output(raw: dict[str, Any]) -> list[Finding]:
    """Parse Semgrep JSON output into normalized Finding objects.

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

        # Some Semgrep rules include CWE or CVE references in metadata.
        cve_id = metadata.get("cve") or None
        cwe = metadata.get("cwe", [])
        if isinstance(cwe, list):
            cwe_str = ", ".join(cwe) if cwe else ""
        else:
            cwe_str = str(cwe)

        title = f"{check_id}"
        if cwe_str:
            title = f"{check_id} ({cwe_str})"

        finding_id = f"semgrep-{check_id}"

        findings.append(
            Finding(
                id=finding_id,
                source_tool="semgrep",
                category="sast",
                severity=severity,
                cvss_score=None,
                cve_id=cve_id,
                title=title,
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
