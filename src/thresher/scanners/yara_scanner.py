"""YARA scanner wrapper -- malware pattern detection."""

from __future__ import annotations

import logging
import time
from typing import Any

from thresher.scanners.models import Finding, ScanResults
from thresher.vm.ssh import ssh_exec

logger = logging.getLogger(__name__)


def run_yara(vm_name: str, target_dir: str, output_dir: str) -> ScanResults:
    """Run YARA rules against the target directory to detect malware patterns.

    Scans using key rule categories from /opt/yara-rules.  If the rules
    directory does not exist, returns empty results with a warning.

    Args:
        vm_name: Name of the Lima VM.
        target_dir: Path to the repository inside the VM.
        output_dir: Directory for scan artifacts inside the VM.

    Returns:
        ScanResults with parsed Finding objects.
    """
    output_path = f"{output_dir}/yara.txt"

    start = time.monotonic()
    try:
        # Check if YARA rules directory exists.
        check_result = ssh_exec(vm_name, "[ -d /opt/yara-rules ] && echo exists")
        if "exists" not in check_result.stdout:
            elapsed = time.monotonic() - start
            logger.warning("YARA rules directory /opt/yara-rules not found")
            return ScanResults(
                tool_name="yara",
                execution_time_seconds=elapsed,
                exit_code=0,
                findings=[],
            )

        # Run YARA with key rule categories, suppressing errors from
        # individual rule files that fail to compile.
        # Exclude .git directory to avoid false positives on hook samples.
        cmd = (
            f"for f in /opt/yara-rules/malware/MALW_*.yar "
            f"/opt/yara-rules/packers/*.yar; do "
            f"yara -r \"$f\" {target_dir} 2>/dev/null | grep -v '/.git/'; "
            f"done > {output_path}"
        )

        result = ssh_exec(vm_name, cmd, timeout=600)
        elapsed = time.monotonic() - start

        # Findings remain inside the VM at output_path.
        # No data crosses the VM trust boundary.
        return ScanResults(
            tool_name="yara",
            execution_time_seconds=elapsed,
            exit_code=result.exit_code,
            raw_output_path=output_path,
        )

    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.exception("YARA execution failed")
        return ScanResults(
            tool_name="yara",
            execution_time_seconds=elapsed,
            exit_code=-1,
            errors=[f"YARA execution error: {exc}"],
        )


def parse_yara_output(raw_text: str) -> list[Finding]:
    """Parse YARA text output into normalized Finding objects.

    YARA outputs one match per line in the format: ``rule_name file_path``

    Args:
        raw_text: Raw text output from YARA.

    Returns:
        List of normalized Finding objects.
    """
    findings: list[Finding] = []

    for idx, line in enumerate(raw_text.splitlines()):
        line = line.strip()
        if not line:
            continue

        parts = line.split(None, 1)
        if len(parts) < 2:
            continue

        rule_name = parts[0]
        file_path = parts[1]

        title = f"YARA match: {rule_name}"
        description = f"YARA rule '{rule_name}' matched file: {file_path}"
        finding_id = f"yara-{rule_name}-{idx}"

        findings.append(
            Finding(
                id=finding_id,
                source_tool="yara",
                category="malware",
                severity="critical",
                cvss_score=None,
                cve_id=None,
                title=title,
                description=description,
                file_path=file_path,
                line_number=None,
                package_name=None,
                package_version=None,
                fix_version=None,
                raw_output={"rule": rule_name, "file": file_path},
            )
        )

    return findings
