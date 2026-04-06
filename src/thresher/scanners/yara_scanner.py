"""YARA scanner wrapper -- malware pattern detection."""

from __future__ import annotations

import logging
import subprocess
import time
from pathlib import Path
from typing import Any

from thresher.scanners.models import Finding, ScanResults

logger = logging.getLogger(__name__)

YARA_RULES_DIR = "/opt/yara-rules"


def run_yara(target_dir: str, output_dir: str) -> ScanResults:
    """Run YARA rules against the target directory to detect malware patterns.

    Scans using key rule categories from /opt/yara-rules.  If the rules
    directory does not exist, returns empty results with a warning.

    Args:
        target_dir: Path to the repository.
        output_dir: Directory for scan artifacts.

    Returns:
        ScanResults with parsed Finding objects.
    """
    output_path = f"{output_dir}/yara.txt"

    start = time.monotonic()
    try:
        # Check if YARA rules directory exists.
        if not Path(YARA_RULES_DIR).is_dir():
            elapsed = time.monotonic() - start
            logger.warning("YARA rules directory /opt/yara-rules not found")
            return ScanResults(
                tool_name="yara",
                execution_time_seconds=elapsed,
                exit_code=0,
                findings=[],
            )

        # Gather rule files to scan.
        malw_rules = sorted(Path(YARA_RULES_DIR, "malware").glob("MALW_*.yar"))
        packer_rules = sorted(Path(YARA_RULES_DIR, "packers").glob("*.yar"))
        rule_files = malw_rules + packer_rules

        all_output_lines: list[str] = []
        last_exit_code = 0

        for rule_file in rule_files:
            result = subprocess.run(
                ["yara", "-r", str(rule_file), target_dir],
                capture_output=True,
                timeout=600,
            )
            last_exit_code = result.returncode
            # Filter out .git matches to avoid false positives on hook samples.
            for line in result.stdout.decode(errors="replace").splitlines():
                if "/.git/" not in line:
                    all_output_lines.append(line)

        output_text = "\n".join(all_output_lines)
        Path(output_path).write_text(output_text)
        elapsed = time.monotonic() - start

        return ScanResults(
            tool_name="yara",
            execution_time_seconds=elapsed,
            exit_code=last_exit_code,
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
