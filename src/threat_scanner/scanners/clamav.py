"""ClamAV scanner wrapper -- open source antivirus scanning."""

from __future__ import annotations

import logging
import time
from typing import Any

from threat_scanner.scanners.models import Finding, ScanResults
from threat_scanner.vm.ssh import ssh_exec

logger = logging.getLogger(__name__)


def run_clamav(vm_name: str, target_dir: str, output_dir: str) -> ScanResults:
    """Run ClamAV to scan for known viruses and malware.

    Uses clamscan (on-demand scanner) rather than the daemon.
    Exit 0 = clean, 1 = virus found, 2 = error.
    """
    output_path = f"{output_dir}/clamav.txt"
    cmd = (
        f"clamscan -r --infected --no-summary "
        f"{target_dir} > {output_path} 2>/dev/null"
    )

    start = time.monotonic()
    try:
        result = ssh_exec(vm_name, cmd)
        elapsed = time.monotonic() - start

        if result.exit_code == 2:
            logger.warning("ClamAV error (exit 2): %s", result.stderr)
            return ScanResults(
                tool_name="clamav",
                execution_time_seconds=elapsed,
                exit_code=result.exit_code,
                errors=[f"ClamAV error (exit 2): {result.stderr}"],
            )

        if result.exit_code == 0:
            return ScanResults(
                tool_name="clamav",
                execution_time_seconds=elapsed,
                exit_code=0,
                findings=[],
                raw_output_path=output_path,
            )

        # Exit 1 = infections found. Parse output.
        cat_result = ssh_exec(vm_name, f"cat {output_path}")
        findings = _parse_clamav_output(cat_result.stdout)
        return ScanResults(
            tool_name="clamav",
            execution_time_seconds=elapsed,
            exit_code=result.exit_code,
            findings=findings,
            raw_output_path=output_path,
        )

    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.exception("ClamAV execution failed")
        return ScanResults(
            tool_name="clamav",
            execution_time_seconds=elapsed,
            exit_code=-1,
            errors=[f"ClamAV execution error: {exc}"],
        )


def _parse_clamav_output(text: str) -> list[Finding]:
    """Parse ClamAV text output into Finding objects.

    ClamAV --infected output format: ``/path/to/file: VirusName FOUND``
    """
    findings: list[Finding] = []

    for idx, line in enumerate(text.strip().splitlines()):
        line = line.strip()
        if not line or "FOUND" not in line:
            continue

        # Format: /path/to/file: Virus.Name FOUND
        parts = line.rsplit(":", 1)
        if len(parts) != 2:
            continue

        file_path = parts[0].strip()
        virus_info = parts[1].strip()
        virus_name = virus_info.replace(" FOUND", "").strip()

        findings.append(
            Finding(
                id=f"clamav-{virus_name}-{idx}",
                source_tool="clamav",
                category="malware",
                severity="critical",
                cvss_score=None,
                cve_id=None,
                title=f"Virus detected: {virus_name}",
                description=f"ClamAV detected {virus_name} in {file_path}",
                file_path=file_path,
                line_number=None,
                package_name=None,
                package_version=None,
                fix_version=None,
                raw_output={"file": file_path, "virus": virus_name},
            )
        )

    return findings
