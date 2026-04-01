"""Trivy scanner wrapper -- filesystem vulnerability scanning."""

from __future__ import annotations

import logging
import time
from typing import Any

from thresher.scanners.models import Finding, ScanResults
from thresher.vm.safe_io import safe_json_loads
from thresher.vm.ssh import ssh_exec

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}


def run_trivy(vm_name: str, target_dir: str, output_dir: str) -> ScanResults:
    """Run Trivy filesystem scan to detect vulnerabilities.

    Args:
        vm_name: Name of the Lima VM.
        target_dir: Path to the repository inside the VM.
        output_dir: Directory for scan artifacts inside the VM.

    Returns:
        ScanResults with parsed Finding objects.
    """
    output_path = f"{output_dir}/trivy.json"
    cmd = f"trivy fs --format json --output {output_path} {target_dir} 2>/dev/null"

    start = time.monotonic()
    try:
        result = ssh_exec(vm_name, cmd)
        elapsed = time.monotonic() - start

        if result.exit_code not in (0, 1):
            logger.warning("Trivy exited with code %d: %s", result.exit_code, result.stderr)
            return ScanResults(
                tool_name="trivy",
                execution_time_seconds=elapsed,
                exit_code=result.exit_code,
                errors=[f"Trivy failed (exit {result.exit_code}): {result.stderr}"],
            )

        cat_result = ssh_exec(vm_name, f"cat {output_path}")
        raw = safe_json_loads(cat_result.stdout, source="trivy output")
        if raw is None:
            return ScanResults(
                tool_name="trivy",
                execution_time_seconds=elapsed,
                exit_code=result.exit_code,
                errors=["Failed to parse Trivy JSON output"],
                raw_output_path=output_path,
            )

        findings = parse_trivy_output(raw)
        return ScanResults(
            tool_name="trivy",
            execution_time_seconds=elapsed,
            exit_code=result.exit_code,
            findings=findings,
            raw_output_path=output_path,
        )

    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.exception("Trivy execution failed")
        return ScanResults(
            tool_name="trivy",
            execution_time_seconds=elapsed,
            exit_code=-1,
            errors=[f"Trivy execution error: {exc}"],
        )


def parse_trivy_output(raw: dict[str, Any]) -> list[Finding]:
    """Parse Trivy JSON output into normalized Finding objects.

    Args:
        raw: Parsed JSON dict from Trivy's ``--format json`` output.

    Returns:
        List of normalized Finding objects.
    """
    findings: list[Finding] = []
    results = raw.get("Results", [])

    for target_result in results:
        vulns = target_result.get("Vulnerabilities") or []

        for vuln in vulns:
            vuln_id = vuln.get("VulnerabilityID", "unknown")
            pkg_name = vuln.get("PkgName", "unknown")
            installed_version = vuln.get("InstalledVersion", "unknown")
            fixed_version = vuln.get("FixedVersion") or None
            severity_raw = vuln.get("Severity", "UNKNOWN")
            title = vuln.get("Title", "")
            description = vuln.get("Description", "")

            severity = _SEVERITY_MAP.get(severity_raw.upper(), "info")

            finding_title = f"{vuln_id} in {pkg_name}@{installed_version}"
            if title:
                finding_title = f"{vuln_id}: {title}"

            finding_id = f"trivy-{vuln_id}-{pkg_name}"

            findings.append(
                Finding(
                    id=finding_id,
                    source_tool="trivy",
                    category="sca",
                    severity=severity,
                    cvss_score=None,
                    cve_id=vuln_id if vuln_id.startswith("CVE-") else None,
                    title=finding_title,
                    description=description,
                    file_path=None,
                    line_number=None,
                    package_name=pkg_name,
                    package_version=installed_version,
                    fix_version=fixed_version,
                    raw_output=vuln,
                )
            )

    return findings
