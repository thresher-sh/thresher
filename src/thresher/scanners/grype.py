"""Grype scanner wrapper -- SCA vulnerability scanning against an SBOM."""

from __future__ import annotations

import logging
import time
from typing import Any

from thresher.scanners.models import Finding, ScanResults
from thresher.vm.ssh import ssh_exec

logger = logging.getLogger(__name__)

# Grype severity values mapped to our normalized scale.
_SEVERITY_MAP: dict[str, str] = {
    "Critical": "critical",
    "High": "high",
    "Medium": "medium",
    "Low": "low",
    "Negligible": "info",
    "Unknown": "info",
}


def run_grype(vm_name: str, sbom_path: str, output_dir: str) -> ScanResults:
    """Run Grype against a CycloneDX SBOM produced by Syft.

    Grype exits with code 0 when no vulnerabilities are found and code 1
    when vulnerabilities *are* found.  Both are treated as successful runs.

    Args:
        vm_name: Name of the Lima VM.
        sbom_path: Path to the SBOM JSON inside the VM.
        output_dir: Directory for scan artifacts inside the VM.

    Returns:
        ScanResults with execution metadata only (findings stay in VM).
    """
    output_path = f"{output_dir}/grype.json"
    cmd = f"grype sbom:{sbom_path} -o json > {output_path}"

    start = time.monotonic()
    try:
        result = ssh_exec(vm_name, cmd)
        elapsed = time.monotonic() - start

        # Exit codes: 0 = no vulns, 1 = vulns found (not an error).
        # Anything else is a real failure.
        if result.exit_code not in (0, 1):
            logger.warning("Grype exited with code %d: %s", result.exit_code, result.stderr)
            return ScanResults(
                tool_name="grype",
                execution_time_seconds=elapsed,
                exit_code=result.exit_code,
                errors=[f"Grype failed (exit {result.exit_code}): {result.stderr}"],
            )

        # Findings remain inside the VM at output_path.
        # No data crosses the VM trust boundary.
        return ScanResults(
            tool_name="grype",
            execution_time_seconds=elapsed,
            exit_code=result.exit_code,
            raw_output_path=output_path,
        )

    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.exception("Grype execution failed")
        return ScanResults(
            tool_name="grype",
            execution_time_seconds=elapsed,
            exit_code=-1,
            errors=[f"Grype execution error: {exc}"],
        )


def parse_grype_output(raw: dict[str, Any]) -> list[Finding]:
    """Parse Grype JSON output into normalized Finding objects.

    Args:
        raw: Parsed JSON dict from Grype's ``-o json`` output.

    Returns:
        List of normalized Finding objects.
    """
    findings: list[Finding] = []
    matches = raw.get("matches", [])

    for match in matches:
        vulnerability = match.get("vulnerability", {})
        artifact = match.get("artifact", {})

        cve_id = vulnerability.get("id", "")
        severity_raw = vulnerability.get("severity", "Unknown")
        severity = _SEVERITY_MAP.get(severity_raw, "info")

        # Extract CVSS score -- Grype may include multiple CVSS entries.
        cvss_score = _extract_cvss_score(vulnerability)

        pkg_name = artifact.get("name", "unknown")
        pkg_version = artifact.get("version", "unknown")

        # Fix version from the first available fixed-in entry.
        fix_versions = vulnerability.get("fix", {}).get("versions", [])
        fix_version = fix_versions[0] if fix_versions else None

        description = vulnerability.get("description", "")
        if not description:
            # Fall back to the data source description if the top-level one is empty.
            for ds in vulnerability.get("dataSource", []):
                if isinstance(ds, str):
                    description = f"See: {ds}"
                    break

        finding_id = f"grype-{cve_id}" if cve_id else f"grype-{pkg_name}-{pkg_version}"

        findings.append(
            Finding(
                id=finding_id,
                source_tool="grype",
                category="sca",
                severity=severity,
                cvss_score=cvss_score,
                cve_id=cve_id if cve_id.startswith("CVE-") else None,
                title=f"{cve_id} in {pkg_name}@{pkg_version}",
                description=description,
                file_path=None,
                line_number=None,
                package_name=pkg_name,
                package_version=pkg_version,
                fix_version=fix_version,
                raw_output=match,
            )
        )

    return findings


def _extract_cvss_score(vulnerability: dict[str, Any]) -> float | None:
    """Extract the highest CVSS score from a Grype vulnerability entry."""
    best: float | None = None
    for cvss_entry in vulnerability.get("cvss", []):
        metrics = cvss_entry.get("metrics", {})
        score = metrics.get("baseScore")
        if score is not None:
            if best is None or score > best:
                best = score
    return best
