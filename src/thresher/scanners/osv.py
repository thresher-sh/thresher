"""OSV-Scanner wrapper -- SCA vulnerability scanning with MAL entry support."""

from __future__ import annotations

import logging
import subprocess
import time
from pathlib import Path
from typing import Any

from thresher.scanners.models import Finding, ScanResults

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}


def run_osv(target_dir: str, output_dir: str) -> ScanResults:
    """Run OSV-Scanner against the target directory.

    OSV-Scanner exits with code 0 when no vulnerabilities are found and
    code 1 when vulnerabilities are present.  Both are valid results.

    Args:
        target_dir: Path to the repository.
        output_dir: Directory for scan artifacts.

    Returns:
        ScanResults with execution metadata only (findings stay in output_dir).
    """
    output_path = f"{output_dir}/osv.json"

    start = time.monotonic()
    try:
        result = subprocess.run(
            ["osv-scanner", "scan", "--format", "json", target_dir],
            capture_output=True,
            timeout=300,
        )
        Path(output_path).write_bytes(result.stdout)
        elapsed = time.monotonic() - start

        # Exit 0 = clean, 1 = vulns found (expected).  Other codes are errors.
        if result.returncode not in (0, 1):
            logger.warning("OSV-Scanner exited with code %d: %s", result.returncode, result.stderr.decode())
            return ScanResults(
                tool_name="osv-scanner",
                execution_time_seconds=elapsed,
                exit_code=result.returncode,
                errors=[f"OSV-Scanner failed (exit {result.returncode}): {result.stderr.decode()}"],
            )

        return ScanResults(
            tool_name="osv-scanner",
            execution_time_seconds=elapsed,
            exit_code=result.returncode,
            raw_output_path=output_path,
        )

    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.exception("OSV-Scanner execution failed")
        return ScanResults(
            tool_name="osv-scanner",
            execution_time_seconds=elapsed,
            exit_code=-1,
            errors=[f"OSV-Scanner execution error: {exc}"],
        )


def parse_osv_output(raw: dict[str, Any]) -> list[Finding]:
    """Parse OSV-Scanner JSON output into normalized Finding objects.

    Handles both standard CVE advisories and MAL-prefixed entries for
    malicious package detections.

    Args:
        raw: Parsed JSON dict from OSV-Scanner's ``--format json`` output.

    Returns:
        List of normalized Finding objects.
    """
    findings: list[Finding] = []
    results = raw.get("results", [])

    for package_result in results:
        source = package_result.get("source", {})
        source_path = source.get("path", "")

        for pkg_info in package_result.get("packages", []):
            package = pkg_info.get("package", {})
            pkg_name = package.get("name", "unknown")
            pkg_version = package.get("version", "unknown")

            for vuln in pkg_info.get("vulnerabilities", []):
                vuln_id = vuln.get("id", "unknown")
                summary = vuln.get("summary", "")
                details = vuln.get("detail", "") or vuln.get("details", "")

                # Determine category: MAL-prefixed IDs indicate malicious packages.
                is_malicious = vuln_id.startswith("MAL-")
                category = "supply_chain" if is_malicious else "sca"

                severity = _extract_severity(vuln)
                cvss_score = _extract_cvss_score(vuln)
                cve_id = vuln_id if vuln_id.startswith("CVE-") else None

                # Extract fix version from affected ranges.
                fix_version = _extract_fix_version(vuln)

                # Malicious packages are always critical.
                if is_malicious and severity != "critical":
                    severity = "critical"

                finding_id = f"osv-{vuln_id}"

                findings.append(
                    Finding(
                        id=finding_id,
                        source_tool="osv-scanner",
                        category=category,
                        severity=severity,
                        cvss_score=cvss_score,
                        cve_id=cve_id,
                        title=summary or f"{vuln_id} in {pkg_name}@{pkg_version}",
                        description=details or summary,
                        file_path=source_path or None,
                        line_number=None,
                        package_name=pkg_name,
                        package_version=pkg_version,
                        fix_version=fix_version,
                        raw_output=vuln,
                    )
                )

    return findings


def _extract_severity(vuln: dict[str, Any]) -> str:
    """Extract and normalize severity from an OSV vulnerability entry."""
    # database_specific may contain severity info.
    db_specific = vuln.get("database_specific", {})
    severity_str = db_specific.get("severity", "")
    if severity_str and severity_str.upper() in _SEVERITY_MAP:
        return _SEVERITY_MAP[severity_str.upper()]

    # Check severity array (CVSS-based).
    for sev in vuln.get("severity", []):
        score_str = sev.get("score", "")
        # CVSS vector strings contain the score; try to extract from type field.
        sev_type = sev.get("type", "")
        if sev_type == "CVSS_V3":
            score = _parse_cvss_from_vector(score_str)
            if score is not None:
                return _score_to_severity(score)

    return "medium"  # Default when severity is not provided.


def _extract_cvss_score(vuln: dict[str, Any]) -> float | None:
    """Extract CVSS score from an OSV vulnerability entry."""
    for sev in vuln.get("severity", []):
        if sev.get("type") == "CVSS_V3":
            score = _parse_cvss_from_vector(sev.get("score", ""))
            if score is not None:
                return score
    return None


def _parse_cvss_from_vector(vector: str) -> float | None:
    """Attempt to extract a base score from a CVSS vector string.

    OSV sometimes stores the full vector string (e.g.
    ``CVSS:3.1/AV:N/AC:L/...``) rather than a bare score.  We cannot
    calculate the score from the vector without a CVSS library, so we
    return None for vector strings and only parse bare floats.
    """
    try:
        return float(vector)
    except (ValueError, TypeError):
        return None


def _score_to_severity(score: float) -> str:
    """Map a CVSS numeric score to a severity label."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 0.1:
        return "low"
    return "info"


def _extract_fix_version(vuln: dict[str, Any]) -> str | None:
    """Extract the earliest fix version from OSV affected ranges."""
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                fixed = event.get("fixed")
                if fixed:
                    return fixed
    return None
