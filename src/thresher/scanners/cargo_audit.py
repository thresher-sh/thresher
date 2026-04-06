"""cargo-audit scanner wrapper -- Rust dependency vulnerability scanning."""

from __future__ import annotations

import logging
import subprocess
import time
from pathlib import Path
from typing import Any

from thresher.scanners.models import Finding, ScanResults

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "none": "info",
}


def run_cargo_audit(target_dir: str, output_dir: str) -> ScanResults:
    """Run cargo-audit to detect vulnerabilities in Rust dependencies.

    First checks if a Cargo.lock file exists.  If not, returns empty
    results.

    Args:
        target_dir: Path to the repository.
        output_dir: Directory for scan artifacts.

    Returns:
        ScanResults with parsed Finding objects.
    """
    output_path = f"{output_dir}/cargo-audit.json"

    start = time.monotonic()
    try:
        # Check if Cargo.lock exists.
        if not Path(target_dir, "Cargo.lock").exists():
            elapsed = time.monotonic() - start
            logger.info("No Cargo.lock found, skipping cargo-audit")
            return ScanResults(
                tool_name="cargo-audit",
                execution_time_seconds=elapsed,
                exit_code=0,
                findings=[],
            )

        result = subprocess.run(
            ["cargo-audit", "audit", "--json"],
            capture_output=True,
            timeout=300,
            cwd=target_dir,
        )
        Path(output_path).write_bytes(result.stdout)
        elapsed = time.monotonic() - start

        if result.returncode not in (0, 1):
            logger.warning("cargo-audit exited with code %d: %s", result.returncode, result.stderr.decode())
            return ScanResults(
                tool_name="cargo-audit",
                execution_time_seconds=elapsed,
                exit_code=result.returncode,
                errors=[f"cargo-audit failed (exit {result.returncode}): {result.stderr.decode()}"],
            )

        return ScanResults(
            tool_name="cargo-audit",
            execution_time_seconds=elapsed,
            exit_code=result.returncode,
            raw_output_path=output_path,
        )

    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.exception("cargo-audit execution failed")
        return ScanResults(
            tool_name="cargo-audit",
            execution_time_seconds=elapsed,
            exit_code=-1,
            errors=[f"cargo-audit execution error: {exc}"],
        )


def parse_cargo_audit_output(raw: dict[str, Any]) -> list[Finding]:
    """Parse cargo-audit JSON output into normalized Finding objects.

    Args:
        raw: Parsed JSON dict from cargo-audit's ``--json`` output.

    Returns:
        List of normalized Finding objects.
    """
    findings: list[Finding] = []
    vuln_list = raw.get("vulnerabilities", {}).get("list", [])

    for idx, vuln in enumerate(vuln_list):
        advisory = vuln.get("advisory", {})
        package = vuln.get("package", {})
        versions = vuln.get("versions", {})

        advisory_id = advisory.get("id", "unknown")
        title = advisory.get("title", "")
        description = advisory.get("description", "")
        url = advisory.get("url", "")
        severity_raw = advisory.get("severity", "")

        pkg_name = package.get("name", "unknown")
        pkg_version = package.get("version", "unknown")

        patched = versions.get("patched", [])
        fix_version = patched[0] if patched else None

        severity = _SEVERITY_MAP.get(severity_raw.lower(), "high")

        if url:
            description = f"{description}\nRef: {url}" if description else f"See: {url}"

        finding_title = f"{advisory_id}: {title}" if title else advisory_id
        finding_id = f"cargo-audit-{advisory_id}-{idx}"

        findings.append(
            Finding(
                id=finding_id,
                source_tool="cargo-audit",
                category="sca",
                severity=severity,
                cvss_score=None,
                cve_id=advisory_id if advisory_id.startswith("CVE-") else None,
                title=finding_title,
                description=description,
                file_path=None,
                line_number=None,
                package_name=pkg_name,
                package_version=pkg_version,
                fix_version=fix_version,
                raw_output=vuln,
            )
        )

    return findings
