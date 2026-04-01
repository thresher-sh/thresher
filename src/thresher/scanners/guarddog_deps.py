"""GuardDog dependency scanner -- runs GuardDog against /opt/deps/ source."""

from __future__ import annotations

import logging
import time
from typing import Any

from thresher.scanners.models import Finding, ScanResults
from thresher.vm.ssh import ssh_exec

logger = logging.getLogger(__name__)

DEPS_DIR = "/opt/deps"


def run_guarddog_deps(vm_name: str, output_dir: str) -> ScanResults:
    """Run GuardDog against dependency source in /opt/deps/.

    Iterates over ecosystem subdirectories in /opt/deps/ and scans each.
    All findings remain inside the VM.

    Args:
        vm_name: Name of the Lima VM.
        output_dir: Directory for scan artifacts inside the VM.

    Returns:
        ScanResults with execution metadata only (findings stay in VM).
    """
    output_path = f"{output_dir}/guarddog-deps.json"

    # Scan each ecosystem subdir under /opt/deps/, aggregate into one file.
    # If /opt/deps/ has no subdirs, scan it directly.
    cmd = (
        f"echo '[]' > {output_path} && "
        f"for d in {DEPS_DIR}/*/; do "
        f'  [ -d "$d" ] && guarddog scan "$d" --output-format json '
        f"  >> {output_path} 2>/dev/null; "
        f"done || guarddog scan {DEPS_DIR} --output-format json "
        f"> {output_path} 2>/dev/null"
    )

    start = time.monotonic()
    try:
        result = ssh_exec(vm_name, cmd, timeout=600)
        elapsed = time.monotonic() - start

        if result.exit_code not in (0, 1):
            logger.warning(
                "GuardDog deps exited with code %d: %s",
                result.exit_code,
                result.stderr,
            )
            return ScanResults(
                tool_name="guarddog-deps",
                execution_time_seconds=elapsed,
                exit_code=result.exit_code,
                errors=[
                    f"GuardDog deps failed (exit {result.exit_code}): "
                    f"{result.stderr}"
                ],
            )

        return ScanResults(
            tool_name="guarddog-deps",
            execution_time_seconds=elapsed,
            exit_code=result.exit_code,
            raw_output_path=output_path,
        )

    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.exception("GuardDog deps execution failed")
        return ScanResults(
            tool_name="guarddog-deps",
            execution_time_seconds=elapsed,
            exit_code=-1,
            errors=[f"GuardDog deps execution error: {exc}"],
        )


def parse_guarddog_deps_output(raw: dict[str, Any] | list) -> list[Finding]:
    """Parse GuardDog deps JSON output into normalized Finding objects.

    Args:
        raw: Parsed JSON from GuardDog output.

    Returns:
        List of normalized Finding objects.
    """
    findings: list[Finding] = []

    if isinstance(raw, list):
        for idx, item in enumerate(raw):
            if not isinstance(item, dict):
                continue
            rule_name = item.get("rule", item.get("name", f"unknown-{idx}"))
            pkg_name = item.get("package", "unknown")
            description = item.get("message", item.get("description", rule_name))
            file_path = item.get("location", item.get("file"))

            findings.append(
                Finding(
                    id=f"guarddog-deps-{pkg_name}-{rule_name}",
                    source_tool="guarddog-deps",
                    category="behavioral",
                    severity="high",
                    cvss_score=None,
                    cve_id=None,
                    title=f"Suspicious dep behavior: {rule_name} in {pkg_name}",
                    description=str(description),
                    file_path=str(file_path) if file_path else None,
                    line_number=None,
                    package_name=pkg_name,
                    package_version=None,
                    fix_version=None,
                    raw_output=item,
                )
            )
        return findings

    if isinstance(raw, dict):
        for pkg_name, pkg_data in raw.items():
            if not isinstance(pkg_data, dict):
                continue
            results = pkg_data.get("results", {})
            if isinstance(results, dict):
                for rule_name, rule_matches in results.items():
                    if not rule_matches:
                        continue
                    findings.append(
                        Finding(
                            id=f"guarddog-deps-{pkg_name}-{rule_name}",
                            source_tool="guarddog-deps",
                            category="behavioral",
                            severity="high",
                            cvss_score=None,
                            cve_id=None,
                            title=f"Suspicious dep behavior: {rule_name} in {pkg_name}",
                            description=rule_name,
                            file_path=None,
                            line_number=None,
                            package_name=pkg_name,
                            package_version=None,
                            fix_version=None,
                            raw_output={"package": pkg_name, "rule": rule_name},
                        )
                    )

    return findings
