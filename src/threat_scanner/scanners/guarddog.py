"""GuardDog scanner wrapper -- supply chain behavioral analysis."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from threat_scanner.scanners.models import Finding, ScanResults
from threat_scanner.vm.ssh import ssh_exec

logger = logging.getLogger(__name__)


def run_guarddog(vm_name: str, target_dir: str, output_dir: str) -> ScanResults:
    """Run GuardDog to detect malicious package behaviors.

    GuardDog exits with code 0 on success.  Non-zero typically indicates
    a real error (e.g. unsupported ecosystem, missing files).

    Args:
        vm_name: Name of the Lima VM.
        target_dir: Path to the repository inside the VM.
        output_dir: Directory for scan artifacts inside the VM.

    Returns:
        ScanResults with parsed Finding objects.
    """
    output_path = f"{output_dir}/guarddog.json"
    cmd = f"guarddog scan {target_dir} --output-format json > {output_path} 2>&1"

    start = time.monotonic()
    try:
        result = ssh_exec(vm_name, cmd)
        elapsed = time.monotonic() - start

        # GuardDog exit 0 = success.  Non-zero may indicate findings or errors
        # depending on version; treat 0 and 1 as valid.
        if result.exit_code not in (0, 1):
            logger.warning("GuardDog exited with code %d: %s", result.exit_code, result.stderr)
            return ScanResults(
                tool_name="guarddog",
                execution_time_seconds=elapsed,
                exit_code=result.exit_code,
                errors=[f"GuardDog failed (exit {result.exit_code}): {result.stderr}"],
            )

        cat_result = ssh_exec(vm_name, f"cat {output_path}")
        raw = _safe_parse_json(cat_result.stdout)
        if raw is None:
            return ScanResults(
                tool_name="guarddog",
                execution_time_seconds=elapsed,
                exit_code=result.exit_code,
                errors=["Failed to parse GuardDog JSON output"],
                raw_output_path=output_path,
            )

        findings = parse_guarddog_output(raw)
        return ScanResults(
            tool_name="guarddog",
            execution_time_seconds=elapsed,
            exit_code=result.exit_code,
            findings=findings,
            raw_output_path=output_path,
        )

    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.exception("GuardDog execution failed")
        return ScanResults(
            tool_name="guarddog",
            execution_time_seconds=elapsed,
            exit_code=-1,
            errors=[f"GuardDog execution error: {exc}"],
        )


def parse_guarddog_output(raw: dict[str, Any]) -> list[Finding]:
    """Parse GuardDog JSON output into normalized Finding objects.

    GuardDog's JSON output contains a dict of package names to their
    scan results, each with a list of detected issues/rules that fired.

    Args:
        raw: Parsed JSON dict from GuardDog's ``--output-format json`` output.

    Returns:
        List of normalized Finding objects.
    """
    findings: list[Finding] = []

    # GuardDog output can be structured as:
    # { "package_name": { "issues": [...], "results": {...} } }
    # or as a top-level "results" dict depending on version.
    packages = raw if isinstance(raw, dict) else {}

    # Handle the case where output is a list of results.
    if isinstance(raw, list):
        for idx, item in enumerate(raw):
            finding = _parse_single_result(item, idx)
            if finding:
                findings.append(finding)
        return findings

    for pkg_name, pkg_data in packages.items():
        if not isinstance(pkg_data, dict):
            continue

        # Handle "results" key structure.
        results = pkg_data.get("results", {})
        if isinstance(results, dict):
            for rule_name, rule_matches in results.items():
                if not rule_matches:
                    continue

                description_parts: list[str] = []
                file_path: str | None = None
                line_number: int | None = None

                if isinstance(rule_matches, list):
                    for match in rule_matches:
                        if isinstance(match, dict):
                            loc = match.get("location", "")
                            if loc and not file_path:
                                file_path = str(loc)
                            msg = match.get("message", "")
                            if msg:
                                description_parts.append(msg)
                        elif isinstance(match, str):
                            description_parts.append(match)

                description = "; ".join(description_parts) if description_parts else rule_name

                finding_id = f"guarddog-{pkg_name}-{rule_name}"

                findings.append(
                    Finding(
                        id=finding_id,
                        source_tool="guarddog",
                        category="supply_chain",
                        severity="high",  # GuardDog detections are supply chain risks.
                        cvss_score=None,
                        cve_id=None,
                        title=f"Suspicious behavior: {rule_name} in {pkg_name}",
                        description=description,
                        file_path=file_path,
                        line_number=line_number,
                        package_name=pkg_name,
                        package_version=None,
                        fix_version=None,
                        raw_output={"package": pkg_name, "rule": rule_name, "matches": rule_matches},
                    )
                )

    return findings


def _parse_single_result(item: Any, index: int) -> Finding | None:
    """Parse a single result entry when GuardDog returns a list."""
    if not isinstance(item, dict):
        return None

    rule_name = item.get("rule", item.get("name", f"unknown-{index}"))
    pkg_name = item.get("package", "unknown")
    description = item.get("message", item.get("description", rule_name))
    file_path = item.get("location", item.get("file", None))

    return Finding(
        id=f"guarddog-{pkg_name}-{rule_name}",
        source_tool="guarddog",
        category="supply_chain",
        severity="high",
        cvss_score=None,
        cve_id=None,
        title=f"Suspicious behavior: {rule_name} in {pkg_name}",
        description=str(description),
        file_path=str(file_path) if file_path else None,
        line_number=None,
        package_name=pkg_name,
        package_version=None,
        fix_version=None,
        raw_output=item,
    )


def _safe_parse_json(text: str) -> dict[str, Any] | None:
    """Attempt to parse JSON, returning None on failure."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        logger.error("Failed to parse JSON output from GuardDog")
        return None
