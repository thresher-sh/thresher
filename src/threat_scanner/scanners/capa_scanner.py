"""capa scanner wrapper -- binary capability analysis."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from threat_scanner.scanners.models import Finding, ScanResults
from threat_scanner.vm.ssh import ssh_exec

logger = logging.getLogger(__name__)


def run_capa(vm_name: str, target_dir: str, output_dir: str) -> ScanResults:
    """Run capa to analyze executable binaries for capabilities.

    First finds ELF/PE binaries in the target directory.  If none are
    found, returns empty results.  Runs capa on each binary and
    aggregates findings.

    Args:
        vm_name: Name of the Lima VM.
        target_dir: Path to the repository inside the VM.
        output_dir: Directory for scan artifacts inside the VM.

    Returns:
        ScanResults with parsed Finding objects.
    """
    output_path = f"{output_dir}/capa.json"

    start = time.monotonic()
    try:
        # Find executable binaries and common binary file extensions.
        # Exclude .git directory to avoid false positives on hook samples.
        find_cmd = (
            f"{{ find {target_dir} -path '*/.git' -prune -o -type f -executable -print 2>/dev/null; "
            f"find {target_dir} -path '*/.git' -prune -o -type f "
            f'\\( -name "*.so" -o -name "*.dll" -o -name "*.exe" \\) -print 2>/dev/null; }} | sort -u'
        )
        find_result = ssh_exec(vm_name, find_cmd)
        elapsed = time.monotonic() - start

        binaries = [
            line.strip()
            for line in find_result.stdout.strip().splitlines()
            if line.strip()
        ]

        if not binaries:
            logger.info("No executable binaries found, skipping capa")
            return ScanResults(
                tool_name="capa",
                execution_time_seconds=elapsed,
                exit_code=0,
                findings=[],
            )

        # Run capa on each binary and collect all findings.
        all_findings: list[Finding] = []
        last_exit_code = 0

        for binary_path in binaries:
            binary_output = f"{output_path}.{binary_path.replace('/', '_')}"
            cmd = f"capa --format json {binary_path} > {binary_output} 2>/dev/null"

            result = ssh_exec(vm_name, cmd)
            last_exit_code = result.exit_code

            if result.exit_code != 0:
                logger.debug("capa exited with code %d for %s", result.exit_code, binary_path)
                continue

            cat_result = ssh_exec(vm_name, f"cat {binary_output}")
            raw = _safe_parse_json(cat_result.stdout)
            if raw is None:
                continue

            all_findings.extend(parse_capa_output(raw, binary_path))

        elapsed = time.monotonic() - start
        return ScanResults(
            tool_name="capa",
            execution_time_seconds=elapsed,
            exit_code=last_exit_code,
            findings=all_findings,
            raw_output_path=output_path,
        )

    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.exception("capa execution failed")
        return ScanResults(
            tool_name="capa",
            execution_time_seconds=elapsed,
            exit_code=-1,
            errors=[f"capa execution error: {exc}"],
        )


def parse_capa_output(raw: dict[str, Any], binary_path: str) -> list[Finding]:
    """Parse capa JSON output into normalized Finding objects.

    Args:
        raw: Parsed JSON dict from capa's ``--format json`` output.
        binary_path: Path to the binary that was analyzed.

    Returns:
        List of normalized Finding objects.
    """
    findings: list[Finding] = []
    rules = raw.get("rules", {})

    for idx, (rule_name, rule_data) in enumerate(rules.items()):
        namespace = rule_data.get("namespace", "")
        meta = rule_data.get("meta", {})
        attack = meta.get("attack", [])

        # Map severity based on namespace.
        if "malware" in namespace.lower():
            severity = "critical"
        elif "anti-analysis" in namespace.lower():
            severity = "high"
        else:
            severity = "medium"

        # Build MITRE ATT&CK references.
        attack_refs = []
        for entry in attack:
            if isinstance(entry, dict):
                technique = entry.get("technique", "")
                if technique:
                    attack_refs.append(technique)
            elif isinstance(entry, str):
                attack_refs.append(entry)

        title = f"capa: {rule_name}"
        description_parts = [f"Namespace: {namespace}"]
        if attack_refs:
            description_parts.append(f"MITRE ATT&CK: {', '.join(attack_refs)}")

        description = "; ".join(description_parts)
        finding_id = f"capa-{rule_name.replace(' ', '_')}-{idx}"

        findings.append(
            Finding(
                id=finding_id,
                source_tool="capa",
                category="binary_analysis",
                severity=severity,
                cvss_score=None,
                cve_id=None,
                title=title,
                description=description,
                file_path=binary_path,
                line_number=None,
                package_name=None,
                package_version=None,
                fix_version=None,
                raw_output=rule_data,
            )
        )

    return findings


def _safe_parse_json(text: str) -> dict[str, Any] | None:
    """Attempt to parse JSON, returning None on failure."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        logger.error("Failed to parse JSON output from capa")
        return None
