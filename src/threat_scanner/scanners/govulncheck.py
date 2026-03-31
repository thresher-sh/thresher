"""govulncheck scanner wrapper -- Go vulnerability scanning."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from threat_scanner.scanners.models import Finding, ScanResults
from threat_scanner.vm.ssh import ssh_exec

logger = logging.getLogger(__name__)


def run_govulncheck(vm_name: str, target_dir: str, output_dir: str) -> ScanResults:
    """Run govulncheck to detect vulnerabilities in Go modules.

    First checks if a go.mod file exists.  If not, returns empty results.
    govulncheck only reports reachable vulnerabilities.

    Args:
        vm_name: Name of the Lima VM.
        target_dir: Path to the repository inside the VM.
        output_dir: Directory for scan artifacts inside the VM.

    Returns:
        ScanResults with parsed Finding objects.
    """
    output_path = f"{output_dir}/govulncheck.json"

    start = time.monotonic()
    try:
        # Check if go.mod exists.
        check_result = ssh_exec(vm_name, f"[ -f {target_dir}/go.mod ] && echo exists")
        if "exists" not in check_result.stdout:
            elapsed = time.monotonic() - start
            logger.info("No go.mod found, skipping govulncheck")
            return ScanResults(
                tool_name="govulncheck",
                execution_time_seconds=elapsed,
                exit_code=0,
                findings=[],
            )

        cmd = f"cd {target_dir} && govulncheck -json ./... > {output_path} 2>/dev/null"

        result = ssh_exec(vm_name, cmd)
        elapsed = time.monotonic() - start

        if result.exit_code not in (0, 1):
            logger.warning("govulncheck exited with code %d: %s", result.exit_code, result.stderr)
            return ScanResults(
                tool_name="govulncheck",
                execution_time_seconds=elapsed,
                exit_code=result.exit_code,
                errors=[f"govulncheck failed (exit {result.exit_code}): {result.stderr}"],
            )

        cat_result = ssh_exec(vm_name, f"cat {output_path}")
        findings = parse_govulncheck_output(cat_result.stdout)
        return ScanResults(
            tool_name="govulncheck",
            execution_time_seconds=elapsed,
            exit_code=result.exit_code,
            findings=findings,
            raw_output_path=output_path,
        )

    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.exception("govulncheck execution failed")
        return ScanResults(
            tool_name="govulncheck",
            execution_time_seconds=elapsed,
            exit_code=-1,
            errors=[f"govulncheck execution error: {exc}"],
        )


def parse_govulncheck_output(raw_text: str) -> list[Finding]:
    """Parse govulncheck newline-delimited JSON output into Finding objects.

    govulncheck outputs newline-delimited JSON objects.  We look for
    objects with a ``finding`` key which indicate reachable vulnerabilities.

    Args:
        raw_text: Raw text output from govulncheck (NDJSON format).

    Returns:
        List of normalized Finding objects.
    """
    findings: list[Finding] = []

    for idx, line in enumerate(raw_text.strip().splitlines()):
        line = line.strip()
        if not line:
            continue

        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue

        finding_data = obj.get("finding")
        if finding_data is None:
            continue

        osv_id = finding_data.get("osv", "unknown")
        trace = finding_data.get("trace", [])

        # Build description from trace information.
        trace_parts = []
        for entry in trace:
            module = entry.get("module", "")
            function = entry.get("function", "")
            if module:
                part = module
                if function:
                    part = f"{module}.{function}"
                trace_parts.append(part)

        title = f"govulncheck: {osv_id}"
        description = f"Reachable vulnerability {osv_id}"
        if trace_parts:
            description += f" via: {' -> '.join(trace_parts)}"

        finding_id = f"govulncheck-{osv_id}-{idx}"

        findings.append(
            Finding(
                id=finding_id,
                source_tool="govulncheck",
                category="sca",
                severity="high",
                cvss_score=None,
                cve_id=osv_id if osv_id.startswith("CVE-") else None,
                title=title,
                description=description,
                file_path=None,
                line_number=None,
                package_name=trace_parts[0] if trace_parts else None,
                package_version=None,
                fix_version=None,
                raw_output=obj,
            )
        )

    return findings
