"""GuardDog dependency scanner -- runs GuardDog against /opt/deps/ source."""

from __future__ import annotations

import logging
import time
from typing import Any

from thresher.scanners.models import Finding, ScanResults
from thresher.vm.ssh import ssh_exec, ssh_write_file

logger = logging.getLogger(__name__)

DEPS_DIR = "/opt/deps"

# Small helper script written into the VM to combine per-subdir guarddog
# results into a single valid JSON array.  The previous approach of
# ``echo '[]' > file && guarddog ... >> file`` produced malformed JSON
# (``[]{"pkg": ...}{"pkg": ...}``).
_COMBINE_SCRIPT = r'''#!/usr/bin/env python3
"""Combine per-subdir GuardDog JSON results into one array."""
import json
import glob
import sys

output_path = sys.argv[1]
results = []
for f in sorted(glob.glob("/tmp/guarddog_sub_*.json")):
    try:
        with open(f) as fh:
            data = json.load(fh)
        if isinstance(data, list):
            results.extend(data)
        elif isinstance(data, dict):
            results.append(data)
    except Exception:
        pass

with open(output_path, "w") as fh:
    json.dump(results, fh)
'''


def run_guarddog_deps(vm_name: str, output_dir: str) -> ScanResults:
    """Run GuardDog against dependency source in /opt/deps/.

    Iterates over ecosystem subdirectories in /opt/deps/ and scans each.
    Each subdir result is written to a separate temp file, then combined
    into a single valid JSON array.  All findings remain inside the VM.

    Args:
        vm_name: Name of the Lima VM.
        output_dir: Directory for scan artifacts inside the VM.

    Returns:
        ScanResults with execution metadata only (findings stay in VM).
    """
    output_path = f"{output_dir}/guarddog-deps.json"
    combine_script_path = "/tmp/guarddog_combine.py"

    # Scan each ecosystem subdir under /opt/deps/, writing each result to a
    # separate temp file, then use a Python script to merge them into one
    # valid JSON array.
    scan_cmd = (
        f"rm -f /tmp/guarddog_sub_*.json && "
        f"_gd_idx=0 && "
        f"for d in {DEPS_DIR}/*/; do "
        f'  if [ -d "$d" ]; then '
        f"    guarddog scan \"$d\" --output-format json "
        f"    > /tmp/guarddog_sub_${{_gd_idx}}.json 2>/dev/null; "
        f"    _gd_idx=$((_gd_idx + 1)); "
        f"  fi; "
        f"done && "
        f"if [ \"$_gd_idx\" -eq 0 ]; then "
        f"  guarddog scan {DEPS_DIR} --output-format json "
        f"  > /tmp/guarddog_sub_0.json 2>/dev/null; "
        f"fi && "
        f"python3 {combine_script_path} {output_path} "
        f"|| echo '[]' > {output_path}"
    )

    start = time.monotonic()
    try:
        # Write the combiner script into the VM first.
        ssh_write_file(vm_name, _COMBINE_SCRIPT, combine_script_path)

        result = ssh_exec(vm_name, scan_cmd, timeout=600)
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
