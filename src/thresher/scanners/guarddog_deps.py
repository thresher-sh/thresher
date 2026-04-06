"""GuardDog dependency scanner -- runs GuardDog against /opt/deps/ source."""

from __future__ import annotations

import glob
import json
import logging
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from thresher.scanners.models import Finding, ScanResults

logger = logging.getLogger(__name__)

DEPS_DIR = "/opt/deps"


def run_guarddog_deps(output_dir: str) -> ScanResults:
    """Run GuardDog against dependency source in /opt/deps/.

    Iterates over ecosystem subdirectories in /opt/deps/ and scans each.
    Each subdir result is written to a separate temp file, then combined
    into a single valid JSON array.

    Args:
        output_dir: Directory for scan artifacts.

    Returns:
        ScanResults with execution metadata only.
    """
    output_path = f"{output_dir}/guarddog-deps.json"

    start = time.monotonic()
    try:
        deps_path = Path(DEPS_DIR)
        subdirs = [str(d) for d in deps_path.iterdir() if d.is_dir()] if deps_path.is_dir() else []

        if not subdirs:
            # Fall back to scanning the whole deps dir
            subdirs = [DEPS_DIR]

        all_results: list[Any] = []
        last_exit_code = 0

        with tempfile.TemporaryDirectory() as tmpdir:
            for idx, subdir in enumerate(sorted(subdirs)):
                sub_output = str(Path(tmpdir) / f"guarddog_sub_{idx}.json")
                result = subprocess.run(
                    ["guarddog", "scan", subdir, "--output-format", "json"],
                    capture_output=True,
                    timeout=600,
                )
                last_exit_code = result.returncode

                # Parse and accumulate results
                try:
                    data = json.loads(result.stdout.decode(errors="replace"))
                    if isinstance(data, list):
                        all_results.extend(data)
                    elif isinstance(data, dict):
                        all_results.append(data)
                except (json.JSONDecodeError, ValueError):
                    pass

        # Write combined results
        Path(output_path).write_text(json.dumps(all_results))
        elapsed = time.monotonic() - start

        if last_exit_code not in (0, 1):
            logger.warning(
                "GuardDog deps exited with code %d",
                last_exit_code,
            )
            return ScanResults(
                tool_name="guarddog-deps",
                execution_time_seconds=elapsed,
                exit_code=last_exit_code,
                errors=[f"GuardDog deps failed (exit {last_exit_code})"],
            )

        return ScanResults(
            tool_name="guarddog-deps",
            execution_time_seconds=elapsed,
            exit_code=last_exit_code,
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
