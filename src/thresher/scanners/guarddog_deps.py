"""GuardDog dependency scanner -- runs GuardDog against /opt/deps/ source."""

from __future__ import annotations

import glob
import json
import logging
import tempfile
import time
from pathlib import Path
from typing import Any

from thresher.run import run as run_cmd
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
                result = run_cmd(
                    ["guarddog", "scan", subdir, "--output-format", "json"],
                    label="guarddog-deps",
                    timeout=600,
                    ok_codes=(0, 1),
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


# Top-level keys that GuardDog adds to its per-scan summary dict.
# These are not package names, so the package-keyed scan must skip them.
_GUARDDOG_META_KEYS = frozenset({"issues", "errors", "results"})


def _is_explicit_finding_dict(item: dict[str, Any]) -> bool:
    """True when a dict already looks like a single, formed finding entry
    (the older list-of-findings format)."""
    return "rule" in item or ("package" in item and "message" in item)


def _parse_explicit_finding(item: dict[str, Any], idx: int) -> Finding:
    rule_name = item.get("rule", item.get("name", f"unknown-{idx}"))
    pkg_name = item.get("package", "unknown")
    description = item.get("message", item.get("description", rule_name))
    file_path = item.get("location", item.get("file"))
    return Finding(
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


def _parse_package_keyed_dict(raw: dict[str, Any]) -> list[Finding]:
    """Walk a per-scan dict where top-level keys are package names mapping
    to ``{"results": {rule: matches, ...}}`` entries.

    Skips GuardDog's own meta keys (``issues``, ``errors``, ``results``)
    so empty/clean scans yield zero findings instead of phantom entries.
    """
    findings: list[Finding] = []
    for pkg_name, pkg_data in raw.items():
        if pkg_name in _GUARDDOG_META_KEYS:
            continue
        if not isinstance(pkg_data, dict):
            continue
        results = pkg_data.get("results", {})
        if not isinstance(results, dict):
            continue
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


def parse_guarddog_deps_output(raw: dict[str, Any] | list) -> list[Finding]:
    """Parse GuardDog deps JSON output into normalized Finding objects.

    The harness combines per-subdir scan results into a list of dicts.
    Each dict can be either:
      1. an explicit finding entry (older list-of-findings format), or
      2. a per-scan summary with package-keyed nested results.

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
            if _is_explicit_finding_dict(item):
                findings.append(_parse_explicit_finding(item, idx))
            else:
                findings.extend(_parse_package_keyed_dict(item))
        return findings

    if isinstance(raw, dict):
        return _parse_package_keyed_dict(raw)

    return findings
