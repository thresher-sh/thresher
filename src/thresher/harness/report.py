"""Report validation, enrichment, and generation."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from thresher.scanners.models import ScanResults
from thresher.report.scoring import enrich_findings

logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = frozenset({
    ".json", ".md", ".txt", ".csv", ".log", ".sarif", ".html"
})
DEFAULT_MAX_FILE_BYTES = 50 * 1024 * 1024
DEFAULT_MAX_JSON_BYTES = 10 * 1024 * 1024


def validate_report_output(
    report_dir: str,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> None:
    """Validate and sanitize report output directory.

    Removes symlinks, files with disallowed extensions, and oversized
    files.  Mirrors the boundary validation logic in ``safe_io.py`` but
    applied to the host-side output directory produced by the harness.

    Args:
        report_dir: Path to the report directory to validate.
        max_file_bytes: Maximum allowed file size in bytes.
    """
    root = Path(report_dir)
    for path in list(root.rglob("*")):
        if path.is_symlink():
            logger.warning("Removing symlink from report output: %s", path)
            path.unlink()
            continue
        if not path.is_file():
            continue
        if path.suffix.lower() not in ALLOWED_EXTENSIONS:
            logger.warning(
                "Removing file with disallowed extension: %s", path
            )
            path.unlink()
            continue
        if path.stat().st_size > max_file_bytes:
            logger.warning("Removing oversized file from report: %s", path)
            path.unlink()
            continue
        # Strip any world-executable bits
        path.chmod(path.stat().st_mode & 0o666)


def enrich_all_findings(
    scan_results: list[ScanResults],
    verified_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Enrich findings with EPSS scores, KEV status, and composite priority.

    The harness runs natively (not inside the VM), so enrichment calls out
    to the public EPSS / CISA KEV APIs directly.  ``enrich_findings`` in
    ``scoring.py`` requires a ``vm_name`` for interface consistency with the
    VM pipeline; we pass an empty string here since network access is
    unconditional in the harness context.

    Args:
        scan_results: Execution metadata from all scanner runs.
        verified_findings: AI-verified findings (may be empty when skip_ai).

    Returns:
        Dict with ``findings`` (enriched list) and ``scanner_results``
        (tool_name -> ScanResults mapping).
    """
    all_findings = list(verified_findings) if verified_findings else []
    enriched = enrich_findings(all_findings, vm_name="")

    scanner_results_map = {r.tool_name: r for r in (scan_results or [])}

    return {
        "findings": enriched,
        "scanner_results": scanner_results_map,
    }


def generate_report(
    enriched_findings: dict[str, Any],
    scan_results: list[ScanResults],
    config: dict[str, Any],
) -> str:
    """Synthesize final report and write to output directory.

    Generates markdown and HTML reports using either the AI synthesis
    agent (default) or Jinja2 templates (``skip_ai=True``).  Validates
    the output directory after generation.

    Args:
        enriched_findings: Dict from ``enrich_all_findings``.
        scan_results: Execution metadata list from all scanners.
        config: Scan configuration dict.

    Returns:
        Path to the generated report directory.
    """
    from thresher.report.synthesize import (
        _generate_template_report,
        _generate_agent_report,
        _build_synthesis_input,
    )

    output_dir = config.get("output_dir", "/output")
    os.makedirs(output_dir, exist_ok=True)

    findings: list[dict[str, Any]] = enriched_findings.get("findings", [])
    scanner_results: dict[str, Any] = enriched_findings.get(
        "scanner_results", {}
    )

    if config.get("skip_ai"):
        _generate_template_report(
            output_dir, findings, scanner_results
        )
    else:
        synthesis_input = _build_synthesis_input(
            scanner_results, findings, findings
        )
        _generate_agent_report(output_dir, synthesis_input, config)

    validate_report_output(output_dir)
    return output_dir
