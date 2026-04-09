"""Report validation, enrichment, and generation."""

from __future__ import annotations

import json
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
    if isinstance(verified_findings, dict):
        all_findings = verified_findings.get("findings", [])
    elif verified_findings:
        all_findings = list(verified_findings)
    else:
        all_findings = []

    # Merge scanner findings into the combined list
    for sr in (scan_results or []):
        for finding in sr.findings:
            all_findings.append(finding.to_dict())

    enriched = enrich_findings(all_findings, vm_name="")

    scanner_results_map = {r.tool_name: r for r in (scan_results or [])}

    return {
        "findings": enriched,
        "scanner_results": scanner_results_map,
    }


def generate_report(
    enriched_findings: dict[str, Any],
    scan_results: list[ScanResults],
    config,
    *,
    analyst_findings: list[dict[str, Any]] | None = None,
) -> str:
    """Synthesize final report and write to output directory.

    Generates markdown and HTML reports using either the AI synthesis
    agent (default) or Jinja2 templates (``skip_ai=True``).  Validates
    the output directory after generation.

    Args:
        enriched_findings: Dict from ``enrich_all_findings``.
        scan_results: Execution metadata list from all scanners.
        config: ScanConfig instance.
        analyst_findings: Per-analyst findings dicts from run_all_analysts().

    Returns:
        Path to the generated report directory.
    """
    from thresher.report.synthesize import (
        _generate_template_report,
        _generate_agent_report,
        _generate_html_report,
        _build_synthesis_input,
    )

    output_dir = config.output_dir if not isinstance(config, dict) else config.get("output_dir", "/output")
    os.makedirs(output_dir, exist_ok=True)

    findings: list[dict[str, Any]] = enriched_findings.get("findings", [])
    scanner_results: dict[str, Any] = enriched_findings.get(
        "scanner_results", {}
    )

    # Use config directly if it's already a ScanConfig, otherwise build one
    if isinstance(config, dict):
        from thresher.config import ScanConfig, VMConfig
        scan_config = ScanConfig(
            repo_url=config.get("repo_url", ""),
            skip_ai=config.get("skip_ai", False),
            output_dir=output_dir,
            vm=VMConfig(),
            anthropic_api_key=config.get("anthropic_api_key", ""),
            model=config.get("model", "sonnet"),
        )
    else:
        scan_config = config

    # vm_name is empty string in harness context (runs natively, not in VM)
    vm_name = ""

    if scan_config.skip_ai:
        _generate_template_report(
            vm_name, scan_config, findings, scanner_results, output_dir
        )
    else:
        ai_findings_dict = {"findings": findings}
        _generate_agent_report(
            vm_name, scan_config, scanner_results, ai_findings_dict, findings, output_dir
        )

    # HTML report (always generated after markdown reports)
    agent_succeeded = False
    if not scan_config.skip_ai:
        agent_succeeded = (
            os.path.isfile(f"{output_dir}/executive-summary.md")
            and os.path.isfile(f"{output_dir}/detailed-report.md")
        )
    _generate_html_report(
        vm_name, scan_config, findings, scanner_results, output_dir,
        agent_succeeded=agent_succeeded,
    )

    # Write findings.json (machine-readable output)
    findings_path = Path(output_dir) / "findings.json"
    findings_path.write_text(json.dumps(findings, indent=2, default=str))

    # Save per-analyst findings as individual JSON files
    if analyst_findings:
        scan_results_dir = Path(output_dir) / "scan-results"
        scan_results_dir.mkdir(exist_ok=True)
        for af in analyst_findings:
            number = af.get("analyst_number", 0)
            name = af.get("analyst", "unknown")
            filename = f"analyst-{number:02d}-{name}.json"
            (scan_results_dir / filename).write_text(
                json.dumps(af, indent=2, default=str)
            )
            logger.info("Saved per-analyst findings: %s", filename)

    # Copy raw scanner output files into scan-results/ subfolder
    scan_results_dir = Path(output_dir) / "scan-results"
    scan_results_dir.mkdir(exist_ok=True)
    source_dir = Path("/opt/scan-results")
    if source_dir.exists():
        import shutil
        for f in source_dir.iterdir():
            if f.is_file():
                shutil.copy2(f, scan_results_dir / f.name)

    validate_report_output(output_dir)
    return output_dir
