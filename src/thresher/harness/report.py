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


def finalize_output(
    enriched_findings: dict[str, Any],
    scan_results: list[ScanResults],
    config,
    *,
    analyst_findings: list[dict[str, Any]] | None = None,
) -> None:
    """Handle non-HTML output responsibilities: findings.json, scanner copies, validation.

    This extracts the file management duties from generate_report() so
    the pipeline can call render_report() for HTML and finalize_output()
    for everything else independently.
    """
    output_dir = config.output_dir if not isinstance(config, dict) else config.get("output_dir", "/output")
    os.makedirs(output_dir, exist_ok=True)

    findings: list[dict[str, Any]] = enriched_findings.get("findings", [])

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


def render_report(
    report_data: dict,
    output_dir: str,
    *,
    template_dir: str | None = None,
) -> str:
    """Render HTML report by injecting report_data JSON into the Jinja template.

    Returns the path to the generated report.html.
    """
    import json as _json
    from jinja2 import Environment, FileSystemLoader

    if template_dir is None:
        candidates = [
            Path("/opt/templates/report"),
            Path(__file__).parent.parent.parent.parent / "templates" / "report",
        ]
        for candidate in candidates:
            if (candidate / "template_report.html").exists():
                template_dir = str(candidate)
                break
        if template_dir is None:
            raise FileNotFoundError(
                "template_report.html not found. Checked: "
                + ", ".join(str(c) for c in candidates)
            )

    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=False,
    )
    template = env.get_template("template_report.html")

    html = template.render(report_data=_json.dumps(report_data, indent=2))

    out_path = Path(output_dir) / "report.html"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html)

    logger.info("Report written to %s", out_path)
    return str(out_path)


def build_fallback_report_data(config, enriched_findings: list) -> dict:
    """Build report JSON programmatically when the AI agent is unavailable."""
    from datetime import date

    repo_name = config.repo_url.rstrip("/").rstrip(".git")
    repo_name = "/".join(repo_name.split("/")[-2:]) if "/" in repo_name else repo_name

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in enriched_findings:
        sev = (f.get("composite_priority") or f.get("severity", "low")).lower()
        if sev in counts:
            counts[sev] += 1

    if counts["critical"] > 0:
        verdict_label, verdict_severity = "FIX BEFORE USE", "critical"
    elif counts["high"] > 0:
        verdict_label, verdict_severity = "REVIEW BEFORE USE", "high"
    elif counts["medium"] > 0:
        verdict_label, verdict_severity = "LOW RISK", "medium"
    else:
        verdict_label, verdict_severity = "LOW RISK", "low"

    total = sum(counts.values())
    callout = f"{total} findings detected." if total > 0 else "No significant issues found."

    scanner = [f for f in enriched_findings if f.get("source_tool") != "ai"]
    scanner.sort(key=lambda f: float(f.get("cvss_score") or 0), reverse=True)
    scanner_top = []
    for i, f in enumerate(scanner[:10], 1):
        pkg = f.get("package_name", "unknown")
        ver = f.get("package_version", "")
        scanner_top.append({
            "rank": str(i),
            "severity": (f.get("composite_priority") or f.get("severity", "low")).lower(),
            "package": f"{pkg}@{ver}" if ver else pkg,
            "title": f.get("title", ""),
            "cve": f.get("cve_id", ""),
            "cvss": str(f.get("cvss_score", "")),
        })

    mitigations = []
    for f in enriched_findings:
        sev = (f.get("composite_priority") or f.get("severity", "")).lower()
        if sev in ("critical", "high"):
            cve = f.get("cve_id", "")
            pkg = f.get("package_name", "unknown")
            mitigations.append(
                f"Resolve {cve} in {pkg}" if cve else f"Remediate {pkg}: {f.get('title', '')}"
            )

    return {
        "meta": {
            "scan_date": date.today().isoformat(),
            "thresher_version": "v0.3.0",
            "scanner_count": "22",
            "analyst_count": "0" if config.skip_ai else "8",
            "repo_name": repo_name,
            "repo_url": config.repo_url,
        },
        "verdict": {
            "label": verdict_label,
            "severity": verdict_severity,
            "callout": callout,
        },
        "counts": {
            "total_scanner": str(total),
            "total_ai": "0",
            "p0": "0",
            "critical": str(counts["critical"]),
            "high_scanner": str(counts["high"]),
            "high_ai": "0",
            "medium": str(counts["medium"]),
            "low": str(counts["low"]),
        },
        "executive_summary": (
            f"<p>Automated scanning of <strong>{repo_name}</strong> produced "
            f"<strong>{total} findings</strong> across 22 tools.</p>"
        ),
        "mitigations": mitigations[:10],
        "scanner_findings": scanner_top,
        "ai_findings": [],
        "trust_signals": [],
        "dependency_upgrades": [],
        "remediation": None,
        "pipeline": {
            "scanners": [
                "grype", "trivy", "osv-scanner", "semgrep", "gitleaks",
                "checkov", "bandit", "clamav", "guarddog", "yara",
                "entropy", "install-hooks",
            ],
            "analysts": [],
            "notes": (
                "AI analysts were not run." if config.skip_ai
                else "AI agent failed; using fallback report."
            ),
        },
        "config": {
            "show_cta": "true",
            "show_remediation": "false",
        },
    }
