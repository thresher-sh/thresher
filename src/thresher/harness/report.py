"""Report validation, enrichment, and generation."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from thresher.report.scoring import enrich_findings
from thresher.scanners.models import ScanResults

logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = frozenset({".json", ".md", ".txt", ".csv", ".log", ".sarif", ".html"})
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
            logger.warning("Removing file with disallowed extension: %s", path)
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
        raw_ai = verified_findings.get("findings", [])
    elif verified_findings:
        raw_ai = list(verified_findings)
    else:
        raw_ai = []

    # Map AI-specific fields so composite priority scoring works.
    # This mirrors the field mapping in synthesize.py:_collect_findings()
    # which the harness path bypasses.
    all_findings: list[dict[str, Any]] = []
    for af in raw_ai:
        if not isinstance(af, dict):
            continue
        mapped = dict(af)
        if "risk_score" in mapped and "ai_risk_score" not in mapped:
            mapped["ai_risk_score"] = mapped["risk_score"]
        mapped.setdefault("source_tool", "ai_analysis")
        mapped.setdefault("category", "ai_analysis")

        # Derive ai_confidence from sub-findings if not set directly
        sub_findings = mapped.get("findings", [])
        if isinstance(sub_findings, list) and sub_findings:
            max_conf = max(
                (sf.get("confidence", 0) for sf in sub_findings if isinstance(sf, dict)),
                default=0,
            )
            if max_conf and "ai_confidence" not in mapped:
                mapped["ai_confidence"] = max_conf

            # Derive severity from highest sub-finding severity
            sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
            worst_sev = "low"
            for sf in sub_findings:
                if isinstance(sf, dict):
                    s = sf.get("severity", "low").lower()
                    if sev_rank.get(s, 99) < sev_rank.get(worst_sev, 99):
                        worst_sev = s
            mapped.setdefault("severity", worst_sev)
        else:
            mapped.setdefault("severity", "low")

        all_findings.append(mapped)

    # Merge scanner findings into the combined list
    for sr in scan_results or []:
        for finding in sr.findings:
            all_findings.append(finding.to_dict())

    enriched = enrich_findings(all_findings, vm_name="")

    scanner_results_map = {r.tool_name: r for r in (scan_results or [])}

    return {
        "findings": enriched,
        "scanner_results": scanner_results_map,
    }


def stage_artifacts(
    enriched_findings: dict[str, Any],
    config,
    *,
    analyst_findings: list[dict[str, Any]] | None = None,
    scan_results_source: str = "/opt/scan-results",
    deps_source: str = "/opt/deps",
) -> str:
    """Stage every artifact the report-maker / synthesize agents need to
    read into the report output directory.

    Runs BEFORE the report-maker / render_report stages so the agents can
    treat ``output_dir`` as the single source of truth. Specifically:

      - writes ``findings.json`` (enriched findings list)
      - writes per-analyst ``analyst-NN-<name>.{json,md}`` files
      - copies the 22 raw scanner outputs into ``scan-results/``
      - copies ``dep_resolution.json`` from the deps dir alongside them

    Returns the resolved output directory path so DAG callers can use it
    as a value-typed dependency for downstream nodes.
    """
    output_dir = config.output_dir if not isinstance(config, dict) else config.get("output_dir", "/output")
    os.makedirs(output_dir, exist_ok=True)
    out_path = Path(output_dir)
    scan_results_dir = out_path / "scan-results"
    scan_results_dir.mkdir(exist_ok=True)

    findings: list[dict[str, Any]] = enriched_findings.get("findings", [])

    # Machine-readable enriched findings — used by both downstream agents
    # and any humans poking at the report tree.
    (out_path / "findings.json").write_text(json.dumps(findings, indent=2, default=str))

    # Per-analyst output: JSON for the formatter, markdown for humans.
    if analyst_findings:
        from thresher.agents.analysts import (
            ANALYST_DEFINITIONS,
            _format_analyst_markdown,
        )

        analyst_def_by_name = {d["name"]: d for d in ANALYST_DEFINITIONS}
        for af in analyst_findings:
            number = af.get("analyst_number", 0)
            name = af.get("analyst", "unknown")
            base = f"analyst-{number:02d}-{name}"
            (scan_results_dir / f"{base}.json").write_text(json.dumps(af, indent=2, default=str))
            analyst_def = analyst_def_by_name.get(name)
            if analyst_def is not None:
                try:
                    md_text = _format_analyst_markdown(af, analyst_def)
                    (scan_results_dir / f"{base}.md").write_text(md_text)
                except Exception:
                    logger.warning(
                        "Failed to format analyst markdown for %s",
                        name,
                        exc_info=True,
                    )
            logger.info("Staged per-analyst output: %s.json/.md", base)

    # Copy raw scanner outputs into scan-results/.
    source_dir = Path(scan_results_source)
    if source_dir.exists():
        import shutil

        for f in source_dir.iterdir():
            if f.is_file():
                shutil.copy2(f, scan_results_dir / f.name)

    # Copy dep_resolution.json so the report-maker can surface degraded
    # ecosystems in pipeline.notes.
    dep_status = Path(deps_source) / "dep_resolution.json"
    if dep_status.is_file():
        import shutil

        shutil.copy2(dep_status, scan_results_dir / "dep_resolution.json")

    return str(out_path)


def finalize_output(
    config,
    *,
    staged_dir: str | None = None,
) -> None:
    """Final post-render pass: validate the staged report tree.

    All artifact staging now happens in :func:`stage_artifacts` (called
    earlier in the DAG so the report-maker / synthesize agents can read
    everything). This function only runs the boundary validator that
    rejects symlinks, oversized files, and disallowed extensions.
    """
    output_dir = staged_dir or (
        config.output_dir if not isinstance(config, dict) else config.get("output_dir", "/output")
    )
    validate_report_output(output_dir)


# Top-level keys the HTML template's renderHero/renderFindingsBar/etc.
# expect on the report_data dict. Missing keys cause "undefined" cells in
# the rendered page, so we treat their absence as a hard validation
# failure and fall back to build_fallback_report_data().
_REQUIRED_REPORT_DATA_KEYS = frozenset(
    {
        "meta",
        "verdict",
        "counts",
        "executive_summary",
        "scanner_findings",
        "ai_findings",
        "pipeline",
    }
)


def _dep_resolution_dir() -> str:
    """Return the directory holding ``dep_resolution.json``.

    Defaults to ``/opt/deps`` (the in-container path used by the
    pipeline). Tests patch this to redirect to a tmp dir.
    """
    return "/opt/deps"


def summarize_dep_resolution(deps_dir: str | None = None) -> str:
    """Return a human-readable note about dependency-resolution failures.

    Reads ``deps_dir/dep_resolution.json`` (written by ``resolve_deps``)
    and produces a one-line summary of any failed ecosystems. Returns an
    empty string when the file is missing or every ecosystem succeeded —
    so callers can safely ``or`` it into existing notes.
    """
    base = Path(deps_dir or _dep_resolution_dir())
    status_file = base / "dep_resolution.json"
    if not status_file.is_file():
        return ""
    try:
        data = json.loads(status_file.read_text())
    except (OSError, json.JSONDecodeError):
        return ""

    ecosystems = data.get("ecosystems", {}) if isinstance(data, dict) else {}
    failures: list[tuple[str, str]] = []
    for name, entry in ecosystems.items():
        if not isinstance(entry, dict):
            continue
        if entry.get("status") == "failed":
            failures.append((name, entry.get("reason", "")))

    if not failures:
        return ""

    parts = []
    for name, reason in failures:
        if reason:
            parts.append(f"{name} (failed: {reason})")
        else:
            parts.append(f"{name} (failed)")
    return (
        "Dependency download failed for: "
        + ", ".join(parts)
        + ". Downstream scanner coverage for these ecosystems is degraded."
    )


def validate_report_data(report_data: dict) -> set[str]:
    """Return the set of required top-level keys missing from report_data.

    An empty return set means the dict has every key the HTML template
    needs. The pipeline's report_data() node uses this to decide whether
    to fall back to ``build_fallback_report_data``.
    """
    if not isinstance(report_data, dict):
        return set(_REQUIRED_REPORT_DATA_KEYS)
    return {k for k in _REQUIRED_REPORT_DATA_KEYS if k not in report_data}


def render_report(
    report_data: dict,
    output_dir: str,
    *,
    template_dir: str | None = None,
) -> str:
    """Render HTML report by injecting report_data JSON into the Jinja template.

    Also persists ``report_data.json`` next to ``report.html`` so downstream
    tools can consume the structured data without scraping the HTML.

    Returns the path to the generated report.html.
    """
    import json as _json

    from jinja2 import Environment, FileSystemLoader

    if template_dir is None:
        candidates = [
            Path("/opt/templates/report"),
            Path(__file__).parent.parent / "report" / "templates",
        ]
        for candidate in candidates:
            if (candidate / "template_report.html").exists():
                template_dir = str(candidate)
                break
        if template_dir is None:
            raise FileNotFoundError("template_report.html not found. Checked: " + ", ".join(str(c) for c in candidates))

    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=False,
    )
    template = env.get_template("template_report.html")

    serialized = _json.dumps(report_data, indent=2, default=str)
    html = template.render(report_data=serialized)

    out_dir_path = Path(output_dir)
    out_dir_path.mkdir(parents=True, exist_ok=True)

    out_path = out_dir_path / "report.html"
    out_path.write_text(html)

    # Persist the raw report_data alongside the HTML so it's independently
    # inspectable. Without this, the HTML is the only place the data lives.
    (out_dir_path / "report_data.json").write_text(serialized)

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
        verdict_label, verdict_severity = "CAUTION", "medium"
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
        scanner_top.append(
            {
                "rank": str(i),
                "severity": (f.get("composite_priority") or f.get("severity", "low")).lower(),
                "package": f"{pkg}@{ver}" if ver else pkg,
                "title": f.get("title", ""),
                "cve": f.get("cve_id", ""),
                "cvss": str(f.get("cvss_score", "")),
            }
        )

    mitigations = []
    for f in enriched_findings:
        sev = (f.get("composite_priority") or f.get("severity", "")).lower()
        if sev in ("critical", "high"):
            cve = f.get("cve_id", "")
            pkg = f.get("package_name", "unknown")
            mitigations.append(f"Resolve {cve} in {pkg}" if cve else f"Remediate {pkg}: {f.get('title', '')}")

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
                "grype",
                "trivy",
                "osv-scanner",
                "semgrep",
                "gitleaks",
                "checkov",
                "bandit",
                "clamav",
                "guarddog",
                "yara",
                "entropy",
                "install-hooks",
            ],
            "analysts": [],
            "notes": ("AI analysts were not run." if config.skip_ai else "AI agent failed; using fallback report."),
        },
        "config": {
            "show_cta": "false",
            "show_remediation": "false",
        },
    }
