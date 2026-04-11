"""Hamilton DAG pipeline for the Thresher scan harness.

Each function is a DAG node. Parameter names define dependencies.
Hamilton auto-resolves the execution graph and parallelizes independent nodes.
"""

import logging
from hamilton import driver

from thresher.config import ScanConfig
from thresher.scanners.models import ScanResults

logger = logging.getLogger(__name__)


# ── DAG Node Functions ──────────────────────────────────────────────


def cloned_path(repo_url: str, config: ScanConfig) -> str:
    """Clone repo using hardened git clone."""
    from thresher.harness.clone import safe_clone
    branch = config.branch
    return safe_clone(repo_url, "/opt/target", branch=branch)


def ecosystems(cloned_path: str) -> list[str]:
    """Detect package ecosystems in the cloned repo."""
    from thresher.harness.deps import detect_ecosystems
    return detect_ecosystems(cloned_path)


def hidden_deps(cloned_path: str, config: ScanConfig) -> dict:
    """Pre-dep agent discovers hidden dependencies. Skipped if skip_ai."""
    if config.skip_ai:
        return {}
    from thresher.agents.predep import run_predep_discovery
    return run_predep_discovery(config, cloned_path)


def deps_path(cloned_path: str, ecosystems: list[str],
              hidden_deps: dict, config: ScanConfig) -> str:
    """Resolve and download dependencies as source-only."""
    from thresher.harness.deps import resolve_deps
    return resolve_deps(cloned_path, ecosystems, hidden_deps, config)


def sbom_path(cloned_path: str, output_dir: str) -> str:
    """Generate SBOM with Syft (sequential, required before Grype)."""
    from thresher.scanners.syft import run_syft
    result = run_syft(cloned_path, output_dir)
    return result.metadata.get("sbom_path", f"{output_dir}/sbom.json")


def scan_results(sbom_path: str, cloned_path: str, deps_path: str,
                 output_dir: str, config: ScanConfig) -> list[ScanResults]:
    """Run all scanners in parallel and aggregate results."""
    from thresher.harness.scanning import run_all_scanners
    return run_all_scanners(
        sbom_path=sbom_path,
        target_dir=cloned_path,
        deps_dir=deps_path,
        output_dir=output_dir,
        config=config,
    )


def analyst_findings(cloned_path: str, deps_path: str,
                     scan_results: list[ScanResults],
                     config: ScanConfig) -> list[dict]:
    """Run 8 analyst agents in parallel. Depends on scan_results for ordering."""
    if config.skip_ai:
        return []
    from thresher.agents.analysts import run_all_analysts
    return run_all_analysts(config, cloned_path)


def verified_findings(analyst_findings: list[dict],
                      cloned_path: str, config: ScanConfig) -> list[dict]:
    """Adversarial agent verifies high-risk findings."""
    if config.skip_ai or not analyst_findings:
        return analyst_findings
    from thresher.agents.adversarial import run_adversarial_verification
    result = run_adversarial_verification(
        config,
        analyst_findings,
        cloned_path,
        output_dir=config.output_dir or "/opt/scan-results",
    )
    if isinstance(result, dict):
        return result.get("findings", [])
    return result if result else []


def enriched_findings(scan_results: list[ScanResults],
                      verified_findings: list[dict]) -> dict:
    """EPSS/KEV enrichment and priority scoring."""
    from thresher.harness.report import enrich_all_findings
    return enrich_all_findings(scan_results, verified_findings)


def _inject_dep_resolution_notes(result: dict) -> dict:
    """Append a degraded-coverage note to ``pipeline.notes`` when the
    ``dep_resolution.json`` status file shows any ecosystem failures.
    Returns the same dict (mutated)."""
    from thresher.harness.report import summarize_dep_resolution

    notes = summarize_dep_resolution()
    if not notes:
        return result
    pipeline_section = result.setdefault("pipeline", {})
    existing = pipeline_section.get("notes", "") or ""
    if existing:
        pipeline_section["notes"] = existing.rstrip(". ") + ". " + notes
    else:
        pipeline_section["notes"] = notes
    return result


def staged_artifacts(synthesized_reports: bool,
                     enriched_findings: dict,
                     analyst_findings: list[dict],
                     config: ScanConfig) -> str:
    """Stage every report artifact into config.output_dir BEFORE the
    report-maker runs.

    The DAG dependency on ``synthesized_reports`` enforces ordering: the
    synthesis agent writes ``executive-summary.md`` etc. directly into
    ``config.output_dir``, then this node copies the scanner outputs and
    per-analyst files alongside them so the formatter has everything in
    one place. Returns the resolved output dir for downstream nodes.
    """
    from thresher.harness.report import stage_artifacts as _stage
    _ = synthesized_reports  # ordering only
    return _stage(
        enriched_findings,
        config,
        analyst_findings=analyst_findings,
    )


def report_data(staged_artifacts: str,
                enriched_findings: dict,
                scan_results: list[ScanResults],
                analyst_findings: list[dict],
                synthesized_reports: bool,
                config: ScanConfig) -> dict:
    """Run report-maker agent to FORMAT the staged scan into structured JSON.

    Hard-depends on ``staged_artifacts`` and ``synthesized_reports`` so
    the report directory contains every file the agent needs to consume:
    synthesis markdown (the "judge" output), per-analyst files, raw
    scanner JSONs, dep_resolution.json. The agent then packages these
    into the JSON the HTML template renders.
    """
    from thresher.harness.report import (
        build_fallback_report_data,
        validate_report_data,
    )

    _ = synthesized_reports  # ordering only — value flows via staged_artifacts

    if config.skip_ai:
        findings = enriched_findings.get("findings", [])
        return _inject_dep_resolution_notes(
            build_fallback_report_data(config, findings)
        )

    from thresher.agents.report_maker import run_report_maker
    result = run_report_maker(config, staged_artifacts)
    if result is None:
        findings = enriched_findings.get("findings", [])
        logger.warning(
            "report_maker returned no data; using fallback report_data"
        )
        return _inject_dep_resolution_notes(
            build_fallback_report_data(config, findings)
        )

    # Schema validation: if the agent's output is missing required keys
    # (typically because it hit error_max_turns), fall back to the
    # programmatic builder rather than feeding broken data to the HTML
    # template.
    missing = validate_report_data(result)
    if missing:
        logger.warning(
            "report_maker output missing required schema keys (%s); "
            "using fallback report_data",
            ", ".join(sorted(missing)),
        )
        findings = enriched_findings.get("findings", [])
        return _inject_dep_resolution_notes(
            build_fallback_report_data(config, findings)
        )

    return _inject_dep_resolution_notes(result)


def synthesized_reports(verified_findings: list[dict],
                        enriched_findings: dict,
                        scan_results: list[ScanResults],
                        config: ScanConfig) -> bool:
    """Run the synthesis agent to write executive-summary / detailed-report
    / synthesis-findings markdown files into the output directory.

    Returns True when the agent produced the expected files. Skipped when
    skip_ai is set or AI credentials are unavailable.
    """
    if config.skip_ai or not config.has_ai_credentials:
        return False

    from thresher.agents.synthesize import (
        build_synthesis_input,
        run_synthesize_agent,
    )
    import os as _os

    output_dir = config.output_dir or "/opt/scan-results"
    _os.makedirs(output_dir, exist_ok=True)

    findings = enriched_findings.get("findings", [])
    synthesis_input = build_synthesis_input(
        scan_results,
        {"findings": verified_findings},
        findings,
    )
    try:
        return run_synthesize_agent(config, output_dir, synthesis_input)
    except Exception as exc:
        logger.warning("synthesize agent invocation failed: %s", exc)
        return False


def report_html(report_data: dict, staged_artifacts: str,
                config: ScanConfig) -> str:
    """Render final HTML report and run the boundary validator.

    By the time this node runs, ``staged_artifacts`` has already copied
    every per-analyst file, scanner output, and dep_resolution.json into
    ``config.output_dir`` and ``report_data`` has produced the structured
    JSON. All that's left is rendering ``report.html`` + ``report_data.json``
    and validating the directory tree.
    """
    from thresher.harness.report import render_report, finalize_output

    html_path = render_report(report_data, staged_artifacts)
    finalize_output(config, staged_dir=staged_artifacts)
    return html_path


# ── Pipeline Runner ─────────────────────────────────────────────────


def _build_driver() -> driver.Driver:
    """Build Hamilton driver from this module."""
    import thresher.harness.pipeline as pipeline_module
    return driver.Builder().with_modules(pipeline_module).build()


def run_pipeline(scan_config: ScanConfig) -> str:
    """Execute the full scan pipeline via Hamilton DAG."""
    dr = _build_driver()

    inputs = {
        "repo_url": scan_config.repo_url,
        "config": scan_config,
        "output_dir": "/opt/scan-results",
    }

    logger.info("Executing pipeline DAG")
    result = dr.execute(
        final_vars=["report_html"],
        inputs=inputs,
    )

    report = result["report_html"]
    logger.info("Pipeline complete — report at %s", report)
    return report
