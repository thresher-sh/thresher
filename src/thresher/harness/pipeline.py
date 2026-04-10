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
    result = run_adversarial_verification(config, analyst_findings, cloned_path)
    if isinstance(result, dict):
        return result.get("findings", [])
    return result if result else []


def enriched_findings(scan_results: list[ScanResults],
                      verified_findings: list[dict]) -> dict:
    """EPSS/KEV enrichment and priority scoring."""
    from thresher.harness.report import enrich_all_findings
    return enrich_all_findings(scan_results, verified_findings)


def report_data(enriched_findings: dict, scan_results: list[ScanResults],
                analyst_findings: list[dict], config: ScanConfig) -> dict:
    """Run report-maker agent to produce structured JSON for the HTML report.

    Note: Uses config.output_dir rather than a Hamilton-wired output_dir input.
    This matches the pattern used by other agent-calling nodes in this pipeline.
    """
    if config.skip_ai:
        from thresher.harness.report import build_fallback_report_data
        findings = enriched_findings.get("findings", [])
        return build_fallback_report_data(config, findings)

    from thresher.agents.report_maker import run_report_maker
    result = run_report_maker(config, config.output_dir or "/opt/scan-results")
    if result is None:
        from thresher.harness.report import build_fallback_report_data
        findings = enriched_findings.get("findings", [])
        return build_fallback_report_data(config, findings)
    return result


def report_html(report_data: dict, enriched_findings: dict,
                scan_results: list[ScanResults], analyst_findings: list[dict],
                config: ScanConfig) -> str:
    """Render final HTML report and finalize output directory."""
    from thresher.harness.report import render_report, finalize_output

    output_dir = config.output_dir or "/opt/scan-results"
    html_path = render_report(report_data, output_dir)
    finalize_output(enriched_findings, scan_results, config,
                    analyst_findings=analyst_findings)
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
