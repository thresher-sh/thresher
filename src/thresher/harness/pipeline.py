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


def cloned_path(repo_url: str, config: dict) -> str:
    """Clone repo using hardened git clone."""
    from thresher.harness.clone import safe_clone
    branch = config.get("branch", "")
    return safe_clone(repo_url, "/opt/target", branch=branch)


def ecosystems(cloned_path: str) -> list[str]:
    """Detect package ecosystems in the cloned repo."""
    from thresher.harness.deps import detect_ecosystems
    return detect_ecosystems(cloned_path)


def hidden_deps(cloned_path: str, config: dict) -> dict:
    """Pre-dep agent discovers hidden dependencies. Skipped if skip_ai."""
    if config.get("skip_ai"):
        return {}
    from thresher.agents.predep import run_predep_discovery
    return run_predep_discovery(cloned_path, config)


def deps_path(cloned_path: str, ecosystems: list[str],
              hidden_deps: dict, config: dict) -> str:
    """Resolve and download dependencies as source-only."""
    from thresher.harness.deps import resolve_deps
    return resolve_deps(cloned_path, ecosystems, hidden_deps, config)


def sbom_path(cloned_path: str, output_dir: str) -> str:
    """Generate SBOM with Syft (sequential, required before Grype)."""
    from thresher.scanners.syft import run_syft
    result = run_syft(cloned_path, output_dir)
    return result.metadata.get("sbom_path", f"{output_dir}/sbom.json")


def scan_results(sbom_path: str, cloned_path: str, deps_path: str,
                 output_dir: str, config: dict) -> list[ScanResults]:
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
                     config: dict) -> list[dict]:
    """Run 8 analyst agents in parallel. Depends on scan_results for ordering."""
    if config.get("skip_ai"):
        return []
    from thresher.agents.analysts import run_all_analysts
    return run_all_analysts(cloned_path, deps_path, config)


def verified_findings(analyst_findings: list[dict],
                      cloned_path: str, config: dict) -> list[dict]:
    """Adversarial agent verifies high-risk findings."""
    if config.get("skip_ai") or not analyst_findings:
        return analyst_findings
    from thresher.agents.adversarial import run_adversarial_verification
    return run_adversarial_verification(analyst_findings, cloned_path, config)


def enriched_findings(scan_results: list[ScanResults],
                      verified_findings: list[dict]) -> dict:
    """EPSS/KEV enrichment and priority scoring."""
    from thresher.harness.report import enrich_all_findings
    return enrich_all_findings(scan_results, verified_findings)


def report_path(enriched_findings: dict, scan_results: list[ScanResults],
                config: dict) -> str:
    """Synthesize final report and write to output directory."""
    from thresher.harness.report import generate_report
    return generate_report(enriched_findings, scan_results, config)


# ── Pipeline Runner ─────────────────────────────────────────────────


def _build_driver() -> driver.Driver:
    """Build Hamilton driver from this module."""
    import thresher.harness.pipeline as pipeline_module
    return driver.Builder().with_modules(pipeline_module).build()


def run_pipeline(scan_config: ScanConfig) -> str:
    """Execute the full scan pipeline via Hamilton DAG."""
    dr = _build_driver()

    config_dict = {
        "skip_ai": scan_config.skip_ai,
        "high_risk_dep": scan_config.high_risk_dep,
        "model": scan_config.model,
        "branch": scan_config.branch,
        "verbose": scan_config.verbose,
        "depth": scan_config.depth,
        "analyst_max_turns": scan_config.analyst_max_turns,
        "analyst_max_turns_by_name": scan_config.analyst_max_turns_by_name,
        "adversarial_max_turns": scan_config.adversarial_max_turns,
    }

    inputs = {
        "repo_url": scan_config.repo_url,
        "config": config_dict,
        "output_dir": "/opt/scan-results",
    }

    logger.info("Executing pipeline DAG")
    result = dr.execute(
        final_vars=["report_path"],
        inputs=inputs,
    )

    report = result["report_path"]
    logger.info("Pipeline complete — report at %s", report)
    return report
