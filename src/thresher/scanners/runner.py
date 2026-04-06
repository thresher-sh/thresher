"""Scanner orchestration -- runs all scanners and aggregates results."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable

from thresher.config import ScanConfig
from thresher.scanners.bandit import run_bandit
from thresher.scanners.capa_scanner import run_capa
from thresher.scanners.clamav import run_clamav
from thresher.scanners.cargo_audit import run_cargo_audit
from thresher.scanners.checkov import run_checkov
from thresher.scanners.deps_dev import run_deps_dev
from thresher.scanners.entropy import run_entropy
from thresher.scanners.govulncheck import run_govulncheck
from thresher.scanners.grype import run_grype
from thresher.scanners.gitleaks import run_gitleaks
from thresher.scanners.guarddog import run_guarddog
from thresher.scanners.guarddog_deps import run_guarddog_deps
from thresher.scanners.hadolint import run_hadolint
from thresher.scanners.install_hooks import run_install_hooks
from thresher.scanners.models import Finding, ScanResults
from thresher.scanners.osv import run_osv
from thresher.scanners.registry_meta import run_registry_meta
from thresher.scanners.scancode import run_scancode
from thresher.scanners.semgrep import run_semgrep
from thresher.scanners.semgrep_supply_chain import run_semgrep_supply_chain
from thresher.scanners.syft import run_syft
from thresher.scanners.trivy import run_trivy
from thresher.scanners.yara_scanner import run_yara

logger = logging.getLogger(__name__)

TARGET_DIR = "/opt/target"
OUTPUT_DIR = "/opt/scan-results"


def run_all_scanners(target_dir: str, output_dir: str, config: ScanConfig) -> list[ScanResults]:
    """Run all configured scanners against the target repo.

    Scanner findings are written to output_dir.  Only execution metadata
    (tool name, exit code, timing, errors) is returned.

    Execution order:
      1. Syft runs first to produce the SBOM (required by Grype).
      2. All other scanners run in parallel.

    Args:
        target_dir: Path to the cloned repository.
        output_dir: Directory where scan artifacts are written.
        config: Scan configuration.

    Returns:
        List of ScanResults with execution metadata only (no findings).
    """
    # Ensure the output directory exists.
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    all_results: list[ScanResults] = []

    # --- Phase 1: SBOM generation (must complete before Grype) ---
    logger.info("Running Syft for SBOM generation...")
    syft_results = run_syft(target_dir, output_dir)
    all_results.append(syft_results)

    if syft_results.errors:
        logger.warning("Syft encountered errors: %s", syft_results.errors)

    sbom_path = syft_results.metadata.get("sbom_path", f"{output_dir}/sbom.json")

    # --- Phase 2: All other scanners in parallel ---
    parallel_tasks: list[tuple[str, Callable[[], ScanResults]]] = [
        ("grype", lambda: run_grype(sbom_path, output_dir)),
        ("osv-scanner", lambda: run_osv(target_dir, output_dir)),
        ("semgrep", lambda: run_semgrep(target_dir, output_dir)),
        ("guarddog", lambda: run_guarddog(target_dir, output_dir)),
        ("gitleaks", lambda: run_gitleaks(target_dir, output_dir)),
        ("bandit", lambda: run_bandit(target_dir, output_dir)),
        ("checkov", lambda: run_checkov(target_dir, output_dir)),
        ("hadolint", lambda: run_hadolint(target_dir, output_dir)),
        ("trivy", lambda: run_trivy(target_dir, output_dir)),
        ("yara", lambda: run_yara(target_dir, output_dir)),
        ("capa", lambda: run_capa(target_dir, output_dir)),
        ("govulncheck", lambda: run_govulncheck(target_dir, output_dir)),
        ("cargo-audit", lambda: run_cargo_audit(target_dir, output_dir)),
        ("scancode", lambda: run_scancode(target_dir, output_dir)),
        ("clamav", lambda: run_clamav(target_dir, output_dir)),
        ("semgrep-supply-chain", lambda: run_semgrep_supply_chain(output_dir)),
        ("guarddog-deps", lambda: run_guarddog_deps(output_dir)),
        ("install-hooks", lambda: run_install_hooks(output_dir)),
        ("entropy", lambda: run_entropy(output_dir)),
        ("deps-dev", lambda: run_deps_dev(output_dir)),
        ("registry-meta", lambda: run_registry_meta(output_dir)),
    ]

    logger.info("Running %d scanners in parallel...", len(parallel_tasks))

    max_workers = min(len(parallel_tasks), getattr(config.limits, "max_concurrent_scans", 10))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_name = {}
        for name, task_fn in parallel_tasks:
            future = executor.submit(task_fn)
            future_to_name[future] = name

        for future in as_completed(future_to_name):
            name = future_to_name[future]
            try:
                result = future.result()
                all_results.append(result)
                logger.info(
                    "Scanner %s completed (exit=%d, errors=%d)",
                    name,
                    result.exit_code,
                    len(result.errors),
                )
            except Exception as exc:
                logger.exception("Scanner %s raised an unexpected exception", name)
                all_results.append(
                    ScanResults(
                        tool_name=name,
                        execution_time_seconds=0.0,
                        exit_code=-1,
                        errors=[f"Unexpected error running {name}: {exc}"],
                    )
                )

    return all_results


def aggregate_findings(results: list[ScanResults]) -> list[Finding]:
    """Merge and de-duplicate findings from all scanner results.

    De-duplication strategy: if two findings share the same CVE ID and
    the same package name, they are considered duplicates.  The finding
    with the richer detail (more fields populated) is kept.

    Findings without a CVE ID are always included (they cannot be
    de-duplicated by CVE).

    Args:
        results: List of ScanResults from all scanners.

    Returns:
        De-duplicated list of Finding objects sorted by severity.
    """
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    # Collect all findings.
    all_findings: list[Finding] = []
    for scan_result in results:
        all_findings.extend(scan_result.findings)

    # De-duplicate by (cve_id, package_name) where both are non-None.
    seen: dict[tuple[str, str], Finding] = {}
    unique: list[Finding] = []

    for finding in all_findings:
        if finding.cve_id and finding.package_name:
            key = (finding.cve_id, finding.package_name)
            existing = seen.get(key)
            if existing is None:
                seen[key] = finding
                unique.append(finding)
            else:
                # Keep the finding with more populated fields.
                if _richness(finding) > _richness(existing):
                    unique.remove(existing)
                    seen[key] = finding
                    unique.append(finding)
        else:
            # No CVE or no package -- cannot de-duplicate, always include.
            unique.append(finding)

    # Sort by severity (critical first).
    unique.sort(key=lambda f: severity_order.get(f.severity, 99))

    return unique


def _richness(finding: Finding) -> int:
    """Score how many optional fields are populated on a finding.

    Used to prefer the richer of two duplicate findings during
    de-duplication.
    """
    score = 0
    if finding.cvss_score is not None:
        score += 1
    if finding.description:
        score += 1
    if finding.fix_version:
        score += 1
    if finding.file_path:
        score += 1
    if finding.line_number is not None:
        score += 1
    return score
