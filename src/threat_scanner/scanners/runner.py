"""Scanner orchestration -- runs all scanners and aggregates results."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from threat_scanner.config import ScanConfig
from threat_scanner.scanners.bandit import run_bandit
from threat_scanner.scanners.capa_scanner import run_capa
from threat_scanner.scanners.clamav import run_clamav
from threat_scanner.scanners.cargo_audit import run_cargo_audit
from threat_scanner.scanners.checkov import run_checkov
from threat_scanner.scanners.govulncheck import run_govulncheck
from threat_scanner.scanners.grype import run_grype
from threat_scanner.scanners.gitleaks import run_gitleaks
from threat_scanner.scanners.guarddog import run_guarddog
from threat_scanner.scanners.hadolint import run_hadolint
from threat_scanner.scanners.models import Finding, ScanResults
from threat_scanner.scanners.osv import run_osv
from threat_scanner.scanners.scancode import run_scancode
from threat_scanner.scanners.semgrep import run_semgrep
from threat_scanner.scanners.syft import run_syft
from threat_scanner.scanners.trivy import run_trivy
from threat_scanner.scanners.yara_scanner import run_yara
from threat_scanner.vm.ssh import ssh_exec

logger = logging.getLogger(__name__)

TARGET_DIR = "/opt/target"
OUTPUT_DIR = "/opt/scan-results"


def run_all_scanners(vm_name: str, config: ScanConfig) -> list[ScanResults]:
    """Run all configured scanners against the target repo inside the VM.

    Execution order:
      1. Syft runs first to produce the SBOM (required by Grype).
      2. Grype, OSV-Scanner, Semgrep, GuardDog, and Gitleaks run in parallel.

    Args:
        vm_name: Name of the Lima VM containing the cloned repository.
        config: Scan configuration.

    Returns:
        List of ScanResults from each scanner.
    """
    # Ensure the output directory exists inside the VM.
    ssh_exec(vm_name, f"mkdir -p {OUTPUT_DIR}")

    all_results: list[ScanResults] = []

    # --- Phase 1: SBOM generation (must complete before Grype) ---
    logger.info("Running Syft for SBOM generation...")
    syft_results = run_syft(vm_name, TARGET_DIR, OUTPUT_DIR)
    all_results.append(syft_results)

    if syft_results.errors:
        logger.warning("Syft encountered errors: %s", syft_results.errors)

    sbom_path = syft_results.metadata.get("sbom_path", f"{OUTPUT_DIR}/sbom.json")

    # --- Phase 2: All other scanners in parallel ---
    parallel_tasks: list[tuple[str, Callable[[], ScanResults]]] = [
        ("grype", lambda: run_grype(vm_name, sbom_path, OUTPUT_DIR)),
        ("osv-scanner", lambda: run_osv(vm_name, TARGET_DIR, OUTPUT_DIR)),
        ("semgrep", lambda: run_semgrep(vm_name, TARGET_DIR, OUTPUT_DIR)),
        ("guarddog", lambda: run_guarddog(vm_name, TARGET_DIR, OUTPUT_DIR)),
        ("gitleaks", lambda: run_gitleaks(vm_name, TARGET_DIR, OUTPUT_DIR)),
        ("bandit", lambda: run_bandit(vm_name, TARGET_DIR, OUTPUT_DIR)),
        ("checkov", lambda: run_checkov(vm_name, TARGET_DIR, OUTPUT_DIR)),
        ("hadolint", lambda: run_hadolint(vm_name, TARGET_DIR, OUTPUT_DIR)),
        ("trivy", lambda: run_trivy(vm_name, TARGET_DIR, OUTPUT_DIR)),
        ("yara", lambda: run_yara(vm_name, TARGET_DIR, OUTPUT_DIR)),
        ("capa", lambda: run_capa(vm_name, TARGET_DIR, OUTPUT_DIR)),
        ("govulncheck", lambda: run_govulncheck(vm_name, TARGET_DIR, OUTPUT_DIR)),
        ("cargo-audit", lambda: run_cargo_audit(vm_name, TARGET_DIR, OUTPUT_DIR)),
        ("scancode", lambda: run_scancode(vm_name, TARGET_DIR, OUTPUT_DIR)),
        ("clamav", lambda: run_clamav(vm_name, TARGET_DIR, OUTPUT_DIR)),
    ]

    logger.info("Running %d scanners in parallel...", len(parallel_tasks))

    with ThreadPoolExecutor(max_workers=len(parallel_tasks)) as executor:
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
                    "Scanner %s completed (exit=%d, findings=%d, errors=%d)",
                    name,
                    result.exit_code,
                    len(result.findings),
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
