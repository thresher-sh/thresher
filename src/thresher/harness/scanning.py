"""Scanner orchestration — runs all scanners in parallel."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from thresher.scanners.models import ScanResults

logger = logging.getLogger(__name__)
MAX_WORKERS = 15


def run_all_scanners(
    sbom_path: str,
    target_dir: str,
    deps_dir: str,
    output_dir: str,
    config: dict,
) -> list[ScanResults]:
    """Run all configured scanners in parallel.

    Args:
        sbom_path: Path to the SBOM JSON file (produced by Syft).
        target_dir: Path to the cloned repository.
        deps_dir: Path to the resolved dependencies directory.
        output_dir: Directory where scanner output files are written.
        config: Scan configuration dict.

    Returns:
        List of ScanResults with execution metadata.
    """
    tasks = _get_scanner_tasks()
    results: list[ScanResults] = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures: dict = {}
        for name, fn in tasks:
            kwargs = _resolve_scanner_kwargs(
                name,
                sbom_path=sbom_path,
                target_dir=target_dir,
                deps_dir=deps_dir,
                output_dir=output_dir,
            )
            futures[pool.submit(fn, **kwargs)] = name

        for future in as_completed(futures):
            name = futures[future]
            try:
                result = future.result()
                results.append(result)
                logger.info(
                    "Scanner %s done (exit=%d, %.1fs)",
                    name,
                    result.exit_code,
                    result.execution_time_seconds,
                )
            except Exception as exc:
                logger.exception("Scanner %s failed", name)
                results.append(
                    ScanResults(
                        tool_name=name,
                        execution_time_seconds=0.0,
                        exit_code=-1,
                        errors=[str(exc)],
                    )
                )

    return results


def _get_scanner_tasks() -> list[tuple[str, Callable]]:
    """Return (name, run_function) pairs for all scanners.

    NOTE: These scanner modules currently expect a ``vm_name`` first
    argument because they were written for the VM-based pipeline.  Task 7
    will refactor them to run natively (without SSH).  Until then this
    function is the seam that tests mock out.
    """
    from thresher.scanners.grype import run_grype
    from thresher.scanners.osv import run_osv
    from thresher.scanners.trivy import run_trivy
    from thresher.scanners.semgrep import run_semgrep
    from thresher.scanners.bandit import run_bandit
    from thresher.scanners.checkov import run_checkov
    from thresher.scanners.guarddog import run_guarddog
    from thresher.scanners.guarddog_deps import run_guarddog_deps
    from thresher.scanners.gitleaks import run_gitleaks
    from thresher.scanners.clamav import run_clamav
    from thresher.scanners.yara_scanner import run_yara
    from thresher.scanners.capa_scanner import run_capa
    from thresher.scanners.govulncheck import run_govulncheck
    from thresher.scanners.cargo_audit import run_cargo_audit
    from thresher.scanners.scancode import run_scancode
    from thresher.scanners.hadolint import run_hadolint
    from thresher.scanners.entropy import run_entropy
    from thresher.scanners.install_hooks import run_install_hooks
    from thresher.scanners.deps_dev import run_deps_dev
    from thresher.scanners.registry_meta import run_registry_meta
    from thresher.scanners.semgrep_supply_chain import run_semgrep_supply_chain

    return [
        ("grype", run_grype),
        ("osv", run_osv),
        ("trivy", run_trivy),
        ("semgrep", run_semgrep),
        ("bandit", run_bandit),
        ("checkov", run_checkov),
        ("guarddog", run_guarddog),
        ("guarddog-deps", run_guarddog_deps),
        ("gitleaks", run_gitleaks),
        ("clamav", run_clamav),
        ("yara", run_yara),
        ("capa", run_capa),
        ("govulncheck", run_govulncheck),
        ("cargo-audit", run_cargo_audit),
        ("scancode", run_scancode),
        ("hadolint", run_hadolint),
        ("entropy", run_entropy),
        ("install-hooks", run_install_hooks),
        ("deps-dev", run_deps_dev),
        ("registry-meta", run_registry_meta),
        ("semgrep-sc", run_semgrep_supply_chain),
    ]


def _resolve_scanner_kwargs(
    name: str,
    sbom_path: str,
    target_dir: str,
    deps_dir: str,
    output_dir: str,
) -> dict:
    """Build the kwargs dict for each scanner based on its signature.

    Scanners fall into three groups:
      - grype: needs sbom_path (not target_dir)
      - output-only: entropy, install-hooks, guarddog-deps, deps-dev,
        registry-meta, semgrep-sc — just need output_dir
      - standard: target_dir + output_dir
    """
    output_only = {
        "entropy",
        "install-hooks",
        "guarddog-deps",
        "deps-dev",
        "registry-meta",
        "semgrep-sc",
    }

    if name == "grype":
        return {"sbom_path": sbom_path, "output_dir": output_dir}
    if name in output_only:
        return {"output_dir": output_dir}
    return {"target_dir": target_dir, "output_dir": output_dir}
