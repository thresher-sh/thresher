"""Hamilton DAG pipeline for the Thresher scan harness.

Each function is a DAG node. Parameter names define dependencies.
Hamilton auto-resolves the execution graph and parallelizes independent nodes.

Benchmark data is collected via a ``benchmark`` parameter (BenchmarkCollector)
passed as a DAG input. Each node wraps its work with ``_time_stage()`` which
records runtime, findings, errors, and token usage.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from hamilton import driver

from thresher.config import ScanConfig
from thresher.harness.benchmarks import BenchmarkCollector, StageStats
from thresher.scanners.models import ScanResults

logger = logging.getLogger(__name__)


def _time_stage(
    collector: BenchmarkCollector,
    name: str,
) -> _Timer:
    return _Timer(collector, name)


class _Timer:
    """Context manager that times a pipeline stage and records it."""

    def __init__(self, collector: BenchmarkCollector, name: str) -> None:
        self._collector = collector
        self._name = name
        self._start = 0.0

    def __enter__(self) -> _Timer:
        self._start = time.monotonic()
        return self

    def record(
        self,
        *,
        findings_count: int = 0,
        errors: list[str] | None = None,
        token_usage: dict[str, int] | None = None,
        metadata: dict[str, object] | None = None,
    ) -> None:
        duration = time.monotonic() - self._start
        self._collector.add(
            StageStats(
                name=self._name,
                runtime_seconds=duration,
                findings_count=findings_count,
                errors=errors or [],
                token_usage=token_usage or {},
                metadata=metadata or {},
            )
        )

    def __exit__(self, *args: object) -> None:
        pass  # record() must be called explicitly


# ── Helpers ─────────────────────────────────────────────────────────


def copy_local_source(source_dir: str, target_dir: str) -> str:
    """Copy a local non-git directory into the scan target."""
    import shutil
    shutil.copytree(source_dir, target_dir, dirs_exist_ok=True)
    return target_dir


# ── DAG Node Functions ──────────────────────────────────────────────


def cloned_path(repo_url: str, config: ScanConfig, benchmark: BenchmarkCollector) -> str:
    """Clone repo or copy local source into scan target."""
    from thresher.harness.clone import safe_clone

    with _time_stage(benchmark, "clone") as t:
        if config.local_path:
            if (Path(config.local_path) / ".git").is_dir():
                logger.info("Local git repo detected — cloning via file:// protocol")
                result = safe_clone(
                    "file://" + config.local_path,
                    "/opt/target",
                    branch=config.branch,
                )
            else:
                logger.info("Local directory detected — copying to target")
                result = copy_local_source(config.local_path, "/opt/target")
        else:
            result = safe_clone(repo_url, "/opt/target", branch=config.branch)
        t.record()
    return result


def ecosystems(cloned_path: str, benchmark: BenchmarkCollector) -> list[str]:
    """Detect package ecosystems in the cloned repo."""
    from thresher.harness.deps import detect_ecosystems

    with _time_stage(benchmark, "ecosystems") as t:
        result = detect_ecosystems(cloned_path)
        t.record()
    return result


def hidden_deps(cloned_path: str, config: ScanConfig, benchmark: BenchmarkCollector) -> dict:
    """Pre-dep agent discovers hidden dependencies. Skipped if skip_ai."""
    if config.skip_ai:
        return {}
    from thresher.agents.predep import run_predep_discovery

    with _time_stage(benchmark, "predep") as t:
        result = run_predep_discovery(config, cloned_path)
        bm = result.pop("_benchmark", {})
        t.record(
            token_usage=bm.get("token_usage", {}),
            metadata={
                "turns": bm.get("turns", 0),
                "model_usage": bm.get("model_usage", {}),
            },
            errors=[result.get("summary", "")] if result.get("hidden_dependencies") is None else None,
        )
    return result


def deps_path(
    cloned_path: str, ecosystems: list[str], hidden_deps: dict, config: ScanConfig, benchmark: BenchmarkCollector
) -> str:
    """Resolve and download dependencies as source-only."""
    from thresher.harness.deps import resolve_deps

    with _time_stage(benchmark, "deps") as t:
        result = resolve_deps(cloned_path, ecosystems, hidden_deps, config)
        t.record()
    return result


def sbom_path(cloned_path: str, output_dir: str, benchmark: BenchmarkCollector) -> str:
    """Generate SBOM with Syft (sequential, required before Grype)."""
    from thresher.scanners.syft import run_syft

    with _time_stage(benchmark, "sbom") as t:
        result = run_syft(cloned_path, output_dir)
        sbom = result.metadata.get("sbom_path", f"{output_dir}/sbom.json")
        t.record(errors=result.errors or None)
    return sbom


def scan_results(
    sbom_path: str,
    cloned_path: str,
    deps_path: str,
    output_dir: str,
    config: ScanConfig,
    benchmark: BenchmarkCollector,
) -> list[ScanResults]:
    """Run all scanners in parallel and aggregate results."""
    from thresher.harness.scanning import run_all_scanners

    with _time_stage(benchmark, "scanners") as t:
        results = run_all_scanners(
            sbom_path=sbom_path,
            target_dir=cloned_path,
            deps_dir=deps_path,
            output_dir=output_dir,
            config=config,
        )
        total_findings = sum(len(r.findings) for r in results)
        errors = [e for r in results for e in r.errors]
        t.record(
            findings_count=total_findings,
            errors=errors or None,
            metadata={"finding_lifecycle": "raw_scanner"},
        )
    return results


def analyst_findings(
    cloned_path: str,
    deps_path: str,
    scan_results: list[ScanResults],
    config: ScanConfig,
    benchmark: BenchmarkCollector,
) -> list[dict]:
    """Run 8 analyst agents in parallel. Depends on scan_results for ordering."""
    if config.skip_ai:
        return []
    from thresher.agents.analysts import run_all_analysts

    with _time_stage(benchmark, "analysts") as t:
        all_findings = run_all_analysts(config, cloned_path)
        total_findings = sum(len(f.get("findings", [])) for f in all_findings)
        combined_tokens: dict[str, int] = {}
        combined_model_usage: dict[str, dict[str, int]] = {}
        for f in all_findings:
            timing = f.get("_timing", {})
            analyst_name = timing.get("name") or f.get("analyst", "unknown")
            analyst_number = f.get("analyst_number", 0)
            benchmark.add(
                StageStats(
                    name=f"analyst-{analyst_number:02d}-{analyst_name}",
                    runtime_seconds=float(timing.get("duration", 0.0) or 0.0),
                    findings_count=len(f.get("findings", [])),
                    token_usage=timing.get("token_usage", {}) or {},
                    metadata={
                        "turns": timing.get("turns", 0),
                        "model_usage": timing.get("model_usage", {}) or {},
                        "finding_lifecycle": "analyst_candidate",
                    },
                )
            )
            for model, usage in (timing.get("model_usage", {}) or {}).items():
                model_totals = combined_model_usage.setdefault(
                    model,
                    {
                        "input_tokens": 0,
                        "output_tokens": 0,
                        "cache_creation_input_tokens": 0,
                        "cache_read_input_tokens": 0,
                    },
                )
                for key, val in usage.items():
                    model_totals[key] = model_totals.get(key, 0) + val
        for f in all_findings:
            timing = f.get("_timing", {})
            for key, val in timing.get("token_usage", {}).items():
                combined_tokens[key] = combined_tokens.get(key, 0) + val
        t.record(
            findings_count=total_findings,
            token_usage=combined_tokens,
            metadata={
                "stage_kind": "analyst_parallel_block",
                "model_usage": combined_model_usage,
            },
        )
    # Strip internal timing metadata now that benchmarks have consumed it
    for f in all_findings:
        f.pop("_timing", None)
    return all_findings


def verified_findings(
    analyst_findings: list[dict], cloned_path: str, config: ScanConfig, benchmark: BenchmarkCollector
) -> list[dict]:
    """Adversarial agent verifies high-risk findings."""
    if config.skip_ai or not analyst_findings:
        return analyst_findings
    from thresher.agents.adversarial import run_adversarial_verification

    with _time_stage(benchmark, "adversarial") as t:
        result = run_adversarial_verification(
            config,
            analyst_findings,
            cloned_path,
            output_dir=config.output_dir or "/opt/scan-results",
        )
        if isinstance(result, dict):
            bm = result.pop("_benchmark", {})
            findings = result.get("findings", [])
            t.record(
                findings_count=len(findings),
                token_usage=bm.get("token_usage", {}),
                metadata={
                    "turns": bm.get("turns", 0),
                    "model_usage": bm.get("model_usage", {}),
                    "finding_lifecycle": "verified",
                },
            )
            return findings
        items = result if result else []
        t.record(findings_count=len(items), metadata={"finding_lifecycle": "verified"})
        return items


def enriched_findings(
    scan_results: list[ScanResults], verified_findings: list[dict], benchmark: BenchmarkCollector
) -> dict:
    """EPSS/KEV enrichment and priority scoring."""
    from thresher.harness.report import enrich_all_findings

    with _time_stage(benchmark, "enrich") as t:
        result = enrich_all_findings(scan_results, verified_findings)
        t.record(
            findings_count=len(result.get("findings", [])),
            metadata={"finding_lifecycle": "final"},
        )
    return result


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


def synthesized_reports(
    verified_findings: list[dict],
    enriched_findings: dict,
    scan_results: list[ScanResults],
    config: ScanConfig,
    benchmark: BenchmarkCollector,
) -> bool:
    """Run the synthesis agent to write executive-summary / detailed-report
    / synthesis-findings markdown files into the output directory.

    Returns True when the agent produced the expected files. Skipped when
    skip_ai is set or AI credentials are unavailable.
    """
    if config.skip_ai or not config.has_ai_credentials:
        return False

    import os as _os

    from thresher.agents.synthesize import (
        build_synthesis_input,
        run_synthesize_agent,
    )

    output_dir = config.output_dir or "/opt/scan-results"
    _os.makedirs(output_dir, exist_ok=True)

    findings = enriched_findings.get("findings", [])
    synthesis_input = build_synthesis_input(
        scan_results,
        {"findings": verified_findings},
        findings,
    )
    with _time_stage(benchmark, "synthesize") as t:
        try:
            success, bm = run_synthesize_agent(config, output_dir, synthesis_input)
            t.record(
                token_usage=bm.get("token_usage", {}),
                metadata={
                    "turns": bm.get("turns", 0),
                    "model_usage": bm.get("model_usage", {}),
                },
            )
            return success
        except Exception as exc:
            logger.warning("synthesize agent invocation failed: %s", exc)
            t.record(errors=[str(exc)])
            return False


def staged_artifacts(
    synthesized_reports: bool,
    enriched_findings: dict,
    analyst_findings: list[dict],
    config: ScanConfig,
    benchmark: BenchmarkCollector,
) -> str:
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
    with _time_stage(benchmark, "stage_artifacts") as t:
        result = _stage(
            enriched_findings,
            config,
            analyst_findings=analyst_findings,
        )
        t.record()
    return result


def report_data(
    staged_artifacts: str,
    enriched_findings: dict,
    scan_results: list[ScanResults],
    analyst_findings: list[dict],
    synthesized_reports: bool,
    config: ScanConfig,
    benchmark: BenchmarkCollector,
) -> dict:
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
        return _inject_dep_resolution_notes(build_fallback_report_data(config, findings))

    from thresher.agents.report_maker import run_report_maker

    with _time_stage(benchmark, "report_maker") as t:
        result = run_report_maker(config, staged_artifacts)
        if result is None:
            findings = enriched_findings.get("findings", [])
            logger.warning("report_maker returned no data; using fallback report_data")
            t.record(errors=["report_maker returned no data"])
            return _inject_dep_resolution_notes(build_fallback_report_data(config, findings))

        bm = result.pop("_benchmark", {})

        # Schema validation: if the agent's output is missing required keys
        # (typically because it hit error_max_turns), fall back to the
        # programmatic builder rather than feeding broken data to the HTML
        # template.
        missing = validate_report_data(result)
        if missing:
            logger.warning(
                "report_maker output missing required schema keys (%s); using fallback report_data",
                ", ".join(sorted(missing)),
            )
            t.record(
                token_usage=bm.get("token_usage", {}),
                metadata={
                    "turns": bm.get("turns", 0),
                    "model_usage": bm.get("model_usage", {}),
                },
                errors=[f"missing schema keys: {', '.join(sorted(missing))}"],
            )
            findings = enriched_findings.get("findings", [])
            return _inject_dep_resolution_notes(build_fallback_report_data(config, findings))

        t.record(
            token_usage=bm.get("token_usage", {}),
            metadata={
                "turns": bm.get("turns", 0),
                "model_usage": bm.get("model_usage", {}),
            },
        )
    return _inject_dep_resolution_notes(result)


def report_html(
    report_data: dict,
    staged_artifacts: str,
    config: ScanConfig,
    benchmark: BenchmarkCollector,
) -> str:
    """Render final HTML report and run the boundary validator.

    By the time this node runs, ``staged_artifacts`` has already copied
    every per-analyst file, scanner output, and dep_resolution.json into
    ``config.output_dir`` and ``report_data`` has produced the structured
    JSON. All that's left is rendering ``report.html`` + ``report_data.json``
    and validating the directory tree.
    """
    from thresher.harness.report import finalize_output, render_report

    with _time_stage(benchmark, "report_html") as t:
        html_path = render_report(report_data, staged_artifacts)
        finalize_output(config, staged_dir=staged_artifacts)
        t.record()
    return html_path


def benchmark_report(
    report_html: str,
    staged_artifacts: str,
    config: ScanConfig,
    benchmark: BenchmarkCollector,
) -> None:
    """Write benchmark.json and benchmark.md to the output directory.

    This is the last node in the DAG so it captures timing for every
    preceding stage including report_html. Failures are logged but do
    not propagate — benchmark reporting is non-critical.
    """
    from thresher.report.benchmarks import create_report

    output_dir = config.output_dir or staged_artifacts
    try:
        create_report(benchmark, output_dir, model=config.model)
    except Exception:
        logger.exception("Benchmark report generation failed — continuing without it")


# ── Pipeline Runner ─────────────────────────────────────────────────


def _build_driver() -> driver.Driver:
    """Build Hamilton driver from this module."""
    import thresher.harness.pipeline as pipeline_module

    return driver.Builder().with_modules(pipeline_module).build()


def run_pipeline(scan_config: ScanConfig) -> str:
    """Execute the full scan pipeline via Hamilton DAG."""
    dr = _build_driver()

    collector = BenchmarkCollector()
    collector.start()

    inputs = {
        "repo_url": scan_config.repo_url,
        "config": scan_config,
        "output_dir": "/opt/scan-results",
        "benchmark": collector,
    }

    logger.info("Executing pipeline DAG")
    result = dr.execute(
        final_vars=["report_html", "benchmark_report"],
        inputs=inputs,
    )

    report = result["report_html"]
    logger.info("Pipeline complete — report at %s", report)
    return report
