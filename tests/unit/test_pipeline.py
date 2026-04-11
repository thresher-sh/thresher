from unittest.mock import MagicMock, patch

from hamilton import driver

from thresher.config import ScanConfig
from thresher.harness import pipeline
from thresher.harness.benchmarks import BenchmarkCollector


def _collector() -> BenchmarkCollector:
    c = BenchmarkCollector()
    c.start()
    return c


def test_pipeline_module_has_required_functions():
    """Pipeline module defines all DAG node functions."""
    required = [
        "cloned_path",
        "ecosystems",
        "hidden_deps",
        "deps_path",
        "sbom_path",
        "scan_results",
        "analyst_findings",
        "verified_findings",
        "enriched_findings",
        "report_data",
        "synthesized_reports",
        "report_html",
        "benchmark_report",
    ]
    for name in required:
        assert hasattr(pipeline, name), f"Missing DAG node: {name}"


def test_pipeline_dag_builds():
    """Hamilton driver can build a DAG from the pipeline module."""
    dr = driver.Builder().with_modules(pipeline).build()
    assert dr is not None


def test_pipeline_skip_ai_short_circuits():
    """When skip_ai=True, AI stages return empty results."""
    config = ScanConfig(skip_ai=True, high_risk_dep=False)
    result = pipeline.hidden_deps(cloned_path="/opt/target", config=config, benchmark=_collector())
    assert result == {}


def test_pipeline_skip_ai_analyst_findings():
    """When skip_ai=True, analyst_findings returns empty list."""
    config = ScanConfig(skip_ai=True)
    result = pipeline.analyst_findings(
        cloned_path="/opt/target",
        deps_path="/opt/deps",
        scan_results=[],
        config=config,
        benchmark=_collector(),
    )
    assert result == []


def test_pipeline_verified_findings_empty_input():
    """When analyst_findings is empty, verified_findings passes through."""
    config = ScanConfig(skip_ai=False)
    result = pipeline.verified_findings(
        analyst_findings=[],
        cloned_path="/opt/target",
        config=config,
        benchmark=_collector(),
    )
    assert result == []


def test_pipeline_verified_findings_unwraps_dict():
    """When adversarial returns {'findings': [...]}, verified_findings extracts the list."""
    config = ScanConfig(skip_ai=False)
    findings_list = [{"title": "CVE-2024-1234", "cve_id": "CVE-2024-1234"}]
    with patch("thresher.agents.adversarial.run_adversarial_verification", return_value={"findings": findings_list}):
        result = pipeline.verified_findings(
            analyst_findings=[{"title": "something"}],
            cloned_path="/opt/target",
            config=config,
            benchmark=_collector(),
        )
    assert result == findings_list


def test_pipeline_verified_findings_handles_none():
    """When adversarial returns None, verified_findings returns empty list."""
    config = ScanConfig(skip_ai=False)
    with patch("thresher.agents.adversarial.run_adversarial_verification", return_value=None):
        result = pipeline.verified_findings(
            analyst_findings=[{"title": "something"}],
            cloned_path="/opt/target",
            config=config,
            benchmark=_collector(),
        )
    assert result == []


def test_run_pipeline_calls_hamilton_execute(tmp_path):
    """run_pipeline builds and executes the Hamilton DAG."""
    config = ScanConfig(
        repo_url="https://github.com/test/repo",
        output_dir=str(tmp_path),
        skip_ai=True,
    )
    with patch("thresher.harness.pipeline._build_driver") as mock_build:
        mock_dr = MagicMock()
        mock_dr.execute.return_value = {
            "report_html": str(tmp_path / "report"),
            "benchmark_report": None,
        }
        mock_build.return_value = mock_dr
        pipeline.run_pipeline(config)
        mock_dr.execute.assert_called_once()


def test_synthesized_reports_skip_ai_returns_false():
    """When skip_ai=True, synthesized_reports short-circuits."""
    config = ScanConfig(skip_ai=True)
    result = pipeline.synthesized_reports(
        verified_findings=[],
        enriched_findings={"findings": [], "scanner_results": {}},
        scan_results=[],
        config=config,
        benchmark=_collector(),
    )
    assert result is False


def test_synthesized_reports_invokes_agent():
    """When AI is enabled, synthesized_reports calls run_synthesize_agent."""
    config = ScanConfig(
        skip_ai=False,
        anthropic_api_key="sk-ant-test",
        output_dir="/tmp/test-output",
    )
    enriched = {"findings": [{"title": "x", "severity": "high"}], "scanner_results": {}}
    with patch(
        "thresher.agents.synthesize.run_synthesize_agent",
        return_value=(True, {"duration": 10.0, "turns": 5, "token_usage": {}}),
    ) as mock_agent:
        result = pipeline.synthesized_reports(
            verified_findings=[],
            enriched_findings=enriched,
            scan_results=[],
            config=config,
            benchmark=_collector(),
        )
    mock_agent.assert_called_once()
    assert result is True


def test_dag_orders_synthesize_before_report_data():
    """Architectural contract: synthesize is the judge, report-maker is
    the formatter that reads its output. The DAG MUST run synthesize
    before report_data, and report_data MUST list synthesized_reports as
    a parameter so Hamilton enforces the ordering."""
    import inspect

    sig = inspect.signature(pipeline.report_data)
    params = list(sig.parameters.keys())
    assert "synthesized_reports" in params, (
        f"report_data must depend on synthesized_reports for DAG ordering; current params: {params}"
    )


def test_dag_orders_stage_artifacts_before_report_data():
    """report-maker reads scanner outputs, per-analyst files, and synthesis
    markdown from the report directory. Those have to be staged there
    BEFORE report-maker runs."""
    import inspect

    assert hasattr(pipeline, "staged_artifacts"), (
        "pipeline must define a staged_artifacts node that copies "
        "scanner + per-analyst outputs into output_dir before report-maker"
    )
    sig = inspect.signature(pipeline.report_data)
    assert "staged_artifacts" in sig.parameters, (
        "report_data must depend on staged_artifacts so the DAG enforces ordering"
    )
