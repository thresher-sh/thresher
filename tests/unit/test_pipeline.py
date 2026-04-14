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


def test_benchmark_report_does_not_raise_on_failure(tmp_path):
    """benchmark_report is a non-critical reporting step. If it fails
    (e.g. missing costs file), it must not crash the entire DAG."""
    config = ScanConfig(output_dir=str(tmp_path))
    collector = _collector()
    with patch("thresher.report.benchmarks.create_report", side_effect=FileNotFoundError("costs_claude.json")):
        result = pipeline.benchmark_report(
            report_html=str(tmp_path / "report.html"),
            staged_artifacts=str(tmp_path),
            config=config,
            benchmark=collector,
        )
    assert result is None


def test_analyst_findings_strips_timing_metadata():
    """_timing should be stripped from findings after benchmark aggregation.

    Regression test: _timing was leaking into user-facing report JSON because
    analysts.py changed from .pop() to .get(). The pipeline should strip it.
    """
    config = ScanConfig(skip_ai=False)
    mock_findings = [
        {
            "analyst": "paranoid",
            "findings": [{"title": "test"}],
            "summary": "test",
            "risk_score": 5,
            "_timing": {"name": "paranoid", "duration": 1.0, "turns": 2, "token_usage": {"input_tokens": 100}},
        }
    ]
    with patch("thresher.agents.analysts.run_all_analysts", return_value=mock_findings):
        result = pipeline.analyst_findings(
            cloned_path="/opt/target",
            deps_path="/opt/deps",
            scan_results=[],
            config=config,
            benchmark=_collector(),
        )
    assert len(result) == 1
    assert "_timing" not in result[0], "_timing should be stripped after benchmark aggregation"


def test_analyst_findings_records_individual_benchmark_stages():
    config = ScanConfig(skip_ai=False)
    collector = _collector()
    mock_findings = [
        {
            "analyst": "paranoid",
            "analyst_number": 1,
            "findings": [{"title": "a"}, {"title": "b"}],
            "summary": "test",
            "risk_score": 5,
            "_timing": {
                "name": "paranoid",
                "duration": 1.0,
                "turns": 2,
                "token_usage": {"input_tokens": 100},
                "model_usage": {
                    "claude-sonnet-4-6": {
                        "input_tokens": 100,
                        "output_tokens": 0,
                        "cache_creation_input_tokens": 0,
                        "cache_read_input_tokens": 0,
                    }
                },
            },
        },
        {
            "analyst": "behaviorist",
            "analyst_number": 2,
            "findings": [{"title": "c"}],
            "summary": "test",
            "risk_score": 3,
            "_timing": {
                "name": "behaviorist",
                "duration": 2.0,
                "turns": 4,
                "token_usage": {"input_tokens": 200},
                "model_usage": {
                    "claude-haiku-4-5-20251001": {
                        "input_tokens": 200,
                        "output_tokens": 0,
                        "cache_creation_input_tokens": 0,
                        "cache_read_input_tokens": 0,
                    }
                },
            },
        },
    ]
    with patch("thresher.agents.analysts.run_all_analysts", return_value=mock_findings):
        pipeline.analyst_findings(
            cloned_path="/opt/target",
            deps_path="/opt/deps",
            scan_results=[],
            config=config,
            benchmark=collector,
        )

    analyst_rows = [stage for stage in collector.stages if stage.name.startswith("analyst-")]
    assert [stage.name for stage in analyst_rows] == [
        "analyst-01-paranoid",
        "analyst-02-behaviorist",
    ]
    assert analyst_rows[0].metadata["turns"] == 2
    assert analyst_rows[1].metadata["turns"] == 4

    aggregate = next(stage for stage in collector.stages if stage.name == "analysts")
    assert aggregate.findings_count == 3
    assert aggregate.metadata["stage_kind"] == "analyst_parallel_block"
