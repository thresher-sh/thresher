import pytest
from unittest.mock import patch, MagicMock
from hamilton import driver
from thresher.harness import pipeline
from thresher.config import ScanConfig


def test_pipeline_module_has_required_functions():
    """Pipeline module defines all DAG node functions."""
    required = [
        "cloned_path", "ecosystems", "hidden_deps", "deps_path",
        "sbom_path", "scan_results", "analyst_findings",
        "verified_findings", "enriched_findings", "report_path",
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
    result = pipeline.hidden_deps(cloned_path="/opt/target", config=config)
    assert result == {}


def test_pipeline_skip_ai_analyst_findings():
    """When skip_ai=True, analyst_findings returns empty list."""
    config = ScanConfig(skip_ai=True)
    result = pipeline.analyst_findings(
        cloned_path="/opt/target", deps_path="/opt/deps",
        scan_results=[], config=config,
    )
    assert result == []


def test_pipeline_verified_findings_empty_input():
    """When analyst_findings is empty, verified_findings passes through."""
    config = ScanConfig(skip_ai=False)
    result = pipeline.verified_findings(
        analyst_findings=[], cloned_path="/opt/target", config=config,
    )
    assert result == []


def test_pipeline_verified_findings_unwraps_dict():
    """When adversarial returns {'findings': [...]}, verified_findings extracts the list."""
    config = ScanConfig(skip_ai=False)
    findings_list = [{"title": "CVE-2024-1234", "cve_id": "CVE-2024-1234"}]
    with patch("thresher.agents.adversarial.run_adversarial_verification",
               return_value={"findings": findings_list}):
        result = pipeline.verified_findings(
            analyst_findings=[{"title": "something"}],
            cloned_path="/opt/target",
            config=config,
        )
    assert result == findings_list


def test_pipeline_verified_findings_handles_none():
    """When adversarial returns None, verified_findings returns empty list."""
    config = ScanConfig(skip_ai=False)
    with patch("thresher.agents.adversarial.run_adversarial_verification",
               return_value=None):
        result = pipeline.verified_findings(
            analyst_findings=[{"title": "something"}],
            cloned_path="/opt/target",
            config=config,
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
        mock_dr.execute.return_value = {"report_path": str(tmp_path / "report")}
        mock_build.return_value = mock_dr
        pipeline.run_pipeline(config)
        mock_dr.execute.assert_called_once()
