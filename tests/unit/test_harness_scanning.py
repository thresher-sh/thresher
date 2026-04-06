"""Unit tests for thresher.harness.scanning."""

import pytest
from unittest.mock import patch, MagicMock
from thresher.harness.scanning import run_all_scanners
from thresher.scanners.models import ScanResults


@patch("thresher.harness.scanning._get_scanner_tasks")
def test_run_all_scanners_returns_results(mock_tasks):
    mock_tasks.return_value = [
        (
            "grype",
            lambda **kw: ScanResults(
                tool_name="grype", execution_time_seconds=1.0, exit_code=0
            ),
        ),
    ]
    results = run_all_scanners(
        sbom_path="/x",
        target_dir="/x",
        deps_dir="/x",
        output_dir="/x",
        config={},
    )
    assert len(results) == 1
    assert results[0].tool_name == "grype"


@patch("thresher.harness.scanning._get_scanner_tasks")
def test_run_all_scanners_handles_failure(mock_tasks):
    def failing_scanner(**kwargs):
        raise RuntimeError("scanner exploded")

    mock_tasks.return_value = [
        ("broken", failing_scanner),
        (
            "working",
            lambda **kw: ScanResults(
                tool_name="working", execution_time_seconds=0.5, exit_code=0
            ),
        ),
    ]
    results = run_all_scanners(
        sbom_path="/x",
        target_dir="/x",
        deps_dir="/x",
        output_dir="/x",
        config={},
    )
    assert len(results) == 2
    broken = [r for r in results if r.tool_name == "broken"][0]
    assert broken.exit_code == -1


@patch("thresher.harness.scanning._get_scanner_tasks")
def test_run_all_scanners_empty_tasks(mock_tasks):
    mock_tasks.return_value = []
    results = run_all_scanners(
        sbom_path="/x",
        target_dir="/x",
        deps_dir="/x",
        output_dir="/x",
        config={},
    )
    assert results == []


@patch("thresher.harness.scanning._get_scanner_tasks")
def test_run_all_scanners_failure_error_message(mock_tasks):
    def failing_scanner(**kwargs):
        raise ValueError("bad input")

    mock_tasks.return_value = [("bad", failing_scanner)]
    results = run_all_scanners(
        sbom_path="/x",
        target_dir="/x",
        deps_dir="/x",
        output_dir="/x",
        config={},
    )
    assert len(results) == 1
    assert results[0].exit_code == -1
    assert "bad input" in results[0].errors[0]


@patch("thresher.harness.scanning._get_scanner_tasks")
def test_run_all_scanners_multiple_results(mock_tasks):
    names = ["grype", "osv", "semgrep"]
    mock_tasks.return_value = [
        (
            name,
            (lambda n: lambda **kw: ScanResults(
                tool_name=n, execution_time_seconds=0.1, exit_code=0
            ))(name),
        )
        for name in names
    ]
    results = run_all_scanners(
        sbom_path="/x",
        target_dir="/x",
        deps_dir="/x",
        output_dir="/x",
        config={},
    )
    assert len(results) == 3
    result_names = {r.tool_name for r in results}
    assert result_names == set(names)
