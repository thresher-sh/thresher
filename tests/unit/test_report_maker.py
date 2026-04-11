"""Tests for the report-maker agent runner."""

import json
from unittest.mock import patch, MagicMock

from thresher.config import ScanConfig


def _mock_popen(returncode=0, stdout=b""):
    mock = MagicMock()
    mock.stdout = iter(stdout.splitlines(keepends=True)) if stdout else iter([])
    mock.returncode = returncode
    mock.wait.return_value = returncode
    return mock


def _stream_bytes(report_data: dict) -> bytes:
    """Build stream-json output containing a result with report data."""
    lines = [
        json.dumps({"type": "assistant", "message": {"content": [{"text": "Working..."}]}}),
        json.dumps({"type": "result", "result": json.dumps(report_data)}),
    ]
    return "\n".join(lines).encode()


def _valid_report_data():
    return {
        "meta": {
            "scan_date": "2026-04-02", "thresher_version": "v0.2.2",
            "scanner_count": "22", "analyst_count": "8",
            "repo_name": "owner/repo", "repo_url": "https://github.com/owner/repo",
        },
        "verdict": {"label": "LOW RISK", "severity": "low", "callout": "No issues."},
        "counts": {
            "total_scanner": "0", "total_ai": "0", "p0": "0", "critical": "0",
            "high_scanner": "0", "high_ai": "0", "medium": "0", "low": "0",
        },
        "executive_summary": "<p>Clean.</p>",
        "mitigations": [],
        "scanner_findings": [],
        "ai_findings": [],
        "trust_signals": [],
        "dependency_upgrades": [],
        "remediation": None,
        "pipeline": {"scanners": ["grype"], "analysts": [], "notes": ""},
        "config": {"show_cta": "true", "show_remediation": "false"},
    }


@patch("thresher.run._popen")
def test_builds_correct_cmd(mock_popen):
    from thresher.agents.report_maker import run_report_maker

    mock_popen.return_value = _mock_popen(stdout=_stream_bytes(_valid_report_data()))
    config = ScanConfig(repo_url="https://github.com/owner/repo", model="sonnet")
    run_report_maker(config, "/tmp/output")

    cmd = mock_popen.call_args[0][0]
    assert cmd[0] == "claude"
    assert "--bare" not in cmd
    assert "--settings" in cmd
    assert "--output-format" in cmd
    assert "stream-json" in cmd
    assert "--verbose" in cmd


@patch("thresher.run._popen")
def test_parses_valid_output(mock_popen):
    from thresher.agents.report_maker import run_report_maker

    expected = _valid_report_data()
    mock_popen.return_value = _mock_popen(stdout=_stream_bytes(expected))
    config = ScanConfig(repo_url="https://github.com/owner/repo")
    result = run_report_maker(config, "/tmp/output")

    assert result is not None
    assert result["meta"]["repo_name"] == "owner/repo"
    assert result["verdict"]["severity"] == "low"


@patch("thresher.run._popen")
def test_returns_none_on_failure(mock_popen):
    from thresher.agents.report_maker import run_report_maker

    mock_popen.side_effect = RuntimeError("claude crashed")
    config = ScanConfig(repo_url="https://github.com/owner/repo")
    result = run_report_maker(config, "/tmp/output")

    assert result is None


@patch("thresher.run._popen")
def test_uses_custom_max_turns(mock_popen):
    from thresher.agents.report_maker import run_report_maker

    mock_popen.return_value = _mock_popen(stdout=_stream_bytes(_valid_report_data()))
    config = ScanConfig(
        repo_url="https://github.com/owner/repo",
        report_maker_max_turns=25,
    )
    run_report_maker(config, "/tmp/output")

    cmd = mock_popen.call_args[0][0]
    turns_idx = cmd.index("--max-turns") + 1
    assert cmd[turns_idx] == "25"


@patch("thresher.run._popen")
def test_cwd_defaults_to_output_dir(mock_popen, tmp_path):
    """Architectural change: report-maker now runs as a final formatter
    that consumes everything in the report output directory (synthesis
    markdown, per-analyst files, scanner JSONs). Its cwd must be the
    output dir, not /opt/scan-results."""
    from thresher.agents.report_maker import run_report_maker

    mock_popen.return_value = _mock_popen(stdout=_stream_bytes(_valid_report_data()))
    config = ScanConfig(repo_url="https://github.com/owner/repo")
    run_report_maker(config, str(tmp_path))

    kwargs = mock_popen.call_args[1]
    assert kwargs.get("cwd") == str(tmp_path), (
        f"report-maker cwd should be output_dir, got {kwargs.get('cwd')!r}"
    )
