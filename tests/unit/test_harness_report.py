"""Unit tests for thresher.harness.report."""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from thresher.harness.report import (
    validate_report_output,
    enrich_all_findings,
    ALLOWED_EXTENSIONS,
)
from thresher.scanners.models import ScanResults


class TestValidateReportOutput:
    def test_rejects_symlinks(self, tmp_path):
        real = tmp_path / "real.json"
        real.write_text("{}")
        link = tmp_path / "evil.json"
        link.symlink_to(real)
        validate_report_output(str(tmp_path))
        assert not link.exists()
        assert real.exists()

    def test_rejects_invalid_extensions(self, tmp_path):
        (tmp_path / "findings.json").write_text("{}")
        (tmp_path / "evil.exe").write_text("bad")
        validate_report_output(str(tmp_path))
        assert (tmp_path / "findings.json").exists()
        assert not (tmp_path / "evil.exe").exists()

    def test_rejects_oversized_files(self, tmp_path):
        (tmp_path / "big.json").write_text("x" * 200)
        validate_report_output(str(tmp_path), max_file_bytes=100)
        assert not (tmp_path / "big.json").exists()

    def test_allowed_extensions(self):
        for ext in [".json", ".md", ".txt", ".csv", ".log", ".sarif", ".html"]:
            assert ext in ALLOWED_EXTENSIONS

    def test_keeps_valid_files(self, tmp_path):
        (tmp_path / "report.md").write_text("# Report")
        (tmp_path / "findings.json").write_text("{}")
        (tmp_path / "summary.txt").write_text("ok")
        validate_report_output(str(tmp_path))
        assert (tmp_path / "report.md").exists()
        assert (tmp_path / "findings.json").exists()
        assert (tmp_path / "summary.txt").exists()

    def test_handles_nested_directories(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "data.json").write_text("{}")
        (sub / "bad.sh").write_text("rm -rf /")
        validate_report_output(str(tmp_path))
        assert (sub / "data.json").exists()
        assert not (sub / "bad.sh").exists()

    def test_handles_empty_directory(self, tmp_path):
        # Should not raise
        validate_report_output(str(tmp_path))

    def test_file_at_size_limit_kept(self, tmp_path):
        content = "x" * 100
        (tmp_path / "exact.json").write_text(content)
        validate_report_output(str(tmp_path), max_file_bytes=100)
        assert (tmp_path / "exact.json").exists()

    def test_file_over_size_limit_removed(self, tmp_path):
        content = "x" * 101
        (tmp_path / "over.json").write_text(content)
        validate_report_output(str(tmp_path), max_file_bytes=100)
        assert not (tmp_path / "over.json").exists()


class TestEnrichAllFindings:
    @patch("thresher.harness.report.enrich_findings")
    def test_calls_enrichment(self, mock_enrich):
        mock_enrich.return_value = [{"id": "test", "composite_priority": "high"}]
        result = enrich_all_findings([], [])
        assert "findings" in result

    @patch("thresher.harness.report.enrich_findings")
    def test_returns_scanner_results_map(self, mock_enrich):
        mock_enrich.return_value = []
        sr = ScanResults(tool_name="grype", execution_time_seconds=1.0, exit_code=0)
        result = enrich_all_findings([sr], [])
        assert "scanner_results" in result
        assert "grype" in result["scanner_results"]

    @patch("thresher.harness.report.enrich_findings")
    def test_passes_verified_findings_to_enrichment(self, mock_enrich):
        mock_enrich.return_value = []
        findings = [{"id": "f1", "cve_id": "CVE-2024-1234"}]
        enrich_all_findings([], findings)
        mock_enrich.assert_called_once()
        call_args = mock_enrich.call_args
        passed_findings = call_args[0][0]
        assert passed_findings == findings

    @patch("thresher.harness.report.enrich_findings")
    def test_empty_inputs(self, mock_enrich):
        mock_enrich.return_value = []
        result = enrich_all_findings([], [])
        assert result["findings"] == []
        assert result["scanner_results"] == {}

    @patch("thresher.harness.report.enrich_findings")
    def test_none_verified_findings(self, mock_enrich):
        mock_enrich.return_value = []
        result = enrich_all_findings([], None)
        assert result["findings"] == []
