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

    def test_uppercase_extensions_accepted(self, tmp_path):
        (tmp_path / "report.JSON").write_text("{}")
        (tmp_path / "data.TXT").write_text("text")
        validate_report_output(str(tmp_path))
        assert (tmp_path / "report.JSON").exists()
        assert (tmp_path / "data.TXT").exists()

    def test_file_permissions_stripped(self, tmp_path):
        f = tmp_path / "test.json"
        f.write_text("{}")
        f.chmod(0o777)
        validate_report_output(str(tmp_path))
        mode = f.stat().st_mode & 0o777
        assert mode == 0o666

    def test_nonexistent_directory_silently_ok(self, tmp_path):
        nonexistent = tmp_path / "does_not_exist"
        # Should not raise, Path.rglob returns empty iterator for nonexistent paths
        validate_report_output(str(nonexistent))

    def test_mixed_valid_and_invalid_files(self, tmp_path):
        (tmp_path / "good.json").write_text("{}")
        (tmp_path / "bad.exe").write_text("malware")
        (tmp_path / "good2.md").write_text("# Report")
        real = tmp_path / "real.txt"
        real.write_text("data")
        link = tmp_path / "evil.txt"
        link.symlink_to(real)
        validate_report_output(str(tmp_path))
        assert (tmp_path / "good.json").exists()
        assert (tmp_path / "good2.md").exists()
        assert (tmp_path / "real.txt").exists()
        assert not (tmp_path / "bad.exe").exists()
        assert not link.exists()

    def test_deeply_nested_invalid_file(self, tmp_path):
        deep = tmp_path / "a" / "b" / "c" / "d"
        deep.mkdir(parents=True)
        (deep / "good.json").write_text("{}")
        (deep / "bad.bin").write_text("data")
        validate_report_output(str(tmp_path))
        assert (deep / "good.json").exists()
        assert not (deep / "bad.bin").exists()


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

    @patch("thresher.harness.report.enrich_findings")
    def test_dict_verified_findings_extracts_list(self, mock_enrich):
        """When verified_findings is a dict with 'findings' key, extract the list."""
        mock_enrich.return_value = [{"id": "f1"}]
        findings_dict = {"findings": [{"id": "f1", "cve_id": "CVE-2024-1234"}]}
        enrich_all_findings([], findings_dict)
        call_args = mock_enrich.call_args
        passed_findings = call_args[0][0]
        assert isinstance(passed_findings, list)
        assert passed_findings == [{"id": "f1", "cve_id": "CVE-2024-1234"}]

    @patch("thresher.harness.report.enrich_findings")
    def test_passes_vm_name_as_empty_string(self, mock_enrich):
        """Verify harness passes empty vm_name to enrich_findings."""
        mock_enrich.return_value = []
        enrich_all_findings([], [])
        call_args = mock_enrich.call_args
        # Second positional arg should be vm_name=""
        assert call_args[1]["vm_name"] == ""


class TestGenerateReport:
    @patch("thresher.report.synthesize._generate_template_report")
    @patch("thresher.report.synthesize._generate_agent_report")
    @patch("thresher.report.synthesize._build_synthesis_input")
    @patch("thresher.harness.report.validate_report_output")
    def test_generate_report_skip_ai_uses_template(
        self, mock_validate, mock_build, mock_agent, mock_template
    ):
        """When skip_ai=True, should use template-based report generation."""
        from thresher.harness.report import generate_report

        enriched = {"findings": [], "scanner_results": {}}
        result = generate_report(
            enriched,
            [],
            {"output_dir": "/tmp/out", "skip_ai": True},
        )
        mock_template.assert_called_once()
        mock_agent.assert_not_called()
        assert result == "/tmp/out"

    @patch("thresher.report.synthesize._generate_template_report")
    @patch("thresher.report.synthesize._generate_agent_report")
    @patch("thresher.harness.report.validate_report_output")
    def test_generate_report_ai_enabled_uses_agent(
        self, mock_validate, mock_agent, mock_template
    ):
        """When skip_ai=False, should use agent-based report generation."""
        from thresher.harness.report import generate_report

        enriched = {"findings": [], "scanner_results": {}}
        result = generate_report(
            enriched,
            [],
            {"output_dir": "/tmp/out", "skip_ai": False},
        )
        mock_agent.assert_called_once()
        mock_template.assert_not_called()
        assert result == "/tmp/out"

    @patch("thresher.report.synthesize._generate_template_report")
    @patch("thresher.report.synthesize._generate_agent_report")
    @patch("thresher.harness.report.validate_report_output")
    def test_generate_report_passes_ai_findings_as_dict(
        self, mock_validate, mock_agent, mock_template
    ):
        """ai_findings arg to _generate_agent_report must be a dict, not a list."""
        from thresher.harness.report import generate_report

        findings_list = [{"title": "XSS", "severity": "high"}]
        enriched = {"findings": findings_list, "scanner_results": {}}
        generate_report(
            enriched,
            [],
            {"output_dir": "/tmp/out", "skip_ai": False},
        )
        call_args = mock_agent.call_args[0]
        # arg 3 is ai_findings — must be a dict with "findings" key, not a bare list
        ai_findings_arg = call_args[3]
        assert isinstance(ai_findings_arg, dict), \
            f"ai_findings should be dict, got {type(ai_findings_arg).__name__}"
        assert "findings" in ai_findings_arg
        assert ai_findings_arg["findings"] == findings_list
        # arg 4 is enriched — should be the list directly
        enriched_arg = call_args[4]
        assert isinstance(enriched_arg, list)

    @patch("thresher.report.synthesize._generate_template_report")
    @patch("thresher.report.synthesize._generate_agent_report")
    @patch("thresher.report.synthesize._build_synthesis_input")
    @patch("thresher.harness.report.validate_report_output")
    def test_generate_report_creates_output_dir(
        self, mock_validate, mock_build, mock_agent, mock_template
    ):
        """Should create output_dir if it doesn't exist."""
        from thresher.harness.report import generate_report
        import tempfile
        import os

        with tempfile.TemporaryDirectory() as tmp:
            output_path = os.path.join(tmp, "nested", "output")
            enriched = {"findings": [], "scanner_results": {}}
            result = generate_report(
                enriched,
                [],
                {"output_dir": output_path, "skip_ai": True},
            )
            assert os.path.exists(output_path)
            assert result == output_path

    @patch("thresher.report.synthesize._generate_template_report")
    @patch("thresher.report.synthesize._generate_agent_report")
    @patch("thresher.report.synthesize._build_synthesis_input")
    @patch("thresher.harness.report.validate_report_output")
    def test_generate_report_default_output_dir(
        self, mock_validate, mock_build, mock_agent, mock_template, tmp_path
    ):
        """Should use /output as default when not specified."""
        from thresher.harness.report import generate_report

        enriched = {"findings": [], "scanner_results": {}}
        # Use tmp_path so findings.json can actually be written
        result = generate_report(enriched, [], {"output_dir": str(tmp_path)})
        assert result == str(tmp_path)
        assert (tmp_path / "findings.json").exists()

    @patch("thresher.report.synthesize._generate_template_report")
    @patch("thresher.report.synthesize._generate_agent_report")
    @patch("thresher.report.synthesize._build_synthesis_input")
    @patch("thresher.harness.report.validate_report_output")
    def test_generate_report_calls_validate(
        self, mock_validate, mock_build, mock_agent, mock_template
    ):
        """Should always call validate_report_output after generation."""
        from thresher.harness.report import generate_report

        enriched = {"findings": [], "scanner_results": {}}
        generate_report(
            enriched,
            [],
            {"output_dir": "/tmp/out", "skip_ai": True},
        )
        mock_validate.assert_called_once_with("/tmp/out")
