"""Unit tests for thresher.harness.report."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from thresher.harness.benchmarks import BenchmarkCollector
from thresher.harness.report import (
    ALLOWED_EXTENSIONS,
    enrich_all_findings,
    validate_report_output,
)
from thresher.scanners.models import Finding, ScanResults


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
        # After P0 fix, AI findings get source_tool and category mapped
        assert len(passed_findings) == 1
        assert passed_findings[0]["id"] == "f1"
        assert passed_findings[0]["cve_id"] == "CVE-2024-1234"
        assert passed_findings[0]["source_tool"] == "ai_analysis"

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
        assert len(passed_findings) == 1
        assert passed_findings[0]["id"] == "f1"
        assert passed_findings[0]["source_tool"] == "ai_analysis"

    @patch("thresher.harness.report.enrich_findings")
    def test_passes_vm_name_as_empty_string(self, mock_enrich):
        """Verify harness passes empty vm_name to enrich_findings."""
        mock_enrich.return_value = []
        enrich_all_findings([], [])
        call_args = mock_enrich.call_args
        # Second positional arg should be vm_name=""
        assert call_args[1]["vm_name"] == ""

    @patch("thresher.harness.report.enrich_findings")
    def test_includes_scanner_findings(self, mock_enrich):
        """Scanner findings from ScanResults should be merged into enrichment."""
        mock_enrich.return_value = []
        scanner_finding = Finding(
            id="grype-CVE-2024-1234",
            source_tool="grype",
            category="sca",
            severity="high",
            cvss_score=8.1,
            cve_id="CVE-2024-1234",
            title="Test vuln",
            description="desc",
            file_path=None,
            line_number=None,
            package_name="requests",
            package_version="2.25.0",
            fix_version="2.32.0",
            raw_output={},
        )
        sr = ScanResults(
            tool_name="grype",
            execution_time_seconds=5.0,
            exit_code=0,
            findings=[scanner_finding],
        )
        ai_findings = [{"title": "AI finding", "source_tool": "ai_analysis"}]
        enrich_all_findings([sr], ai_findings)
        passed = mock_enrich.call_args[0][0]
        sources = [f.get("source_tool") for f in passed]
        assert "grype" in sources
        assert "ai_analysis" in sources
        assert len(passed) == 2

    @patch("thresher.harness.report.enrich_findings")
    def test_maps_risk_score_to_ai_risk_score(self, mock_enrich):
        """AI findings with risk_score should get ai_risk_score mapped."""
        mock_enrich.return_value = []
        findings = [{"risk_score": 8, "title": "backdoor"}]
        enrich_all_findings([], findings)
        passed = mock_enrich.call_args[0][0]
        assert passed[0]["ai_risk_score"] == 8

    @patch("thresher.harness.report.enrich_findings")
    def test_does_not_overwrite_existing_ai_risk_score(self, mock_enrich):
        """If ai_risk_score is already set, risk_score should not overwrite it."""
        mock_enrich.return_value = []
        findings = [{"risk_score": 8, "ai_risk_score": 5}]
        enrich_all_findings([], findings)
        passed = mock_enrich.call_args[0][0]
        assert passed[0]["ai_risk_score"] == 5

    @patch("thresher.harness.report.enrich_findings")
    def test_sets_source_tool_on_ai_findings(self, mock_enrich):
        """AI findings must get source_tool='ai_analysis' for downstream filtering."""
        mock_enrich.return_value = []
        findings = [{"title": "suspicious eval"}]
        enrich_all_findings([], findings)
        passed = mock_enrich.call_args[0][0]
        assert passed[0]["source_tool"] == "ai_analysis"

    @patch("thresher.harness.report.enrich_findings")
    def test_sets_category_on_ai_findings(self, mock_enrich):
        """AI findings must get category='ai_analysis' as default."""
        mock_enrich.return_value = []
        findings = [{"title": "suspicious eval"}]
        enrich_all_findings([], findings)
        passed = mock_enrich.call_args[0][0]
        assert passed[0]["category"] == "ai_analysis"

    @patch("thresher.harness.report.enrich_findings")
    def test_derives_ai_confidence_from_sub_findings(self, mock_enrich):
        """ai_confidence should be derived from max sub-finding confidence."""
        mock_enrich.return_value = []
        findings = [
            {
                "risk_score": 7,
                "findings": [
                    {"confidence": 85, "severity": "high"},
                    {"confidence": 92, "severity": "medium"},
                ],
            }
        ]
        enrich_all_findings([], findings)
        passed = mock_enrich.call_args[0][0]
        assert passed[0]["ai_confidence"] == 92

    @patch("thresher.harness.report.enrich_findings")
    def test_derives_severity_from_worst_sub_finding(self, mock_enrich):
        """Severity should be derived from worst sub-finding severity."""
        mock_enrich.return_value = []
        findings = [
            {
                "risk_score": 7,
                "findings": [
                    {"severity": "medium", "confidence": 80},
                    {"severity": "high", "confidence": 70},
                    {"severity": "low", "confidence": 90},
                ],
            }
        ]
        enrich_all_findings([], findings)
        passed = mock_enrich.call_args[0][0]
        assert passed[0]["severity"] == "high"

    @patch("thresher.harness.report.enrich_findings")
    def test_defaults_severity_to_low_without_sub_findings(self, mock_enrich):
        """Without sub-findings, severity should default to 'low'."""
        mock_enrich.return_value = []
        findings = [{"risk_score": 3}]
        enrich_all_findings([], findings)
        passed = mock_enrich.call_args[0][0]
        assert passed[0]["severity"] == "low"

    def test_composite_priority_reflects_ai_risk_score(self):
        """End-to-end: high risk_score AI finding should NOT get 'low' composite_priority."""
        findings = [{"risk_score": 8, "title": "backdoor detected"}]
        with (
            patch("thresher.report.scoring.fetch_epss_scores", return_value={}),
            patch("thresher.report.scoring.load_kev_catalog", return_value=set()),
        ):
            result = enrich_all_findings([], findings)
        enriched = result["findings"]
        assert len(enriched) == 1
        assert enriched[0]["ai_risk_score"] == 8
        assert enriched[0]["composite_priority"] == "high"

    def test_composite_priority_critical_for_confirmed_high_risk(self):
        """End-to-end: risk_score 9 + confirmed should yield 'critical'."""
        findings = [
            {
                "risk_score": 9,
                "adversarial_status": "confirmed",
                "title": "data exfiltration",
            }
        ]
        with (
            patch("thresher.report.scoring.fetch_epss_scores", return_value={}),
            patch("thresher.report.scoring.load_kev_catalog", return_value=set()),
        ):
            result = enrich_all_findings([], findings)
        assert result["findings"][0]["composite_priority"] == "critical"


class TestStageArtifacts:
    """stage_artifacts writes per-analyst markdown + JSON, copies scanner
    outputs, and copies dep_resolution.json into the report dir BEFORE
    the report-maker runs."""

    def test_writes_per_analyst_markdown(self, tmp_path):
        from thresher.config import ScanConfig
        from thresher.harness.report import stage_artifacts

        config = ScanConfig(output_dir=str(tmp_path), skip_ai=True)
        analyst_data = [
            {
                "analyst": "paranoid",
                "analyst_number": 1,
                "core_question": "Is this safe?",
                "files_analyzed": 12,
                "findings": [
                    {
                        "title": "suspicious eval",
                        "severity": "high",
                        "confidence": 80,
                        "file_path": "/opt/target/app.py",
                        "line_numbers": [42],
                        "description": "Found eval call",
                        "evidence": "eval(user_input)",
                        "reasoning": "RCE",
                        "recommendation": "Remove eval",
                    }
                ],
                "summary": "one issue",
                "risk_score": 7,
            },
        ]
        stage_artifacts(
            {"findings": []},
            config,
            analyst_findings=analyst_data,
            scan_results_source=str(tmp_path / "missing_scan_src"),
            deps_source=str(tmp_path / "missing_deps_src"),
        )
        md_path = tmp_path / "scan-results" / "analyst-01-paranoid.md"
        assert md_path.exists(), "per-analyst markdown not written"
        body = md_path.read_text()
        assert "# Analyst 1" in body
        assert "suspicious eval" in body
        assert "app.py" in body

    def test_no_markdown_when_no_analysts(self, tmp_path):
        from thresher.config import ScanConfig
        from thresher.harness.report import stage_artifacts

        config = ScanConfig(output_dir=str(tmp_path), skip_ai=True)
        stage_artifacts(
            {"findings": []},
            config,
            analyst_findings=None,
            scan_results_source=str(tmp_path / "missing"),
            deps_source=str(tmp_path / "missing2"),
        )
        sr = tmp_path / "scan-results"
        md_files = list(sr.glob("analyst-*.md")) if sr.exists() else []
        assert md_files == []

    def test_copies_dep_resolution_json(self, tmp_path):
        """The dep_resolution.json status file must end up alongside the
        scanner outputs so the report-maker can read it from one place."""
        from thresher.config import ScanConfig
        from thresher.harness.report import stage_artifacts

        deps_src = tmp_path / "deps"
        deps_src.mkdir()
        (deps_src / "dep_resolution.json").write_text(
            json.dumps(
                {
                    "ecosystems": {"python": {"status": "failed", "reason": "x"}},
                }
            )
        )

        config = ScanConfig(output_dir=str(tmp_path / "out"), skip_ai=True)
        stage_artifacts(
            {"findings": []},
            config,
            analyst_findings=None,
            scan_results_source=str(tmp_path / "missing_scan"),
            deps_source=str(deps_src),
        )
        copied = tmp_path / "out" / "scan-results" / "dep_resolution.json"
        assert copied.exists()
        loaded = json.loads(copied.read_text())
        assert loaded["ecosystems"]["python"]["status"] == "failed"

    def test_writes_findings_json(self, tmp_path):
        from thresher.config import ScanConfig
        from thresher.harness.report import stage_artifacts

        config = ScanConfig(output_dir=str(tmp_path), skip_ai=True)
        stage_artifacts(
            {"findings": [{"id": "x", "severity": "high"}]},
            config,
            analyst_findings=None,
            scan_results_source=str(tmp_path / "missing"),
            deps_source=str(tmp_path / "missing2"),
        )
        f = tmp_path / "findings.json"
        assert f.exists()
        loaded = json.loads(f.read_text())
        assert loaded[0]["severity"] == "high"


class TestValidateReportData:
    """validate_report_data flags missing required keys."""

    def test_complete_report_returns_empty_set(self):
        from thresher.harness.report import validate_report_data

        report = {
            "meta": {},
            "verdict": {},
            "counts": {},
            "executive_summary": "",
            "scanner_findings": [],
            "ai_findings": [],
            "pipeline": {},
        }
        assert validate_report_data(report) == set()

    def test_missing_keys_returned(self):
        from thresher.harness.report import validate_report_data

        report = {"executive_summary": "x", "ai_findings": []}
        missing = validate_report_data(report)
        assert "meta" in missing
        assert "verdict" in missing
        assert "counts" in missing
        assert "scanner_findings" in missing
        assert "pipeline" in missing
        # Present keys should NOT be reported
        assert "executive_summary" not in missing
        assert "ai_findings" not in missing

    def test_non_dict_input_returns_all_keys(self):
        from thresher.harness.report import (
            _REQUIRED_REPORT_DATA_KEYS,
            validate_report_data,
        )

        assert validate_report_data(None) == set(_REQUIRED_REPORT_DATA_KEYS)
        assert validate_report_data("not a dict") == set(_REQUIRED_REPORT_DATA_KEYS)
        assert validate_report_data([]) == set(_REQUIRED_REPORT_DATA_KEYS)

    def test_pipeline_falls_back_when_report_maker_returns_partial_data(self, tmp_path):
        """Regression for the inspection report C1: report_maker hits
        error_max_turns and returns a dict missing required keys. The
        pipeline must reject it and use build_fallback_report_data."""
        from thresher.config import ScanConfig
        from thresher.harness import pipeline

        config = ScanConfig(
            repo_url="https://github.com/x/y",
            anthropic_api_key="sk-ant-test",
            output_dir=str(tmp_path),
        )
        # Simulate report_maker emitting a fragment that's missing required
        # top-level keys (verdict, counts, pipeline) — exactly what happens
        # on error_max_turns.
        partial = {
            "executive_summary": "<p>truncated mid-thought</p>",
            "mitigations": [],
            "scanner_findings": [],
            "ai_findings": [],
        }
        with patch("thresher.agents.report_maker.run_report_maker", return_value=partial):
            result = pipeline.report_data(
                staged_artifacts=str(tmp_path),
                enriched_findings={"findings": [], "scanner_results": {}},
                scan_results=[],
                analyst_findings=[],
                synthesized_reports=True,
                config=config,
                benchmark=BenchmarkCollector(),
            )
        # Fallback report has every required key
        from thresher.harness.report import validate_report_data

        assert validate_report_data(result) == set()
        # And it must NOT be the partial dict
        assert "verdict" in result
        assert "counts" in result
        assert "pipeline" in result

    def test_pipeline_uses_report_maker_when_complete(self, tmp_path):
        """When report_maker returns a complete dict, pipeline passes it through."""
        from thresher.config import ScanConfig
        from thresher.harness import pipeline

        config = ScanConfig(
            repo_url="https://github.com/x/y",
            anthropic_api_key="sk-ant-test",
            output_dir=str(tmp_path),
        )
        complete = {
            "meta": {"scan_date": "2026-04-10", "repo_name": "x/y"},
            "verdict": {"label": "OK", "severity": "low", "callout": "fine"},
            "counts": {"critical": "0"},
            "executive_summary": "<p>clean</p>",
            "scanner_findings": [],
            "ai_findings": [],
            "pipeline": {"scanners": [], "analysts": [], "notes": ""},
        }
        with patch("thresher.agents.report_maker.run_report_maker", return_value=complete):
            result = pipeline.report_data(
                staged_artifacts=str(tmp_path),
                enriched_findings={"findings": [], "scanner_results": {}},
                scan_results=[],
                analyst_findings=[],
                synthesized_reports=True,
                config=config,
                benchmark=BenchmarkCollector(),
            )
        assert result is complete


class TestDepResolutionNotes:
    """summarize_dep_resolution turns the deps_dir/dep_resolution.json
    status file into a human-readable notes string for pipeline.notes."""

    def test_returns_empty_string_when_file_missing(self, tmp_path):
        from thresher.harness.report import summarize_dep_resolution

        assert summarize_dep_resolution(str(tmp_path)) == ""

    def test_summarizes_failures(self, tmp_path):
        from thresher.harness.report import summarize_dep_resolution

        (tmp_path / "dep_resolution.json").write_text(
            json.dumps(
                {
                    "ecosystems": {
                        "python": {"status": "failed", "reason": "pip3 download exited 1"},
                        "node": {"status": "ok", "reason": ""},
                    },
                }
            )
        )
        notes = summarize_dep_resolution(str(tmp_path))
        assert "python" in notes
        assert "failed" in notes
        # Successful ecosystems should not be mentioned in failure notes
        assert "node" not in notes or notes.lower().count("node") == 0

    def test_no_notes_when_all_ok(self, tmp_path):
        from thresher.harness.report import summarize_dep_resolution

        (tmp_path / "dep_resolution.json").write_text(
            json.dumps(
                {
                    "ecosystems": {"python": {"status": "ok", "reason": ""}},
                }
            )
        )
        assert summarize_dep_resolution(str(tmp_path)) == ""

    def test_pipeline_inserts_notes_into_report_data(self, tmp_path):
        """The report_data DAG node must surface dep failures in
        pipeline.notes when they exist."""
        from thresher.config import ScanConfig
        from thresher.harness import pipeline

        # Stand up a fake deps dir with a failure status file
        deps_dir = tmp_path / "deps"
        deps_dir.mkdir()
        (deps_dir / "dep_resolution.json").write_text(
            json.dumps(
                {
                    "ecosystems": {
                        "python": {"status": "failed", "reason": "Multiple top-level packages"},
                    },
                }
            )
        )

        config = ScanConfig(
            repo_url="https://github.com/x/y",
            anthropic_api_key="sk-ant-test",
            output_dir=str(tmp_path),
        )
        complete = {
            "meta": {"scan_date": "2026-04-10", "repo_name": "x/y"},
            "verdict": {"label": "OK", "severity": "low", "callout": "fine"},
            "counts": {"critical": "0"},
            "executive_summary": "<p>clean</p>",
            "scanner_findings": [],
            "ai_findings": [],
            "pipeline": {"scanners": [], "analysts": [], "notes": ""},
        }

        with (
            patch("thresher.agents.report_maker.run_report_maker", return_value=complete),
            patch("thresher.harness.report._dep_resolution_dir", return_value=str(deps_dir)),
        ):
            result = pipeline.report_data(
                staged_artifacts=str(tmp_path),
                enriched_findings={"findings": [], "scanner_results": {}},
                scan_results=[],
                analyst_findings=[],
                synthesized_reports=True,
                config=config,
                benchmark=BenchmarkCollector(),
            )
        notes = result.get("pipeline", {}).get("notes", "")
        assert "python" in notes.lower()
        assert "failed" in notes.lower()


class TestRenderReportPersistsJson:
    """render_report persists the report_data dict next to report.html."""

    def test_writes_report_data_json(self, tmp_path):
        from thresher.harness.report import render_report

        report_data = {
            "meta": {"scan_date": "2026-04-10", "repo_name": "x/y"},
            "verdict": {"label": "LOW RISK", "severity": "low", "callout": "ok"},
            "counts": {"critical": "0", "high_scanner": "0"},
        }

        # Patch jinja loader to return a stub template
        with patch("thresher.harness.report.Path") as _:
            pass  # placeholder so the import path is used

        # Use the real render_report but with an explicit template_dir that
        # points at the project's actual template.
        templates = Path(__file__).parent.parent.parent / "src" / "thresher" / "report" / "templates"
        if not (templates / "template_report.html").exists():
            pytest.skip("template_report.html not found in repo")

        render_report(report_data, str(tmp_path), template_dir=str(templates))

        json_path = tmp_path / "report_data.json"
        assert json_path.exists(), "report_data.json was not persisted"
        loaded = json.loads(json_path.read_text())
        assert loaded["meta"]["repo_name"] == "x/y"
        assert loaded["verdict"]["label"] == "LOW RISK"
