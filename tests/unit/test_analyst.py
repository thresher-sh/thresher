"""Tests for threat_scanner.agents.analyst."""

from __future__ import annotations

import json

from threat_scanner.agents.analyst import (
    _build_analyst_prompt,
    _empty_findings,
    _extract_flagged_paths,
    _extract_json_from_text,
    _format_scanner_summary,
    _limit_init_files,
    _parse_agent_json_output,
    MAX_INIT_FILES,
)
from threat_scanner.agents.prompts import ANALYST_SYSTEM_PROMPT


class TestExtractFlaggedPaths:
    def test_basic(self):
        results = {
            "grype": [{"file_path": "/a.py"}, {"file_path": "/b.py"}],
            "semgrep": [{"file_path": "/c.py"}],
        }
        paths = _extract_flagged_paths(results)
        assert paths == {"/a.py", "/b.py", "/c.py"}

    def test_ignores_none(self):
        results = {
            "grype": [{"file_path": None}, {"file_path": ""}, {}],
        }
        paths = _extract_flagged_paths(results)
        assert paths == set()

    def test_non_dict_input(self):
        assert _extract_flagged_paths("not a dict") == set()
        assert _extract_flagged_paths([]) == set()

    def test_skips_non_list_values(self):
        results = {"meta": {"version": "1.0"}, "grype": [{"file_path": "/a.py"}]}
        paths = _extract_flagged_paths(results)
        assert paths == {"/a.py"}


class TestLimitInitFiles:
    def test_under_limit(self):
        paths = {"/a/__init__.py", "/b/__init__.py", "/c/foo.py"}
        result = _limit_init_files(paths)
        assert result == paths

    def test_over_limit(self):
        inits = {f"/pkg{i}/__init__.py" for i in range(MAX_INIT_FILES + 10)}
        others = {"/x.py", "/y.py"}
        result = _limit_init_files(inits | others)
        init_count = sum(1 for p in result if p.endswith("__init__.py"))
        assert init_count == MAX_INIT_FILES
        assert "/x.py" in result
        assert "/y.py" in result

    def test_preserves_non_init(self):
        paths = {"/a/foo.py", "/b/bar.py"}
        result = _limit_init_files(paths)
        assert result == paths


class TestFormatScannerSummary:
    def test_basic_format(self):
        results = {
            "grype": [
                {"severity": "critical", "title": "CVE-2024-1", "file_path": "/a.py",
                 "cve_id": "CVE-2024-1", "line_number": None},
            ],
            "semgrep": [],
        }
        text = _format_scanner_summary(results)
        assert "grype" in text
        assert "1 finding" in text
        assert "semgrep" in text
        assert "No findings" in text

    def test_non_dict(self):
        text = _format_scanner_summary("not a dict")
        assert "No scanner results" in text


class TestBuildAnalystPrompt:
    def test_contains_system_prompt(self):
        prompt = _build_analyst_prompt({}, ["/a.py"])
        assert ANALYST_SYSTEM_PROMPT in prompt

    def test_contains_files(self):
        files = ["/opt/target/setup.py", "/opt/target/src/main.py"]
        prompt = _build_analyst_prompt({}, files)
        for f in files:
            assert f in prompt

    def test_contains_file_count(self):
        files = ["/a.py", "/b.py", "/c.py"]
        prompt = _build_analyst_prompt({}, files)
        assert "Total files: 3" in prompt


class TestParseAgentJsonOutput:
    def test_clean_json(self, analyst_clean_fixture):
        result = _parse_agent_json_output(json.dumps(analyst_clean_fixture))
        assert result["files_analyzed"] == 15
        assert len(result["findings"]) == 2

    def test_envelope(self, analyst_envelope_fixture):
        result = _parse_agent_json_output(json.dumps(analyst_envelope_fixture))
        assert "findings" in result
        assert len(result["findings"]) == 1

    def test_codeblock(self, analyst_codeblock_fixture):
        result = _parse_agent_json_output(analyst_codeblock_fixture)
        assert result["files_analyzed"] == 5
        assert result["findings"] == []

    def test_empty(self):
        result = _parse_agent_json_output("")
        assert "error" in result

    def test_plain_text_fallback(self):
        result = _parse_agent_json_output("no json here at all")
        assert "error" in result


class TestEmptyFindings:
    def test_structure(self):
        result = _empty_findings("test reason")
        assert result["analysis_summary"] == "test reason"
        assert result["files_analyzed"] == 0
        assert result["high_risk_count"] == 0
        assert result["findings"] == []
        assert result["error"] == "test reason"
