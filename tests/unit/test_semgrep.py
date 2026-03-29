"""Tests for threat_scanner.scanners.semgrep."""

from __future__ import annotations

from threat_scanner.scanners.semgrep import parse_semgrep_output


class TestParseSemgrepOutput:
    def test_basic_finding(self, semgrep_fixture):
        findings = parse_semgrep_output(semgrep_fixture)
        assert len(findings) == 2

        first = findings[0]
        assert first.file_path == "/opt/target/src/utils.py"
        assert first.line_number == 42
        assert first.source_tool == "semgrep"
        assert first.category == "sast"

    def test_severity_mapping(self, semgrep_fixture):
        findings = parse_semgrep_output(semgrep_fixture)
        sev_map = {f.id: f.severity for f in findings}
        assert sev_map["semgrep-python.lang.security.audit.eval-usage"] == "high"
        assert sev_map["semgrep-python.lang.security.audit.subprocess-shell-true"] == "medium"

    def test_cwe_in_title(self, semgrep_fixture):
        findings = parse_semgrep_output(semgrep_fixture)
        eval_finding = findings[0]
        assert "CWE-94" in eval_finding.title
        assert "CWE-95" in eval_finding.title

    def test_no_cve(self, semgrep_fixture):
        findings = parse_semgrep_output(semgrep_fixture)
        for f in findings:
            assert f.cve_id is None

    def test_from_fixture(self, semgrep_fixture):
        findings = parse_semgrep_output(semgrep_fixture)
        for f in findings:
            assert f.id.startswith("semgrep-")
            assert f.source_tool == "semgrep"

    def test_empty_results(self):
        findings = parse_semgrep_output({"results": []})
        assert findings == []
