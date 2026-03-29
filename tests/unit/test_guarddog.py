"""Tests for threat_scanner.scanners.guarddog."""

from __future__ import annotations

from threat_scanner.scanners.guarddog import (
    _parse_single_result,
    parse_guarddog_output,
)


class TestParseGuarddogOutput:
    def test_dict_format(self, guarddog_fixture):
        findings = parse_guarddog_output(guarddog_fixture)
        # suspicious-pkg has 2 rules, clean-pkg has 0
        assert len(findings) == 2

    def test_rule_names(self, guarddog_fixture):
        findings = parse_guarddog_output(guarddog_fixture)
        rules = {f.title for f in findings}
        assert any("shady-link" in r for r in rules)
        assert any("code-execution" in r for r in rules)

    def test_file_path_extracted(self, guarddog_fixture):
        findings = parse_guarddog_output(guarddog_fixture)
        paths = [f.file_path for f in findings if f.file_path]
        assert any("setup.py" in p for p in paths)

    def test_all_supply_chain(self, guarddog_fixture):
        findings = parse_guarddog_output(guarddog_fixture)
        for f in findings:
            assert f.category == "supply_chain"
            assert f.severity == "high"

    def test_empty_results(self):
        findings = parse_guarddog_output({"pkg": {"results": {}}})
        assert findings == []

    def test_list_format(self):
        raw = [
            {
                "rule": "suspicious-setup",
                "package": "bad-pkg",
                "message": "Suspicious setup.py",
                "location": "/opt/target/setup.py",
            }
        ]
        findings = parse_guarddog_output(raw)
        assert len(findings) == 1
        assert findings[0].package_name == "bad-pkg"

    def test_from_fixture(self, guarddog_fixture):
        findings = parse_guarddog_output(guarddog_fixture)
        for f in findings:
            assert f.id.startswith("guarddog-")
            assert f.source_tool == "guarddog"


class TestParseSingleResult:
    def test_valid_item(self):
        item = {
            "rule": "exfil",
            "package": "evil",
            "message": "Data exfiltration detected",
            "file": "/path/to/file.py",
        }
        finding = _parse_single_result(item, 0)
        assert finding is not None
        assert finding.package_name == "evil"
        assert finding.file_path == "/path/to/file.py"

    def test_non_dict_returns_none(self):
        assert _parse_single_result("not a dict", 0) is None

    def test_missing_fields(self):
        finding = _parse_single_result({}, 0)
        assert finding is not None
        assert finding.package_name == "unknown"
