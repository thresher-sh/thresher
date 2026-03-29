"""Tests for threat_scanner.scanners.gitleaks."""

from __future__ import annotations

from threat_scanner.scanners.gitleaks import parse_gitleaks_output


class TestParseGitleaksOutput:
    def test_basic_parsing(self, gitleaks_fixture):
        findings = parse_gitleaks_output(gitleaks_fixture)
        assert len(findings) == 2

    def test_fields_extracted(self, gitleaks_fixture):
        findings = parse_gitleaks_output(gitleaks_fixture)
        first = findings[0]
        assert first.file_path == "config/settings.py"
        assert first.line_number == 10
        assert first.source_tool == "gitleaks"
        assert first.category == "secrets"
        assert first.severity == "high"

    def test_match_truncated(self, gitleaks_fixture):
        findings = parse_gitleaks_output(gitleaks_fixture)
        first = findings[0]
        # Match "AKIAIOSFODNN7EXAMPLE1234567890" is > 20 chars
        assert "AKIAIOSFODNN7EXAMPLE..." in first.description
        # Should NOT contain the full match
        assert "1234567890" not in first.description

    def test_short_match_not_truncated(self):
        raw = [
            {
                "RuleID": "test",
                "Description": "Test",
                "File": "f.py",
                "StartLine": 1,
                "Match": "short",
            }
        ]
        findings = parse_gitleaks_output(raw)
        assert "short" in findings[0].description
        assert "..." not in findings[0].description

    def test_all_secrets_category(self, gitleaks_fixture):
        for f in parse_gitleaks_output(gitleaks_fixture):
            assert f.category == "secrets"
            assert f.severity == "high"

    def test_empty_list(self):
        assert parse_gitleaks_output([]) == []

    def test_from_fixture(self, gitleaks_fixture):
        for f in parse_gitleaks_output(gitleaks_fixture):
            assert f.id.startswith("gitleaks-")
