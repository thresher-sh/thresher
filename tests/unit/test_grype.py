"""Tests for threat_scanner.scanners.grype."""

from __future__ import annotations

from threat_scanner.scanners.grype import (
    _extract_cvss_score,
    parse_grype_output,
)


class TestParseGrypeOutput:
    def test_empty_matches(self):
        assert parse_grype_output({"matches": []}) == []

    def test_single_vuln(self, grype_fixture):
        findings = parse_grype_output(grype_fixture)
        assert len(findings) == 3

        crit = findings[0]
        assert crit.cve_id == "CVE-2024-1234"
        assert crit.severity == "critical"
        assert crit.cvss_score == 9.8
        assert crit.package_name == "example-lib"
        assert crit.package_version == "1.2.3"
        assert crit.fix_version == "1.2.4"
        assert crit.source_tool == "grype"
        assert crit.category == "sca"

    def test_severity_mapping(self, grype_fixture):
        findings = parse_grype_output(grype_fixture)
        severities = [f.severity for f in findings]
        assert "critical" in severities
        assert "medium" in severities
        assert "low" in severities

    def test_no_cve_prefix(self, grype_fixture):
        findings = parse_grype_output(grype_fixture)
        ghsa_finding = [f for f in findings if "GHSA" in f.id][0]
        assert ghsa_finding.cve_id is None

    def test_no_fix_version(self, grype_fixture):
        findings = parse_grype_output(grype_fixture)
        medium = [f for f in findings if f.severity == "medium"][0]
        assert medium.fix_version is None

    def test_from_fixture(self, grype_fixture):
        findings = parse_grype_output(grype_fixture)
        for f in findings:
            assert f.id.startswith("grype-")
            assert f.source_tool == "grype"


class TestExtractCVSSScore:
    def test_single_entry(self):
        vuln = {"cvss": [{"metrics": {"baseScore": 7.5}}]}
        assert _extract_cvss_score(vuln) == 7.5

    def test_multiple_entries_takes_highest(self):
        vuln = {
            "cvss": [
                {"metrics": {"baseScore": 5.0}},
                {"metrics": {"baseScore": 9.1}},
                {"metrics": {"baseScore": 7.0}},
            ]
        }
        assert _extract_cvss_score(vuln) == 9.1

    def test_no_cvss(self):
        assert _extract_cvss_score({"cvss": []}) is None
        assert _extract_cvss_score({}) is None
