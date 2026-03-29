"""Tests for threat_scanner.scanners.models."""

from __future__ import annotations

from threat_scanner.scanners.models import Finding, ScanResults


class TestFinding:
    def test_to_dict_keys(self, sample_finding: Finding):
        d = sample_finding.to_dict()
        expected_keys = {
            "id", "source_tool", "category", "severity", "cvss_score",
            "cve_id", "title", "description", "file_path", "line_number",
            "package_name", "package_version", "fix_version", "raw_output",
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_values(self, sample_finding: Finding):
        d = sample_finding.to_dict()
        assert d["id"] == "grype-CVE-2024-1234"
        assert d["severity"] == "critical"
        assert d["cvss_score"] == 9.8
        assert d["cve_id"] == "CVE-2024-1234"
        assert d["package_name"] == "example-lib"
        assert d["fix_version"] == "1.2.4"

    def test_to_dict_roundtrip(self, sample_finding: Finding):
        d = sample_finding.to_dict()
        reconstructed = Finding(**d)
        assert reconstructed.to_dict() == d

    def test_to_dict_minimal(self, sample_finding_minimal: Finding):
        d = sample_finding_minimal.to_dict()
        assert d["cvss_score"] is None
        assert d["cve_id"] is None
        assert d["file_path"] is None


class TestScanResults:
    def test_to_dict(self, sample_scan_results: ScanResults):
        d = sample_scan_results.to_dict()
        assert d["tool_name"] == "grype"
        assert d["exit_code"] == 1
        assert len(d["findings"]) == 1
        assert d["findings"][0]["id"] == "grype-CVE-2024-1234"

    def test_defaults(self):
        sr = ScanResults(tool_name="test", execution_time_seconds=0.0, exit_code=0)
        assert sr.findings == []
        assert sr.errors == []
        assert sr.raw_output_path is None
        assert sr.metadata == {}
