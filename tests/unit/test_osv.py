"""Tests for threat_scanner.scanners.osv."""

from __future__ import annotations

from threat_scanner.scanners.osv import (
    _extract_fix_version,
    _extract_severity,
    parse_osv_output,
)


class TestParseOSVOutput:
    def test_cve_finding(self, osv_fixture):
        findings = parse_osv_output(osv_fixture)
        cve_findings = [f for f in findings if f.cve_id is not None]
        assert len(cve_findings) == 1
        cve = cve_findings[0]
        assert cve.cve_id == "CVE-2024-1234"
        assert cve.category == "sca"
        assert cve.package_name == "example-lib"

    def test_mal_finding(self, osv_fixture):
        findings = parse_osv_output(osv_fixture)
        mal_findings = [f for f in findings if f.id.startswith("osv-MAL")]
        assert len(mal_findings) == 1
        mal = mal_findings[0]
        assert mal.category == "supply_chain"
        assert mal.severity == "critical"
        assert mal.package_name == "evil-package"

    def test_fix_version_extracted(self, osv_fixture):
        findings = parse_osv_output(osv_fixture)
        cve = [f for f in findings if f.cve_id == "CVE-2024-1234"][0]
        assert cve.fix_version == "1.2.4"

    def test_from_fixture(self, osv_fixture):
        findings = parse_osv_output(osv_fixture)
        assert len(findings) == 2
        for f in findings:
            assert f.source_tool == "osv-scanner"
            assert f.id.startswith("osv-")


class TestExtractSeverity:
    def test_from_database_specific(self):
        vuln = {"database_specific": {"severity": "HIGH"}}
        assert _extract_severity(vuln) == "high"

    def test_default_medium(self):
        assert _extract_severity({}) == "medium"

    def test_moderate_maps_to_medium(self):
        vuln = {"database_specific": {"severity": "MODERATE"}}
        assert _extract_severity(vuln) == "medium"


class TestExtractFixVersion:
    def test_found(self):
        vuln = {
            "affected": [
                {
                    "ranges": [
                        {
                            "events": [
                                {"introduced": "0"},
                                {"fixed": "2.0.0"},
                            ]
                        }
                    ]
                }
            ]
        }
        assert _extract_fix_version(vuln) == "2.0.0"

    def test_not_found(self):
        vuln = {
            "affected": [
                {
                    "ranges": [
                        {"events": [{"introduced": "0"}]}
                    ]
                }
            ]
        }
        assert _extract_fix_version(vuln) is None

    def test_empty(self):
        assert _extract_fix_version({}) is None
