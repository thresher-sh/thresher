"""Tests for threat_scanner.scanners.runner."""

from __future__ import annotations

from threat_scanner.scanners.models import Finding, ScanResults
from threat_scanner.scanners.runner import _richness, aggregate_findings


def _make_finding(**overrides) -> Finding:
    defaults = dict(
        id="test-001",
        source_tool="test",
        category="sca",
        severity="medium",
        cvss_score=None,
        cve_id=None,
        title="Test",
        description="",
        file_path=None,
        line_number=None,
        package_name=None,
        package_version=None,
        fix_version=None,
        raw_output={},
    )
    defaults.update(overrides)
    return Finding(**defaults)


class TestAggregateFindings:
    def test_dedup_same_cve_package(self):
        f1 = _make_finding(id="a", cve_id="CVE-2024-1", package_name="pkg")
        f2 = _make_finding(id="b", cve_id="CVE-2024-1", package_name="pkg")
        results = [
            ScanResults(tool_name="t1", execution_time_seconds=0, exit_code=0, findings=[f1]),
            ScanResults(tool_name="t2", execution_time_seconds=0, exit_code=0, findings=[f2]),
        ]
        merged = aggregate_findings(results)
        assert len(merged) == 1

    def test_keeps_richer(self):
        sparse = _make_finding(
            id="a", cve_id="CVE-2024-1", package_name="pkg",
            description="", fix_version=None, cvss_score=None,
        )
        rich = _make_finding(
            id="b", cve_id="CVE-2024-1", package_name="pkg",
            description="Detailed", fix_version="2.0", cvss_score=9.0,
        )
        results = [
            ScanResults(tool_name="t1", execution_time_seconds=0, exit_code=0, findings=[sparse]),
            ScanResults(tool_name="t2", execution_time_seconds=0, exit_code=0, findings=[rich]),
        ]
        merged = aggregate_findings(results)
        assert len(merged) == 1
        assert merged[0].fix_version == "2.0"

    def test_no_cve_always_included(self):
        f1 = _make_finding(id="a", cve_id=None, package_name="pkg")
        f2 = _make_finding(id="b", cve_id=None, package_name="pkg")
        results = [
            ScanResults(tool_name="t", execution_time_seconds=0, exit_code=0, findings=[f1, f2]),
        ]
        merged = aggregate_findings(results)
        assert len(merged) == 2

    def test_sorted_by_severity(self):
        low = _make_finding(id="low", severity="low")
        crit = _make_finding(id="crit", severity="critical")
        med = _make_finding(id="med", severity="medium")
        results = [
            ScanResults(tool_name="t", execution_time_seconds=0, exit_code=0,
                        findings=[low, crit, med]),
        ]
        merged = aggregate_findings(results)
        assert [f.severity for f in merged] == ["critical", "medium", "low"]

    def test_different_cve_not_deduped(self):
        f1 = _make_finding(id="a", cve_id="CVE-2024-1", package_name="pkg")
        f2 = _make_finding(id="b", cve_id="CVE-2024-2", package_name="pkg")
        results = [
            ScanResults(tool_name="t", execution_time_seconds=0, exit_code=0, findings=[f1, f2]),
        ]
        merged = aggregate_findings(results)
        assert len(merged) == 2


class TestRichness:
    def test_empty(self):
        f = _make_finding()
        assert _richness(f) == 0

    def test_full(self):
        f = _make_finding(
            cvss_score=9.0,
            description="desc",
            fix_version="2.0",
            file_path="/a.py",
            line_number=10,
        )
        assert _richness(f) == 5

    def test_partial(self):
        f = _make_finding(cvss_score=5.0, description="d")
        assert _richness(f) == 2
