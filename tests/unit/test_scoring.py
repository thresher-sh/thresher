"""Tests for threat_scanner.report.scoring."""

from __future__ import annotations

from unittest.mock import patch

from threat_scanner.report.scoring import (
    EPSS_BATCH_SIZE,
    compute_composite_priority,
    enrich_findings,
    fetch_epss_scores,
)


def _finding(**overrides) -> dict:
    base = {
        "cve_id": "",
        "cvss_score": None,
        "ai_risk_score": None,
        "ai_confidence": None,
        "ai_category": "",
        "adversarial_status": "",
    }
    base.update(overrides)
    return base


class TestCompositeP0:
    def test_kev(self):
        f = _finding(cve_id="CVE-2024-1")
        assert compute_composite_priority(f, {}, {"CVE-2024-1"}) == "P0"

    def test_ai_exfiltration_high_confidence(self):
        f = _finding(ai_confidence=95, ai_category="exfiltration")
        assert compute_composite_priority(f, {}, set()) == "P0"

    def test_ai_backdoor(self):
        f = _finding(ai_confidence=90, ai_category="backdoor")
        assert compute_composite_priority(f, {}, set()) == "P0"

    def test_ai_below_90_not_p0(self):
        f = _finding(ai_confidence=89, ai_category="exfiltration")
        assert compute_composite_priority(f, {}, set()) != "P0"


class TestCompositeCritical:
    def test_cvss_9(self):
        f = _finding(cvss_score=9.0)
        assert compute_composite_priority(f, {}, set()) == "critical"

    def test_cvss_10(self):
        f = _finding(cvss_score=10.0)
        assert compute_composite_priority(f, {}, set()) == "critical"

    def test_epss_above_90(self):
        f = _finding(cve_id="CVE-2024-1")
        assert compute_composite_priority(f, {"CVE-2024-1": 0.95}, set()) == "critical"

    def test_ai_risk_9_confirmed(self):
        f = _finding(ai_risk_score=9, adversarial_status="confirmed")
        assert compute_composite_priority(f, {}, set()) == "critical"

    def test_ai_risk_9_not_confirmed(self):
        f = _finding(ai_risk_score=9, adversarial_status="downgraded")
        # Without confirmation, falls to "high" based on ai_risk_score 9
        result = compute_composite_priority(f, {}, set())
        assert result != "critical"


class TestCompositeHigh:
    def test_cvss_7(self):
        f = _finding(cvss_score=7.0)
        assert compute_composite_priority(f, {}, set()) == "high"

    def test_cvss_8_9(self):
        f = _finding(cvss_score=8.9)
        assert compute_composite_priority(f, {}, set()) == "high"

    def test_epss_above_75(self):
        f = _finding(cve_id="CVE-1")
        assert compute_composite_priority(f, {"CVE-1": 0.8}, set()) == "high"

    def test_ai_risk_7(self):
        f = _finding(ai_risk_score=7)
        assert compute_composite_priority(f, {}, set()) == "high"


class TestCompositeMedium:
    def test_cvss_4(self):
        f = _finding(cvss_score=4.0)
        assert compute_composite_priority(f, {}, set()) == "medium"

    def test_epss_above_50(self):
        f = _finding(cve_id="CVE-1")
        assert compute_composite_priority(f, {"CVE-1": 0.6}, set()) == "medium"

    def test_ai_risk_5(self):
        f = _finding(ai_risk_score=5)
        assert compute_composite_priority(f, {}, set()) == "medium"


class TestCompositeLow:
    def test_default(self):
        f = _finding()
        assert compute_composite_priority(f, {}, set()) == "low"

    def test_cvss_3(self):
        f = _finding(cvss_score=3.0)
        assert compute_composite_priority(f, {}, set()) == "low"


class TestEnrichFindings:
    @patch("threat_scanner.report.scoring.load_kev_catalog")
    @patch("threat_scanner.report.scoring.fetch_epss_scores")
    def test_adds_fields(self, mock_epss, mock_kev):
        mock_epss.return_value = {"CVE-2024-1": 0.85}
        mock_kev.return_value = set()

        findings = [_finding(cve_id="CVE-2024-1", cvss_score=8.0)]
        enriched = enrich_findings(findings, "vm")

        assert enriched[0]["epss_score"] == 0.85
        assert enriched[0]["in_kev"] is False
        assert enriched[0]["composite_priority"] == "high"

    @patch("threat_scanner.report.scoring.load_kev_catalog")
    @patch("threat_scanner.report.scoring.fetch_epss_scores")
    def test_kev_flag(self, mock_epss, mock_kev):
        mock_epss.return_value = {}
        mock_kev.return_value = {"CVE-2024-1"}

        findings = [_finding(cve_id="CVE-2024-1")]
        enriched = enrich_findings(findings, "vm")
        assert enriched[0]["in_kev"] is True
        assert enriched[0]["composite_priority"] == "P0"


class TestFetchEPSS:
    def test_empty_input(self):
        assert fetch_epss_scores([]) == {}

    @patch("threat_scanner.report.scoring._fetch_epss_batch")
    def test_batching(self, mock_batch):
        mock_batch.return_value = {}
        cves = [f"CVE-2024-{i}" for i in range(EPSS_BATCH_SIZE + 10)]
        fetch_epss_scores(cves)
        assert mock_batch.call_count == 2

    @patch("threat_scanner.report.scoring._fetch_epss_batch")
    def test_deduplicates(self, mock_batch):
        mock_batch.return_value = {"CVE-2024-1": 0.5}
        result = fetch_epss_scores(["CVE-2024-1", "CVE-2024-1", "CVE-2024-1"])
        assert mock_batch.call_count == 1
