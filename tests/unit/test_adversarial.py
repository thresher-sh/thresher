"""Tests for threat_scanner.agents.adversarial."""

from __future__ import annotations

import json

from threat_scanner.agents.adversarial import (
    RISK_THRESHOLD,
    _extract_ai_high_risk,
    _extract_scanner_high_risk,
    _merge_verification_results,
    _parse_adversarial_output,
    filter_high_risk_findings,
)


class TestExtractScannerHighRisk:
    def test_critical_included(self):
        results = {"grype": [{"severity": "critical", "title": "t", "file_path": "/a.py"}]}
        high = _extract_scanner_high_risk(results)
        assert len(high) == 1
        assert high[0]["risk_score"] == 9

    def test_low_excluded(self):
        results = {"grype": [{"severity": "low", "title": "t"}]}
        high = _extract_scanner_high_risk(results)
        assert len(high) == 0

    def test_medium_included(self):
        results = {"grype": [{"severity": "medium", "title": "t"}]}
        high = _extract_scanner_high_risk(results)
        assert len(high) == 1
        assert high[0]["risk_score"] == 5

    def test_high_included(self):
        results = {"grype": [{"severity": "high", "title": "t"}]}
        high = _extract_scanner_high_risk(results)
        assert len(high) == 1
        assert high[0]["risk_score"] == 7

    def test_info_excluded(self):
        results = {"grype": [{"severity": "info", "title": "t"}]}
        assert _extract_scanner_high_risk(results) == []

    def test_non_dict_input(self):
        assert _extract_scanner_high_risk("bad") == []

    def test_explicit_risk_score(self):
        results = {"tool": [{"severity": "low", "risk_score": 8, "title": "t"}]}
        high = _extract_scanner_high_risk(results)
        assert len(high) == 1
        assert high[0]["risk_score"] == 8


class TestExtractAIHighRisk:
    def test_above_threshold(self):
        ai = {"findings": [{"file_path": "/a.py", "risk_score": 7, "findings": []}]}
        high = _extract_ai_high_risk(ai)
        assert len(high) == 1

    def test_below_threshold(self):
        ai = {"findings": [{"file_path": "/a.py", "risk_score": 2, "findings": []}]}
        high = _extract_ai_high_risk(ai)
        assert len(high) == 0

    def test_at_threshold(self):
        ai = {"findings": [{"file_path": "/a.py", "risk_score": RISK_THRESHOLD, "findings": []}]}
        high = _extract_ai_high_risk(ai)
        assert len(high) == 1

    def test_extracts_line_numbers(self):
        ai = {
            "findings": [
                {
                    "file_path": "/a.py",
                    "risk_score": 5,
                    "findings": [
                        {"line_numbers": [10, 20], "description": "bad"},
                    ],
                }
            ]
        }
        high = _extract_ai_high_risk(ai)
        assert high[0]["line_numbers"] == [10, 20]

    def test_empty_findings(self):
        assert _extract_ai_high_risk({"findings": []}) == []
        assert _extract_ai_high_risk({}) == []


class TestFilterHighRiskFindings:
    def test_combines_sources(self):
        scanner = {"grype": [{"severity": "critical", "title": "t"}]}
        ai = {"findings": [{"file_path": "/a.py", "risk_score": 7, "findings": []}]}
        combined = filter_high_risk_findings(scanner, ai)
        sources = {f["source"] for f in combined}
        assert "scanner:grype" in sources
        assert "ai_analysis" in sources


class TestMergeVerificationResults:
    def test_confirmed_preserves_score(self, adversarial_fixture):
        ai = {
            "findings": [
                {"file_path": "/opt/target/setup.py", "risk_score": 7},
            ]
        }
        merged = _merge_verification_results(ai, adversarial_fixture)
        setup = [f for f in merged["findings"] if f["file_path"] == "/opt/target/setup.py"][0]
        assert setup["adversarial_status"] == "confirmed"
        assert setup["risk_score"] == 7

    def test_downgraded_updates_score(self, adversarial_fixture):
        ai = {
            "findings": [
                {"file_path": "/opt/target/conftest.py", "risk_score": 5},
            ]
        }
        merged = _merge_verification_results(ai, adversarial_fixture)
        conftest = [f for f in merged["findings"]
                    if f["file_path"] == "/opt/target/conftest.py"][0]
        assert conftest["adversarial_status"] == "downgraded"
        assert conftest["risk_score"] == 2
        assert conftest["original_risk_score"] == 5

    def test_adds_metadata(self, adversarial_fixture):
        ai = {"findings": []}
        merged = _merge_verification_results(ai, adversarial_fixture)
        assert "adversarial_verification" in merged
        assert merged["adversarial_verification"]["confirmed_count"] == 1
        assert merged["adversarial_verification"]["downgraded_count"] == 1

    def test_no_results(self):
        ai = {"findings": [{"file_path": "/a.py", "risk_score": 5}]}
        merged = _merge_verification_results(ai, {"results": []})
        assert merged["findings"][0]["risk_score"] == 5


class TestParseAdversarialOutput:
    def test_clean_json(self, adversarial_fixture):
        raw = json.dumps(adversarial_fixture)
        result = _parse_adversarial_output(raw)
        assert len(result["results"]) == 2

    def test_envelope(self):
        inner = json.dumps({"results": [{"verdict": "confirmed"}]})
        envelope = json.dumps({"result": inner})
        result = _parse_adversarial_output(envelope)
        assert len(result["results"]) == 1

    def test_empty(self):
        result = _parse_adversarial_output("")
        assert "error" in result
