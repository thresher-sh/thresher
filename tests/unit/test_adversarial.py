"""Tests for threat_scanner.agents.adversarial."""

from __future__ import annotations

import json

from threat_scanner.agents.adversarial import (
    RISK_THRESHOLD,
    _extract_high_risk,
    _extract_result_from_stream,
    _merge_adversarial_results,
    _parse_adversarial_output,
)


class TestExtractHighRisk:
    def test_above_threshold(self):
        ai = {"findings": [
            {"file_path": "/a.py", "risk_score": 7, "findings": [{"description": "bad"}]},
            {"file_path": "/b.py", "risk_score": 2, "findings": []},
        ]}
        high = _extract_high_risk(ai)
        assert len(high) == 1
        assert high[0]["file_path"] == "/a.py"

    def test_empty_findings(self):
        assert _extract_high_risk({"findings": []}) == []

    def test_no_findings_key(self):
        assert _extract_high_risk({}) == []

    def test_threshold_boundary(self):
        ai = {"findings": [
            {"file_path": "/a.py", "risk_score": RISK_THRESHOLD, "findings": []},
            {"file_path": "/b.py", "risk_score": RISK_THRESHOLD - 1, "findings": []},
        ]}
        high = _extract_high_risk(ai)
        assert len(high) == 1

    def test_collects_line_numbers(self):
        ai = {"findings": [
            {
                "file_path": "/a.py",
                "risk_score": 8,
                "findings": [
                    {"description": "x", "line_numbers": [10, 20]},
                    {"description": "y", "line_numbers": [20, 30]},
                ],
            }
        ]}
        high = _extract_high_risk(ai)
        assert high[0]["line_numbers"] == [10, 20, 30]


class TestParseAdversarialOutput:
    def test_direct_json(self):
        data = json.dumps({
            "verification_summary": "done",
            "results": [{"file_path": "/a.py", "verdict": "confirmed"}],
        })
        result = _parse_adversarial_output(data)
        assert result["verification_summary"] == "done"

    def test_empty(self):
        result = _parse_adversarial_output("")
        assert "error" in result

    def test_stream_json(self):
        inner = {"results": [{"verdict": "downgraded"}]}
        stream = f'{{"type":"result","result":{json.dumps(json.dumps(inner))}}}\n'
        result = _parse_adversarial_output(stream)
        assert len(result["results"]) == 1

    def test_code_block(self):
        text = '```json\n{"results": []}\n```'
        result = _parse_adversarial_output(text)
        assert result["results"] == []


class TestMergeAdversarialResults:
    def test_merges_verdict(self):
        ai = {"findings": [
            {"file_path": "/a.py", "risk_score": 7},
            {"file_path": "/b.py", "risk_score": 5},
        ]}
        verification = {
            "verification_summary": "done",
            "total_reviewed": 1,
            "confirmed_count": 0,
            "downgraded_count": 1,
            "results": [{
                "file_path": "/a.py",
                "verdict": "downgraded",
                "revised_risk_score": 2,
                "reasoning": "benign pattern",
                "confidence": 95,
                "benign_explanation_attempted": "it's fine",
            }],
        }
        result = _merge_adversarial_results(ai, verification)
        finding_a = [f for f in result["findings"] if f["file_path"] == "/a.py"][0]
        assert finding_a["adversarial_status"] == "downgraded"
        assert finding_a["risk_score"] == 2
        assert finding_a["original_risk_score"] == 7
        assert result["adversarial_verification"]["downgraded_count"] == 1

    def test_unmatched_finding_unchanged(self):
        ai = {"findings": [{"file_path": "/x.py", "risk_score": 6}]}
        verification = {"results": [], "total_reviewed": 0, "confirmed_count": 0, "downgraded_count": 0}
        result = _merge_adversarial_results(ai, verification)
        assert result["findings"][0]["risk_score"] == 6
        assert "adversarial_status" not in result["findings"][0]


class TestExtractResultFromStream:
    def test_extracts_result(self):
        stream = '{"type":"result","result":"data"}\n'
        assert _extract_result_from_stream(stream) == "data"

    def test_fallback(self):
        assert _extract_result_from_stream("plain text") == "plain text"
