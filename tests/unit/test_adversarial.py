"""Tests for thresher.agents.adversarial."""

from __future__ import annotations

import json

from thresher.agents.adversarial import (
    RISK_THRESHOLD,
    _extract_high_risk,
    _extract_result_from_stream,
    _finding_risk_score,
    _merge_adversarial_results,
    _normalize_adversarial_schema,
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


class TestFindingRiskScore:
    def test_explicit_risk_score(self):
        assert _finding_risk_score({"risk_score": 7}) == 7

    def test_severity_critical(self):
        assert _finding_risk_score({"severity": "critical"}) == 9

    def test_severity_high(self):
        assert _finding_risk_score({"severity": "high"}) == 7

    def test_severity_medium(self):
        assert _finding_risk_score({"severity": "medium"}) == 4

    def test_severity_low(self):
        assert _finding_risk_score({"severity": "low"}) == 2

    def test_unknown_severity(self):
        assert _finding_risk_score({"severity": "unknown"}) == 0

    def test_no_score_or_severity(self):
        assert _finding_risk_score({}) == 0

    def test_explicit_risk_score_takes_precedence(self):
        assert _finding_risk_score({"risk_score": 3, "severity": "critical"}) == 3


class TestExtractHighRiskMultiAnalyst:
    """Tests for _extract_high_risk with multi-analyst flat schema (severity-based)."""

    def test_critical_and_high_pass_threshold(self):
        ai = {"findings": [
            {"file_path": "/a.py", "severity": "critical", "title": "Bad", "description": "Very bad"},
            {"file_path": "/b.py", "severity": "high", "title": "Risky", "description": "Risky"},
            {"file_path": "/c.py", "severity": "low", "title": "Minor", "description": "Minor"},
        ]}
        high = _extract_high_risk(ai)
        assert len(high) == 2
        paths = {h["file_path"] for h in high}
        assert paths == {"/a.py", "/b.py"}

    def test_medium_at_threshold_boundary(self):
        ai = {"findings": [
            {"file_path": "/a.py", "severity": "medium", "title": "Med", "description": "Med"},
        ]}
        high = _extract_high_risk(ai)
        # medium maps to 4, threshold is 4, so it passes
        assert len(high) == 1

    def test_low_below_threshold(self):
        ai = {"findings": [
            {"file_path": "/a.py", "severity": "low", "title": "Low", "description": "Low"},
        ]}
        high = _extract_high_risk(ai)
        assert len(high) == 0

    def test_preserves_source_analyst(self):
        ai = {"findings": [
            {
                "file_path": "/a.py",
                "severity": "critical",
                "title": "Bad",
                "description": "Very bad",
                "source_analyst": "paranoid",
                "source_analyst_number": 1,
            },
        ]}
        high = _extract_high_risk(ai)
        assert high[0]["source_analyst"] == "paranoid"
        assert high[0]["source_analyst_number"] == 1

    def test_preserves_line_numbers(self):
        ai = {"findings": [
            {
                "file_path": "/a.py",
                "severity": "high",
                "title": "Bad",
                "description": "Very bad",
                "line_numbers": [10, 5, 20],
            },
        ]}
        high = _extract_high_risk(ai)
        assert high[0]["line_numbers"] == [5, 10, 20]


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

    def test_error_result_with_assistant_text_fallback(self):
        stream = (
            '{"type":"system","subtype":"init","cwd":"/opt/target"}\n'
            '{"type":"assistant","message":{"content":[{"type":"text","text":"partial output"}]}}\n'
            '{"type":"result","subtype":"error_max_turns","is_error":true}\n'
        )
        assert _extract_result_from_stream(stream) == "partial output"

    def test_error_result_no_assistant_text(self):
        stream = (
            '{"type":"system","subtype":"init","cwd":"/opt/target"}\n'
            '{"type":"result","subtype":"error_max_turns","is_error":true}\n'
        )
        assert _extract_result_from_stream(stream) == ""

    def test_successful_result_preferred_over_assistant_text(self):
        stream = (
            '{"type":"assistant","message":{"content":[{"type":"text","text":"partial"}]}}\n'
            '{"type":"result","result":"final answer"}\n'
        )
        assert _extract_result_from_stream(stream) == "final answer"


class TestNormalizeAdversarialSchema:
    """Tests for _normalize_adversarial_schema handling analyst-forced output."""

    def test_native_schema_unchanged(self):
        """Data already in adversarial schema passes through unmodified."""
        data = {
            "verification_summary": "done",
            "total_reviewed": 2,
            "confirmed_count": 1,
            "downgraded_count": 1,
            "results": [
                {"file_path": "/a.py", "verdict": "confirmed", "reasoning": "bad"},
                {"file_path": "/b.py", "verdict": "downgraded", "reasoning": "ok"},
            ],
        }
        result = _normalize_adversarial_schema(data)
        assert result is data  # same object, not copied

    def test_analyst_forced_schema_remapped(self):
        """Analyst-forced schema (findings with verdicts) gets remapped."""
        data = {
            "analyst": "adversarial",
            "summary": "Reviewed 3 findings",
            "findings": [
                {"file_path": "/a.py", "verdict": "confirmed", "reasoning": "bad", "confidence": 90},
                {"file_path": "/b.py", "verdict": "downgraded", "reasoning": "ok", "confidence": 80},
                {"file_path": "/c.py", "verdict": "confirmed", "reasoning": "also bad", "confidence": 85},
            ],
        }
        result = _normalize_adversarial_schema(data)
        assert "results" in result
        assert len(result["results"]) == 3
        assert result["verification_summary"] == "Reviewed 3 findings"
        assert result["total_reviewed"] == 3
        assert result["confirmed_count"] == 2
        assert result["downgraded_count"] == 1

    def test_findings_without_verdicts_not_remapped(self):
        """Findings without verdict fields are NOT remapped (analyst schema)."""
        data = {
            "findings": [
                {"file_path": "/a.py", "risk_score": 7, "description": "bad"},
            ],
        }
        result = _normalize_adversarial_schema(data)
        # Should not have "results" key — not remapped
        assert "results" not in result
        assert "findings" in result

    def test_empty_findings_not_remapped(self):
        data = {"findings": []}
        result = _normalize_adversarial_schema(data)
        assert "results" not in result


class TestParseAdversarialOutputSchemaDetection:
    """Tests that _parse_adversarial_output handles both schemas."""

    def test_analyst_forced_schema_produces_results(self):
        """When analyst stop hook forced wrong schema, parser normalizes it."""
        data = json.dumps({
            "analyst": "adversarial",
            "summary": "Reviewed findings",
            "findings": [
                {"file_path": "/a.py", "verdict": "confirmed", "reasoning": "bad", "confidence": 90},
                {"file_path": "/b.py", "verdict": "downgraded", "reasoning": "ok", "confidence": 80},
            ],
        })
        result = _parse_adversarial_output(data)
        assert "results" in result
        assert len(result["results"]) == 2
        assert result["confirmed_count"] == 1
        assert result["downgraded_count"] == 1

    def test_native_schema_direct(self):
        data = json.dumps({
            "verification_summary": "done",
            "total_reviewed": 1,
            "confirmed_count": 1,
            "downgraded_count": 0,
            "results": [{"file_path": "/a.py", "verdict": "confirmed", "reasoning": "bad"}],
        })
        result = _parse_adversarial_output(data)
        assert result["total_reviewed"] == 1
        assert len(result["results"]) == 1


class TestMergeAdversarialResultsBothSchemas:
    """Tests that _merge_adversarial_results works with both schemas after normalization."""

    def test_merge_with_normalized_analyst_schema(self):
        """Analyst-forced schema, after normalization, merges correctly."""
        ai_findings = {"findings": [
            {"file_path": "/a.py", "risk_score": 7},
            {"file_path": "/b.py", "risk_score": 5},
        ]}
        # Simulate what _parse_adversarial_output returns after normalization
        verification = _normalize_adversarial_schema({
            "summary": "Reviewed 2 findings",
            "findings": [
                {"file_path": "/a.py", "verdict": "confirmed", "reasoning": "bad", "confidence": 90},
                {"file_path": "/b.py", "verdict": "downgraded", "reasoning": "ok", "confidence": 80,
                 "revised_risk_score": 2},
            ],
        })
        result = _merge_adversarial_results(ai_findings, verification)

        # Both findings should have adversarial annotations
        finding_a = [f for f in result["findings"] if f["file_path"] == "/a.py"][0]
        finding_b = [f for f in result["findings"] if f["file_path"] == "/b.py"][0]
        assert finding_a["adversarial_status"] == "confirmed"
        assert finding_b["adversarial_status"] == "downgraded"
        assert finding_b["risk_score"] == 2

        # Verification summary should be populated
        assert result["adversarial_verification"]["total_reviewed"] == 2
        assert result["adversarial_verification"]["confirmed_count"] == 1
        assert result["adversarial_verification"]["downgraded_count"] == 1

    def test_merge_logs_warning_on_unexpected_schema(self, caplog):
        """When total_reviewed is 0 but dict is non-empty, log a warning."""
        import logging
        ai_findings = {"findings": [{"file_path": "/a.py", "risk_score": 7}]}
        verification = {"some_unexpected_key": "value", "results": []}
        with caplog.at_level(logging.WARNING):
            _merge_adversarial_results(ai_findings, verification)
        assert "unexpected schema" in caplog.text.lower()
