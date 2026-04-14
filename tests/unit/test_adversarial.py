"""Tests for thresher.agents.adversarial."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from thresher.agents.adversarial import (
    _deduplicate_findings,
    _extract_high_risk,
    _finding_risk_score,
    _merge_adversarial_results,
    _merge_analyst_findings,
    _normalize_adversarial_schema,
    _normalize_title,
    _parse_adversarial_output,
    run_adversarial_verification,
)
from thresher.config import ScanConfig


def _mock_popen(returncode=0, stdout=b""):
    """Create a mock that behaves like subprocess.Popen."""
    mock = MagicMock()
    mock.stdout = iter(stdout.splitlines(keepends=True)) if stdout else iter([])
    mock.returncode = returncode
    mock.wait.return_value = returncode
    return mock


def _make_config() -> ScanConfig:
    return ScanConfig(
        repo_url="https://github.com/x/y",
        anthropic_api_key="sk-ant-test-key",
        model="sonnet",
    )


class TestFindingRiskScore:
    def test_explicit_risk_score_used_when_severity_missing(self):
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

    def test_no_severity(self):
        assert _finding_risk_score({}) == 0

    def test_severity_takes_precedence_over_explicit_risk_score(self):
        assert _finding_risk_score({"severity": "critical", "risk_score": 3}) == 9

    def test_explicit_risk_score_used_when_severity_invalid(self):
        assert _finding_risk_score({"severity": "unknown", "risk_score": 5}) == 5


class TestExtractHighRiskMultiAnalyst:
    """Tests for _extract_high_risk with multi-analyst flat schema (severity-based)."""

    def test_critical_and_high_pass_threshold(self):
        ai = {
            "findings": [
                {"file_path": "/a.py", "severity": "critical", "title": "Bad", "description": "Very bad"},
                {"file_path": "/b.py", "severity": "high", "title": "Risky", "description": "Risky"},
                {"file_path": "/c.py", "severity": "low", "title": "Minor", "description": "Minor"},
            ]
        }
        high = _extract_high_risk(ai)
        assert len(high) == 2
        paths = {h["file_path"] for h in high}
        assert paths == {"/a.py", "/b.py"}

    def test_medium_at_threshold_boundary(self):
        ai = {
            "findings": [
                {"file_path": "/a.py", "severity": "medium", "title": "Med", "description": "Med"},
            ]
        }
        high = _extract_high_risk(ai)
        # medium maps to 4, threshold is 4, so it passes
        assert len(high) == 1

    def test_low_below_threshold(self):
        ai = {
            "findings": [
                {"file_path": "/a.py", "severity": "low", "title": "Low", "description": "Low"},
            ]
        }
        high = _extract_high_risk(ai)
        assert len(high) == 0

    def test_preserves_source_analyst(self):
        ai = {
            "findings": [
                {
                    "file_path": "/a.py",
                    "severity": "critical",
                    "title": "Bad",
                    "description": "Very bad",
                    "source_analyst": "paranoid",
                    "source_analyst_number": 1,
                },
            ]
        }
        high = _extract_high_risk(ai)
        assert high[0]["source_analyst"] == "paranoid"
        assert high[0]["source_analyst_number"] == 1

    def test_preserves_line_numbers(self):
        ai = {
            "findings": [
                {
                    "file_path": "/a.py",
                    "severity": "high",
                    "title": "Bad",
                    "description": "Very bad",
                    "line_numbers": [10, 5, 20],
                },
            ]
        }
        high = _extract_high_risk(ai)
        assert high[0]["line_numbers"] == [5, 10, 20]


class TestParseAdversarialOutput:
    def test_direct_json(self):
        data = json.dumps(
            {
                "verification_summary": "done",
                "results": [{"file_path": "/a.py", "verdict": "confirmed"}],
            }
        )
        result = _parse_adversarial_output(data)
        assert result["verification_summary"] == "done"

    def test_empty(self):
        result = _parse_adversarial_output("")
        assert "error" in result

    def test_envelope_unwrap(self):
        """Stream-JSON ``result`` envelopes are unwrapped through extract_json_object."""
        inner = {"results": [{"verdict": "downgraded"}]}
        envelope = f'{{"result":{json.dumps(json.dumps(inner))}}}'
        result = _parse_adversarial_output(envelope)
        assert len(result["results"]) == 1

    def test_code_block(self):
        text = '```json\n{"results": []}\n```'
        result = _parse_adversarial_output(text)
        assert result["results"] == []


class TestMergeAdversarialResults:
    def test_merges_verdict(self):
        ai = {
            "findings": [
                {"file_path": "/a.py", "risk_score": 7},
                {"file_path": "/b.py", "risk_score": 5},
            ]
        }
        verification = {
            "verification_summary": "done",
            "total_reviewed": 1,
            "confirmed_count": 0,
            "downgraded_count": 1,
            "results": [
                {
                    "file_path": "/a.py",
                    "verdict": "downgraded",
                    "revised_risk_score": 2,
                    "reasoning": "benign pattern",
                    "confidence": 95,
                    "benign_explanation_attempted": "it's fine",
                }
            ],
        }
        result = _merge_adversarial_results(ai, verification)
        finding_a = next(f for f in result["findings"] if f["file_path"] == "/a.py")
        assert finding_a["adversarial_status"] == "downgraded"
        assert finding_a["risk_score"] == 2
        assert finding_a["original_risk_score"] == 7
        assert result["adversarial_verification"]["downgraded_count"] == 1

    def test_unmatched_finding_gets_not_reviewed(self):
        ai = {"findings": [{"file_path": "/x.py", "risk_score": 6}]}
        verification = {"results": [], "total_reviewed": 0, "confirmed_count": 0, "downgraded_count": 0}
        result = _merge_adversarial_results(ai, verification)
        assert result["findings"][0]["risk_score"] == 6
        assert result["findings"][0]["adversarial_status"] == "not_reviewed"

    def test_multiple_findings_same_path_get_correct_verdicts(self):
        """Two findings at the same file_path should each get their own verdict."""
        ai = {
            "findings": [
                {"file_path": "/main.py", "title": "Rate Limiting", "risk_score": 7},
                {"file_path": "/main.py", "title": "CORS Misconfiguration", "risk_score": 6},
            ]
        }
        verification = {
            "verification_summary": "done",
            "total_reviewed": 2,
            "confirmed_count": 1,
            "downgraded_count": 1,
            "results": [
                {
                    "file_path": "/main.py",
                    "title": "Rate Limiting",
                    "verdict": "confirmed",
                    "reasoning": "rate limiting is missing",
                    "confidence": 90,
                    "benign_explanation_attempted": "",
                },
                {
                    "file_path": "/main.py",
                    "title": "CORS Misconfiguration",
                    "verdict": "downgraded",
                    "revised_risk_score": 2,
                    "reasoning": "CORS is correctly configured",
                    "confidence": 85,
                    "benign_explanation_attempted": "default deny",
                },
            ],
        }
        result = _merge_adversarial_results(ai, verification)
        rate_limit = next(f for f in result["findings"] if f["title"] == "Rate Limiting")
        cors = next(f for f in result["findings"] if f["title"] == "CORS Misconfiguration")
        assert rate_limit["adversarial_status"] == "confirmed"
        assert rate_limit["risk_score"] == 7  # no revision
        assert cors["adversarial_status"] == "downgraded"
        assert cors["risk_score"] == 2
        assert cors["original_risk_score"] == 6


class TestNormalizeTitle:
    def test_lowercases(self):
        assert _normalize_title("Suspicious Eval Call") == "suspicious eval call"

    def test_collapses_whitespace(self):
        assert _normalize_title("suspicious   eval   call") == "suspicious eval call"

    def test_strips(self):
        assert _normalize_title("  spaced  ") == "spaced"

    def test_empty(self):
        assert _normalize_title("") == ""


class TestDeduplicateFindings:
    def test_removes_duplicates_same_file_and_title(self):
        findings = [
            {
                "file_path": "/a.py",
                "title": "Suspicious eval",
                "risk_score": 7,
                "source_analyst": "paranoid",
            },
            {
                "file_path": "/a.py",
                "title": "Suspicious eval",
                "risk_score": 5,
                "source_analyst": "behaviorist",
            },
            {
                "file_path": "/a.py",
                "title": "Suspicious eval",
                "risk_score": 7,
                "source_analyst": "netwatch",
            },
        ]
        result = _deduplicate_findings(findings)
        assert len(result) == 1
        assert result[0]["risk_score"] == 7
        assert result[0]["duplicate_count"] == 3
        assert sorted(result[0]["source_analysts"]) == ["behaviorist", "netwatch", "paranoid"]

    def test_keeps_highest_risk_score(self):
        findings = [
            {"file_path": "/a.py", "title": "Bad", "risk_score": 5, "source_analyst": "a"},
            {"file_path": "/a.py", "title": "Bad", "risk_score": 9, "source_analyst": "b"},
            {"file_path": "/a.py", "title": "Bad", "risk_score": 7, "source_analyst": "c"},
        ]
        result = _deduplicate_findings(findings)
        assert result[0]["risk_score"] == 9

    def test_unique_findings_pass_through(self):
        findings = [
            {"file_path": "/a.py", "title": "Issue A", "risk_score": 7, "source_analyst": "paranoid"},
            {"file_path": "/b.py", "title": "Issue B", "risk_score": 5, "source_analyst": "behaviorist"},
        ]
        result = _deduplicate_findings(findings)
        assert len(result) == 2
        for f in result:
            assert f["duplicate_count"] == 1

    def test_title_normalization_groups_variants(self):
        findings = [
            {"file_path": "/a.py", "title": "Suspicious Eval", "risk_score": 7, "source_analyst": "a"},
            {"file_path": "/a.py", "title": "suspicious  eval", "risk_score": 5, "source_analyst": "b"},
        ]
        result = _deduplicate_findings(findings)
        assert len(result) == 1
        assert result[0]["duplicate_count"] == 2

    def test_different_files_not_deduped(self):
        findings = [
            {"file_path": "/a.py", "title": "Eval", "risk_score": 7, "source_analyst": "a"},
            {"file_path": "/b.py", "title": "Eval", "risk_score": 7, "source_analyst": "b"},
        ]
        result = _deduplicate_findings(findings)
        assert len(result) == 2

    def test_empty_input(self):
        assert _deduplicate_findings([]) == []

    def test_does_not_mutate_input(self):
        findings = [
            {"file_path": "/a.py", "title": "Bad", "risk_score": 7, "source_analyst": "a"},
            {"file_path": "/a.py", "title": "Bad", "risk_score": 5, "source_analyst": "b"},
        ]
        originals = [dict(f) for f in findings]
        _deduplicate_findings(findings)
        for orig, current in zip(originals, findings, strict=True):
            assert orig == current

    def test_confidence_breaks_ties(self):
        findings = [
            {"file_path": "/a.py", "title": "Bad", "risk_score": 7, "confidence": 60, "source_analyst": "a"},
            {"file_path": "/a.py", "title": "Bad", "risk_score": 7, "confidence": 90, "source_analyst": "b"},
        ]
        result = _deduplicate_findings(findings)
        assert result[0]["confidence"] == 90
        assert result[0]["source_analysts"] == ["a", "b"]


class TestNormalizeAdversarialSchema:
    """Tests for _normalize_adversarial_schema handling analyst-forced output."""

    def test_native_schema_unchanged(self):
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
        assert result is data

    def test_analyst_forced_schema_remapped(self):
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
        data = {
            "findings": [
                {"file_path": "/a.py", "risk_score": 7, "description": "bad"},
            ],
        }
        result = _normalize_adversarial_schema(data)
        assert "results" not in result
        assert "findings" in result

    def test_empty_findings_not_remapped(self):
        data = {"findings": []}
        result = _normalize_adversarial_schema(data)
        assert "results" not in result


class TestParseAdversarialOutputSchemaDetection:
    def test_analyst_forced_schema_produces_results(self):
        data = json.dumps(
            {
                "analyst": "adversarial",
                "summary": "Reviewed findings",
                "findings": [
                    {"file_path": "/a.py", "verdict": "confirmed", "reasoning": "bad", "confidence": 90},
                    {"file_path": "/b.py", "verdict": "downgraded", "reasoning": "ok", "confidence": 80},
                ],
            }
        )
        result = _parse_adversarial_output(data)
        assert "results" in result
        assert len(result["results"]) == 2
        assert result["confirmed_count"] == 1
        assert result["downgraded_count"] == 1

    def test_native_schema_direct(self):
        data = json.dumps(
            {
                "verification_summary": "done",
                "total_reviewed": 1,
                "confirmed_count": 1,
                "downgraded_count": 0,
                "results": [{"file_path": "/a.py", "verdict": "confirmed", "reasoning": "bad"}],
            }
        )
        result = _parse_adversarial_output(data)
        assert result["total_reviewed"] == 1
        assert len(result["results"]) == 1


class TestMergeAdversarialResultsBothSchemas:
    def test_merge_with_normalized_analyst_schema(self):
        ai_findings = {
            "findings": [
                {"file_path": "/a.py", "risk_score": 7},
                {"file_path": "/b.py", "risk_score": 5},
            ]
        }
        verification = _normalize_adversarial_schema(
            {
                "summary": "Reviewed 2 findings",
                "findings": [
                    {"file_path": "/a.py", "verdict": "confirmed", "reasoning": "bad", "confidence": 90},
                    {
                        "file_path": "/b.py",
                        "verdict": "downgraded",
                        "reasoning": "ok",
                        "confidence": 80,
                        "revised_risk_score": 2,
                    },
                ],
            }
        )
        result = _merge_adversarial_results(ai_findings, verification)

        finding_a = next(f for f in result["findings"] if f["file_path"] == "/a.py")
        finding_b = next(f for f in result["findings"] if f["file_path"] == "/b.py")
        assert finding_a["adversarial_status"] == "confirmed"
        assert finding_b["adversarial_status"] == "downgraded"
        assert finding_b["risk_score"] == 2
        assert result["adversarial_verification"]["total_reviewed"] == 2
        assert result["adversarial_verification"]["confirmed_count"] == 1
        assert result["adversarial_verification"]["downgraded_count"] == 1

    def test_merge_logs_warning_on_unexpected_schema(self, caplog):
        import logging

        ai_findings = {"findings": [{"file_path": "/a.py", "risk_score": 7}]}
        verification = {"some_unexpected_key": "value", "results": []}
        with caplog.at_level(logging.WARNING):
            _merge_adversarial_results(ai_findings, verification)
        assert "unexpected schema" in caplog.text.lower()


class TestMergeNormalizedTitleMatching:
    """Tests for robust title matching in _merge_adversarial_results."""

    def test_matches_with_different_casing(self):
        ai = {
            "findings": [
                {"file_path": "/a.py", "title": "SQL Injection Risk", "risk_score": 7},
            ]
        }
        verification = {
            "results": [
                {"file_path": "/a.py", "title": "sql injection risk", "verdict": "confirmed", "confidence": 90}
            ],
            "total_reviewed": 1,
            "confirmed_count": 1,
            "downgraded_count": 0,
        }
        result = _merge_adversarial_results(ai, verification)
        assert result["findings"][0]["adversarial_status"] == "confirmed"

    def test_matches_with_extra_whitespace(self):
        ai = {
            "findings": [
                {"file_path": "/a.py", "title": "Command  Injection", "risk_score": 8},
            ]
        }
        verification = {
            "results": [
                {
                    "file_path": "/a.py",
                    "title": "Command Injection",
                    "verdict": "downgraded",
                    "revised_risk_score": 3,
                    "confidence": 85,
                }
            ],
            "total_reviewed": 1,
            "confirmed_count": 0,
            "downgraded_count": 1,
        }
        result = _merge_adversarial_results(ai, verification)
        assert result["findings"][0]["adversarial_status"] == "downgraded"

    def test_fallback_single_finding_per_file(self):
        """When one finding and one result share a file_path but titles differ,
        fall back to file_path-only matching."""
        ai = {
            "findings": [
                {"file_path": "/a.py", "title": "Hardcoded credentials detected", "risk_score": 7},
            ]
        }
        verification = {
            "results": [
                {"file_path": "/a.py", "title": "Exposed API key in source", "verdict": "confirmed", "confidence": 92}
            ],
            "total_reviewed": 1,
            "confirmed_count": 1,
            "downgraded_count": 0,
        }
        result = _merge_adversarial_results(ai, verification)
        assert result["findings"][0]["adversarial_status"] == "confirmed"

    def test_matches_paraphrased_titles_with_keyword_overlap(self):
        """When titles share significant keywords, match even if paraphrased."""
        ai = {
            "findings": [
                {"file_path": "/server.js", "title": "Hardcoded API credentials in configuration", "risk_score": 7},
                {"file_path": "/server.js", "title": "Missing input validation on user endpoint", "risk_score": 6},
            ]
        }
        verification = {
            "results": [
                {
                    "file_path": "/server.js",
                    "title": "API credentials hardcoded in config file",
                    "verdict": "confirmed",
                    "confidence": 90,
                },
                {
                    "file_path": "/server.js",
                    "title": "User endpoint lacks input validation",
                    "verdict": "downgraded",
                    "revised_risk_score": 3,
                    "confidence": 85,
                },
            ],
            "total_reviewed": 2,
            "confirmed_count": 1,
            "downgraded_count": 1,
        }
        result = _merge_adversarial_results(ai, verification)
        statuses = [f["adversarial_status"] for f in result["findings"]]
        assert "not_reviewed" not in statuses, f"Paraphrased titles should still match. Got: {statuses}"

    def test_no_fallback_when_multiple_findings_per_file(self):
        """When multiple findings share a file_path, don't use file-only fallback."""
        ai = {
            "findings": [
                {"file_path": "/a.py", "title": "Issue A", "risk_score": 7},
                {"file_path": "/a.py", "title": "Issue B", "risk_score": 6},
            ]
        }
        verification = {
            "results": [
                {"file_path": "/a.py", "title": "Something else entirely", "verdict": "confirmed", "confidence": 80}
            ],
            "total_reviewed": 1,
            "confirmed_count": 1,
            "downgraded_count": 0,
        }
        result = _merge_adversarial_results(ai, verification)
        # Neither should match — ambiguous which finding the result corresponds to
        statuses = [f["adversarial_status"] for f in result["findings"]]
        assert statuses == ["not_reviewed", "not_reviewed"]

    def test_all_findings_get_adversarial_status(self):
        """Every finding should have adversarial_status after merge."""
        ai = {
            "findings": [
                {"file_path": "/a.py", "title": "Critical bug", "risk_score": 9},
                {"file_path": "/b.py", "title": "Minor issue", "risk_score": 2},
            ]
        }
        verification = {
            "results": [{"file_path": "/a.py", "title": "Critical bug", "verdict": "confirmed", "confidence": 95}],
            "total_reviewed": 1,
            "confirmed_count": 1,
            "downgraded_count": 0,
        }
        result = _merge_adversarial_results(ai, verification)
        assert result["findings"][0]["adversarial_status"] == "confirmed"
        assert result["findings"][1]["adversarial_status"] == "not_reviewed"

    def test_adversarial_status_survives_enrichment(self):
        """End-to-end: adversarial_status should survive through enrich_all_findings."""
        from unittest.mock import patch

        from thresher.harness.report import enrich_all_findings

        ai = {
            "findings": [
                {"file_path": "/a.py", "title": "RCE", "risk_score": 9},
            ]
        }
        verification = {
            "results": [{"file_path": "/a.py", "title": "RCE", "verdict": "confirmed", "confidence": 95}],
            "total_reviewed": 1,
            "confirmed_count": 1,
            "downgraded_count": 0,
        }
        merged = _merge_adversarial_results(ai, verification)
        verified_list = merged["findings"]

        with (
            patch("thresher.report.scoring.fetch_epss_scores", return_value={}),
            patch("thresher.report.scoring.load_kev_catalog", return_value=set()),
        ):
            result = enrich_all_findings([], verified_list)

        enriched = result["findings"]
        assert len(enriched) == 1
        assert enriched[0]["adversarial_status"] == "confirmed"
        assert enriched[0]["ai_risk_score"] == 9

    def test_no_match_when_titles_completely_different(self):
        """Titles with no keyword overlap should not match even on same file."""
        ai = {
            "findings": [
                {"file_path": "/a.py", "title": "SQL injection in query builder", "risk_score": 8},
                {"file_path": "/a.py", "title": "Insecure random number generator", "risk_score": 5},
            ]
        }
        verification = {
            "results": [
                {
                    "file_path": "/a.py",
                    "title": "Memory leak in connection pool",
                    "verdict": "confirmed",
                    "confidence": 70,
                }
            ],
            "total_reviewed": 1,
            "confirmed_count": 1,
            "downgraded_count": 0,
        }
        result = _merge_adversarial_results(ai, verification)
        statuses = [f["adversarial_status"] for f in result["findings"]]
        assert statuses == ["not_reviewed", "not_reviewed"]


class TestMergeAnalystFindings:
    def test_merges_multiple_analysts(self):
        analyst_findings_list = [
            {
                "analyst": "paranoid",
                "analyst_number": 1,
                "findings": [
                    {"file_path": "/a.py", "severity": "high", "title": "Bad"},
                ],
                "summary": "Found issues",
                "risk_score": 7,
            },
            {
                "analyst": "behaviorist",
                "analyst_number": 2,
                "findings": [
                    {"file_path": "/b.py", "severity": "medium", "title": "Medium issue"},
                ],
                "summary": "Some concerns",
                "risk_score": 4,
            },
        ]
        result = _merge_analyst_findings(analyst_findings_list)
        assert len(result["findings"]) == 2
        paths = {f["file_path"] for f in result["findings"]}
        assert paths == {"/a.py", "/b.py"}

    def test_annotates_source_analyst(self):
        analyst_findings_list = [
            {
                "analyst": "paranoid",
                "analyst_number": 1,
                "findings": [{"file_path": "/a.py", "title": "Bad"}],
                "summary": "Issues",
                "risk_score": 7,
            },
        ]
        result = _merge_analyst_findings(analyst_findings_list)
        assert result["findings"][0]["source_analyst"] == "paranoid"
        assert result["findings"][0]["source_analyst_number"] == 1

    def test_empty_list_returns_empty_findings(self):
        result = _merge_analyst_findings([])
        assert result == {"findings": []}


class TestRunAdversarialVerification:
    def _valid_adversarial_output(self):
        return json.dumps(
            {
                "verification_summary": "done",
                "total_reviewed": 1,
                "confirmed_count": 1,
                "downgraded_count": 0,
                "results": [{"file_path": "/a.py", "verdict": "confirmed", "reasoning": "bad"}],
            }
        ).encode()

    def _analyst_findings_with_high_risk(self):
        return [
            {
                "analyst": "paranoid",
                "analyst_number": 1,
                "findings": [
                    {
                        "file_path": "/a.py",
                        "severity": "high",
                        "title": "Bad",
                        "description": "Very bad",
                    }
                ],
                "summary": "Found issues",
                "risk_score": 7,
            }
        ]

    def _analyst_findings_low_risk(self):
        return [
            {
                "analyst": "paranoid",
                "analyst_number": 1,
                "findings": [
                    {
                        "file_path": "/a.py",
                        "severity": "low",
                        "title": "Minor",
                        "description": "Minor issue",
                    }
                ],
                "summary": "Minor issues",
                "risk_score": 1,
            }
        ]

    @patch("thresher.run._popen")
    def test_returns_merged_findings(self, mock_popen):
        mock_popen.return_value = _mock_popen(returncode=0, stdout=self._valid_adversarial_output())

        result = run_adversarial_verification(
            _make_config(),
            analyst_findings=self._analyst_findings_with_high_risk(),
        )
        assert result is not None
        assert isinstance(result, dict)
        assert "findings" in result

    @patch("thresher.run._popen")
    def test_skips_when_no_high_risk(self, mock_popen):
        result = run_adversarial_verification(
            _make_config(),
            analyst_findings=self._analyst_findings_low_risk(),
        )
        assert result is None
        mock_popen.assert_not_called()

    @patch("thresher.run._popen")
    def test_skips_when_no_findings(self, mock_popen):
        result = run_adversarial_verification(_make_config(), analyst_findings=[])
        assert result is None
        mock_popen.assert_not_called()

    @patch("thresher.run._popen")
    def test_skips_when_findings_is_none(self, mock_popen):
        result = run_adversarial_verification(_make_config(), analyst_findings=None)
        assert result is None
        mock_popen.assert_not_called()

    @patch("thresher.run._popen")
    def test_uses_correct_max_turns(self, mock_popen):
        mock_popen.return_value = _mock_popen(returncode=0, stdout=self._valid_adversarial_output())

        config = _make_config()
        config.adversarial_max_turns = 35
        run_adversarial_verification(
            config,
            analyst_findings=self._analyst_findings_with_high_risk(),
        )

        cmd = mock_popen.call_args[0][0]
        idx = cmd.index("--max-turns")
        assert cmd[idx + 1] == "35"

    @patch("thresher.run._popen")
    def test_default_20_turns(self, mock_popen):
        mock_popen.return_value = _mock_popen(returncode=0, stdout=self._valid_adversarial_output())

        config = _make_config()
        assert config.adversarial_max_turns is None
        run_adversarial_verification(
            config,
            analyst_findings=self._analyst_findings_with_high_risk(),
        )

        cmd = mock_popen.call_args[0][0]
        idx = cmd.index("--max-turns")
        assert cmd[idx + 1] == "20"

    @patch("thresher.run._popen")
    def test_api_key_in_env(self, mock_popen):
        mock_popen.return_value = _mock_popen(returncode=0, stdout=self._valid_adversarial_output())

        run_adversarial_verification(
            _make_config(),
            analyst_findings=self._analyst_findings_with_high_risk(),
        )

        call_kwargs = mock_popen.call_args[1]
        env = call_kwargs.get("env", {})
        assert "ANTHROPIC_API_KEY" in env

    @patch("thresher.run._popen")
    def test_handles_subprocess_failure(self, mock_popen):
        mock_popen.side_effect = RuntimeError("subprocess died")

        result = run_adversarial_verification(
            _make_config(),
            analyst_findings=self._analyst_findings_with_high_risk(),
        )
        assert result is None

    @patch("thresher.run._popen")
    def test_writes_markdown_when_output_dir_provided(self, mock_popen, tmp_path):
        """When output_dir is provided, an adversarial-verification.md is
        written next to the report so the verification work is visible."""
        mock_popen.return_value = _mock_popen(
            returncode=0,
            stdout=self._valid_adversarial_output(),
        )
        run_adversarial_verification(
            _make_config(),
            analyst_findings=self._analyst_findings_with_high_risk(),
            output_dir=str(tmp_path),
        )
        md_path = tmp_path / "adversarial-verification.md"
        assert md_path.exists(), "adversarial-verification.md not written"
        body = md_path.read_text()
        assert "Adversarial Verification" in body

    @patch("thresher.run._popen")
    def test_no_markdown_when_no_output_dir(self, mock_popen, tmp_path):
        """Without output_dir, no markdown file should be written anywhere."""
        mock_popen.return_value = _mock_popen(
            returncode=0,
            stdout=self._valid_adversarial_output(),
        )
        run_adversarial_verification(
            _make_config(),
            analyst_findings=self._analyst_findings_with_high_risk(),
        )
        # Confirm no markdown got written into tmp_path
        assert list(tmp_path.glob("*.md")) == []
