"""Tests for threat_scanner.report.synthesize."""

from __future__ import annotations

from threat_scanner.report.synthesize import (
    _build_template_context,
    _collect_findings,
    _build_synthesis_input,
    PRIORITY_ORDER,
)
from threat_scanner.config import ScanConfig


class TestCollectFindings:
    def test_scanner_dict(self):
        scanner = {
            "grype": [{"id": "g1", "severity": "high"}],
            "semgrep": [{"id": "s1", "severity": "medium"}],
        }
        findings = _collect_findings(scanner, None)
        assert len(findings) == 2

    def test_ai_findings_mapped(self):
        scanner = {"grype": []}
        ai = {
            "findings": [
                {
                    "file_path": "/a.py",
                    "risk_score": 7,
                    "findings": [
                        {"confidence": 85, "description": "bad"},
                        {"confidence": 60, "description": "maybe"},
                    ],
                }
            ]
        }
        findings = _collect_findings(scanner, ai)
        assert len(findings) == 1
        af = findings[0]
        assert af["ai_risk_score"] == 7
        assert af["source_tool"] == "ai_analysis"
        assert af["ai_confidence"] == 85  # max of sub-findings

    def test_no_ai(self):
        scanner = {"grype": [{"id": "g1"}]}
        findings = _collect_findings(scanner, None)
        assert len(findings) == 1

    def test_ai_no_duplicate_source_tool(self):
        ai = {
            "findings": [
                {"file_path": "/a.py", "risk_score": 5, "source_tool": "custom", "findings": []}
            ]
        }
        findings = _collect_findings({}, ai)
        # Should keep existing source_tool, not overwrite
        assert findings[0]["source_tool"] == "custom"


class TestBuildTemplateContext:
    def _make_config(self, **kw):
        defaults = dict(
            repo_url="https://github.com/x/y",
            depth=2,
            skip_ai=False,
            verbose=False,
            output_dir="./out",
        )
        defaults.update(kw)
        return ScanConfig(**defaults)

    def test_do_not_use(self):
        enriched = [{"composite_priority": "critical", "package_name": "x"}]
        ctx = _build_template_context(self._make_config(), enriched, {})
        assert ctx["risk_assessment"] == "DO NOT USE"

    def test_caution(self):
        enriched = [{"composite_priority": "high", "package_name": "x"}]
        ctx = _build_template_context(self._make_config(), enriched, {})
        assert ctx["risk_assessment"] == "CAUTION"

    def test_go(self):
        enriched = [{"composite_priority": "medium", "package_name": "x"}]
        ctx = _build_template_context(self._make_config(), enriched, {})
        assert ctx["risk_assessment"] == "GO"

    def test_p0_is_do_not_use(self):
        enriched = [{"composite_priority": "P0", "package_name": "x"}]
        ctx = _build_template_context(self._make_config(), enriched, {})
        assert ctx["risk_assessment"] == "DO NOT USE"

    def test_top_10(self):
        enriched = [
            {"composite_priority": "medium", "package_name": f"pkg{i}"}
            for i in range(15)
        ]
        ctx = _build_template_context(self._make_config(), enriched, {})
        assert len(ctx["top_findings"]) == 10

    def test_priority_counts(self):
        enriched = [
            {"composite_priority": "high"},
            {"composite_priority": "high"},
            {"composite_priority": "low"},
        ]
        ctx = _build_template_context(self._make_config(), enriched, {})
        assert ctx["priority_counts"]["high"] == 2
        assert ctx["priority_counts"]["low"] == 1
        assert ctx["total_findings"] == 3


class TestBuildSynthesisInput:
    def test_contains_priority_counts(self):
        enriched = [
            {"composite_priority": "critical", "source_tool": "grype"},
            {"composite_priority": "low", "source_tool": "semgrep"},
        ]
        text = _build_synthesis_input({}, None, enriched)
        assert "CRITICAL" in text
        assert "LOW" in text

    def test_contains_tool_coverage(self):
        enriched = [
            {"composite_priority": "low", "source_tool": "grype"},
            {"composite_priority": "low", "source_tool": "grype"},
            {"composite_priority": "low", "source_tool": "semgrep"},
        ]
        text = _build_synthesis_input({}, None, enriched)
        assert "grype" in text
        assert "semgrep" in text

    def test_contains_json(self):
        enriched = [{"composite_priority": "low", "source_tool": "t", "id": "x"}]
        text = _build_synthesis_input({}, None, enriched)
        assert "```json" in text
