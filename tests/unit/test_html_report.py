"""Tests for HTML report context helpers in thresher.report.synthesize."""

from __future__ import annotations

import importlib.metadata

from thresher.report.synthesize import (
    _build_upgrade_packages,
    _split_findings_by_source,
    _build_template_context,
    PRIORITY_ORDER,
)
from thresher.config import ScanConfig


def _make_config(**kw):
    defaults = dict(
        repo_url="https://github.com/x/y",
        depth=2,
        skip_ai=False,
        verbose=False,
        output_dir="./out",
    )
    defaults.update(kw)
    return ScanConfig(**defaults)


class TestBuildUpgradePackages:
    def test_basic_finding_with_fix_version_is_included(self):
        enriched = [
            {
                "package_name": "requests",
                "package_version": "2.0.0",
                "fix_version": "2.28.0",
                "composite_priority": "high",
                "cvss_score": 7.5,
                "cve_ids": ["CVE-2023-1234"],
            }
        ]
        result = _build_upgrade_packages(enriched)
        assert len(result) == 1
        assert result[0]["package_name"] == "requests"
        assert result[0]["fix_version"] == "2.28.0"
        assert result[0]["composite_priority"] == "high"

    def test_finding_without_fix_version_is_excluded(self):
        enriched = [
            {
                "package_name": "requests",
                "package_version": "2.0.0",
                "composite_priority": "high",
                "cvss_score": 7.5,
                "cve_ids": [],
            }
        ]
        result = _build_upgrade_packages(enriched)
        assert result == []

    def test_same_package_deduped_keeps_highest_severity(self):
        enriched = [
            {
                "package_name": "requests",
                "package_version": "2.0.0",
                "fix_version": "2.28.0",
                "composite_priority": "medium",
                "cvss_score": 5.0,
                "cve_ids": ["CVE-2023-0001"],
            },
            {
                "package_name": "requests",
                "package_version": "2.0.0",
                "fix_version": "2.28.0",
                "composite_priority": "critical",
                "cvss_score": 9.1,
                "cve_ids": ["CVE-2023-0002"],
            },
        ]
        result = _build_upgrade_packages(enriched)
        assert len(result) == 1
        assert result[0]["composite_priority"] == "critical"

    def test_same_package_collects_all_cve_ids(self):
        enriched = [
            {
                "package_name": "requests",
                "package_version": "2.0.0",
                "fix_version": "2.28.0",
                "composite_priority": "high",
                "cvss_score": 7.5,
                "cve_ids": ["CVE-2023-0001"],
            },
            {
                "package_name": "requests",
                "package_version": "2.0.0",
                "fix_version": "2.28.0",
                "composite_priority": "medium",
                "cvss_score": 5.0,
                "cve_ids": ["CVE-2023-0002"],
            },
        ]
        result = _build_upgrade_packages(enriched)
        assert len(result) == 1
        cve_ids = result[0]["cve_ids"]
        assert "CVE-2023-0001" in cve_ids
        assert "CVE-2023-0002" in cve_ids

    def test_sorted_by_severity_highest_first(self):
        enriched = [
            {
                "package_name": "pkg-low",
                "package_version": "1.0",
                "fix_version": "2.0",
                "composite_priority": "low",
                "cvss_score": 2.0,
                "cve_ids": [],
            },
            {
                "package_name": "pkg-critical",
                "package_version": "1.0",
                "fix_version": "2.0",
                "composite_priority": "critical",
                "cvss_score": 9.8,
                "cve_ids": [],
            },
            {
                "package_name": "pkg-medium",
                "package_version": "1.0",
                "fix_version": "2.0",
                "composite_priority": "medium",
                "cvss_score": 5.5,
                "cve_ids": [],
            },
        ]
        result = _build_upgrade_packages(enriched)
        assert len(result) == 3
        priorities = [r["composite_priority"] for r in result]
        assert priorities == ["critical", "medium", "low"]

    def test_empty_input_returns_empty_list(self):
        assert _build_upgrade_packages([]) == []

    def test_result_has_required_keys(self):
        enriched = [
            {
                "package_name": "flask",
                "package_version": "1.0.0",
                "fix_version": "2.0.0",
                "composite_priority": "high",
                "cvss_score": 8.0,
                "cve_ids": ["CVE-2023-9999"],
            }
        ]
        result = _build_upgrade_packages(enriched)
        assert len(result) == 1
        r = result[0]
        assert "package_name" in r
        assert "package_version" in r
        assert "fix_version" in r
        assert "composite_priority" in r
        assert "cvss_score" in r
        assert "cve_ids" in r

    def test_cve_ids_deduplicated(self):
        enriched = [
            {
                "package_name": "requests",
                "package_version": "2.0.0",
                "fix_version": "2.28.0",
                "composite_priority": "high",
                "cvss_score": 7.5,
                "cve_ids": ["CVE-2023-0001", "CVE-2023-0001"],
            },
        ]
        result = _build_upgrade_packages(enriched)
        assert result[0]["cve_ids"].count("CVE-2023-0001") == 1


class TestSplitFindingsBySource:
    def test_separates_ai_from_scanner_findings(self):
        enriched = [
            {"id": "s1", "source_tool": "grype", "composite_priority": "high"},
            {"id": "a1", "source_tool": "ai_analysis", "composite_priority": "critical"},
            {"id": "s2", "source_tool": "semgrep", "composite_priority": "medium"},
        ]
        scanner, ai = _split_findings_by_source(enriched)
        assert len(scanner) == 2
        assert len(ai) == 1
        assert ai[0]["id"] == "a1"

    def test_empty_input_returns_two_empty_lists(self):
        scanner, ai = _split_findings_by_source([])
        assert scanner == []
        assert ai == []

    def test_no_ai_findings_all_go_to_scanner(self):
        enriched = [
            {"id": "s1", "source_tool": "grype"},
            {"id": "s2", "source_tool": "trivy"},
        ]
        scanner, ai = _split_findings_by_source(enriched)
        assert len(scanner) == 2
        assert ai == []

    def test_all_ai_findings_go_to_ai(self):
        enriched = [
            {"id": "a1", "source_tool": "ai_analysis"},
            {"id": "a2", "source_tool": "ai_analysis"},
        ]
        scanner, ai = _split_findings_by_source(enriched)
        assert scanner == []
        assert len(ai) == 2

    def test_scanner_plus_ai_count_equals_total(self):
        enriched = [
            {"id": "s1", "source_tool": "grype"},
            {"id": "a1", "source_tool": "ai_analysis"},
            {"id": "s2", "source_tool": "bandit"},
            {"id": "a2", "source_tool": "ai_analysis"},
        ]
        scanner, ai = _split_findings_by_source(enriched)
        assert len(scanner) + len(ai) == len(enriched)


class TestExtendedTemplateContext:
    def _make_enriched(self):
        return [
            {"id": "s1", "source_tool": "grype", "composite_priority": "high",
             "package_name": "pkg-a"},
            {"id": "s2", "source_tool": "semgrep", "composite_priority": "medium",
             "package_name": "pkg-b"},
            {"id": "a1", "source_tool": "ai_analysis", "composite_priority": "critical",
             "package_name": "pkg-c"},
            {"id": "a2", "source_tool": "ai_analysis", "composite_priority": "high",
             "package_name": "pkg-d"},
        ]

    def test_scanner_finding_counts_excludes_ai(self):
        config = _make_config()
        enriched = self._make_enriched()
        ctx = _build_template_context(config, enriched, {})
        counts = ctx["scanner_finding_counts"]
        # grype(high) + semgrep(medium) — no ai_analysis
        assert counts.get("high", 0) == 1
        assert counts.get("medium", 0) == 1
        assert counts.get("critical", 0) == 0

    def test_ai_finding_counts_includes_only_ai(self):
        config = _make_config()
        enriched = self._make_enriched()
        ctx = _build_template_context(config, enriched, {})
        counts = ctx["ai_finding_counts"]
        assert counts.get("critical", 0) == 1
        assert counts.get("high", 0) == 1
        assert counts.get("medium", 0) == 0

    def test_ai_findings_grouped_by_priority(self):
        config = _make_config()
        enriched = self._make_enriched()
        ctx = _build_template_context(config, enriched, {})
        grouped = ctx["ai_findings_grouped"]
        assert isinstance(grouped, dict)
        assert len(grouped.get("critical", [])) == 1
        assert len(grouped.get("high", [])) == 1
        assert grouped["critical"][0]["id"] == "a1"

    def test_upgrade_packages_key_exists(self):
        config = _make_config()
        enriched = self._make_enriched()
        ctx = _build_template_context(config, enriched, {})
        assert "upgrade_packages" in ctx
        assert isinstance(ctx["upgrade_packages"], list)

    def test_upgrade_packages_only_includes_fixable(self):
        config = _make_config()
        enriched = [
            {"id": "s1", "source_tool": "grype", "composite_priority": "high",
             "package_name": "pkg-a", "fix_version": "2.0.0",
             "package_version": "1.0.0", "cvss_score": 7.0, "cve_ids": []},
            {"id": "s2", "source_tool": "grype", "composite_priority": "medium",
             "package_name": "pkg-b"},  # no fix_version
        ]
        ctx = _build_template_context(config, enriched, {})
        packages = ctx["upgrade_packages"]
        names = [p["package_name"] for p in packages]
        assert "pkg-a" in names
        assert "pkg-b" not in names

    def test_thresher_version_key_exists_and_is_string(self):
        config = _make_config()
        ctx = _build_template_context(config, [], {})
        assert "thresher_version" in ctx
        assert isinstance(ctx["thresher_version"], str)

    def test_fix_metadata_is_empty_dict(self):
        config = _make_config()
        ctx = _build_template_context(config, [], {})
        assert ctx["fix_metadata"] == {}

    def test_trust_signals_is_empty_list(self):
        config = _make_config()
        ctx = _build_template_context(config, [], {})
        assert ctx["trust_signals"] == []

    def test_agent_executive_summary_is_none(self):
        config = _make_config()
        ctx = _build_template_context(config, [], {})
        assert ctx["agent_executive_summary"] is None

    def test_agent_synthesis_is_none(self):
        config = _make_config()
        ctx = _build_template_context(config, [], {})
        assert ctx["agent_synthesis"] is None

    def test_all_new_keys_present(self):
        config = _make_config()
        ctx = _build_template_context(config, [], {})
        new_keys = [
            "scanner_finding_counts",
            "ai_finding_counts",
            "ai_findings_grouped",
            "upgrade_packages",
            "thresher_version",
            "fix_metadata",
            "trust_signals",
            "agent_executive_summary",
            "agent_synthesis",
        ]
        for key in new_keys:
            assert key in ctx, f"Missing key: {key}"

    def test_ai_findings_grouped_uses_priority_order(self):
        config = _make_config()
        enriched = [
            {"id": "a1", "source_tool": "ai_analysis", "composite_priority": "low"},
            {"id": "a2", "source_tool": "ai_analysis", "composite_priority": "high"},
        ]
        ctx = _build_template_context(config, enriched, {})
        grouped = ctx["ai_findings_grouped"]
        # All PRIORITY_ORDER keys should be present (even empty lists)
        for p in PRIORITY_ORDER:
            assert p in grouped


# ---------------------------------------------------------------------------
# HTML template rendering tests
# ---------------------------------------------------------------------------

from markupsafe import Markup

from thresher.report.synthesize import _render_html_report


def _minimal_context(**overrides):
    ctx = {
        "scan_date": "2026-04-03 12:00:00 UTC",
        "repo_url": "https://github.com/test/repo",
        "depth": 2,
        "skip_ai": False,
        "risk_assessment": "GO",
        "priority_counts": {"P0": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        "total_findings": 0,
        "top_findings": [],
        "findings_by_priority": {},
        "priority_order": ["P0", "critical", "high", "medium", "low"],
        "tools": {},
        "total_packages": 0,
        "ecosystems": [],
        "config": None,
        "scanner_finding_counts": {},
        "ai_finding_counts": {},
        "ai_findings_grouped": {},
        "upgrade_packages": [],
        "thresher_version": "0.2.2",
        "fix_metadata": {},
        "trust_signals": [],
        "agent_executive_summary": None,
        "agent_synthesis": None,
    }
    ctx.update(overrides)
    return ctx


class TestHtmlTemplateRendering:
    def test_renders_without_error(self):
        html = _render_html_report(_minimal_context())
        assert "<!DOCTYPE html>" in html
        assert "test/repo" in html

    def test_zero_findings(self):
        html = _render_html_report(_minimal_context(total_findings=0))
        assert "<!DOCTYPE html>" in html
        # Should render cleanly without any error
        assert "test/repo" in html

    def test_verdict_do_not_use(self):
        html = _render_html_report(_minimal_context(risk_assessment="DO NOT USE"))
        assert "DO NOT USE" in html
        assert "threat-red" in html

    def test_verdict_caution(self):
        html = _render_html_report(_minimal_context(risk_assessment="CAUTION"))
        assert "CAUTION" in html
        assert "amber" in html

    def test_verdict_go(self):
        html = _render_html_report(_minimal_context(risk_assessment="GO"))
        assert "GO" in html
        assert "safe-green" in html

    def test_ai_section_hidden_when_skip_ai(self):
        html = _render_html_report(_minimal_context(skip_ai=True))
        assert "AI Analyst Findings" not in html

    def test_ai_section_shown_with_findings(self):
        ai_grouped = {
            "P0": [],
            "critical": [
                {
                    "title": "IDOR Vulnerability",
                    "file_path": "src/handlers.ts:42",
                    "description": "Missing ownership check",
                    "ai_confidence": 95,
                    "composite_priority": "critical",
                }
            ],
            "high": [],
            "medium": [],
            "low": [],
        }
        html = _render_html_report(
            _minimal_context(
                ai_findings_grouped=ai_grouped,
                ai_finding_counts={"critical": 1},
            )
        )
        assert "AI Analyst Findings" in html
        assert "IDOR Vulnerability" in html

    def test_upgrade_section_hidden_when_empty(self):
        html = _render_html_report(_minimal_context(upgrade_packages=[]))
        assert "Dependency Upgrades" not in html

    def test_upgrade_section_shown(self):
        packages = [
            {
                "package_name": "requests",
                "package_version": "2.0.0",
                "fix_version": "2.28.0",
                "composite_priority": "high",
                "cvss_score": 7.5,
                "cve_ids": ["CVE-2023-1234"],
            }
        ]
        html = _render_html_report(_minimal_context(upgrade_packages=packages))
        assert "Dependency Upgrades" in html
        assert "requests" in html
        assert "2.28.0" in html

    def test_fix_section_hidden_when_empty(self):
        html = _render_html_report(_minimal_context(fix_metadata={}))
        assert "what was fixed" not in html.lower()

    def test_trust_section_hidden_when_empty(self):
        html = _render_html_report(_minimal_context(trust_signals=[]))
        assert "Trust Assessment" not in html

    def test_html_escaping(self):
        html = _render_html_report(
            _minimal_context(repo_url="<script>alert('xss')</script>")
        )
        assert "&lt;script&gt;" in html
        assert "<script>alert" not in html

    def test_agent_narrative_used(self):
        narrative = Markup("<p>Agent found <strong>serious issues</strong>.</p>")
        html = _render_html_report(
            _minimal_context(agent_executive_summary=narrative)
        )
        # Should render unescaped (raw HTML)
        assert "<p>Agent found <strong>serious issues</strong>.</p>" in html

    def test_agent_synthesis_shown(self):
        synthesis = Markup("<p>Synthesis analysis content.</p>")
        html = _render_html_report(
            _minimal_context(agent_synthesis=synthesis)
        )
        assert "<p>Synthesis analysis content.</p>" in html
        assert "Synthesis Analysis" in html

    def test_scanner_findings_table(self):
        findings = [
            {
                "title": "Path Traversal in rollup",
                "composite_priority": "critical",
                "cve_id": "CVE-2026-27606",
                "cvss_score": 9.8,
            }
        ]
        html = _render_html_report(_minimal_context(top_findings=findings))
        assert "Path Traversal in rollup" in html
        assert "CVE-2026-27606" in html

    def test_distribution_bar_counts(self):
        html = _render_html_report(
            _minimal_context(
                scanner_finding_counts={"critical": 2, "high": 5},
            )
        )
        assert "CRIT" in html

    def test_pipeline_section_shows_tools(self):
        tools = {
            "grype": {"exit_code": 0, "duration": 12.5},
            "semgrep": {"exit_code": 0, "duration": 8.3},
        }
        html = _render_html_report(_minimal_context(tools=tools))
        assert "grype" in html
        assert "semgrep" in html
