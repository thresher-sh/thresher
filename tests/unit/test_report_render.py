"""Tests for the Jinja report render function and fallback report builder."""

import json
from pathlib import Path


def _valid_report_data():
    """Minimal valid report data dict."""
    return {
        "meta": {
            "scan_date": "2026-04-02",
            "thresher_version": "v0.2.2",
            "scanner_count": "22",
            "analyst_count": "8",
            "repo_name": "owner/repo",
            "repo_url": "https://github.com/owner/repo",
        },
        "verdict": {"label": "LOW RISK", "severity": "low", "callout": "No issues."},
        "counts": {
            "total_scanner": "0",
            "total_ai": "0",
            "p0": "0",
            "critical": "0",
            "high_scanner": "0",
            "high_ai": "0",
            "medium": "0",
            "low": "0",
        },
        "executive_summary": "<p>Clean scan.</p>",
        "mitigations": [],
        "scanner_findings": [],
        "ai_findings": [],
        "trust_signals": [],
        "dependency_upgrades": [],
        "remediation": None,
        "pipeline": {"scanners": ["grype"], "analysts": [], "notes": ""},
        "config": {"show_cta": "true", "show_remediation": "false"},
    }


def test_render_report_produces_html(tmp_path):
    from thresher.harness.report import render_report

    output = render_report(_valid_report_data(), str(tmp_path))
    html_path = Path(output)
    assert html_path.exists()
    content = html_path.read_text()
    assert "<!DOCTYPE html>" in content
    assert "owner/repo" in content


def test_render_report_embeds_json(tmp_path):
    from thresher.harness.report import render_report

    data = _valid_report_data()
    output = render_report(data, str(tmp_path))
    content = Path(output).read_text()
    assert '"scan_date"' in content
    assert '"LOW RISK"' in content


def test_render_report_with_findings(tmp_path):
    from thresher.harness.report import render_report

    data = _valid_report_data()
    data["scanner_findings"] = [
        {
            "rank": "1",
            "severity": "critical",
            "package": "foo@1.0",
            "title": "Bad vuln",
            "cve": "CVE-2026-9999",
            "cvss": "9.8",
        }
    ]
    output = render_report(data, str(tmp_path))
    content = Path(output).read_text()
    assert "CVE-2026-9999" in content


def test_render_report_null_remediation(tmp_path):
    from thresher.harness.report import render_report

    data = _valid_report_data()
    data["remediation"] = None
    output = render_report(data, str(tmp_path))
    content = Path(output).read_text()
    assert "<!DOCTYPE html>" in content


def test_build_fallback_report_data_minimal():
    from thresher.config import ScanConfig
    from thresher.harness.report import build_fallback_report_data

    config = ScanConfig(repo_url="https://github.com/owner/repo")
    findings = []
    data = build_fallback_report_data(config, findings)

    assert data["meta"]["repo_name"] == "owner/repo"
    assert data["verdict"]["severity"] == "low"
    assert data["counts"]["critical"] == "0"
    assert data["remediation"] is None
    assert data["config"]["show_remediation"] == "false"


def test_build_fallback_report_data_with_critical():
    from thresher.config import ScanConfig
    from thresher.harness.report import build_fallback_report_data

    config = ScanConfig(repo_url="https://github.com/owner/repo")
    findings = [
        {
            "id": "1",
            "source_tool": "grype",
            "category": "sca",
            "severity": "critical",
            "title": "Bad vuln",
            "description": "Very bad",
            "cvss_score": 9.8,
            "cve_id": "CVE-2026-1234",
            "package_name": "foo",
            "package_version": "1.0",
            "fix_version": "2.0",
            "composite_priority": "critical",
        },
    ]
    data = build_fallback_report_data(config, findings)

    assert data["verdict"]["severity"] == "critical"
    assert data["counts"]["critical"] == "1"
    assert len(data["scanner_findings"]) == 1
    assert data["scanner_findings"][0]["cvss"] == "9.8"


def test_build_fallback_validates_against_schema():
    """Fallback output must pass the JSON schema."""
    from jsonschema import validate

    from thresher.config import ScanConfig
    from thresher.harness.report import build_fallback_report_data

    schema_path = Path(__file__).parent.parent.parent / "src" / "thresher" / "report" / "schema" / "report_schema.json"
    schema = json.loads(schema_path.read_text())
    config = ScanConfig(repo_url="https://github.com/owner/repo")
    data = build_fallback_report_data(config, [])
    validate(instance=data, schema=schema)


class TestTemplateFieldCompatibility:
    """The JS template reads fields from REPORT_DATA. These tests verify
    the injected JSON uses field names the template actually reads."""

    def _render_and_extract_data(self, tmp_path, data_overrides=None):
        from thresher.harness.report import render_report

        data = _valid_report_data()
        data["verdict"] = {
            "label": "FIX BEFORE USE",
            "severity": "critical",
            "callout": "Critical vuln found.",
        }
        data["counts"]["critical"] = "1"
        data["scanner_findings"] = [
            {
                "rank": "1",
                "severity": "critical",
                "package": "foo@1.0",
                "title": "Bad vuln",
                "cve": "CVE-2026-9999",
                "cvss": "9.8",
            }
        ]
        data["ai_findings"] = [
            {
                "severity": "high",
                "title": "Suspicious eval()",
                "file": "src/app.js",
                "description": "Dynamic code execution from user input.",
                "confidence": "85",
                "analysts": ["pentester-vulns"],
            }
        ]
        data["trust_signals"] = [
            {"icon": "check", "text": "Signed commits"},
            {"icon": "shield", "text": "8 AI analysts"},
        ]
        data["dependency_upgrades"] = [
            {
                "package": "foo",
                "old_version": "1.0",
                "new_version": "2.0",
                "severity": "critical",
                "cvss": "9.8",
                "cves": "CVE-2026-9999",
            }
        ]
        data["mitigations"] = [
            "Upgrade foo to 2.0",
            "Remove eval() from src/app.js",
        ]
        if data_overrides:
            data.update(data_overrides)
        html_path = render_report(data, str(tmp_path))
        html = Path(html_path).read_text()
        report_data_json = Path(html_path).parent / "report_data.json"
        injected = json.loads(report_data_json.read_text())
        return html, injected

    def test_injected_data_has_verdict_label(self, tmp_path):
        _, data = self._render_and_extract_data(tmp_path)
        assert data["verdict"]["label"] == "FIX BEFORE USE"

    def test_injected_data_meta_fields_match_schema(self, tmp_path):
        _, data = self._render_and_extract_data(tmp_path)
        meta = data["meta"]
        assert "repo_name" in meta
        assert "thresher_version" in meta
        assert "scanner_count" in meta
        assert "analyst_count" in meta

    def test_injected_trust_signals_are_objects_with_text(self, tmp_path):
        _, data = self._render_and_extract_data(tmp_path)
        for signal in data["trust_signals"]:
            assert isinstance(signal, dict)
            assert "text" in signal

    def test_injected_dependency_upgrades_use_schema_fields(self, tmp_path):
        _, data = self._render_and_extract_data(tmp_path)
        for u in data["dependency_upgrades"]:
            assert "old_version" in u
            assert "new_version" in u
            assert "severity" in u

    def test_js_template_reads_verdict_label(self):
        template = (
            Path(__file__).parent.parent.parent / "src" / "thresher" / "report" / "templates" / "template_report.html"
        )
        src = template.read_text()
        assert "v.label" in src, "JS template must read verdict.label (not v.text)"

    def test_js_template_reads_repo_name(self):
        template = (
            Path(__file__).parent.parent.parent / "src" / "thresher" / "report" / "templates" / "template_report.html"
        )
        src = template.read_text()
        assert "m.repo_name" in src, "JS template must read meta.repo_name"

    def test_js_template_reads_thresher_version(self):
        template = (
            Path(__file__).parent.parent.parent / "src" / "thresher" / "report" / "templates" / "template_report.html"
        )
        src = template.read_text()
        assert "m.thresher_version" in src, "JS template must read meta.thresher_version"

    def test_js_template_reads_scanner_count(self):
        template = (
            Path(__file__).parent.parent.parent / "src" / "thresher" / "report" / "templates" / "template_report.html"
        )
        src = template.read_text()
        assert "m.scanner_count" in src, "JS template must read meta.scanner_count"

    def test_js_template_reads_analyst_count(self):
        template = (
            Path(__file__).parent.parent.parent / "src" / "thresher" / "report" / "templates" / "template_report.html"
        )
        src = template.read_text()
        assert "m.analyst_count" in src, "JS template must read meta.analyst_count"

    def test_js_template_reads_old_version_not_previous(self):
        template = (
            Path(__file__).parent.parent.parent / "src" / "thresher" / "report" / "templates" / "template_report.html"
        )
        src = template.read_text()
        assert "u.old_version" in src, "JS template must read old_version (not u.previous)"

    def test_js_template_reads_new_version_not_fixed(self):
        template = (
            Path(__file__).parent.parent.parent / "src" / "thresher" / "report" / "templates" / "template_report.html"
        )
        src = template.read_text()
        assert "u.new_version" in src, "JS template must read new_version (not u.fixed)"

    def test_js_template_handles_trust_signal_objects(self):
        template = (
            Path(__file__).parent.parent.parent / "src" / "thresher" / "report" / "templates" / "template_report.html"
        )
        src = template.read_text()
        assert ".text" in src, "JS template must read .text from trust signal objects"

    def test_js_template_computes_ai_counts_from_findings(self):
        template = (
            Path(__file__).parent.parent.parent / "src" / "thresher" / "report" / "templates" / "template_report.html"
        )
        src = template.read_text()
        assert "ai_crit" not in src or "d.ai_findings" in src, (
            "JS template must compute AI counts from ai_findings array, not read non-existent counts fields"
        )

    def test_cta_hidden_for_scan_reports(self, tmp_path):
        _, data = self._render_and_extract_data(
            tmp_path,
            {"config": {"show_cta": "false", "show_remediation": "false"}},
        )
        assert data["config"]["show_cta"] == "false"

    def test_mitigations_section_after_upgrades(self):
        template = (
            Path(__file__).parent.parent.parent / "src" / "thresher" / "report" / "templates" / "template_report.html"
        )
        src = template.read_text()
        upgrades_pos = src.find("renderUpgrades")
        mitigations_pos = src.find("renderMitigations")
        assert mitigations_pos > 0, "JS template must have a renderMitigations function"
        if upgrades_pos > 0:
            assert mitigations_pos > upgrades_pos, "Mitigations section must render after upgrades"


class TestVerdictLogic:
    def test_fallback_critical_is_fix_before_use_not_do_not_use(self):
        from thresher.config import ScanConfig
        from thresher.harness.report import build_fallback_report_data

        config = ScanConfig(repo_url="https://github.com/owner/repo")
        findings = [
            {
                "source_tool": "grype",
                "category": "sca",
                "severity": "critical",
                "title": "Vuln",
                "description": "",
                "composite_priority": "critical",
            }
        ]
        data = build_fallback_report_data(config, findings)
        assert data["verdict"]["label"] == "FIX BEFORE USE"
        assert data["verdict"]["label"] != "DO NOT USE"

    def test_fallback_show_cta_is_false(self):
        from thresher.config import ScanConfig
        from thresher.harness.report import build_fallback_report_data

        config = ScanConfig(repo_url="https://github.com/owner/repo")
        data = build_fallback_report_data(config, [])
        assert data["config"]["show_cta"] == "false"
