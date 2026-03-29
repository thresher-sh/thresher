"""Integration tests for report generation pipeline."""

from __future__ import annotations

from unittest.mock import patch, call

from threat_scanner.config import ScanConfig
from threat_scanner.report.synthesize import generate_report
from threat_scanner.vm.ssh import SSHResult


def _make_config(**kw) -> ScanConfig:
    defaults = dict(
        repo_url="https://github.com/x/y",
        anthropic_api_key="key",
        skip_ai=True,
    )
    defaults.update(kw)
    return ScanConfig(**defaults)


class TestGenerateReport:
    @patch("threat_scanner.report.synthesize.ssh_write_file")
    @patch("threat_scanner.report.synthesize.ssh_exec")
    @patch("threat_scanner.report.scoring.load_kev_catalog")
    @patch("threat_scanner.report.scoring.fetch_epss_scores")
    def test_skip_ai_template_report(self, mock_epss, mock_kev, mock_exec, mock_write):
        mock_epss.return_value = {}
        mock_kev.return_value = set()
        mock_exec.return_value = SSHResult("", "", 0)
        mock_write.return_value = None

        scanner_results = {
            "grype": [
                {
                    "id": "g1",
                    "severity": "high",
                    "cve_id": "CVE-2024-1",
                    "cvss_score": 7.5,
                    "title": "Vuln in pkg",
                    "source_tool": "grype",
                }
            ]
        }

        config = _make_config(skip_ai=True)
        report_path = generate_report("vm", config, scanner_results, None)

        # Report path should be under /opt/security-reports/
        assert report_path.startswith("/opt/security-reports/")

        # ssh_write_file should have been called for:
        # findings.json, executive-summary.md, detailed-report.md
        write_calls = mock_write.call_args_list
        remote_paths = [c[0][2] for c in write_calls]
        assert any("findings.json" in p for p in remote_paths)
        assert any("executive-summary.md" in p for p in remote_paths)
        assert any("detailed-report.md" in p for p in remote_paths)

    @patch("threat_scanner.report.synthesize.ssh_write_file")
    @patch("threat_scanner.report.synthesize.ssh_exec")
    @patch("threat_scanner.report.scoring.load_kev_catalog")
    @patch("threat_scanner.report.scoring.fetch_epss_scores")
    def test_agent_fallback_on_failure(self, mock_epss, mock_kev, mock_exec, mock_write):
        mock_epss.return_value = {}
        mock_kev.return_value = set()
        mock_write.return_value = None

        # First exec calls succeed (mkdir, cp), Claude agent succeeds but
        # verification of output files fails, then template fallback succeeds
        mock_exec.side_effect = [
            SSHResult("", "", 0),  # mkdir
            SSHResult("", "", 0),  # cp scan-results
            SSHResult("", "", 0),  # cp sbom
            SSHResult("", "", 0),  # claude invocation
            SSHResult("", "", 1),  # test -f check fails (agent didn't write files)
        ]

        config = _make_config(skip_ai=False)
        report_path = generate_report("vm", config, {"grype": []}, {"findings": []})

        # Should still produce output via template fallback
        write_calls = mock_write.call_args_list
        remote_paths = [c[0][2] for c in write_calls]
        assert any("executive-summary.md" in p for p in remote_paths)

    @patch("threat_scanner.report.synthesize.ssh_write_file")
    @patch("threat_scanner.report.synthesize.ssh_exec")
    @patch("threat_scanner.report.scoring.load_kev_catalog")
    @patch("threat_scanner.report.scoring.fetch_epss_scores")
    def test_enrichment_applied(self, mock_epss, mock_kev, mock_exec, mock_write):
        mock_epss.return_value = {"CVE-2024-1": 0.95}
        mock_kev.return_value = {"CVE-2024-1"}
        mock_exec.return_value = SSHResult("", "", 0)
        mock_write.return_value = None

        scanner_results = {
            "grype": [
                {"cve_id": "CVE-2024-1", "cvss_score": 9.0, "severity": "critical",
                 "source_tool": "grype", "title": "RCE"}
            ]
        }

        config = _make_config(skip_ai=True)
        generate_report("vm", config, scanner_results, None)

        # Check the findings.json write contains enrichment fields
        findings_write = [c for c in mock_write.call_args_list
                          if "findings.json" in c[0][2]][0]
        import json
        findings = json.loads(findings_write[0][1])
        assert findings[0]["in_kev"] is True
        assert findings[0]["epss_score"] == 0.95
        assert findings[0]["composite_priority"] == "P0"

    @patch("threat_scanner.report.synthesize.ssh_write_file")
    @patch("threat_scanner.report.synthesize.ssh_exec")
    @patch("threat_scanner.report.scoring.load_kev_catalog")
    @patch("threat_scanner.report.scoring.fetch_epss_scores")
    def test_report_dir_timestamped(self, mock_epss, mock_kev, mock_exec, mock_write):
        mock_epss.return_value = {}
        mock_kev.return_value = set()
        mock_exec.return_value = SSHResult("", "", 0)
        mock_write.return_value = None

        config = _make_config(skip_ai=True)
        report_path = generate_report("vm", config, {}, None)

        # Should match /opt/security-reports/YYYYMMDD-HHMMSS
        import re
        assert re.search(r"/\d{8}-\d{6}$", report_path)
