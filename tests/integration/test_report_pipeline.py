"""Integration tests for report generation pipeline."""

from __future__ import annotations

import json
from unittest.mock import patch, call

from thresher.config import ScanConfig
from thresher.report.synthesize import generate_report
from thresher.vm.ssh import SSHResult


def _make_config(**kw) -> ScanConfig:
    defaults = dict(
        repo_url="https://github.com/x/y",
        anthropic_api_key="key",
        skip_ai=True,
    )
    defaults.update(kw)
    return ScanConfig(**defaults)


class TestGenerateReport:
    @patch("thresher.report.synthesize.ssh_write_file")
    @patch("thresher.report.synthesize.ssh_exec")
    @patch("thresher.report.scoring.load_kev_catalog")
    @patch("thresher.report.scoring.fetch_epss_scores")
    def test_skip_ai_template_report(self, mock_epss, mock_kev, mock_exec, mock_write):
        mock_epss.return_value = {}
        mock_kev.return_value = set()
        # ssh_exec calls: mkdir, cat scanner files (all fail), cp scan-results, cp sbom
        mock_exec.return_value = SSHResult("", "", 1)
        mock_write.return_value = None

        config = _make_config(skip_ai=True)
        report_path = generate_report("vm", config)

        # Report path should be under /opt/security-reports/
        assert report_path.startswith("/opt/security-reports/")

        # ssh_write_file should have been called for:
        # findings.json, executive-summary.md, detailed-report.md
        write_calls = mock_write.call_args_list
        remote_paths = [c[0][2] for c in write_calls]
        assert any("findings.json" in p for p in remote_paths)
        assert any("executive-summary.md" in p for p in remote_paths)
        assert any("detailed-report.md" in p for p in remote_paths)

    @patch("thresher.report.synthesize.ssh_write_file")
    @patch("thresher.report.synthesize.ssh_exec")
    @patch("thresher.report.scoring.load_kev_catalog")
    @patch("thresher.report.scoring.fetch_epss_scores")
    def test_agent_fallback_on_failure(self, mock_epss, mock_kev, mock_exec, mock_write):
        mock_epss.return_value = {}
        mock_kev.return_value = set()
        mock_write.return_value = None

        # ssh_exec calls for reading scanner files will fail (exit 1),
        # then AI findings read, mkdir, cp, claude, test -f check fails
        mock_exec.return_value = SSHResult("", "", 1)

        config = _make_config(skip_ai=False)
        report_path = generate_report("vm", config)

        # Should still produce output via template fallback
        write_calls = mock_write.call_args_list
        remote_paths = [c[0][2] for c in write_calls]
        assert any("executive-summary.md" in p for p in remote_paths)

    @patch("thresher.report.synthesize.ssh_write_file")
    @patch("thresher.report.synthesize.ssh_exec")
    @patch("thresher.report.scoring.load_kev_catalog")
    @patch("thresher.report.scoring.fetch_epss_scores")
    def test_enrichment_applied(self, mock_epss, mock_kev, mock_exec, mock_write):
        mock_epss.return_value = {"CVE-2024-1": 0.95}
        mock_kev.return_value = {"CVE-2024-1"}
        mock_write.return_value = None

        # Build scanner output that will be read from the VM
        grype_output = json.dumps({
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2024-1",
                        "severity": "Critical",
                        "description": "RCE",
                        "cvss": [{"metrics": {"baseScore": 9.0}}],
                        "fix": {"versions": []},
                    },
                    "artifact": {
                        "name": "example-lib",
                        "version": "1.0.0",
                    },
                }
            ]
        })

        def exec_side_effect(vm_name, cmd, **kwargs):
            # Return grype fixture when cat grype.json is called
            if "cat /opt/scan-results/grype.json" in cmd:
                return SSHResult(grype_output, "", 0)
            # All other cat calls fail (no other scanner output)
            if cmd.startswith("cat /opt/scan-results/"):
                return SSHResult("", "", 1)
            return SSHResult("", "", 0)

        mock_exec.side_effect = exec_side_effect

        config = _make_config(skip_ai=True)
        generate_report("vm", config)

        # Check the findings.json write contains enrichment fields
        findings_write = [c for c in mock_write.call_args_list
                          if "findings.json" in c[0][2]][0]
        findings = json.loads(findings_write[0][1])
        assert findings[0]["in_kev"] is True
        assert findings[0]["epss_score"] == 0.95
        assert findings[0]["composite_priority"] == "P0"

    @patch("thresher.report.synthesize.ssh_write_file")
    @patch("thresher.report.synthesize.ssh_exec")
    @patch("thresher.report.scoring.load_kev_catalog")
    @patch("thresher.report.scoring.fetch_epss_scores")
    def test_report_dir_timestamped(self, mock_epss, mock_kev, mock_exec, mock_write):
        mock_epss.return_value = {}
        mock_kev.return_value = set()
        mock_exec.return_value = SSHResult("", "", 1)
        mock_write.return_value = None

        config = _make_config(skip_ai=True)
        report_path = generate_report("vm", config)

        # Should match /opt/security-reports/YYYYMMDD-HHMMSS
        import re
        assert re.search(r"/\d{8}-\d{6}$", report_path)
