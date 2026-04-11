"""Integration tests for report generation pipeline."""

from __future__ import annotations

import json
import subprocess as _sp
from unittest.mock import patch, MagicMock

import pytest

from thresher.config import ScanConfig
from thresher.report.synthesize import generate_report


def _make_config(**kw) -> ScanConfig:
    defaults = dict(
        repo_url="https://github.com/x/y",
        anthropic_api_key="key",
        skip_ai=True,
    )
    defaults.update(kw)
    return ScanConfig(**defaults)


# Shared patches for all tests that call generate_report
_COMMON_PATCHES = [
    patch("thresher.report.synthesize._generate_template_report"),
    patch("thresher.report.synthesize._generate_html_report"),
    patch("thresher.report.synthesize.shutil.copytree"),
    patch("thresher.report.synthesize.os.path.isdir", return_value=False),
    patch("thresher.report.synthesize.os.path.exists", return_value=False),
    patch("thresher.report.synthesize.os.makedirs"),
    patch("thresher.report.synthesize._read_file", return_value=None),
    patch("thresher.report.synthesize._write_file"),
    patch("thresher.report.scoring.load_kev_catalog"),
    patch("thresher.report.scoring.fetch_epss_scores"),
]


class TestGenerateReport:
    @patch("thresher.report.synthesize._generate_html_report")
    @patch("thresher.report.synthesize._generate_template_report")
    @patch("thresher.report.synthesize.shutil.copytree")
    @patch("thresher.report.synthesize.os.path.isdir", return_value=False)
    @patch("thresher.report.synthesize.os.path.exists", return_value=False)
    @patch("thresher.report.synthesize.os.makedirs")
    @patch("thresher.report.synthesize._read_file", return_value=None)
    @patch("thresher.report.synthesize._write_file")
    @patch("thresher.report.scoring.load_kev_catalog")
    @patch("thresher.report.scoring.fetch_epss_scores")
    def test_skip_ai_template_report(
        self, mock_epss, mock_kev, mock_write, mock_read,
        mock_makedirs, mock_exists, mock_isdir, mock_copytree,
        mock_template_report, mock_html_report
    ):
        mock_epss.return_value = {}
        mock_kev.return_value = set()

        config = _make_config(skip_ai=True)
        report_path = generate_report("", config)

        # Report path should be under /opt/security-reports/
        assert report_path.startswith("/opt/security-reports/")
        # Template report should have been called
        assert mock_template_report.called
        # findings.json should have been written
        write_calls = mock_write.call_args_list
        written_paths = [c[0][0] for c in write_calls]
        assert any("findings.json" in p for p in written_paths)

    @patch("thresher.report.synthesize._generate_html_report")
    @patch("thresher.report.synthesize._generate_template_report")
    @patch("thresher.report.synthesize.shutil.copytree")
    @patch("thresher.report.synthesize.os.path.isdir", return_value=False)
    @patch("thresher.report.synthesize.os.path.exists", return_value=False)
    @patch("thresher.report.synthesize.os.makedirs")
    @patch("thresher.report.synthesize._read_file", return_value=None)
    @patch("thresher.report.synthesize._write_file")
    @patch("thresher.agents.synthesize.run_synthesize_agent", return_value=False)
    @patch("thresher.report.scoring.load_kev_catalog")
    @patch("thresher.report.scoring.fetch_epss_scores")
    def test_agent_fallback_on_failure(
        self, mock_epss, mock_kev, mock_agent, mock_write, mock_read,
        mock_makedirs, mock_exists, mock_isdir, mock_copytree,
        mock_template_report, mock_html_report
    ):
        mock_epss.return_value = {}
        mock_kev.return_value = set()

        config = _make_config(skip_ai=False)
        report_path = generate_report("", config)

        # Synthesis agent was called
        assert mock_agent.called
        # Template fallback should have been called (agent returned False)
        assert mock_template_report.called

    @patch("thresher.report.synthesize._generate_html_report")
    @patch("thresher.report.synthesize._generate_template_report")
    @patch("thresher.report.synthesize.shutil.copytree")
    @patch("thresher.report.synthesize.os.path.isdir", return_value=False)
    @patch("thresher.report.synthesize.os.path.exists", return_value=False)
    @patch("thresher.report.synthesize.os.makedirs")
    @patch("thresher.report.synthesize._write_file")
    @patch("thresher.report.scoring.load_kev_catalog")
    @patch("thresher.report.scoring.fetch_epss_scores")
    def test_enrichment_applied(
        self, mock_epss, mock_kev, mock_write, mock_makedirs,
        mock_exists, mock_isdir, mock_copytree,
        mock_template_report, mock_html_report
    ):
        mock_epss.return_value = {"CVE-2024-1": 0.95}
        mock_kev.return_value = {"CVE-2024-1"}

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

        def read_side_effect(path):
            if "grype.json" in path:
                return grype_output
            return None

        config = _make_config(skip_ai=True)

        with patch("thresher.report.synthesize._read_file", side_effect=read_side_effect):
            generate_report("", config)

        # Check the findings.json write contains enrichment fields
        findings_writes = [
            c for c in mock_write.call_args_list
            if "findings.json" in c[0][0]
        ]
        assert findings_writes, "findings.json not written"
        findings = json.loads(findings_writes[0][0][1])
        assert findings[0]["in_kev"] is True
        assert findings[0]["epss_score"] == 0.95
        assert findings[0]["composite_priority"] == "P0"

    @patch("thresher.report.synthesize._generate_html_report")
    @patch("thresher.report.synthesize._generate_template_report")
    @patch("thresher.report.synthesize.shutil.copytree")
    @patch("thresher.report.synthesize.os.path.isdir", return_value=False)
    @patch("thresher.report.synthesize.os.path.exists", return_value=False)
    @patch("thresher.report.synthesize.os.makedirs")
    @patch("thresher.report.synthesize._read_file", return_value=None)
    @patch("thresher.report.synthesize._write_file")
    @patch("thresher.report.scoring.load_kev_catalog")
    @patch("thresher.report.scoring.fetch_epss_scores")
    def test_report_dir_timestamped(
        self, mock_epss, mock_kev, mock_write, mock_read,
        mock_makedirs, mock_exists, mock_isdir, mock_copytree,
        mock_template_report, mock_html_report
    ):
        mock_epss.return_value = {}
        mock_kev.return_value = set()

        config = _make_config(skip_ai=True)
        report_path = generate_report("", config)

        # Should match /opt/security-reports/YYYYMMDD-HHMMSS
        import re
        assert re.search(r"/\d{8}-\d{6}$", report_path)

    @patch("thresher.report.synthesize._generate_html_report")
    @patch("thresher.report.synthesize._generate_template_report")
    @patch("thresher.report.synthesize.shutil.copytree")
    @patch("thresher.report.synthesize.os.path.isdir", return_value=False)
    @patch("thresher.report.synthesize.os.path.exists", return_value=False)
    @patch("thresher.report.synthesize.os.makedirs")
    @patch("thresher.report.synthesize._read_file", return_value=None)
    @patch("thresher.report.synthesize._write_file")
    @patch("thresher.report.scoring.load_kev_catalog")
    @patch("thresher.report.scoring.fetch_epss_scores")
    def test_html_report_generated(
        self, mock_epss, mock_kev, mock_write, mock_read,
        mock_makedirs, mock_exists, mock_isdir, mock_copytree,
        mock_template_report, mock_html_report
    ):
        mock_epss.return_value = {}
        mock_kev.return_value = set()

        config = _make_config(skip_ai=True)
        generate_report("", config)

        # HTML report function should have been called
        assert mock_html_report.called
