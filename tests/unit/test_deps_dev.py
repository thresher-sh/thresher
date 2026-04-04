"""Tests for thresher.scanners.deps_dev."""

from __future__ import annotations

import json
import os
import textwrap
from unittest.mock import patch

from thresher.scanners.deps_dev import parse_deps_dev_output, run_deps_dev, _DEPS_DEV_SCRIPT
from thresher.vm.ssh import SSHResult


class TestParseDepsDevOutput:
    def test_empty_output(self):
        raw = {"scanner": "deps-dev", "findings": [], "total": 0}
        assert parse_deps_dev_output(raw) == []

    def test_low_scorecard(self):
        raw = {
            "scanner": "deps-dev",
            "findings": [
                {
                    "type": "low_scorecard",
                    "package": "sketchy-pkg",
                    "ecosystem": "npm",
                    "severity": "medium",
                    "description": "Low OpenSSF Scorecard: 2.1/10",
                    "detail": {"overall_score": 2.1, "checks": {"BranchProtection": 0}},
                }
            ],
        }
        findings = parse_deps_dev_output(raw)
        assert len(findings) == 1
        assert findings[0].category == "metadata"
        assert findings[0].severity == "medium"
        assert findings[0].package_name == "sketchy-pkg"
        assert "low_scorecard" in findings[0].title

    def test_typosquatting_signal(self):
        raw = {
            "scanner": "deps-dev",
            "findings": [
                {
                    "type": "typosquatting_signal",
                    "package": "loadsh",
                    "ecosystem": "npm",
                    "severity": "high",
                    "description": "Package name is similar to 'lodash'",
                    "detail": {"similar_package": "lodash"},
                }
            ],
        }
        findings = parse_deps_dev_output(raw)
        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_dormant_reactivation(self):
        raw = {
            "scanner": "deps-dev",
            "findings": [
                {
                    "type": "dormant_reactivation",
                    "package": "old-pkg",
                    "ecosystem": "pypi",
                    "severity": "medium",
                    "description": "Package was dormant for 500 days",
                    "detail": {"gap_days": 500},
                }
            ],
        }
        findings = parse_deps_dev_output(raw)
        assert len(findings) == 1
        assert "dormant_reactivation" in findings[0].title

    def test_multiple_findings(self):
        raw = {
            "scanner": "deps-dev",
            "findings": [
                {"type": "low_scorecard", "package": "a", "ecosystem": "npm",
                 "severity": "medium", "description": "low score"},
                {"type": "typosquatting_signal", "package": "b", "ecosystem": "npm",
                 "severity": "high", "description": "similar name"},
            ],
        }
        findings = parse_deps_dev_output(raw)
        assert len(findings) == 2
        ids = [f.id for f in findings]
        assert len(ids) == len(set(ids))

    def test_no_source_repo(self):
        raw = {
            "scanner": "deps-dev",
            "findings": [
                {
                    "type": "no_source_repo",
                    "package": "mystery-pkg",
                    "ecosystem": "npm",
                    "severity": "low",
                    "description": "No linked source repository found",
                }
            ],
        }
        findings = parse_deps_dev_output(raw)
        assert findings[0].severity == "low"


class TestDepsDevScript:
    """Tests for the embedded deps.dev scanner script."""

    def test_script_searches_multiple_manifest_paths(self):
        """The script should search /opt/deps/, /opt/target/ for manifests."""
        assert "/opt/deps/dep_manifest.json" in _DEPS_DEV_SCRIPT
        assert "/opt/target/package-lock.json" in _DEPS_DEV_SCRIPT
        assert "/opt/target/package.json" in _DEPS_DEV_SCRIPT
        assert "/opt/target/Cargo.toml" in _DEPS_DEV_SCRIPT

    def test_script_logs_searched_paths_on_no_manifests(self):
        """When no manifests found, script should report searched paths."""
        assert "WARNING: No manifests found" in _DEPS_DEV_SCRIPT

    def test_script_outputs_warning_field_when_empty(self):
        """When no packages found, output should include warning field."""
        assert '"warning"' in _DEPS_DEV_SCRIPT

    def test_script_has_package_json_parser(self):
        """Script should contain logic to parse package.json files."""
        assert "_parse_package_json" in _DEPS_DEV_SCRIPT

    def test_script_has_cargo_toml_parser(self):
        """Script should contain logic to parse Cargo.toml files."""
        assert "_parse_cargo_toml" in _DEPS_DEV_SCRIPT


class TestRunDepsDev:
    @patch("thresher.scanners.deps_dev.ssh_write_file")
    @patch("thresher.scanners.deps_dev.ssh_exec")
    def test_success(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult("Checking 5 packages...", "", 0)
        mock_write.return_value = None

        result = run_deps_dev("vm", "/opt/scan-results")

        assert result.tool_name == "deps-dev"
        assert result.exit_code == 0
        assert result.raw_output_path == "/opt/scan-results/deps-dev.json"

    @patch("thresher.scanners.deps_dev.ssh_write_file")
    @patch("thresher.scanners.deps_dev.ssh_exec")
    def test_failure(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult("", "error", 1)
        mock_write.return_value = None

        result = run_deps_dev("vm", "/opt/scan-results")

        assert result.exit_code == 1
        assert len(result.errors) > 0
