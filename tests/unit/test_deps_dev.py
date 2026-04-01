"""Tests for thresher.scanners.deps_dev."""

from __future__ import annotations

from thresher.scanners.deps_dev import parse_deps_dev_output


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
