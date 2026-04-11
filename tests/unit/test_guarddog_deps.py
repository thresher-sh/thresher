"""Tests for thresher.scanners.guarddog_deps."""

from __future__ import annotations

from thresher.scanners.guarddog_deps import parse_guarddog_deps_output


class TestParseGuarddogDepsOutput:
    def test_empty_list_returns_no_findings(self):
        assert parse_guarddog_deps_output([]) == []

    def test_clean_scans_return_no_findings(self):
        """Regression for M3c: when run_guarddog_deps appends per-subdir
        result dicts, an empty/clean dict (no issues) must NOT be reported
        as a finding. Previously each clean dict became one fake
        ``unknown-N`` finding, so 2 clean subdirs reported 2 findings."""
        clean_results = [
            {"issues": 0, "errors": [], "results": {}},
            {"issues": 0, "errors": [], "results": {}},
        ]
        findings = parse_guarddog_deps_output(clean_results)
        assert findings == []

    def test_top_level_dict_with_real_findings(self):
        """When a per-subdir dict contains package-keyed results with rules,
        each rule produces a finding."""
        raw = [
            {
                "issues": 1,
                "results": {},
                "evil-pkg": {
                    "results": {
                        "exfiltration": ["found in setup.py"],
                    },
                },
            },
        ]
        findings = parse_guarddog_deps_output(raw)
        assert len(findings) == 1
        assert findings[0].package_name == "evil-pkg"
        assert "exfiltration" in findings[0].title

    def test_list_of_explicit_finding_dicts(self):
        """Older list-of-findings format still works."""
        raw = [
            {
                "rule": "shady-import",
                "package": "evil",
                "message": "Shady import detected",
                "location": "/opt/deps/evil/setup.py",
            }
        ]
        findings = parse_guarddog_deps_output(raw)
        assert len(findings) == 1
        assert findings[0].package_name == "evil"

    def test_top_level_dict_format(self):
        """Direct dict input (single scan) still parses correctly."""
        raw = {
            "evil-pkg": {
                "results": {
                    "code-execution": ["found"],
                },
            },
        }
        findings = parse_guarddog_deps_output(raw)
        assert len(findings) == 1
        assert findings[0].package_name == "evil-pkg"

    def test_mixed_clean_and_dirty_scans(self):
        """A clean subdir alongside a dirty one — only the dirty one
        should produce findings."""
        raw = [
            {"issues": 0, "errors": [], "results": {}},
            {
                "issues": 2,
                "results": {},
                "bad-pkg": {
                    "results": {
                        "obfuscation": ["found in lib.py"],
                        "network-call": ["found in init.py"],
                    },
                },
            },
        ]
        findings = parse_guarddog_deps_output(raw)
        assert len(findings) == 2
        rules = {f.title for f in findings}
        assert any("obfuscation" in r for r in rules)
        assert any("network-call" in r for r in rules)
