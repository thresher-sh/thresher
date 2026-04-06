"""Integration tests for scanner pipeline with mocked subprocess."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock
import subprocess

from thresher.config import ScanConfig
from thresher.scanners.runner import run_all_scanners

FIXTURES = Path(__file__).parent.parent / "fixtures" / "sample_scanner_output"


def _make_config() -> ScanConfig:
    return ScanConfig(repo_url="https://github.com/x/y", anthropic_api_key="key")


def _mock_proc(returncode: int = 0, stdout: bytes = b"", stderr: bytes = b"") -> MagicMock:
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = stderr
    return m


def _patch_all_subproc(extras: dict | None = None):
    """Return a dict of default subprocess.run mocks for each scanner module."""
    defaults = {
        "thresher.scanners.gitleaks.subprocess.run": _mock_proc(0),
        "thresher.scanners.guarddog.subprocess.run": _mock_proc(0),
        "thresher.scanners.semgrep.subprocess.run": _mock_proc(0),
        "thresher.scanners.osv.subprocess.run": _mock_proc(0),
        "thresher.scanners.grype.subprocess.run": _mock_proc(0, b'{"matches":[]}'),
        "thresher.scanners.syft.subprocess.run": _mock_proc(0, b'{"bomFormat":"CycloneDX"}'),
        "thresher.scanners.bandit.subprocess.run": _mock_proc(0),
        "thresher.scanners.checkov.subprocess.run": _mock_proc(0),
        "thresher.scanners.hadolint.subprocess.run": _mock_proc(0),
        "thresher.scanners.trivy.subprocess.run": _mock_proc(0),
        "thresher.scanners.clamav.subprocess.run": _mock_proc(0),
        "thresher.scanners.scancode.subprocess.run": _mock_proc(0),
        "thresher.scanners.semgrep_supply_chain.subprocess.run": _mock_proc(0),
        "thresher.scanners.install_hooks.subprocess.run": _mock_proc(0),
        "thresher.scanners.entropy.subprocess.run": _mock_proc(0),
        "thresher.scanners.deps_dev.subprocess.run": _mock_proc(0),
        "thresher.scanners.registry_meta.subprocess.run": _mock_proc(0),
        "thresher.scanners.guarddog_deps.subprocess.run": _mock_proc(0, b"[]"),
    }
    if extras:
        defaults.update(extras)
    return defaults


class TestRunAllScanners:
    def test_happy_path(self):
        """All scanners run, 22 results returned."""
        mocks = _patch_all_subproc({
            "thresher.scanners.grype.subprocess.run": _mock_proc(1, b'{"matches":[]}'),
            "thresher.scanners.osv.subprocess.run": _mock_proc(1, b'{"results":[]}'),
            "thresher.scanners.gitleaks.subprocess.run": _mock_proc(1, b'[]'),
        })

        patchers = [patch(target, return_value=mock) for target, mock in mocks.items()]
        # Also need to prevent file writes and mkdir
        patchers.append(patch("pathlib.Path.mkdir"))
        patchers.append(patch("pathlib.Path.write_bytes"))
        patchers.append(patch("pathlib.Path.write_text"))
        patchers.append(patch("pathlib.Path.exists", return_value=False))
        patchers.append(patch("pathlib.Path.is_dir", return_value=False))
        patchers.append(patch("pathlib.Path.rglob", return_value=[]))
        # cargo_audit, govulncheck check Path(..., "Cargo.lock").exists() etc.
        # is_dir and exists are already False, so those scanners skip

        for p in patchers:
            p.start()

        try:
            results = run_all_scanners("/opt/target", "/opt/scan-results", _make_config())
        finally:
            for p in patchers:
                p.stop()

        assert len(results) == 22

        tool_names = {r.tool_name for r in results}
        assert tool_names == {
            "syft", "grype", "osv-scanner", "semgrep", "guarddog", "gitleaks",
            "bandit", "checkov", "hadolint", "trivy", "yara", "capa",
            "govulncheck", "cargo-audit", "scancode", "clamav",
            "semgrep-supply-chain", "guarddog-deps", "install-hooks", "entropy",
            "deps-dev", "registry-meta",
        }

    def test_scanner_exception_handled(self):
        """If a scanner raises an exception, it's caught and returned as error."""
        mocks = _patch_all_subproc()
        grype_mock = MagicMock(side_effect=RuntimeError("connection lost"))

        patchers = [patch(target, return_value=mock) for target, mock in mocks.items()]
        patchers.append(patch("thresher.scanners.grype.subprocess.run", side_effect=RuntimeError("connection lost")))
        patchers.append(patch("pathlib.Path.mkdir"))
        patchers.append(patch("pathlib.Path.write_bytes"))
        patchers.append(patch("pathlib.Path.write_text"))
        patchers.append(patch("pathlib.Path.exists", return_value=False))
        patchers.append(patch("pathlib.Path.is_dir", return_value=False))
        patchers.append(patch("pathlib.Path.rglob", return_value=[]))

        for p in patchers:
            p.start()

        try:
            results = run_all_scanners("/opt/target", "/opt/scan-results", _make_config())
        finally:
            for p in patchers:
                p.stop()

        assert len(results) == 22

        grype = [r for r in results if r.tool_name == "grype"][0]
        assert grype.exit_code == -1
        assert len(grype.errors) > 0

    def test_exit_code_1_is_findings(self):
        """Exit code 1 from Grype/OSV/Gitleaks means findings found, not error."""
        mocks = _patch_all_subproc({
            "thresher.scanners.grype.subprocess.run": _mock_proc(1, b'{"matches":[]}'),
            "thresher.scanners.osv.subprocess.run": _mock_proc(1, b'{"results":[]}'),
            "thresher.scanners.gitleaks.subprocess.run": _mock_proc(1, b'[]'),
        })

        patchers = [patch(target, return_value=mock) for target, mock in mocks.items()]
        patchers.append(patch("pathlib.Path.mkdir"))
        patchers.append(patch("pathlib.Path.write_bytes"))
        patchers.append(patch("pathlib.Path.write_text"))
        patchers.append(patch("pathlib.Path.exists", return_value=False))
        patchers.append(patch("pathlib.Path.is_dir", return_value=False))
        patchers.append(patch("pathlib.Path.rglob", return_value=[]))

        for p in patchers:
            p.start()

        try:
            results = run_all_scanners("/opt/target", "/opt/scan-results", _make_config())
        finally:
            for p in patchers:
                p.stop()

        for r in results:
            assert len(r.errors) == 0, f"{r.tool_name} should not have errors for exit code 1"
