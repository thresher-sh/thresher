"""Integration tests for scanner pipeline with mocked SSH."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

from threat_scanner.config import ScanConfig
from threat_scanner.scanners.runner import run_all_scanners
from threat_scanner.vm.ssh import SSHResult

FIXTURES = Path(__file__).parent.parent / "fixtures" / "sample_scanner_output"


def _make_config() -> ScanConfig:
    return ScanConfig(repo_url="https://github.com/x/y", anthropic_api_key="key")


def _load(name: str) -> str:
    return (FIXTURES / name).read_text()


class TestRunAllScanners:
    @patch("threat_scanner.scanners.runner.ssh_exec")
    @patch("threat_scanner.scanners.syft.ssh_exec")
    @patch("threat_scanner.scanners.grype.ssh_exec")
    @patch("threat_scanner.scanners.osv.ssh_exec")
    @patch("threat_scanner.scanners.semgrep.ssh_exec")
    @patch("threat_scanner.scanners.guarddog.ssh_exec")
    @patch("threat_scanner.scanners.gitleaks.ssh_exec")
    def test_happy_path(
        self, mock_gl, mock_gd, mock_sg, mock_osv, mock_grype, mock_syft, mock_runner_ssh
    ):
        # Runner's mkdir call
        mock_runner_ssh.return_value = SSHResult("", "", 0)

        # Syft: run + no cat needed (metadata only)
        mock_syft.return_value = SSHResult("", "", 0)

        # All other scanners: run command returns 0/1, then cat returns fixture
        mock_grype.side_effect = [
            SSHResult("", "", 1),  # grype run (exit 1 = findings)
            SSHResult(_load("grype.json"), "", 0),  # cat output
        ]
        mock_osv.side_effect = [
            SSHResult("", "", 1),
            SSHResult(_load("osv.json"), "", 0),
        ]
        mock_sg.side_effect = [
            SSHResult("", "", 0),
            SSHResult(_load("semgrep.json"), "", 0),
        ]
        mock_gd.side_effect = [
            SSHResult("", "", 0),
            SSHResult(_load("guarddog.json"), "", 0),
        ]
        mock_gl.side_effect = [
            SSHResult("", "", 1),  # exit 1 = leaks found
            SSHResult(_load("gitleaks.json"), "", 0),
        ]

        results = run_all_scanners("test-vm", _make_config())

        # Should have 6 results (syft + 5 parallel)
        assert len(results) == 6

        tool_names = {r.tool_name for r in results}
        assert tool_names == {"syft", "grype", "osv-scanner", "semgrep", "guarddog", "gitleaks"}

        # Check that findings were parsed
        grype_result = [r for r in results if r.tool_name == "grype"][0]
        assert len(grype_result.findings) == 3

        gitleaks_result = [r for r in results if r.tool_name == "gitleaks"][0]
        assert len(gitleaks_result.findings) == 2

    @patch("threat_scanner.scanners.runner.ssh_exec")
    @patch("threat_scanner.scanners.syft.ssh_exec")
    @patch("threat_scanner.scanners.grype.ssh_exec")
    @patch("threat_scanner.scanners.osv.ssh_exec")
    @patch("threat_scanner.scanners.semgrep.ssh_exec")
    @patch("threat_scanner.scanners.guarddog.ssh_exec")
    @patch("threat_scanner.scanners.gitleaks.ssh_exec")
    def test_scanner_exception_handled(
        self, mock_gl, mock_gd, mock_sg, mock_osv, mock_grype, mock_syft, mock_runner_ssh
    ):
        mock_runner_ssh.return_value = SSHResult("", "", 0)
        mock_syft.return_value = SSHResult("", "", 0)

        # Make grype raise an exception
        mock_grype.side_effect = RuntimeError("connection lost")

        # Others succeed
        mock_osv.side_effect = [SSHResult("", "", 0), SSHResult('{"results":[]}', "", 0)]
        mock_sg.side_effect = [SSHResult("", "", 0), SSHResult('{"results":[]}', "", 0)]
        mock_gd.side_effect = [SSHResult("", "", 0), SSHResult("{}", "", 0)]
        mock_gl.return_value = SSHResult("", "", 0)

        results = run_all_scanners("test-vm", _make_config())

        # All 6 should still be present
        assert len(results) == 6

        # Grype should have an error entry
        grype = [r for r in results if r.tool_name == "grype"][0]
        assert grype.exit_code == -1
        assert len(grype.errors) > 0

    @patch("threat_scanner.scanners.runner.ssh_exec")
    @patch("threat_scanner.scanners.syft.ssh_exec")
    @patch("threat_scanner.scanners.grype.ssh_exec")
    @patch("threat_scanner.scanners.osv.ssh_exec")
    @patch("threat_scanner.scanners.semgrep.ssh_exec")
    @patch("threat_scanner.scanners.guarddog.ssh_exec")
    @patch("threat_scanner.scanners.gitleaks.ssh_exec")
    def test_exit_code_1_is_findings(
        self, mock_gl, mock_gd, mock_sg, mock_osv, mock_grype, mock_syft, mock_runner_ssh
    ):
        """Exit code 1 from Grype/OSV/Gitleaks means findings found, not error."""
        mock_runner_ssh.return_value = SSHResult("", "", 0)
        mock_syft.return_value = SSHResult("", "", 0)

        mock_grype.side_effect = [
            SSHResult("", "", 1),
            SSHResult('{"matches": []}', "", 0),
        ]
        mock_osv.side_effect = [
            SSHResult("", "", 1),
            SSHResult('{"results": []}', "", 0),
        ]
        mock_sg.side_effect = [SSHResult("", "", 0), SSHResult('{"results":[]}', "", 0)]
        mock_gd.side_effect = [SSHResult("", "", 0), SSHResult("{}", "", 0)]
        mock_gl.side_effect = [
            SSHResult("", "", 1),
            SSHResult("[]", "", 0),
        ]

        results = run_all_scanners("test-vm", _make_config())

        for r in results:
            assert len(r.errors) == 0, f"{r.tool_name} should not have errors for exit code 1"
