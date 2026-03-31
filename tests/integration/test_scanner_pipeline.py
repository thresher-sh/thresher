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
    @patch("threat_scanner.scanners.clamav.ssh_exec")
    @patch("threat_scanner.scanners.scancode.ssh_exec")
    @patch("threat_scanner.scanners.cargo_audit.ssh_exec")
    @patch("threat_scanner.scanners.govulncheck.ssh_exec")
    @patch("threat_scanner.scanners.capa_scanner.ssh_exec")
    @patch("threat_scanner.scanners.yara_scanner.ssh_exec")
    @patch("threat_scanner.scanners.trivy.ssh_exec")
    @patch("threat_scanner.scanners.hadolint.ssh_exec")
    @patch("threat_scanner.scanners.checkov.ssh_exec")
    @patch("threat_scanner.scanners.bandit.ssh_exec")
    @patch("threat_scanner.scanners.runner.ssh_exec")
    @patch("threat_scanner.scanners.syft.ssh_exec")
    @patch("threat_scanner.scanners.grype.ssh_exec")
    @patch("threat_scanner.scanners.osv.ssh_exec")
    @patch("threat_scanner.scanners.semgrep.ssh_exec")
    @patch("threat_scanner.scanners.guarddog.ssh_exec")
    @patch("threat_scanner.scanners.gitleaks.ssh_exec")
    def test_happy_path(
        self,
        mock_gl, mock_gd, mock_sg, mock_osv, mock_grype, mock_syft, mock_runner_ssh,
        mock_bandit, mock_checkov, mock_hadolint, mock_trivy, mock_yara,
        mock_capa, mock_govulncheck, mock_cargo_audit, mock_scancode, mock_clamav,
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

        # New scanners: return minimal valid output
        mock_bandit.side_effect = [
            SSHResult("", "", 0),
            SSHResult('{"results":[]}', "", 0),
        ]
        mock_checkov.side_effect = [
            SSHResult("", "", 0),
            SSHResult('{"results":{"failed_checks":[]}}', "", 0),
        ]
        # hadolint: find returns no dockerfiles
        mock_hadolint.return_value = SSHResult("", "", 0)
        mock_trivy.side_effect = [
            SSHResult("", "", 0),
            SSHResult('{"Results":[]}', "", 0),
        ]
        # yara: rules dir not found
        mock_yara.return_value = SSHResult("", "", 0)
        # capa: no binaries found
        mock_capa.return_value = SSHResult("", "", 0)
        # govulncheck: no go.mod
        mock_govulncheck.return_value = SSHResult("", "", 0)
        # cargo-audit: no Cargo.lock
        mock_cargo_audit.return_value = SSHResult("", "", 0)
        mock_scancode.side_effect = [
            SSHResult("", "", 0),
            SSHResult('{"files":[]}', "", 0),
        ]
        mock_clamav.return_value = SSHResult("", "", 0)

        results = run_all_scanners("test-vm", _make_config())

        # Should have 16 results (syft + 15 parallel)
        assert len(results) == 16

        tool_names = {r.tool_name for r in results}
        assert tool_names == {
            "syft", "grype", "osv-scanner", "semgrep", "guarddog", "gitleaks",
            "bandit", "checkov", "hadolint", "trivy", "yara", "capa",
            "govulncheck", "cargo-audit", "scancode", "clamav",
        }

        # Check that findings were parsed
        grype_result = [r for r in results if r.tool_name == "grype"][0]
        assert len(grype_result.findings) == 3

        gitleaks_result = [r for r in results if r.tool_name == "gitleaks"][0]
        assert len(gitleaks_result.findings) == 2

    @patch("threat_scanner.scanners.clamav.ssh_exec")
    @patch("threat_scanner.scanners.scancode.ssh_exec")
    @patch("threat_scanner.scanners.cargo_audit.ssh_exec")
    @patch("threat_scanner.scanners.govulncheck.ssh_exec")
    @patch("threat_scanner.scanners.capa_scanner.ssh_exec")
    @patch("threat_scanner.scanners.yara_scanner.ssh_exec")
    @patch("threat_scanner.scanners.trivy.ssh_exec")
    @patch("threat_scanner.scanners.hadolint.ssh_exec")
    @patch("threat_scanner.scanners.checkov.ssh_exec")
    @patch("threat_scanner.scanners.bandit.ssh_exec")
    @patch("threat_scanner.scanners.runner.ssh_exec")
    @patch("threat_scanner.scanners.syft.ssh_exec")
    @patch("threat_scanner.scanners.grype.ssh_exec")
    @patch("threat_scanner.scanners.osv.ssh_exec")
    @patch("threat_scanner.scanners.semgrep.ssh_exec")
    @patch("threat_scanner.scanners.guarddog.ssh_exec")
    @patch("threat_scanner.scanners.gitleaks.ssh_exec")
    def test_scanner_exception_handled(
        self,
        mock_gl, mock_gd, mock_sg, mock_osv, mock_grype, mock_syft, mock_runner_ssh,
        mock_bandit, mock_checkov, mock_hadolint, mock_trivy, mock_yara,
        mock_capa, mock_govulncheck, mock_cargo_audit, mock_scancode, mock_clamav,
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

        # New scanners: minimal valid responses
        mock_bandit.side_effect = [
            SSHResult("", "", 0),
            SSHResult('{"results":[]}', "", 0),
        ]
        mock_checkov.side_effect = [
            SSHResult("", "", 0),
            SSHResult('{"results":{"failed_checks":[]}}', "", 0),
        ]
        mock_hadolint.return_value = SSHResult("", "", 0)
        mock_trivy.side_effect = [
            SSHResult("", "", 0),
            SSHResult('{"Results":[]}', "", 0),
        ]
        mock_yara.return_value = SSHResult("", "", 0)
        mock_capa.return_value = SSHResult("", "", 0)
        mock_govulncheck.return_value = SSHResult("", "", 0)
        mock_cargo_audit.return_value = SSHResult("", "", 0)
        mock_scancode.side_effect = [
            SSHResult("", "", 0),
            SSHResult('{"files":[]}', "", 0),
        ]
        mock_clamav.return_value = SSHResult("", "", 0)

        results = run_all_scanners("test-vm", _make_config())

        # All 16 should still be present
        assert len(results) == 16

        # Grype should have an error entry
        grype = [r for r in results if r.tool_name == "grype"][0]
        assert grype.exit_code == -1
        assert len(grype.errors) > 0

    @patch("threat_scanner.scanners.clamav.ssh_exec")
    @patch("threat_scanner.scanners.scancode.ssh_exec")
    @patch("threat_scanner.scanners.cargo_audit.ssh_exec")
    @patch("threat_scanner.scanners.govulncheck.ssh_exec")
    @patch("threat_scanner.scanners.capa_scanner.ssh_exec")
    @patch("threat_scanner.scanners.yara_scanner.ssh_exec")
    @patch("threat_scanner.scanners.trivy.ssh_exec")
    @patch("threat_scanner.scanners.hadolint.ssh_exec")
    @patch("threat_scanner.scanners.checkov.ssh_exec")
    @patch("threat_scanner.scanners.bandit.ssh_exec")
    @patch("threat_scanner.scanners.runner.ssh_exec")
    @patch("threat_scanner.scanners.syft.ssh_exec")
    @patch("threat_scanner.scanners.grype.ssh_exec")
    @patch("threat_scanner.scanners.osv.ssh_exec")
    @patch("threat_scanner.scanners.semgrep.ssh_exec")
    @patch("threat_scanner.scanners.guarddog.ssh_exec")
    @patch("threat_scanner.scanners.gitleaks.ssh_exec")
    def test_exit_code_1_is_findings(
        self,
        mock_gl, mock_gd, mock_sg, mock_osv, mock_grype, mock_syft, mock_runner_ssh,
        mock_bandit, mock_checkov, mock_hadolint, mock_trivy, mock_yara,
        mock_capa, mock_govulncheck, mock_cargo_audit, mock_scancode, mock_clamav,
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

        # New scanners: minimal valid responses
        mock_bandit.side_effect = [
            SSHResult("", "", 0),
            SSHResult('{"results":[]}', "", 0),
        ]
        mock_checkov.side_effect = [
            SSHResult("", "", 0),
            SSHResult('{"results":{"failed_checks":[]}}', "", 0),
        ]
        mock_hadolint.return_value = SSHResult("", "", 0)
        mock_trivy.side_effect = [
            SSHResult("", "", 0),
            SSHResult('{"Results":[]}', "", 0),
        ]
        mock_yara.return_value = SSHResult("", "", 0)
        mock_capa.return_value = SSHResult("", "", 0)
        mock_govulncheck.return_value = SSHResult("", "", 0)
        mock_cargo_audit.return_value = SSHResult("", "", 0)
        mock_scancode.side_effect = [
            SSHResult("", "", 0),
            SSHResult('{"files":[]}', "", 0),
        ]
        mock_clamav.return_value = SSHResult("", "", 0)

        results = run_all_scanners("test-vm", _make_config())

        for r in results:
            assert len(r.errors) == 0, f"{r.tool_name} should not have errors for exit code 1"
