"""Integration tests for scanner pipeline with mocked SSH."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

from thresher.config import ScanConfig
from thresher.scanners.runner import run_all_scanners
from thresher.vm.ssh import SSHResult

FIXTURES = Path(__file__).parent.parent / "fixtures" / "sample_scanner_output"


def _make_config() -> ScanConfig:
    return ScanConfig(repo_url="https://github.com/x/y", anthropic_api_key="key")


def _load(name: str) -> str:
    return (FIXTURES / name).read_text()


class TestRunAllScanners:
    @patch("thresher.scanners.registry_meta.ssh_write_file")
    @patch("thresher.scanners.registry_meta.ssh_exec")
    @patch("thresher.scanners.deps_dev.ssh_write_file")
    @patch("thresher.scanners.deps_dev.ssh_exec")
    @patch("thresher.scanners.entropy.ssh_write_file")
    @patch("thresher.scanners.entropy.ssh_exec")
    @patch("thresher.scanners.install_hooks.ssh_write_file")
    @patch("thresher.scanners.install_hooks.ssh_exec")
    @patch("thresher.scanners.guarddog_deps.ssh_write_file")
    @patch("thresher.scanners.guarddog_deps.ssh_exec")
    @patch("thresher.scanners.semgrep_supply_chain.ssh_exec")
    @patch("thresher.scanners.clamav.ssh_exec")
    @patch("thresher.scanners.scancode.ssh_exec")
    @patch("thresher.scanners.cargo_audit.ssh_exec")
    @patch("thresher.scanners.govulncheck.ssh_exec")
    @patch("thresher.scanners.capa_scanner.ssh_exec")
    @patch("thresher.scanners.yara_scanner.ssh_exec")
    @patch("thresher.scanners.trivy.ssh_exec")
    @patch("thresher.scanners.hadolint.ssh_exec")
    @patch("thresher.scanners.checkov.ssh_exec")
    @patch("thresher.scanners.bandit.ssh_exec")
    @patch("thresher.scanners.runner.ssh_exec")
    @patch("thresher.scanners.syft.ssh_exec")
    @patch("thresher.scanners.grype.ssh_exec")
    @patch("thresher.scanners.osv.ssh_exec")
    @patch("thresher.scanners.semgrep.ssh_exec")
    @patch("thresher.scanners.guarddog.ssh_exec")
    @patch("thresher.scanners.gitleaks.ssh_exec")
    def test_happy_path(
        self,
        mock_gl, mock_gd, mock_sg, mock_osv, mock_grype, mock_syft, mock_runner_ssh,
        mock_bandit, mock_checkov, mock_hadolint, mock_trivy, mock_yara,
        mock_capa, mock_govulncheck, mock_cargo_audit, mock_scancode, mock_clamav,
        mock_semgrep_sc, mock_guarddog_deps_exec, mock_guarddog_deps_write,
        mock_install_hooks_exec, mock_install_hooks_write,
        mock_entropy_exec, mock_entropy_write,
        mock_deps_dev_exec, mock_deps_dev_write,
        mock_registry_meta_exec, mock_registry_meta_write,
    ):
        # Runner's mkdir call
        mock_runner_ssh.return_value = SSHResult("", "", 0)

        # Syft: run + no cat needed (metadata only)
        mock_syft.return_value = SSHResult("", "", 0)

        # Scanners no longer cat+parse output — findings stay in VM.
        # Each scanner only makes one ssh_exec call (the tool run itself).
        mock_grype.return_value = SSHResult("", "", 1)  # exit 1 = findings
        mock_osv.return_value = SSHResult("", "", 1)
        mock_sg.return_value = SSHResult("", "", 0)
        mock_gd.return_value = SSHResult("", "", 0)
        mock_gl.return_value = SSHResult("", "", 1)  # exit 1 = leaks found

        mock_bandit.return_value = SSHResult("", "", 0)
        mock_checkov.return_value = SSHResult("", "", 0)
        # hadolint: find returns no dockerfiles
        mock_hadolint.return_value = SSHResult("", "", 0)
        mock_trivy.return_value = SSHResult("", "", 0)
        # yara: rules dir not found
        mock_yara.return_value = SSHResult("", "", 0)
        # capa: no binaries found
        mock_capa.return_value = SSHResult("", "", 0)
        # govulncheck: no go.mod
        mock_govulncheck.return_value = SSHResult("", "", 0)
        # cargo-audit: no Cargo.lock
        mock_cargo_audit.return_value = SSHResult("", "", 0)
        mock_scancode.return_value = SSHResult("", "", 0)
        mock_clamav.return_value = SSHResult("", "", 0)

        # New scanners
        mock_semgrep_sc.return_value = SSHResult("", "", 0)
        mock_guarddog_deps_exec.return_value = SSHResult("", "", 0)
        mock_guarddog_deps_write.return_value = None
        mock_install_hooks_exec.return_value = SSHResult("", "", 0)
        mock_install_hooks_write.return_value = None
        mock_entropy_exec.return_value = SSHResult("", "", 0)
        mock_entropy_write.return_value = None
        mock_deps_dev_exec.return_value = SSHResult("", "", 0)
        mock_deps_dev_write.return_value = None
        mock_registry_meta_exec.return_value = SSHResult("", "", 0)
        mock_registry_meta_write.return_value = None

        results = run_all_scanners("test-vm", _make_config())

        # Should have 22 results (syft + 21 parallel)
        assert len(results) == 22

        tool_names = {r.tool_name for r in results}
        assert tool_names == {
            "syft", "grype", "osv-scanner", "semgrep", "guarddog", "gitleaks",
            "bandit", "checkov", "hadolint", "trivy", "yara", "capa",
            "govulncheck", "cargo-audit", "scancode", "clamav",
            "semgrep-supply-chain", "guarddog-deps", "install-hooks", "entropy",
            "deps-dev", "registry-meta",
        }

        # Findings stay in VM — host-side ScanResults have empty findings
        grype_result = [r for r in results if r.tool_name == "grype"][0]
        assert len(grype_result.findings) == 0
        assert grype_result.raw_output_path == "/opt/scan-results/grype.json"

        gitleaks_result = [r for r in results if r.tool_name == "gitleaks"][0]
        assert len(gitleaks_result.findings) == 0
        assert gitleaks_result.raw_output_path == "/opt/scan-results/gitleaks.json"

    @patch("thresher.scanners.registry_meta.ssh_write_file")
    @patch("thresher.scanners.registry_meta.ssh_exec")
    @patch("thresher.scanners.deps_dev.ssh_write_file")
    @patch("thresher.scanners.deps_dev.ssh_exec")
    @patch("thresher.scanners.entropy.ssh_write_file")
    @patch("thresher.scanners.entropy.ssh_exec")
    @patch("thresher.scanners.install_hooks.ssh_write_file")
    @patch("thresher.scanners.install_hooks.ssh_exec")
    @patch("thresher.scanners.guarddog_deps.ssh_write_file")
    @patch("thresher.scanners.guarddog_deps.ssh_exec")
    @patch("thresher.scanners.semgrep_supply_chain.ssh_exec")
    @patch("thresher.scanners.clamav.ssh_exec")
    @patch("thresher.scanners.scancode.ssh_exec")
    @patch("thresher.scanners.cargo_audit.ssh_exec")
    @patch("thresher.scanners.govulncheck.ssh_exec")
    @patch("thresher.scanners.capa_scanner.ssh_exec")
    @patch("thresher.scanners.yara_scanner.ssh_exec")
    @patch("thresher.scanners.trivy.ssh_exec")
    @patch("thresher.scanners.hadolint.ssh_exec")
    @patch("thresher.scanners.checkov.ssh_exec")
    @patch("thresher.scanners.bandit.ssh_exec")
    @patch("thresher.scanners.runner.ssh_exec")
    @patch("thresher.scanners.syft.ssh_exec")
    @patch("thresher.scanners.grype.ssh_exec")
    @patch("thresher.scanners.osv.ssh_exec")
    @patch("thresher.scanners.semgrep.ssh_exec")
    @patch("thresher.scanners.guarddog.ssh_exec")
    @patch("thresher.scanners.gitleaks.ssh_exec")
    def test_scanner_exception_handled(
        self,
        mock_gl, mock_gd, mock_sg, mock_osv, mock_grype, mock_syft, mock_runner_ssh,
        mock_bandit, mock_checkov, mock_hadolint, mock_trivy, mock_yara,
        mock_capa, mock_govulncheck, mock_cargo_audit, mock_scancode, mock_clamav,
        mock_semgrep_sc, mock_guarddog_deps_exec, mock_guarddog_deps_write,
        mock_install_hooks_exec, mock_install_hooks_write,
        mock_entropy_exec, mock_entropy_write,
        mock_deps_dev_exec, mock_deps_dev_write,
        mock_registry_meta_exec, mock_registry_meta_write,
    ):
        mock_runner_ssh.return_value = SSHResult("", "", 0)
        mock_syft.return_value = SSHResult("", "", 0)

        # Make grype raise an exception
        mock_grype.side_effect = RuntimeError("connection lost")

        # Others succeed (single call each — no more cat+parse)
        mock_osv.return_value = SSHResult("", "", 0)
        mock_sg.return_value = SSHResult("", "", 0)
        mock_gd.return_value = SSHResult("", "", 0)
        mock_gl.return_value = SSHResult("", "", 0)

        mock_bandit.return_value = SSHResult("", "", 0)
        mock_checkov.return_value = SSHResult("", "", 0)
        mock_hadolint.return_value = SSHResult("", "", 0)
        mock_trivy.return_value = SSHResult("", "", 0)
        mock_yara.return_value = SSHResult("", "", 0)
        mock_capa.return_value = SSHResult("", "", 0)
        mock_govulncheck.return_value = SSHResult("", "", 0)
        mock_cargo_audit.return_value = SSHResult("", "", 0)
        mock_scancode.return_value = SSHResult("", "", 0)
        mock_clamav.return_value = SSHResult("", "", 0)

        # New scanners
        mock_semgrep_sc.return_value = SSHResult("", "", 0)
        mock_guarddog_deps_exec.return_value = SSHResult("", "", 0)
        mock_guarddog_deps_write.return_value = None
        mock_install_hooks_exec.return_value = SSHResult("", "", 0)
        mock_install_hooks_write.return_value = None
        mock_entropy_exec.return_value = SSHResult("", "", 0)
        mock_entropy_write.return_value = None
        mock_deps_dev_exec.return_value = SSHResult("", "", 0)
        mock_deps_dev_write.return_value = None
        mock_registry_meta_exec.return_value = SSHResult("", "", 0)
        mock_registry_meta_write.return_value = None

        results = run_all_scanners("test-vm", _make_config())

        # All 22 should still be present
        assert len(results) == 22

        # Grype should have an error entry
        grype = [r for r in results if r.tool_name == "grype"][0]
        assert grype.exit_code == -1
        assert len(grype.errors) > 0

    @patch("thresher.scanners.registry_meta.ssh_write_file")
    @patch("thresher.scanners.registry_meta.ssh_exec")
    @patch("thresher.scanners.deps_dev.ssh_write_file")
    @patch("thresher.scanners.deps_dev.ssh_exec")
    @patch("thresher.scanners.entropy.ssh_write_file")
    @patch("thresher.scanners.entropy.ssh_exec")
    @patch("thresher.scanners.install_hooks.ssh_write_file")
    @patch("thresher.scanners.install_hooks.ssh_exec")
    @patch("thresher.scanners.guarddog_deps.ssh_write_file")
    @patch("thresher.scanners.guarddog_deps.ssh_exec")
    @patch("thresher.scanners.semgrep_supply_chain.ssh_exec")
    @patch("thresher.scanners.clamav.ssh_exec")
    @patch("thresher.scanners.scancode.ssh_exec")
    @patch("thresher.scanners.cargo_audit.ssh_exec")
    @patch("thresher.scanners.govulncheck.ssh_exec")
    @patch("thresher.scanners.capa_scanner.ssh_exec")
    @patch("thresher.scanners.yara_scanner.ssh_exec")
    @patch("thresher.scanners.trivy.ssh_exec")
    @patch("thresher.scanners.hadolint.ssh_exec")
    @patch("thresher.scanners.checkov.ssh_exec")
    @patch("thresher.scanners.bandit.ssh_exec")
    @patch("thresher.scanners.runner.ssh_exec")
    @patch("thresher.scanners.syft.ssh_exec")
    @patch("thresher.scanners.grype.ssh_exec")
    @patch("thresher.scanners.osv.ssh_exec")
    @patch("thresher.scanners.semgrep.ssh_exec")
    @patch("thresher.scanners.guarddog.ssh_exec")
    @patch("thresher.scanners.gitleaks.ssh_exec")
    def test_exit_code_1_is_findings(
        self,
        mock_gl, mock_gd, mock_sg, mock_osv, mock_grype, mock_syft, mock_runner_ssh,
        mock_bandit, mock_checkov, mock_hadolint, mock_trivy, mock_yara,
        mock_capa, mock_govulncheck, mock_cargo_audit, mock_scancode, mock_clamav,
        mock_semgrep_sc, mock_guarddog_deps_exec, mock_guarddog_deps_write,
        mock_install_hooks_exec, mock_install_hooks_write,
        mock_entropy_exec, mock_entropy_write,
        mock_deps_dev_exec, mock_deps_dev_write,
        mock_registry_meta_exec, mock_registry_meta_write,
    ):
        """Exit code 1 from Grype/OSV/Gitleaks means findings found, not error."""
        mock_runner_ssh.return_value = SSHResult("", "", 0)
        mock_syft.return_value = SSHResult("", "", 0)

        # Single call each — no more cat+parse
        mock_grype.return_value = SSHResult("", "", 1)
        mock_osv.return_value = SSHResult("", "", 1)
        mock_sg.return_value = SSHResult("", "", 0)
        mock_gd.return_value = SSHResult("", "", 0)
        mock_gl.return_value = SSHResult("", "", 1)

        mock_bandit.return_value = SSHResult("", "", 0)
        mock_checkov.return_value = SSHResult("", "", 0)
        mock_hadolint.return_value = SSHResult("", "", 0)
        mock_trivy.return_value = SSHResult("", "", 0)
        mock_yara.return_value = SSHResult("", "", 0)
        mock_capa.return_value = SSHResult("", "", 0)
        mock_govulncheck.return_value = SSHResult("", "", 0)
        mock_cargo_audit.return_value = SSHResult("", "", 0)
        mock_scancode.return_value = SSHResult("", "", 0)
        mock_clamav.return_value = SSHResult("", "", 0)

        # New scanners
        mock_semgrep_sc.return_value = SSHResult("", "", 0)
        mock_guarddog_deps_exec.return_value = SSHResult("", "", 0)
        mock_guarddog_deps_write.return_value = None
        mock_install_hooks_exec.return_value = SSHResult("", "", 0)
        mock_install_hooks_write.return_value = None
        mock_entropy_exec.return_value = SSHResult("", "", 0)
        mock_entropy_write.return_value = None
        mock_deps_dev_exec.return_value = SSHResult("", "", 0)
        mock_deps_dev_write.return_value = None
        mock_registry_meta_exec.return_value = SSHResult("", "", 0)
        mock_registry_meta_write.return_value = None

        results = run_all_scanners("test-vm", _make_config())

        for r in results:
            assert len(r.errors) == 0, f"{r.tool_name} should not have errors for exit code 1"
