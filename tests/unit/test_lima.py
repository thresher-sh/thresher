"""Unit tests for Lima VM lifecycle, including base VM caching."""

from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import pytest

from thresher.config import ScanConfig, VMConfig
from thresher.vm.lima import (
    BASE_VM_NAME,
    LimaError,
    base_exists,
    build_base,
    clean_working_dirs,
    ensure_base_running,
    provision_vm,
    stop_vm,
)


@pytest.fixture
def config():
    return ScanConfig(
        repo_url="",
        skip_ai=True,
        vm=VMConfig(cpus=4, memory=8, disk=50),
    )


class TestBaseExists:
    @patch("thresher.vm.lima.vm_status", return_value="Stopped")
    def test_returns_true_when_stopped(self, mock_status):
        assert base_exists() is True
        mock_status.assert_called_once_with(BASE_VM_NAME)

    @patch("thresher.vm.lima.vm_status", return_value="Running")
    def test_returns_true_when_running(self, mock_status):
        assert base_exists() is True

    @patch("thresher.vm.lima.vm_status", return_value="Not found")
    def test_returns_false_when_not_found(self, mock_status):
        assert base_exists() is False


class TestEnsureBaseRunning:
    @patch("thresher.vm.lima.start_vm")
    @patch("thresher.vm.lima.vm_status", return_value="Stopped")
    def test_starts_stopped_vm(self, mock_status, mock_start):
        name = ensure_base_running()
        assert name == BASE_VM_NAME
        mock_start.assert_called_once_with(BASE_VM_NAME)

    @patch("thresher.vm.lima.start_vm")
    @patch("thresher.vm.lima.vm_status", return_value="Running")
    def test_skips_start_if_running(self, mock_status, mock_start):
        name = ensure_base_running()
        assert name == BASE_VM_NAME
        mock_start.assert_not_called()

    @patch("thresher.vm.lima.vm_status", return_value="Not found")
    def test_raises_when_not_found(self, mock_status):
        with pytest.raises(LimaError, match="not found"):
            ensure_base_running()


class TestBuildBase:
    @patch("thresher.vm.lima.stop_vm")
    @patch("thresher.vm.lima.provision_vm")
    @patch("thresher.vm.lima.start_vm")
    @patch("thresher.vm.lima._run_limactl")
    @patch("thresher.vm.lima._TEMPLATE_PATH")
    @patch("thresher.vm.lima.base_exists", return_value=False)
    def test_builds_fresh_base(
        self, mock_exists, mock_tpl, mock_run, mock_start, mock_prov, mock_stop, config
    ):
        mock_tpl.exists.return_value = True
        mock_tpl.__str__ = lambda s: "/fake/thresher.yaml"
        mock_run.return_value = MagicMock(returncode=0)

        build_base(config)

        # Should create, start, provision, stop
        mock_run.assert_called_once()
        mock_start.assert_called_once_with(BASE_VM_NAME)
        mock_prov.assert_called_once_with(BASE_VM_NAME, config)
        mock_stop.assert_called_once_with(BASE_VM_NAME)

    @patch("thresher.vm.lima.stop_vm")
    @patch("thresher.vm.lima.provision_vm")
    @patch("thresher.vm.lima.start_vm")
    @patch("thresher.vm.lima._run_limactl")
    @patch("thresher.vm.lima._TEMPLATE_PATH")
    @patch("thresher.vm.lima.destroy_vm")
    @patch("thresher.vm.lima.base_exists", return_value=True)
    def test_destroys_existing_before_rebuild(
        self, mock_exists, mock_destroy, mock_tpl, mock_run,
        mock_start, mock_prov, mock_stop, config
    ):
        mock_tpl.exists.return_value = True
        mock_tpl.__str__ = lambda s: "/fake/thresher.yaml"
        mock_run.return_value = MagicMock(returncode=0)

        build_base(config)

        mock_destroy.assert_called_once_with(BASE_VM_NAME)


class TestProvisionVM:
    @patch("thresher.vm.lima.ssh_exec", return_value=("", "", 0))
    @patch("thresher.vm.lima.ssh_copy_to")
    def test_copies_all_hardening_scripts(self, mock_copy, mock_exec, config):
        provision_vm("test-vm", config)

        # Collect all destination paths from ssh_copy_to calls
        copied_destinations = [c[0][2] for c in mock_copy.call_args_list]

        # Core provisioning scripts
        assert "/tmp/provision.sh" in copied_destinations
        assert "/tmp/firewall.sh" in copied_destinations

        # Source download hardening (persistent path, survives reboots)
        assert "/opt/thresher/bin/safe_clone.sh" in copied_destinations

        # Scanner-deps Docker build context
        assert "/tmp/docker-scanner-deps/Dockerfile.scanner-deps" in copied_destinations

        # Network hardening (lockdown)
        assert "/tmp/lockdown.sh" in copied_destinations
        assert "/tmp/scanner-docker" in copied_destinations

    @patch("thresher.vm.lima.ssh_exec", return_value=("", "", 0))
    @patch("thresher.vm.lima.ssh_copy_to")
    def test_lockdown_runs_last(self, mock_copy, mock_exec, config):
        provision_vm("test-vm", config)

        # Collect the commands that were executed via ssh_exec
        exec_cmds = [c[0][1] for c in mock_exec.call_args_list]

        # Find indices of provision, firewall, and lockdown executions
        provision_idx = next(i for i, c in enumerate(exec_cmds) if "provision.sh" in c)
        firewall_idx = next(i for i, c in enumerate(exec_cmds) if "firewall.sh" in c)
        lockdown_idx = next(i for i, c in enumerate(exec_cmds) if "lockdown.sh" in c)

        # Lockdown must run after both provision and firewall
        assert lockdown_idx > provision_idx
        assert lockdown_idx > firewall_idx

    @patch("thresher.vm.lima.ssh_exec")
    @patch("thresher.vm.lima.ssh_copy_to")
    def test_raises_on_lockdown_failure(self, mock_copy, mock_exec, config):
        # All ssh_exec calls succeed except lockdown.sh
        mock_exec.return_value = ("", "", 0)
        call_count = [0]
        original_return = ("", "", 0)

        def side_effect(*args, **kwargs):
            call_count[0] += 1
            cmd = args[1] if len(args) > 1 else ""
            if "lockdown.sh" in cmd:
                return ("", "lockdown error", 1)
            return original_return

        mock_exec.side_effect = side_effect
        with pytest.raises(LimaError, match="Lockdown failed"):
            provision_vm("test-vm", config)


class TestCleanWorkingDirs:
    @patch("thresher.vm.lima.ssh_exec", return_value=("", "", 0))
    def test_cleans_all_dirs(self, mock_ssh):
        clean_working_dirs("test-vm")
        assert mock_ssh.call_count == 6
        # Verify each working dir is cleaned
        cmds = [c[0][1] for c in mock_ssh.call_args_list]
        assert any("/opt/target" in cmd for cmd in cmds)
        assert any("/opt/deps" in cmd for cmd in cmds)
        assert any("/opt/scan-results" in cmd for cmd in cmds)
        assert any("/opt/security-reports" in cmd for cmd in cmds)
        assert any("/opt/thresher/work/target" in cmd for cmd in cmds)
        assert any("/opt/thresher/work/deps" in cmd for cmd in cmds)

    @patch("thresher.vm.lima.ssh_exec", return_value=("", "", 0))
    def test_tries_without_sudo_first(self, mock_ssh):
        """Primary path should not require sudo; sudo is only a fallback."""
        clean_working_dirs("test-vm")
        cmds = [c[0][1] for c in mock_ssh.call_args_list]
        for cmd in cmds:
            # mkdir/chmod should try without sudo first, with sudo as || fallback
            assert "mkdir -p" in cmd
            assert cmd.index("mkdir -p") < cmd.index("sudo mkdir -p")


class TestStopVm:
    @patch("thresher.vm.lima.ssh_exec", return_value=("", "", 0))
    @patch("thresher.vm.lima._run_limactl")
    def test_graceful_stop_syncs_first(self, mock_run, mock_ssh):
        mock_run.return_value = MagicMock(returncode=0)
        stop_vm("test-vm")
        # Graceful stop should sync filesystem then stop without -f
        mock_ssh.assert_called_once_with("test-vm", "sync", timeout=30)
        mock_run.assert_called_once_with(["limactl", "stop", "test-vm"], timeout=120)

    @patch("thresher.vm.lima.ssh_exec", return_value=("", "", 0))
    @patch("thresher.vm.lima._run_limactl")
    def test_raises_on_failure(self, mock_run, mock_ssh):
        mock_run.return_value = MagicMock(returncode=1, stderr="error")
        with pytest.raises(LimaError, match="Failed to stop"):
            stop_vm("test-vm")
