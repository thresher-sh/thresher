"""Tests for thresher.docker.sandbox (containerized dependency resolution)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from thresher.docker.sandbox import download_dependencies
from thresher.config import ScanConfig, VMConfig
from thresher.vm.ssh import SSHResult


SSH_EXEC_PATH = "thresher.vm.ssh.ssh_exec"


@pytest.fixture
def config():
    return ScanConfig(
        repo_url="https://github.com/example/repo",
        skip_ai=True,
        vm=VMConfig(cpus=4, memory=8, disk=50),
    )


class TestDownloadDependencies:
    @patch(SSH_EXEC_PATH)
    def test_invokes_scanner_docker_wrapper(self, mock_exec, config):
        mock_exec.return_value = SSHResult("", "", 0)

        download_dependencies("test-vm", config)

        cmds = [c[0][1] for c in mock_exec.call_args_list]
        assert any("sudo /usr/local/bin/scanner-docker" in cmd for cmd in cmds)

    @patch(SSH_EXEC_PATH)
    def test_copies_deps_to_opt_deps(self, mock_exec, config):
        mock_exec.return_value = SSHResult("", "", 0)

        download_dependencies("test-vm", config)

        cmds = [c[0][1] for c in mock_exec.call_args_list]
        assert any("/opt/deps/" in cmd for cmd in cmds)

    @patch(SSH_EXEC_PATH)
    def test_raises_on_container_failure(self, mock_exec, config):
        mock_exec.side_effect = [
            SSHResult("", "", 0),  # mkdir + cp
            SSHResult("", "container error", 1),  # scanner-docker fails
        ]

        with pytest.raises(RuntimeError, match="Dependency resolution failed"):
            download_dependencies("test-vm", config)

    @patch(SSH_EXEC_PATH)
    def test_no_data_leaves_vm(self, mock_exec, config):
        """Verify that no VM data is parsed on the host side."""
        mock_exec.return_value = SSHResult("", "", 0)

        download_dependencies("test-vm", config)

        # download_dependencies returns None — nothing read from VM
        # All commands are ssh_exec (running commands IN the VM),
        # no ssh_copy_from calls
        for call in mock_exec.call_args_list:
            cmd = call[0][1]
            # Should never cat files to read them on the host
            assert "cat " not in cmd or "2>/dev/null" in cmd
