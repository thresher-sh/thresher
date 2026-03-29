"""Tests for threat_scanner.docker.sandbox."""

from __future__ import annotations

from unittest.mock import patch

from threat_scanner.docker.sandbox import (
    ECOSYSTEM_IMAGES,
    ECOSYSTEM_INDICATORS,
    _parse_package_name,
    detect_ecosystems,
)
from threat_scanner.vm.ssh import SSHResult


# sandbox.py imports ssh_exec locally inside functions via
# "from threat_scanner.vm.ssh import ssh_exec", so we patch the
# canonical location in the ssh module.
SSH_EXEC_PATH = "threat_scanner.vm.ssh.ssh_exec"


class TestDetectEcosystems:
    @patch(SSH_EXEC_PATH)
    def test_python(self, mock_exec):
        mock_exec.return_value = SSHResult("python\n", "", 0)
        result = detect_ecosystems("vm", "/opt/target")
        assert result == ["python"]

    @patch(SSH_EXEC_PATH)
    def test_node(self, mock_exec):
        mock_exec.return_value = SSHResult("node\n", "", 0)
        result = detect_ecosystems("vm", "/opt/target")
        assert result == ["node"]

    @patch(SSH_EXEC_PATH)
    def test_multi_ecosystem(self, mock_exec):
        mock_exec.return_value = SSHResult("python\nnode\nrust\n", "", 0)
        result = detect_ecosystems("vm", "/opt/target")
        assert result == ["node", "python", "rust"]

    @patch(SSH_EXEC_PATH)
    def test_no_ecosystems(self, mock_exec):
        mock_exec.return_value = SSHResult("", "", 0)
        result = detect_ecosystems("vm", "/opt/target")
        assert result == []

    @patch(SSH_EXEC_PATH)
    def test_deduplication(self, mock_exec):
        mock_exec.return_value = SSHResult("python\npython\npython\n", "", 0)
        result = detect_ecosystems("vm", "/opt/target")
        assert result == ["python"]


class TestParsePackageName:
    def test_python_tar_gz(self):
        name, ver = _parse_package_name("requests-2.31.0.tar.gz", "python")
        assert name == "requests"
        assert ver == "2.31.0"

    def test_python_zip(self):
        name, ver = _parse_package_name("foo-1.0.zip", "python")
        assert name == "foo"
        assert ver == "1.0"

    def test_python_no_version(self):
        name, ver = _parse_package_name("somepkg.tar.gz", "python")
        assert name == "somepkg"
        assert ver == "unknown"

    def test_node_tgz(self):
        name, ver = _parse_package_name("express-4.18.2.tgz", "node")
        assert name == "express"
        assert ver == "4.18.2"

    def test_node_no_version(self):
        name, ver = _parse_package_name("lodash.tgz", "node")
        assert name == "lodash"
        assert ver == "unknown"

    def test_rust_dir_with_version(self):
        name, ver = _parse_package_name("serde-1.0.193", "rust")
        assert name == "serde"
        assert ver == "1.0.193"

    def test_rust_dir_no_version(self):
        name, ver = _parse_package_name("serde", "rust")
        assert name == "serde"
        assert ver == "unknown"

    def test_go_dir(self):
        name, ver = _parse_package_name("modules", "go")
        assert name == "modules"
        assert ver == "unknown"

    def test_unknown_ecosystem(self):
        name, ver = _parse_package_name("anything", "unknown_eco")
        assert name == "anything"
        assert ver == "unknown"


class TestDockerRunUsesSudo:
    @patch(SSH_EXEC_PATH)
    def test_sudo_in_command(self, mock_exec):
        mock_exec.return_value = SSHResult("", "", 0)
        from threat_scanner.docker.sandbox import _docker_run

        _docker_run("vm", "python:3.12", "echo hi", [], network=True)
        cmd = mock_exec.call_args[0][1]
        assert cmd.startswith("sudo docker run")

    @patch(SSH_EXEC_PATH)
    def test_network_none(self, mock_exec):
        mock_exec.return_value = SSHResult("", "", 0)
        from threat_scanner.docker.sandbox import _docker_run

        _docker_run("vm", "python:3.12", "echo hi", [], network=False)
        cmd = mock_exec.call_args[0][1]
        assert "--network=none" in cmd
