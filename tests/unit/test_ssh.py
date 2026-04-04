"""Tests for thresher.vm.ssh."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from thresher.vm.ssh import (
    SSHError,
    SSHResult,
    _redact_credentials,
    _shell_quote,
    ssh_copy_from,
    ssh_exec,
    ssh_write_file,
)


class TestSSHResult:
    def test_attribute_access(self):
        r = SSHResult("out", "err", 0)
        assert r.stdout == "out"
        assert r.stderr == "err"
        assert r.exit_code == 0

    def test_destructuring(self):
        stdout, stderr, rc = SSHResult("out", "err", 42)
        assert stdout == "out"
        assert stderr == "err"
        assert rc == 42

    def test_indexing(self):
        r = SSHResult("a", "b", 1)
        assert r[0] == "a"
        assert r[1] == "b"
        assert r[2] == 1


class TestShellQuote:
    def test_simple(self):
        assert _shell_quote("hello") == "'hello'"

    def test_single_quotes(self):
        result = _shell_quote("it's")
        assert result == "'it'\\''s'"

    def test_special_chars(self):
        result = _shell_quote("$HOME `id` \\n")
        # Should be wrapped in single quotes, neutralizing $, `, etc.
        assert result.startswith("'")
        assert result.endswith("'")
        assert "$HOME" in result


def _mock_popen(stdout_data="", stderr_data="", returncode=0):
    """Create a mock Popen with real file descriptors for selectors."""
    import io
    import os

    # Create real pipes so selectors.DefaultSelector works
    stdout_r, stdout_w = os.pipe()
    stderr_r, stderr_w = os.pipe()

    # Write data and close write ends so reads see EOF
    os.write(stdout_w, stdout_data.encode())
    os.close(stdout_w)
    os.write(stderr_w, stderr_data.encode())
    os.close(stderr_w)

    mock_proc = MagicMock()
    mock_proc.stdout = io.TextIOWrapper(io.FileIO(stdout_r, closefd=True))
    mock_proc.stderr = io.TextIOWrapper(io.FileIO(stderr_r, closefd=True))
    mock_proc.returncode = returncode
    mock_proc.wait.return_value = returncode
    mock_proc.kill = MagicMock()
    return mock_proc


class TestSSHExec:
    @patch("thresher.vm.ssh.subprocess.Popen")
    def test_returns_ssh_result(self, mock_popen_cls):
        mock_popen_cls.return_value = _mock_popen(stdout_data="hello\n")
        result = ssh_exec("test-vm", "echo hello")
        assert isinstance(result, SSHResult)
        assert result.stdout == "hello\n"
        assert result.exit_code == 0

    @patch("thresher.vm.ssh.subprocess.Popen")
    def test_env_uses_export(self, mock_popen_cls):
        mock_popen_cls.return_value = _mock_popen()
        ssh_exec("vm", "cmd", env={"FOO": "bar"})
        cmd_list = mock_popen_cls.call_args[0][0]
        full_cmd = cmd_list[-1]  # bash -c "..."
        assert "export FOO=" in full_cmd

    @patch("thresher.vm.ssh.subprocess.Popen")
    def test_no_env(self, mock_popen_cls):
        mock_popen_cls.return_value = _mock_popen()
        ssh_exec("vm", "echo hi")
        cmd_list = mock_popen_cls.call_args[0][0]
        full_cmd = cmd_list[-1]
        assert "export" not in full_cmd
        assert "echo hi" in full_cmd

    @patch("thresher.vm.ssh.subprocess.Popen")
    def test_timeout_raises_ssh_error(self, mock_popen_cls):
        mock_popen_cls.return_value = _mock_popen()
        with pytest.raises(SSHError, match="timed out"):
            ssh_exec("vm", "slow", timeout=0)

    @patch("thresher.vm.ssh.subprocess.Popen")
    def test_missing_limactl_raises_ssh_error(self, mock_popen_cls):
        mock_popen_cls.side_effect = FileNotFoundError()
        with pytest.raises(SSHError, match="limactl not found"):
            ssh_exec("vm", "cmd")


class TestSSHCopyFrom:
    @patch("thresher.vm.ssh.subprocess.run")
    def test_recursive_flag(self, mock_run, tmp_path):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        ssh_copy_from("vm", "/remote/dir", str(tmp_path / "out"))
        cmd = mock_run.call_args[0][0]
        assert "-r" in cmd


class TestSSHWriteFile:
    @patch("thresher.vm.ssh.ssh_copy_to")
    def test_writes_and_cleans_up(self, mock_copy_to):
        ssh_write_file("vm", "content here", "/remote/file.txt")
        assert mock_copy_to.called
        # The temp file should have been cleaned up
        local_path = mock_copy_to.call_args[0][1]
        assert not Path(local_path).exists()

    @patch("thresher.vm.ssh.ssh_copy_to")
    def test_content_matches(self, mock_copy_to, tmp_path):
        # We can't easily check content since temp file is deleted,
        # but we can verify the remote path is correct
        ssh_write_file("vm", "test content", "/remote/out.txt")
        assert mock_copy_to.call_args[0][2] == "/remote/out.txt"
        assert mock_copy_to.call_args[0][0] == "vm"


class TestRedactCredentials:
    def test_redacts_oat_token(self):
        text = "command with sk-ant-oat01-jcFmozABC123_def in it"
        result = _redact_credentials(text)
        assert "sk-ant-oat01-****" in result
        assert "jcFmozABC123_def" not in result

    def test_redacts_api_key(self):
        text = "key is sk-ant-api03-abcDEF789xyz"
        result = _redact_credentials(text)
        assert "sk-ant-api****" in result
        assert "abcDEF789xyz" not in result

    def test_redacts_printf_tmpfs_payload(self):
        text = "printf '%s' 'sk-ant-oat01-secret123' > /dev/shm/.cred_KEY"
        result = _redact_credentials(text)
        assert "'[REDACTED]'" in result
        assert "secret123" not in result
        assert "/dev/shm/.cred_KEY" in result

    def test_preserves_non_credential_text(self):
        text = "echo hello world"
        result = _redact_credentials(text)
        assert result == text

    def test_preserves_printf_not_targeting_tmpfs(self):
        text = "printf '%s' 'safe-value' > /tmp/output.txt"
        result = _redact_credentials(text)
        assert "safe-value" in result

    def test_redacts_credential_in_logged_label(self):
        # Simulate the label that ssh_exec logs
        command = "printf '%s' 'sk-ant-oat01-longTokenValue_here' > /dev/shm/.cred_ANTHROPIC"
        label = _redact_credentials(command[:80])
        assert "longTokenValue" not in label
        assert "/dev/shm/.cred_ANTHROPIC" in label

    @patch("thresher.vm.ssh.subprocess.Popen")
    def test_ssh_exec_redacts_label_in_log(self, mock_popen_cls, caplog):
        mock_popen_cls.return_value = _mock_popen()
        import logging
        with caplog.at_level(logging.INFO):
            ssh_exec("vm", "printf '%s' 'sk-ant-oat01-SECRET' > /dev/shm/.cred_KEY")
        # The logged label should be redacted
        assert "sk-ant-oat01-SECRET" not in caplog.text
        assert "[REDACTED]" in caplog.text

    @patch("thresher.vm.ssh.subprocess.Popen")
    def test_ssh_exec_redacts_stdout_in_log(self, mock_popen_cls, caplog):
        mock_popen_cls.return_value = _mock_popen(
            stdout_data="token: sk-ant-oat01-leaked123\n"
        )
        import logging
        with caplog.at_level(logging.INFO):
            result = ssh_exec("vm", "echo token")
        # The actual stdout should NOT be redacted (only logs)
        assert "sk-ant-oat01-leaked123" in result.stdout
        # But the log output should be redacted
        assert "sk-ant-oat01-****" in caplog.text
        assert "sk-ant-oat01-leaked123" not in caplog.text
