"""Tests for thresher.run — subprocess runner with limits enforcement."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from thresher.run import run, set_max_stdout, set_verbose


def _mock_popen(returncode=0, stdout=b""):
    """Create a mock that behaves like subprocess.Popen."""
    mock = MagicMock()
    mock.stdout = iter(stdout.splitlines(keepends=True)) if stdout else iter([])
    mock.returncode = returncode
    mock.wait.return_value = returncode
    mock.kill = MagicMock()
    return mock


class TestSetMaxStdout:
    def test_set_max_stdout_changes_limit(self):
        """set_max_stdout should update the module-level limit."""
        import thresher.run as run_module
        original = run_module._max_stdout_bytes
        try:
            set_max_stdout(1024)
            assert run_module._max_stdout_bytes == 1024
        finally:
            run_module._max_stdout_bytes = original


class TestStdoutLimit:
    @patch("thresher.run._popen")
    def test_stdout_within_limit_completes(self, mock_popen):
        """Process with stdout under the limit should complete normally."""
        output = b"line 1\nline 2\nline 3\n"
        mock_popen.return_value = _mock_popen(returncode=0, stdout=output)

        import thresher.run as run_module
        original = run_module._max_stdout_bytes
        try:
            set_max_stdout(1024)  # 1KB — plenty of room
            result = run(["echo", "test"], label="test")
            assert result.returncode == 0
            assert result.stdout == output
        finally:
            run_module._max_stdout_bytes = original

    @patch("thresher.run._popen")
    def test_stdout_exceeds_limit_kills_process(self, mock_popen):
        """Process that exceeds max_stdout_bytes should be killed."""
        # Create output that exceeds a 50 byte limit
        output = b"x" * 100 + b"\n"
        mock_popen.return_value = _mock_popen(returncode=0, stdout=output)

        import thresher.run as run_module
        original = run_module._max_stdout_bytes
        try:
            set_max_stdout(50)
            result = run(["echo", "test"], label="test")
            # Process should have been killed
            mock_popen.return_value.kill.assert_called_once()
        finally:
            run_module._max_stdout_bytes = original

    @patch("thresher.run._popen")
    def test_stdout_limit_zero_means_unlimited(self, mock_popen):
        """A limit of 0 should mean no limit (unlimited)."""
        output = b"x" * 10000 + b"\n"
        mock_popen.return_value = _mock_popen(returncode=0, stdout=output)

        import thresher.run as run_module
        original = run_module._max_stdout_bytes
        try:
            set_max_stdout(0)
            result = run(["echo", "test"], label="test")
            mock_popen.return_value.kill.assert_not_called()
            assert result.stdout == output
        finally:
            run_module._max_stdout_bytes = original

    @patch("thresher.run._popen")
    def test_stdout_limit_logs_warning(self, mock_popen, caplog):
        """When stdout is killed for exceeding limit, a warning should be logged."""
        import logging
        output = b"x" * 100 + b"\n"
        mock_popen.return_value = _mock_popen(returncode=0, stdout=output)

        import thresher.run as run_module
        original = run_module._max_stdout_bytes
        try:
            set_max_stdout(50)
            with caplog.at_level(logging.WARNING, logger="thresher.run"):
                run(["echo", "test"], label="test")
            assert "stdout limit" in caplog.text.lower()
        finally:
            run_module._max_stdout_bytes = original


class TestRun:
    @patch("thresher.run._popen")
    def test_returns_completed_process(self, mock_popen):
        mock_popen.return_value = _mock_popen(returncode=0, stdout=b"ok\n")
        result = run(["echo", "ok"], label="test")
        assert isinstance(result, subprocess.CompletedProcess)
        assert result.returncode == 0

    @patch("thresher.run._popen")
    def test_captures_stdout(self, mock_popen):
        mock_popen.return_value = _mock_popen(returncode=0, stdout=b"hello\nworld\n")
        result = run(["echo"], label="test")
        assert result.stdout == b"hello\nworld\n"

    @patch("thresher.run._popen")
    def test_nonzero_exit(self, mock_popen):
        mock_popen.return_value = _mock_popen(returncode=1, stdout=b"err\n")
        result = run(["false"], label="test")
        assert result.returncode == 1
