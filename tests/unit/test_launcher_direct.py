"""Tests for thresher.launcher.direct."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

from thresher.config import ScanConfig
from thresher.launcher.direct import launch_direct


def _make_config() -> ScanConfig:
    return ScanConfig(
        repo_url="https://github.com/example/pkg",
        output_dir="/tmp/test-output",
        skip_ai=True,
    )


class TestLaunchDirect:
    def test_calls_subprocess_run(self):
        config = _make_config()
        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch("thresher.launcher.direct.subprocess.run", return_value=mock_result) as mock_run:
            rc = launch_direct(config)
        assert rc == 0
        mock_run.assert_called_once()

    def test_command_uses_sys_executable(self):
        config = _make_config()
        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch("thresher.launcher.direct.subprocess.run", return_value=mock_result) as mock_run:
            launch_direct(config)
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == sys.executable

    def test_command_includes_harness_module(self):
        config = _make_config()
        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch("thresher.launcher.direct.subprocess.run", return_value=mock_result) as mock_run:
            launch_direct(config)
        cmd = mock_run.call_args[0][0]
        assert "-m" in cmd
        m_idx = cmd.index("-m")
        assert cmd[m_idx + 1] == "thresher.harness"

    def test_command_includes_config_flag(self):
        config = _make_config()
        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch("thresher.launcher.direct.subprocess.run", return_value=mock_result) as mock_run:
            launch_direct(config)
        cmd = mock_run.call_args[0][0]
        assert "--config" in cmd

    def test_command_includes_output_flag(self):
        config = _make_config()
        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch("thresher.launcher.direct.subprocess.run", return_value=mock_result) as mock_run:
            launch_direct(config)
        cmd = mock_run.call_args[0][0]
        assert "--output" in cmd
        out_idx = cmd.index("--output")
        assert cmd[out_idx + 1] == config.output_dir

    def test_returns_nonzero_exit_code(self):
        config = _make_config()
        mock_result = MagicMock()
        mock_result.returncode = 1
        with patch("thresher.launcher.direct.subprocess.run", return_value=mock_result):
            rc = launch_direct(config)
        assert rc == 1

    def test_config_file_cleaned_up_on_success(self, tmp_path):
        config = ScanConfig(
            repo_url="https://github.com/example/pkg",
            output_dir=str(tmp_path),
            skip_ai=True,
        )
        captured_path = []

        def capture_and_run(cmd, **kwargs):
            # Find the config path from --config flag
            idx = cmd.index("--config")
            captured_path.append(cmd[idx + 1])
            r = MagicMock()
            r.returncode = 0
            return r

        with patch("thresher.launcher.direct.subprocess.run", side_effect=capture_and_run):
            launch_direct(config)

        import os
        assert not os.path.exists(captured_path[0]), "Temp config file should be deleted"

    def test_config_file_cleaned_up_on_failure(self, tmp_path):
        config = ScanConfig(
            repo_url="https://github.com/example/pkg",
            output_dir=str(tmp_path),
            skip_ai=True,
        )
        captured_path = []

        def capture_and_raise(cmd, **kwargs):
            idx = cmd.index("--config")
            captured_path.append(cmd[idx + 1])
            raise RuntimeError("subprocess failed")

        with patch("thresher.launcher.direct.subprocess.run", side_effect=capture_and_raise):
            with pytest.raises(RuntimeError):
                launch_direct(config)

        import os
        assert not os.path.exists(captured_path[0]), "Temp config file should be deleted even on failure"

    def test_config_serialized_to_temp_file(self):
        """Verifies the config JSON is written to the temp file before subprocess."""
        config = _make_config()
        written_content = []

        original_run = __import__("subprocess").run

        def fake_run(cmd, **kwargs):
            idx = cmd.index("--config")
            path = cmd[idx + 1]
            import os
            if os.path.exists(path):
                with open(path) as f:
                    written_content.append(f.read())
            r = MagicMock()
            r.returncode = 0
            return r

        with patch("thresher.launcher.direct.subprocess.run", side_effect=fake_run):
            launch_direct(config)

        assert len(written_content) == 1
        import json
        data = json.loads(written_content[0])
        assert data["repo_url"] == config.repo_url
