"""Tests for thresher.launcher.docker."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from thresher.config import ScanConfig
from thresher.launcher.docker import DOCKER_IMAGE, _build_docker_cmd, launch_docker


def _make_config() -> ScanConfig:
    return ScanConfig(
        repo_url="https://github.com/example/pkg",
        output_dir="/tmp/test-output",
        skip_ai=True,
    )


class TestBuildDockerCmd:
    def test_starts_with_docker_run(self):
        config = _make_config()
        cmd = _build_docker_cmd(config, "/tmp/config.json")
        assert cmd[:2] == ["docker", "run"]

    def test_includes_read_only(self):
        config = _make_config()
        cmd = _build_docker_cmd(config, "/tmp/config.json")
        assert "--read-only" in cmd

    def test_includes_rm(self):
        config = _make_config()
        cmd = _build_docker_cmd(config, "/tmp/config.json")
        assert "--rm" in cmd

    def test_includes_cap_drop_all(self):
        config = _make_config()
        cmd = _build_docker_cmd(config, "/tmp/config.json")
        assert "--cap-drop=ALL" in cmd

    def test_includes_no_new_privileges(self):
        config = _make_config()
        cmd = _build_docker_cmd(config, "/tmp/config.json")
        assert "--security-opt=no-new-privileges" in cmd

    def test_includes_user_thresher(self):
        config = _make_config()
        cmd = _build_docker_cmd(config, "/tmp/config.json")
        assert "--user" in cmd
        idx = cmd.index("--user")
        assert cmd[idx + 1] == "thresher"

    def test_includes_anthropic_api_key_env(self):
        config = _make_config()
        cmd = _build_docker_cmd(config, "/tmp/config.json")
        # -e ANTHROPIC_API_KEY should appear as two consecutive elements
        assert "-e" in cmd
        e_indices = [i for i, v in enumerate(cmd) if v == "-e"]
        env_vars = [cmd[i + 1] for i in e_indices]
        assert "ANTHROPIC_API_KEY" in env_vars

    def test_includes_oauth_token_env(self):
        config = _make_config()
        cmd = _build_docker_cmd(config, "/tmp/config.json")
        e_indices = [i for i, v in enumerate(cmd) if v == "-e"]
        env_vars = [cmd[i + 1] for i in e_indices]
        assert "CLAUDE_CODE_OAUTH_TOKEN" in env_vars

    def test_includes_tmpfs_mounts(self):
        config = _make_config()
        cmd = _build_docker_cmd(config, "/tmp/config.json")
        tmpfs_indices = [i for i, v in enumerate(cmd) if v == "--tmpfs"]
        tmpfs_targets = [cmd[i + 1] for i in tmpfs_indices]
        # Verify key tmpfs mounts are present
        assert any("/tmp:" in t for t in tmpfs_targets)
        assert any("/opt/target:" in t for t in tmpfs_targets)
        assert any("/opt/scan-results:" in t for t in tmpfs_targets)
        assert any("/opt/deps:" in t for t in tmpfs_targets)

    def test_includes_output_volume(self):
        config = _make_config()
        cmd = _build_docker_cmd(config, "/tmp/config.json")
        v_indices = [i for i, v in enumerate(cmd) if v == "-v"]
        vol_args = [cmd[i + 1] for i in v_indices]
        assert any("/output" in v for v in vol_args)
        assert any(config.output_dir in v for v in vol_args)

    def test_includes_config_volume(self):
        config_path = "/tmp/my-config.json"
        config = _make_config()
        cmd = _build_docker_cmd(config, config_path)
        v_indices = [i for i, v in enumerate(cmd) if v == "-v"]
        vol_args = [cmd[i + 1] for i in v_indices]
        assert any(config_path in v for v in vol_args)
        assert any(":ro" in v for v in vol_args)

    def test_uses_correct_image(self):
        config = _make_config()
        cmd = _build_docker_cmd(config, "/tmp/config.json")
        assert DOCKER_IMAGE in cmd

    def test_harness_config_flag(self):
        config = _make_config()
        cmd = _build_docker_cmd(config, "/tmp/config.json")
        assert "--config" in cmd
        idx = cmd.index("--config")
        assert cmd[idx + 1] == "/config/config.json"

    def test_harness_output_flag(self):
        config = _make_config()
        cmd = _build_docker_cmd(config, "/tmp/config.json")
        assert "--output" in cmd
        idx = cmd.index("--output")
        assert cmd[idx + 1] == "/output"


class TestLaunchDocker:
    def test_calls_subprocess_run(self):
        config = _make_config()
        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch("thresher.launcher.docker.subprocess.run", return_value=mock_result) as mock_run:
            rc = launch_docker(config)
        assert rc == 0
        mock_run.assert_called_once()

    def test_returns_exit_code(self):
        config = _make_config()
        mock_result = MagicMock()
        mock_result.returncode = 42
        with patch("thresher.launcher.docker.subprocess.run", return_value=mock_result):
            rc = launch_docker(config)
        assert rc == 42

    def test_config_file_cleaned_up(self, tmp_path):
        config = ScanConfig(
            repo_url="https://github.com/example/pkg",
            output_dir=str(tmp_path),
            skip_ai=True,
        )
        captured_path = []

        def capture(cmd, **kwargs):
            # Config path is passed via -v flag, find it
            v_indices = [i for i, v in enumerate(cmd) if v == "-v"]
            for i in v_indices:
                vol = cmd[i + 1]
                if "/config/config.json:ro" in vol:
                    captured_path.append(vol.split(":")[0])
            r = MagicMock()
            r.returncode = 0
            return r

        with patch("thresher.launcher.docker.subprocess.run", side_effect=capture):
            launch_docker(config)

        import os
        assert captured_path, "Should have captured config path"
        assert not os.path.exists(captured_path[0]), "Temp config file should be deleted"

    def test_config_file_cleaned_up_on_exception(self, tmp_path):
        config = ScanConfig(
            repo_url="https://github.com/example/pkg",
            output_dir=str(tmp_path),
            skip_ai=True,
        )
        captured_path = []

        def capture_and_raise(cmd, **kwargs):
            v_indices = [i for i, v in enumerate(cmd) if v == "-v"]
            for i in v_indices:
                vol = cmd[i + 1]
                if "/config/config.json:ro" in vol:
                    captured_path.append(vol.split(":")[0])
            raise OSError("docker not found")

        with patch("thresher.launcher.docker.subprocess.run", side_effect=capture_and_raise):
            with pytest.raises(OSError):
                launch_docker(config)

        import os
        assert captured_path, "Should have captured config path"
        assert not os.path.exists(captured_path[0]), "Temp config file should be deleted on failure"
