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
        cmd = _build_docker_cmd(config, "/tmp/config.json", config.output_dir)
        assert cmd[:2] == ["docker", "run"]

    def test_includes_read_only(self):
        config = _make_config()
        cmd = _build_docker_cmd(config, "/tmp/config.json", config.output_dir)
        assert "--read-only" in cmd

    def test_includes_rm(self):
        config = _make_config()
        cmd = _build_docker_cmd(config, "/tmp/config.json", config.output_dir)
        assert "--rm" in cmd

    def test_includes_cap_drop_all(self):
        config = _make_config()
        cmd = _build_docker_cmd(config, "/tmp/config.json", config.output_dir)
        assert "--cap-drop=ALL" in cmd

    def test_includes_no_new_privileges(self):
        config = _make_config()
        cmd = _build_docker_cmd(config, "/tmp/config.json", config.output_dir)
        assert "--security-opt=no-new-privileges" in cmd

    def test_includes_user_thresher(self):
        config = _make_config()
        cmd = _build_docker_cmd(config, "/tmp/config.json", config.output_dir)
        assert "--user" in cmd
        idx = cmd.index("--user")
        assert cmd[idx + 1] == "thresher"

    def test_includes_anthropic_api_key_env(self):
        config = ScanConfig(
            repo_url="https://github.com/example/pkg",
            output_dir="/tmp/test-output",
            anthropic_api_key="sk-ant-test",
        )
        cmd = _build_docker_cmd(config, "/tmp/config.json", config.output_dir)
        assert "-e" in cmd
        e_indices = [i for i, v in enumerate(cmd) if v == "-e"]
        env_vars = [cmd[i + 1] for i in e_indices]
        assert any(v.startswith("ANTHROPIC_API_KEY=") for v in env_vars)

    def test_includes_oauth_token_env(self):
        config = ScanConfig(
            repo_url="https://github.com/example/pkg",
            output_dir="/tmp/test-output",
            oauth_token="oauth-test-token",
        )
        cmd = _build_docker_cmd(config, "/tmp/config.json", config.output_dir)
        e_indices = [i for i, v in enumerate(cmd) if v == "-e"]
        env_vars = [cmd[i + 1] for i in e_indices]
        assert any(v.startswith("CLAUDE_CODE_OAUTH_TOKEN=") for v in env_vars)

    def test_includes_tmpfs_mounts(self):
        config = _make_config()
        cmd = _build_docker_cmd(config, "/tmp/config.json", config.output_dir)
        tmpfs_indices = [i for i, v in enumerate(cmd) if v == "--tmpfs"]
        tmpfs_targets = [cmd[i + 1] for i in tmpfs_indices]
        # Verify key tmpfs mounts are present
        assert any("/tmp:" in t for t in tmpfs_targets)
        assert any("/home/thresher:" in t for t in tmpfs_targets)
        assert any("/opt/target:" in t for t in tmpfs_targets)
        assert any("/opt/scan-results:" in t for t in tmpfs_targets)
        assert any("/opt/deps:" in t for t in tmpfs_targets)

    def test_home_tmpfs_has_sufficient_size(self):
        """home tmpfs must be >= 512MB for Claude Code config and misc files.

        Vuln DBs are now baked into the image at /opt/vuln-db/ so the home
        tmpfs no longer needs to hold multi-GB database downloads.
        """
        config = _make_config()
        cmd = _build_docker_cmd(config, "/tmp/config.json", config.output_dir)
        tmpfs_indices = [i for i, v in enumerate(cmd) if v == "--tmpfs"]
        tmpfs_targets = [cmd[i + 1] for i in tmpfs_indices]
        home_mount = [t for t in tmpfs_targets if "/home/thresher:" in t][0]
        for part in home_mount.split(","):
            if part.startswith("size="):
                size = int(part.split("=")[1])
                assert size >= 512 * 1024 * 1024, f"home tmpfs too small: {size}"
                break

    def test_vuln_db_env_vars_set(self):
        """Grype and Trivy must point at pre-populated DBs and skip updates."""
        config = _make_config()
        cmd = _build_docker_cmd(config, "/tmp/config.json", config.output_dir)
        e_indices = [i for i, v in enumerate(cmd) if v == "-e"]
        env_vars = [cmd[i + 1] for i in e_indices]
        assert "GRYPE_DB_CACHE_DIR=/opt/vuln-db/grype" in env_vars
        assert "GRYPE_DB_AUTO_UPDATE=false" in env_vars
        assert "TRIVY_CACHE_DIR=/opt/vuln-db/trivy" in env_vars
        assert "TRIVY_SKIP_DB_UPDATE=true" in env_vars

    def test_includes_output_volume(self):
        config = _make_config()
        cmd = _build_docker_cmd(config, "/tmp/config.json", config.output_dir)
        v_indices = [i for i, v in enumerate(cmd) if v == "-v"]
        vol_args = [cmd[i + 1] for i in v_indices]
        assert any("/output" in v for v in vol_args)
        assert any(config.output_dir in v for v in vol_args)

    def test_includes_config_volume(self):
        config_path = "/tmp/my-config.json"
        config = _make_config()
        cmd = _build_docker_cmd(config, config_path, config.output_dir)
        v_indices = [i for i, v in enumerate(cmd) if v == "-v"]
        vol_args = [cmd[i + 1] for i in v_indices]
        assert any(config_path in v for v in vol_args)
        assert any(":ro" in v for v in vol_args)

    def test_uses_correct_image(self):
        config = _make_config()
        cmd = _build_docker_cmd(config, "/tmp/config.json", config.output_dir)
        assert DOCKER_IMAGE in cmd

    def test_harness_config_flag(self):
        config = _make_config()
        cmd = _build_docker_cmd(config, "/tmp/config.json", config.output_dir)
        assert "--config" in cmd
        idx = cmd.index("--config")
        assert cmd[idx + 1] == "/config/config.json"

    def test_harness_output_flag(self):
        config = _make_config()
        cmd = _build_docker_cmd(config, "/tmp/config.json", config.output_dir)
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


class TestLaunchDockerLogging:
    """Tests for log streaming when a file handler is present."""

    def test_streams_to_log_file_when_handler_exists(self, tmp_path):
        """Container output is written to the log file."""
        config = ScanConfig(
            repo_url="https://github.com/example/pkg",
            output_dir=str(tmp_path),
            skip_ai=True,
        )
        log_file = tmp_path / "scan.log"

        mock_proc = MagicMock()
        mock_proc.stdout = [b"line1\n", b"line2\n"]
        mock_proc.returncode = 0

        with patch("thresher.launcher.docker._resolve_log_file", return_value=str(log_file)):
            with patch("thresher.launcher.docker.subprocess.Popen", return_value=mock_proc):
                rc = launch_docker(config)

        assert rc == 0
        content = log_file.read_text()
        assert "line1" in content
        assert "line2" in content

    def test_returns_exit_code_with_logging(self, tmp_path):
        """Exit code is returned correctly when streaming logs."""
        config = ScanConfig(
            repo_url="https://github.com/example/pkg",
            output_dir=str(tmp_path),
            skip_ai=True,
        )
        log_file = tmp_path / "scan.log"

        mock_proc = MagicMock()
        mock_proc.stdout = []
        mock_proc.returncode = 7

        with patch("thresher.launcher.docker._resolve_log_file", return_value=str(log_file)):
            with patch("thresher.launcher.docker.subprocess.Popen", return_value=mock_proc):
                rc = launch_docker(config)

        assert rc == 7

    def test_falls_back_to_subprocess_run_without_handler(self, tmp_path):
        """Uses subprocess.run when no log file handler exists."""
        config = ScanConfig(
            repo_url="https://github.com/example/pkg",
            output_dir=str(tmp_path),
            skip_ai=True,
        )
        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("thresher.launcher.docker._resolve_log_file", return_value=None):
            with patch("thresher.launcher.docker.subprocess.run", return_value=mock_result) as mock_run:
                rc = launch_docker(config)

        assert rc == 0
        mock_run.assert_called_once()

    def test_config_cleaned_up_with_logging(self, tmp_path):
        """Temp config file is cleaned up even with log streaming."""
        config = ScanConfig(
            repo_url="https://github.com/example/pkg",
            output_dir=str(tmp_path),
            skip_ai=True,
        )
        log_file = tmp_path / "scan.log"

        mock_proc = MagicMock()
        mock_proc.stdout = []
        mock_proc.returncode = 0

        captured_paths = []

        def capture_popen(cmd, **kwargs):
            v_indices = [i for i, v in enumerate(cmd) if v == "-v"]
            for i in v_indices:
                vol = cmd[i + 1]
                if "/config/config.json:ro" in vol:
                    captured_paths.append(vol.split(":")[0])
            return mock_proc

        with patch("thresher.launcher.docker._resolve_log_file", return_value=str(log_file)):
            with patch("thresher.launcher.docker.subprocess.Popen", side_effect=capture_popen):
                launch_docker(config)

        import os
        assert captured_paths
        assert not os.path.exists(captured_paths[0])
