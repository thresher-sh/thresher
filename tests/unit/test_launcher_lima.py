"""Tests for thresher.launcher.lima."""

from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import pytest

from thresher.config import ScanConfig
from thresher.launcher.lima import (
    BASE_VM_NAME,
    DOCKER_IMAGE,
    _apply_firewall,
    _build_lima_docker_cmd,
    _copy_report_to_host,
    _ensure_vm_running,
    launch_lima,
)


def _make_config() -> ScanConfig:
    return ScanConfig(
        repo_url="https://github.com/example/pkg",
        output_dir="/tmp/test-output",
        skip_ai=True,
    )


class TestEnsureVmRunning:
    def test_running_vm_does_nothing(self):
        mock_result = MagicMock()
        mock_result.stdout = b"Running\n"
        mock_result.returncode = 0
        with patch("thresher.launcher.lima.subprocess.run", return_value=mock_result) as mock_run:
            _ensure_vm_running()
        # Only the status check call should be made
        assert mock_run.call_count == 1

    def test_stopped_vm_is_started(self):
        status_result = MagicMock()
        status_result.stdout = b"Stopped\n"
        start_result = MagicMock()
        start_result.returncode = 0

        call_results = [status_result, start_result]

        with patch("thresher.launcher.lima.subprocess.run", side_effect=call_results) as mock_run:
            _ensure_vm_running()

        assert mock_run.call_count == 2
        start_call = mock_run.call_args_list[1]
        cmd = start_call[0][0]
        assert "limactl" in cmd
        assert "start" in cmd
        assert BASE_VM_NAME in cmd

    def test_missing_vm_raises_runtime_error(self):
        mock_result = MagicMock()
        mock_result.stdout = b""
        with patch("thresher.launcher.lima.subprocess.run", return_value=mock_result):
            with pytest.raises(RuntimeError, match="not found"):
                _ensure_vm_running()

    def test_unknown_status_raises_runtime_error(self):
        mock_result = MagicMock()
        mock_result.stdout = b"Unknown\n"
        with patch("thresher.launcher.lima.subprocess.run", return_value=mock_result):
            with pytest.raises(RuntimeError):
                _ensure_vm_running()


class TestApplyFirewall:
    def test_calls_limactl_shell_with_sudo_bash(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch("thresher.launcher.lima.subprocess.run", return_value=mock_result) as mock_run:
            _apply_firewall()
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "limactl" in cmd
        assert "shell" in cmd
        assert BASE_VM_NAME in cmd
        assert "sudo" in cmd
        assert "bash" in cmd

    def test_passes_firewall_rules(self):
        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch("thresher.launcher.lima.subprocess.run", return_value=mock_result) as mock_run:
            _apply_firewall()
        cmd = mock_run.call_args[0][0]
        # The rules string should be the last argument (passed to bash -c)
        rules_arg = cmd[-1]
        assert "iptables" in rules_arg


class TestBuildLimaDockerCmd:
    def test_starts_with_docker_run(self):
        config = _make_config()
        cmd = _build_lima_docker_cmd(config)
        assert cmd[:2] == ["docker", "run"]

    def test_includes_read_only(self):
        config = _make_config()
        cmd = _build_lima_docker_cmd(config)
        assert "--read-only" in cmd

    def test_includes_rm(self):
        config = _make_config()
        cmd = _build_lima_docker_cmd(config)
        assert "--rm" in cmd

    def test_includes_cap_drop_all(self):
        config = _make_config()
        cmd = _build_lima_docker_cmd(config)
        assert "--cap-drop=ALL" in cmd

    def test_includes_no_new_privileges(self):
        config = _make_config()
        cmd = _build_lima_docker_cmd(config)
        assert "--security-opt=no-new-privileges" in cmd

    def test_includes_user_thresher(self):
        config = _make_config()
        cmd = _build_lima_docker_cmd(config)
        assert "--user" in cmd
        idx = cmd.index("--user")
        assert cmd[idx + 1] == "thresher"

    def test_includes_anthropic_api_key_env(self):
        config = _make_config()
        cmd = _build_lima_docker_cmd(config)
        e_indices = [i for i, v in enumerate(cmd) if v == "-e"]
        env_vars = [cmd[i + 1] for i in e_indices]
        assert "ANTHROPIC_API_KEY" in env_vars

    def test_includes_oauth_token_env(self):
        config = _make_config()
        cmd = _build_lima_docker_cmd(config)
        e_indices = [i for i, v in enumerate(cmd) if v == "-e"]
        env_vars = [cmd[i + 1] for i in e_indices]
        assert "CLAUDE_CODE_OAUTH_TOKEN" in env_vars

    def test_includes_tmpfs_mounts(self):
        config = _make_config()
        cmd = _build_lima_docker_cmd(config)
        tmpfs_indices = [i for i, v in enumerate(cmd) if v == "--tmpfs"]
        tmpfs_targets = [cmd[i + 1] for i in tmpfs_indices]
        assert any("/tmp:" in t for t in tmpfs_targets)
        assert any("/opt/target:" in t for t in tmpfs_targets)
        assert any("/opt/scan-results:" in t for t in tmpfs_targets)
        assert any("/opt/deps:" in t for t in tmpfs_targets)

    def test_uses_vm_internal_paths(self):
        """Lima docker cmd uses /opt/reports (VM path), not host output_dir."""
        config = _make_config()
        cmd = _build_lima_docker_cmd(config)
        v_indices = [i for i, v in enumerate(cmd) if v == "-v"]
        vol_args = [cmd[i + 1] for i in v_indices]
        assert any("/opt/reports:/output" in v for v in vol_args)
        assert any("/opt/config.json:/config/config.json:ro" in v for v in vol_args)

    def test_uses_correct_image(self):
        config = _make_config()
        cmd = _build_lima_docker_cmd(config)
        assert DOCKER_IMAGE in cmd

    def test_harness_flags(self):
        config = _make_config()
        cmd = _build_lima_docker_cmd(config)
        assert "--config" in cmd
        assert "--output" in cmd


class TestCopyReportToHost:
    def test_calls_limactl_copy(self, tmp_path):
        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch("thresher.launcher.lima.subprocess.run", return_value=mock_result) as mock_run:
            _copy_report_to_host(str(tmp_path))
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "limactl" in cmd
        assert "copy" in cmd
        assert "-r" in cmd
        assert BASE_VM_NAME in " ".join(cmd)

    def test_creates_output_dir(self, tmp_path):
        new_dir = tmp_path / "new" / "output"
        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch("thresher.launcher.lima.subprocess.run", return_value=mock_result):
            _copy_report_to_host(str(new_dir))
        assert new_dir.exists()


class TestLaunchLima:
    def _make_subprocess_sequence(self, *returncodes):
        """Build a list of mock results for sequential subprocess.run calls."""
        results = []
        for rc in returncodes:
            r = MagicMock()
            r.returncode = rc
            if isinstance(rc, bytes):
                r.stdout = rc
                r.returncode = 0
            else:
                r.stdout = b"Running\n"
            results.append(r)
        return results

    def test_successful_scan_copies_report(self, tmp_path):
        config = ScanConfig(
            repo_url="https://github.com/example/pkg",
            output_dir=str(tmp_path / "output"),
            skip_ai=True,
        )

        call_log = []

        def fake_run(cmd, **kwargs):
            call_log.append(list(cmd))
            r = MagicMock()
            r.returncode = 0
            r.stdout = b"Running\n"
            return r

        with patch("thresher.launcher.lima.subprocess.run", side_effect=fake_run):
            rc = launch_lima(config)

        assert rc == 0
        # Find a limactl copy call (report copy)
        copy_calls = [c for c in call_log if "copy" in c and "-r" in c]
        assert copy_calls, "Should have called limactl copy -r for report"

    def test_failed_scan_skips_report_copy(self, tmp_path):
        config = ScanConfig(
            repo_url="https://github.com/example/pkg",
            output_dir=str(tmp_path / "output"),
            skip_ai=True,
        )

        call_log = []

        def fake_run(cmd, **kwargs):
            call_log.append(list(cmd))
            r = MagicMock()
            r.stdout = b"Running\n"
            # Return failure only for the docker run command
            if "docker" in cmd:
                r.returncode = 1
            else:
                r.returncode = 0
            return r

        with patch("thresher.launcher.lima.subprocess.run", side_effect=fake_run):
            rc = launch_lima(config)

        assert rc == 1
        # No limactl copy -r should have been called
        copy_calls = [c for c in call_log if "copy" in c and "-r" in c]
        assert not copy_calls, "Should NOT copy report on failure"

    def test_copies_config_to_vm(self, tmp_path):
        config = ScanConfig(
            repo_url="https://github.com/example/pkg",
            output_dir=str(tmp_path / "output"),
            skip_ai=True,
        )

        call_log = []

        def fake_run(cmd, **kwargs):
            call_log.append(list(cmd))
            r = MagicMock()
            r.returncode = 0
            r.stdout = b"Running\n"
            return r

        with patch("thresher.launcher.lima.subprocess.run", side_effect=fake_run):
            launch_lima(config)

        # Find limactl copy (config upload, not report download)
        config_copy_calls = [
            c for c in call_log
            if "copy" in c and "-r" not in c and BASE_VM_NAME in " ".join(c)
        ]
        assert config_copy_calls, "Should upload config to VM via limactl copy"
        # Destination should be /opt/config.json
        assert any("/opt/config.json" in " ".join(c) for c in config_copy_calls)

    def test_docker_runs_inside_limactl_shell(self, tmp_path):
        config = ScanConfig(
            repo_url="https://github.com/example/pkg",
            output_dir=str(tmp_path / "output"),
            skip_ai=True,
        )

        call_log = []

        def fake_run(cmd, **kwargs):
            call_log.append(list(cmd))
            r = MagicMock()
            r.returncode = 0
            r.stdout = b"Running\n"
            return r

        with patch("thresher.launcher.lima.subprocess.run", side_effect=fake_run):
            launch_lima(config)

        shell_calls = [c for c in call_log if "shell" in c and BASE_VM_NAME in c]
        # At least one shell call should contain a docker run command
        docker_shell_calls = [c for c in shell_calls if "docker" in c]
        assert docker_shell_calls, "Docker run should execute inside limactl shell"

    def test_config_file_cleaned_up(self, tmp_path):
        config = ScanConfig(
            repo_url="https://github.com/example/pkg",
            output_dir=str(tmp_path / "output"),
            skip_ai=True,
        )

        captured_paths = []

        def fake_run(cmd, **kwargs):
            # Capture config temp file path from limactl copy call
            if "copy" in cmd and "/opt/config.json" in " ".join(cmd):
                # The source is the temp file
                for arg in cmd:
                    if arg.startswith("/tmp/") and arg.endswith(".json"):
                        captured_paths.append(arg)
            r = MagicMock()
            r.returncode = 0
            r.stdout = b"Running\n"
            return r

        with patch("thresher.launcher.lima.subprocess.run", side_effect=fake_run):
            launch_lima(config)

        import os
        for path in captured_paths:
            assert not os.path.exists(path), f"Temp config {path} should be deleted"
