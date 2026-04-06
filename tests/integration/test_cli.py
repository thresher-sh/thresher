"""Integration tests for CLI entry point."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from thresher.cli import cli


class TestCLI:
    def test_no_command_shows_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, [])
        assert result.exit_code == 0
        assert "Commands" in result.output

    def test_scan_missing_repo_url(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan"])
        assert result.exit_code == 2  # Click usage error

    def test_scan_missing_credentials(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with patch("thresher.config._get_oauth_token_from_keychain", return_value=""):
            runner = CliRunner()
            result = runner.invoke(cli, ["scan", "https://github.com/x/y"])
            assert result.exit_code == 1
            assert "credentials" in result.output.lower()

    def test_scan_skip_ai_no_key(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        runner = CliRunner()
        with patch("thresher.cli.launch_lima") as mock_launcher:
            mock_launcher.return_value = 0
            result = runner.invoke(cli, ["scan", "https://github.com/x/y", "--skip-ai"])
        assert result.exit_code == 0
        assert mock_launcher.called
        config = mock_launcher.call_args[0][0]
        assert config.skip_ai is True

    def test_scan_custom_options(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        runner = CliRunner()
        with patch("thresher.cli.launch_lima") as mock_launcher:
            mock_launcher.return_value = 0
            result = runner.invoke(cli, [
                "scan",
                "https://github.com/x/y",
                "--cpus", "16",
                "--memory", "32",
                "--disk", "200",
                "--depth", "5",
                "--output", "/tmp/out",
                "--verbose",
            ])
        assert result.exit_code == 0
        config = mock_launcher.call_args[0][0]
        assert config.vm.cpus == 16
        assert config.vm.memory == 32
        assert config.vm.disk == 200
        assert config.depth == 5
        assert config.output_dir == "/tmp/out"
        assert config.verbose is True

    def test_scan_keyboard_interrupt(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        runner = CliRunner()
        with patch("thresher.cli.launch_lima", side_effect=KeyboardInterrupt):
            result = runner.invoke(cli, ["scan", "https://github.com/x/y"])
        assert result.exit_code == 130

    def test_scan_exception(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        runner = CliRunner()
        with patch("thresher.cli.launch_lima", side_effect=RuntimeError("boom")):
            result = runner.invoke(cli, ["scan", "https://github.com/x/y"])
        assert result.exit_code == 1
        assert "boom" in result.output


class TestScanCommandRefactored:
    @patch("thresher.cli.launch_direct")
    def test_scan_no_vm_uses_direct_launcher(self, mock_launch):
        mock_launch.return_value = 0
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "https://github.com/test/repo", "--no-vm", "--skip-ai"])
        mock_launch.assert_called_once()
        config = mock_launch.call_args[0][0]
        assert config.launch_mode == "direct"

    @patch("thresher.cli.launch_docker")
    def test_scan_docker_uses_docker_launcher(self, mock_launch):
        mock_launch.return_value = 0
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "https://github.com/test/repo", "--docker", "--skip-ai"])
        mock_launch.assert_called_once()
        config = mock_launch.call_args[0][0]
        assert config.launch_mode == "docker"

    @patch("thresher.cli.launch_lima")
    def test_scan_default_uses_lima_launcher(self, mock_launch):
        mock_launch.return_value = 0
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "https://github.com/test/repo", "--skip-ai"])
        mock_launch.assert_called_once()
        config = mock_launch.call_args[0][0]
        assert config.launch_mode == "lima"


class TestBuildCommand:
    @patch("thresher.cli.subprocess.run")
    def test_build_runs_docker_build(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        runner = CliRunner()
        result = runner.invoke(cli, ["build"])
        assert mock_run.called
        cmd = mock_run.call_args[0][0]
        assert "docker" in cmd
        assert "build" in cmd
        assert "-t" in cmd
        assert "thresher:latest" in cmd

    @patch("thresher.cli.subprocess.run")
    def test_build_exits_with_docker_returncode(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1)
        runner = CliRunner()
        result = runner.invoke(cli, ["build"])
        assert result.exit_code == 1


class TestStopCommand:
    @patch("thresher.cli._stop_all")
    def test_stop(self, mock_stop):
        runner = CliRunner()
        result = runner.invoke(cli, ["stop"])
        assert result.exit_code == 0
        assert mock_stop.called
