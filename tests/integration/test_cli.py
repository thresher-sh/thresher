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
        with patch("thresher.cli._run_scan") as mock_scan:
            result = runner.invoke(cli, ["scan", "https://github.com/x/y", "--skip-ai"])
        assert result.exit_code == 0
        assert mock_scan.called
        config = mock_scan.call_args[0][0]
        assert config.skip_ai is True

    def test_scan_custom_options(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        runner = CliRunner()
        with patch("thresher.cli._run_scan") as mock_scan:
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
        config = mock_scan.call_args[0][0]
        assert config.vm.cpus == 16
        assert config.vm.memory == 32
        assert config.vm.disk == 200
        assert config.depth == 5
        assert config.output_dir == "/tmp/out"
        assert config.verbose is True

    def test_scan_keyboard_interrupt(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        runner = CliRunner()
        with patch("thresher.cli._run_scan", side_effect=KeyboardInterrupt):
            result = runner.invoke(cli, ["scan", "https://github.com/x/y"])
        assert result.exit_code == 130

    def test_scan_exception(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        runner = CliRunner()
        with patch("thresher.cli._run_scan", side_effect=RuntimeError("boom")):
            result = runner.invoke(cli, ["scan", "https://github.com/x/y"])
        assert result.exit_code == 1
        assert "boom" in result.output


class TestBuildCommand:
    @patch("thresher.vm.lima.stop_vm")
    @patch("thresher.vm.lima.provision_vm")
    @patch("thresher.vm.lima.start_vm")
    @patch("thresher.vm.lima._run_limactl")
    @patch("thresher.vm.lima._TEMPLATE_PATH")
    @patch("thresher.vm.lima.base_exists", return_value=False)
    def test_build_creates_and_provisions(
        self, mock_exists, mock_tpl, mock_run, mock_start, mock_prov, mock_stop
    ):
        mock_tpl.exists.return_value = True
        mock_tpl.__str__ = lambda s: "/fake/thresher.yaml"
        mock_run.return_value = MagicMock(returncode=0)

        runner = CliRunner()
        result = runner.invoke(cli, ["build"])
        assert result.exit_code == 0
        assert mock_prov.called
        assert mock_stop.called

    @patch("thresher.vm.lima.stop_vm")
    @patch("thresher.vm.lima.provision_vm")
    @patch("thresher.vm.lima.start_vm")
    @patch("thresher.vm.lima._run_limactl")
    @patch("thresher.vm.lima._TEMPLATE_PATH")
    @patch("thresher.vm.lima.base_exists", return_value=False)
    def test_build_with_vm_options(
        self, mock_exists, mock_tpl, mock_run, mock_start, mock_prov, mock_stop
    ):
        mock_tpl.exists.return_value = True
        mock_tpl.__str__ = lambda s: "/fake/thresher.yaml"
        mock_run.return_value = MagicMock(returncode=0)

        runner = CliRunner()
        result = runner.invoke(cli, ["build", "--cpus", "8", "--memory", "16", "--disk", "100"])
        assert result.exit_code == 0
        # Check the limactl create command had the right flags
        create_call = mock_run.call_args[0][0]
        assert "--cpus=8" in create_call
        assert "--memory=16" in create_call
        assert "--disk=100" in create_call

    @patch("thresher.vm.lima.start_vm", side_effect=RuntimeError("boot failed"))
    @patch("thresher.vm.lima._run_limactl")
    @patch("thresher.vm.lima._TEMPLATE_PATH")
    @patch("thresher.vm.lima.base_exists", return_value=False)
    def test_build_error(self, mock_exists, mock_tpl, mock_run, mock_start):
        mock_tpl.exists.return_value = True
        mock_tpl.__str__ = lambda s: "/fake/thresher.yaml"
        mock_run.return_value = MagicMock(returncode=0)

        runner = CliRunner()
        result = runner.invoke(cli, ["build"])
        assert result.exit_code == 1
        assert "boot failed" in result.output


class TestStopCommand:
    @patch("thresher.cli._stop_all")
    def test_stop(self, mock_stop):
        runner = CliRunner()
        result = runner.invoke(cli, ["stop"])
        assert result.exit_code == 0
        assert mock_stop.called
