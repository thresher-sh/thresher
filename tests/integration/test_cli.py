"""Integration tests for CLI entry point."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from thresher.cli import build, main


class TestCLI:
    def test_missing_repo_url(self):
        runner = CliRunner()
        result = runner.invoke(main, [])
        assert result.exit_code == 2  # Click usage error

    def test_missing_credentials(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with patch("thresher.config._get_oauth_token_from_keychain", return_value=""):
            runner = CliRunner()
            result = runner.invoke(main, ["https://github.com/x/y"])
            assert result.exit_code == 1
            assert "credentials" in result.output.lower()

    def test_skip_ai_no_key(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        runner = CliRunner()
        with patch("thresher.cli.run_scan") as mock_scan:
            result = runner.invoke(main, ["https://github.com/x/y", "--skip-ai"])
        # Should not error on missing key
        assert result.exit_code == 0
        assert mock_scan.called
        config = mock_scan.call_args[0][0]
        assert config.skip_ai is True

    def test_custom_options(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        runner = CliRunner()
        with patch("thresher.cli.run_scan") as mock_scan:
            result = runner.invoke(main, [
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

    def test_keyboard_interrupt(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        runner = CliRunner()
        with patch("thresher.cli.run_scan", side_effect=KeyboardInterrupt):
            result = runner.invoke(main, ["https://github.com/x/y"])
        assert result.exit_code == 130

    def test_scan_exception(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        runner = CliRunner()
        with patch("thresher.cli.run_scan", side_effect=RuntimeError("boom")):
            result = runner.invoke(main, ["https://github.com/x/y"])
        assert result.exit_code == 1
        assert "boom" in result.output


class TestBuildCommand:
    def test_build_invokes_build_base(self):
        runner = CliRunner()
        with patch("thresher.vm.lima.build_base") as mock_build:
            result = runner.invoke(build, [])
        assert result.exit_code == 0
        assert mock_build.called
        assert "built successfully" in result.output.lower()

    def test_build_with_vm_options(self):
        runner = CliRunner()
        with patch("thresher.vm.lima.build_base") as mock_build:
            result = runner.invoke(build, ["--cpus", "8", "--memory", "16", "--disk", "100"])
        assert result.exit_code == 0
        config = mock_build.call_args[0][0]
        assert config.vm.cpus == 8
        assert config.vm.memory == 16
        assert config.vm.disk == 100

    def test_build_error(self):
        runner = CliRunner()
        with patch("thresher.vm.lima.build_base", side_effect=RuntimeError("fail")):
            result = runner.invoke(build, [])
        assert result.exit_code == 1
        assert "fail" in result.output
