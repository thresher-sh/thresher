"""Tests for thresher.config."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from unittest.mock import patch

from thresher.config import ScanConfig, VMConfig, load_config


class TestScanConfigValidate:
    def test_missing_repo_url(self):
        cfg = ScanConfig(repo_url="", anthropic_api_key="key")
        errors = cfg.validate()
        assert any("repo_url" in e for e in errors)

    def test_missing_credentials(self):
        cfg = ScanConfig(repo_url="https://github.com/x/y", anthropic_api_key="", oauth_token="")
        errors = cfg.validate()
        assert any("credentials" in e.lower() for e in errors)

    def test_skip_ai_no_key_ok(self):
        cfg = ScanConfig(
            repo_url="https://github.com/x/y",
            skip_ai=True,
            anthropic_api_key="",
        )
        assert cfg.validate() == []

    def test_bad_depth(self):
        cfg = ScanConfig(
            repo_url="https://github.com/x/y",
            anthropic_api_key="key",
            depth=0,
        )
        errors = cfg.validate()
        assert any("depth" in e for e in errors)

    def test_happy_path(self):
        cfg = ScanConfig(
            repo_url="https://github.com/x/y",
            anthropic_api_key="key",
        )
        assert cfg.validate() == []


class TestLoadConfig:
    def test_defaults(self, tmp_path: Path):
        cfg = load_config(
            repo_url="https://github.com/x/y",
            config_path=tmp_path / "nonexistent.toml",
        )
        assert cfg.depth == 2
        assert cfg.vm.cpus == 4
        assert cfg.vm.memory == 8
        assert cfg.vm.disk == 50
        assert cfg.skip_ai is False
        assert cfg.output_dir == "./thresher-reports"

    def test_cli_overrides(self):
        cfg = load_config(
            repo_url="https://github.com/x/y",
            depth=5,
            cpus=16,
            memory=32,
            disk=200,
            output_dir="/tmp/out",
        )
        assert cfg.depth == 5
        assert cfg.vm.cpus == 16
        assert cfg.vm.memory == 32
        assert cfg.vm.disk == 200
        assert cfg.output_dir == "/tmp/out"

    def test_config_file(self, tmp_path: Path):
        config_file = tmp_path / "thresher.toml"
        config_file.write_text(textwrap.dedent("""\
            depth = 4
            model = "opus"
            output_dir = "/tmp/reports"

            [vm]
            cpus = 8
            memory = 16
            disk = 100
        """))
        cfg = load_config(
            repo_url="https://github.com/x/y",
            config_path=config_file,
        )
        assert cfg.depth == 4
        assert cfg.model == "opus"
        assert cfg.output_dir == "/tmp/reports"
        assert cfg.vm.cpus == 8
        assert cfg.vm.memory == 16
        assert cfg.vm.disk == 100

    def test_cli_overrides_config_file(self, tmp_path: Path):
        config_file = tmp_path / "thresher.toml"
        config_file.write_text('depth = 4\n')
        cfg = load_config(
            repo_url="https://github.com/x/y",
            depth=7,
            config_path=config_file,
        )
        assert cfg.depth == 7

    def test_env_api_key(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-from-env")
        cfg = load_config(repo_url="https://github.com/x/y")
        assert cfg.anthropic_api_key == "sk-ant-from-env"

    def test_limits_from_config(self, tmp_path: Path):
        config_file = tmp_path / "thresher.toml"
        config_file.write_text(textwrap.dedent("""\
            [limits]
            max_json_size_mb = 20
            max_file_size_mb = 100
            max_copy_size_mb = 1000
            max_stdout_mb = 75
        """))
        cfg = load_config(
            repo_url="https://github.com/x/y",
            config_path=config_file,
        )
        assert cfg.limits.max_json_size_mb == 20
        assert cfg.limits.max_file_size_mb == 100
        assert cfg.limits.max_copy_size_mb == 1000
        assert cfg.limits.max_stdout_mb == 75
        assert cfg.limits.max_json_size_bytes == 20 * 1024 * 1024
        assert cfg.limits.max_stdout_bytes == 75 * 1024 * 1024

    def test_limits_defaults(self):
        cfg = load_config(repo_url="https://github.com/x/y")
        assert cfg.limits.max_json_size_mb == 10
        assert cfg.limits.max_file_size_mb == 50
        assert cfg.limits.max_copy_size_mb == 500
        assert cfg.limits.max_stdout_mb == 50

    def test_analyst_max_turns_from_config(self, tmp_path: Path):
        config_file = tmp_path / "thresher.toml"
        config_file.write_text(textwrap.dedent("""\
            [analysts]
            max_turns = 50
        """))
        cfg = load_config(
            repo_url="https://github.com/x/y",
            config_path=config_file,
        )
        assert cfg.analyst_max_turns == 50

    def test_analyst_max_turns_default_none(self, tmp_path: Path):
        cfg = load_config(
            repo_url="https://github.com/x/y",
            config_path=tmp_path / "nonexistent.toml",
        )
        assert cfg.analyst_max_turns is None

    def test_analyst_max_turns_by_name(self, tmp_path: Path):
        config_file = tmp_path / "thresher.toml"
        config_file.write_text(textwrap.dedent("""\
            [analysts]
            max_turns = 50

            [analysts.max_turns_by_name]
            paranoid = 60
            shadowcatcher = 80
        """))
        cfg = load_config(
            repo_url="https://github.com/x/y",
            config_path=config_file,
        )
        assert cfg.analyst_max_turns == 50
        assert cfg.analyst_max_turns_by_name == {"paranoid": 60, "shadowcatcher": 80}

    def test_analyst_max_turns_by_name_default_empty(self, tmp_path: Path):
        cfg = load_config(
            repo_url="https://github.com/x/y",
            config_path=tmp_path / "nonexistent.toml",
        )
        assert cfg.analyst_max_turns_by_name == {}

    def test_adversarial_max_turns_from_config(self, tmp_path: Path):
        config_file = tmp_path / "thresher.toml"
        config_file.write_text(textwrap.dedent("""\
            [adversarial]
            max_turns = 30
        """))
        cfg = load_config(
            repo_url="https://github.com/x/y",
            config_path=config_file,
        )
        assert cfg.adversarial_max_turns == 30

    def test_adversarial_max_turns_default_none(self, tmp_path: Path):
        cfg = load_config(
            repo_url="https://github.com/x/y",
            config_path=tmp_path / "nonexistent.toml",
        )
        assert cfg.adversarial_max_turns is None


class TestAiCredentials:
    def test_has_ai_credentials_api_key(self):
        cfg = ScanConfig(repo_url="https://github.com/x/y", anthropic_api_key="key")
        assert cfg.has_ai_credentials is True

    def test_has_ai_credentials_oauth(self):
        cfg = ScanConfig(repo_url="https://github.com/x/y", oauth_token="tok")
        assert cfg.has_ai_credentials is True

    def test_has_ai_credentials_none(self):
        cfg = ScanConfig(repo_url="https://github.com/x/y")
        assert cfg.has_ai_credentials is False

    def test_oauth_validates_ok(self):
        cfg = ScanConfig(repo_url="https://github.com/x/y", oauth_token="tok")
        assert cfg.validate() == []

    def test_ai_env_api_key_takes_precedence(self):
        cfg = ScanConfig(
            repo_url="https://github.com/x/y",
            anthropic_api_key="key",
            oauth_token="tok",
        )
        env = cfg.ai_env()
        assert env == {"ANTHROPIC_API_KEY": "key"}
        assert "CLAUDE_CODE_OAUTH_TOKEN" not in env

    def test_ai_env_oauth_fallback(self):
        cfg = ScanConfig(repo_url="https://github.com/x/y", oauth_token="tok")
        env = cfg.ai_env()
        assert env == {"CLAUDE_CODE_OAUTH_TOKEN": "tok"}

    def test_ai_env_empty(self):
        cfg = ScanConfig(repo_url="https://github.com/x/y")
        assert cfg.ai_env() == {}

    @patch("thresher.config._get_oauth_token_from_keychain", return_value="kc-token")
    def test_load_config_keychain_fallback(self, mock_kc, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        cfg = load_config(repo_url="https://github.com/x/y")
        assert cfg.oauth_token == "kc-token"
        assert cfg.anthropic_api_key == ""
        mock_kc.assert_called_once()

    @patch("thresher.config._get_oauth_token_from_keychain", return_value="kc-token")
    def test_load_config_api_key_skips_keychain(self, mock_kc, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant")
        cfg = load_config(repo_url="https://github.com/x/y")
        assert cfg.anthropic_api_key == "sk-ant"
        assert cfg.oauth_token == ""
        mock_kc.assert_not_called()

    @patch("thresher.config._get_oauth_token_from_keychain", return_value="kc-token")
    def test_load_config_skip_ai_skips_keychain(self, mock_kc, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        cfg = load_config(repo_url="https://github.com/x/y", skip_ai=True)
        assert cfg.oauth_token == ""
        mock_kc.assert_not_called()


class TestLaunchMode:
    def test_scan_config_launch_mode_default(self):
        """launch_mode defaults to 'lima'."""
        config = ScanConfig()
        assert config.launch_mode == "lima"

    def test_scan_config_launch_mode_from_dict(self):
        """launch_mode can be set from config dict."""
        config = ScanConfig(launch_mode="docker")
        assert config.launch_mode == "docker"

    def test_scan_config_launch_mode_validates(self):
        """launch_mode rejects invalid values."""
        config = ScanConfig(launch_mode="invalid")
        errors = config.validate()
        assert any("launch_mode" in e for e in errors)

    def test_scan_config_serializes_to_json(self):
        """ScanConfig can round-trip through JSON for harness handoff."""
        config = ScanConfig(repo_url="https://github.com/test/repo", launch_mode="docker")
        blob = config.to_json()
        restored = ScanConfig.from_json(blob)
        assert restored.repo_url == config.repo_url
        assert restored.launch_mode == config.launch_mode

    def test_scan_config_from_json(self):
        """ScanConfig.from_json handles all fields."""
        data = json.dumps({"repo_url": "https://example.com/repo", "launch_mode": "direct",
                           "skip_ai": True, "model": "opus"})
        config = ScanConfig.from_json(data)
        assert config.launch_mode == "direct"
        assert config.skip_ai is True
        assert config.model == "opus"
