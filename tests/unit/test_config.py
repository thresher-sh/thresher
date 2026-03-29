"""Tests for threat_scanner.config."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest
import yaml

from threat_scanner.config import ScanConfig, VMConfig, load_config


class TestScanConfigValidate:
    def test_missing_repo_url(self):
        cfg = ScanConfig(repo_url="", anthropic_api_key="key")
        errors = cfg.validate()
        assert any("repo_url" in e for e in errors)

    def test_missing_api_key(self):
        cfg = ScanConfig(repo_url="https://github.com/x/y", anthropic_api_key="")
        errors = cfg.validate()
        assert any("ANTHROPIC_API_KEY" in e for e in errors)

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
    def test_defaults(self):
        cfg = load_config(repo_url="https://github.com/x/y")
        assert cfg.depth == 2
        assert cfg.vm.cpus == 4
        assert cfg.vm.memory == 8
        assert cfg.vm.disk == 50
        assert cfg.skip_ai is False
        assert cfg.output_dir == "./scan-results"

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
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            yaml.dump(
                {
                    "default_depth": 4,
                    "model": "opus",
                    "vm": {"cpus": 8, "memory": 16, "disk": 100},
                }
            )
        )
        cfg = load_config(
            repo_url="https://github.com/x/y",
            config_path=config_file,
        )
        assert cfg.depth == 4
        assert cfg.model == "opus"
        assert cfg.vm.cpus == 8
        assert cfg.vm.memory == 16
        assert cfg.vm.disk == 100

    def test_cli_overrides_config_file(self, tmp_path: Path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump({"default_depth": 4}))
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
