"""Integration test for the full harness pipeline with mocked tools."""

from __future__ import annotations

import json
import pytest
from unittest.mock import patch, MagicMock

from thresher.config import ScanConfig
from thresher.harness.pipeline import run_pipeline


class TestHarnessPipeline:

    def test_full_pipeline_skip_ai(self, tmp_path):
        """Full pipeline with skip_ai runs and returns a report path via Hamilton."""
        config = ScanConfig(
            repo_url="https://github.com/test/repo",
            output_dir=str(tmp_path),
            skip_ai=True,
        )
        expected_report = str(tmp_path / "report")

        with patch("thresher.harness.pipeline._build_driver") as mock_build:
            mock_dr = MagicMock()
            mock_dr.execute.return_value = {"report_html": expected_report}
            mock_build.return_value = mock_dr

            result = run_pipeline(config)

        assert result == expected_report
        mock_dr.execute.assert_called_once()

        # Verify the Hamilton execute was called with the correct final_vars
        call_kwargs = mock_dr.execute.call_args[1]
        assert "final_vars" in call_kwargs
        assert "report_html" in call_kwargs["final_vars"]

    def test_full_pipeline_inputs_contain_config(self, tmp_path):
        """Pipeline passes correct inputs to Hamilton DAG including config dict."""
        config = ScanConfig(
            repo_url="https://github.com/test/repo",
            output_dir=str(tmp_path),
            skip_ai=True,
            model="opus",
            depth=3,
            high_risk_dep=True,
            branch="main",
        )

        with patch("thresher.harness.pipeline._build_driver") as mock_build:
            mock_dr = MagicMock()
            mock_dr.execute.return_value = {"report_html": str(tmp_path)}
            mock_build.return_value = mock_dr

            run_pipeline(config)

        call_kwargs = mock_dr.execute.call_args[1]
        inputs = call_kwargs["inputs"]

        assert inputs["repo_url"] == "https://github.com/test/repo"
        cfg = inputs["config"]
        assert cfg.skip_ai is True
        assert cfg.model == "opus"
        assert cfg.depth == 3
        assert cfg.high_risk_dep is True
        assert cfg.branch == "main"

    def test_full_pipeline_skip_ai_false(self, tmp_path):
        """Pipeline with skip_ai=False passes correct flag in config dict."""
        config = ScanConfig(
            repo_url="https://github.com/test/repo",
            output_dir=str(tmp_path),
            skip_ai=False,
            anthropic_api_key="sk-ant-test",
        )

        with patch("thresher.harness.pipeline._build_driver") as mock_build:
            mock_dr = MagicMock()
            mock_dr.execute.return_value = {"report_html": str(tmp_path)}
            mock_build.return_value = mock_dr

            run_pipeline(config)

        call_kwargs = mock_dr.execute.call_args[1]
        inputs = call_kwargs["inputs"]
        assert inputs["config"].skip_ai is False

    def test_full_pipeline_returns_report_path(self, tmp_path):
        """run_pipeline returns the report_path from the DAG result."""
        config = ScanConfig(
            repo_url="https://github.com/test/repo",
            skip_ai=True,
        )
        sentinel = "/opt/scan-results/report-20240101"

        with patch("thresher.harness.pipeline._build_driver") as mock_build:
            mock_dr = MagicMock()
            mock_dr.execute.return_value = {"report_html": sentinel}
            mock_build.return_value = mock_dr

            result = run_pipeline(config)

        assert result == sentinel

    def test_config_round_trip(self):
        """Config serializes and deserializes correctly for harness handoff."""
        config = ScanConfig(
            repo_url="https://github.com/test/repo",
            skip_ai=True,
            model="opus",
            depth=3,
            high_risk_dep=True,
        )
        json_str = config.to_json()
        restored = ScanConfig.from_json(json_str)

        assert restored.repo_url == config.repo_url
        assert restored.skip_ai == config.skip_ai
        assert restored.model == config.model
        assert restored.depth == config.depth
        assert restored.high_risk_dep == config.high_risk_dep

    def test_config_round_trip_vm_and_limits(self):
        """Config round-trip preserves vm and limits sub-configs."""
        config = ScanConfig(
            repo_url="https://github.com/test/repo",
            skip_ai=True,
        )
        config.vm.cpus = 8
        config.vm.memory = 16
        config.limits.max_json_size_mb = 20

        json_str = config.to_json()
        restored = ScanConfig.from_json(json_str)

        assert restored.vm.cpus == 8
        assert restored.vm.memory == 16
        assert restored.limits.max_json_size_mb == 20

    def test_config_round_trip_analyst_overrides(self):
        """Config round-trip preserves analyst max_turns overrides."""
        config = ScanConfig(
            repo_url="https://github.com/test/repo",
            skip_ai=False,
            analyst_max_turns=15,
            analyst_max_turns_by_name={"paranoid": 30},
            adversarial_max_turns=25,
        )
        json_str = config.to_json()
        restored = ScanConfig.from_json(json_str)

        assert restored.analyst_max_turns == 15
        assert restored.analyst_max_turns_by_name == {"paranoid": 30}
        assert restored.adversarial_max_turns == 25

    def test_config_to_json_is_valid_json(self):
        """to_json produces parseable JSON."""
        config = ScanConfig(repo_url="https://github.com/test/repo")
        json_str = config.to_json()
        data = json.loads(json_str)
        assert isinstance(data, dict)
        assert data["repo_url"] == "https://github.com/test/repo"
