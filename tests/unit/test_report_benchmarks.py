"""Tests for thresher.report.benchmarks — cost calculation and report generation."""

import json
from pathlib import Path
from unittest.mock import patch

from thresher.harness.benchmarks import BenchmarkCollector, StageStats
from thresher.report.benchmarks import (
    _load_costs,
    build_markdown,
    build_report_data,
    compute_stage_cost,
    create_report,
)


class TestComputeStageCost:
    def test_sonnet_pricing(self):
        stage = StageStats(
            name="predep",
            runtime_seconds=1.0,
            token_usage={
                "input_tokens": 1_000_000,
                "output_tokens": 500_000,
                "cache_creation_input_tokens": 200_000,
                "cache_read_input_tokens": 300_000,
            },
        )
        pricing = {
            "input_per_mtok": 3.0,
            "output_per_mtok": 15.0,
            "cache_write_per_mtok": 3.75,
            "cache_read_per_mtok": 0.30,
        }
        cost = compute_stage_cost(stage, pricing)
        assert cost["input_cost"] == 3.0
        assert cost["output_cost"] == 7.5
        assert cost["cache_write_cost"] == 0.75
        assert cost["cache_read_cost"] == 0.09
        assert cost["total_cost"] == round(3.0 + 7.5 + 0.75 + 0.09, 4)

    def test_no_token_usage(self):
        stage = StageStats(name="clone", runtime_seconds=1.0)
        cost = compute_stage_cost(stage, {"input_per_mtok": 3.0})
        assert cost["total_cost"] == 0.0

    def test_no_pricing(self):
        stage = StageStats(
            name="test", runtime_seconds=1.0, token_usage={"input_tokens": 100}
        )
        cost = compute_stage_cost(stage, {})
        assert cost["total_cost"] == 0.0


class TestBuildReportData:
    def test_structure_with_sonnet(self):
        c = BenchmarkCollector()
        c.start()
        c.add(StageStats(name="clone", runtime_seconds=2.0))
        c.add(
            StageStats(
                name="predep",
                runtime_seconds=1.0,
                token_usage={"input_tokens": 100, "output_tokens": 50},
                metadata={
                    "model_usage": {
                        "claude-sonnet-4-6": {
                            "input_tokens": 100,
                            "output_tokens": 50,
                            "cache_creation_input_tokens": 0,
                            "cache_read_input_tokens": 0,
                        }
                    }
                },
            )
        )
        c.add(
            StageStats(
                name="analyst-01-paranoid",
                runtime_seconds=5.0,
                findings_count=3,
                token_usage={"input_tokens": 500, "output_tokens": 200},
                metadata={
                    "finding_lifecycle": "analyst_candidate",
                    "turns": 3,
                    "model_usage": {
                        "claude-haiku-4-5-20251001": {
                            "input_tokens": 500,
                            "output_tokens": 200,
                            "cache_creation_input_tokens": 0,
                            "cache_read_input_tokens": 0,
                        }
                    },
                },
            )
        )
        c.add(
            StageStats(
                name="analysts",
                runtime_seconds=3.0,
                findings_count=3,
                metadata={"finding_lifecycle": "analyst_candidate"},
            )
        )
        c.add(
            StageStats(
                name="enrich",
                runtime_seconds=2.0,
                findings_count=3,
                metadata={"finding_lifecycle": "final"},
            )
        )

        data = build_report_data(c, model="sonnet")

        assert data["model"] == "sonnet"
        assert "pipeline_total_seconds" in data
        assert len(data["stages"]) == 5
        assert data["totals"]["runtime_seconds"] == 13.0
        assert data["totals"]["findings_count"] == 3
        assert data["totals"]["token_usage"]["input_tokens"] == 600
        assert data["totals"]["token_usage"]["output_tokens"] == 250
        assert data["totals"]["cost"]["total_cost"] > 0
        assert data["totals"]["raw_scanner_findings_total"] == 0
        assert data["totals"]["analyst_candidate_findings_total"] == 3
        assert data["totals"]["final_findings_total"] == 3

        # Analyst totals
        assert data["analyst_totals"]["runtime_seconds"] == 5.0
        assert data["analyst_totals"]["findings_count"] == 3
        assert data["analyst_totals"]["wall_clock_runtime_seconds"] == 3.0
        assert data["analyst_totals"]["cost"]["total_cost"] > 0

    def test_stage_cost_populated_for_agentic(self):
        c = BenchmarkCollector()
        c.add(
            StageStats(
                name="predep",
                runtime_seconds=1.0,
                token_usage={"input_tokens": 100_000, "output_tokens": 10_000},
            )
        )
        data = build_report_data(c, model="sonnet")
        stage = data["stages"][0]
        assert stage["cost"] is not None
        assert stage["cost"]["total_cost"] > 0

    def test_stage_cost_none_for_non_agentic(self):
        c = BenchmarkCollector()
        c.add(StageStats(name="clone", runtime_seconds=2.0))
        data = build_report_data(c, model="sonnet")
        stage = data["stages"][0]
        assert stage["cost"] is None
        assert stage["token_usage"] is None

    def test_unknown_model_gives_zero_cost(self):
        c = BenchmarkCollector()
        c.add(
            StageStats(
                name="test",
                runtime_seconds=1.0,
                token_usage={"input_tokens": 1000},
            )
        )
        data = build_report_data(c, model="nonexistent-model")
        assert data["totals"]["cost"]["total_cost"] == 0.0

    def test_empty_collector(self):
        c = BenchmarkCollector()
        data = build_report_data(c, model="sonnet")
        assert data["stages"] == []
        assert data["totals"]["findings_count"] == 0
        assert data["analyst_totals"]["runtime_seconds"] == 0.0


class TestBuildMarkdown:
    def test_contains_key_sections(self):
        c = BenchmarkCollector()
        c.add(StageStats(name="clone", runtime_seconds=2.0))
        c.add(
            StageStats(
                name="predep",
                runtime_seconds=1.0,
                token_usage={
                    "input_tokens": 100,
                    "output_tokens": 50,
                    "cache_creation_input_tokens": 30,
                    "cache_read_input_tokens": 40,
                },
            )
        )
        data = build_report_data(c, model="sonnet")
        md = build_markdown(data)

        assert "# Benchmark Report" in md
        assert "**Model:** sonnet" in md
        assert "| clone |" in md
        assert "| predep |" in md
        assert "100/50/30/40" in md
        assert "## Analyst Totals" not in md  # no analyst stages

    def test_analyst_section_when_present(self):
        c = BenchmarkCollector()
        c.add(
            StageStats(
                name="analyst-01-paranoid",
                runtime_seconds=5.0,
                token_usage={"input_tokens": 500, "output_tokens": 200},
                metadata={"finding_lifecycle": "analyst_candidate"},
            )
        )
        data = build_report_data(c, model="sonnet")
        md = build_markdown(data)
        assert "## Analyst Totals" in md
        assert "| analyst-01-paranoid |" in md

    def test_cost_column_shows_dollar(self):
        c = BenchmarkCollector()
        c.add(
            StageStats(
                name="predep",
                runtime_seconds=1.0,
                token_usage={"input_tokens": 100_000, "output_tokens": 10_000},
            )
        )
        data = build_report_data(c, model="sonnet")
        md = build_markdown(data)
        assert "$" in md


class TestCreateReport:
    def test_writes_json_and_markdown(self, tmp_path):
        c = BenchmarkCollector()
        c.start()
        c.add(StageStats(name="clone", runtime_seconds=2.0))
        c.add(
            StageStats(
                name="predep",
                runtime_seconds=1.0,
                token_usage={"input_tokens": 100, "output_tokens": 50},
            )
        )
        create_report(c, str(tmp_path), model="sonnet")

        json_path = tmp_path / "benchmark.json"
        md_path = tmp_path / "benchmark.md"
        assert json_path.exists()
        assert md_path.exists()

        data = json.loads(json_path.read_text())
        assert data["model"] == "sonnet"
        assert data["stages"][0]["name"] == "clone"
        assert data["stages"][1]["name"] == "predep"
        assert data["totals"]["cost"]["total_cost"] > 0

        md = md_path.read_text()
        assert "# Benchmark Report" in md

    def test_creates_output_dir(self, tmp_path):
        out = tmp_path / "nested" / "dir"
        c = BenchmarkCollector()
        c.add(StageStats(name="clone", runtime_seconds=1.0))
        create_report(c, str(out), model="sonnet")
        assert (out / "benchmark.json").exists()


class TestLoadCostsGracefulDegradation:
    def test_missing_costs_file_returns_empty(self):
        with patch("thresher.report.benchmarks._COSTS_PATH", Path("/nonexistent/costs_claude.json")):
            costs = _load_costs()
            assert costs == {}

    def test_missing_costs_file_does_not_crash_build_report_data(self):
        c = BenchmarkCollector()
        c.add(
            StageStats(
                name="predep",
                runtime_seconds=1.0,
                token_usage={"input_tokens": 100, "output_tokens": 50},
            )
        )
        with patch("thresher.report.benchmarks._COSTS_PATH", Path("/nonexistent/costs_claude.json")):
            data = build_report_data(c, model="sonnet")
            assert data["stages"][0]["cost"]["total_cost"] == 0.0
            assert data["totals"]["cost"]["total_cost"] == 0.0

    def test_missing_costs_file_does_not_crash_create_report(self, tmp_path):
        c = BenchmarkCollector()
        c.add(
            StageStats(
                name="predep",
                runtime_seconds=1.0,
                token_usage={"input_tokens": 100, "output_tokens": 50},
            )
        )
        with patch("thresher.report.benchmarks._COSTS_PATH", Path("/nonexistent/costs_claude.json")):
            create_report(c, str(tmp_path), model="sonnet")
            assert (tmp_path / "benchmark.json").exists()
            assert (tmp_path / "benchmark.md").exists()
            data = json.loads((tmp_path / "benchmark.json").read_text())
            assert data["totals"]["cost"]["total_cost"] == 0.0


class TestCostsFilePackaged:
    def test_costs_file_exists_in_source(self):
        from thresher.report.benchmarks import _COSTS_PATH

        assert _COSTS_PATH.exists(), f"costs_claude.json missing at {_COSTS_PATH}"

    def test_costs_file_valid_json(self):
        from thresher.report.benchmarks import _COSTS_PATH

        data = json.loads(_COSTS_PATH.read_text())
        assert "models" in data
        assert len(data["models"]) > 0


class TestCreateReportWithExistingDir:
    def test_writes_benchmark_into_existing_report_dir(self, tmp_path):
        existing_files = [
            "report_data.json",
            "report.html",
            "findings.json",
            "executive-summary.md",
            "detailed-report.md",
        ]
        for name in existing_files:
            (tmp_path / name).write_text("{}" if name.endswith(".json") else "# placeholder")
        (tmp_path / "scan-results").mkdir()

        c = BenchmarkCollector()
        c.start()
        c.add(StageStats(name="clone", runtime_seconds=2.0))
        c.add(
            StageStats(
                name="scanners",
                runtime_seconds=30.0,
                findings_count=248,
            )
        )
        c.add(
            StageStats(
                name="analyst-paranoid",
                runtime_seconds=270.0,
                findings_count=2,
                token_usage={"input_tokens": 50000, "output_tokens": 10000},
            )
        )
        c.add(
            StageStats(
                name="adversarial",
                runtime_seconds=120.0,
                findings_count=18,
                token_usage={"input_tokens": 80000, "output_tokens": 20000},
            )
        )
        c.add(
            StageStats(
                name="synthesize",
                runtime_seconds=45.0,
                token_usage={"input_tokens": 200000, "output_tokens": 30000},
            )
        )

        create_report(c, str(tmp_path), model="sonnet")

        assert (tmp_path / "benchmark.json").exists()
        assert (tmp_path / "benchmark.md").exists()
        for name in existing_files:
            assert (tmp_path / name).exists(), f"{name} was overwritten or removed"

        data = json.loads((tmp_path / "benchmark.json").read_text())
        assert data["model"] == "sonnet"
        assert len(data["stages"]) == 5
        assert data["totals"]["findings_count"] == 268
        assert data["analyst_totals"]["findings_count"] == 2
