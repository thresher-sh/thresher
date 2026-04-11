"""Tests for thresher.report.benchmarks — cost calculation and report generation."""

import json

from thresher.harness.benchmarks import BenchmarkCollector, StageStats
from thresher.report.benchmarks import (
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
            )
        )
        c.add(
            StageStats(
                name="analyst-paranoid",
                runtime_seconds=5.0,
                findings_count=3,
                token_usage={"input_tokens": 500, "output_tokens": 200},
            )
        )

        data = build_report_data(c, model="sonnet")

        assert data["model"] == "sonnet"
        assert "pipeline_total_seconds" in data
        assert len(data["stages"]) == 3
        assert data["totals"]["runtime_seconds"] == 8.0
        assert data["totals"]["findings_count"] == 3
        assert data["totals"]["token_usage"]["input_tokens"] == 600
        assert data["totals"]["token_usage"]["output_tokens"] == 250
        assert data["totals"]["cost"]["total_cost"] > 0

        # Analyst totals
        assert data["analyst_totals"]["runtime_seconds"] == 5.0
        assert data["analyst_totals"]["findings_count"] == 3
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
                token_usage={"input_tokens": 100, "output_tokens": 50},
            )
        )
        data = build_report_data(c, model="sonnet")
        md = build_markdown(data)

        assert "# Benchmark Report" in md
        assert "**Model:** sonnet" in md
        assert "| clone |" in md
        assert "| predep |" in md
        assert "100/50" in md
        assert "## Analyst Totals" not in md  # no analyst stages

    def test_analyst_section_when_present(self):
        c = BenchmarkCollector()
        c.add(
            StageStats(
                name="analyst-paranoid",
                runtime_seconds=5.0,
                token_usage={"input_tokens": 500, "output_tokens": 200},
            )
        )
        data = build_report_data(c, model="sonnet")
        md = build_markdown(data)
        assert "## Analyst Totals" in md

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
