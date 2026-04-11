"""Tests for thresher.harness.benchmarks — benchmark collector."""

from thresher.harness.benchmarks import BenchmarkCollector, StageStats


class TestStageStats:
    def test_is_agentic_when_token_usage(self):
        stats = StageStats(name="test", runtime_seconds=1.0, token_usage={"input_tokens": 100})
        assert stats.is_agentic is True

    def test_is_not_agentic_without_tokens(self):
        stats = StageStats(name="test", runtime_seconds=1.0)
        assert stats.is_agentic is False

    def test_defaults(self):
        stats = StageStats(name="test", runtime_seconds=0.5)
        assert stats.findings_count == 0
        assert stats.errors == []
        assert stats.token_usage == {}


class TestBenchmarkCollector:
    def test_add_and_totals(self):
        c = BenchmarkCollector()
        c.add(StageStats(name="clone", runtime_seconds=2.0))
        c.add(StageStats(name="scanners", runtime_seconds=5.0, findings_count=10, errors=["grype failed"]))
        assert c.total_runtime() == 7.0
        assert c.total_findings() == 10
        assert c.total_errors() == ["grype failed"]

    def test_total_token_usage_sums_across_stages(self):
        c = BenchmarkCollector()
        c.add(StageStats(name="predep", runtime_seconds=1.0, token_usage={"input_tokens": 100, "output_tokens": 50}))
        c.add(
            StageStats(name="analysts", runtime_seconds=10.0, token_usage={"input_tokens": 500, "output_tokens": 200})
        )
        tokens = c.total_token_usage()
        assert tokens["input_tokens"] == 600
        assert tokens["output_tokens"] == 250

    def test_analyst_stages_filters(self):
        c = BenchmarkCollector()
        c.add(StageStats(name="clone", runtime_seconds=1.0))
        c.add(StageStats(name="analyst-paranoid", runtime_seconds=5.0))
        c.add(StageStats(name="analyst-behaviorist", runtime_seconds=3.0))
        assert len(c.analyst_stages()) == 2

    def test_pipeline_elapsed(self):
        import time

        c = BenchmarkCollector()
        assert c.pipeline_elapsed() == 0.0
        c.start()
        time.sleep(0.05)
        elapsed = c.pipeline_elapsed()
        assert elapsed > 0.0

    def test_empty_collector(self):
        c = BenchmarkCollector()
        assert c.total_runtime() == 0.0
        assert c.total_findings() == 0
        assert c.total_token_usage() == {}
        assert c.analyst_stages() == []
