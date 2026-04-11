"""Benchmark collector — tracks per-stage stats across a pipeline run.

Every pipeline node records its runtime, findings count, errors, and
(for agentic stages) token usage into a shared ``BenchmarkCollector``.
Report generation lives in ``thresher.report.benchmarks`` — this module
only handles data collection.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class StageStats:
    """Stats for a single pipeline stage."""

    name: str
    runtime_seconds: float
    findings_count: int = 0
    errors: list[str] = field(default_factory=list)
    token_usage: dict[str, int] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_agentic(self) -> bool:
        return bool(self.token_usage)


class BenchmarkCollector:
    """Accumulates StageStats from pipeline nodes."""

    def __init__(self) -> None:
        self.stages: list[StageStats] = []
        self._start_time: float = 0.0

    def start(self) -> None:
        """Mark the beginning of the pipeline run."""
        self._start_time = time.monotonic()

    def add(self, stats: StageStats) -> None:
        self.stages.append(stats)

    def pipeline_elapsed(self) -> float:
        """Seconds since ``start()`` was called (or 0 if not started)."""
        return time.monotonic() - self._start_time if self._start_time else 0.0

    def total_runtime(self) -> float:
        return sum(s.runtime_seconds for s in self.stages)

    def total_findings(self) -> int:
        return sum(s.findings_count for s in self.stages)

    def total_errors(self) -> list[str]:
        errors: list[str] = []
        for s in self.stages:
            errors.extend(s.errors)
        return errors

    def total_token_usage(self) -> dict[str, int]:
        totals: dict[str, int] = {}
        for s in self.stages:
            for key, val in s.token_usage.items():
                totals[key] = totals.get(key, 0) + val
        return totals

    def analyst_stages(self) -> list[StageStats]:
        return [s for s in self.stages if s.name.startswith("analyst-")]


def record_stage(
    name: str,
    *,
    findings_count: int = 0,
    errors: list[str] | None = None,
    token_usage: dict[str, int] | None = None,
) -> StageStats:
    """Helper to build a StageStats after timing a stage."""
    return StageStats(
        name=name,
        runtime_seconds=0.0,
        findings_count=findings_count,
        errors=errors or [],
        token_usage=token_usage or {},
    )
