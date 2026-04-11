"""Benchmark report generation — produces JSON + markdown cost reports.

Reads per-stage stats collected by ``thresher.harness.benchmarks.BenchmarkCollector``
and enriches them with cost data from ``data/costs_claude.json``.

The collector lives in the harness; this module lives in the report package.
That split keeps collection logic (timing, counting) near the pipeline and
report rendering (formatting, cost calculation) near the output layer.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from thresher.harness.benchmarks import BenchmarkCollector, StageStats

logger = logging.getLogger(__name__)

_COSTS_PATH = Path(__file__).parent / "data" / "costs_claude.json"


def _load_costs() -> dict[str, Any]:
    """Load the Claude cost table (model -> pricing)."""
    return json.loads(_COSTS_PATH.read_text())


def _resolve_model_pricing(model: str, costs: dict[str, Any]) -> dict[str, float]:
    """Look up pricing for a model name or alias.

    Returns the pricing dict or an empty dict if model is unknown.
    """
    models = costs.get("models", {})
    # Direct model ID match
    if model in models:
        return models[model]
    # Alias match
    for _model_id, info in models.items():
        if model in info.get("aliases", []):
            return info
    return {}


def compute_stage_cost(
    stage: StageStats,
    pricing: dict[str, float],
) -> dict[str, float]:
    """Compute dollar cost for a single stage's token usage.

    Returns a dict with input_cost, output_cost, cache_write_cost,
    cache_read_cost, and total_cost.
    """
    if not stage.token_usage or not pricing:
        return {
            "input_cost": 0.0,
            "output_cost": 0.0,
            "cache_write_cost": 0.0,
            "cache_read_cost": 0.0,
            "total_cost": 0.0,
        }

    input_tokens = stage.token_usage.get("input_tokens", 0)
    output_tokens = stage.token_usage.get("output_tokens", 0)
    cache_write = stage.token_usage.get("cache_creation_input_tokens", 0)
    cache_read = stage.token_usage.get("cache_read_input_tokens", 0)

    input_cost = input_tokens * pricing.get("input_per_mtok", 0) / 1_000_000
    output_cost = output_tokens * pricing.get("output_per_mtok", 0) / 1_000_000
    cache_write_cost = cache_write * pricing.get("cache_write_per_mtok", 0) / 1_000_000
    cache_read_cost = cache_read * pricing.get("cache_read_per_mtok", 0) / 1_000_000

    return {
        "input_cost": round(input_cost, 4),
        "output_cost": round(output_cost, 4),
        "cache_write_cost": round(cache_write_cost, 4),
        "cache_read_cost": round(cache_read_cost, 4),
        "total_cost": round(input_cost + output_cost + cache_write_cost + cache_read_cost, 4),
    }


def build_report_data(
    collector: BenchmarkCollector,
    model: str = "sonnet",
) -> dict[str, Any]:
    """Build the full benchmark report dict from a collector.

    Enriches each stage and the totals with dollar costs computed from
    the Claude pricing table.
    """
    costs = _load_costs()
    pricing = _resolve_model_pricing(model, costs)

    pipeline_total = collector.pipeline_elapsed()

    stage_entries: list[dict[str, Any]] = []
    for s in collector.stages:
        cost = compute_stage_cost(s, pricing)
        stage_entries.append(
            {
                "name": s.name,
                "runtime_seconds": round(s.runtime_seconds, 2),
                "findings_count": s.findings_count,
                "errors": s.errors,
                "token_usage": s.token_usage if s.is_agentic else None,
                "cost": cost if s.is_agentic else None,
            }
        )

    totals_tokens = collector.total_token_usage()
    totals_cost = _compute_totals_cost(collector.stages, pricing)

    analyst_stages = collector.analyst_stages()
    analyst_tokens: dict[str, int] = {}
    for s in analyst_stages:
        for key, val in s.token_usage.items():
            analyst_tokens[key] = analyst_tokens.get(key, 0) + val
    analyst_cost = _compute_totals_cost(analyst_stages, pricing)

    return {
        "pipeline_total_seconds": round(pipeline_total, 2),
        "model": model,
        "stages": stage_entries,
        "analyst_totals": {
            "runtime_seconds": round(sum(s.runtime_seconds for s in analyst_stages), 2),
            "findings_count": sum(s.findings_count for s in analyst_stages),
            "error_count": sum(len(s.errors) for s in analyst_stages),
            "token_usage": analyst_tokens,
            "cost": analyst_cost,
        },
        "totals": {
            "runtime_seconds": round(collector.total_runtime(), 2),
            "findings_count": collector.total_findings(),
            "error_count": len(collector.total_errors()),
            "token_usage": totals_tokens,
            "cost": totals_cost,
        },
    }


def _compute_totals_cost(
    stages: list[StageStats],
    pricing: dict[str, float],
) -> dict[str, float]:
    """Aggregate costs across a list of stages."""
    agg = {
        "input_cost": 0.0,
        "output_cost": 0.0,
        "cache_write_cost": 0.0,
        "cache_read_cost": 0.0,
        "total_cost": 0.0,
    }
    for s in stages:
        cost = compute_stage_cost(s, pricing)
        for key in agg:
            agg[key] += cost[key]
    return {k: round(v, 4) for k, v in agg.items()}


def build_markdown(data: dict[str, Any]) -> str:
    """Render benchmark report data as markdown."""
    lines: list[str] = ["# Benchmark Report", ""]
    lines.append(f"**Model:** {data.get('model', 'unknown')}")
    lines.append(f"**Pipeline wall time:** {data['pipeline_total_seconds']:.1f}s")
    lines.append("")

    # Per-stage table
    lines.append("## Per-Stage Stats")
    lines.append("")
    lines.append(
        "| Stage | Runtime | Findings | Errors | Tokens (in/out) | Cost |"
    )
    lines.append(
        "|-------|---------|----------|--------|-----------------|------|"
    )
    for stage in data["stages"]:
        tokens = ""
        cost_str = ""
        if stage["token_usage"]:
            tokens = (
                f"{stage['token_usage'].get('input_tokens', 0):,}"
                f"/"
                f"{stage['token_usage'].get('output_tokens', 0):,}"
            )
        if stage.get("cost") and stage["cost"]["total_cost"] > 0:
            cost_str = f"${stage['cost']['total_cost']:.4f}"
        lines.append(
            f"| {stage['name']} "
            f"| {stage['runtime_seconds']:.1f}s "
            f"| {stage['findings_count']} "
            f"| {len(stage['errors'])} "
            f"| {tokens} "
            f"| {cost_str} |"
        )
    lines.append("")

    # Analyst totals
    analyst = data.get("analyst_totals", {})
    if analyst.get("token_usage"):
        lines.append("## Analyst Totals")
        lines.append("")
        lines.append(f"- **Runtime:** {analyst['runtime_seconds']:.1f}s")
        lines.append(f"- **Findings:** {analyst['findings_count']}")
        lines.append(f"- **Errors:** {analyst['error_count']}")
        tu = analyst["token_usage"]
        lines.append(f"- **Input tokens:** {tu.get('input_tokens', 0):,}")
        lines.append(f"- **Output tokens:** {tu.get('output_tokens', 0):,}")
        lines.append(f"- **Cache write:** {tu.get('cache_creation_input_tokens', 0):,}")
        lines.append(f"- **Cache read:** {tu.get('cache_read_input_tokens', 0):,}")
        if analyst.get("cost"):
            lines.append(f"- **Cost:** ${analyst['cost']['total_cost']:.4f}")
        lines.append("")

    # Pipeline totals
    totals = data["totals"]
    lines.append("## Pipeline Totals")
    lines.append("")
    lines.append(f"- **Runtime:** {totals['runtime_seconds']:.1f}s")
    lines.append(f"- **Findings:** {totals['findings_count']}")
    lines.append(f"- **Errors:** {totals['error_count']}")
    tu = totals["token_usage"]
    if tu:
        lines.append(f"- **Input tokens:** {tu.get('input_tokens', 0):,}")
        lines.append(f"- **Output tokens:** {tu.get('output_tokens', 0):,}")
        lines.append(f"- **Cache write:** {tu.get('cache_creation_input_tokens', 0):,}")
        lines.append(f"- **Cache read:** {tu.get('cache_read_input_tokens', 0):,}")
    if totals.get("cost"):
        lines.append(f"- **Total cost:** ${totals['cost']['total_cost']:.4f}")
    lines.append("")

    return "\n".join(lines)


def create_report(
    collector: BenchmarkCollector,
    output_dir: str,
    model: str = "sonnet",
) -> None:
    """Write benchmark.json and benchmark.md to the output directory."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    json_path = out / "benchmark.json"
    md_path = out / "benchmark.md"

    data = build_report_data(collector, model=model)
    md_text = build_markdown(data)

    json_path.write_text(json.dumps(data, indent=2))
    md_path.write_text(md_text)
    logger.info("Benchmark report written to %s and %s", json_path, md_path)
