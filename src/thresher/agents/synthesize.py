"""Report Synthesis agent — merges scanner and AI findings into final reports.

Invokes Claude Code headless to produce executive-summary.md,
detailed-report.md, and synthesis-findings.md from enriched findings.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

import yaml

from thresher.config import ScanConfig
from thresher.run import run as run_cmd

logger = logging.getLogger(__name__)

_DEFINITION_PATH = Path(__file__).parent / "definitions" / "report" / "synthesize.yaml"

# Priority ordering for the synthesis-input summary table
_PRIORITY_ORDER = ["P0", "critical", "high", "medium", "low"]


def _load_definition() -> dict[str, Any]:
    """Load the synthesize YAML definition."""
    with open(_DEFINITION_PATH) as f:
        return yaml.safe_load(f)


def _write_file(path: str, content: str) -> None:
    """Write content to a local file."""
    dir_path = os.path.dirname(path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _build_synthesis_prompt(
    definition: dict[str, Any], report_dir: str, input_path: str,
) -> str:
    """Format the YAML prompt template with runtime paths."""
    return definition["prompt"].format(
        report_dir=report_dir,
        input_path=input_path,
    )


def build_synthesis_input(
    scan_results: Any,
    ai_findings: dict[str, Any] | None,
    enriched: list[dict[str, Any]],
) -> str:
    """Build the markdown input text for the synthesis agent.

    Summarizes total findings by priority, top risks, AI verification stats,
    and includes the important findings as JSON. Low/medium findings are
    summarized by tool to keep the input size manageable.
    """
    lines: list[str] = []
    lines.append("# Security Scan Synthesis Input")
    lines.append("")

    # Priority counts
    priority_counts: dict[str, int] = {}
    for f in enriched:
        p = f.get("composite_priority", "low")
        priority_counts[p] = priority_counts.get(p, 0) + 1

    lines.append("## Finding Counts by Priority")
    for priority in _PRIORITY_ORDER:
        count = priority_counts.get(priority, 0)
        lines.append(f"- **{priority.upper()}**: {count}")
    lines.append(f"- **Total**: {len(enriched)}")
    lines.append("")

    # Tool coverage
    tools_seen: set[str] = set()
    for f in enriched:
        tool = f.get("source_tool")
        if tool:
            tools_seen.add(tool)

    lines.append("## Tool Coverage")
    if tools_seen:
        for tool in sorted(tools_seen):
            tool_count = sum(1 for f in enriched if f.get("source_tool") == tool)
            lines.append(f"- {tool}: {tool_count} findings")
    else:
        lines.append("- No tool attribution found in findings")
    lines.append("")

    # Top risks
    top_risks = [
        f for f in enriched if f.get("composite_priority") in ("P0", "critical")
    ]
    if top_risks:
        lines.append("## Top Risks")
        for risk in top_risks[:20]:
            title = risk.get("title", "Unknown")
            cve = risk.get("cve_id", "N/A")
            priority = risk.get("composite_priority", "unknown")
            lines.append(f"- [{priority.upper()}] {title} ({cve})")
        lines.append("")

    # AI summary
    if ai_findings:
        lines.append("## AI Analysis Summary")
        ai_list = ai_findings.get("findings", [])
        confirmed = sum(
            1 for f in ai_list if f.get("adversarial_status") == "confirmed"
        )
        downgraded = sum(
            1 for f in ai_list if f.get("adversarial_status") == "downgraded"
        )
        lines.append(f"- AI findings: {len(ai_list)}")
        lines.append(f"- Adversarially confirmed: {confirmed}")
        lines.append(f"- Adversarially downgraded: {downgraded}")
        lines.append("")

    # Important findings in full
    important = [
        f for f in enriched
        if f.get("composite_priority") in ("P0", "critical", "high")
        or f.get("source_tool") == "ai_analysis"
        or f.get("in_kev") is True
    ]
    low_medium = [f for f in enriched if f not in important]

    lines.append(
        f"## Important Findings ({len(important)} of {len(enriched)} total)"
    )
    lines.append(
        "These are all P0/Critical/High findings, AI analysis findings, "
        "and CISA KEV entries."
    )
    lines.append("```json")
    lines.append(json.dumps(important, indent=2, default=str))
    lines.append("```")
    lines.append("")

    if low_medium:
        lines.append(
            f"## Remaining Findings Summary ({len(low_medium)} low/medium)"
        )
        tool_summary: dict[str, dict[str, int]] = {}
        for f in low_medium:
            tool = f.get("source_tool", "unknown")
            sev = f.get("severity", "low")
            if tool not in tool_summary:
                tool_summary[tool] = {}
            tool_summary[tool][sev] = tool_summary[tool].get(sev, 0) + 1
        for tool, sevs in sorted(tool_summary.items()):
            counts = ", ".join(f"{s}: {c}" for s, c in sorted(sevs.items()))
            lines.append(f"- **{tool}**: {counts}")

    return "\n".join(lines)


def run_synthesize_agent(
    config: ScanConfig,
    report_dir: str,
    synthesis_input: str,
) -> bool:
    """Run the synthesis agent to generate report markdown files.

    Writes the synthesis input to the report directory, builds the prompt,
    and invokes Claude Code headless to generate the report files.

    Args:
        config: Scan configuration.
        report_dir: Directory where report files will be written.
        synthesis_input: Markdown-formatted synthesis input text.

    Returns:
        True if the agent produced the expected output files.
    """
    definition = _load_definition()
    tools = ",".join(definition["tools"])
    max_turns = getattr(config, "synthesize_max_turns", None) or definition["max_turns"]

    # Write synthesis input to report directory
    input_path = f"{report_dir}/synthesis_input.md"
    _write_file(input_path, synthesis_input)

    # Build and write prompt from YAML definition template
    synthesis_prompt = _build_synthesis_prompt(definition, report_dir, input_path)
    prompt_path = Path(tempfile.mktemp(suffix="_synthesis_prompt.txt"))

    try:
        prompt_path.write_text(synthesis_prompt)

        model = config.model
        cmd = [
            "claude",
            "-p", str(prompt_path),
            "--model", model,
            "--allowedTools", tools,
            "--output-format", "stream-json",
            "--verbose",
            "--max-turns", str(max_turns),
        ]

        env = os.environ.copy()
        ai_env = config.ai_env()
        env.update(ai_env)

        logger.info("Invoking synthesis agent (max_turns=%d)", max_turns)
        try:
            result = run_cmd(
                cmd,
                label="synthesize",
                cwd=report_dir,
                env=env,
                timeout=1800,
            )
            exit_code = result.returncode
        except Exception as exc:
            logger.warning("Synthesis agent failed: %s", exc)
            exit_code = 1

        logger.info("Synthesis agent completed: exit_code=%d", exit_code)

        # Verify expected output files exist
        agent_succeeded = (
            os.path.isfile(f"{report_dir}/executive-summary.md")
            and os.path.isfile(f"{report_dir}/detailed-report.md")
        )

        if agent_succeeded:
            logger.info("Synthesis agent produced expected report files")
        else:
            logger.warning("Synthesis agent did not produce expected files")

        return agent_succeeded

    finally:
        try:
            prompt_path.unlink(missing_ok=True)
        except Exception:
            pass
