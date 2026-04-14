"""Multi-analyst AI architecture — 8 parallel analyst personas.

Analyst definitions (prompts, tools, config) live in analyst_definitions.yaml.
This module loads them and runs all analysts in parallel.

Each analyst returns its findings as a dict. All findings are returned as
a list from run_all_analysts.
"""

from __future__ import annotations

import logging
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import yaml

from thresher.agents._json import extract_json_object
from thresher.agents._runner import AgentSpec, build_stop_hook_settings, run_agent
from thresher.config import ScanConfig

logger = logging.getLogger(__name__)

TARGET_DIR = "/opt/target"
DEPS_DIR = "/opt/deps"
SCAN_RESULTS_DIR = "/opt/scan-results"

_DEFINITIONS_DIR = Path(__file__).parent / "definitions"


# ---------------------------------------------------------------------------
# Load analyst definitions from individual YAML files
# ---------------------------------------------------------------------------


def _load_definitions() -> list[dict[str, Any]]:
    """Load analyst definitions from agents/definitions/NN-*.yaml.

    The numbered prefix (01-paranoid.yaml, 02-behaviorist.yaml, ...)
    sorts execution order. Non-numbered files in the same directory
    (predep, adversarial) are agent definitions for other stages and
    are skipped here.
    """
    definitions = []
    for yaml_file in sorted(_DEFINITIONS_DIR.glob("[0-9][0-9]-*.yaml")):
        with open(yaml_file) as f:
            definition = yaml.safe_load(f)
        if isinstance(definition, dict) and "number" in definition:
            definitions.append(definition)
        else:
            logger.warning("Skipping invalid definition file: %s", yaml_file.name)
    if not definitions:
        logger.error("No analyst definitions found in %s", _DEFINITIONS_DIR)
    return definitions


# Module-level cache — loaded once on first import
ANALYST_DEFINITIONS: list[dict[str, Any]] = _load_definitions()


# ---------------------------------------------------------------------------
# Output format template shared by all analysts
# ---------------------------------------------------------------------------

_OUTPUT_FORMAT = """\

## Output format

Your output MUST be a single JSON object with NO surrounding text, NO markdown
code fences, and NO commentary before or after the JSON:

{{
  "analyst": "{name}",
  "analyst_number": {number},
  "core_question": "{core_question}",
  "files_analyzed": <number of files you examined>,
  "findings": [
    {{
      "title": "Brief title",
      "severity": "critical|high|medium|low",
      "confidence": 0-100,
      "file_path": "/opt/target/path/to/file",
      "line_numbers": [1, 2, 3],
      "description": "What you found",
      "evidence": "The specific code/pattern/signal",
      "reasoning": "Why this is a concern",
      "recommendation": "What to do about it"
    }}
  ],
  "summary": "Overall assessment from this analyst's perspective",
  "risk_score": 0-10
}}

If you find nothing suspicious, return the JSON with an empty findings array,
risk_score 0, and an honest summary.
"""


def _build_analyst_prompt(analyst_def: dict[str, Any]) -> str:
    """Construct the full prompt for an analyst (definition prompt + output format)."""
    output_section = _OUTPUT_FORMAT.format(
        name=analyst_def["name"],
        number=analyst_def["number"],
        core_question=analyst_def["core_question"],
    )
    return analyst_def["prompt"] + output_section


# ---------------------------------------------------------------------------
# Output parsing
# ---------------------------------------------------------------------------

_REQUIRED_ANALYST_KEYS = {"analyst", "findings", "summary", "risk_score"}


def _validate_analyst_schema(parsed: dict[str, Any], analyst_def: dict[str, Any]) -> dict[str, Any] | None:
    """Return the parsed dict if it matches the analyst schema, else None."""
    if not isinstance(parsed, dict):
        return None
    # Reject pre-dep schema
    if "hidden_dependencies" in parsed and "findings" not in parsed:
        logger.warning(
            "Analyst %s returned pre-dep schema (hidden_dependencies), rejecting",
            analyst_def["name"],
        )
        return None
    if not _REQUIRED_ANALYST_KEYS.issubset(parsed.keys()):
        missing = _REQUIRED_ANALYST_KEYS - parsed.keys()
        logger.warning(
            "Analyst %s output missing required keys: %s",
            analyst_def["name"],
            missing,
        )
        return None
    return parsed


def _parse_analyst_json_output(text: str, analyst_def: dict[str, Any]) -> dict[str, Any]:
    """Parse the analyst JSON object out of the extracted result text."""
    if not text or not text.strip():
        logger.warning("Empty output from analyst %s", analyst_def["name"])
        return _empty_findings(analyst_def, "Agent returned empty output")

    parsed = extract_json_object(
        text,
        accept=lambda d: _validate_analyst_schema(d, analyst_def) is not None,
    )
    if parsed is not None:
        return parsed

    logger.warning(
        "Could not parse valid analyst JSON from %s output",
        analyst_def["name"],
    )
    return _empty_findings(analyst_def, f"Failed to parse output. Raw: {text[:500]}")


def _empty_findings(analyst_def: dict[str, Any], reason: str) -> dict[str, Any]:
    """Return an empty findings structure with error info."""
    return {
        "analyst": analyst_def["name"],
        "analyst_number": analyst_def["number"],
        "core_question": analyst_def["core_question"],
        "files_analyzed": 0,
        "findings": [],
        "summary": reason,
        "risk_score": 0,
        "error": reason,
    }


# ---------------------------------------------------------------------------
# Markdown formatting
# ---------------------------------------------------------------------------


def _format_analyst_markdown(findings: dict[str, Any], analyst_def: dict[str, Any]) -> str:
    """Format analyst findings as a readable markdown report."""
    lines: list[str] = []
    title = analyst_def["title"]
    lines.append(f"# Analyst {analyst_def['number']} — {title}")
    lines.append("")
    lines.append(f"**Core question:** {analyst_def['core_question']}")
    lines.append("")

    summary = findings.get("summary", "")
    if summary:
        lines.append(f"**Summary:** {summary}")
        lines.append("")

    lines.append(f"**Files analyzed:** {findings.get('files_analyzed', '?')}")
    lines.append(f"**Risk score:** {findings.get('risk_score', 0)}/10")
    lines.append("")

    finding_list = findings.get("findings", [])
    if not finding_list:
        lines.append("## Findings")
        lines.append("")
        lines.append("No concerns identified from this analyst's perspective.")
        return "\n".join(lines)

    lines.append(f"## Findings ({len(finding_list)})")
    lines.append("")

    for i, f in enumerate(finding_list, 1):
        fp = f.get("file_path", "unknown").replace("/opt/target/", "")
        severity = f.get("severity", "?").upper()
        confidence = f.get("confidence", "?")
        title_str = f.get("title", "Untitled")

        lines.append("---")
        lines.append(f"### {i}. [{severity}] {title_str}")
        lines.append(f"**File:** `{fp}`")

        line_nums = f.get("line_numbers", [])
        if line_nums:
            lines.append(f"**Lines:** {', '.join(str(ln) for ln in line_nums)}")

        lines.append(f"**Confidence:** {confidence}%")
        lines.append("")

        desc = f.get("description", "")
        if desc:
            lines.append(f"**Description:** {desc}")
            lines.append("")

        evidence = f.get("evidence", "")
        if evidence:
            lines.append(f"**Evidence:** {evidence}")
            lines.append("")

        reasoning = f.get("reasoning", "")
        if reasoning:
            lines.append(f"**Reasoning:** {reasoning}")
            lines.append("")

        rec = f.get("recommendation", "")
        if rec:
            lines.append(f"**Recommendation:** {rec}")
            lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Single analyst execution
# ---------------------------------------------------------------------------


def _run_single_analyst(
    config: ScanConfig,
    analyst_def: dict[str, Any],
    target_dir: str = TARGET_DIR,
) -> dict[str, Any] | None:
    """Run a single analyst agent locally via subprocess.

    Returns findings dict with timing metadata, or None on early failure.
    """
    number = analyst_def["number"]
    name = analyst_def["name"]
    # Priority: per-analyst toml > global toml > YAML default
    max_turns = config.analyst_max_turns_by_name.get(name) or config.analyst_max_turns or analyst_def["max_turns"]
    label = f"analyst-{number}-{name}"
    logger.info("%s using max_turns=%d", label, max_turns)

    try:
        hooks_json: str | None = build_stop_hook_settings("analyst")
    except Exception:
        logger.warning(
            "Failed to resolve analyst hook settings for %s",
            label,
            exc_info=True,
        )
        hooks_json = None

    spec = AgentSpec(
        label=label,
        prompt=_build_analyst_prompt(analyst_def),
        allowed_tools=["Read", "Glob", "Grep", "Bash"],
        max_turns=max_turns,
        timeout=3600,
        cwd=target_dir,
        hooks_settings_json=hooks_json,
    )

    logger.info("Invoking %s", label)
    start_time = time.monotonic()
    agent_result = run_agent(spec, config)
    duration = time.monotonic() - start_time

    if agent_result.failed:
        return None

    findings = _parse_analyst_json_output(agent_result.result_text, analyst_def)
    logger.info(
        "Analyst %s completed in %.1fs (num_turns=%d): %d findings, risk_score=%s",
        name,
        duration,
        agent_result.num_turns,
        len(findings.get("findings", [])),
        findings.get("risk_score", "?"),
    )

    findings["_timing"] = {
        "name": name,
        "duration": duration,
        "turns": agent_result.num_turns,
        "token_usage": agent_result.token_usage,
        "model_usage": agent_result.model_usage_by_model,
    }
    return findings


# ---------------------------------------------------------------------------
# Timing summary
# ---------------------------------------------------------------------------


def _log_timing_summary(timings: list[dict[str, Any]]) -> None:
    """Log a summary table of analyst runtimes with slowest-analyst warning."""
    if not timings:
        return

    durations = [t["duration"] for t in timings]
    median_duration = statistics.median(durations)
    max_duration = max(durations)
    next(t["name"] for t in timings if t["duration"] == max_duration)

    lines = ["Analyst timing summary:"]
    for t in sorted(timings, key=lambda x: x["name"]):
        tag = "  [SLOWEST]" if t["duration"] == max_duration and len(timings) > 1 else ""
        lines.append(
            f"  analyst-{t['name']}:{' ' * max(1, 30 - len(t['name']))} {t['duration']:>7.1f}s  (turns={t['turns']}){tag}"
        )

    logger.info("\n".join(lines))

    # Warn if any analyst took more than 2x the median runtime
    if len(timings) > 1:
        for t in timings:
            if t["duration"] > 2 * median_duration:
                logger.warning(
                    "Analyst %s took %.1fs (%.1fx median of %.1fs) — consider reducing prompt scope",
                    t["name"],
                    t["duration"],
                    t["duration"] / median_duration,
                    median_duration,
                )


# ---------------------------------------------------------------------------
# Main entry point — run all 8 analysts in parallel
# ---------------------------------------------------------------------------


def run_all_analysts(config: ScanConfig, target_dir: str = TARGET_DIR) -> list[dict[str, Any]]:
    """Run all 8 analyst agents in parallel.

    Returns a list of findings dicts, one per analyst that completed
    successfully.

    Args:
        config: Scan configuration.
        target_dir: Directory to run analysts in.
    """
    logger.info("Starting %d analyst agents in parallel", len(ANALYST_DEFINITIONS))

    timings: list[dict[str, Any]] = []
    all_findings: list[dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=8) as executor:
        future_to_name = {}
        for analyst_def in ANALYST_DEFINITIONS:
            future = executor.submit(_run_single_analyst, config, analyst_def, target_dir)
            future_to_name[future] = f"analyst-{analyst_def['number']}-{analyst_def['name']}"

        for future in as_completed(future_to_name):
            label = future_to_name[future]
            try:
                findings = future.result()
                if findings is not None:
                    timing = findings.get("_timing")  # Keep _timing in findings for pipeline aggregation
                    if timing:
                        timings.append(timing)
                    all_findings.append(findings)
                logger.info("%s finished successfully", label)
            except Exception:
                logger.exception("%s raised an unexpected exception", label)

    _log_timing_summary(timings)
    logger.info("All %d analyst agents completed", len(ANALYST_DEFINITIONS))
    return all_findings
