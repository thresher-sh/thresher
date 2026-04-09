"""Multi-analyst AI architecture — 8 parallel analyst personas.

Analyst definitions (prompts, tools, config) live in analyst_definitions.yaml.
This module loads them and runs all analysts in parallel.

Each analyst returns its findings as a dict. All findings are returned as
a list from run_all_analysts.
"""

from __future__ import annotations

import json
import logging
import os
import re
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from thresher.run import run as run_cmd
from typing import Any

import yaml

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
    """Load analyst definitions from agents/definitions/*.yaml.

    Files are sorted by name (01-paranoid.yaml, 02-behaviorist.yaml, etc.)
    so the numbering prefix controls execution order.
    """
    definitions = []
    for yaml_file in sorted(_DEFINITIONS_DIR.glob("*.yaml")):
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
# Stream-JSON parsing
# ---------------------------------------------------------------------------

def _extract_result_from_stream(raw_output: str) -> str:
    """Extract the final result text from stream-json output.

    Handles both successful results and error results (e.g. max_turns).
    For error results, attempts to extract the last assistant text content
    as a fallback before giving up.
    """
    result_text = ""
    is_error = False
    error_reason = ""
    last_assistant_text = ""

    for line in raw_output.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if not isinstance(obj, dict):
                continue

            if obj.get("type") == "result":
                result_text = obj.get("result", "")
                is_error = obj.get("is_error", False)
                if is_error:
                    error_reason = obj.get("subtype", "unknown_error")
            elif obj.get("type") == "assistant":
                # Track last assistant text output for fallback extraction
                content = obj.get("message", {}).get("content", [])
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "text":
                        last_assistant_text = block.get("text", "")
            elif "result" in obj and "type" not in obj:
                result_text = obj["result"]
        except json.JSONDecodeError:
            continue

    if result_text:
        return result_text

    # For error results (e.g. max_turns), try last assistant text as fallback
    if is_error and last_assistant_text:
        logger.warning(
            "Agent ended with %s; using last assistant text as fallback",
            error_reason,
        )
        return last_assistant_text

    if is_error:
        logger.warning("Agent ended with %s and produced no text output", error_reason)
        return ""

    return raw_output


def _count_turns_from_stream(raw_output: str) -> int:
    """Count agentic turns in stream-json output.

    Only counts assistant messages that contain tool_use blocks, matching
    how Claude Code's --max-turns flag counts turns.  Text-only responses
    do not count toward the turn limit.
    """
    turns = 0
    for line in raw_output.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict) and obj.get("type") == "assistant":
                content = obj.get("message", {}).get("content", [])
                has_tool_use = any(
                    isinstance(b, dict) and b.get("type") == "tool_use"
                    for b in content
                )
                if has_tool_use:
                    turns += 1
        except json.JSONDecodeError:
            continue
    return turns


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
            analyst_def["name"], missing,
        )
        return None
    return parsed


def _parse_analyst_json_output(raw_output: str, analyst_def: dict[str, Any]) -> dict[str, Any]:
    """Parse JSON from Claude Code headless output for an analyst."""
    if not raw_output or not raw_output.strip():
        logger.warning("Empty output from analyst %s", analyst_def["name"])
        return _empty_findings(analyst_def, "Agent returned empty output")

    text = _extract_result_from_stream(raw_output).strip()

    candidates: list[dict[str, Any]] = []

    # Try direct JSON parse
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict) and "result" in parsed:
            inner = parsed["result"]
            if isinstance(inner, str):
                try:
                    inner_parsed = json.loads(inner)
                    if isinstance(inner_parsed, dict):
                        candidates.append(inner_parsed)
                except json.JSONDecodeError:
                    pass
            elif isinstance(inner, dict):
                candidates.append(inner)
        if isinstance(parsed, dict):
            candidates.append(parsed)
    except json.JSONDecodeError:
        pass

    # Try to extract JSON from markdown code blocks
    json_block = re.search(r"```(?:json)?\s*\n(.*?)\n```", text, re.DOTALL)
    if json_block:
        try:
            parsed = json.loads(json_block.group(1))
            if isinstance(parsed, dict):
                candidates.append(parsed)
        except json.JSONDecodeError:
            pass

    # Try to find a top-level JSON object by braces
    brace_start = text.find("{")
    if brace_start >= 0:
        depth = 0
        for i in range(brace_start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[brace_start : i + 1]
                    try:
                        parsed = json.loads(candidate)
                        if isinstance(parsed, dict):
                            candidates.append(parsed)
                    except json.JSONDecodeError:
                        pass
                    break

    # Return the first candidate that passes schema validation
    for candidate in candidates:
        validated = _validate_analyst_schema(candidate, analyst_def)
        if validated is not None:
            return validated

    logger.warning("Could not parse valid analyst JSON from %s output", analyst_def["name"])
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
    max_turns = (
        config.analyst_max_turns_by_name.get(name)
        or config.analyst_max_turns
        or analyst_def["max_turns"]
    )
    label = f"analyst-{number}-{name}"
    logger.info("%s using max_turns=%d", label, max_turns)

    prompt = _build_analyst_prompt(analyst_def)

    prompt_path = Path(f"/tmp/analyst_{number}_prompt.txt")
    try:
        prompt_path.write_text(prompt)
    except Exception:
        logger.warning("Failed to write prompt for %s", label, exc_info=True)
        return None

    model = config.model
    cmd = [
        "claude",
        "-p", str(prompt_path),
        "--model", model,
        "--allowedTools", "Read,Glob,Grep,Bash",
        "--output-format", "stream-json",
        "--verbose",
        "--max-turns", str(max_turns),
    ]

    env = os.environ.copy()
    ai_env = config.ai_env()
    env.update(ai_env)

    logger.info("Invoking %s", label)
    start_time = time.monotonic()
    try:
        proc = run_cmd(
            cmd,
            label=f"analyst-{name}",
            env=env,
            timeout=3600,
            cwd=target_dir,
        )
        raw_output = proc.stdout.decode(errors="replace")
    except Exception as exc:
        logger.error("%s invocation failed: %s", label, exc)
        return None
    end_time = time.monotonic()
    duration = end_time - start_time

    turns = _count_turns_from_stream(raw_output)
    findings = _parse_analyst_json_output(raw_output, analyst_def)
    logger.info(
        "Analyst %s completed in %.1fs (turns=%d): %d findings, risk_score=%s",
        name,
        duration,
        turns,
        len(findings.get("findings", [])),
        findings.get("risk_score", "?"),
    )

    # Attach timing metadata to the findings dict for the caller
    findings["_timing"] = {"name": name, "duration": duration, "turns": turns}

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
    slowest_name = next(t["name"] for t in timings if t["duration"] == max_duration)

    lines = ["Analyst timing summary:"]
    for t in sorted(timings, key=lambda x: x["name"]):
        tag = "  [SLOWEST]" if t["duration"] == max_duration and len(timings) > 1 else ""
        lines.append(f"  analyst-{t['name']}:{' ' * max(1, 30 - len(t['name']))} {t['duration']:>7.1f}s  (turns={t['turns']}){tag}")

    logger.info("\n".join(lines))

    # Warn if any analyst took more than 2x the median runtime
    if len(timings) > 1:
        for t in timings:
            if t["duration"] > 2 * median_duration:
                logger.warning(
                    "Analyst %s took %.1fs (%.1fx median of %.1fs) — "
                    "consider reducing prompt scope",
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
                    timing = findings.pop("_timing", None)
                    if timing:
                        timings.append(timing)
                    all_findings.append(findings)
                logger.info("%s finished successfully", label)
            except Exception:
                logger.exception("%s raised an unexpected exception", label)

    _log_timing_summary(timings)
    logger.info("All %d analyst agents completed", len(ANALYST_DEFINITIONS))
    return all_findings
