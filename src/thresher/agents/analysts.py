"""Multi-analyst AI architecture — 8 parallel analyst personas.

Analyst definitions (prompts, tools, config) live in analyst_definitions.yaml.
This module loads them and runs all analysts in parallel inside the VM.

Each analyst writes findings to /opt/scan-results/analyst-{N}-{name}-findings.json.
All data stays in the VM. Functions return None.
"""

from __future__ import annotations

import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import yaml

from thresher.config import ScanConfig
from thresher.vm.ssh import ssh_exec, ssh_write_file

logger = logging.getLogger(__name__)

TARGET_DIR = "/opt/target"
DEPS_DIR = "/opt/deps"
SCAN_RESULTS_DIR = "/opt/scan-results"

_DEFINITIONS_DIR = Path(__file__).parent / "definitions"


def _shell_quote_key(value: str) -> str:
    """Quote a string for safe inclusion in a shell command."""
    return "'" + value.replace("'", "'\\''") + "'"


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
    """Extract the final result text from stream-json output."""
    result_text = ""
    for line in raw_output.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict) and obj.get("type") == "result":
                result_text = obj.get("result", "")
            elif isinstance(obj, dict) and "result" in obj and "type" not in obj:
                result_text = obj["result"]
        except json.JSONDecodeError:
            continue
    return result_text if result_text else raw_output


def _parse_analyst_json_output(raw_output: str, analyst_def: dict[str, Any]) -> dict[str, Any]:
    """Parse JSON from Claude Code headless output for an analyst."""
    if not raw_output or not raw_output.strip():
        logger.warning("Empty output from analyst %s", analyst_def["name"])
        return _empty_findings(analyst_def, "Agent returned empty output")

    text = _extract_result_from_stream(raw_output).strip()

    # Try direct JSON parse
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict) and "result" in parsed:
            inner = parsed["result"]
            if isinstance(inner, str):
                try:
                    inner_parsed = json.loads(inner)
                    if isinstance(inner_parsed, dict):
                        return inner_parsed
                except json.JSONDecodeError:
                    pass
            elif isinstance(inner, dict):
                return inner
        if isinstance(parsed, dict) and "findings" in parsed:
            return parsed
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    # Try to extract JSON from markdown code blocks
    json_block = re.search(r"```(?:json)?\s*\n(.*?)\n```", text, re.DOTALL)
    if json_block:
        try:
            parsed = json.loads(json_block.group(1))
            if isinstance(parsed, dict):
                return parsed
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
                            return parsed
                    except json.JSONDecodeError:
                        break

    logger.warning("Could not parse JSON from analyst %s output", analyst_def["name"])
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
    vm_name: str,
    config: ScanConfig,
    analyst_def: dict[str, Any],
) -> None:
    """Run a single analyst agent inside the VM.

    Writes findings to /opt/scan-results/analyst-{N}-{name}-findings.json
    and a markdown summary alongside it. Returns None.
    """
    number = analyst_def["number"]
    name = analyst_def["name"]
    max_turns = analyst_def["max_turns"]
    label = f"analyst-{number}-{name}"

    prompt = _build_analyst_prompt(analyst_def)

    prompt_path = f"/tmp/analyst_{number}_prompt.txt"
    try:
        ssh_write_file(vm_name, prompt, prompt_path)
    except Exception:
        logger.warning("Failed to write prompt for %s", label, exc_info=True)
        return

    model = config.model
    claude_cmd = (
        f"cd {TARGET_DIR} && "
        f"claude -p \"$(cat {prompt_path})\" "
        f"--model {model} "
        f'--allowedTools "Read,Glob,Grep,Bash" '
        f"--output-format stream-json "
        f"--verbose "
        f"--max-turns {max_turns}"
    )

    # Write API key to tmpfs (never touches disk) and read-and-delete
    env = config.ai_env()
    api_key = env.get("ANTHROPIC_API_KEY", "") if env else ""
    if api_key:
        # Each analyst uses a unique tmpfs path to avoid race conditions
        key_path = f"/dev/shm/.api_key_{number}"
        ssh_exec(
            vm_name,
            "printf '%s' " + _shell_quote_key(api_key) + f" > {key_path}"
            f" && chmod 600 {key_path}",
        )
        claude_cmd = (
            f"ANTHROPIC_API_KEY=$(cat {key_path}); "
            "export ANTHROPIC_API_KEY; "
            f"rm -f {key_path}; "
            + claude_cmd
        )

    logger.info("Invoking %s in VM %s", label, vm_name)
    try:
        stdout, _stderr, _rc = ssh_exec(
            vm_name, claude_cmd, timeout=3600,
        )
        raw_output = stdout
    except Exception as exc:
        logger.error("%s invocation failed: %s", label, exc)
        return

    findings = _parse_analyst_json_output(raw_output, analyst_def)
    logger.info(
        "%s completed: %d findings, risk_score=%s",
        label,
        len(findings.get("findings", [])),
        findings.get("risk_score", "?"),
    )

    # Write findings JSON into the VM
    findings_path = f"{SCAN_RESULTS_DIR}/{label}-findings.json"
    try:
        findings_json = json.dumps(findings, indent=2, default=str)
        ssh_write_file(vm_name, findings_json, findings_path)
    except Exception:
        logger.warning("Failed to save %s findings JSON", label, exc_info=True)

    # Write markdown summary
    md_path = f"{SCAN_RESULTS_DIR}/{label}-findings.md"
    try:
        md = _format_analyst_markdown(findings, analyst_def)
        ssh_write_file(vm_name, md, md_path)
    except Exception:
        logger.warning("Failed to save %s findings markdown", label, exc_info=True)


# ---------------------------------------------------------------------------
# Main entry point — run all 8 analysts in parallel
# ---------------------------------------------------------------------------

def run_all_analysts(vm_name: str, config: ScanConfig) -> None:
    """Run all 8 analyst agents in parallel inside the VM.

    Each analyst writes its findings to the VM at
    /opt/scan-results/analyst-{N}-{name}-findings.json. No structured
    data is returned to the host.

    Args:
        vm_name: Name of the Lima VM.
        config: Scan configuration.
    """
    logger.info("Starting %d analyst agents in parallel", len(ANALYST_DEFINITIONS))

    with ThreadPoolExecutor(max_workers=8) as executor:
        future_to_name = {}
        for analyst_def in ANALYST_DEFINITIONS:
            future = executor.submit(_run_single_analyst, vm_name, config, analyst_def)
            future_to_name[future] = f"analyst-{analyst_def['number']}-{analyst_def['name']}"

        for future in as_completed(future_to_name):
            label = future_to_name[future]
            try:
                future.result()
                logger.info("%s finished successfully", label)
            except Exception:
                logger.exception("%s raised an unexpected exception", label)

    logger.info("All %d analyst agents completed", len(ANALYST_DEFINITIONS))
