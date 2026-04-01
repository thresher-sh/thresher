"""Agent 1: Independent Security Researcher.

Invokes Claude Code headless inside the VM to independently explore and
investigate the target repository for supply chain attacks, malicious code,
and dangerous dependencies. Has NO access to scanner results — conducts
its own investigation from scratch.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from thresher.agents.prompts import ANALYST_SYSTEM_PROMPT
from thresher.config import ScanConfig
from thresher.vm.ssh import ssh_exec, ssh_write_file

logger = logging.getLogger(__name__)


def _shell_quote_key(value: str) -> str:
    """Quote a string for safe inclusion in a shell command."""
    return "'" + value.replace("'", "'\\''") + "'"

TARGET_DIR = "/opt/target"


def _extract_result_from_stream(raw_output: str) -> str:
    """Extract the final result text from stream-json output.

    stream-json emits one JSON object per line. The last ``result`` message
    contains the agent's final response text.
    """
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


def _parse_agent_json_output(raw_output: str) -> dict[str, Any]:
    """Parse JSON from Claude Code headless output.

    Supports both --output-format json (single envelope) and
    --output-format stream-json (newline-delimited events).
    """
    if not raw_output or not raw_output.strip():
        logger.warning("Empty output from analyst agent")
        return _empty_findings("Agent returned empty output")

    text = _extract_result_from_stream(raw_output).strip()

    # Try direct JSON parse
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict) and "result" in parsed:
            inner = parsed["result"]
            if isinstance(inner, str):
                return _parse_inner_json(inner)
            if isinstance(inner, dict):
                return inner
        if isinstance(parsed, dict) and "findings" in parsed:
            return parsed
        if isinstance(parsed, list):
            return {"findings": parsed, "project_summary": "Parsed from list output"}
        return parsed
    except json.JSONDecodeError:
        pass

    # Try to extract JSON from markdown code blocks
    return _extract_json_from_text(text)


def _parse_inner_json(text: str) -> dict[str, Any]:
    """Parse the inner JSON string from a Claude Code result envelope."""
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict):
            return parsed
        return {"findings": parsed if isinstance(parsed, list) else [], "raw": text}
    except json.JSONDecodeError:
        return _extract_json_from_text(text)


def _extract_json_from_text(text: str) -> dict[str, Any]:
    """Try to find and parse JSON embedded in text (e.g., inside code blocks)."""
    # Look for ```json ... ``` blocks
    import re

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

    logger.warning("Could not parse JSON from agent output; returning raw text")
    return _empty_findings(f"Failed to parse agent output. Raw: {text[:500]}")


def _empty_findings(reason: str) -> dict[str, Any]:
    """Return an empty findings structure with an error note."""
    return {
        "project_summary": reason,
        "files_analyzed": 0,
        "high_risk_count": 0,
        "findings": [],
        "error": reason,
    }


def run_analysis(
    vm_name: str,
    config: ScanConfig,
) -> None:
    """Run the analyst agent as an independent security researcher.

    The agent explores the repository on its own with no scanner context.
    It uses Read, Glob, and Grep to investigate the codebase for supply
    chain attacks, malicious code, and dangerous dependencies.

    Findings are written to the VM at /opt/scan-results/analyst-findings.json
    and /opt/scan-results/analyst-findings.md.  No structured findings data
    is returned to the host -- only log-level output crosses the VM boundary.

    Args:
        vm_name: Name of the Lima VM.
        config: Scan configuration.
    """
    prompt = ANALYST_SYSTEM_PROMPT

    try:
        ssh_write_file(vm_name, prompt, "/tmp/analyst_prompt.txt")
    except Exception:
        logger.warning("Failed to write prompt file to VM", exc_info=True)
        return

    model = config.model
    claude_cmd = (
        f"cd {TARGET_DIR} && "
        f"claude -p \"$(cat /tmp/analyst_prompt.txt)\" "
        f"--model {model} "
        f'--allowedTools "Read,Glob,Grep" '
        f"--output-format stream-json "
        f"--verbose "
        f"--max-turns 30"
    )

    # Write API key to tmpfs (never touches disk) and read-and-delete to
    # minimize the exposure window inside the VM.
    env = config.ai_env()
    api_key = env.get("ANTHROPIC_API_KEY", "") if env else ""
    if api_key:
        ssh_exec(
            vm_name,
            "printf '%s' " + _shell_quote_key(api_key) + " > /dev/shm/.api_key"
            " && chmod 600 /dev/shm/.api_key",
        )
        claude_cmd = (
            "ANTHROPIC_API_KEY=$(cat /dev/shm/.api_key); "
            "export ANTHROPIC_API_KEY; "
            "rm -f /dev/shm/.api_key; "
            + claude_cmd
        )

    logger.info("Invoking analyst agent (independent researcher) in VM %s", vm_name)
    try:
        stdout, _stderr, _rc = ssh_exec(
            vm_name, claude_cmd, timeout=3600,
        )
        raw_output = stdout
    except Exception as exc:
        logger.error("Analyst agent invocation failed: %s", exc)
        return

    findings = _parse_agent_json_output(raw_output)
    logger.info(
        "Analyst agent completed: %d findings",
        len(findings.get("findings", [])),
    )

    # Write findings JSON back into the VM so downstream agents can read it.
    # The slight boundary crossing (stdout -> host -> write back) is acceptable
    # because we are routing data back into the VM, not consuming it on the host.
    try:
        findings_json = json.dumps(findings, indent=2, default=str)
        ssh_write_file(vm_name, findings_json, "/opt/scan-results/analyst-findings.json")
    except Exception:
        logger.warning("Failed to save analyst findings JSON", exc_info=True)

    # Write analyst findings as a readable markdown report
    try:
        md = _format_analyst_markdown(findings)
        ssh_write_file(vm_name, md, "/opt/scan-results/analyst-findings.md")
    except Exception:
        logger.warning("Failed to save analyst findings markdown", exc_info=True)


def _format_analyst_markdown(findings: dict[str, Any]) -> str:
    """Format analyst findings as a readable markdown report."""
    lines: list[str] = []
    lines.append("# AI Security Researcher — Analyst Findings")
    lines.append("")

    summary = findings.get("project_summary", "")
    if summary:
        lines.append(f"**Summary:** {summary}")
        lines.append("")

    lines.append(f"**Files analyzed:** {findings.get('files_analyzed', '?')}")
    lines.append(f"**High risk count:** {findings.get('high_risk_count', 0)}")
    lines.append("")

    # Show what areas were investigated
    areas = findings.get("investigation_areas", [])
    if areas:
        lines.append("## Investigation Areas")
        lines.append("")
        for area in areas:
            lines.append(f"- {area}")
        lines.append("")

    finding_list = findings.get("findings", [])
    if not finding_list:
        lines.append("## Findings")
        lines.append("")
        lines.append("No security concerns identified. All investigated files appear clean.")
        return "\n".join(lines)

    lines.append(f"## Findings ({len(finding_list)})")
    lines.append("")

    for i, f in enumerate(finding_list, 1):
        fp = f.get("file_path", "unknown").replace("/opt/target/", "")
        score = f.get("risk_score", "?")
        reasoning = f.get("reasoning", "")

        lines.append(f"---")
        lines.append(f"## {i}. `{fp}` (risk: {score}/10)")
        lines.append("")

        if reasoning:
            lines.append(f"**Analysis:** {reasoning}")
            lines.append("")

        sub_findings = f.get("findings", [])
        for sf in sub_findings:
            if not isinstance(sf, dict):
                continue
            sev = sf.get("severity", "?").upper()
            pattern = sf.get("pattern", "?")
            desc = sf.get("description", "")
            conf = sf.get("confidence", "?")
            line_nums = sf.get("line_numbers", [])
            line_str = f" (lines {', '.join(str(l) for l in line_nums)})" if line_nums else ""

            lines.append(f"- **[{sev}]** `{pattern}`{line_str} — confidence {conf}%")
            lines.append(f"  {desc}")
            lines.append("")

    return "\n".join(lines)
