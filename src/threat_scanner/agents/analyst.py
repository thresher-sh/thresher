"""Agent 1: Triage + Focused Code Analysis.

Builds a targeted file list from scanner results and known high-risk file types,
then invokes Claude Code headless inside the VM to perform deep code analysis.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from threat_scanner.agents.prompts import ANALYST_SYSTEM_PROMPT
from threat_scanner.config import ScanConfig
from threat_scanner.vm.ssh import ssh_exec, ssh_write_file

logger = logging.getLogger(__name__)

# High-risk file glob patterns to always include in triage
HIGH_RISK_GLOBS: list[str] = [
    # Package install hooks and config
    "**/setup.py",
    "**/setup.cfg",
    "**/pyproject.toml",
    # Package entry points
    "**/__init__.py",
    # .pth files (auto-execute on Python startup)
    "**/*.pth",
    # CI/CD configurations
    "**/.github/workflows/*.yml",
    "**/.github/workflows/*.yaml",
    "**/.gitlab-ci.yml",
    "**/Jenkinsfile",
    "**/.circleci/config.yml",
    # Build scripts
    "**/Makefile",
    "**/Dockerfile",
    "**/docker-compose.yml",
    "**/docker-compose.yaml",
    "**/Justfile",
    # npm lifecycle scripts
    "**/postinstall",
    "**/postinstall.sh",
    "**/preinstall",
    "**/preinstall.sh",
    "**/.npmrc",
    # Node entry points
    "**/package.json",
    # Go
    "**/go.mod",
    # Rust
    "**/build.rs",
    "**/Cargo.toml",
]

# Limit on how many __init__.py files to include (only package roots, not every subdir)
MAX_INIT_FILES = 20

TARGET_DIR = "/opt/target"


def _extract_flagged_paths(scanner_results: dict[str, Any]) -> set[str]:
    """Extract all file paths referenced in deterministic scanner findings.

    Handles the normalized finding format defined in the scanner runner:
    each tool key maps to a list of findings, each with an optional 'file_path'.
    """
    paths: set[str] = set()

    if not isinstance(scanner_results, dict):
        return paths

    for _tool_name, tool_findings in scanner_results.items():
        if not isinstance(tool_findings, list):
            # Some tools may store metadata dicts; skip non-list values
            continue
        for finding in tool_findings:
            if not isinstance(finding, dict):
                continue
            file_path = finding.get("file_path")
            if file_path and isinstance(file_path, str):
                paths.add(file_path)

    return paths


def _glob_high_risk_files(vm_name: str) -> set[str]:
    """Glob for known high-risk file types inside the VM.

    Uses find command since it's more reliable across environments than
    shell globbing for recursive patterns.
    """
    paths: set[str] = set()

    for glob_pattern in HIGH_RISK_GLOBS:
        # Convert glob pattern to find arguments
        # e.g., "**/*.pth" -> -name "*.pth"
        # e.g., "**/.github/workflows/*.yml" -> -path "*/.github/workflows/*.yml"
        if "/" in glob_pattern.replace("**/", ""):
            # Path pattern: use -path
            find_pattern = glob_pattern.replace("**", "*")
            cmd = f'find {TARGET_DIR} -path "{find_pattern}" -type f 2>/dev/null'
        else:
            # Simple name pattern
            name_pattern = glob_pattern.replace("**/", "")
            cmd = f'find {TARGET_DIR} -name "{name_pattern}" -type f 2>/dev/null'

        try:
            stdout, _stderr, _rc = ssh_exec(vm_name, cmd)
            for line in stdout.strip().splitlines():
                line = line.strip()
                if line:
                    paths.add(line)
        except Exception:
            logger.debug("Failed to glob pattern %s in VM", glob_pattern, exc_info=True)

    return paths


def _limit_init_files(paths: set[str]) -> set[str]:
    """Limit __init__.py files to package roots (shallowest paths) to avoid noise."""
    init_files = sorted(
        [p for p in paths if p.endswith("__init__.py")],
        key=lambda p: p.count("/"),
    )
    non_init = {p for p in paths if not p.endswith("__init__.py")}

    limited_inits = set(init_files[:MAX_INIT_FILES])
    return non_init | limited_inits


def build_triage_file_list(
    vm_name: str,
    scanner_results: dict[str, Any],
) -> list[str]:
    """Build a deduplicated list of files for the analyst agent to examine.

    Collects:
    1. All file paths flagged by deterministic scanners
    2. Known high-risk file types found by globbing inside the VM

    Args:
        vm_name: Name of the Lima VM.
        scanner_results: Aggregated deterministic scanner output (tool -> findings).

    Returns:
        Deduplicated, sorted list of file paths to analyze.
    """
    paths: set[str] = set()

    # 1. Files flagged by scanners
    flagged = _extract_flagged_paths(scanner_results)
    paths.update(flagged)
    logger.info("Scanner-flagged files: %d", len(flagged))

    # 2. Known high-risk file types
    high_risk = _glob_high_risk_files(vm_name)
    paths.update(high_risk)
    logger.info("High-risk glob files: %d", len(high_risk))

    # 3. Limit __init__.py to avoid context bloat
    paths = _limit_init_files(paths)

    result = sorted(paths)
    logger.info("Total triage file list: %d files", len(result))
    return result


def _format_scanner_summary(scanner_results: dict[str, Any]) -> str:
    """Format scanner results into a concise text summary for the prompt."""
    lines: list[str] = []
    lines.append("## Deterministic Scanner Findings Summary\n")

    if not isinstance(scanner_results, dict):
        lines.append("No scanner results available.\n")
        return "\n".join(lines)

    for tool_name, tool_findings in scanner_results.items():
        if not isinstance(tool_findings, list):
            continue

        count = len(tool_findings)
        if count == 0:
            lines.append(f"### {tool_name}: No findings\n")
            continue

        lines.append(f"### {tool_name}: {count} finding(s)\n")

        # Include up to 50 findings per tool to stay within reasonable prompt size
        for finding in tool_findings[:50]:
            if not isinstance(finding, dict):
                continue
            severity = finding.get("severity", "unknown")
            title = finding.get("title", "Untitled")
            file_path = finding.get("file_path", "N/A")
            cve_id = finding.get("cve_id", "")
            line_num = finding.get("line_number", "")

            entry = f"- [{severity.upper()}] {title}"
            if cve_id:
                entry += f" ({cve_id})"
            entry += f"  -- {file_path}"
            if line_num:
                entry += f":{line_num}"
            lines.append(entry)

        if count > 50:
            lines.append(f"  ... and {count - 50} more findings")
        lines.append("")

    return "\n".join(lines)


def _build_analyst_prompt(
    scanner_results: dict[str, Any],
    triage_files: list[str],
) -> str:
    """Construct the full prompt for the analyst agent."""
    parts: list[str] = [
        ANALYST_SYSTEM_PROMPT,
        "\n---\n",
        _format_scanner_summary(scanner_results),
        "\n---\n",
        "## Files to Analyze (Triage List)\n",
        "Analyze each of the following files. Read them using the Read tool, "
        "then apply the analysis framework described above.\n",
    ]

    for f in triage_files:
        parts.append(f"- {f}")

    parts.append(
        f"\n\nTotal files: {len(triage_files)}. "
        "Analyze every file in the list. Output your findings as the JSON structure "
        "described in the system prompt above."
    )

    return "\n".join(parts)


def _extract_result_from_stream(raw_output: str) -> str:
    """Extract the final result text from stream-json output.

    stream-json emits one JSON object per line. The last ``result`` message
    contains the agent's final response text.  If no result message is found,
    returns the raw output so the downstream parser can try its luck.
    """
    result_text = ""
    for line in raw_output.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            # stream-json result message has type=="result" with a "result" field
            if isinstance(obj, dict) and obj.get("type") == "result":
                result_text = obj.get("result", "")
            # Also handle {"result": "..."} envelope from non-stream format
            elif isinstance(obj, dict) and "result" in obj and "type" not in obj:
                result_text = obj["result"]
        except json.JSONDecodeError:
            continue
    return result_text if result_text else raw_output


def _parse_agent_json_output(raw_output: str) -> dict[str, Any]:
    """Parse JSON from Claude Code headless output, handling malformed responses.

    Supports both --output-format json (single envelope) and
    --output-format stream-json (newline-delimited events).
    """
    if not raw_output or not raw_output.strip():
        logger.warning("Empty output from analyst agent")
        return _empty_findings("Agent returned empty output")

    text = _extract_result_from_stream(raw_output).strip()

    # Try direct JSON parse first (agent output may be clean JSON)
    try:
        parsed = json.loads(text)
        # If the parsed result has a "result" key, it's the Claude Code envelope
        if isinstance(parsed, dict) and "result" in parsed:
            inner = parsed["result"]
            if isinstance(inner, str):
                return _parse_inner_json(inner)
            if isinstance(inner, dict):
                return inner
        # Otherwise it might be the findings directly
        if isinstance(parsed, dict) and "findings" in parsed:
            return parsed
        # Could be a list (unusual but handle it)
        if isinstance(parsed, list):
            return {"findings": parsed, "analysis_summary": "Parsed from list output"}
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

    json_block_pattern = re.compile(r"```(?:json)?\s*\n(.*?)\n```", re.DOTALL)
    matches = json_block_pattern.findall(text)
    for match in matches:
        try:
            parsed = json.loads(match)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            continue

    # Look for the first { ... } that could be valid JSON
    brace_start = text.find("{")
    if brace_start >= 0:
        # Find matching closing brace by counting nesting
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
        "analysis_summary": reason,
        "files_analyzed": 0,
        "high_risk_count": 0,
        "findings": [],
        "error": reason,
    }


def run_analysis(
    vm_name: str,
    config: ScanConfig,
    scanner_results: dict[str, Any],
) -> dict[str, Any]:
    """Run the analyst agent (Agent 1) for triage and focused code analysis.

    Builds the triage file list, constructs the analysis prompt, invokes
    Claude Code headless inside the VM, and returns structured findings.

    Args:
        vm_name: Name of the Lima VM.
        config: Scan configuration.
        scanner_results: Aggregated deterministic scanner output.

    Returns:
        Dict with structured AI analysis findings.
    """
    # Build triage file list
    triage_files = build_triage_file_list(vm_name, scanner_results)

    if not triage_files:
        logger.info("No files to analyze — triage list is empty")
        return _empty_findings("No files matched triage criteria")

    logger.info("Starting analyst agent with %d files", len(triage_files))

    # Build the full prompt
    prompt = _build_analyst_prompt(scanner_results, triage_files)

    # Write prompt to a file inside the VM via safe copy (avoids heredoc
    # injection if scanner findings contain the EOF marker string).
    try:
        ssh_write_file(vm_name, prompt, "/tmp/analyst_prompt.txt")
    except Exception:
        logger.warning("Failed to write prompt file to VM", exc_info=True)
        return _empty_findings("Failed to write prompt file to VM")

    # Invoke Claude Code headless inside the VM.
    # Pass the API key via env so Claude Code can authenticate.
    model = config.model
    claude_cmd = (
        f"cd /opt/target && "
        f"claude -p \"$(cat /tmp/analyst_prompt.txt)\" "
        f"--model {model} "
        f'--allowedTools "Read,Glob,Grep" '
        f"--output-format stream-json "
        f"--verbose "
        f"--max-turns 30"
    )

    env = config.ai_env()

    logger.info("Invoking analyst agent in VM %s", vm_name)
    try:
        stdout, _stderr, _rc = ssh_exec(
            vm_name, claude_cmd, timeout=3600, env=env or None
        )
        raw_output = stdout
    except Exception as exc:
        logger.error("Analyst agent invocation failed: %s", exc)
        return _empty_findings(f"Agent invocation failed: {exc}")

    # Parse the output
    findings = _parse_agent_json_output(raw_output)
    logger.info(
        "Analyst agent completed: %d findings",
        len(findings.get("findings", [])),
    )

    return findings
