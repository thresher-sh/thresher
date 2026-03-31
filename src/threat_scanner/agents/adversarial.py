"""Agent 2: Adversarial Verification.

Takes high-risk findings from both deterministic scanners and AI analysis,
then invokes Claude Code headless inside the VM to attempt benign explanations.
Findings that survive become confirmed; findings that don't get downgraded.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from threat_scanner.agents.prompts import ADVERSARIAL_SYSTEM_PROMPT
from threat_scanner.config import ScanConfig
from threat_scanner.vm.ssh import ssh_exec, ssh_write_file

logger = logging.getLogger(__name__)

# Risk threshold: findings at or above this score go through adversarial review
RISK_THRESHOLD = 4


def _extract_scanner_high_risk(scanner_results: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract findings from deterministic scanners that meet the risk threshold.

    Maps scanner severity levels to numeric risk scores for threshold comparison:
    - critical -> 9
    - high -> 7
    - medium -> 5
    - low -> 2
    - info -> 1
    """
    severity_to_risk: dict[str, int] = {
        "critical": 9,
        "high": 7,
        "medium": 5,
        "low": 2,
        "info": 1,
    }

    high_risk: list[dict[str, Any]] = []

    if not isinstance(scanner_results, dict):
        return high_risk

    for tool_name, tool_findings in scanner_results.items():
        if not isinstance(tool_findings, list):
            continue
        for finding in tool_findings:
            if not isinstance(finding, dict):
                continue

            severity = finding.get("severity", "info").lower()
            risk_score = severity_to_risk.get(severity, 1)

            # Also check if the finding has an explicit risk_score field
            explicit_risk = finding.get("risk_score")
            if isinstance(explicit_risk, (int, float)):
                risk_score = max(risk_score, int(explicit_risk))

            if risk_score >= RISK_THRESHOLD:
                high_risk.append(
                    {
                        "source": f"scanner:{tool_name}",
                        "file_path": finding.get("file_path", "N/A"),
                        "line_numbers": (
                            [finding["line_number"]]
                            if finding.get("line_number")
                            else []
                        ),
                        "risk_score": risk_score,
                        "title": finding.get("title", "Untitled"),
                        "description": finding.get("description", ""),
                        "severity": severity,
                        "cve_id": finding.get("cve_id"),
                    }
                )

    return high_risk


def _extract_ai_high_risk(ai_findings: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract findings from AI analysis that meet the risk threshold."""
    high_risk: list[dict[str, Any]] = []

    findings_list = ai_findings.get("findings", [])
    if not isinstance(findings_list, list):
        return high_risk

    for file_finding in findings_list:
        if not isinstance(file_finding, dict):
            continue

        risk_score = file_finding.get("risk_score", 0)
        if not isinstance(risk_score, (int, float)):
            continue

        if risk_score >= RISK_THRESHOLD:
            # Flatten the sub-findings into the entry for the adversarial agent
            sub_findings = file_finding.get("findings", [])
            descriptions = []
            line_numbers: list[int] = []
            for sf in sub_findings if isinstance(sub_findings, list) else []:
                if isinstance(sf, dict):
                    desc = sf.get("description", "")
                    if desc:
                        descriptions.append(desc)
                    lines = sf.get("line_numbers", [])
                    if isinstance(lines, list):
                        line_numbers.extend(
                            ln for ln in lines if isinstance(ln, int)
                        )

            high_risk.append(
                {
                    "source": "ai_analysis",
                    "file_path": file_finding.get("file_path", "N/A"),
                    "line_numbers": sorted(set(line_numbers)),
                    "risk_score": int(risk_score),
                    "title": (
                        descriptions[0][:120] if descriptions else "AI finding"
                    ),
                    "description": "\n".join(descriptions),
                    "reasoning": file_finding.get("reasoning", ""),
                    "git_blame_notes": file_finding.get("git_blame_notes", ""),
                    "stripped_reanalysis": file_finding.get(
                        "stripped_reanalysis", ""
                    ),
                }
            )

    return high_risk


def filter_high_risk_findings(
    scanner_results: dict[str, Any],
    ai_findings: dict[str, Any],
) -> list[dict[str, Any]]:
    """Collect all findings with risk >= 4 from both scanners and AI analysis.

    Args:
        scanner_results: Aggregated deterministic scanner output (tool -> findings).
        ai_findings: Structured output from the analyst agent.

    Returns:
        List of high-risk findings formatted for the adversarial agent.
    """
    scanner_high = _extract_scanner_high_risk(scanner_results)
    ai_high = _extract_ai_high_risk(ai_findings)

    combined = scanner_high + ai_high
    logger.info(
        "High-risk findings for adversarial review: %d (scanner: %d, AI: %d)",
        len(combined),
        len(scanner_high),
        len(ai_high),
    )
    return combined


def _format_findings_for_prompt(findings: list[dict[str, Any]]) -> str:
    """Format high-risk findings as text for the adversarial prompt."""
    lines: list[str] = []
    lines.append("## Findings to Verify\n")
    lines.append(
        f"The following {len(findings)} finding(s) scored risk >= {RISK_THRESHOLD} "
        "and require adversarial verification.\n"
    )

    for i, finding in enumerate(findings, 1):
        lines.append(f"### Finding {i}")
        lines.append(f"- **Source**: {finding.get('source', 'unknown')}")
        lines.append(f"- **File**: {finding.get('file_path', 'N/A')}")
        line_nums = finding.get("line_numbers", [])
        if line_nums:
            lines.append(f"- **Lines**: {', '.join(str(ln) for ln in line_nums)}")
        lines.append(f"- **Risk Score**: {finding.get('risk_score', 'N/A')}")
        lines.append(f"- **Title**: {finding.get('title', 'Untitled')}")

        description = finding.get("description", "")
        if description:
            lines.append(f"- **Description**: {description}")

        reasoning = finding.get("reasoning", "")
        if reasoning:
            lines.append(f"- **Analyst Reasoning**: {reasoning}")

        cve_id = finding.get("cve_id")
        if cve_id:
            lines.append(f"- **CVE**: {cve_id}")

        lines.append("")

    return "\n".join(lines)


def _build_adversarial_prompt(findings: list[dict[str, Any]]) -> str:
    """Construct the full prompt for the adversarial agent."""
    parts: list[str] = [
        ADVERSARIAL_SYSTEM_PROMPT,
        "\n---\n",
        _format_findings_for_prompt(findings),
        "\n---\n",
        "Read each flagged file at the specified path and line numbers. "
        "For each finding, attempt a benign explanation as described above, "
        "then render your verdict. Output your results as the JSON structure "
        "described in the system prompt.",
    ]
    return "\n".join(parts)


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


def _parse_adversarial_output(raw_output: str) -> dict[str, Any]:
    """Parse JSON from the adversarial agent output.

    Supports both --output-format json and stream-json.
    """
    if not raw_output or not raw_output.strip():
        logger.warning("Empty output from adversarial agent")
        return {"results": [], "error": "Agent returned empty output"}

    text = _extract_result_from_stream(raw_output).strip()

    # Try direct parse
    try:
        parsed = json.loads(text)
        if isinstance(parsed, dict) and "result" in parsed:
            inner = parsed["result"]
            if isinstance(inner, str):
                try:
                    return json.loads(inner)
                except json.JSONDecodeError:
                    pass
            elif isinstance(inner, dict):
                return inner
        if isinstance(parsed, dict) and "results" in parsed:
            return parsed
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    # Try extracting from code blocks
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

    # Try extracting first JSON object
    brace_start = text.find("{")
    if brace_start >= 0:
        depth = 0
        for i in range(brace_start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[brace_start : i + 1])
                    except json.JSONDecodeError:
                        break

    logger.warning("Could not parse adversarial agent output")
    return {"results": [], "error": f"Failed to parse output. Raw: {text[:500]}"}


def _merge_verification_results(
    ai_findings: dict[str, Any],
    verification: dict[str, Any],
) -> dict[str, Any]:
    """Merge adversarial verification results back into the AI findings dict.

    Updates each finding's status based on the adversarial verdict:
    - confirmed: finding stands, add adversarial_status and reasoning
    - downgraded: reduce risk_score, add adversarial_status and reasoning
    """
    results = verification.get("results", [])
    if not isinstance(results, list):
        logger.warning("No verification results to merge")
        return ai_findings

    # Build a lookup by file_path for fast matching
    verification_by_path: dict[str, dict[str, Any]] = {}
    for result in results:
        if isinstance(result, dict):
            path = result.get("file_path", "")
            if path:
                verification_by_path[path] = result

    # Update AI findings
    updated_findings = ai_findings.copy()
    findings_list = updated_findings.get("findings", [])
    if not isinstance(findings_list, list):
        return updated_findings

    for finding in findings_list:
        if not isinstance(finding, dict):
            continue
        file_path = finding.get("file_path", "")
        if file_path in verification_by_path:
            vr = verification_by_path[file_path]
            finding["adversarial_status"] = vr.get("verdict", "unknown")
            finding["adversarial_reasoning"] = vr.get("reasoning", "")
            finding["adversarial_confidence"] = vr.get("confidence")
            finding["benign_explanation"] = vr.get(
                "benign_explanation_attempted", ""
            )

            # If downgraded, update the risk score
            if vr.get("verdict") == "downgraded":
                revised = vr.get("revised_risk_score")
                if isinstance(revised, (int, float)):
                    finding["original_risk_score"] = finding.get("risk_score")
                    finding["risk_score"] = int(revised)

    # Add verification metadata
    updated_findings["adversarial_verification"] = {
        "summary": verification.get("verification_summary", ""),
        "total_reviewed": verification.get("total_reviewed", 0),
        "confirmed_count": verification.get("confirmed_count", 0),
        "downgraded_count": verification.get("downgraded_count", 0),
    }

    return updated_findings


def run_adversarial_verification(
    vm_name: str,
    config: ScanConfig,
    ai_findings: dict[str, Any],
    scanner_results: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Run the adversarial verification agent (Agent 2).

    Filters to high-risk findings, invokes Claude Code headless inside the VM
    to attempt benign explanations, and merges results back into findings.

    Args:
        vm_name: Name of the Lima VM.
        config: Scan configuration.
        ai_findings: Structured output from the analyst agent.
        scanner_results: Aggregated deterministic scanner output. If None,
            only AI findings are checked for high-risk entries.

    Returns:
        Updated findings dict with adversarial verification status merged in.
    """
    # Filter to high-risk findings
    high_risk = filter_high_risk_findings(
        scanner_results if scanner_results is not None else {},
        ai_findings,
    )

    if not high_risk:
        logger.info("No high-risk findings to verify — skipping adversarial agent")
        return ai_findings

    logger.info(
        "Starting adversarial verification of %d finding(s)", len(high_risk)
    )

    # Build the prompt
    prompt = _build_adversarial_prompt(high_risk)

    # Write prompt to file inside the VM via safe copy (avoids heredoc
    # injection if finding descriptions contain the EOF marker string).
    try:
        ssh_write_file(vm_name, prompt, "/tmp/adversarial_prompt.txt")
    except Exception:
        logger.warning(
            "Failed to write adversarial prompt file to VM", exc_info=True
        )
        ai_findings_copy = ai_findings.copy()
        ai_findings_copy["adversarial_verification"] = {
            "error": "Failed to write prompt file to VM",
            "summary": "Adversarial verification failed",
        }
        return ai_findings_copy

    # Invoke Claude Code headless.
    # Pass the API key via env so Claude Code can authenticate.
    model = config.model
    claude_cmd = (
        f"cd /opt/target && "
        f"claude -p \"$(cat /tmp/adversarial_prompt.txt)\" "
        f"--model {model} "
        f'--allowedTools "Read,Glob,Grep" '
        f"--output-format stream-json "
        f"--verbose "
        f"--max-turns 20"
    )

    env = config.ai_env()

    logger.info("Invoking adversarial agent in VM %s", vm_name)
    try:
        stdout, _stderr, _rc = ssh_exec(
            vm_name, claude_cmd, timeout=2400, env=env or None
        )
        raw_output = stdout
    except Exception as exc:
        logger.error("Adversarial agent invocation failed: %s", exc)
        # Return AI findings unmodified on failure
        ai_findings_copy = ai_findings.copy()
        ai_findings_copy["adversarial_verification"] = {
            "error": str(exc),
            "summary": "Adversarial verification failed",
        }
        return ai_findings_copy

    # Parse the output
    verification = _parse_adversarial_output(raw_output)

    # Merge verification results back into findings
    merged = _merge_verification_results(ai_findings, verification)

    confirmed = verification.get("confirmed_count", "?")
    downgraded = verification.get("downgraded_count", "?")
    logger.info(
        "Adversarial verification completed: confirmed=%s, downgraded=%s",
        confirmed,
        downgraded,
    )

    return merged
