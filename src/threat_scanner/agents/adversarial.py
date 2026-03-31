"""Agent 2: Adversarial Verification.

Takes findings from the independent AI security researcher and attempts
to construct benign explanations. Findings that survive become confirmed;
findings that don't get downgraded. Has NO access to scanner results —
only verifies the AI researcher's findings.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from threat_scanner.agents.prompts import ADVERSARIAL_SYSTEM_PROMPT
from threat_scanner.config import ScanConfig
from threat_scanner.vm.ssh import ssh_exec, ssh_write_file

logger = logging.getLogger(__name__)

TARGET_DIR = "/opt/target"

# Risk threshold: findings at or above this score go through adversarial review
RISK_THRESHOLD = 4


def _extract_high_risk(ai_findings: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract AI findings that meet the risk threshold for adversarial review."""
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
                    "file_path": file_finding.get("file_path", "N/A"),
                    "line_numbers": sorted(set(line_numbers)),
                    "risk_score": int(risk_score),
                    "title": (
                        descriptions[0][:120] if descriptions else "AI finding"
                    ),
                    "description": "\n".join(descriptions),
                    "reasoning": file_finding.get("reasoning", ""),
                }
            )

    return high_risk


def _format_findings_for_prompt(findings: list[dict[str, Any]]) -> str:
    """Format high-risk findings as text for the adversarial prompt."""
    lines: list[str] = []
    lines.append("## Findings to Verify\n")
    lines.append(
        f"The following {len(findings)} finding(s) scored risk >= {RISK_THRESHOLD} "
        "from the security researcher and require adversarial verification.\n"
    )

    for i, finding in enumerate(findings, 1):
        lines.append(f"### Finding {i}")
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
            lines.append(f"- **Researcher Reasoning**: {reasoning}")

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
    """Parse JSON from the adversarial agent output."""
    if not raw_output or not raw_output.strip():
        logger.warning("Empty output from adversarial agent")
        return {"results": [], "error": "Agent returned empty output"}

    text = _extract_result_from_stream(raw_output).strip()

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

    # Try code block extraction
    import re

    json_block = re.search(r"```(?:json)?\s*\n(.*?)\n```", text, re.DOTALL)
    if json_block:
        try:
            parsed = json.loads(json_block.group(1))
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass

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

    logger.warning("Could not parse adversarial output")
    return {"results": [], "error": f"Parse failed. Raw: {text[:500]}"}


def _merge_adversarial_results(
    ai_findings: dict[str, Any],
    verification: dict[str, Any],
) -> dict[str, Any]:
    """Merge adversarial verification verdicts back into AI findings."""
    updated_findings = ai_findings.copy()

    results = verification.get("results", [])
    if not isinstance(results, list):
        return updated_findings

    results_by_path: dict[str, dict[str, Any]] = {}
    for result in results:
        if isinstance(result, dict):
            fp = result.get("file_path", "")
            if fp:
                results_by_path[fp] = result

    findings_list = updated_findings.get("findings", [])
    for finding in findings_list:
        if not isinstance(finding, dict):
            continue
        fp = finding.get("file_path", "")
        verification_result = results_by_path.get(fp)
        if verification_result:
            finding["adversarial_status"] = verification_result.get("verdict", "unknown")
            finding["adversarial_reasoning"] = verification_result.get("reasoning", "")
            finding["adversarial_confidence"] = verification_result.get("confidence", 0)
            finding["benign_explanation"] = verification_result.get(
                "benign_explanation_attempted", ""
            )
            revised = verification_result.get("revised_risk_score")
            if revised is not None:
                finding["original_risk_score"] = finding.get("risk_score", 0)
                finding["risk_score"] = int(revised)

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
) -> dict[str, Any]:
    """Run the adversarial verification agent.

    Filters AI findings to high-risk (score >= 4), invokes Claude Code
    headless to attempt benign explanations, and merges results back.

    Has NO access to scanner results — only verifies the AI researcher's findings.

    Args:
        vm_name: Name of the Lima VM.
        config: Scan configuration.
        ai_findings: Structured output from the analyst agent.

    Returns:
        Updated findings dict with adversarial verification status merged in.
    """
    high_risk = _extract_high_risk(ai_findings)

    if not high_risk:
        logger.info("No high-risk findings to verify — skipping adversarial agent")
        return ai_findings

    logger.info(
        "Starting adversarial verification of %d finding(s)", len(high_risk)
    )

    prompt = _build_adversarial_prompt(high_risk)

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

    model = config.model
    claude_cmd = (
        f"cd {TARGET_DIR} && "
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
        ai_findings_copy = ai_findings.copy()
        ai_findings_copy["adversarial_verification"] = {
            "error": f"Agent invocation failed: {exc}",
            "summary": "Adversarial verification failed",
        }
        return ai_findings_copy

    verification = _parse_adversarial_output(raw_output)
    logger.info(
        "Adversarial verification completed: confirmed=%s, downgraded=%s",
        verification.get("confirmed_count", "?"),
        verification.get("downgraded_count", "?"),
    )

    merged = _merge_adversarial_results(ai_findings, verification)

    # Write adversarial findings as a readable markdown report
    try:
        md = _format_adversarial_markdown(verification, merged)
        ssh_write_file(vm_name, md, "/opt/scan-results/adversarial-findings.md")
    except Exception:
        logger.warning("Failed to save adversarial findings markdown", exc_info=True)

    return merged


def _format_adversarial_markdown(
    verification: dict[str, Any],
    merged: dict[str, Any],
) -> str:
    """Format adversarial verification results as a readable markdown report."""
    lines: list[str] = []
    lines.append("# AI Security Researcher — Adversarial Verification")
    lines.append("")

    summary = verification.get("verification_summary", "")
    if summary:
        lines.append(f"**Summary:** {summary}")
        lines.append("")

    lines.append(f"**Total reviewed:** {verification.get('total_reviewed', 0)}")
    lines.append(f"**Confirmed:** {verification.get('confirmed_count', 0)}")
    lines.append(f"**Downgraded:** {verification.get('downgraded_count', 0)}")
    lines.append("")

    results = verification.get("results", [])
    if not results:
        lines.append("No findings reviewed (all below risk threshold).")
        return "\n".join(lines)

    for i, r in enumerate(results, 1):
        fp = r.get("file_path", "unknown").replace("/opt/target/", "")
        verdict = r.get("verdict", "?").upper()
        orig_score = r.get("original_risk_score", "?")
        revised_score = r.get("revised_risk_score", orig_score)
        conf = r.get("confidence", "?")

        lines.append("---")
        lines.append(f"## {i}. `{fp}` — {verdict}")
        lines.append(f"**Risk:** {orig_score} → {revised_score} | **Confidence:** {conf}%")
        lines.append("")

        benign = r.get("benign_explanation_attempted", "")
        if benign:
            lines.append(f"**Benign explanation attempted:** {benign}")
            lines.append("")

        reasoning = r.get("reasoning", "")
        if reasoning:
            lines.append(f"**Verdict reasoning:** {reasoning}")
            lines.append("")

    return "\n".join(lines)
