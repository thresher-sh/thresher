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

from thresher.agents.prompts import ADVERSARIAL_SYSTEM_PROMPT
from thresher.config import ScanConfig
from thresher.vm.safe_io import safe_json_loads
from thresher.vm.ssh import ssh_exec, ssh_write_file

logger = logging.getLogger(__name__)


def _shell_quote_key(value: str) -> str:
    """Quote a string for safe inclusion in a shell command."""
    return "'" + value.replace("'", "'\\''") + "'"

TARGET_DIR = "/opt/target"

# Risk threshold: findings at or above this score go through adversarial review
RISK_THRESHOLD = 4

# Map severity strings (from multi-analyst schema) to numeric risk scores
_SEVERITY_TO_RISK: dict[str, int] = {
    "critical": 9,
    "high": 7,
    "medium": 4,
    "low": 2,
}


def _finding_risk_score(finding: dict[str, Any]) -> int:
    """Derive a numeric risk score from a finding.

    Supports both the legacy per-file schema (has ``risk_score`` int) and
    the multi-analyst flat schema (has ``severity`` string + ``confidence``).
    """
    # Legacy schema: explicit risk_score on the finding
    explicit = finding.get("risk_score")
    if isinstance(explicit, (int, float)):
        return int(explicit)

    # Multi-analyst schema: map severity string to numeric score
    severity = finding.get("severity", "").lower()
    return _SEVERITY_TO_RISK.get(severity, 0)


def _extract_high_risk(ai_findings: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract AI findings that meet the risk threshold for adversarial review.

    Supports both the legacy per-file schema (nested findings with risk_score)
    and the multi-analyst flat schema (severity + confidence per finding).
    """
    high_risk: list[dict[str, Any]] = []

    findings_list = ai_findings.get("findings", [])
    if not isinstance(findings_list, list):
        return high_risk

    for finding in findings_list:
        if not isinstance(finding, dict):
            continue

        risk_score = _finding_risk_score(finding)

        if risk_score < RISK_THRESHOLD:
            continue

        # Multi-analyst flat schema: finding itself has title, description, etc.
        if "title" in finding or "severity" in finding:
            line_numbers = finding.get("line_numbers", [])
            if isinstance(line_numbers, list):
                line_numbers = sorted(
                    ln for ln in line_numbers if isinstance(ln, int)
                )
            else:
                line_numbers = []

            high_risk.append(
                {
                    "file_path": finding.get("file_path", "N/A"),
                    "line_numbers": line_numbers,
                    "risk_score": risk_score,
                    "title": finding.get("title", "AI finding")[:120],
                    "description": finding.get("description", ""),
                    "reasoning": finding.get("reasoning", ""),
                    "source_analyst": finding.get("source_analyst", "unknown"),
                    "source_analyst_number": finding.get("source_analyst_number", 0),
                }
            )
        else:
            # Legacy per-file schema: nested sub-findings
            sub_findings = finding.get("findings", [])
            descriptions = []
            line_nums: list[int] = []
            for sf in sub_findings if isinstance(sub_findings, list) else []:
                if isinstance(sf, dict):
                    desc = sf.get("description", "")
                    if desc:
                        descriptions.append(desc)
                    lines = sf.get("line_numbers", [])
                    if isinstance(lines, list):
                        line_nums.extend(
                            ln for ln in lines if isinstance(ln, int)
                        )

            high_risk.append(
                {
                    "file_path": finding.get("file_path", "N/A"),
                    "line_numbers": sorted(set(line_nums)),
                    "risk_score": risk_score,
                    "title": (
                        descriptions[0][:120] if descriptions else "AI finding"
                    ),
                    "description": "\n".join(descriptions),
                    "reasoning": finding.get("reasoning", ""),
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

    if is_error and last_assistant_text:
        logger.warning(
            "Adversarial agent ended with %s; using last assistant text as fallback",
            error_reason,
        )
        return last_assistant_text

    if is_error:
        logger.warning("Adversarial agent ended with %s and produced no text output", error_reason)
        return ""

    return raw_output


def _normalize_adversarial_schema(parsed: dict[str, Any]) -> dict[str, Any]:
    """Normalize analyst-forced schema to the expected adversarial schema.

    If the adversarial agent was forced by the analyst stop hook to output
    the analyst schema (with ``findings`` instead of ``results``), map it
    to the expected adversarial schema so downstream code works correctly.
    """
    # Already has "results" key — nothing to remap
    if "results" in parsed:
        return parsed

    # Check for analyst-forced schema: has "findings" with verdict fields
    findings = parsed.get("findings", [])
    if not isinstance(findings, list):
        return parsed

    # Only remap if findings items look like adversarial verdicts (have "verdict")
    has_verdicts = any(
        isinstance(f, dict) and "verdict" in f for f in findings
    )
    if not has_verdicts:
        return parsed

    logger.info(
        "Remapping analyst-forced schema to adversarial schema "
        "(%d findings with verdicts)", len(findings),
    )

    confirmed = sum(
        1 for f in findings
        if isinstance(f, dict) and f.get("verdict") == "confirmed"
    )
    downgraded = sum(
        1 for f in findings
        if isinstance(f, dict) and f.get("verdict") == "downgraded"
    )

    return {
        "results": findings,
        "verification_summary": parsed.get("summary", parsed.get("project_summary", "")),
        "total_reviewed": len(findings),
        "confirmed_count": confirmed,
        "downgraded_count": downgraded,
    }


def _parse_adversarial_output(raw_output: str) -> dict[str, Any]:
    """Parse JSON from the adversarial agent output.

    Handles both the native adversarial schema (``results``) and the
    analyst-forced schema (``findings`` with verdict fields), normalizing
    the latter to the expected adversarial format.
    """
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
                    return _normalize_adversarial_schema(json.loads(inner))
                except json.JSONDecodeError:
                    pass
            elif isinstance(inner, dict):
                return _normalize_adversarial_schema(inner)
        if isinstance(parsed, dict):
            return _normalize_adversarial_schema(parsed)
    except json.JSONDecodeError:
        pass

    # Try code block extraction
    import re

    json_block = re.search(r"```(?:json)?\s*\n(.*?)\n```", text, re.DOTALL)
    if json_block:
        try:
            parsed = json.loads(json_block.group(1))
            if isinstance(parsed, dict):
                return _normalize_adversarial_schema(parsed)
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
                            return _normalize_adversarial_schema(parsed)
                    except json.JSONDecodeError:
                        break

    logger.warning("Could not parse adversarial output. Raw (first 500 chars): %s", text[:500])
    return {"results": [], "error": f"Parse failed. Raw: {text[:500]}"}


def _merge_adversarial_results(
    ai_findings: dict[str, Any],
    verification: dict[str, Any],
) -> dict[str, Any]:
    """Merge adversarial verification verdicts back into AI findings."""
    updated_findings = ai_findings.copy()

    results = verification.get("results", [])
    if not isinstance(results, list):
        if verification:
            logger.warning(
                "Adversarial output has unexpected schema. Keys: %s",
                list(verification.keys()),
            )
        return updated_findings

    total_reviewed = verification.get("total_reviewed", 0)
    if total_reviewed == 0 and verification:
        logger.warning(
            "Adversarial output has unexpected schema. Keys: %s",
            list(verification.keys()),
        )

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


def _read_analyst_findings_from_vm(vm_name: str) -> dict[str, Any]:
    """Read all analyst findings JSON files from within the VM.

    Discovers analyst-*-findings.json files in /opt/scan-results/,
    reads each one, and merges them into a combined findings structure.
    Each finding is annotated with which analyst produced it.

    Returns the merged findings dict, or an empty findings structure
    if no files can be read or parsed.
    """
    combined_findings: list[dict[str, Any]] = []

    try:
        # List all analyst findings files
        result = ssh_exec(
            vm_name,
            "ls /opt/scan-results/analyst-*-findings.json 2>/dev/null",
        )
        if result.exit_code != 0 or not result.stdout.strip():
            # Fall back to legacy single-analyst file
            logger.info("No multi-analyst files found, trying legacy analyst-findings.json")
            try:
                result = ssh_exec(vm_name, "cat /opt/scan-results/analyst-findings.json")
                if result.exit_code != 0:
                    logger.warning("Could not read analyst findings from VM")
                    return {"findings": []}
                parsed = safe_json_loads(result.stdout, source="analyst-findings.json")
                if parsed is None:
                    return {"findings": []}
                return parsed
            except Exception:
                logger.warning("Failed to read legacy analyst findings", exc_info=True)
                return {"findings": []}

        files = result.stdout.strip().splitlines()
        logger.info("Found %d analyst findings files to merge", len(files))

        for filepath in files:
            filepath = filepath.strip()
            if not filepath:
                continue
            try:
                file_result = ssh_exec(vm_name, f"cat {filepath}")
                if file_result.exit_code != 0:
                    logger.warning("Could not read %s", filepath)
                    continue
                parsed = safe_json_loads(
                    file_result.stdout,
                    source=filepath.rsplit("/", 1)[-1],
                )
                if parsed is None:
                    continue

                analyst_name = parsed.get("analyst", "unknown")
                analyst_number = parsed.get("analyst_number", 0)

                # Annotate each finding with the producing analyst
                for finding in parsed.get("findings", []):
                    if isinstance(finding, dict):
                        finding["source_analyst"] = analyst_name
                        finding["source_analyst_number"] = analyst_number
                        combined_findings.append(finding)

            except Exception:
                logger.warning("Failed to read %s", filepath, exc_info=True)

    except Exception:
        logger.warning("Failed to list analyst findings from VM", exc_info=True)
        return {"findings": []}

    return {"findings": combined_findings}


def run_adversarial_verification(
    vm_name: str,
    config: ScanConfig,
) -> None:
    """Run the adversarial verification agent.

    Reads analyst findings from /opt/scan-results/analyst-findings.json
    inside the VM, filters to high-risk (score >= 4), invokes Claude Code
    headless to attempt benign explanations, and writes merged results
    back to the VM.

    No structured findings data is returned to the host.

    Has NO access to scanner results -- only verifies the AI researcher's findings.

    Args:
        vm_name: Name of the Lima VM.
        config: Scan configuration.
    """
    ai_findings = _read_analyst_findings_from_vm(vm_name)
    high_risk = _extract_high_risk(ai_findings)

    if not high_risk:
        logger.info("No high-risk findings to verify — skipping adversarial agent")
        # Still write the report explaining why verification was skipped
        try:
            num_findings = len(ai_findings.get("findings", []))
            md = (
                "# AI Security Researcher — Adversarial Verification\n\n"
                f"**Status:** Skipped — no findings scored >= {RISK_THRESHOLD}/10\n\n"
                f"The analyst identified {num_findings} finding(s), but all scored "
                f"below the adversarial review threshold of {RISK_THRESHOLD}. "
                "No adversarial verification was needed.\n"
            )
            ssh_write_file(vm_name, md, "/opt/scan-results/adversarial-findings.md")
        except Exception:
            logger.warning("Failed to save adversarial skip report", exc_info=True)
        return

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
        return

    # Set up the stop hook to validate output schema before the agent
    # is allowed to finish. Uses the adversarial-specific schema validator.
    hook_settings = json.dumps({
        "hooks": {
            "Stop": [{
                "hooks": [{
                    "type": "command",
                    "command": "/opt/thresher/bin/validate_adversarial_output.sh",
                    "timeout": 30,
                }]
            }]
        }
    })
    try:
        ssh_exec(vm_name, f"mkdir -p {TARGET_DIR}/.claude")
        ssh_write_file(
            vm_name, hook_settings,
            f"{TARGET_DIR}/.claude/settings.local.json",
        )
    except Exception:
        logger.warning("Failed to write adversarial stop hook settings", exc_info=True)
        # Continue without the hook — output parsing will still handle both schemas

    model = config.model
    max_turns = config.adversarial_max_turns or 20
    claude_cmd = (
        f"cd {TARGET_DIR} && "
        f"claude -p \"$(cat /tmp/adversarial_prompt.txt)\" "
        f"--model {model} "
        f'--allowedTools "Read,Glob,Grep,WebSearch,WebFetch" '
        f"--output-format stream-json "
        f"--verbose "
        f"--max-turns {max_turns}"
    )

    # Write credentials to tmpfs and read-and-delete.
    env = config.ai_env()
    if env:
        exports = []
        for key, value in env.items():
            tmpfile = f"/dev/shm/.cred_{key}"
            ssh_exec(
                vm_name,
                "printf '%s' " + _shell_quote_key(value) + f" > {tmpfile}"
                f" && chmod 600 {tmpfile}",
            )
            exports.append(f"{key}=$(cat {tmpfile}); export {key}; rm -f {tmpfile}")
        claude_cmd = "; ".join(exports) + "; " + claude_cmd

    logger.info("Invoking adversarial agent in VM %s", vm_name)
    try:
        stdout, _stderr, _rc = ssh_exec(
            vm_name, claude_cmd, timeout=2400,
        )
        raw_output = stdout
    except Exception as exc:
        logger.error("Adversarial agent invocation failed: %s", exc)
        return

    verification = _parse_adversarial_output(raw_output)
    logger.info(
        "Adversarial verification completed: confirmed=%s, downgraded=%s",
        verification.get("confirmed_count", "?"),
        verification.get("downgraded_count", "?"),
    )

    merged = _merge_adversarial_results(ai_findings, verification)

    # Write merged findings JSON back into the VM for the synthesis agent.
    try:
        merged_json = json.dumps(merged, indent=2, default=str)
        ssh_write_file(vm_name, merged_json, "/opt/scan-results/adversarial-findings.json")
    except Exception:
        logger.warning("Failed to save adversarial findings JSON", exc_info=True)

    # Write adversarial findings as a readable markdown report
    try:
        md = _format_adversarial_markdown(verification, merged)
        ssh_write_file(vm_name, md, "/opt/scan-results/adversarial-findings.md")
    except Exception:
        logger.warning("Failed to save adversarial findings markdown", exc_info=True)


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
