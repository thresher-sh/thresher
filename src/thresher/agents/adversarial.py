"""Agent 2: Adversarial Verification.

Takes findings from the independent AI security researcher and attempts
to construct benign explanations. Findings that survive become confirmed;
findings that don't get downgraded. Has NO access to scanner results —
only verifies the AI researcher's findings.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any

from thresher.run import run as run_cmd

from thresher.agents.prompts import ADVERSARIAL_SYSTEM_PROMPT
from thresher.config import ScanConfig

logger = logging.getLogger(__name__)


TARGET_DIR = "/opt/target"
_HOOKS_DIR = Path(__file__).parent / "hooks" / "adversarial"

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


def _normalize_title(title: str) -> str:
    """Normalize a finding title for dedup grouping: lowercase, collapse whitespace."""
    return re.sub(r"\s+", " ", title.lower().strip())


def _deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate findings by (file_path, normalized title).

    For each group of duplicates, keeps the finding with the highest
    risk_score (ties broken by confidence). Annotates each kept finding
    with ``duplicate_count`` and ``source_analysts``.

    Returns a new list; does not mutate the input.
    """
    if not findings:
        return []

    # Group by (file_path, title_normalized)
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        key = (
            finding.get("file_path", "N/A"),
            _normalize_title(finding.get("title", "")),
        )
        groups[key].append(finding)

    deduped: list[dict[str, Any]] = []
    for _key, group in groups.items():
        # Sort by risk_score desc, then confidence desc (from source_analyst finding)
        best = max(
            group,
            key=lambda f: (f.get("risk_score", 0), f.get("confidence", 0)),
        )
        # Shallow copy to avoid mutating the original dict's top-level keys
        kept = dict(best)
        kept["duplicate_count"] = len(group)
        kept["source_analysts"] = sorted(
            {f.get("source_analyst", "unknown") for f in group}
        )
        deduped.append(kept)

    return deduped


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

        dup_count = finding.get("duplicate_count", 1)
        source_analysts = finding.get("source_analysts", [])
        if dup_count > 1 and source_analysts:
            lines.append(
                f"- **Independent reports**: This finding was independently "
                f"reported by {dup_count} analysts "
                f"({', '.join(source_analysts)}), increasing confidence."
            )

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

    # Build lookup by (file_path, normalized_title) for robust matching.
    # The adversarial agent may paraphrase or truncate titles.
    results_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    results_by_file: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for result in results:
        if isinstance(result, dict):
            fp = result.get("file_path", "")
            title = _normalize_title(result.get("title", ""))
            if fp:
                results_by_key[(fp, title)] = result
                results_by_file[fp].append(result)

    findings_list = updated_findings.get("findings", [])

    # Count findings per file_path for fallback matching
    findings_by_file: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings_list:
        if isinstance(finding, dict):
            findings_by_file[finding.get("file_path", "")].append(finding)

    for finding in findings_list:
        if not isinstance(finding, dict):
            continue
        fp = finding.get("file_path", "")
        title = _normalize_title(finding.get("title", ""))
        verification_result = results_by_key.get((fp, title))

        # Fallback: if there's exactly one finding and one result for this
        # file_path, match them even if titles diverged
        if not verification_result and fp:
            file_results = results_by_file.get(fp, [])
            file_findings = findings_by_file.get(fp, [])
            if len(file_results) == 1 and len(file_findings) == 1:
                verification_result = file_results[0]

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

    # Tag unreviewed findings so downstream code can distinguish "not reviewed"
    # from "reviewed but unmatched"
    for finding in findings_list:
        if isinstance(finding, dict) and "adversarial_status" not in finding:
            finding["adversarial_status"] = "not_reviewed"

    updated_findings["adversarial_verification"] = {
        "summary": verification.get("verification_summary", ""),
        "total_reviewed": verification.get("total_reviewed", 0),
        "confirmed_count": verification.get("confirmed_count", 0),
        "downgraded_count": verification.get("downgraded_count", 0),
    }

    return updated_findings


def _merge_analyst_findings(analyst_findings_list: list[dict[str, Any]]) -> dict[str, Any]:
    """Merge a list of per-analyst findings dicts into a combined structure.

    Each finding is annotated with which analyst produced it.
    """
    combined_findings: list[dict[str, Any]] = []

    for analyst_result in analyst_findings_list:
        if not isinstance(analyst_result, dict):
            continue
        analyst_name = analyst_result.get("analyst", "unknown")
        analyst_number = analyst_result.get("analyst_number", 0)

        for finding in analyst_result.get("findings", []):
            if isinstance(finding, dict):
                finding = dict(finding)  # shallow copy
                finding["source_analyst"] = analyst_name
                finding["source_analyst_number"] = analyst_number
                combined_findings.append(finding)

    return {"findings": combined_findings}


def _resolve_hooks_settings() -> Path:
    """Write a temporary settings.json with absolute path to the hook script.

    Resolves the hook script path to an absolute path so the hook works
    regardless of cwd (important inside Docker).
    """
    hook_script = _HOOKS_DIR / "validate_json_output.sh"
    if not hook_script.exists():
        raise FileNotFoundError(f"Hook script not found: {hook_script}")

    settings = {
        "hooks": {
            "Stop": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": str(hook_script.resolve()),
                            "timeout": 15,
                        }
                    ]
                }
            ]
        }
    }
    settings_path = Path(tempfile.mktemp(suffix="_adversarial_hooks_settings.json"))
    settings_path.write_text(json.dumps(settings))
    return settings_path


def run_adversarial_verification(
    config: ScanConfig,
    analyst_findings: list[dict[str, Any]] | None = None,
    target_dir: str = TARGET_DIR,
    *,
    output_dir: str | None = None,
) -> dict[str, Any] | None:
    """Run the adversarial verification agent.

    Accepts analyst findings directly (from run_all_analysts), filters to
    high-risk (score >= 4), invokes Claude Code headless to attempt benign
    explanations, and returns merged results.

    Args:
        config: Scan configuration.
        analyst_findings: List of per-analyst findings dicts from run_all_analysts.
                          If None or empty, returns None (no verification needed).
        target_dir: Directory to run the agent in.

    Returns:
        Merged findings dict with adversarial verification, or None if skipped.
    """
    if analyst_findings is None:
        analyst_findings = []

    # Merge per-analyst findings into a combined structure
    ai_findings = _merge_analyst_findings(analyst_findings)

    high_risk = _extract_high_risk(ai_findings)

    # Deduplicate before adversarial review to avoid re-verifying the same
    # finding reported by multiple analysts.
    original_count = len(high_risk)
    high_risk = _deduplicate_findings(high_risk)
    deduped_count = len(high_risk)
    if original_count != deduped_count:
        logger.info(
            "Deduplicated %d findings to %d unique (%d duplicates removed)",
            original_count,
            deduped_count,
            original_count - deduped_count,
        )

    if not high_risk:
        logger.info("No high-risk findings to verify — skipping adversarial agent")
        return None

    logger.info(
        "Starting adversarial verification of %d finding(s)", len(high_risk)
    )

    prompt = _build_adversarial_prompt(high_risk)

    prompt_path = Path(tempfile.mktemp(suffix="_adversarial_prompt.txt"))
    settings_path = None
    try:
        prompt_path.write_text(prompt)
    except Exception:
        logger.warning("Failed to write adversarial prompt file", exc_info=True)
        return None

    try:
        settings_path = _resolve_hooks_settings()
    except Exception:
        logger.warning("Failed to resolve adversarial hook settings", exc_info=True)

    model = config.model
    max_turns = config.adversarial_max_turns or 20
    cmd = [
        "claude",
        "-p", str(prompt_path),
        "--model", model,
        "--allowedTools", "Read,Glob,Grep,WebSearch,WebFetch",
        "--output-format", "stream-json",
        "--verbose",
        "--max-turns", str(max_turns),
    ]
    if settings_path is not None:
        cmd.extend(["--settings", str(settings_path)])

    env = os.environ.copy()
    ai_env = config.ai_env()
    env.update(ai_env)

    logger.info("Invoking adversarial agent")
    try:
        proc = run_cmd(
            cmd,
            label="adversarial",
            env=env,
            timeout=2400,
            cwd=target_dir,
        )
        raw_output = proc.stdout.decode(errors="replace")
    except Exception as exc:
        logger.error("Adversarial agent invocation failed: %s", exc)
        return None
    finally:
        try:
            prompt_path.unlink(missing_ok=True)
        except Exception:
            pass
        if settings_path is not None:
            try:
                settings_path.unlink(missing_ok=True)
            except Exception:
                pass

    verification = _parse_adversarial_output(raw_output)
    logger.info(
        "Adversarial verification completed: confirmed=%s, downgraded=%s",
        verification.get("confirmed_count", "?"),
        verification.get("downgraded_count", "?"),
    )

    merged = _merge_adversarial_results(ai_findings, verification)

    # Persist a human-readable adversarial-verification.md report next to
    # the main report. Without this the verification work is only visible
    # in scan logs.
    if output_dir:
        try:
            md_path = Path(output_dir) / "adversarial-verification.md"
            md_path.parent.mkdir(parents=True, exist_ok=True)
            md_path.write_text(
                _format_adversarial_markdown(verification, merged)
            )
            logger.info("Adversarial verification markdown written to %s", md_path)
        except Exception:
            logger.warning(
                "Failed to write adversarial markdown report", exc_info=True,
            )

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
