"""Agent 2: Adversarial Verification.

Takes findings from the independent AI security researcher and attempts
to construct benign explanations. Findings that survive become confirmed;
findings that don't get downgraded. Has NO access to scanner results —
only verifies the AI researcher's findings.
"""

from __future__ import annotations

import logging
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

import yaml

from thresher.agents._json import extract_json_object
from thresher.agents._runner import AgentSpec, build_stop_hook_settings, run_agent
from thresher.config import ScanConfig

logger = logging.getLogger(__name__)


TARGET_DIR = "/opt/target"

_DEFINITION_PATH = Path(__file__).parent / "definitions" / "adversarial.yaml"


def _load_definition() -> dict[str, Any]:
    with open(_DEFINITION_PATH) as f:
        return yaml.safe_load(f)


_DEFINITION = _load_definition()
ADVERSARIAL_SYSTEM_PROMPT: str = _DEFINITION["prompt"]

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
    """Map a finding to a numeric risk score.

    Severity remains the primary source of truth for this branch's
    per-finding risk model. When severity is missing or invalid, fall back
    to an explicit integer ``risk_score`` if present so we can tolerate
    slightly different agent output shapes.
    """
    severity = finding.get("severity", "").lower()
    mapped = _SEVERITY_TO_RISK.get(severity)
    if mapped is not None:
        return mapped

    explicit = finding.get("risk_score")
    if isinstance(explicit, int):
        return explicit

    return 0


def _extract_high_risk(ai_findings: dict[str, Any]) -> list[dict[str, Any]]:
    """Pull findings at or above the adversarial-review risk threshold."""
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

        line_numbers = finding.get("line_numbers", [])
        if isinstance(line_numbers, list):
            line_numbers = sorted(ln for ln in line_numbers if isinstance(ln, int))
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

    return high_risk


def _normalize_title(title: str) -> str:
    """Normalize a finding title for dedup grouping: lowercase, collapse whitespace."""
    return re.sub(r"\s+", " ", title.lower().strip())


def _title_keyword_similarity(a: str, b: str) -> float:
    """Compute Jaccard similarity between keyword sets of two titles.

    Strips common English stop words to focus on meaningful terms.
    Returns a float between 0.0 and 1.0.
    """
    stop = {
        "a",
        "an",
        "the",
        "in",
        "on",
        "of",
        "for",
        "to",
        "and",
        "or",
        "is",
        "are",
        "was",
        "were",
        "with",
        "from",
        "by",
        "at",
        "it",
        "its",
        "this",
        "that",
    }
    words_a = {w for w in a.lower().split() if w not in stop and len(w) > 2}
    words_b = {w for w in b.lower().split() if w not in stop and len(w) > 2}
    if not words_a or not words_b:
        return 0.0
    intersection = words_a & words_b
    union = words_a | words_b
    return len(intersection) / len(union)


def _apply_verdict(finding: dict, verification_result: dict) -> None:
    """Apply adversarial verification verdict to a finding."""
    finding["adversarial_status"] = verification_result.get("verdict", "unknown")
    finding["adversarial_reasoning"] = verification_result.get("reasoning", "")
    finding["adversarial_confidence"] = verification_result.get("confidence", 0)
    finding["benign_explanation"] = verification_result.get("benign_explanation_attempted", "")
    revised = verification_result.get("revised_risk_score")
    if revised is not None:
        finding["original_risk_score"] = finding.get("risk_score", 0)
        finding["risk_score"] = int(revised)


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
        kept["source_analysts"] = sorted({f.get("source_analyst", "unknown") for f in group})
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
    has_verdicts = any(isinstance(f, dict) and "verdict" in f for f in findings)
    if not has_verdicts:
        return parsed

    logger.info(
        "Remapping analyst-forced schema to adversarial schema (%d findings with verdicts)",
        len(findings),
    )

    confirmed = sum(1 for f in findings if isinstance(f, dict) and f.get("verdict") == "confirmed")
    downgraded = sum(1 for f in findings if isinstance(f, dict) and f.get("verdict") == "downgraded")

    return {
        "results": findings,
        "verification_summary": parsed.get("summary", parsed.get("project_summary", "")),
        "total_reviewed": len(findings),
        "confirmed_count": confirmed,
        "downgraded_count": downgraded,
    }


def _parse_adversarial_output(text: str) -> dict[str, Any]:
    """Parse the adversarial JSON object from the agent's result text.

    Handles both the native adversarial schema (``results``) and the
    analyst-forced schema (``findings`` with verdict fields), normalizing
    the latter to the expected adversarial format.
    """
    if not text or not text.strip():
        logger.warning("Empty output from adversarial agent")
        return {"results": [], "error": "Agent returned empty output"}

    parsed = extract_json_object(text)
    if parsed is not None:
        return _normalize_adversarial_schema(parsed)

    logger.warning(
        "Could not parse adversarial output. Result (first 500 chars): %s",
        text[:500],
    )
    return {"results": [], "error": f"Parse failed. Result: {text[:500]}"}


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

    # --- Pass 1: exact matches and single-file fallback ---
    matched_results: set[int] = set()  # indices into `results` list
    matched_findings: set[int] = set()  # indices into findings_list

    for fi, finding in enumerate(findings_list):
        if not isinstance(finding, dict):
            continue
        fp = finding.get("file_path", "")
        title = _normalize_title(finding.get("title", ""))
        verification_result = results_by_key.get((fp, title))

        # Existing single-file fallback
        if not verification_result and fp:
            file_results = results_by_file.get(fp, [])
            file_findings = findings_by_file.get(fp, [])
            if len(file_results) == 1 and len(file_findings) == 1:
                verification_result = file_results[0]

        if verification_result:
            _apply_verdict(finding, verification_result)
            matched_findings.add(fi)
            # Track consumed result by index
            for ri, r in enumerate(results):
                if r is verification_result:
                    matched_results.add(ri)
                    break

    # --- Pass 2: fuzzy keyword matching for unmatched findings ---
    unconsumed = [(ri, r) for ri, r in enumerate(results) if ri not in matched_results and isinstance(r, dict)]

    for fi, finding in enumerate(findings_list):
        if fi in matched_findings or not isinstance(finding, dict):
            continue
        fp = finding.get("file_path", "")
        if not fp:
            continue

        best_score = 0.0
        best_ri = -1
        best_match = None
        for ri, candidate in unconsumed:
            if candidate.get("file_path", "") != fp:
                continue
            sim = _title_keyword_similarity(
                finding.get("title", ""),
                candidate.get("title", ""),
            )
            if sim > best_score:
                best_score = sim
                best_ri = ri
                best_match = candidate

        # Threshold 0.3: requires ~30% keyword overlap to match.
        # Low enough to catch paraphrasing, high enough to avoid false positives.
        if best_score >= 0.3 and best_match is not None:
            _apply_verdict(finding, best_match)
            matched_findings.add(fi)
            unconsumed = [(ri, r) for ri, r in unconsumed if ri != best_ri]

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

    logger.info("Starting adversarial verification of %d finding(s)", len(high_risk))

    try:
        hooks_json: str | None = build_stop_hook_settings("adversarial")
    except Exception:
        logger.warning("Failed to resolve adversarial hook settings", exc_info=True)
        hooks_json = None

    spec = AgentSpec(
        label="adversarial",
        prompt=_build_adversarial_prompt(high_risk),
        allowed_tools=list(_DEFINITION["tools"]),
        max_turns=config.adversarial_max_turns or _DEFINITION["max_turns"],
        timeout=2400,
        cwd=target_dir,
        hooks_settings_json=hooks_json,
    )

    logger.info("Invoking adversarial agent")
    start_time = time.monotonic()
    agent_result = run_agent(spec, config)
    duration = time.monotonic() - start_time
    if agent_result.failed:
        return None

    verification = _parse_adversarial_output(agent_result.result_text)
    logger.info(
        "Adversarial verification completed in %.1fs: confirmed=%s, downgraded=%s",
        duration,
        verification.get("confirmed_count", "?"),
        verification.get("downgraded_count", "?"),
    )

    merged = _merge_adversarial_results(ai_findings, verification)
    merged["_benchmark"] = {
        "duration": duration,
        "turns": agent_result.num_turns,
        "token_usage": agent_result.token_usage,
        "model_usage": agent_result.model_usage_by_model,
    }

    # Persist a human-readable adversarial-verification.md report next to
    # the main report. Without this the verification work is only visible
    # in scan logs.
    if output_dir:
        try:
            md_path = Path(output_dir) / "adversarial-verification.md"
            md_path.parent.mkdir(parents=True, exist_ok=True)
            md_path.write_text(_format_adversarial_markdown(verification, merged))
            logger.info("Adversarial verification markdown written to %s", md_path)
        except Exception:
            logger.warning(
                "Failed to write adversarial markdown report",
                exc_info=True,
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
