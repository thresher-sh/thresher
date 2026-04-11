"""Report Synthesis agent — merges scanner and AI findings into final reports.

Invokes Claude Code headless to produce executive-summary.md,
detailed-report.md, and synthesis-findings.md from enriched findings.
"""

from __future__ import annotations

import logging
import os
import tempfile
from pathlib import Path
from typing import Any

import yaml

from thresher.config import ScanConfig
from thresher.run import run as run_cmd

logger = logging.getLogger(__name__)

_DEFINITION_PATH = Path(__file__).parent / "definitions" / "report" / "synthesize.yaml"


def _load_definition() -> dict[str, Any]:
    """Load the synthesize YAML definition."""
    with open(_DEFINITION_PATH) as f:
        return yaml.safe_load(f)


def _write_file(path: str, content: str) -> None:
    """Write content to a local file."""
    dir_path = os.path.dirname(path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _build_synthesis_prompt(report_dir: str, input_path: str) -> str:
    """Build the prompt for the Claude synthesis agent."""
    return (
        "You are a security report synthesis agent. You have been given the complete "
        "output from two independent analysis tracks:\n\n"
        "1. **Deterministic scanner findings** — normalized results from automated "
        "tools (SCA, SAST, IaC scanning, secrets detection, malware scanning, "
        "license compliance)\n"
        "2. **Independent AI security investigation** — structured results from an "
        "AI security researcher who explored the codebase looking for supply chain "
        "attacks, malicious code, and dangerous dependencies\n"
        "3. **Adversarial verification results** — confirmed/downgraded status for "
        "the AI researcher's findings\n\n"
        "Your job is to merge everything into a single, coherent, actionable "
        "security report.\n\n"
        f"Read the synthesis input at {input_path}. It contains all enriched "
        "findings with EPSS scores, CISA KEV status, and composite priority "
        "levels.\n\n"
        "## Workflow\n\n"
        "1. **Merge all findings** from all sources into a unified view.\n\n"
        "2. **De-duplicate**: When the same issue is reported by both scanners and "
        "the AI researcher:\n"
        "   - Same CVE from multiple scanners: keep one entry, note all sources\n"
        "   - Same suspicious pattern from scanner and AI: keep one entry with "
        "combined confidence, note both sources\n"
        "   - When merging, prefer the entry with the most detail/context\n\n"
        "3. **Assign composite priority** using all available signals:\n"
        "   - **P0 / Emergency**: In CISA KEV (actively exploited), OR "
        "AI-confirmed exfiltration/backdoor with high confidence\n"
        "   - **Critical**: CVSS >= 9.0, OR EPSS > 90th percentile, OR AI risk "
        "9-10 confirmed\n"
        "   - **High**: CVSS 7.0-8.9, OR EPSS > 75th percentile, OR AI risk 7-8 "
        "confirmed\n"
        "   - **Medium**: CVSS 4.0-6.9, OR EPSS > 50th percentile, OR AI risk 4-6\n"
        "   - **Low**: Everything else\n\n"
        "   When scanners and AI agree, boost confidence. When they disagree, "
        "present both perspectives and flag the disagreement.\n\n"
        "## Output Files\n\n"
        f"1. **{report_dir}/executive-summary.md** — Concise executive summary:\n"
        "   - One-paragraph overall assessment\n"
        "   - GO / CAUTION / DO NOT USE recommendation:\n"
        "     * Any P0 or Critical finding → **DO NOT USE**\n"
        "     * High findings only → **USE WITH CAUTION** (list required mitigations)\n"
        "     * Medium and below only → **ACCEPTABLE RISK**\n"
        "   - Top 10 findings table (priority, title, source tool, CVE, CVSS)\n"
        "   - Total finding counts by priority level\n"
        "   - SBOM summary\n\n"
        f"2. **{report_dir}/detailed-report.md** — Full detailed report:\n"
        "   - Every finding, grouped by priority (P0 first, then Critical, High, "
        "Medium, Low)\n"
        "   - Each finding: title, description, source tool(s), CVE/CWE IDs, CVSS "
        "score, EPSS percentile, KEV status, AI risk score, adversarial status, "
        "file path, line numbers, remediation guidance\n"
        "   - Section on agreements/disagreements between scanner and AI findings\n"
        "   - Dependency risk summary from SBOM analysis\n"
        "   - Appendix with scanner execution summary\n\n"
        f"3. **{report_dir}/synthesis-findings.md** — Your own synthesis analysis:\n"
        "   - How you merged and prioritized findings from scanners and AI\n"
        "   - Key agreements and disagreements between the two tracks\n"
        "   - Your reasoning for the overall recommendation\n"
        "   - Any findings you elevated or downgraded during synthesis and why\n\n"
        f"4. **{report_dir}/findings.json** already exists — do not overwrite it.\n\n"
        "## Rules\n\n"
        "- Never omit a finding. Every finding from every source must appear.\n"
        "- Clearly attribute each finding to its source(s).\n"
        "- The executive summary must give a clear, unambiguous recommendation.\n"
        "- When in doubt about priority, err on the side of higher severity.\n"
        "- The detailed report should be readable by someone who has not seen the "
        "raw data.\n"
        "- Write clear, professional prose. Use markdown tables where appropriate. "
        "Be specific about remediation steps."
    )


def run_synthesize_agent(
    config: ScanConfig,
    report_dir: str,
    synthesis_input: str,
) -> bool:
    """Run the synthesis agent to generate report markdown files.

    Writes the synthesis input to the report directory, builds the prompt,
    and invokes Claude Code headless to generate the report files.

    Args:
        config: Scan configuration.
        report_dir: Directory where report files will be written.
        synthesis_input: Markdown-formatted synthesis input text.

    Returns:
        True if the agent produced the expected output files.
    """
    definition = _load_definition()
    tools = ",".join(definition["tools"])
    max_turns = getattr(config, "synthesize_max_turns", None) or definition["max_turns"]

    # Write synthesis input to report directory
    input_path = f"{report_dir}/synthesis_input.md"
    _write_file(input_path, synthesis_input)

    # Build and write prompt
    synthesis_prompt = _build_synthesis_prompt(report_dir, input_path)
    prompt_path = Path(tempfile.mktemp(suffix="_synthesis_prompt.txt"))

    try:
        prompt_path.write_text(synthesis_prompt)

        model = config.model
        cmd = [
            "claude",
            "-p", str(prompt_path),
            "--model", model,
            "--allowedTools", tools,
            "--output-format", "stream-json",
            "--verbose",
            "--max-turns", str(max_turns),
        ]

        env = os.environ.copy()
        ai_env = config.ai_env()
        env.update(ai_env)

        logger.info("Invoking synthesis agent (max_turns=%d)", max_turns)
        try:
            result = run_cmd(
                cmd,
                label="synthesize",
                cwd=report_dir,
                env=env,
                timeout=1800,
            )
            exit_code = result.returncode
        except Exception as exc:
            logger.warning("Synthesis agent failed: %s", exc)
            exit_code = 1

        logger.info("Synthesis agent completed: exit_code=%d", exit_code)

        # Verify expected output files exist
        agent_succeeded = (
            os.path.isfile(f"{report_dir}/executive-summary.md")
            and os.path.isfile(f"{report_dir}/detailed-report.md")
        )

        if agent_succeeded:
            logger.info("Synthesis agent produced expected report files")
        else:
            logger.warning("Synthesis agent did not produce expected files")

        return agent_succeeded

    finally:
        try:
            prompt_path.unlink(missing_ok=True)
        except Exception:
            pass
