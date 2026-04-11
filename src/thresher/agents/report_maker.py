"""Report Maker agent — transforms scan findings into structured report data.

Invokes Claude Code headless with a stop hook that validates output against
the report JSON Schema. The agent reads scan results and produces a single
JSON object suitable for rendering into the HTML report template.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import yaml

from thresher.agents._json import extract_json_object
from thresher.agents._runner import AgentSpec, run_agent
from thresher.config import ScanConfig

logger = logging.getLogger(__name__)

_DEFINITION_PATH = Path(__file__).parent / "definitions" / "report" / "report_maker.yaml"
_HOOKS_DIR = Path(__file__).parent / "hooks" / "report"


def _resolve_schema_path() -> str:
    """Find the report_schema.json file across known locations.

    The hook script reads ``REPORT_SCHEMA_PATH`` from its environment;
    we resolve to the first existing file so the hook never has to guess.
    """
    candidates = [
        Path("/opt/templates/report/report_schema.json"),
        Path(__file__).parent.parent.parent.parent / "templates" / "report" / "report_schema.json",
    ]
    for c in candidates:
        if c.is_file():
            return str(c.resolve())
    # Fall back to the project-root path; the hook will surface the error.
    return str(candidates[-1])


def _load_definition() -> dict[str, Any]:
    """Load the report_maker YAML definition."""
    with open(_DEFINITION_PATH) as f:
        return yaml.safe_load(f)


def _build_hooks_settings_json() -> str:
    """Return the settings.json content for the report-maker stop hook.

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
    return json.dumps(settings)


def _parse_report_output(text: str) -> dict[str, Any] | None:
    """Parse the report JSON object from the agent's result text."""
    if not text or not text.strip():
        logger.warning("Empty output from report maker agent")
        return None

    parsed = extract_json_object(text)
    if parsed is not None:
        return parsed

    logger.warning(
        "Could not parse report maker output. Result (first 500 chars): %s", text[:500],
    )
    return None


def run_report_maker(
    config: ScanConfig,
    output_dir: str,
    *,
    target_dir: str | None = None,
) -> dict[str, Any] | None:
    """Run the report maker agent to format the scan into structured JSON.

    The agent runs as the LAST step in the pipeline. By that point the
    output directory contains every artifact the report needs to consume:

      - executive-summary.md, detailed-report.md, synthesis-findings.md
        (written by the synthesize agent — the "judge")
      - adversarial-verification.md
      - findings.json
      - scan-results/analyst-NN-*.json + analyst-NN-*.md
      - scan-results/<scanner>.json (22 of them)
      - scan-results/dep_resolution.json

    The agent's job is to read those files and produce the structured
    JSON that the HTML template renders. A stop hook validates the
    output against the schema before accepting it.

    Args:
        config: Scan configuration.
        output_dir: Report output directory — used as the agent's cwd
            so all the artifacts above are reachable via relative paths.
        target_dir: (Deprecated) historical override; if not provided,
            defaults to ``output_dir``.

    Returns:
        Parsed report data dict, or None on failure.
    """
    if target_dir is None:
        target_dir = output_dir
    definition = _load_definition()
    max_turns = (
        getattr(config, "report_maker_max_turns", None) or definition["max_turns"]
    )

    try:
        hooks_json = _build_hooks_settings_json()
    except Exception as exc:
        logger.error("Report maker agent failed to resolve hook settings: %s", exc)
        return None

    spec = AgentSpec(
        label="report-maker",
        prompt=definition["prompt"],
        allowed_tools=definition["tools"],
        max_turns=max_turns,
        timeout=3600,
        cwd=target_dir,
        hooks_settings_json=hooks_json,
        # Pin the absolute schema path so the validate hook never has to
        # guess (the relative default broke when cwd != project root).
        extra_env={"REPORT_SCHEMA_PATH": _resolve_schema_path()},
    )

    logger.info("Invoking report maker agent (max_turns=%d)", max_turns)
    agent_result = run_agent(spec, config)
    if agent_result.failed:
        return None

    result = _parse_report_output(agent_result.result_text)
    if result is not None:
        logger.info("Report maker agent completed successfully")
    else:
        logger.warning("Report maker agent produced unparseable output")
    return result
