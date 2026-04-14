"""Stage 1: Pre-Dependency Discovery Agent.

Runs AFTER source clone but BEFORE dependency resolution. Scans the
source code to discover hidden dependency sources that standard ecosystem
indicators (package.json, requirements.txt, etc.) don't capture:

- Git clones in Makefiles, shell scripts, Dockerfiles, CI configs
- Git submodule references in .gitmodules
- curl/wget downloads of tarballs or binaries
- Docker base images that pull additional code
- go install / pip install commands in scripts
- Vendored repos referenced by URL

Outputs a structured dict with discovered hidden dependencies.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

import yaml

from thresher.agents._json import extract_json_object
from thresher.agents._runner import AgentSpec, build_stop_hook_settings, run_agent
from thresher.config import ScanConfig

logger = logging.getLogger(__name__)

TARGET_DIR = "/opt/target"
OUTPUT_PATH = "/opt/thresher/work/deps/hidden_deps.json"

_DEFINITION_PATH = Path(__file__).parent / "definitions" / "predep.yaml"


def _load_definition() -> dict[str, Any]:
    with open(_DEFINITION_PATH) as f:
        return yaml.safe_load(f)


_DEFINITION = _load_definition()
PREDEP_PROMPT: str = _DEFINITION["prompt"]


def run_predep_discovery(
    config: ScanConfig,
    target_dir: str = TARGET_DIR,
) -> dict[str, Any]:
    """Run the pre-dependency discovery agent locally via subprocess.

    Scans the cloned source for hidden dependency sources and returns
    the results as a dict. A stop hook validates the output against the
    hidden_dependencies schema before accepting it.
    """
    try:
        hooks_json: str | None = build_stop_hook_settings("predep")
    except Exception:
        logger.warning("Failed to resolve predep hook settings", exc_info=True)
        # Continue without the hook — output validation still happens
        # in _parse_predep_output, just without retry.
        hooks_json = None

    logger.info("Running pre-dependency discovery agent")
    start_time = time.monotonic()
    spec = AgentSpec(
        label="predep",
        prompt=_DEFINITION["prompt"],
        allowed_tools=list(_DEFINITION["tools"]),
        max_turns=config.predep_max_turns or _DEFINITION["max_turns"],
        timeout=600,
        cwd=target_dir,
        hooks_settings_json=hooks_json,
    )
    agent_result = run_agent(spec, config)
    duration = time.monotonic() - start_time
    if agent_result.failed:
        return _empty_result(f"Agent invocation failed: {agent_result.error}")

    result = _parse_predep_output(agent_result.result_text)
    result["_benchmark"] = {
        "duration": duration,
        "turns": agent_result.num_turns,
        "token_usage": agent_result.token_usage,
        "model_usage": agent_result.model_usage_by_model,
    }

    # Inject the high_risk_dep flag so downstream can know whether
    # to download high-risk entries.
    result["high_risk_dep"] = config.high_risk_dep

    deps = result.get("hidden_dependencies", [])
    high_risk = [d for d in deps if d.get("risk") == "high"]
    logger.info(
        "Pre-dep discovery complete: %d hidden dependencies found (%d high-risk, %s)",
        len(deps),
        len(high_risk),
        "will download" if config.high_risk_dep else "will skip download",
    )

    return result


def _parse_predep_output(text: str) -> dict[str, Any]:
    """Extract the predep JSON object from the agent's result text."""
    parsed = extract_json_object(
        text,
        accept=lambda d: "hidden_dependencies" in d,
    )
    if parsed is not None:
        return parsed

    preview = text[:500] if text else "(empty)"
    logger.warning(
        "Could not parse predep agent output. Result (first 500 chars): %s",
        preview,
    )
    return _empty_result("Failed to parse agent output")


def _empty_result(reason: str) -> dict[str, Any]:
    """Return an empty result structure."""
    return {
        "hidden_dependencies": [],
        "files_scanned": 0,
        "summary": reason,
    }
