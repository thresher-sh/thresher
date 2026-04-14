"""Shared driver for running Claude Code agents in headless mode.

Each Thresher agent (predep, analyst, adversarial, report-maker,
synthesize) follows the same recipe:

1. Write the prompt and (optional) stop-hook settings to tempfiles.
2. Build a ``claude -p ... --model ... --allowedTools ... --output-format
   stream-json --max-turns ...`` command.
3. Merge ``config.ai_env()`` plus any agent-specific env vars into the
   subprocess environment.
4. Run the subprocess via ``thresher.run.run`` and decode the stream-JSON.
5. Pull the final result text and ``num_turns`` out of the stream.

This module owns that recipe so the per-agent files only have to declare
*what* they want, not *how* to launch a Claude Code subprocess.
"""

from __future__ import annotations

import json
import logging
import os
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path

from thresher.agents._json import extract_stream_result
from thresher.config import ScanConfig
from thresher.fs import tempfile_with
from thresher.run import run as run_cmd

logger = logging.getLogger(__name__)

_SHARED_HOOK = Path(__file__).parent / "hooks" / "_common" / "validate_json_output.sh"


def build_stop_hook_settings(schema_name: str) -> str:
    """Return Claude Code ``settings.json`` content for a stop hook.

    Points the hook at the shared ``validate_json_output.sh`` and passes
    *schema_name* as the dispatch argument. The script path is resolved
    to an absolute path so the hook fires regardless of cwd (important
    inside Docker).
    """
    if not _SHARED_HOOK.exists():
        raise FileNotFoundError(f"Hook script not found: {_SHARED_HOOK}")
    settings = {
        "hooks": {
            "Stop": [
                {
                    "hooks": [
                        {
                            "type": "command",
                            "command": f"{_SHARED_HOOK.resolve()} {schema_name}",
                            "timeout": 15,
                        }
                    ]
                }
            ]
        }
    }
    return json.dumps(settings)


@dataclass
class AgentSpec:
    """Declarative description of a Claude Code agent invocation."""

    label: str
    prompt: str
    allowed_tools: list[str]
    max_turns: int
    timeout: int = 3600
    cwd: str | None = None
    hooks_settings_json: str | None = None
    extra_env: dict[str, str] = field(default_factory=dict)


@dataclass
class AgentResult:
    """Outcome of a single agent run."""

    result_text: str
    num_turns: int
    returncode: int
    failed: bool = False
    error: str | None = None
    token_usage: dict[str, int] = field(default_factory=dict)
    model_usage_by_model: dict[str, dict[str, int]] = field(default_factory=dict)


def run_agent(spec: AgentSpec, config: ScanConfig) -> AgentResult:
    """Launch a Claude Code agent and return its parsed result.

    Wraps prompt + settings tempfile management, command assembly, env
    merging, subprocess invocation, and stream-JSON extraction. Any
    failure — tempfile write error, subprocess crash, decode error —
    is caught and surfaced as ``AgentResult(failed=True)``, so callers
    don't need their own try/except.
    """
    env = os.environ.copy()
    env.update(config.ai_env())
    env.update(spec.extra_env)

    try:
        with ExitStack() as stack:
            prompt_path = stack.enter_context(
                tempfile_with(spec.prompt, suffix=f"_{spec.label}_prompt.txt"),
            )
            cmd: list[str] = [
                "claude",
                "-p",
                str(prompt_path),
                "--model",
                config.model,
                "--allowedTools",
                ",".join(spec.allowed_tools),
                "--output-format",
                "stream-json",
                "--verbose",
                "--max-turns",
                str(spec.max_turns),
            ]
            if spec.hooks_settings_json is not None:
                settings_path = stack.enter_context(
                    tempfile_with(
                        spec.hooks_settings_json,
                        suffix=f"_{spec.label}_hooks.json",
                    ),
                )
                cmd.extend(["--settings", str(settings_path)])

            proc = run_cmd(
                cmd,
                label=spec.label,
                env=env,
                timeout=spec.timeout,
                cwd=spec.cwd,
            )
            raw_output = proc.stdout.decode(errors="replace")
    except Exception as exc:
        logger.error("Agent %s invocation failed: %s", spec.label, exc)
        return AgentResult(
            result_text="",
            num_turns=0,
            returncode=-1,
            failed=True,
            error=str(exc),
        )

    stream_result = extract_stream_result(raw_output)
    return AgentResult(
        result_text=stream_result.text,
        num_turns=stream_result.num_turns,
        returncode=proc.returncode,
        token_usage=stream_result.token_usage,
        model_usage_by_model=stream_result.model_usage_by_model,
    )
