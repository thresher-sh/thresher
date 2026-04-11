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

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

from thresher.run import run as run_cmd

from thresher.config import ScanConfig

logger = logging.getLogger(__name__)

TARGET_DIR = "/opt/target"
_HOOKS_DIR = Path(__file__).parent / "hooks" / "predep"
OUTPUT_PATH = "/opt/thresher/work/deps/hidden_deps.json"

PREDEP_PROMPT = """\
You are a dependency discovery agent. Your job is to scan a source code \
repository and find ALL dependency sources that would NOT be detected by \
standard package manager indicator files (package.json, requirements.txt, \
Cargo.toml, go.mod, pyproject.toml, setup.py, Pipfile).

Scan the repository thoroughly. Look at:
- Makefiles, Rakefiles, Justfiles, Taskfiles
- Shell scripts (.sh, .bash)
- Dockerfiles and docker-compose files
- CI/CD configs (.github/workflows/, .gitlab-ci.yml, Jenkinsfile, .circleci/)
- .gitmodules (git submodule references)
- Build scripts (build.sh, build.py, build.rs beyond normal cargo)
- Install scripts
- Any file that references external code sources

For each hidden dependency you find, classify it:

Types:
- "git" — a git clone/checkout of an external repository
- "npm" — an npm install/add of a package not in package.json
- "pypi" — a pip install of a package not in requirements/pyproject
- "cargo" — a cargo install not in Cargo.toml
- "go" — a go install/get not in go.mod
- "url" — a curl/wget/fetch of a tarball, binary, or script
- "docker" — a Docker base image that may contain relevant dependencies
- "submodule" — a git submodule reference

Your output MUST be a single JSON object with this exact structure:
```json
{
  "hidden_dependencies": [
    {
      "type": "git",
      "source": "https://github.com/example/repo.git",
      "found_in": "Makefile:42",
      "context": "Cloned during build step to vendor a parser library",
      "confidence": "high",
      "risk": "low"
    },
    {
      "type": "url",
      "source": "https://example.com/tool-v1.2.tar.gz",
      "found_in": "scripts/setup.sh:17",
      "context": "Downloads and extracts a precompiled binary",
      "confidence": "medium",
      "risk": "high"
    }
  ],
  "files_scanned": 42,
  "summary": "Brief description of what you found"
}
```

Rules:
- confidence is "high", "medium", or "low" (how sure you are this is a real dependency)
- risk is "high", "medium", or "low" — classify based on download risk:
  - "high": precompiled binaries, tarballs from non-package-registry URLs, \
executable downloads, curl-piped-to-bash patterns, unknown/suspicious domains
  - "medium": git clones from non-major-hosting platforms, Docker images from \
third-party registries
  - "low": git clones from GitHub/GitLab/Bitbucket, standard package manager \
installs, well-known CDN URLs
- If you find NO hidden dependencies, return an empty list: "hidden_dependencies": []
- Do NOT include dependencies that ARE in standard package files (package.json, requirements.txt, etc.)
- DO include git submodules (.gitmodules entries)
- DO include Docker FROM images if they reference non-standard base images
- DO include any URL that downloads code, libraries, or tools
- Be thorough — check EVERY file type listed above
- Output ONLY the JSON object, nothing else
"""


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
    settings_path = Path(tempfile.mktemp(suffix="_predep_hooks_settings.json"))
    settings_path.write_text(json.dumps(settings))
    return settings_path


def run_predep_discovery(
    config: ScanConfig,
    target_dir: str = TARGET_DIR,
) -> dict[str, Any]:
    """Run the pre-dependency discovery agent locally via subprocess.

    Scans the cloned source for hidden dependency sources and returns
    the results as a dict. A stop hook validates the output against the
    hidden_dependencies schema before accepting it.

    Args:
        config: Scan configuration.
        target_dir: Directory to scan (passed as cwd to claude).

    Returns:
        Dict with discovered hidden dependencies.
    """
    prompt_path = Path(tempfile.mktemp(suffix="_predep_prompt.txt"))
    settings_path = None
    try:
        prompt_path.write_text(PREDEP_PROMPT)
    except Exception:
        logger.warning("Failed to write predep prompt", exc_info=True)
        return _empty_result("Failed to write prompt file")

    try:
        settings_path = _resolve_hooks_settings()
    except Exception:
        logger.warning("Failed to resolve predep hook settings", exc_info=True)
        # Continue without the hook — output validation will still
        # happen in _parse_predep_output, just without retry

    model = config.model
    max_turns = config.predep_max_turns or 15
    cmd = [
        "claude",
        "-p", str(prompt_path),
        "--model", model,
        "--allowedTools", "Read,Glob,Grep",
        "--output-format", "stream-json",
        "--verbose",
        "--max-turns", str(max_turns),
    ]
    if settings_path is not None:
        cmd.extend(["--settings", str(settings_path)])

    env = os.environ.copy()
    ai_env = config.ai_env()
    env.update(ai_env)

    logger.info("Running pre-dependency discovery agent")
    try:
        proc = run_cmd(
            cmd,
            label="predep",
            env=env,
            timeout=600,
            cwd=target_dir,
        )
        stdout = proc.stdout.decode(errors="replace")
    except Exception as exc:
        logger.error("Pre-dep discovery agent failed: %s", exc)
        return _empty_result(f"Agent invocation failed: {exc}")
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

    result = _parse_predep_output(stdout)

    # Inject the high_risk_dep flag so downstream can know whether
    # to download high-risk entries
    result["high_risk_dep"] = config.high_risk_dep

    # Log summary with risk breakdown
    deps = result.get("hidden_dependencies", [])
    high_risk = [d for d in deps if d.get("risk") == "high"]
    logger.info(
        "Pre-dep discovery complete: %d hidden dependencies found "
        "(%d high-risk, %s)",
        len(deps),
        len(high_risk),
        "will download" if config.high_risk_dep else "will skip download",
    )

    return result


def _strip_markdown_fences(text: str) -> str:
    """Strip ``` / ```json markdown fences from a string, if present.

    Claude often wraps structured output in fenced code blocks even when
    asked not to. This returns the inner content unchanged if no fences
    are found.
    """
    import re
    if not isinstance(text, str):
        return text
    stripped = text.strip()
    fence_match = re.match(
        r"^```(?:json)?\s*\n(.*?)\n```\s*$",
        stripped,
        re.DOTALL,
    )
    if fence_match:
        return fence_match.group(1)
    return text


def _parse_predep_output(raw_output: str) -> dict[str, Any]:
    """Parse the agent's stream-json output to extract the JSON result.

    Uses the same extraction strategies as the analyst agent:
    stream-json result field, markdown code blocks, bare JSON.
    """
    # Try stream-json format first (look for {"type":"result",...} lines)
    for line in raw_output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                # stream-json wraps in {"type":"result","result":"..."}
                if obj.get("type") == "result" and "result" in obj:
                    inner = obj["result"]
                    if isinstance(inner, str):
                        # Claude may wrap the JSON in ```json fences even
                        # when asked not to — strip them first.
                        inner_stripped = _strip_markdown_fences(inner)
                        try:
                            parsed = json.loads(inner_stripped)
                            if isinstance(parsed, dict) and "hidden_dependencies" in parsed:
                                return parsed
                        except (json.JSONDecodeError, TypeError):
                            pass
                    elif isinstance(inner, dict) and "hidden_dependencies" in inner:
                        return inner
                # Direct JSON object with our expected key
                if "hidden_dependencies" in obj:
                    return obj
        except (json.JSONDecodeError, TypeError):
            continue

    # Try extracting from markdown code block
    import re
    code_block = re.search(r"```(?:json)?\s*\n(.*?)\n```", raw_output, re.DOTALL)
    if code_block:
        try:
            parsed = json.loads(code_block.group(1))
            if isinstance(parsed, dict) and "hidden_dependencies" in parsed:
                return parsed
        except (json.JSONDecodeError, TypeError):
            pass

    # Try finding any JSON object with our key
    brace_start = raw_output.find("{")
    if brace_start >= 0:
        # Find matching closing brace
        depth = 0
        for i in range(brace_start, len(raw_output)):
            if raw_output[i] == "{":
                depth += 1
            elif raw_output[i] == "}":
                depth -= 1
                if depth == 0:
                    candidate = raw_output[brace_start : i + 1]
                    try:
                        parsed = json.loads(candidate)
                        if isinstance(parsed, dict) and "hidden_dependencies" in parsed:
                            return parsed
                    except (json.JSONDecodeError, TypeError):
                        pass
                    break

    preview = raw_output[:500] if raw_output else "(empty)"
    logger.warning("Could not parse predep agent output. Raw (first 500 chars): %s", preview)
    return _empty_result("Failed to parse agent output")


def _empty_result(reason: str) -> dict[str, Any]:
    """Return an empty result structure."""
    return {
        "hidden_dependencies": [],
        "files_scanned": 0,
        "summary": reason,
    }
