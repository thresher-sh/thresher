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
from pathlib import Path
from typing import Any

from thresher.agents._json import extract_json_object
from thresher.agents._runner import AgentSpec, run_agent
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


def _build_hooks_settings_json() -> str:
    """Return the settings.json content for the predep stop hook.

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
        hooks_json: str | None = _build_hooks_settings_json()
    except Exception:
        logger.warning("Failed to resolve predep hook settings", exc_info=True)
        # Continue without the hook — output validation still happens
        # in _parse_predep_output, just without retry.
        hooks_json = None

    logger.info("Running pre-dependency discovery agent")
    spec = AgentSpec(
        label="predep",
        prompt=PREDEP_PROMPT,
        allowed_tools=["Read", "Glob", "Grep"],
        max_turns=config.predep_max_turns or 15,
        timeout=600,
        cwd=target_dir,
        hooks_settings_json=hooks_json,
    )
    agent_result = run_agent(spec, config)
    if agent_result.failed:
        return _empty_result(f"Agent invocation failed: {agent_result.error}")

    result = _parse_predep_output(agent_result.result_text)

    # Inject the high_risk_dep flag so downstream can know whether
    # to download high-risk entries.
    result["high_risk_dep"] = config.high_risk_dep

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


def _parse_predep_output(text: str) -> dict[str, Any]:
    """Extract the predep JSON object from the agent's result text."""
    parsed = extract_json_object(
        text, accept=lambda d: "hidden_dependencies" in d,
    )
    if parsed is not None:
        return parsed

    preview = text[:500] if text else "(empty)"
    logger.warning(
        "Could not parse predep agent output. Result (first 500 chars): %s", preview,
    )
    return _empty_result("Failed to parse agent output")


def _empty_result(reason: str) -> dict[str, Any]:
    """Return an empty result structure."""
    return {
        "hidden_dependencies": [],
        "files_scanned": 0,
        "summary": reason,
    }
