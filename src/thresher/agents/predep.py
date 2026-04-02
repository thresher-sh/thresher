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

Outputs a structured JSON file that the scanner-deps container reads
alongside the standard ecosystem detection.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from thresher.config import ScanConfig
from thresher.vm.ssh import ssh_exec, ssh_write_file

logger = logging.getLogger(__name__)

TARGET_DIR = "/opt/target"
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


def _shell_quote_key(value: str) -> str:
    """Quote a string for safe inclusion in a shell command."""
    return "'" + value.replace("'", "'\\''") + "'"


def run_predep_discovery(
    vm_name: str,
    config: ScanConfig,
) -> dict[str, Any]:
    """Run the pre-dependency discovery agent inside the VM.

    Scans the cloned source for hidden dependency sources and writes
    the results to a JSON file that the scanner-deps container reads.

    Args:
        vm_name: Name of the Lima VM.
        config: Scan configuration.

    Returns:
        Dict with discovered hidden dependencies.
    """
    try:
        ssh_write_file(vm_name, PREDEP_PROMPT, "/tmp/predep_prompt.txt")
    except Exception:
        logger.warning("Failed to write predep prompt to VM", exc_info=True)
        return _empty_result("Failed to write prompt file")

    # Set up the stop hook to validate output schema before the agent
    # is allowed to finish. The hook checks that the response contains
    # valid JSON matching the hidden_dependencies schema.
    hook_settings = json.dumps({
        "hooks": {
            "Stop": [{
                "hooks": [{
                    "type": "command",
                    "command": "/opt/thresher/bin/validate_predep_output.sh",
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
        logger.warning("Failed to write stop hook settings", exc_info=True)
        # Continue without the hook — output validation will still
        # happen in _parse_predep_output, just without retry

    model = config.model
    claude_cmd = (
        f"cd {TARGET_DIR} && "
        f"claude -p \"$(cat /tmp/predep_prompt.txt)\" "
        f"--model {model} "
        f'--allowedTools "Read,Glob,Grep" '
        f"--output-format stream-json "
        f"--verbose "
        f"--max-turns 15"
    )

    # Write credentials to tmpfs and read-and-delete.
    # Supports both ANTHROPIC_API_KEY and CLAUDE_CODE_OAUTH_TOKEN.
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

    logger.info("Running pre-dependency discovery agent in VM %s", vm_name)
    try:
        stdout, _stderr, _rc = ssh_exec(
            vm_name, claude_cmd, timeout=600,
        )
    except Exception as exc:
        logger.error("Pre-dep discovery agent failed: %s", exc)
        return _empty_result(f"Agent invocation failed: {exc}")

    result = _parse_predep_output(stdout)

    # Write the result to the VM so the container can read it
    try:
        _, _, rc = ssh_exec(vm_name, f"mkdir -p $(dirname {OUTPUT_PATH})")
        if rc != 0:
            logger.warning(
                "Cannot create output directory %s (exit %d) — "
                "was the VM provisioned correctly?",
                OUTPUT_PATH, rc,
            )
            return result
        # Inject the high_risk_dep flag so the container knows whether
        # to download high-risk entries
        result["high_risk_dep"] = config.high_risk_dep
        ssh_write_file(vm_name, json.dumps(result, indent=2), OUTPUT_PATH)

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
    except Exception:
        logger.warning("Failed to write predep results to VM", exc_info=True)

    return result


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
                        try:
                            parsed = json.loads(inner)
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

    logger.warning("Could not parse predep agent output")
    return _empty_result("Failed to parse agent output")


def _empty_result(reason: str) -> dict[str, Any]:
    """Return an empty result structure."""
    return {
        "hidden_dependencies": [],
        "files_scanned": 0,
        "summary": reason,
    }
