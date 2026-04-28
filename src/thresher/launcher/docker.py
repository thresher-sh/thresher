"""Docker launch mode — runs harness in a container."""

import logging
import subprocess
import sys
from pathlib import Path

from thresher.agents.runtime import runtime_host_mounts
from thresher.config import ScanConfig
from thresher.fs import tempfile_with
from thresher.launcher._container import build_docker_args

logger = logging.getLogger(__name__)


def launch_docker(config: ScanConfig) -> int:
    """Launch the harness inside a Docker container. Returns exit code."""
    # Resolve to absolute path — Docker -v requires it
    output_dir = str(Path(config.output_dir).resolve())
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Rewrite local_path for container — host path becomes /opt/source
    config_for_container = config
    if config.local_path:
        import copy

        config_for_container = copy.copy(config)
        config_for_container.local_path = "/opt/source"

    with tempfile_with(config_for_container.to_json(), suffix=".json") as config_path:
        cmd = _build_docker_cmd(config, str(config_path), output_dir)
        logger.info("Launching harness (docker mode): output=%s", output_dir)
        # Stream container output to both terminal and log file
        log_file = _resolve_log_file(config)
        if log_file:
            with open(log_file, "a") as lf:
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                for line in proc.stdout:
                    sys.stderr.buffer.write(line)
                    sys.stderr.buffer.flush()
                    lf.write(line.decode(errors="replace"))
                    lf.flush()
                proc.wait()
                return proc.returncode
        else:
            result = subprocess.run(cmd)
            return result.returncode


def _resolve_log_file(config: ScanConfig) -> str | None:
    """Find the active log file path from the CLI logging setup."""
    import logging as _logging

    for handler in _logging.getLogger("thresher").handlers:
        if isinstance(handler, _logging.FileHandler):
            return handler.baseFilename
    return None


def _build_docker_cmd(config: ScanConfig, config_path: str, output_dir: str) -> list[str]:
    env_flags: list[str] = []
    extra_mounts: list[str] = []
    # Pass credentials explicitly — they may come from Keychain, not env vars
    if config.anthropic_api_key:
        env_flags += ["-e", f"ANTHROPIC_API_KEY={config.anthropic_api_key}"]
    elif config.oauth_token:
        env_flags += ["-e", f"CLAUDE_CODE_OAUTH_TOKEN={config.oauth_token}"]

    # Forward host files the configured agent runtime needs (e.g. wksp's
    # ~/.config/workshop/credentials.json). Missing files are skipped so
    # the runtime can fall back to env-based credentials.
    for mount in runtime_host_mounts(config.agent_runtime):
        if mount.host_path.exists():
            extra_mounts += ["-v", f"{mount.host_path}:{mount.container_path}:ro"]

    source_mount = None
    if config.local_path:
        source_mount = f"{config.local_path}:/opt/source:ro"

    return build_docker_args(
        output_mount=f"{output_dir}:/output",
        config_mount=f"{config_path}:/config/config.json:ro",
        env_flags=env_flags + extra_mounts,
        source_mount=source_mount,
    )
