"""Docker launch mode — runs harness in a container."""

import logging
import subprocess
import tempfile
from pathlib import Path

from thresher.config import ScanConfig

logger = logging.getLogger(__name__)
DOCKER_IMAGE = "thresher:latest"


def launch_docker(config: ScanConfig) -> int:
    """Launch the harness inside a Docker container. Returns exit code."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write(config.to_json())
        config_path = f.name
    cmd = _build_docker_cmd(config, config_path)
    logger.info("Launching harness (docker mode)")
    try:
        result = subprocess.run(cmd)
        return result.returncode
    finally:
        Path(config_path).unlink(missing_ok=True)


def _build_docker_cmd(config: ScanConfig, config_path: str) -> list[str]:
    return [
        "docker", "run",
        "-v", f"{config.output_dir}:/output",
        "-v", f"{config_path}:/config/config.json:ro",
        "-e", "ANTHROPIC_API_KEY",
        "-e", "CLAUDE_CODE_OAUTH_TOKEN",
        "--rm", "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=1073741824",
        "--tmpfs", "/home/thresher/.cache:rw,size=536870912",
        "--tmpfs", "/opt/target:rw,size=2147483648",
        "--tmpfs", "/opt/scan-results:rw,size=1073741824",
        "--tmpfs", "/opt/deps:rw,size=2147483648",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user", "thresher",
        DOCKER_IMAGE,
        "--config", "/config/config.json",
        "--output", "/output",
    ]
