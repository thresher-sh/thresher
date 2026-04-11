"""Docker launch mode — runs harness in a container."""

import logging
import subprocess
import sys
import tempfile
from pathlib import Path

from thresher.config import ScanConfig

logger = logging.getLogger(__name__)
DOCKER_IMAGE = "thresher:latest"


def launch_docker(config: ScanConfig) -> int:
    """Launch the harness inside a Docker container. Returns exit code."""
    # Resolve to absolute path — Docker -v requires it
    output_dir = str(Path(config.output_dir).resolve())
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write(config.to_json())
        config_path = f.name
    cmd = _build_docker_cmd(config, config_path, output_dir)
    logger.info("Launching harness (docker mode): output=%s", output_dir)
    try:
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
    finally:
        Path(config_path).unlink(missing_ok=True)


def _resolve_log_file(config: ScanConfig) -> str | None:
    """Find the active log file path from the CLI logging setup."""
    import logging as _logging
    for handler in _logging.getLogger("thresher").handlers:
        if isinstance(handler, _logging.FileHandler):
            return handler.baseFilename
    return None


def _build_docker_cmd(config: ScanConfig, config_path: str, output_dir: str) -> list[str]:
    env_flags: list[str] = []
    # Pass credentials explicitly — they may come from Keychain, not env vars
    if config.anthropic_api_key:
        env_flags += ["-e", f"ANTHROPIC_API_KEY={config.anthropic_api_key}"]
    elif config.oauth_token:
        env_flags += ["-e", f"CLAUDE_CODE_OAUTH_TOKEN={config.oauth_token}"]
    return [
        "docker", "run",
        "-v", f"{output_dir}:/output",
        "-v", f"{config_path}:/config/config.json:ro",
        *env_flags,
        # Point vuln scanners at pre-populated DBs baked into the image
        # and skip runtime DB updates (avoids tmpfs exhaustion from
        # concurrent Grype+Trivy downloads competing for /home tmpfs).
        "-e", "GRYPE_DB_CACHE_DIR=/opt/vuln-db/grype",
        "-e", "GRYPE_DB_AUTO_UPDATE=false",
        "-e", "TRIVY_CACHE_DIR=/opt/vuln-db/trivy",
        "-e", "TRIVY_SKIP_DB_UPDATE=true",
        "--rm", "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=1073741824,uid=1000,gid=1000",
        "--tmpfs", "/home/thresher:rw,size=536870912,uid=1000,gid=1000",
        "--tmpfs", "/opt/target:rw,size=2147483648,uid=1000,gid=1000",
        "--tmpfs", "/opt/scan-results:rw,size=1073741824,uid=1000,gid=1000",
        "--tmpfs", "/opt/deps:rw,size=2147483648,uid=1000,gid=1000",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user", "thresher",
        DOCKER_IMAGE,
        "--config", "/config/config.json",
        "--output", "/output",
    ]
