"""Lima+Docker launch mode — maximum isolation."""

import logging
import subprocess
from pathlib import Path

from thresher.config import ScanConfig
from thresher.fs import tempfile_with

logger = logging.getLogger(__name__)
BASE_VM_NAME = "thresher-base"
DOCKER_IMAGE = "thresher:latest"


def launch_lima(config: ScanConfig) -> int:
    """Launch the harness inside Docker running in a Lima VM. Returns exit code."""
    _ensure_vm_running()
    _apply_firewall()
    with tempfile_with(config.to_json(), suffix=".json") as config_path:
        subprocess.run(
            ["limactl", "copy", str(config_path), f"{BASE_VM_NAME}:/opt/config.json"],
            check=True,
        )
        docker_cmd = _build_lima_docker_cmd(config)
        result = subprocess.run(["limactl", "shell", BASE_VM_NAME, "--"] + docker_cmd)
        if result.returncode == 0:
            _copy_report_to_host(config.output_dir)
        return result.returncode


def _ensure_vm_running() -> None:
    """Ensure the base Lima VM is running, starting it if stopped."""
    result = subprocess.run(
        ["limactl", "list", "--format", "{{.Status}}", BASE_VM_NAME],
        capture_output=True,
    )
    status = result.stdout.decode().strip()
    if status == "Running":
        return
    elif status == "Stopped":
        subprocess.run(["limactl", "start", BASE_VM_NAME], check=True)
    else:
        raise RuntimeError(
            f"Lima VM '{BASE_VM_NAME}' not found. Run 'thresher build' first."
        )


def _apply_firewall() -> None:
    """Apply iptables firewall rules inside the Lima VM."""
    from thresher.vm.firewall import generate_firewall_rules
    rules = generate_firewall_rules()
    subprocess.run(
        ["limactl", "shell", BASE_VM_NAME, "--", "sudo", "bash", "-c", rules],
        check=True,
    )


def _build_lima_docker_cmd(config: ScanConfig) -> list[str]:
    return [
        "docker", "run",
        "-v", "/opt/reports:/output",
        "-v", "/opt/config.json:/config/config.json:ro",
        "-e", "ANTHROPIC_API_KEY",
        "-e", "CLAUDE_CODE_OAUTH_TOKEN",
        # Use pre-populated vuln DBs from the image; skip runtime downloads
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


def _copy_report_to_host(output_dir: str) -> None:
    """Copy the report from the VM to the host output directory."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["limactl", "copy", "-r", f"{BASE_VM_NAME}:/opt/reports/.", output_dir],
        check=True,
    )
