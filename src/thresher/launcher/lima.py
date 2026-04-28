"""Lima+Docker launch mode — maximum isolation."""

import hashlib
import logging
import os
import subprocess
from pathlib import Path

from thresher.agents.runtime import HostFileMount, runtime_host_mounts
from thresher.config import ScanConfig
from thresher.fs import tempfile_with
from thresher.launcher._container import build_docker_args

logger = logging.getLogger(__name__)
BASE_VM_NAME = "thresher-base"


def _vm_staging_path(mount: HostFileMount) -> str:
    """Per-mount staging path inside the VM. The hash keeps separate
    runtimes from clobbering each other's files in /opt."""
    digest = hashlib.sha1(mount.container_path.encode()).hexdigest()[:12]
    return f"/opt/runtime-{digest}-{mount.host_path.name}"


def launch_lima(config: ScanConfig) -> int:
    """Launch the harness inside Docker running in a Lima VM. Returns exit code."""
    _ensure_vm_running()
    _apply_firewall()

    # Rewrite local_path for container
    config_for_container = config
    if config.local_path:
        import copy

        config_for_container = copy.copy(config)
        config_for_container.local_path = "/opt/source"

    with tempfile_with(config_for_container.to_json(), suffix=".json") as config_path:
        subprocess.run(
            ["limactl", "copy", str(config_path), f"{BASE_VM_NAME}:/opt/config.json"],
            check=True,
        )
        if config.local_path:
            subprocess.run(
                ["limactl", "copy", "-r", config.local_path, f"{BASE_VM_NAME}:/opt/source"],
                check=True,
            )
        # Stage runtime credentials inside the VM so docker can mount them
        # into the harness container. Missing host files are skipped.
        for mount in runtime_host_mounts(config.agent_runtime):
            if mount.host_path.exists():
                subprocess.run(
                    ["limactl", "copy", str(mount.host_path), f"{BASE_VM_NAME}:{_vm_staging_path(mount)}"],
                    check=True,
                )
        subprocess.run(
            ["limactl", "shell", BASE_VM_NAME, "--", "sudo", "chmod", "-R", "a+rX", "/opt"],
            check=True,
        )
        docker_cmd = _build_lima_docker_cmd(config)
        result = subprocess.run(["limactl", "shell", BASE_VM_NAME, "--", *docker_cmd])
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
        raise RuntimeError(f"Lima VM '{BASE_VM_NAME}' not found. Run 'thresher build' first.")


def _apply_firewall() -> None:
    """Apply iptables firewall rules inside the Lima VM."""
    from thresher.vm.firewall import generate_firewall_rules

    rules = generate_firewall_rules()
    subprocess.run(
        ["limactl", "shell", BASE_VM_NAME, "--", "sudo", "bash", "-c", rules],
        check=True,
    )


def _build_lima_docker_cmd(config: ScanConfig) -> list[str]:
    source_mount = None
    if config.local_path:
        source_mount = "/opt/source:/opt/source:ro"

    extra_flags = _build_credential_env_flags()
    for mount in runtime_host_mounts(config.agent_runtime):
        if not mount.host_path.exists():
            continue
        # Inside the VM, docker mounts the staged copy — not the host path.
        extra_flags += ["-v", f"{_vm_staging_path(mount)}:{mount.container_path}:ro"]

    return build_docker_args(
        output_mount="/opt/reports:/output",
        config_mount="/opt/config.json:/config/config.json:ro",
        # Forward host env vars by VALUE. `limactl shell --` runs a
        # non-login, non-interactive shell that does NOT source
        # /etc/environment or /etc/profile, so by-name forwarding
        # (`-e KEY`) gets empty strings inside the VM. Pass values
        # explicitly so docker sees them.
        env_flags=extra_flags,
        source_mount=source_mount,
    )


def _build_credential_env_flags() -> list[str]:
    flags: list[str] = []
    for key in ("ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"):
        value = os.environ.get(key)
        if value:
            flags += ["-e", f"{key}={value}"]
    return flags


def _copy_report_to_host(output_dir: str) -> None:
    """Copy the report from the VM to the host output directory."""
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["limactl", "copy", "-r", f"{BASE_VM_NAME}:/opt/reports/.", output_dir],
        check=True,
    )
