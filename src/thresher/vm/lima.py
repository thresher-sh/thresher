"""Lima VM lifecycle management."""

from __future__ import annotations

import logging
import os
import subprocess
import time
from pathlib import Path

from thresher.config import ScanConfig
from thresher.vm.ssh import SSHError, ssh_copy_to, ssh_exec

logger = logging.getLogger(__name__)

# Path to the Lima VM template relative to the project root.
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_TEMPLATE_PATH = _PROJECT_ROOT / "lima" / "thresher.yaml"

# Paths to provisioning scripts inside the project.
_VM_SCRIPTS_DIR = _PROJECT_ROOT / "vm_scripts"

# Polling settings
_POLL_INTERVAL = 2  # seconds
_SSH_TIMEOUT = 120  # seconds

# Base VM image name — provisioned once, reused across scans.
BASE_VM_NAME = "thresher-base"

# Working directories cleaned between scans when reusing the base VM.
_WORKING_DIRS = ["/opt/target", "/opt/deps", "/opt/scan-results", "/opt/security-reports"]


class LimaError(Exception):
    """Raised when a Lima operation fails."""


def _wait_for_ssh(vm_name: str) -> None:
    """Poll until SSH is accepting connections inside the VM."""
    deadline = time.monotonic() + _SSH_TIMEOUT
    while time.monotonic() < deadline:
        try:
            result = subprocess.run(
                ["limactl", "shell", vm_name, "true"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        time.sleep(_POLL_INTERVAL)

    raise LimaError(
        f"SSH not ready on VM '{vm_name}' after {_SSH_TIMEOUT}s"
    )


def create_vm(config: ScanConfig) -> str:
    """Create and start a new ephemeral Lima VM.

    Runs limactl create and start synchronously (they stream their own
    progress to stderr), then verifies SSH readiness before returning.
    """
    vm_name = f"thresher-{int(time.time())}"

    if not _TEMPLATE_PATH.exists():
        raise LimaError(f"Lima template not found: {_TEMPLATE_PATH}")

    create_cmd = [
        "limactl",
        "create",
        "--name", vm_name,
        f"--cpus={config.vm.cpus}",
        f"--memory={config.vm.memory}",
        f"--disk={config.vm.disk}",
        "--plain",
        str(_TEMPLATE_PATH),
    ]

    logger.info("Creating VM %s", vm_name)
    result = _run_limactl(create_cmd, timeout=300)
    if result.returncode != 0:
        raise LimaError(f"Failed to create VM '{vm_name}': {result.stderr}")

    start_vm(vm_name)
    return vm_name


def start_vm(vm_name: str) -> None:
    """Start a Lima VM, then wait for SSH to be ready."""
    logger.info("Starting VM %s", vm_name)
    result = _run_limactl(["limactl", "start", vm_name], timeout=600)
    if result.returncode != 0:
        raise LimaError(f"Failed to start VM '{vm_name}': {result.stderr}")

    logger.info("VM %s started, waiting for SSH...", vm_name)
    _wait_for_ssh(vm_name)
    logger.info("VM %s is ready", vm_name)


def provision_vm(vm_name: str, config: ScanConfig) -> None:
    """Provision a running Lima VM with tools and firewall rules.

    Copies provision.sh and the generated firewall script into the VM,
    then executes them. The ANTHROPIC_API_KEY is passed via SSH env var
    (never written to disk inside the VM).

    Args:
        vm_name: Name of the running VM.
        config: Scan configuration (used for API key and verbose flag).

    Raises:
        LimaError: If provisioning fails.
        SSHError: If SSH operations fail.
    """
    provision_script = _VM_SCRIPTS_DIR / "provision.sh"
    if not provision_script.exists():
        raise LimaError(f"Provisioning script not found: {provision_script}")

    # Copy provision.sh into the VM
    ssh_copy_to(vm_name, str(provision_script), "/tmp/provision.sh")

    # Copy firewall script (use the robust bash version that resolves
    # domains to IPs, rather than generating a script with bare domain names)
    firewall_script_path = _VM_SCRIPTS_DIR / "firewall.sh"
    if not firewall_script_path.exists():
        raise LimaError(f"Firewall script not found: {firewall_script_path}")
    ssh_copy_to(vm_name, str(firewall_script_path), "/tmp/firewall.sh")

    # Copy lockdown scripts (scanner-docker wrapper + lockdown.sh)
    lockdown_script = _VM_SCRIPTS_DIR / "lockdown.sh"
    docker_wrapper = _VM_SCRIPTS_DIR / "scanner-docker"
    if not lockdown_script.exists():
        raise LimaError(f"Lockdown script not found: {lockdown_script}")
    if not docker_wrapper.exists():
        raise LimaError(f"Docker wrapper not found: {docker_wrapper}")
    ssh_copy_to(vm_name, str(lockdown_script), "/tmp/lockdown.sh")
    ssh_copy_to(vm_name, str(docker_wrapper), "/tmp/scanner-docker")

    # Build env vars for the remote shell
    env = config.ai_env()

    # Run provision.sh (installs all tools, builds Docker images)
    stdout, stderr, rc = ssh_exec(
        vm_name,
        "chmod +x /tmp/provision.sh && sudo /tmp/provision.sh",
        timeout=900,  # provisioning can take a while
        env=env,
    )
    if rc != 0:
        raise LimaError(
            f"Provisioning failed (exit {rc}):\nstdout: {stdout}\nstderr: {stderr}"
        )

    # Run firewall.sh (applies iptables whitelist + DNS pinning)
    stdout, stderr, rc = ssh_exec(
        vm_name,
        "chmod +x /tmp/firewall.sh && sudo /tmp/firewall.sh",
        timeout=60,
        env=env,
    )
    if rc != 0:
        raise LimaError(
            f"Firewall setup failed (exit {rc}):\nstdout: {stdout}\nstderr: {stderr}"
        )

    # Run lockdown.sh LAST — strips all sudo except the scanner-docker
    # wrapper. Must be after provision.sh and firewall.sh since those
    # scripts use sudo extensively.
    stdout, stderr, rc = ssh_exec(
        vm_name,
        "chmod +x /tmp/lockdown.sh && sudo /tmp/lockdown.sh",
        timeout=60,
        env=env,
    )
    if rc != 0:
        raise LimaError(
            f"Lockdown failed (exit {rc}):\nstdout: {stdout}\nstderr: {stderr}"
        )


def base_exists() -> bool:
    """Check whether the cached base VM exists."""
    status = vm_status(BASE_VM_NAME)
    return status != "Not found"


def build_base(config: ScanConfig) -> None:
    """Create, provision, and stop the base VM image.

    If the base already exists it is deleted first so a fresh image is built.
    After provisioning the VM is stopped (not destroyed) so its disk is
    preserved for reuse.
    """
    if base_exists():
        logger.info("Removing existing base VM before rebuild")
        destroy_vm(BASE_VM_NAME)

    if not _TEMPLATE_PATH.exists():
        raise LimaError(f"Lima template not found: {_TEMPLATE_PATH}")

    create_cmd = [
        "limactl",
        "create",
        "--name", BASE_VM_NAME,
        f"--cpus={config.vm.cpus}",
        f"--memory={config.vm.memory}",
        f"--disk={config.vm.disk}",
        "--plain",
        str(_TEMPLATE_PATH),
    ]

    logger.info("Creating base VM %s", BASE_VM_NAME)
    result = _run_limactl(create_cmd, timeout=300)
    if result.returncode != 0:
        raise LimaError(f"Failed to create base VM: {result.stderr}")

    start_vm(BASE_VM_NAME)
    provision_vm(BASE_VM_NAME, config)
    stop_vm(BASE_VM_NAME)
    logger.info("Base VM %s built and stopped", BASE_VM_NAME)


def ensure_base_running() -> str:
    """Start the base VM if it is stopped and return its name.

    Returns:
        The base VM name (``BASE_VM_NAME``).

    Raises:
        LimaError: If the base VM does not exist or cannot be started.
    """
    status = vm_status(BASE_VM_NAME)
    if status == "Not found":
        raise LimaError(
            f"Base VM '{BASE_VM_NAME}' not found. "
            "Run `thresher-build` first to create the cached base image."
        )
    if status != "Running":
        start_vm(BASE_VM_NAME)
    return BASE_VM_NAME


def clean_working_dirs(vm_name: str) -> None:
    """Remove scan working directories inside the VM.

    This is called between scans when reusing the base VM so that no
    artefacts leak across runs.
    """
    for d in _WORKING_DIRS:
        ssh_exec(vm_name, f"sudo rm -rf {d} && sudo mkdir -p {d} && sudo chmod 777 {d}")
    logger.info("Cleaned working directories in %s", vm_name)


def stop_vm(vm_name: str) -> None:
    """Stop a Lima VM without deleting it."""
    logger.info("Stopping VM %s", vm_name)
    result = _run_limactl(["limactl", "stop", vm_name], timeout=120)
    if result.returncode != 0:
        raise LimaError(f"Failed to stop VM '{vm_name}': {result.stderr}")


def destroy_vm(vm_name: str) -> None:
    """Force-delete a Lima VM.

    Args:
        vm_name: Name of the VM to destroy.

    Raises:
        LimaError: If deletion fails.
    """
    cmd = ["limactl", "delete", "-f", vm_name]
    result = _run_limactl(cmd, timeout=120)
    if result.returncode != 0:
        raise LimaError(f"Failed to destroy VM '{vm_name}': {result.stderr}")


def vm_status(vm_name: str) -> str:
    """Get the status of a Lima VM.

    Args:
        vm_name: Name of the VM to query.

    Returns:
        Status string (e.g., "Running", "Stopped", or "Not found").

    Raises:
        LimaError: If the status query fails unexpectedly.
    """
    cmd = ["limactl", "list", "--format", "{{.Status}}", vm_name]
    result = _run_limactl(cmd, timeout=30)

    if result.returncode != 0:
        # limactl list returns non-zero when the VM doesn't exist
        if "not found" in result.stderr.lower() or not result.stdout.strip():
            return "Not found"
        raise LimaError(
            f"Failed to get status of VM '{vm_name}': {result.stderr}"
        )

    return result.stdout.strip()


def _run_limactl(
    cmd: list[str], timeout: int = 120
) -> subprocess.CompletedProcess[str]:
    """Run a limactl command synchronously (for fast operations like status/destroy)."""
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise LimaError(
            "limactl not found. Install Lima: https://lima-vm.io"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise LimaError(
            f"limactl command timed out after {timeout}s: {' '.join(cmd)}"
        ) from exc


def _write_and_copy_script(
    vm_name: str, content: str, remote_path: str
) -> None:
    """Write script content to a temporary file and copy it into the VM.

    Args:
        vm_name: Name of the VM.
        content: Script content to write.
        remote_path: Destination path inside the VM.
    """
    import tempfile

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".sh", delete=False
    ) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        ssh_copy_to(vm_name, tmp_path, remote_path)
    finally:
        os.unlink(tmp_path)
