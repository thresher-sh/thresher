"""Lima VM lifecycle management."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

from threat_scanner.config import ScanConfig
from threat_scanner.vm.ssh import SSHError, ssh_copy_to, ssh_exec


# Path to the Lima VM template relative to the project root.
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_TEMPLATE_PATH = _PROJECT_ROOT / "lima" / "scanner.yaml"

# Paths to provisioning scripts inside the project.
_VM_SCRIPTS_DIR = _PROJECT_ROOT / "vm_scripts"


class LimaError(Exception):
    """Raised when a Lima operation fails."""


def create_vm(config: ScanConfig) -> str:
    """Create a new ephemeral Lima VM.

    Uses the scanner.yaml template with resource overrides from config.

    Args:
        config: Scan configuration containing VM resource settings.

    Returns:
        The VM instance name (e.g., "scanner-1711648200").

    Raises:
        LimaError: If VM creation fails.
    """
    vm_name = f"scanner-{int(time.time())}"

    if not _TEMPLATE_PATH.exists():
        raise LimaError(f"Lima template not found: {_TEMPLATE_PATH}")

    cmd = [
        "limactl",
        "create",
        "--name", vm_name,
        f"--cpus={config.vm.cpus}",
        f"--memory={config.vm.memory}GiB",
        f"--disk={config.vm.disk}GiB",
        "--plain",
        str(_TEMPLATE_PATH),
    ]

    result = _run_limactl(cmd, timeout=300)
    if result.returncode != 0:
        raise LimaError(f"Failed to create VM '{vm_name}': {result.stderr}")

    # Start the VM after creation
    start_vm(vm_name)

    return vm_name


def start_vm(vm_name: str) -> None:
    """Start a Lima VM.

    Args:
        vm_name: Name of the VM to start.

    Raises:
        LimaError: If the VM fails to start.
    """
    cmd = ["limactl", "start", vm_name]
    result = _run_limactl(cmd, timeout=600)
    if result.returncode != 0:
        raise LimaError(f"Failed to start VM '{vm_name}': {result.stderr}")


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

    # Build env vars for the remote shell
    env: dict[str, str] = {}
    if config.anthropic_api_key:
        env["ANTHROPIC_API_KEY"] = config.anthropic_api_key

    # Run provision.sh
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

    # Run firewall.sh
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
    """Run a limactl command and return the result.

    Args:
        cmd: Command and arguments.
        timeout: Timeout in seconds.

    Returns:
        The completed process result.

    Raises:
        LimaError: If limactl is not found or the command times out.
    """
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
