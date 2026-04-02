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

# Path to custom scanner rules.
_RULES_DIR = _PROJECT_ROOT / "rules"

# Polling settings
_POLL_INTERVAL = 2  # seconds
_SSH_TIMEOUT = 300  # seconds (first boot can be slow)

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
    """Start a Lima VM, then wait for SSH to be ready.

    Uses streaming output so progress is visible during first boot
    (image download, cloud-init, etc.).
    """
    logger.info("Starting VM %s", vm_name)

    try:
        proc = subprocess.Popen(
            ["limactl", "start", vm_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except FileNotFoundError as exc:
        raise LimaError("limactl not found. Install Lima: https://lima-vm.io") from exc

    # Stream output to logger so it shows up in logs/tmux
    for line in proc.stdout:
        stripped = line.rstrip("\n")
        if stripped:
            logger.info("  %s", stripped)

    proc.wait()
    if proc.returncode != 0:
        raise LimaError(f"Failed to start VM '{vm_name}' (exit {proc.returncode})")

    logger.info("VM %s started, waiting for SSH...", vm_name)
    _wait_for_ssh(vm_name)
    logger.info("VM %s is ready", vm_name)
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

    # Copy runtime scripts to /opt/thresher/bin/ (persists across reboots,
    # unlike /tmp/ which is cleared). These are needed during scans, not
    # just during provisioning.
    ssh_exec(vm_name, "sudo mkdir -p /opt/thresher/bin && sudo chmod 777 /opt/thresher/bin")

    safe_clone_script = _VM_SCRIPTS_DIR / "safe_clone.sh"
    if not safe_clone_script.exists():
        raise LimaError(f"Safe clone script not found: {safe_clone_script}")
    ssh_copy_to(vm_name, str(safe_clone_script), "/opt/thresher/bin/safe_clone.sh")
    ssh_exec(vm_name, "sudo chmod +x /opt/thresher/bin/safe_clone.sh")

    validate_script = _VM_SCRIPTS_DIR / "validate_predep_output.sh"
    if validate_script.exists():
        ssh_copy_to(vm_name, str(validate_script), "/opt/thresher/bin/validate_predep_output.sh")
        ssh_exec(vm_name, "sudo chmod +x /opt/thresher/bin/validate_predep_output.sh")

    # Copy scanner-deps Docker build context (Dockerfile + scripts)
    docker_dir = _PROJECT_ROOT / "docker"
    if docker_dir.exists():
        # Create the build context directory in the VM
        ssh_exec(vm_name, "mkdir -p /tmp/docker-scanner-deps/scripts")
        ssh_copy_to(
            vm_name,
            str(docker_dir / "Dockerfile.scanner-deps"),
            "/tmp/docker-scanner-deps/Dockerfile.scanner-deps",
        )
        for script in sorted((docker_dir / "scripts").iterdir()):
            ssh_copy_to(
                vm_name,
                str(script),
                f"/tmp/docker-scanner-deps/scripts/{script.name}",
            )

    # Copy custom scanner rules (Semgrep supply-chain rules, etc.)
    semgrep_rules_dir = _RULES_DIR / "semgrep"
    if semgrep_rules_dir.exists():
        ssh_exec(vm_name, "sudo mkdir -p /opt/rules/semgrep && sudo chmod 777 /opt/rules/semgrep")
        for rule_file in sorted(semgrep_rules_dir.iterdir()):
            if rule_file.is_file():
                ssh_copy_to(
                    vm_name,
                    str(rule_file),
                    f"/opt/rules/semgrep/{rule_file.name}",
                )

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
    # Use progress bar — provision.sh has ~30 major [provision] log lines
    from thresher.branding import FinProgressBar

    _provision_bar = FinProgressBar("Provisioning", total=100)
    _provision_step = [0]  # mutable for closure

    def _on_provision_line(line: str) -> None:
        if "[provision]" in line:
            _provision_step[0] += 1
            # Extract the message after the timestamp
            parts = line.split("] ", 1)
            status = parts[1][:30] if len(parts) > 1 else ""
            _provision_bar.update(_provision_step[0], status)

    stdout, stderr, rc = ssh_exec(
        vm_name,
        "chmod +x /tmp/provision.sh && sudo /tmp/provision.sh",
        timeout=900,  # provisioning can take a while
        env=env,
        on_stdout=_on_provision_line,
    )
    _provision_bar.finish()

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
            "Run `thresher build` first to create the cached base image."
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
    """Force-stop a Lima VM without deleting it."""
    logger.info("Force-stopping VM %s", vm_name)
    result = _run_limactl(["limactl", "stop", "-f", vm_name], timeout=30)
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
