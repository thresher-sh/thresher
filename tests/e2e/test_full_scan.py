"""End-to-end tests requiring a real Lima VM.

Run with: pytest -m e2e
These tests are slow (~10 min) and require Lima installed.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from thresher.vm.lima import create_vm, destroy_vm, provision_vm, vm_status, LimaError
from thresher.vm.ssh import ssh_exec
from thresher.config import ScanConfig, VMConfig


pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(
        shutil.which("limactl") is None,
        reason="limactl not found — install Lima: brew install lima",
    ),
]


@pytest.fixture
def ephemeral_vm():
    """Create and yield an ephemeral VM, then destroy it."""
    config = ScanConfig(
        repo_url="https://github.com/pallets/markupsafe",
        vm=VMConfig(cpus=2, memory=4, disk=20),
        skip_ai=True,
    )
    vm_name = None
    try:
        vm_name = create_vm(config)
        yield vm_name, config
    finally:
        if vm_name:
            try:
                destroy_vm(vm_name)
            except LimaError:
                pass


class TestVMLifecycle:
    def test_create_provision_destroy(self, ephemeral_vm):
        vm_name, config = ephemeral_vm
        status = vm_status(vm_name)
        assert status == "Running"

        provision_vm(vm_name, config)

        # Verify tools are installed
        result = ssh_exec(vm_name, "which git && which docker && which syft && which grype")
        assert result.exit_code == 0

    def test_destroy_removes_vm(self, ephemeral_vm):
        vm_name, _ = ephemeral_vm
        destroy_vm(vm_name)
        status = vm_status(vm_name)
        assert status == "Not found"


class TestFirewall:
    def test_blocks_unwhitelisted(self, ephemeral_vm):
        vm_name, config = ephemeral_vm
        provision_vm(vm_name, config)

        # Attempt to reach an unwhitelisted domain — should be blocked
        result = ssh_exec(
            vm_name,
            "curl -s --connect-timeout 5 https://example.com || echo BLOCKED",
            timeout=15,
        )
        assert "BLOCKED" in result.stdout or result.exit_code != 0


class TestSkipAIScan:
    def test_deterministic_scan_small_repo(self, ephemeral_vm):
        vm_name, config = ephemeral_vm
        provision_vm(vm_name, config)

        # Clone a small repo using the hardened safe_clone.sh script
        result = ssh_exec(
            vm_name,
            "bash /tmp/safe_clone.sh https://github.com/pallets/markupsafe /opt/target",
            timeout=300,
        )
        assert result.exit_code == 0, f"safe_clone failed: {result.stderr}"

        # Run Syft to verify scanner tooling works
        result = ssh_exec(
            vm_name,
            "syft /opt/target -o cyclonedx-json | sudo tee /opt/scan-results/sbom.json > /dev/null",
            timeout=120,
        )
        assert result.exit_code == 0, f"syft failed: {result.stderr}"

        # Verify SBOM was created
        result = ssh_exec(vm_name, "test -f /opt/scan-results/sbom.json && echo OK")
        assert "OK" in result.stdout
