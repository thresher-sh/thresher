"""Install hook scanner -- detects install scripts in dependency manifests."""

from __future__ import annotations

import logging
import time
from typing import Any

from thresher.scanners.models import Finding, ScanResults
from thresher.vm.ssh import ssh_exec, ssh_write_file

logger = logging.getLogger(__name__)

# Self-contained Python script that runs INSIDE the VM.
_INSTALL_HOOKS_SCRIPT = r'''#!/usr/bin/env python3
"""Scan dependency manifests for install hooks.

Writes JSON results to /opt/scan-results/install-hooks.json.
"""

import json
import os
import re
import sys

DEPS_DIR = "/opt/deps"
OUTPUT_PATH = "/opt/scan-results/install-hooks.json"

NETWORK_PATTERNS = [
    r"\bfetch\b", r"\bcurl\b", r"\bwget\b", r"\bhttp\.get\b",
    r"\bhttps\.get\b", r"\brequests\.\w+\b", r"\burllib\b",
    r"\bhttp\.request\b", r"\bnet\.connect\b", r"\bsocket\b",
    r"\bXMLHttpRequest\b",
]

SHELL_PATTERNS = [
    r"\bsh\b", r"\bbash\b", r"\bexec\b", r"\bspawn\b",
    r"\bchild_process\b", r"\bsubprocess\b", r"\bos\.system\b",
    r"\bos\.popen\b", r"\beval\b",
]

findings = []


def classify_severity(script_content: str) -> str:
    """Classify severity based on what the install script does."""
    has_network = any(re.search(p, script_content) for p in NETWORK_PATTERNS)
    has_shell = any(re.search(p, script_content) for p in SHELL_PATTERNS)

    if has_network:
        return "critical"
    if has_shell:
        return "high"
    return "medium"


def check_npm_package(manifest_path: str) -> None:
    """Check package.json for install script hooks."""
    try:
        with open(manifest_path, "r") as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError):
        return

    scripts = data.get("scripts", {})
    hook_names = ["preinstall", "postinstall", "preuninstall", "install"]

    for hook in hook_names:
        if hook in scripts:
            script_content = scripts[hook]
            severity = classify_severity(script_content)
            findings.append({
                "type": "npm_install_hook",
                "file": manifest_path,
                "hook": hook,
                "script": script_content,
                "severity": severity,
                "description": f"npm {hook} script detected: {script_content[:200]}",
            })


def check_python_setup(setup_path: str) -> None:
    """Check setup.py for cmdclass overrides."""
    try:
        with open(setup_path, "r") as f:
            content = f.read()
    except IOError:
        return

    if re.search(r"\bcmdclass\b", content):
        severity = classify_severity(content)
        findings.append({
            "type": "python_cmdclass",
            "file": setup_path,
            "hook": "cmdclass",
            "severity": severity,
            "description": "setup.py contains cmdclass overrides that run during install",
        })


def check_python_pyproject(pyproject_path: str) -> None:
    """Check pyproject.toml for build scripts."""
    try:
        with open(pyproject_path, "r") as f:
            content = f.read()
    except IOError:
        return

    # Look for build-system scripts or custom build commands
    if re.search(r"\[tool\..*build\]", content) or re.search(r"build-backend", content):
        if re.search(r"\bscript\b|\bcommand\b|\bexec\b", content):
            severity = classify_severity(content)
            findings.append({
                "type": "python_build_script",
                "file": pyproject_path,
                "hook": "build-script",
                "severity": severity,
                "description": "pyproject.toml contains build scripts that run during install",
            })


def check_rust_build(build_rs_path: str) -> None:
    """Check build.rs for network or download activity."""
    try:
        with open(build_rs_path, "r") as f:
            content = f.read()
    except IOError:
        return

    network_indicators = [
        r"\breqwest\b", r"\bhyper\b", r"\bcurl\b", r"\bdownload\b",
        r"\bTcpStream\b", r"\bUdpSocket\b", r"\bCommand::new\b",
    ]

    has_network = any(re.search(p, content) for p in network_indicators)
    severity = "critical" if has_network else "medium"

    findings.append({
        "type": "rust_build_script",
        "file": build_rs_path,
        "hook": "build.rs",
        "severity": severity,
        "description": "build.rs detected"
        + (" with network/download activity" if has_network else ""),
    })


def scan_deps_dir() -> None:
    """Walk /opt/deps/ and check all manifest files."""
    if not os.path.isdir(DEPS_DIR):
        return

    for root, dirs, files in os.walk(DEPS_DIR):
        for fname in files:
            fpath = os.path.join(root, fname)
            if fname == "package.json":
                check_npm_package(fpath)
            elif fname == "setup.py":
                check_python_setup(fpath)
            elif fname == "pyproject.toml":
                check_python_pyproject(fpath)
            elif fname == "build.rs":
                check_rust_build(fpath)


if __name__ == "__main__":
    scan_deps_dir()
    output = {
        "scanner": "install-hooks",
        "findings": findings,
        "total": len(findings),
    }
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)
    print(f"Install hooks scan complete: {len(findings)} findings")
'''


def run_install_hooks(vm_name: str, output_dir: str) -> ScanResults:
    """Run install hook analysis inside the VM.

    Copies the analysis script into the VM, executes it, and returns
    metadata only. All findings data stays in the VM.

    Args:
        vm_name: Name of the Lima VM.
        output_dir: Directory for scan artifacts inside the VM.

    Returns:
        ScanResults with execution metadata only (findings stay in VM).
    """
    script_remote_path = "/tmp/install_hooks_scanner.py"

    start = time.monotonic()
    try:
        # Copy the script into the VM
        ssh_write_file(vm_name, _INSTALL_HOOKS_SCRIPT, script_remote_path)

        # Execute it
        cmd = f"python3 {script_remote_path}"
        result = ssh_exec(vm_name, cmd, timeout=300)
        elapsed = time.monotonic() - start

        output_path = f"{output_dir}/install-hooks.json"

        if result.exit_code != 0:
            logger.warning(
                "Install hooks scanner exited with code %d: %s",
                result.exit_code,
                result.stderr,
            )
            return ScanResults(
                tool_name="install-hooks",
                execution_time_seconds=elapsed,
                exit_code=result.exit_code,
                errors=[
                    f"Install hooks scanner failed (exit {result.exit_code}): "
                    f"{result.stderr}"
                ],
            )

        return ScanResults(
            tool_name="install-hooks",
            execution_time_seconds=elapsed,
            exit_code=result.exit_code,
            raw_output_path=output_path,
        )

    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.exception("Install hooks scanner execution failed")
        return ScanResults(
            tool_name="install-hooks",
            execution_time_seconds=elapsed,
            exit_code=-1,
            errors=[f"Install hooks scanner execution error: {exc}"],
        )


def parse_install_hooks_output(raw: dict[str, Any]) -> list[Finding]:
    """Parse install hooks JSON output into normalized Finding objects.

    Args:
        raw: Parsed JSON dict from the install hooks scanner.

    Returns:
        List of normalized Finding objects.
    """
    findings: list[Finding] = []

    for idx, item in enumerate(raw.get("findings", [])):
        hook_type = item.get("type", "unknown")
        hook = item.get("hook", "unknown")
        severity = item.get("severity", "medium")
        description = item.get("description", "")
        file_path = item.get("file")

        findings.append(
            Finding(
                id=f"install-hooks-{idx}-{hook_type}",
                source_tool="install-hooks",
                category="install_hook",
                severity=severity,
                cvss_score=None,
                cve_id=None,
                title=f"Install hook detected: {hook} ({hook_type})",
                description=description,
                file_path=file_path,
                line_number=None,
                package_name=None,
                package_version=None,
                fix_version=None,
                raw_output=item,
            )
        )

    return findings
