"""capa scanner wrapper -- binary capability analysis."""

from __future__ import annotations

import logging
import subprocess
import time
from pathlib import Path
from typing import Any

from thresher.scanners.models import Finding, ScanResults

logger = logging.getLogger(__name__)

# Binary signatures recognized by the `file` command output.
_BINARY_SIGS = ("elf", "pe32", "mach-o", "executable", "shared object")


def run_capa(target_dir: str, output_dir: str) -> ScanResults:
    """Run capa to analyze executable binaries for capabilities.

    First finds ELF/PE binaries in the target directory.  If none are
    found, returns empty results.  Runs capa on each binary and
    aggregates findings.

    Args:
        target_dir: Path to the repository.
        output_dir: Directory for scan artifacts.

    Returns:
        ScanResults with parsed Finding objects.
    """
    output_path = f"{output_dir}/capa.json"

    start = time.monotonic()
    try:
        # Find executable files and common binary extensions.
        target_path = Path(target_dir)
        candidates: list[str] = []

        for p in target_path.rglob("*"):
            if ".git" in p.parts:
                continue
            if not p.is_file():
                continue
            # Include executable files and common binary extensions.
            is_exec = p.stat().st_mode & 0o111
            is_binary_ext = p.suffix.lower() in (".so", ".dll", ".exe")
            if is_exec or is_binary_ext:
                candidates.append(str(p))

        # Filter candidates to true binaries using `file` command.
        # This prevents capa from running on shell scripts, Python scripts,
        # etc. which always fail with exit code 2.
        binaries: list[str] = []
        if candidates:
            file_result = subprocess.run(
                ["file", "--brief"] + candidates,
                capture_output=True,
                timeout=60,
            )
            file_lines = file_result.stdout.decode(errors="replace").strip().splitlines()

            if len(file_lines) != len(candidates):
                logger.warning(
                    "file command returned %d lines for %d candidates",
                    len(file_lines),
                    len(candidates),
                )
                binaries = candidates  # Fall back to scanning all candidates
            else:
                for candidate, file_type in zip(candidates, file_lines):
                    file_type_lower = file_type.strip().lower()
                    if any(sig in file_type_lower for sig in _BINARY_SIGS):
                        # Exclude text/script files that `file` might tag as
                        # "executable" in the description line.
                        if "text" not in file_type_lower and "script" not in file_type_lower:
                            binaries.append(candidate)
                        else:
                            logger.debug(
                                "Skipping script/text file: %s (%s)",
                                candidate,
                                file_type.strip(),
                            )
                    else:
                        logger.debug(
                            "Skipping non-binary file: %s (%s)",
                            candidate,
                            file_type.strip(),
                        )

        elapsed = time.monotonic() - start

        if not binaries:
            logger.info("No binary files (ELF/PE/Mach-O) found, skipping capa")
            return ScanResults(
                tool_name="capa",
                execution_time_seconds=elapsed,
                exit_code=0,
                findings=[],
                metadata={"note": "No binary files (ELF/PE/Mach-O) found in target"},
            )

        # Run capa on each binary — results stay in output_dir.
        last_exit_code = 0

        for binary_path in binaries:
            binary_output = f"{output_path}.{binary_path.replace('/', '_')}"
            result = subprocess.run(
                ["capa", "--format", "json", binary_path],
                capture_output=True,
                timeout=600,
            )
            Path(binary_output).write_bytes(result.stdout)
            last_exit_code = result.returncode

            if result.returncode == 2:
                # Exit code 2 means capa doesn't support this file format.
                # This shouldn't happen after our filtering, but log it.
                logger.warning(
                    "capa exit code 2 (unsupported format) for %s — "
                    "file should have been filtered out",
                    binary_path,
                )
            elif result.returncode != 0:
                logger.debug("capa exited with code %d for %s", result.returncode, binary_path)

        elapsed = time.monotonic() - start
        return ScanResults(
            tool_name="capa",
            execution_time_seconds=elapsed,
            exit_code=last_exit_code,
            raw_output_path=output_path,
        )

    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.exception("capa execution failed")
        return ScanResults(
            tool_name="capa",
            execution_time_seconds=elapsed,
            exit_code=-1,
            errors=[f"capa execution error: {exc}"],
        )


def parse_capa_output(raw: dict[str, Any], binary_path: str) -> list[Finding]:
    """Parse capa JSON output into normalized Finding objects.

    Args:
        raw: Parsed JSON dict from capa's ``--format json`` output.
        binary_path: Path to the binary that was analyzed.

    Returns:
        List of normalized Finding objects.
    """
    findings: list[Finding] = []
    rules = raw.get("rules", {})

    for idx, (rule_name, rule_data) in enumerate(rules.items()):
        namespace = rule_data.get("namespace", "")
        meta = rule_data.get("meta", {})
        attack = meta.get("attack", [])

        # Map severity based on namespace.
        if "malware" in namespace.lower():
            severity = "critical"
        elif "anti-analysis" in namespace.lower():
            severity = "high"
        else:
            severity = "medium"

        # Build MITRE ATT&CK references.
        attack_refs = []
        for entry in attack:
            if isinstance(entry, dict):
                technique = entry.get("technique", "")
                if technique:
                    attack_refs.append(technique)
            elif isinstance(entry, str):
                attack_refs.append(entry)

        title = f"capa: {rule_name}"
        description_parts = [f"Namespace: {namespace}"]
        if attack_refs:
            description_parts.append(f"MITRE ATT&CK: {', '.join(attack_refs)}")

        description = "; ".join(description_parts)
        finding_id = f"capa-{rule_name.replace(' ', '_')}-{idx}"

        findings.append(
            Finding(
                id=finding_id,
                source_tool="capa",
                category="binary_analysis",
                severity=severity,
                cvss_score=None,
                cve_id=None,
                title=title,
                description=description,
                file_path=binary_path,
                line_number=None,
                package_name=None,
                package_version=None,
                fix_version=None,
                raw_output=rule_data,
            )
        )

    return findings
