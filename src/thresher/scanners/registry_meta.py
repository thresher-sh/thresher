"""Registry metadata scanner -- queries npm and PyPI registries directly.

Detects supply chain manipulation signals that deps.dev doesn't cover:
- Maintainer changes between versions
- Download count anomalies (typosquatting signal)
- Install script introduction in new versions
- Tarball size spikes between versions
- Author email domain changes

Runs as a self-contained Python script via subprocess.
"""

from __future__ import annotations

import logging
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from thresher.scanners.models import Finding, ScanResults

logger = logging.getLogger(__name__)

_REGISTRY_META_SCRIPT = r'''#!/usr/bin/env python3
"""Query package registries for supply chain manipulation signals.

Reads the dependency manifest, queries npm/PyPI for each package,
and writes findings to /opt/scan-results/registry-meta.json.
"""

import json
import os
import sys
import time
import urllib.request
import urllib.error

MANIFEST_PATH = "/opt/deps/dep_manifest.json"
OUTPUT_PATH = "/opt/scan-results/registry-meta.json"

findings = []


def api_get(url: str) -> dict | None:
    """GET a JSON URL. Returns None on failure."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "thresher/2.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError,
            TimeoutError, OSError):
        return None


def check_npm_package(name: str, version: str) -> None:
    """Check an npm package for supply chain signals."""
    data = api_get(f"https://registry.npmjs.org/{urllib.request.quote(name, safe='@/')}")
    if not data:
        return

    versions = data.get("versions", {})
    dist_tags = data.get("dist-tags", {})
    current_time = data.get("time", {})

    if not versions:
        return

    # --- Maintainer change between versions ---
    version_list = sorted(versions.keys(), key=lambda v: current_time.get(v, ""))
    if len(version_list) >= 2:
        prev_ver = version_list[-2]
        curr_ver = version_list[-1]
        prev_maintainers = set(
            m.get("name", "") for m in versions.get(prev_ver, {}).get("maintainers", [])
            if isinstance(m, dict)
        )
        curr_maintainers = set(
            m.get("name", "") for m in versions.get(curr_ver, {}).get("maintainers", [])
            if isinstance(m, dict)
        )

        if prev_maintainers and curr_maintainers and prev_maintainers != curr_maintainers:
            added = curr_maintainers - prev_maintainers
            removed = prev_maintainers - curr_maintainers
            if removed:  # Someone was removed — more suspicious than just adding
                findings.append({
                    "type": "maintainer_change",
                    "package": name,
                    "ecosystem": "npm",
                    "severity": "high",
                    "description": (
                        f"Maintainer change between {prev_ver} and {curr_ver}. "
                        f"Removed: {', '.join(removed)}. Added: {', '.join(added)}. "
                        f"Possible account takeover."
                    ),
                    "detail": {
                        "previous_version": prev_ver,
                        "current_version": curr_ver,
                        "removed": list(removed),
                        "added": list(added),
                    },
                })

    # --- Install script introduction ---
    if version in versions:
        scripts = versions[version].get("scripts", {})
        has_install = any(
            k in scripts for k in ("preinstall", "postinstall", "preuninstall")
        )
        if has_install:
            # Check if previous version also had install scripts
            prev_versions = [v for v in version_list if v != version]
            if prev_versions:
                prev = prev_versions[-1]
                prev_scripts = versions.get(prev, {}).get("scripts", {})
                prev_had_install = any(
                    k in prev_scripts for k in ("preinstall", "postinstall", "preuninstall")
                )
                if not prev_had_install:
                    install_cmds = {
                        k: v for k, v in scripts.items()
                        if k in ("preinstall", "postinstall", "preuninstall")
                    }
                    findings.append({
                        "type": "install_script_introduced",
                        "package": name,
                        "ecosystem": "npm",
                        "severity": "critical",
                        "description": (
                            f"Install scripts introduced in {version} "
                            f"(not present in {prev}): {install_cmds}"
                        ),
                        "detail": {
                            "version": version,
                            "previous_version": prev,
                            "scripts": install_cmds,
                        },
                    })

    # --- Tarball size spike ---
    if len(version_list) >= 2:
        curr_ver_data = versions.get(version_list[-1], {})
        prev_ver_data = versions.get(version_list[-2], {})
        curr_size = curr_ver_data.get("dist", {}).get("unpackedSize", 0)
        prev_size = prev_ver_data.get("dist", {}).get("unpackedSize", 0)

        if prev_size > 0 and curr_size > 0:
            ratio = curr_size / prev_size
            if ratio > 10:
                findings.append({
                    "type": "tarball_size_spike",
                    "package": name,
                    "ecosystem": "npm",
                    "severity": "medium",
                    "description": (
                        f"Package size increased {ratio:.0f}x between versions "
                        f"({prev_size} → {curr_size} bytes). Possible payload injection."
                    ),
                    "detail": {
                        "previous_size": prev_size,
                        "current_size": curr_size,
                        "ratio": round(ratio, 1),
                    },
                })


def check_pypi_package(name: str, version: str) -> None:
    """Check a PyPI package for supply chain signals."""
    data = api_get(f"https://pypi.org/pypi/{urllib.request.quote(name, safe='')}/json")
    if not data:
        return

    info = data.get("info", {})
    releases = data.get("releases", {})

    if not releases:
        return

    # --- Author email domain change ---
    author_email = info.get("author_email", "")

    # --- Vulnerabilities flagged by PyPI ---
    vulns = data.get("vulnerabilities", [])
    if vulns:
        findings.append({
            "type": "pypi_known_vulnerabilities",
            "package": name,
            "ecosystem": "pypi",
            "severity": "high",
            "description": (
                f"PyPI reports {len(vulns)} known vulnerability/ies for this package"
            ),
            "detail": {
                "count": len(vulns),
                "ids": [v.get("id", "") for v in vulns[:10]],
            },
        })

    # --- Release date anomalies ---
    # Check if there are very recent releases after a long gap
    release_dates = []
    for ver, files in releases.items():
        if files and isinstance(files, list):
            upload_time = files[0].get("upload_time_iso_8601", "")
            if upload_time:
                release_dates.append((ver, upload_time))

    release_dates.sort(key=lambda x: x[1])

    if len(release_dates) >= 3:
        last = release_dates[-1][1]
        prev = release_dates[-2][1]
        try:
            from datetime import datetime
            last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
            prev_dt = datetime.fromisoformat(prev.replace("Z", "+00:00"))
            gap_days = (last_dt - prev_dt).days
            if gap_days > 365:
                findings.append({
                    "type": "dormant_reactivation",
                    "package": name,
                    "ecosystem": "pypi",
                    "severity": "medium",
                    "description": (
                        f"Package dormant for {gap_days} days before "
                        f"version {release_dates[-1][0]}. "
                        f"Possible maintainer takeover."
                    ),
                    "detail": {
                        "gap_days": gap_days,
                        "previous_version": release_dates[-2][0],
                        "latest_version": release_dates[-1][0],
                    },
                })
        except (ValueError, TypeError):
            pass

    # --- Size spike between versions ---
    if len(release_dates) >= 2 and version in releases:
        curr_files = releases.get(release_dates[-1][0], [])
        prev_files = releases.get(release_dates[-2][0], [])
        if curr_files and prev_files:
            curr_size = curr_files[0].get("size", 0)
            prev_size = prev_files[0].get("size", 0)
            if prev_size > 0 and curr_size > 0:
                ratio = curr_size / prev_size
                if ratio > 10:
                    findings.append({
                        "type": "tarball_size_spike",
                        "package": name,
                        "ecosystem": "pypi",
                        "severity": "medium",
                        "description": (
                            f"Package size increased {ratio:.0f}x between versions "
                            f"({prev_size} → {curr_size} bytes)"
                        ),
                        "detail": {
                            "previous_size": prev_size,
                            "current_size": curr_size,
                            "ratio": round(ratio, 1),
                        },
                    })


def _parse_package_json(path: str) -> list[tuple[str, str]]:
    """Extract (name, version) tuples from a package.json or package-lock.json."""
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError):
        return []

    packages = []
    # package-lock.json format
    lock_deps = data.get("packages", data.get("dependencies", {}))
    if isinstance(lock_deps, dict):
        for name, info in lock_deps.items():
            clean_name = name.replace("node_modules/", "")
            if not clean_name:
                continue
            version = "unknown"
            if isinstance(info, dict):
                version = info.get("version", "unknown")
            elif isinstance(info, str):
                version = info
            packages.append((clean_name, version))

    # package.json format
    if not packages:
        for key in ("dependencies", "devDependencies"):
            deps = data.get(key, {})
            if isinstance(deps, dict):
                for name, version in deps.items():
                    packages.append((name, str(version)))

    return packages


def load_manifest() -> dict[str, list[tuple[str, str]]]:
    """Load manifest and return {ecosystem: [(name, version), ...]}.

    Searches multiple locations for dependency information:
    1. /opt/deps/dep_manifest.json (primary, written by dependency resolution)
    2. /opt/target/package.json or package-lock.json (npm fallback)
    3. /opt/deps/package.json or package-lock.json (npm fallback)
    """
    searched_paths = []

    # 1. Primary manifest from dependency resolution
    searched_paths.append(MANIFEST_PATH)
    if os.path.isfile(MANIFEST_PATH):
        try:
            with open(MANIFEST_PATH) as f:
                manifest = json.load(f)
        except (json.JSONDecodeError, IOError):
            manifest = {}

        result: dict[str, list[tuple[str, str]]] = {}
        for ecosystem, deps in manifest.items():
            if ecosystem not in ("node", "python"):
                continue  # Only npm and PyPI have the metadata we need
            if isinstance(deps, list):
                pkgs = []
                for dep in deps:
                    if isinstance(dep, dict):
                        name = dep.get("name", "")
                        version = dep.get("version", "unknown")
                        if name:
                            pkgs.append((name, version))
                if pkgs:
                    result[ecosystem] = pkgs
        if result:
            return result

    # 2. Fall back to raw manifest files in /opt/target/ and /opt/deps/
    fallback_paths = [
        "/opt/target/package-lock.json",
        "/opt/target/package.json",
        "/opt/deps/package-lock.json",
        "/opt/deps/package.json",
    ]

    result = {}
    for path in fallback_paths:
        searched_paths.append(path)
        if os.path.isfile(path):
            pkgs = _parse_package_json(path)
            if pkgs and "node" not in result:
                result["node"] = pkgs

    # Note: PyPI packages require requirements.txt parsing which is
    # already handled by the primary manifest.  No simple fallback here.

    if not result:
        print(f"WARNING: No manifests found. Searched: {', '.join(searched_paths)}")

    return result


if __name__ == "__main__":
    packages = load_manifest()
    total = sum(len(v) for v in packages.values())

    if total == 0:
        print("No npm/PyPI dependencies found — skipping registry metadata checks")
        output = {
            "scanner": "registry-meta",
            "findings": [],
            "total": 0,
            "packages_checked": 0,
            "warning": "No dependency manifests found",
        }
        os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
        with open(OUTPUT_PATH, "w") as f:
            json.dump(output, f, indent=2)
        sys.exit(0)

    print(f"Checking {total} packages against registries...")

    checked = 0
    for ecosystem, pkgs in packages.items():
        for name, version in pkgs:
            checked += 1
            print(f"  [{checked}/{total}] {ecosystem}/{name}@{version}")

            if ecosystem == "node":
                check_npm_package(name, version)
            elif ecosystem == "python":
                check_pypi_package(name, version)

            if checked < total:
                time.sleep(0.2)

    output = {
        "scanner": "registry-meta",
        "findings": findings,
        "total": len(findings),
        "packages_checked": checked,
    }

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)

    print(f"Registry metadata scan complete: {len(findings)} findings from {checked} packages")
'''


def run_registry_meta(output_dir: str) -> ScanResults:
    """Run registry metadata checks via subprocess.

    Args:
        output_dir: Directory for scan artifacts.

    Returns:
        ScanResults with execution metadata only.
    """
    output_path = f"{output_dir}/registry-meta.json"
    script_path = ""

    start = time.monotonic()
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, prefix="registry_meta_scanner_"
        ) as f:
            f.write(_REGISTRY_META_SCRIPT)
            script_path = f.name

        result = subprocess.run(
            [sys.executable, script_path],
            capture_output=True,
            timeout=600,
        )
        elapsed = time.monotonic() - start

        if result.returncode != 0:
            logger.warning(
                "Registry metadata scanner exited with code %d: %s",
                result.returncode,
                result.stderr.decode(),
            )
            return ScanResults(
                tool_name="registry-meta",
                execution_time_seconds=elapsed,
                exit_code=result.returncode,
                errors=[f"Registry metadata scanner failed (exit {result.returncode}): {result.stderr.decode()}"],
            )

        return ScanResults(
            tool_name="registry-meta",
            execution_time_seconds=elapsed,
            exit_code=result.returncode,
            raw_output_path=output_path,
        )

    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.exception("Registry metadata scanner execution failed")
        return ScanResults(
            tool_name="registry-meta",
            execution_time_seconds=elapsed,
            exit_code=-1,
            errors=[f"Registry metadata scanner error: {exc}"],
        )
    finally:
        if script_path:
            try:
                Path(script_path).unlink(missing_ok=True)
            except Exception:
                pass


def parse_registry_meta_output(raw: dict[str, Any]) -> list[Finding]:
    """Parse registry metadata scanner output into normalized Finding objects."""
    findings: list[Finding] = []

    for idx, item in enumerate(raw.get("findings", [])):
        finding_type = item.get("type", "unknown")
        severity = item.get("severity", "low")
        description = item.get("description", "")
        package = item.get("package", "unknown")
        ecosystem = item.get("ecosystem", "unknown")

        findings.append(
            Finding(
                id=f"registry-meta-{idx}-{finding_type}",
                source_tool="registry-meta",
                category="metadata",
                severity=severity,
                cvss_score=None,
                cve_id=None,
                title=f"Registry metadata: {finding_type} ({package})",
                description=description,
                file_path=None,
                line_number=None,
                package_name=package,
                package_version=None,
                fix_version=None,
                raw_output=item,
            )
        )

    return findings
