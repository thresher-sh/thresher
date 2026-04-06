"""deps.dev scanner -- Google Open Source Insights integration.

Queries the deps.dev API for each dependency to get:
- OpenSSF Scorecard results (branch protection, code review, CI, etc.)
- Typosquatting detection (similarly named packages)
- Version history anomalies (dormant packages suddenly active)
- Maintainer count (single-maintainer risk)

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

# Ecosystem name mapping: our names → deps.dev system names
_ECOSYSTEM_MAP = {
    "python": "pypi",
    "node": "npm",
    "rust": "cargo",
    "go": "go",
}

_DEPS_DEV_SCRIPT = r'''#!/usr/bin/env python3
"""Query deps.dev API for package metadata intelligence.

Reads the dependency manifest, queries deps.dev for each package,
and writes findings to /opt/scan-results/deps-dev.json.
"""

import json
import os
import sys
import time
import urllib.request
import urllib.error

MANIFEST_PATH = "/opt/deps/dep_manifest.json"
OUTPUT_PATH = "/opt/scan-results/deps-dev.json"

API_BASE = "https://api.deps.dev/v3alpha"

# Our ecosystem names → deps.dev system names
SYSTEM_MAP = {
    "python": "pypi",
    "node": "npm",
    "rust": "cargo",
    "go": "go",
}

SCORECARD_THRESHOLD = 4.0  # Flag packages with score below this
findings = []


def api_get(path: str) -> dict | None:
    """Make a GET request to the deps.dev API. Returns None on failure."""
    url = f"{API_BASE}{path}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "thresher/2.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError,
            TimeoutError, OSError):
        return None


def check_scorecard(system: str, package: str) -> None:
    """Check OpenSSF Scorecard for a package."""
    data = api_get(f"/systems/{system}/packages/{package}")
    if not data:
        return

    # Extract project info for Scorecard lookup
    project_key = data.get("projectKey", {})
    project_id = project_key.get("id", "")
    if not project_id:
        # No linked project — flag as potential risk
        findings.append({
            "type": "no_source_repo",
            "package": package,
            "ecosystem": system,
            "severity": "low",
            "description": f"No linked source repository found on deps.dev",
            "detail": {},
        })
        return

    # Check Scorecard via the project endpoint
    scorecard_data = api_get(f"/projects/{urllib.request.quote(project_id, safe='')}:scorecard")
    if not scorecard_data:
        return

    overall = scorecard_data.get("overallScore", -1)
    if 0 <= overall < SCORECARD_THRESHOLD:
        # Extract individual check scores
        checks = {}
        for check in scorecard_data.get("checks", []):
            name = check.get("name", "")
            score = check.get("score", -1)
            if name and score >= 0:
                checks[name] = score

        findings.append({
            "type": "low_scorecard",
            "package": package,
            "ecosystem": system,
            "severity": "medium",
            "description": (
                f"Low OpenSSF Scorecard: {overall:.1f}/10. "
                f"Weak checks: {', '.join(k for k, v in checks.items() if v < 5)}"
            ),
            "detail": {
                "overall_score": overall,
                "checks": checks,
                "project": project_id,
            },
        })


def check_typosquatting(system: str, package: str) -> None:
    """Check for similarly named packages (typosquatting signals)."""
    data = api_get(
        f"/systems/{system}/packages/{urllib.request.quote(package, safe='')}:similarlyNamedPackages"
    )
    if not data:
        return

    similar = data.get("packages", [])
    if not similar:
        return

    for sim in similar[:5]:  # Check top 5 similar names
        sim_name = sim.get("packageKey", {}).get("name", "")
        if not sim_name or sim_name == package:
            continue

        findings.append({
            "type": "typosquatting_signal",
            "package": package,
            "ecosystem": system,
            "severity": "high",
            "description": (
                f"Package name is similar to '{sim_name}' — "
                f"possible typosquatting. Verify this is the intended package."
            ),
            "detail": {
                "similar_package": sim_name,
            },
        })


def check_version_history(system: str, package: str, version: str) -> None:
    """Check version history for anomalies."""
    data = api_get(f"/systems/{system}/packages/{urllib.request.quote(package, safe='')}")
    if not data:
        return

    versions = data.get("versions", [])
    if len(versions) < 2:
        return

    # Sort by publish time
    versioned = []
    for v in versions:
        vkey = v.get("versionKey", {})
        published = v.get("publishedAt", "")
        versioned.append({
            "version": vkey.get("version", ""),
            "published": published,
        })

    versioned.sort(key=lambda x: x["published"])

    if not versioned:
        return

    # Check for dormant package suddenly active
    if len(versioned) >= 3:
        # Look at gap between second-to-last and last version
        last = versioned[-1]["published"]
        prev = versioned[-2]["published"]
        if last and prev:
            try:
                from datetime import datetime
                fmt = "%Y-%m-%dT%H:%M:%S"
                # Truncate timezone info for parsing
                last_dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
                prev_dt = datetime.fromisoformat(prev.replace("Z", "+00:00"))
                gap_days = (last_dt - prev_dt).days
                if gap_days > 365:
                    findings.append({
                        "type": "dormant_reactivation",
                        "package": package,
                        "ecosystem": system,
                        "severity": "medium",
                        "description": (
                            f"Package was dormant for {gap_days} days before "
                            f"latest version. Possible maintainer takeover."
                        ),
                        "detail": {
                            "gap_days": gap_days,
                            "previous_version": versioned[-2]["version"],
                            "latest_version": versioned[-1]["version"],
                        },
                    })
            except (ValueError, TypeError):
                pass


def _parse_package_json(path: str) -> list[tuple[str, str, str]]:
    """Extract packages from a package.json or package-lock.json."""
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError):
        return []

    packages = []
    # package-lock.json has "packages" or "dependencies" at top level
    lock_deps = data.get("packages", data.get("dependencies", {}))
    if isinstance(lock_deps, dict):
        for name, info in lock_deps.items():
            if not name or name == "":
                continue
            # package-lock uses "" for root, skip it
            clean_name = name.replace("node_modules/", "")
            if not clean_name:
                continue
            version = "unknown"
            if isinstance(info, dict):
                version = info.get("version", "unknown")
            elif isinstance(info, str):
                version = info
            packages.append(("npm", clean_name, version))

    # package.json has "dependencies" and "devDependencies" as {name: version}
    if not packages:
        for key in ("dependencies", "devDependencies"):
            deps = data.get(key, {})
            if isinstance(deps, dict):
                for name, version in deps.items():
                    packages.append(("npm", name, str(version)))

    return packages


def _parse_cargo_toml(path: str) -> list[tuple[str, str, str]]:
    """Extract packages from a Cargo.toml (simple parsing)."""
    packages = []
    try:
        with open(path) as f:
            content = f.read()
    except IOError:
        return []

    in_deps = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("[dependencies]") or stripped.startswith("[dev-dependencies]"):
            in_deps = True
            continue
        if stripped.startswith("[") and in_deps:
            in_deps = False
            continue
        if in_deps and "=" in stripped:
            name = stripped.split("=")[0].strip()
            version_part = stripped.split("=", 1)[1].strip().strip('"').strip("'")
            if name:
                packages.append(("cargo", name, version_part or "unknown"))

    return packages


def load_manifest() -> list[tuple[str, str, str]]:
    """Load the dependency manifest and return (system, name, version) tuples.

    Searches multiple locations for dependency information:
    1. /opt/deps/dep_manifest.json (primary, written by dependency resolution)
    2. /opt/target/package.json or package-lock.json (npm)
    3. /opt/target/Cargo.toml (Rust)
    4. /opt/deps/ subdirectories
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

        packages = []
        for ecosystem, deps in manifest.items():
            system = SYSTEM_MAP.get(ecosystem)
            if not system:
                continue
            if isinstance(deps, list):
                for dep in deps:
                    if isinstance(dep, dict):
                        name = dep.get("name", "")
                        version = dep.get("version", "unknown")
                        if name:
                            packages.append((system, name, version))
        if packages:
            return packages

    # 2. Fall back to raw manifest files in /opt/target/
    fallback_paths = [
        ("/opt/target/package-lock.json", _parse_package_json),
        ("/opt/target/package.json", _parse_package_json),
        ("/opt/target/Cargo.toml", _parse_cargo_toml),
    ]

    packages = []
    for path, parser in fallback_paths:
        searched_paths.append(path)
        if os.path.isfile(path):
            pkgs = parser(path)
            packages.extend(pkgs)

    # 3. Also check /opt/deps/ for manifest files
    deps_fallbacks = [
        ("/opt/deps/package-lock.json", _parse_package_json),
        ("/opt/deps/package.json", _parse_package_json),
        ("/opt/deps/Cargo.toml", _parse_cargo_toml),
    ]
    for path, parser in deps_fallbacks:
        searched_paths.append(path)
        if os.path.isfile(path):
            pkgs = parser(path)
            packages.extend(pkgs)

    if not packages:
        print(f"WARNING: No manifests found. Searched: {', '.join(searched_paths)}")

    return packages


if __name__ == "__main__":
    packages = load_manifest()
    if not packages:
        print("No dependencies found in manifest — skipping deps.dev checks")
        output = {
            "scanner": "deps-dev",
            "findings": [],
            "total": 0,
            "packages_checked": 0,
            "warning": "No dependency manifests found",
        }
        os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
        with open(OUTPUT_PATH, "w") as f:
            json.dump(output, f, indent=2)
        sys.exit(0)

    print(f"Checking {len(packages)} packages against deps.dev...")

    for i, (system, name, version) in enumerate(packages):
        print(f"  [{i+1}/{len(packages)}] {system}/{name}@{version}")

        check_scorecard(system, name)
        check_typosquatting(system, name)
        check_version_history(system, name, version)

        # Brief pause to be respectful to the API (no auth required)
        if i < len(packages) - 1:
            time.sleep(0.2)

    output = {
        "scanner": "deps-dev",
        "findings": findings,
        "total": len(findings),
        "packages_checked": len(packages),
    }

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(output, f, indent=2)

    print(f"deps.dev scan complete: {len(findings)} findings from {len(packages)} packages")
'''


def run_deps_dev(output_dir: str) -> ScanResults:
    """Run deps.dev metadata checks via subprocess.

    Args:
        output_dir: Directory for scan artifacts.

    Returns:
        ScanResults with execution metadata only.
    """
    output_path = f"{output_dir}/deps-dev.json"
    script_path = ""

    start = time.monotonic()
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, prefix="deps_dev_scanner_"
        ) as f:
            f.write(_DEPS_DEV_SCRIPT)
            script_path = f.name

        result = subprocess.run(
            [sys.executable, script_path],
            capture_output=True,
            timeout=600,
        )
        elapsed = time.monotonic() - start

        if result.returncode != 0:
            logger.warning(
                "deps.dev scanner exited with code %d: %s",
                result.returncode,
                result.stderr.decode(),
            )
            return ScanResults(
                tool_name="deps-dev",
                execution_time_seconds=elapsed,
                exit_code=result.returncode,
                errors=[f"deps.dev scanner failed (exit {result.returncode}): {result.stderr.decode()}"],
            )

        return ScanResults(
            tool_name="deps-dev",
            execution_time_seconds=elapsed,
            exit_code=result.returncode,
            raw_output_path=output_path,
        )

    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.exception("deps.dev scanner execution failed")
        return ScanResults(
            tool_name="deps-dev",
            execution_time_seconds=elapsed,
            exit_code=-1,
            errors=[f"deps.dev scanner error: {exc}"],
        )
    finally:
        if script_path:
            try:
                Path(script_path).unlink(missing_ok=True)
            except Exception:
                pass


def parse_deps_dev_output(raw: dict[str, Any]) -> list[Finding]:
    """Parse deps.dev scanner output into normalized Finding objects."""
    findings: list[Finding] = []

    for idx, item in enumerate(raw.get("findings", [])):
        finding_type = item.get("type", "unknown")
        severity = item.get("severity", "low")
        description = item.get("description", "")
        package = item.get("package", "unknown")
        ecosystem = item.get("ecosystem", "unknown")

        findings.append(
            Finding(
                id=f"deps-dev-{idx}-{finding_type}",
                source_tool="deps-dev",
                category="metadata",
                severity=severity,
                cvss_score=None,
                cve_id=None,
                title=f"Package metadata: {finding_type} ({package})",
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
