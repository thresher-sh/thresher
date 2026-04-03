#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# ///
"""Recalculate totals in remediations.json from per-repo data."""

import json
import re
import subprocess
from pathlib import Path

CVE_PATTERN = re.compile(r"\b(CVE-\d{4}-\d+|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b")


def _repo_root() -> Path:
    """Find the repo root via git."""
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True, text=True, check=True,
    )
    return Path(result.stdout.strip())


def count_cves(report_path: Path) -> int:
    """Count unique CVE/GHSA identifiers in a PR summary file."""
    if not report_path.exists():
        return 0
    text = report_path.read_text()
    return len(set(CVE_PATTERN.findall(text)))


def main():
    root = _repo_root()
    docs_data = root / "docs" / "data"
    remediations_file = docs_data / "remediations.json"
    prs_dir = docs_data / "prs"

    data = json.loads(remediations_file.read_text())
    entries = data["remediations"]

    # Count CVEs from PR summary files and store on each entry
    for entry in entries:
        report_rel = entry.get("report_url", "")
        # report_url is relative like "data/prs/foo.md", resolve from docs/
        report_path = prs_dir / Path(report_rel).name
        entry["remediations"]["cves_resolved"] = count_cves(report_path)

    totals = {
        "projects_scanned": len(entries),
        "total_findings": sum(
            e["findings"]["total_deterministic"] + e["findings"]["total_ai"]
            for e in entries
        ),
        "total_critical": sum(e["findings"]["critical"] for e in entries),
        "total_high": sum(e["findings"]["high"] for e in entries),
        "total_medium": sum(e["findings"]["medium"] for e in entries),
        "total_supply_chain_findings": sum(
            e["findings"]["supply_chain"] for e in entries
        ),
        "total_app_security_fixes": sum(
            e["remediations"]["app_security_fixes"] for e in entries
        ),
        "total_secrets_remediated": sum(
            e["remediations"]["secrets_remediated"] for e in entries
        ),
        "total_ci_cd_fixes": sum(
            e["remediations"]["ci_cd_hardening"] for e in entries
        ),
        "total_dependency_upgrades": sum(
            e["remediations"]["dependency_upgrades"] for e in entries
        ),
        "total_cves_resolved": sum(
            e["remediations"]["cves_resolved"] for e in entries
        ),
    }

    data["totals"] = totals
    remediations_file.write_text(json.dumps(data, indent=2) + "\n")
    print(f"Updated totals for {totals['projects_scanned']} projects:")
    for k, v in totals.items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
