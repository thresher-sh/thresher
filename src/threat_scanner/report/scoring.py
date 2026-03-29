"""Composite risk scoring: EPSS, CISA KEV, and priority computation."""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

# EPSS API endpoint — whitelisted in VM firewall
EPSS_API_URL = "https://api.first.org/data/v1/epss"

# CISA KEV catalog URL
KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)

# Maximum CVEs per EPSS batch request
EPSS_BATCH_SIZE = 100


def fetch_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """Query the FIRST EPSS API for exploitation probability scores.

    Batches requests to reduce API calls. Returns a mapping of
    CVE ID -> exploitation probability (0.0 to 1.0).

    Handles API errors gracefully by returning an empty dict on failure.
    """
    if not cve_ids:
        return {}

    scores: dict[str, float] = {}

    # De-duplicate while preserving order for predictable batching
    unique_cves = list(dict.fromkeys(cve_ids))

    for i in range(0, len(unique_cves), EPSS_BATCH_SIZE):
        batch = unique_cves[i : i + EPSS_BATCH_SIZE]
        try:
            scores.update(_fetch_epss_batch(batch))
        except Exception:
            logger.warning(
                "EPSS batch request failed for CVEs %d-%d, skipping",
                i,
                i + len(batch),
                exc_info=True,
            )

    return scores


def _fetch_epss_batch(cve_ids: list[str]) -> dict[str, float]:
    """Fetch EPSS scores for a single batch of CVE IDs."""
    cve_param = ",".join(cve_ids)
    url = f"{EPSS_API_URL}?cve={cve_param}"

    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))

    results: dict[str, float] = {}
    for entry in data.get("data", []):
        cve_id = entry.get("cve")
        epss_score = entry.get("epss")
        if cve_id and epss_score is not None:
            try:
                results[cve_id] = float(epss_score)
            except (ValueError, TypeError):
                logger.debug("Invalid EPSS score for %s: %s", cve_id, epss_score)

    return results


def load_kev_catalog() -> set[str]:
    """Download the CISA Known Exploited Vulnerabilities catalog.

    Returns a set of CVE IDs that are actively exploited in the wild.
    Returns an empty set on failure.
    """
    try:
        req = urllib.request.Request(
            KEV_CATALOG_URL, headers={"Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        kev_cves: set[str] = set()
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID")
            if cve_id:
                kev_cves.add(cve_id)

        logger.info("Loaded %d CVEs from CISA KEV catalog", len(kev_cves))
        return kev_cves

    except Exception:
        logger.warning("Failed to load CISA KEV catalog", exc_info=True)
        return set()


def compute_composite_priority(
    finding: dict[str, Any],
    epss: dict[str, float],
    kev: set[str],
) -> str:
    """Compute composite priority level for a single finding.

    Priority levels (highest to lowest):
        P0       - In CISA KEV, or AI confidence >= 90 for exfiltration/backdoor
        critical - CVSS >= 9.0, EPSS > 90th percentile, or AI risk 9-10 confirmed
        high     - CVSS 7.0-8.9, EPSS > 75th percentile, or AI risk 7-8
        medium   - CVSS 4.0-6.9, EPSS > 50th percentile, or AI risk 4-6
        low      - Everything else
    """
    cve_id = finding.get("cve_id", "")
    cvss_score: float = finding.get("cvss_score") or 0.0
    ai_risk_score: float = finding.get("ai_risk_score") or 0.0
    ai_confidence: float = finding.get("ai_confidence") or 0.0
    ai_category: str = finding.get("ai_category", "")
    adversarial_status: str = finding.get("adversarial_status", "")
    epss_score: float = epss.get(cve_id, 0.0) if cve_id else 0.0

    # -- P0: Emergency --
    # In CISA KEV
    if cve_id and cve_id in kev:
        return "P0"

    # AI confidence >= 90 for exfiltration or backdoor categories
    high_risk_categories = {"exfiltration", "backdoor", "trojan", "remote_code_execution"}
    if ai_confidence >= 90 and ai_category.lower() in high_risk_categories:
        return "P0"

    # -- Critical --
    if cvss_score >= 9.0:
        return "critical"

    # EPSS > 90th percentile (0.9 probability)
    if epss_score > 0.9:
        return "critical"

    # AI risk 9-10 confirmed by adversarial verification
    if ai_risk_score >= 9.0 and adversarial_status == "confirmed":
        return "critical"

    # -- High --
    if 7.0 <= cvss_score < 9.0:
        return "high"

    if epss_score > 0.75:
        return "high"

    if 7.0 <= ai_risk_score < 9.0:
        return "high"

    # -- Medium --
    if 4.0 <= cvss_score < 7.0:
        return "medium"

    if epss_score > 0.5:
        return "medium"

    if 4.0 <= ai_risk_score < 7.0:
        return "medium"

    # -- Low --
    return "low"


def enrich_findings(
    findings: list[dict[str, Any]],
    vm_name: str,
) -> list[dict[str, Any]]:
    """Enrich findings with EPSS scores, KEV status, and composite priority.

    Fetches EPSS scores for all CVEs, loads the CISA KEV catalog, then
    computes a composite priority for each finding. Returns the enriched
    findings list (each finding dict gets new keys added in-place).

    Args:
        findings: List of normalized finding dicts from scanners/AI.
        vm_name: Name of the VM (unused here but kept for interface
                 consistency — enrichment runs inside the VM with
                 network access to api.first.org).

    Returns:
        The same findings list with added enrichment fields.
    """
    # Collect all CVE IDs from findings
    cve_ids = [
        f["cve_id"] for f in findings if f.get("cve_id") and f["cve_id"].startswith("CVE-")
    ]

    # Fetch EPSS scores (batched)
    epss = fetch_epss_scores(cve_ids)
    logger.info("Fetched EPSS scores for %d / %d CVEs", len(epss), len(cve_ids))

    # Load CISA KEV catalog
    kev = load_kev_catalog()

    # Enrich each finding
    for finding in findings:
        cve_id = finding.get("cve_id", "")

        # Add EPSS score
        finding["epss_score"] = epss.get(cve_id, None) if cve_id else None

        # Add EPSS percentile (the score itself is a percentile-like probability)
        finding["epss_percentile"] = finding["epss_score"]

        # Add KEV status
        finding["in_kev"] = cve_id in kev if cve_id else False

        # Compute composite priority
        finding["composite_priority"] = compute_composite_priority(finding, epss, kev)

    return findings
