"""Firewall rule generation for Lima VM egress control."""

from __future__ import annotations


# Whitelisted destinations that the VM is allowed to reach.
WHITELISTED_DOMAINS: list[str] = [
    "api.anthropic.com",
    "github.com",
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
    "crates.io",
    "static.crates.io",
    "proxy.golang.org",
    "api.first.org",
    "services.nvd.nist.gov",
    "www.cisa.gov",
]


def generate_firewall_rules(phase: str = "full") -> str:
    """Generate an iptables firewall script for the VM.

    The generated script enforces egress filtering:
      - DNS (UDP port 53) is always allowed.
      - Whitelisted destinations are allowed on ports 80 and 443.
      - All other outbound traffic is dropped and logged with a "BLOCKED:" prefix.
      - Default OUTPUT policy is DROP.

    Args:
        phase: Firewall phase. Currently only "full" is implemented.
            Future phases (e.g., "download" for a more permissive download phase)
            can be added here.

    Returns:
        A complete shell script string that applies the iptables rules.
    """
    lines: list[str] = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        "# Flush existing rules",
        "iptables -F OUTPUT",
        "iptables -F INPUT",
        "",
        "# Allow loopback",
        "iptables -A OUTPUT -o lo -j ACCEPT",
        "iptables -A INPUT -i lo -j ACCEPT",
        "",
        "# Allow established and related connections",
        "iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "",
        "# Allow DNS (UDP 53)",
        "iptables -A OUTPUT -p udp --dport 53 -j ACCEPT",
        "",
    ]

    domains = _domains_for_phase(phase)

    # Allow HTTPS (443) and HTTP (80) to whitelisted destinations
    for domain in domains:
        lines.append(f"# Allow {domain}")
        lines.append(
            f"iptables -A OUTPUT -p tcp --dport 443 -d {domain} -j ACCEPT"
        )
        lines.append(
            f"iptables -A OUTPUT -p tcp --dport 80 -d {domain} -j ACCEPT"
        )
        lines.append("")

    # Log and drop everything else
    lines.extend([
        "# Log blocked connections",
        'iptables -A OUTPUT -j LOG --log-prefix "BLOCKED: " --log-level 4',
        "",
        "# Default OUTPUT policy: DROP",
        "iptables -P OUTPUT DROP",
        "",
        "echo 'Firewall rules applied.'",
    ])

    return "\n".join(lines) + "\n"


def _domains_for_phase(phase: str) -> list[str]:
    """Return the list of whitelisted domains for a given phase.

    Args:
        phase: The firewall phase.

    Returns:
        List of domain strings to whitelist.
    """
    if phase == "full":
        return list(WHITELISTED_DOMAINS)

    # Future: a "download" phase could include additional package registries,
    # and an "analysis" phase could restrict to only the API and vuln DBs.
    return list(WHITELISTED_DOMAINS)
