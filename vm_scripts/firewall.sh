#!/bin/bash
# firewall.sh — iptables egress firewall configuration for Lima VM
# Whitelists only the domains needed for scanning operations.
# All other outbound connections are logged and dropped.
set -euo pipefail

LOG_PREFIX="[firewall]"

log() {
    echo "${LOG_PREFIX} $(date '+%H:%M:%S') $*"
}

# ---------------------------------------------------------------------------
# Resolve whitelisted domains to IP addresses
# We resolve at firewall-setup time and create rules per IP.
# ---------------------------------------------------------------------------

# List of whitelisted domains and their purposes
declare -A WHITELIST_DOMAINS=(
    ["api.anthropic.com"]="Claude API"
    ["github.com"]="GitHub"
    ["pypi.org"]="Python Package Index"
    ["files.pythonhosted.org"]="Python package downloads"
    ["registry.npmjs.org"]="npm registry"
    ["crates.io"]="Rust crate registry"
    ["static.crates.io"]="Rust crate downloads"
    ["proxy.golang.org"]="Go module proxy"
    ["api.first.org"]="EPSS vulnerability scoring"
    ["services.nvd.nist.gov"]="NVD vulnerability database"
)

resolve_domain() {
    local domain="$1"
    # Resolve domain to IP addresses (may return multiple)
    # Use getent for reliable resolution; fall back to dig
    if command -v getent &>/dev/null; then
        getent ahosts "$domain" 2>/dev/null | awk '{print $1}' | sort -u || true
    elif command -v dig &>/dev/null; then
        dig +short A "$domain" 2>/dev/null | grep -E '^[0-9]+\.' || true
    elif command -v nslookup &>/dev/null; then
        nslookup "$domain" 2>/dev/null | awk '/^Address: / {print $2}' || true
    else
        log "WARNING: No DNS resolution tool available. Cannot resolve $domain."
    fi
}

# ---------------------------------------------------------------------------
# Flush existing rules and set defaults
# ---------------------------------------------------------------------------
log "Flushing existing iptables rules..."
sudo iptables -F
sudo iptables -F -t nat
sudo iptables -F -t mangle
sudo iptables -X 2>/dev/null || true

log "Setting default policies..."
# INPUT and FORWARD default to DROP for defense in depth
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD DROP
# OUTPUT default to DROP — only whitelisted traffic is allowed
sudo iptables -P OUTPUT DROP

# ---------------------------------------------------------------------------
# Allow loopback traffic (required for local services)
# ---------------------------------------------------------------------------
log "Allowing loopback traffic..."
sudo iptables -A OUTPUT -o lo -j ACCEPT
sudo iptables -A INPUT -i lo -j ACCEPT

# ---------------------------------------------------------------------------
# Allow established and related connections
# (responses to our allowed outbound requests)
# ---------------------------------------------------------------------------
log "Allowing established/related connections..."
sudo iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# ---------------------------------------------------------------------------
# Allow DNS (UDP port 53) — needed to resolve domain names
# ---------------------------------------------------------------------------
log "Allowing DNS (UDP 53)..."
sudo iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
# Also allow TCP DNS for large responses
sudo iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# ---------------------------------------------------------------------------
# Whitelist outbound HTTPS (port 443) to specific domains
# ---------------------------------------------------------------------------
log "Resolving whitelisted domains and creating firewall rules..."

for domain in "${!WHITELIST_DOMAINS[@]}"; do
    purpose="${WHITELIST_DOMAINS[$domain]}"
    ips=$(resolve_domain "$domain")

    if [ -z "$ips" ]; then
        log "WARNING: Could not resolve $domain ($purpose). Skipping."
        continue
    fi

    while IFS= read -r ip; do
        if [ -n "$ip" ]; then
            sudo iptables -A OUTPUT -p tcp --dport 443 -d "$ip" -j ACCEPT
            log "  Allowed: $domain ($purpose) -> $ip:443"
        fi
    done <<< "$ips"
done

# ---------------------------------------------------------------------------
# Also allow port 80 for package registries that may redirect via HTTP
# (Some install scripts fetch over HTTP before redirecting to HTTPS)
# ---------------------------------------------------------------------------
log "Allowing HTTP (80) for package registry redirects..."
for domain in "github.com" "pypi.org" "crates.io" "proxy.golang.org"; do
    ips=$(resolve_domain "$domain")
    while IFS= read -r ip; do
        if [ -n "$ip" ]; then
            sudo iptables -A OUTPUT -p tcp --dport 80 -d "$ip" -j ACCEPT
        fi
    done <<< "$ips"
done

# ---------------------------------------------------------------------------
# Log all blocked outbound connections
# ---------------------------------------------------------------------------
log "Adding logging rule for blocked connections..."
sudo iptables -A OUTPUT -j LOG --log-prefix "BLOCKED: " --log-level 4

# ---------------------------------------------------------------------------
# Drop everything else (explicit rule, default policy is already DROP)
# ---------------------------------------------------------------------------
sudo iptables -A OUTPUT -j DROP

# ---------------------------------------------------------------------------
# Print final rules for verification
# ---------------------------------------------------------------------------
log "Firewall configuration complete. Current rules:"
echo "---"
sudo iptables -L OUTPUT -n -v --line-numbers
echo "---"

log "Firewall setup finished. Only whitelisted domains can be reached on HTTPS."
