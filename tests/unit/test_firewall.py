"""Tests for threat_scanner.vm.firewall."""

from __future__ import annotations

from threat_scanner.vm.firewall import WHITELISTED_DOMAINS, generate_firewall_rules


class TestGenerateFirewallRules:
    def test_valid_bash(self):
        script = generate_firewall_rules()
        assert script.startswith("#!/usr/bin/env bash\n")
        assert "set -euo pipefail" in script

    def test_allows_loopback(self):
        script = generate_firewall_rules()
        assert "-o lo -j ACCEPT" in script

    def test_allows_dns(self):
        script = generate_firewall_rules()
        assert "--dport 53" in script
        assert "-p udp" in script

    def test_whitelists_all_domains(self):
        script = generate_firewall_rules()
        for domain in WHITELISTED_DOMAINS:
            assert domain in script
            assert f"-d {domain} -j ACCEPT" in script

    def test_drops_by_default(self):
        script = generate_firewall_rules()
        assert "iptables -P OUTPUT DROP" in script

    def test_logs_blocked(self):
        script = generate_firewall_rules()
        assert 'LOG --log-prefix "BLOCKED: "' in script

    def test_static_crates_io_included(self):
        assert "static.crates.io" in WHITELISTED_DOMAINS

    def test_https_and_http_rules(self):
        script = generate_firewall_rules()
        for domain in WHITELISTED_DOMAINS:
            assert f"--dport 443 -d {domain}" in script
            assert f"--dport 80 -d {domain}" in script
