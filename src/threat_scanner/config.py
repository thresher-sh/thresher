"""Configuration management for threat-scanner."""

from __future__ import annotations

import json
import logging
import os
import subprocess
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

KEYCHAIN_SERVICE = "Claude Code-credentials"


def _get_oauth_token_from_keychain() -> str:
    """Extract Claude OAuth token from the macOS Keychain.

    Returns the access token string, or empty string if unavailable.
    """
    try:
        result = subprocess.run(
            ["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-w"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            return ""
        creds = json.loads(result.stdout.strip())
        token = creds.get("claudeAiOauth", {}).get("accessToken", "")
        if token:
            logger.debug("OAuth token found in macOS Keychain")
        return token
    except (json.JSONDecodeError, subprocess.TimeoutExpired, FileNotFoundError):
        return ""


DEFAULT_CONFIG_PATH = Path("scanner.toml")


@dataclass
class VMConfig:
    cpus: int = 4
    memory: int = 8  # GB
    disk: int = 50  # GB


@dataclass
class ScanConfig:
    repo_url: str = ""
    depth: int = 2
    skip_ai: bool = False
    verbose: bool = False
    output_dir: str = "./scan-results"
    vm: VMConfig = field(default_factory=VMConfig)
    anthropic_api_key: str = ""
    oauth_token: str = ""
    model: str = "sonnet"
    log_dir: str = ""
    tmux: bool = True

    @property
    def has_ai_credentials(self) -> bool:
        """True if either an API key or OAuth token is available."""
        return bool(self.anthropic_api_key or self.oauth_token)

    def ai_env(self) -> dict[str, str]:
        """Build env dict with the appropriate AI credential.

        ANTHROPIC_API_KEY takes precedence over OAuth token.
        """
        env: dict[str, str] = {}
        if self.anthropic_api_key:
            env["ANTHROPIC_API_KEY"] = self.anthropic_api_key
        elif self.oauth_token:
            env["CLAUDE_CODE_OAUTH_TOKEN"] = self.oauth_token
        return env

    def validate(self) -> list[str]:
        errors = []
        if not self.repo_url:
            errors.append("repo_url is required")
        if not self.skip_ai and not self.has_ai_credentials:
            errors.append(
                "No AI credentials found. Set ANTHROPIC_API_KEY, "
                "log in with `claude login`, or use --skip-ai"
            )
        if self.depth < 1:
            errors.append("depth must be >= 1")
        return errors


def load_config(
    repo_url: str,
    depth: int | None = None,
    skip_ai: bool = False,
    verbose: bool = False,
    output_dir: str | None = None,
    cpus: int | None = None,
    memory: int | None = None,
    disk: int | None = None,
    config_path: Path | None = None,
) -> ScanConfig:
    """Build ScanConfig from config file + CLI args + env vars. CLI args take precedence."""
    config = ScanConfig()

    # Load config file if it exists
    path = config_path or DEFAULT_CONFIG_PATH
    if path.exists():
        with open(path, "rb") as f:
            data = tomllib.load(f)
        if "depth" in data:
            config.depth = data["depth"]
        if "model" in data:
            config.model = data["model"]
        if "output_dir" in data:
            config.output_dir = data["output_dir"]
        if "log_dir" in data:
            config.log_dir = data["log_dir"]
        if "tmux" in data:
            config.tmux = data["tmux"]
        vm_data = data.get("vm", {})
        if "cpus" in vm_data:
            config.vm.cpus = vm_data["cpus"]
        if "memory" in vm_data:
            config.vm.memory = vm_data["memory"]
        if "disk" in vm_data:
            config.vm.disk = vm_data["disk"]

    # CLI args override config file
    config.repo_url = repo_url
    if depth is not None:
        config.depth = depth
    config.skip_ai = skip_ai
    config.verbose = verbose
    if output_dir is not None:
        config.output_dir = output_dir
    if cpus is not None:
        config.vm.cpus = cpus
    if memory is not None:
        config.vm.memory = memory
    if disk is not None:
        config.vm.disk = disk

    # API key from env, with OAuth keychain fallback
    config.anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not config.anthropic_api_key and not config.skip_ai:
        config.oauth_token = _get_oauth_token_from_keychain()

    return config
