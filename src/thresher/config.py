"""Configuration management for thresher."""

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


DEFAULT_CONFIG_PATH = Path("thresher.toml")


@dataclass
class VMConfig:
    cpus: int = 4
    memory: int = 8  # GB
    disk: int = 50  # GB


@dataclass
class LimitsConfig:
    """Configurable size limits for host boundary hardening."""
    max_json_size_mb: int = 10       # Max JSON payload from VM (MB)
    max_file_size_mb: int = 50       # Max individual file in report copy (MB)
    max_copy_size_mb: int = 500      # Max total size of report copy (MB)
    max_stdout_mb: int = 50          # Max stdout from ssh_exec before kill (MB)
    max_concurrent_ssh: int = 8      # Max parallel SSH sessions to VM

    @property
    def max_json_size_bytes(self) -> int:
        return self.max_json_size_mb * 1024 * 1024

    @property
    def max_file_size_bytes(self) -> int:
        return self.max_file_size_mb * 1024 * 1024

    @property
    def max_copy_size_bytes(self) -> int:
        return self.max_copy_size_mb * 1024 * 1024

    @property
    def max_stdout_bytes(self) -> int:
        return self.max_stdout_mb * 1024 * 1024


@dataclass
class ScanConfig:
    repo_url: str = ""
    depth: int = 2
    skip_ai: bool = False
    verbose: bool = False
    output_dir: str = "./thresher-reports"
    vm: VMConfig = field(default_factory=VMConfig)
    limits: LimitsConfig = field(default_factory=LimitsConfig)
    anthropic_api_key: str = ""
    oauth_token: str = ""
    model: str = "sonnet"
    log_dir: str = ""
    tmux: bool = False
    high_risk_dep: bool = False
    branch: str = ""
    analyst_max_turns: int | None = None  # Global override for all analyst max_turns
    analyst_max_turns_by_name: dict[str, int] = field(default_factory=dict)  # Per-analyst overrides
    adversarial_max_turns: int | None = None  # Override adversarial agent max_turns (default 20)
    launch_mode: str = "lima"  # How the harness is launched: lima, docker, or direct

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
        if self.launch_mode not in ("lima", "docker", "direct"):
            raise ValueError(
                f"launch_mode must be one of 'lima', 'docker', 'direct'; got {self.launch_mode!r}"
            )
        return errors

    def to_json(self) -> str:
        """Serialize config to JSON for harness handoff."""
        data = {
            "repo_url": self.repo_url,
            "depth": self.depth,
            "skip_ai": self.skip_ai,
            "verbose": self.verbose,
            "output_dir": self.output_dir,
            "anthropic_api_key": self.anthropic_api_key,
            "oauth_token": self.oauth_token,
            "model": self.model,
            "log_dir": self.log_dir,
            "tmux": self.tmux,
            "high_risk_dep": self.high_risk_dep,
            "branch": self.branch,
            "analyst_max_turns": self.analyst_max_turns,
            "analyst_max_turns_by_name": self.analyst_max_turns_by_name,
            "adversarial_max_turns": self.adversarial_max_turns,
            "launch_mode": self.launch_mode,
            "vm": {
                "cpus": self.vm.cpus,
                "memory": self.vm.memory,
                "disk": self.vm.disk,
            },
            "limits": {
                "max_json_size_mb": self.limits.max_json_size_mb,
                "max_file_size_mb": self.limits.max_file_size_mb,
                "max_copy_size_mb": self.limits.max_copy_size_mb,
                "max_stdout_mb": self.limits.max_stdout_mb,
                "max_concurrent_ssh": self.limits.max_concurrent_ssh,
            },
        }
        return json.dumps(data)

    @classmethod
    def from_json(cls, json_str: str) -> "ScanConfig":
        """Deserialize config from JSON."""
        data = json.loads(json_str)
        vm_data = data.pop("vm", {})
        limits_data = data.pop("limits", {})
        vm = VMConfig(**vm_data) if vm_data else VMConfig()
        limits = LimitsConfig(**limits_data) if limits_data else LimitsConfig()
        # Remove keys that aren't ScanConfig fields
        known_fields = {
            "repo_url", "depth", "skip_ai", "verbose", "output_dir",
            "anthropic_api_key", "oauth_token", "model", "log_dir", "tmux",
            "high_risk_dep", "branch", "analyst_max_turns",
            "analyst_max_turns_by_name", "adversarial_max_turns", "launch_mode",
        }
        filtered = {k: v for k, v in data.items() if k in known_fields}
        return cls(vm=vm, limits=limits, **filtered)


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
    high_risk_dep: bool = False,
    branch: str | None = None,
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
        limits_data = data.get("limits", {})
        if "max_json_size_mb" in limits_data:
            config.limits.max_json_size_mb = limits_data["max_json_size_mb"]
        if "max_file_size_mb" in limits_data:
            config.limits.max_file_size_mb = limits_data["max_file_size_mb"]
        if "max_copy_size_mb" in limits_data:
            config.limits.max_copy_size_mb = limits_data["max_copy_size_mb"]
        if "max_stdout_mb" in limits_data:
            config.limits.max_stdout_mb = limits_data["max_stdout_mb"]
        if "max_concurrent_ssh" in limits_data:
            config.limits.max_concurrent_ssh = limits_data["max_concurrent_ssh"]
        analysts_data = data.get("analysts", {})
        if "max_turns" in analysts_data:
            config.analyst_max_turns = analysts_data["max_turns"]
        by_name = analysts_data.get("max_turns_by_name", {})
        if isinstance(by_name, dict):
            for name, turns in by_name.items():
                if isinstance(turns, int):
                    config.analyst_max_turns_by_name[name] = turns
        adversarial_data = data.get("adversarial", {})
        if "max_turns" in adversarial_data:
            config.adversarial_max_turns = adversarial_data["max_turns"]

    # CLI args override config file
    config.repo_url = repo_url
    if depth is not None:
        config.depth = depth
    config.skip_ai = skip_ai
    config.verbose = verbose
    config.high_risk_dep = high_risk_dep
    if branch is not None:
        config.branch = branch
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

    # Publish limits so utility modules can read them
    global active_limits
    active_limits = config.limits

    # Initialise SSH concurrency limit from config
    from thresher.vm.ssh import _init_ssh_semaphore
    _init_ssh_semaphore(config.limits.max_concurrent_ssh)

    return config


# Module-level limits instance, readable by safe_io.py and ssh.py
# without importing ScanConfig. Updated by load_config().
active_limits = LimitsConfig()
