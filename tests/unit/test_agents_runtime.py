"""Tests for the pluggable agent-runtime registry."""

from __future__ import annotations

from thresher.agents.runtime import HostFileMount, runtime_host_mounts


def test_claude_runtime_has_no_host_mounts():
    assert runtime_host_mounts("claude") == []


def test_unknown_runtime_has_no_host_mounts():
    assert runtime_host_mounts("does-not-exist") == []


def test_wksp_runtime_forwards_credentials_file():
    mounts = runtime_host_mounts("wksp")
    assert len(mounts) == 1
    mount = mounts[0]
    assert isinstance(mount, HostFileMount)
    assert mount.host_path.name == "credentials.json"
    assert mount.host_path.parent.name == "workshop"
    assert mount.container_path == "/home/thresher/.config/workshop/credentials.json"
