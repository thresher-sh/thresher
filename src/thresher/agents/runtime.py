"""Pluggable agent-runtime registry.

Each runtime (``claude``, ``wksp``, …) may need host files forwarded into
the harness container so the in-container CLI can authenticate. This
module is the single place that knows which files belong to which
runtime; launchers iterate the returned mounts without caring about
their semantics.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class HostFileMount:
    """A host file that must be readable inside the harness container."""

    host_path: Path
    container_path: str


def runtime_host_mounts(agent_runtime: str) -> list[HostFileMount]:
    """Files on the host that the given runtime needs inside the container.

    Launchers should skip any mount whose ``host_path`` does not exist —
    the host may simply not have that runtime configured, in which case
    the runtime is expected to fall back to env-based credentials.
    """
    if agent_runtime == "wksp":
        return [
            HostFileMount(
                host_path=Path.home() / ".config" / "workshop" / "credentials.json",
                container_path="/home/thresher/.config/workshop/credentials.json",
            ),
        ]
    return []
