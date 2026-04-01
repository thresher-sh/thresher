"""Shared data models for scanner output normalization."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
VALID_CATEGORIES = frozenset({
    "sca", "sast", "supply_chain", "secrets",
    "iac", "malware", "binary_analysis", "license",
    "behavioral", "obfuscation", "metadata", "install_hook",
})


@dataclass
class Finding:
    """A single normalized security finding produced by any scanner."""

    id: str  # e.g. "grype-CVE-2024-1234"
    source_tool: str  # e.g. "grype", "semgrep"
    category: str  # "sca", "sast", "supply_chain", "secrets"
    severity: str  # "critical", "high", "medium", "low", "info"
    cvss_score: float | None
    cve_id: str | None
    title: str
    description: str
    file_path: str | None
    line_number: int | None
    package_name: str | None
    package_version: str | None
    fix_version: str | None
    raw_output: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the finding to a plain dictionary."""
        return {
            "id": self.id,
            "source_tool": self.source_tool,
            "category": self.category,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cve_id": self.cve_id,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "package_name": self.package_name,
            "package_version": self.package_version,
            "fix_version": self.fix_version,
            "raw_output": self.raw_output,
        }


@dataclass
class ScanResults:
    """Aggregated results from a single scanner run."""

    tool_name: str
    execution_time_seconds: float
    exit_code: int
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    raw_output_path: str | None = None  # Path to the raw JSON output file
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the scan results to a plain dictionary."""
        return {
            "tool_name": self.tool_name,
            "execution_time_seconds": self.execution_time_seconds,
            "exit_code": self.exit_code,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "raw_output_path": self.raw_output_path,
            "metadata": self.metadata,
        }
