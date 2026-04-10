"""Tests for the report-maker stop hook validation script.

Each test invokes the shell script via subprocess.run() with crafted stdin,
checking exit code and stdout to verify allow/block behavior.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest

HOOK_SCRIPT = Path(__file__).resolve().parents[2] / "src" / "thresher" / "agents" / "hooks" / "report" / "validate_json_output.sh"
SCHEMA_PATH = Path(__file__).resolve().parents[2] / "templates" / "report" / "report_schema.json"


def _valid_report_data():
    """Return a minimal valid report data dict matching the schema."""
    return {
        "meta": {
            "scan_date": "2026-04-09",
            "thresher_version": "0.2.2",
            "scanner_count": "22",
            "analyst_count": "8",
            "repo_name": "example/repo",
            "repo_url": "https://github.com/example/repo",
        },
        "verdict": {
            "label": "Low Risk",
            "severity": "low",
            "callout": "No critical issues found.",
        },
        "counts": {
            "total_scanner": "0",
            "total_ai": "0",
            "p0": "0",
            "critical": "0",
            "high_scanner": "0",
            "high_ai": "0",
            "medium": "0",
            "low": "0",
        },
        "executive_summary": "The repository appears safe.",
        "mitigations": [],
        "scanner_findings": [],
        "ai_findings": [],
        "trust_signals": [],
        "dependency_upgrades": [],
        "remediation": None,
        "pipeline": {
            "scanners": [],
            "analysts": [],
            "notes": "",
        },
        "config": {
            "show_cta": "true",
            "show_remediation": "false",
        },
    }


def _run_hook(last_assistant_message, schema_path=None):
    """Run the stop hook script with a crafted hook event on stdin."""
    event = json.dumps({"last_assistant_message": last_assistant_message})
    env = os.environ.copy()
    env["REPORT_SCHEMA_PATH"] = str(schema_path or SCHEMA_PATH)
    result = subprocess.run(
        ["bash", str(HOOK_SCRIPT)],
        input=event.encode(),
        capture_output=True,
        timeout=10,
        env=env,
    )
    return result


def test_valid_json_allows_stop():
    """Valid report JSON should allow stop (exit 0, no block decision)."""
    data = _valid_report_data()
    result = _run_hook(json.dumps(data))
    assert result.returncode == 0
    stdout = result.stdout.decode().strip()
    # No output means allow
    assert stdout == "" or "block" not in stdout


def test_invalid_json_blocks_stop():
    """Plain text (not JSON) should block stop."""
    result = _run_hook("this is not json")
    assert result.returncode == 0
    response = json.loads(result.stdout.decode().strip())
    assert response["decision"] == "block"


def test_missing_required_field_blocks():
    """Removing 'verdict' should cause a schema validation failure."""
    data = _valid_report_data()
    del data["verdict"]
    result = _run_hook(json.dumps(data))
    assert result.returncode == 0
    response = json.loads(result.stdout.decode().strip())
    assert response["decision"] == "block"
    assert "verdict" in response["reason"]


def test_invalid_severity_blocks():
    """A severity value not in the enum should block stop."""
    data = _valid_report_data()
    data["verdict"]["severity"] = "URGENT"
    result = _run_hook(json.dumps(data))
    assert result.returncode == 0
    response = json.loads(result.stdout.decode().strip())
    assert response["decision"] == "block"


def test_json_in_markdown_code_fence():
    """Valid JSON wrapped in markdown triple-backtick code fence should allow stop."""
    data = _valid_report_data()
    message = "```json\n" + json.dumps(data, indent=2) + "\n```"
    result = _run_hook(message)
    assert result.returncode == 0
    stdout = result.stdout.decode().strip()
    assert stdout == "" or "block" not in stdout


def test_empty_message_allows_stop():
    """An empty message should allow stop (nothing to validate)."""
    result = _run_hook("")
    assert result.returncode == 0
    stdout = result.stdout.decode().strip()
    assert stdout == ""


def test_integer_value_blocks():
    """An integer where a string is expected should block stop."""
    data = _valid_report_data()
    data["counts"]["critical"] = 5  # schema requires string
    result = _run_hook(json.dumps(data))
    assert result.returncode == 0
    response = json.loads(result.stdout.decode().strip())
    assert response["decision"] == "block"


def test_custom_schema_path(tmp_path):
    """The hook should respect REPORT_SCHEMA_PATH env var for custom schema locations."""
    # Write the real schema to a temp location
    schema_content = SCHEMA_PATH.read_text()
    custom_schema = tmp_path / "custom_schema.json"
    custom_schema.write_text(schema_content)

    data = _valid_report_data()
    result = _run_hook(json.dumps(data), schema_path=custom_schema)
    assert result.returncode == 0
    stdout = result.stdout.decode().strip()
    assert stdout == "" or "block" not in stdout


def test_missing_schema_file_blocks():
    """If the schema file doesn't exist, the hook should block."""
    data = _valid_report_data()
    result = _run_hook(json.dumps(data), schema_path="/nonexistent/schema.json")
    assert result.returncode == 0
    response = json.loads(result.stdout.decode().strip())
    assert response["decision"] == "block"
    assert "not found" in response["reason"]
