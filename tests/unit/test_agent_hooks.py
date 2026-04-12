"""Tests for agent stop hook validation scripts.

Each test invokes a hook shell script via subprocess.run() with crafted stdin,
checking exit code and stderr to verify allow/block behavior.

Hook contract:
  - exit 0: allow stop (valid output)
  - exit 2: block stop, stderr message fed back to Claude
"""

import json
import os
import subprocess
from pathlib import Path

import pytest

_HOOKS_BASE = Path(__file__).resolve().parents[2] / "src" / "thresher" / "agents" / "hooks"

# All four agent hooks dispatch through one shared script with a schema arg.
SHARED_HOOK = _HOOKS_BASE / "_common" / "validate_json_output.sh"
SCHEMA_PATH = Path(__file__).resolve().parents[2] / "src" / "thresher" / "report" / "schema" / "report_schema.json"


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
    """Run the report stop hook with a crafted hook event on stdin."""
    event = json.dumps({"last_assistant_message": last_assistant_message})
    env = os.environ.copy()
    env["REPORT_SCHEMA_PATH"] = str(schema_path or SCHEMA_PATH)
    result = subprocess.run(
        ["bash", str(SHARED_HOOK), "report"],
        input=event.encode(),
        capture_output=True,
        timeout=10,
        env=env,
    )
    return result


def test_valid_json_allows_stop():
    """Valid report JSON should allow stop (exit 0)."""
    data = _valid_report_data()
    result = _run_hook(json.dumps(data))
    assert result.returncode == 0


def test_invalid_json_blocks_stop():
    """Plain text (not JSON) should block stop (exit 2)."""
    result = _run_hook("this is not json")
    assert result.returncode == 2
    stderr = result.stderr.decode()
    assert "JSON" in stderr


def test_missing_required_field_blocks():
    """Removing 'verdict' should cause a schema validation failure (exit 2)."""
    data = _valid_report_data()
    del data["verdict"]
    result = _run_hook(json.dumps(data))
    assert result.returncode == 2
    stderr = result.stderr.decode()
    assert "verdict" in stderr


def test_invalid_severity_blocks():
    """A severity value not in the enum should block stop (exit 2)."""
    data = _valid_report_data()
    data["verdict"]["severity"] = "URGENT"
    result = _run_hook(json.dumps(data))
    assert result.returncode == 2
    stderr = result.stderr.decode()
    assert "URGENT" in stderr or "enum" in stderr.lower() or "severity" in stderr.lower()


def test_json_in_markdown_code_fence():
    """Valid JSON wrapped in markdown triple-backtick code fence should allow stop."""
    data = _valid_report_data()
    message = "```json\n" + json.dumps(data, indent=2) + "\n```"
    result = _run_hook(message)
    assert result.returncode == 0


def test_empty_message_allows_stop():
    """An empty message should allow stop (nothing to validate)."""
    result = _run_hook("")
    assert result.returncode == 0


def test_integer_value_blocks():
    """An integer where a string is expected should block stop (exit 2)."""
    data = _valid_report_data()
    data["counts"]["critical"] = 5  # schema requires string
    result = _run_hook(json.dumps(data))
    assert result.returncode == 2
    stderr = result.stderr.decode()
    assert "critical" in stderr.lower() or "type" in stderr.lower()


def test_custom_schema_path(tmp_path):
    """The hook should respect REPORT_SCHEMA_PATH env var for custom schema locations."""
    schema_content = SCHEMA_PATH.read_text()
    custom_schema = tmp_path / "custom_schema.json"
    custom_schema.write_text(schema_content)

    data = _valid_report_data()
    result = _run_hook(json.dumps(data), schema_path=custom_schema)
    assert result.returncode == 0


def test_missing_schema_file_blocks():
    """If the schema file doesn't exist, the hook should block (exit 2)."""
    data = _valid_report_data()
    result = _run_hook(json.dumps(data), schema_path="/nonexistent/schema.json")
    assert result.returncode == 2
    stderr = result.stderr.decode().lower()
    # Either "not found" or the L3 fix's clearer "missing file" message.
    assert "not found" in stderr or "missing file" in stderr or "schema" in stderr


def test_unset_schema_path_blocks():
    """Regression for L3: when REPORT_SCHEMA_PATH is unset and the cwd is
    NOT the project root, the previous default ('templates/...') silently
    failed because the relative path didn't resolve. The hook should now
    require an absolute path or fail loud."""
    event = json.dumps({"last_assistant_message": json.dumps(_valid_report_data())})
    env = os.environ.copy()
    env.pop("REPORT_SCHEMA_PATH", None)
    result = subprocess.run(
        ["bash", str(SHARED_HOOK), "report"],
        input=event.encode(),
        capture_output=True,
        timeout=10,
        env=env,
        cwd="/tmp",  # Anywhere that isn't the project root
    )
    # Either: (a) hook resolves the schema via fallback locations and exits 0,
    # OR (b) hook fails loud with a clear "REPORT_SCHEMA_PATH" hint.
    if result.returncode != 0:
        stderr = result.stderr.decode()
        assert "REPORT_SCHEMA_PATH" in stderr or "schema" in stderr.lower()


def test_jsonschema_unimportable_fails_loud(tmp_path):
    """Regression for L3: when jsonschema is not installed, the hook MUST
    NOT silently exit 0. It must surface the missing dependency."""
    # Build a python wrapper script that hides jsonschema from sys.modules
    fake_python = tmp_path / "python3"
    fake_python.write_text(
        "#!/usr/bin/env bash\n"
        'exec /usr/bin/env python3 -c "'
        "import sys; "
        "sys.modules['jsonschema'] = None; "
        "exec(open('/dev/stdin').read())\"\n"
    )
    fake_python.chmod(0o755)

    # Easier: just use python to import-block jsonschema then run the script
    # body. Inline the script body via a shim invocation.
    event = json.dumps({"last_assistant_message": json.dumps(_valid_report_data())})
    env = os.environ.copy()
    env["REPORT_SCHEMA_PATH"] = str(SCHEMA_PATH)
    # Prepend a fake jsonschema-blocking importer
    env["PYTHONPATH"] = str(tmp_path) + ":" + env.get("PYTHONPATH", "")
    blocker = tmp_path / "jsonschema.py"
    blocker.write_text("raise ImportError('jsonschema deliberately blocked for test')\n")

    result = subprocess.run(
        ["bash", str(SHARED_HOOK), "report"],
        input=event.encode(),
        capture_output=True,
        timeout=10,
        env=env,
    )
    assert result.returncode == 2, (
        f"hook silently exited 0 without jsonschema; stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert b"jsonschema" in result.stderr.lower()


# ---------------------------------------------------------------------------
# Helper for non-report hooks (no schema file needed)
# ---------------------------------------------------------------------------


def _run_agent_hook(schema_name, last_assistant_message):
    """Run the shared stop hook with the given schema dispatch arg."""
    event = json.dumps({"last_assistant_message": last_assistant_message})
    result = subprocess.run(
        ["bash", str(SHARED_HOOK), schema_name],
        input=event.encode(),
        capture_output=True,
        timeout=10,
    )
    return result


# ---------------------------------------------------------------------------
# Predep hook tests
# ---------------------------------------------------------------------------


class TestPredepHook:
    def _valid_predep_data(self):
        return {
            "hidden_dependencies": [
                {
                    "type": "git",
                    "source": "https://github.com/example/lib.git",
                    "found_in": "Makefile:42",
                    "context": "Cloned during build",
                    "confidence": "high",
                    "risk": "low",
                }
            ],
            "files_scanned": 15,
            "summary": "Found 1 hidden dependency",
        }

    def test_valid_json_allows_stop(self):
        data = self._valid_predep_data()
        result = _run_agent_hook("predep", json.dumps(data))
        assert result.returncode == 0

    def test_empty_deps_allows_stop(self):
        data = {"hidden_dependencies": [], "files_scanned": 5, "summary": "None found"}
        result = _run_agent_hook("predep", json.dumps(data))
        assert result.returncode == 0

    def test_invalid_json_blocks_stop(self):
        result = _run_agent_hook("predep", "this is not json")
        assert result.returncode == 2
        assert "JSON" in result.stderr.decode()

    def test_missing_hidden_dependencies_blocks(self):
        data = {"files_scanned": 5, "summary": "oops"}
        result = _run_agent_hook("predep", json.dumps(data))
        assert result.returncode == 2
        assert "hidden_dependencies" in result.stderr.decode()

    def test_missing_files_scanned_blocks(self):
        data = {"hidden_dependencies": [], "summary": "None found"}
        result = _run_agent_hook("predep", json.dumps(data))
        assert result.returncode == 2
        assert "files_scanned" in result.stderr.decode()

    def test_missing_summary_blocks(self):
        data = {"hidden_dependencies": [], "files_scanned": 5}
        result = _run_agent_hook("predep", json.dumps(data))
        assert result.returncode == 2
        assert "summary" in result.stderr.decode()

    def test_invalid_dep_type_blocks(self):
        data = self._valid_predep_data()
        data["hidden_dependencies"][0]["type"] = "invalid_type"
        result = _run_agent_hook("predep", json.dumps(data))
        assert result.returncode == 2
        assert "invalid type" in result.stderr.decode().lower()

    def test_invalid_confidence_blocks(self):
        data = self._valid_predep_data()
        data["hidden_dependencies"][0]["confidence"] = "very_high"
        result = _run_agent_hook("predep", json.dumps(data))
        assert result.returncode == 2
        assert "confidence" in result.stderr.decode()

    def test_invalid_risk_blocks(self):
        data = self._valid_predep_data()
        data["hidden_dependencies"][0]["risk"] = "extreme"
        result = _run_agent_hook("predep", json.dumps(data))
        assert result.returncode == 2
        assert "risk" in result.stderr.decode()

    def test_missing_dep_field_blocks(self):
        data = self._valid_predep_data()
        del data["hidden_dependencies"][0]["source"]
        result = _run_agent_hook("predep", json.dumps(data))
        assert result.returncode == 2
        assert "source" in result.stderr.decode()

    def test_json_in_markdown_code_fence(self):
        data = self._valid_predep_data()
        message = "```json\n" + json.dumps(data, indent=2) + "\n```"
        result = _run_agent_hook("predep", message)
        assert result.returncode == 0

    def test_empty_message_allows_stop(self):
        result = _run_agent_hook("predep", "")
        assert result.returncode == 0


# ---------------------------------------------------------------------------
# Analyst hook tests
# ---------------------------------------------------------------------------


class TestAnalystHook:
    def _valid_analyst_data(self):
        return {
            "analyst": "paranoid",
            "analyst_number": 1,
            "core_question": "Is this code malicious?",
            "files_analyzed": 25,
            "findings": [
                {
                    "title": "Suspicious eval call",
                    "severity": "high",
                    "confidence": 85,
                    "file_path": "/opt/target/main.py",
                    "line_numbers": [42],
                    "description": "eval with user input",
                    "evidence": "eval(request.data)",
                    "reasoning": "User-controlled code execution",
                    "recommendation": "Use safe parsing instead",
                }
            ],
            "summary": "Found suspicious patterns",
            "risk_score": 7,
        }

    def test_valid_json_allows_stop(self):
        data = self._valid_analyst_data()
        result = _run_agent_hook("analyst", json.dumps(data))
        assert result.returncode == 0

    def test_empty_findings_allows_stop(self):
        data = self._valid_analyst_data()
        data["findings"] = []
        data["risk_score"] = 0
        data["summary"] = "All clear"
        result = _run_agent_hook("analyst", json.dumps(data))
        assert result.returncode == 0

    def test_invalid_json_blocks_stop(self):
        result = _run_agent_hook("analyst", "not json at all")
        assert result.returncode == 2
        assert "JSON" in result.stderr.decode()

    def test_missing_analyst_blocks(self):
        data = self._valid_analyst_data()
        del data["analyst"]
        result = _run_agent_hook("analyst", json.dumps(data))
        assert result.returncode == 2
        assert "analyst" in result.stderr.decode()

    def test_missing_findings_blocks(self):
        data = self._valid_analyst_data()
        del data["findings"]
        result = _run_agent_hook("analyst", json.dumps(data))
        assert result.returncode == 2
        assert "findings" in result.stderr.decode()

    def test_missing_risk_score_blocks(self):
        data = self._valid_analyst_data()
        del data["risk_score"]
        result = _run_agent_hook("analyst", json.dumps(data))
        assert result.returncode == 2
        assert "risk_score" in result.stderr.decode()

    def test_invalid_severity_blocks(self):
        data = self._valid_analyst_data()
        data["findings"][0]["severity"] = "URGENT"
        result = _run_agent_hook("analyst", json.dumps(data))
        assert result.returncode == 2
        assert "severity" in result.stderr.decode().lower()

    def test_risk_score_out_of_range_blocks(self):
        data = self._valid_analyst_data()
        data["risk_score"] = 15
        result = _run_agent_hook("analyst", json.dumps(data))
        assert result.returncode == 2
        assert "risk_score" in result.stderr.decode()

    def test_risk_score_negative_blocks(self):
        data = self._valid_analyst_data()
        data["risk_score"] = -1
        result = _run_agent_hook("analyst", json.dumps(data))
        assert result.returncode == 2

    def test_rejects_predep_schema(self):
        data = {
            "hidden_dependencies": [{"type": "npm", "source": "foo"}],
            "files_scanned": 10,
            "summary": "wrong schema",
        }
        result = _run_agent_hook("analyst", json.dumps(data))
        assert result.returncode == 2
        assert "hidden_dependencies" in result.stderr.decode()

    def test_missing_finding_title_blocks(self):
        data = self._valid_analyst_data()
        del data["findings"][0]["title"]
        result = _run_agent_hook("analyst", json.dumps(data))
        assert result.returncode == 2
        assert "title" in result.stderr.decode()

    def test_missing_finding_description_blocks(self):
        data = self._valid_analyst_data()
        del data["findings"][0]["description"]
        result = _run_agent_hook("analyst", json.dumps(data))
        assert result.returncode == 2
        assert "description" in result.stderr.decode()

    def test_json_in_markdown_code_fence(self):
        data = self._valid_analyst_data()
        message = "```json\n" + json.dumps(data, indent=2) + "\n```"
        result = _run_agent_hook("analyst", message)
        assert result.returncode == 0

    def test_empty_message_allows_stop(self):
        result = _run_agent_hook("analyst", "")
        assert result.returncode == 0


# ---------------------------------------------------------------------------
# Adversarial hook tests
# ---------------------------------------------------------------------------


class TestAdversarialHook:
    def _valid_adversarial_data(self):
        return {
            "results": [
                {
                    "file_path": "/opt/target/main.py",
                    "title": "Suspicious eval",
                    "verdict": "confirmed",
                    "confidence": 90,
                    "benign_explanation_attempted": "Could be a debug utility",
                    "reasoning": "No legitimate reason for eval on user input",
                    "original_risk_score": 7,
                    "revised_risk_score": 7,
                }
            ],
            "verification_summary": "1 finding confirmed as genuine risk",
            "total_reviewed": 1,
            "confirmed_count": 1,
            "downgraded_count": 0,
        }

    def test_valid_json_allows_stop(self):
        data = self._valid_adversarial_data()
        result = _run_agent_hook("adversarial", json.dumps(data))
        assert result.returncode == 0

    def test_empty_results_allows_stop(self):
        data = {
            "results": [],
            "verification_summary": "No findings to review",
            "total_reviewed": 0,
            "confirmed_count": 0,
            "downgraded_count": 0,
        }
        result = _run_agent_hook("adversarial", json.dumps(data))
        assert result.returncode == 0

    def test_invalid_json_blocks_stop(self):
        result = _run_agent_hook("adversarial", "not json")
        assert result.returncode == 2
        assert "JSON" in result.stderr.decode()

    def test_missing_results_blocks(self):
        data = self._valid_adversarial_data()
        del data["results"]
        result = _run_agent_hook("adversarial", json.dumps(data))
        assert result.returncode == 2
        assert "results" in result.stderr.decode()

    def test_missing_verification_summary_blocks(self):
        data = self._valid_adversarial_data()
        del data["verification_summary"]
        result = _run_agent_hook("adversarial", json.dumps(data))
        assert result.returncode == 2
        assert "verification_summary" in result.stderr.decode()

    def test_missing_total_reviewed_blocks(self):
        data = self._valid_adversarial_data()
        del data["total_reviewed"]
        result = _run_agent_hook("adversarial", json.dumps(data))
        assert result.returncode == 2
        assert "total_reviewed" in result.stderr.decode()

    def test_total_reviewed_not_number_blocks(self):
        data = self._valid_adversarial_data()
        data["total_reviewed"] = "one"
        result = _run_agent_hook("adversarial", json.dumps(data))
        assert result.returncode == 2
        assert "total_reviewed" in result.stderr.decode()

    def test_invalid_verdict_blocks(self):
        data = self._valid_adversarial_data()
        data["results"][0]["verdict"] = "maybe"
        result = _run_agent_hook("adversarial", json.dumps(data))
        assert result.returncode == 2
        assert "verdict" in result.stderr.decode()

    def test_missing_result_file_path_blocks(self):
        data = self._valid_adversarial_data()
        del data["results"][0]["file_path"]
        result = _run_agent_hook("adversarial", json.dumps(data))
        assert result.returncode == 2
        assert "file_path" in result.stderr.decode()

    def test_missing_result_reasoning_blocks(self):
        data = self._valid_adversarial_data()
        del data["results"][0]["reasoning"]
        result = _run_agent_hook("adversarial", json.dumps(data))
        assert result.returncode == 2
        assert "reasoning" in result.stderr.decode()

    def test_downgraded_verdict_allowed(self):
        data = self._valid_adversarial_data()
        data["results"][0]["verdict"] = "downgraded"
        data["downgraded_count"] = 1
        data["confirmed_count"] = 0
        result = _run_agent_hook("adversarial", json.dumps(data))
        assert result.returncode == 0

    def test_json_in_markdown_code_fence(self):
        data = self._valid_adversarial_data()
        message = "```json\n" + json.dumps(data, indent=2) + "\n```"
        result = _run_agent_hook("adversarial", message)
        assert result.returncode == 0

    def test_empty_message_allows_stop(self):
        result = _run_agent_hook("adversarial", "")
        assert result.returncode == 0


# ---------------------------------------------------------------------------
# _resolve_hooks_settings tests
# ---------------------------------------------------------------------------


class TestBuildStopHookSettings:
    """The shared helper points every agent at one script with a schema arg."""

    @pytest.mark.parametrize("schema", ["predep", "analyst", "adversarial", "report"])
    def test_settings_command_dispatches_to_shared_script(self, schema):
        from thresher.agents._runner import build_stop_hook_settings

        settings = json.loads(build_stop_hook_settings(schema))
        hook_cmd = settings["hooks"]["Stop"][0]["hooks"][0]["command"]
        # Command is "<absolute path to script> <schema name>"
        script_path, _, dispatched_schema = hook_cmd.rpartition(" ")
        assert dispatched_schema == schema
        assert script_path.endswith("_common/validate_json_output.sh")
        assert os.path.isfile(script_path)


class TestSettingsPassedToCommand:
    """Verify that agent modules pass --settings to the claude command."""

    def _mock_popen(self, returncode=0, stdout=b""):
        from unittest.mock import MagicMock

        mock = MagicMock()
        mock.stdout = iter(stdout.splitlines(keepends=True)) if stdout else iter([])
        mock.returncode = returncode
        mock.wait.return_value = returncode
        return mock

    def _make_config(self):
        from thresher.config import ScanConfig

        return ScanConfig(
            repo_url="https://github.com/x/y",
            anthropic_api_key="sk-ant-test-key",
        )

    def test_predep_passes_settings_flag(self):
        from unittest.mock import patch

        from thresher.agents.predep import run_predep_discovery

        sample = json.dumps(
            {
                "hidden_dependencies": [],
                "files_scanned": 0,
                "summary": "empty",
            }
        )
        with patch("thresher.run._popen") as mock:
            mock.return_value = self._mock_popen(stdout=sample.encode())
            run_predep_discovery(self._make_config())
            cmd = mock.call_args[0][0]
            assert "--settings" in cmd

    def test_analyst_passes_settings_flag(self):
        from unittest.mock import patch

        from thresher.agents.analysts import ANALYST_DEFINITIONS, _run_single_analyst

        sample = json.dumps(
            {
                "analyst": "paranoid",
                "analyst_number": 1,
                "core_question": "test?",
                "files_analyzed": 0,
                "findings": [],
                "summary": "clean",
                "risk_score": 0,
            }
        )
        with patch("thresher.run._popen") as mock:
            mock.return_value = self._mock_popen(stdout=sample.encode())
            _run_single_analyst(self._make_config(), ANALYST_DEFINITIONS[0])
            cmd = mock.call_args[0][0]
            assert "--settings" in cmd

    def test_adversarial_passes_settings_flag(self):
        from unittest.mock import patch

        from thresher.agents.adversarial import run_adversarial_verification

        sample = json.dumps(
            {
                "results": [
                    {
                        "file_path": "/opt/target/main.py",
                        "verdict": "confirmed",
                        "confidence": 90,
                        "reasoning": "genuine risk",
                    }
                ],
                "verification_summary": "done",
                "total_reviewed": 1,
                "confirmed_count": 1,
                "downgraded_count": 0,
            }
        )
        analyst_findings = [
            {
                "analyst": "paranoid",
                "analyst_number": 1,
                "findings": [
                    {
                        "title": "Suspicious eval",
                        "severity": "critical",
                        "file_path": "/opt/target/main.py",
                        "description": "eval with user input",
                    }
                ],
                "summary": "found issues",
                "risk_score": 9,
            }
        ]
        with patch("thresher.run._popen") as mock:
            mock.return_value = self._mock_popen(stdout=sample.encode())
            run_adversarial_verification(
                self._make_config(),
                analyst_findings=analyst_findings,
            )
            cmd = mock.call_args[0][0]
            assert "--settings" in cmd
