"""Tests for thresher.agents._runner — shared Claude Code agent driver."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from thresher.agents._runner import AgentResult, AgentSpec, run_agent
from thresher.config import ScanConfig


def _make_config() -> ScanConfig:
    return ScanConfig(
        repo_url="https://github.com/x/y",
        anthropic_api_key="sk-ant-test-key",
        model="sonnet",
    )


def _mock_popen(returncode=0, stdout=b""):
    mock = MagicMock()
    mock.stdout = iter(stdout.splitlines(keepends=True)) if stdout else iter([])
    mock.returncode = returncode
    mock.wait.return_value = returncode
    return mock


def _stream_json(result_text="ok", num_turns=1):
    return (
        json.dumps({"type": "system", "subtype": "init"}).encode() + b"\n"
        + json.dumps({
            "type": "result", "result": result_text, "num_turns": num_turns,
        }).encode() + b"\n"
    )


class TestRunAgent:
    def _spec(self, **overrides):
        defaults = dict(
            label="test-agent",
            prompt="say hi",
            allowed_tools=["Read", "Grep"],
            max_turns=10,
            timeout=60,
            cwd="/tmp",
        )
        defaults.update(overrides)
        return AgentSpec(**defaults)

    @patch("thresher.run._popen")
    def test_returns_text_and_turns(self, mock):
        mock.return_value = _mock_popen(stdout=_stream_json("hello", 5))
        result = run_agent(self._spec(), _make_config())
        assert isinstance(result, AgentResult)
        assert result.result_text == "hello"
        assert result.num_turns == 5
        assert result.returncode == 0
        assert not result.failed

    @patch("thresher.run._popen")
    def test_command_includes_required_flags(self, mock):
        mock.return_value = _mock_popen(stdout=_stream_json())
        run_agent(self._spec(max_turns=42), _make_config())
        cmd = mock.call_args[0][0]
        assert cmd[0] == "claude"
        assert "-p" in cmd
        assert "--model" in cmd
        assert cmd[cmd.index("--model") + 1] == "sonnet"
        assert "--allowedTools" in cmd
        assert cmd[cmd.index("--allowedTools") + 1] == "Read,Grep"
        assert "--output-format" in cmd
        assert cmd[cmd.index("--output-format") + 1] == "stream-json"
        assert "--verbose" in cmd
        assert "--max-turns" in cmd
        assert cmd[cmd.index("--max-turns") + 1] == "42"

    @patch("thresher.run._popen")
    def test_no_settings_flag_when_hooks_json_absent(self, mock):
        mock.return_value = _mock_popen(stdout=_stream_json())
        run_agent(self._spec(), _make_config())
        cmd = mock.call_args[0][0]
        assert "--settings" not in cmd

    @patch("thresher.run._popen")
    def test_settings_flag_when_hooks_json_present(self, mock):
        mock.return_value = _mock_popen(stdout=_stream_json())
        spec = self._spec(hooks_settings_json='{"hooks": {}}')
        run_agent(spec, _make_config())
        cmd = mock.call_args[0][0]
        assert "--settings" in cmd

    @patch("thresher.run._popen")
    def test_passes_cwd_to_subprocess(self, mock):
        mock.return_value = _mock_popen(stdout=_stream_json())
        run_agent(self._spec(cwd="/some/dir"), _make_config())
        kwargs = mock.call_args[1]
        assert kwargs.get("cwd") == "/some/dir"

    @patch("thresher.run._popen")
    def test_env_includes_ai_credentials(self, mock):
        mock.return_value = _mock_popen(stdout=_stream_json())
        run_agent(self._spec(), _make_config())
        env = mock.call_args[1].get("env", {})
        assert env.get("ANTHROPIC_API_KEY") == "sk-ant-test-key"

    @patch("thresher.run._popen")
    def test_extra_env_merged_into_subprocess_env(self, mock):
        mock.return_value = _mock_popen(stdout=_stream_json())
        spec = self._spec(extra_env={"REPORT_SCHEMA_PATH": "/abs/schema.json"})
        run_agent(spec, _make_config())
        env = mock.call_args[1].get("env", {})
        assert env.get("REPORT_SCHEMA_PATH") == "/abs/schema.json"

    @patch("thresher.run._popen")
    def test_subprocess_failure_returns_failed_result(self, mock):
        mock.side_effect = RuntimeError("docker connection lost")
        result = run_agent(self._spec(), _make_config())
        assert result.failed
        assert result.error and "docker connection lost" in result.error
        assert result.result_text == ""
        assert result.num_turns == 0

    @patch("thresher.run._popen")
    def test_label_passed_to_run_cmd(self, mock):
        mock.return_value = _mock_popen(stdout=_stream_json())
        # The label flows to run_cmd as the `label` kwarg, which appears
        # in log output. We can't observe it directly but we can verify
        # the call succeeds and the label doesn't crash anything.
        result = run_agent(self._spec(label="predep"), _make_config())
        assert not result.failed

    @patch("thresher.run._popen")
    def test_empty_stream_returns_empty_text(self, mock):
        mock.return_value = _mock_popen(stdout=b"")
        result = run_agent(self._spec(), _make_config())
        assert result.result_text == ""
        assert result.num_turns == 0
