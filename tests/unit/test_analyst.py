"""Tests for thresher.agents.analyst."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from thresher.agents.analyst import (
    _empty_findings,
    _extract_json_from_text,
    _extract_result_from_stream,
    _parse_agent_json_output,
    run_analysis,
)
from thresher.config import ScanConfig


def _mock_popen(returncode=0, stdout=b""):
    """Create a mock that behaves like subprocess.Popen."""
    mock = MagicMock()
    mock.stdout = iter(stdout.splitlines(keepends=True)) if stdout else iter([])
    mock.returncode = returncode
    mock.wait.return_value = returncode
    return mock


def _make_config() -> ScanConfig:
    return ScanConfig(
        repo_url="https://github.com/x/y",
        anthropic_api_key="sk-ant-test-key",
        model="sonnet",
    )


class TestEmptyFindings:
    def test_structure(self):
        result = _empty_findings("test reason")
        assert result["project_summary"] == "test reason"
        assert result["findings"] == []
        assert result["error"] == "test reason"
        assert result["files_analyzed"] == 0


class TestExtractResultFromStream:
    def test_stream_json(self):
        stream = (
            '{"type":"progress","message":"working"}\n'
            '{"type":"result","result":"hello world"}\n'
        )
        assert _extract_result_from_stream(stream) == "hello world"

    def test_json_envelope(self):
        data = '{"result": "the answer"}'
        assert _extract_result_from_stream(data) == "the answer"

    def test_no_result(self):
        raw = "just plain text"
        assert _extract_result_from_stream(raw) == raw

    def test_empty(self):
        assert _extract_result_from_stream("") == ""


class TestParseAgentJsonOutput:
    def test_empty_input(self):
        result = _parse_agent_json_output("")
        assert "error" in result

    def test_direct_json(self):
        data = json.dumps({
            "project_summary": "test",
            "findings": [{"file_path": "/a.py", "risk_score": 5}],
        })
        result = _parse_agent_json_output(data)
        assert result["project_summary"] == "test"
        assert len(result["findings"]) == 1

    def test_stream_json_with_result(self):
        findings = {"findings": [{"file_path": "/a.py", "risk_score": 3}]}
        stream = (
            '{"type":"progress","message":"analyzing"}\n'
            f'{{"type":"result","result":{json.dumps(json.dumps(findings))}}}\n'
        )
        result = _parse_agent_json_output(stream)
        assert len(result["findings"]) == 1

    def test_json_in_code_block(self):
        text = 'Here is my analysis:\n```json\n{"findings": []}\n```\n'
        result = _parse_agent_json_output(text)
        assert result["findings"] == []

    def test_list_output(self):
        data = json.dumps([{"file_path": "/a.py"}])
        result = _parse_agent_json_output(data)
        assert "findings" in result


class TestExtractJsonFromText:
    def test_code_block(self):
        text = 'Some text\n```json\n{"key": "value"}\n```\nMore text'
        result = _extract_json_from_text(text)
        assert result["key"] == "value"

    def test_bare_json(self):
        text = 'Prefix {"findings": []} suffix'
        result = _extract_json_from_text(text)
        assert result["findings"] == []

    def test_no_json(self):
        result = _extract_json_from_text("no json here")
        assert "error" in result


class TestRunAnalysis:
    def _valid_output(self):
        return json.dumps({
            "project_summary": "clean",
            "findings": [],
            "files_analyzed": 5,
        }).encode()

    @patch("thresher.run._popen")
    def test_returns_findings_dict(self, mock_popen):
        mock_popen.return_value = _mock_popen(returncode=0, stdout=self._valid_output())

        result = run_analysis(_make_config())
        assert isinstance(result, dict)
        assert "findings" in result

    @patch("thresher.run._popen")
    def test_uses_correct_model(self, mock_popen):
        mock_popen.return_value = _mock_popen(returncode=0, stdout=self._valid_output())

        run_analysis(_make_config())

        cmd = mock_popen.call_args[0][0]
        assert "--model" in cmd
        assert "sonnet" in cmd

    @patch("thresher.run._popen")
    def test_api_key_in_env(self, mock_popen):
        mock_popen.return_value = _mock_popen(returncode=0, stdout=self._valid_output())

        run_analysis(_make_config())

        call_kwargs = mock_popen.call_args[1]
        env = call_kwargs.get("env", {})
        assert "ANTHROPIC_API_KEY" in env
        assert env["ANTHROPIC_API_KEY"] == "sk-ant-test-key"

    @patch("thresher.run._popen")
    def test_handles_subprocess_failure(self, mock_popen):
        mock_popen.side_effect = RuntimeError("subprocess failed")

        result = run_analysis(_make_config())
        assert "error" in result
        assert result["findings"] == []

    @patch("thresher.run._popen")
    def test_returns_empty_on_bad_output(self, mock_popen):
        mock_popen.return_value = _mock_popen(returncode=0, stdout=b"not valid json at all")

        result = run_analysis(_make_config())
        assert isinstance(result, dict)
        assert "findings" in result

    @patch("thresher.run._popen")
    def test_uses_default_max_turns(self, mock_popen):
        """Without config override, analyst should use default of 30."""
        mock_popen.return_value = _mock_popen(returncode=0, stdout=self._valid_output())
        config = _make_config()
        assert config.analyst_max_turns is None

        run_analysis(config)

        cmd = mock_popen.call_args[0][0]
        idx = cmd.index("--max-turns")
        assert cmd[idx + 1] == "30"

    @patch("thresher.run._popen")
    def test_uses_config_max_turns(self, mock_popen):
        """When analyst_max_turns is set in config, it should override the default."""
        mock_popen.return_value = _mock_popen(returncode=0, stdout=self._valid_output())
        config = _make_config()
        config.analyst_max_turns = 45

        run_analysis(config)

        cmd = mock_popen.call_args[0][0]
        idx = cmd.index("--max-turns")
        assert cmd[idx + 1] == "45"
