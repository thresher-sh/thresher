"""Tests for the Stage 1 pre-dependency discovery agent."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from unittest.mock import MagicMock

from thresher.agents.predep import (
    _parse_predep_output,
    _empty_result,
    run_predep_discovery,
)
from thresher.config import ScanConfig, VMConfig


def _mock_popen(returncode=0, stdout=b""):
    """Create a mock that behaves like subprocess.Popen."""
    mock = MagicMock()
    mock.stdout = iter(stdout.splitlines(keepends=True)) if stdout else iter([])
    mock.returncode = returncode
    mock.wait.return_value = returncode
    return mock


@pytest.fixture
def config():
    return ScanConfig(
        repo_url="https://github.com/example/repo",
        skip_ai=False,
        anthropic_api_key="sk-ant-test-key",
        vm=VMConfig(cpus=4, memory=8, disk=50),
    )


SAMPLE_OUTPUT = '''{
  "hidden_dependencies": [
    {
      "type": "git",
      "source": "https://github.com/example/lib.git",
      "found_in": "Makefile:42",
      "context": "Cloned during build",
      "confidence": "high"
    },
    {
      "type": "url",
      "source": "https://example.com/tool.tar.gz",
      "found_in": "scripts/setup.sh:17",
      "context": "Downloads build tool",
      "confidence": "medium"
    }
  ],
  "files_scanned": 15,
  "summary": "Found 2 hidden dependencies"
}'''


class TestParsePredepOutput:
    def test_direct_json(self):
        result = _parse_predep_output(SAMPLE_OUTPUT)
        assert len(result["hidden_dependencies"]) == 2
        assert result["hidden_dependencies"][0]["type"] == "git"
        assert result["hidden_dependencies"][1]["type"] == "url"

    def test_stream_json_result(self):
        import json
        stream_line = json.dumps({
            "type": "result",
            "result": SAMPLE_OUTPUT,
        })
        result = _parse_predep_output(stream_line)
        assert len(result["hidden_dependencies"]) == 2

    def test_code_block(self):
        wrapped = f"Some text\n```json\n{SAMPLE_OUTPUT}\n```\nMore text"
        result = _parse_predep_output(wrapped)
        assert len(result["hidden_dependencies"]) == 2

    def test_empty_deps(self):
        output = '{"hidden_dependencies": [], "files_scanned": 5, "summary": "None found"}'
        result = _parse_predep_output(output)
        assert result["hidden_dependencies"] == []
        assert result["files_scanned"] == 5

    def test_unparseable_returns_empty(self):
        result = _parse_predep_output("This is not JSON at all")
        assert result["hidden_dependencies"] == []

    def test_empty_input(self):
        result = _parse_predep_output("")
        assert result["hidden_dependencies"] == []

    def test_malformed_json_returns_empty(self):
        result = _parse_predep_output('{"hidden_dependencies": [INVALID]}')
        assert result["hidden_dependencies"] == []

    def test_wrong_schema_returns_empty(self):
        """JSON without hidden_dependencies key is not accepted."""
        result = _parse_predep_output('{"findings": [{"foo": "bar"}]}')
        assert result["hidden_dependencies"] == []

    def test_truncated_json_returns_empty(self):
        result = _parse_predep_output('{"hidden_dependencies": [{"type": "git"')
        assert result["hidden_dependencies"] == []

    def test_logs_raw_output_on_failure(self, caplog):
        """When parsing fails, the raw output should be logged for diagnosis."""
        import logging
        with caplog.at_level(logging.WARNING):
            _parse_predep_output("agent said something unhelpful")
        assert "agent said something unhelpful" in caplog.text


class TestEmptyResult:
    def test_structure(self):
        result = _empty_result("test reason")
        assert result["hidden_dependencies"] == []
        assert result["summary"] == "test reason"


class TestRunPredepDiscovery:
    @patch("thresher.run._popen")
    def test_returns_findings_dict(self, mock_popen, config):
        mock_popen.return_value = _mock_popen(returncode=0, stdout=SAMPLE_OUTPUT.encode())

        result = run_predep_discovery(config)

        assert isinstance(result, dict)
        assert len(result["hidden_dependencies"]) == 2

    @patch("thresher.run._popen")
    def test_injects_high_risk_dep_flag(self, mock_popen, config):
        mock_popen.return_value = _mock_popen(returncode=0, stdout=SAMPLE_OUTPUT.encode())

        result = run_predep_discovery(config)
        assert "high_risk_dep" in result
        assert result["high_risk_dep"] == config.high_risk_dep

    @patch("thresher.run._popen")
    def test_api_key_in_env(self, mock_popen, config):
        mock_popen.return_value = _mock_popen(returncode=0, stdout=SAMPLE_OUTPUT.encode())

        run_predep_discovery(config)

        call_kwargs = mock_popen.call_args[1]
        env = call_kwargs.get("env", {})
        assert "ANTHROPIC_API_KEY" in env
        assert env["ANTHROPIC_API_KEY"] == "sk-ant-test-key"

    @patch("thresher.run._popen")
    def test_handles_subprocess_failure(self, mock_popen, config):
        mock_popen.side_effect = RuntimeError("connection lost")

        result = run_predep_discovery(config)
        assert result["hidden_dependencies"] == []
        assert "failed" in result["summary"].lower()

    @patch("thresher.run._popen")
    def test_handles_bad_output(self, mock_popen, config):
        mock_popen.return_value = _mock_popen(returncode=0, stdout=b"garbled output not json")

        result = run_predep_discovery(config)
        assert isinstance(result, dict)
        assert "hidden_dependencies" in result

    @patch("thresher.run._popen")
    def test_uses_correct_model(self, mock_popen, config):
        mock_popen.return_value = _mock_popen(returncode=0, stdout=SAMPLE_OUTPUT.encode())

        run_predep_discovery(config)

        cmd = mock_popen.call_args[0][0]
        assert "--model" in cmd

    def test_returns_empty_on_prompt_write_failure(self, config):
        with patch("thresher.agents.predep.Path.write_text", side_effect=OSError("write failed")):
            result = run_predep_discovery(config)
            assert result["hidden_dependencies"] == []
            assert "failed" in result["summary"].lower()

    @patch("thresher.run._popen")
    def test_uses_default_max_turns(self, mock_popen, config):
        """Without config override, predep should use default of 15."""
        mock_popen.return_value = _mock_popen(returncode=0, stdout=SAMPLE_OUTPUT.encode())
        assert config.predep_max_turns is None

        run_predep_discovery(config)

        cmd = mock_popen.call_args[0][0]
        idx = cmd.index("--max-turns")
        assert cmd[idx + 1] == "15"

    @patch("thresher.run._popen")
    def test_uses_config_max_turns(self, mock_popen, config):
        """When predep_max_turns is set in config, it should override the default."""
        mock_popen.return_value = _mock_popen(returncode=0, stdout=SAMPLE_OUTPUT.encode())
        config.predep_max_turns = 25

        run_predep_discovery(config)

        cmd = mock_popen.call_args[0][0]
        idx = cmd.index("--max-turns")
        assert cmd[idx + 1] == "25"
