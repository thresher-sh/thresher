"""Tests for the Stage 1 pre-dependency discovery agent."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from thresher.agents.predep import (
    _parse_predep_output,
    _empty_result,
    run_predep_discovery,
)
from thresher.config import ScanConfig, VMConfig
from thresher.vm.ssh import SSHResult


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
    @patch("thresher.agents.predep.ssh_write_file")
    @patch("thresher.agents.predep.ssh_exec")
    def test_writes_output_to_vm(self, mock_exec, mock_write, config):
        mock_exec.return_value = SSHResult(SAMPLE_OUTPUT, "", 0)
        mock_write.return_value = None

        result = run_predep_discovery("test-vm", config)

        assert len(result["hidden_dependencies"]) == 2
        # Should write the result to hidden_deps.json
        write_calls = [c[0] for c in mock_write.call_args_list]
        paths = [c[2] for c in write_calls]
        assert any("hidden_deps.json" in p for p in paths)

    @patch("thresher.agents.predep.ssh_write_file")
    @patch("thresher.agents.predep.ssh_exec")
    def test_uses_tmpfs_api_key(self, mock_exec, mock_write, config):
        mock_exec.return_value = SSHResult(SAMPLE_OUTPUT, "", 0)
        mock_write.return_value = None

        run_predep_discovery("test-vm", config)

        cmds = [c[0][1] for c in mock_exec.call_args_list]
        assert any("/dev/shm/.cred_" in cmd for cmd in cmds)

    @patch("thresher.agents.predep.ssh_write_file")
    @patch("thresher.agents.predep.ssh_exec")
    def test_handles_agent_failure(self, mock_exec, mock_write, config):
        # mkdir for .claude dir, tmpfs key write succeed, then claude fails
        mock_exec.side_effect = [
            SSHResult("", "", 0),  # mkdir .claude
            SSHResult("", "", 0),  # tmpfs key write
            Exception("connection lost"),  # claude invocation
        ]
        mock_write.return_value = None

        result = run_predep_discovery("test-vm", config)
        assert result["hidden_dependencies"] == []
        assert "failed" in result["summary"].lower()

    @patch("thresher.agents.predep.ssh_write_file")
    @patch("thresher.agents.predep.ssh_exec")
    def test_fallback_reads_output_from_vm(self, mock_exec, mock_write, config):
        """If parsing fails, check if agent wrote output directly to VM path."""
        fallback_json = '{"hidden_dependencies": [{"type": "git", "source": "https://example.com/repo.git", "found_in": "Makefile:1", "context": "clone", "confidence": "high", "risk": "low"}], "files_scanned": 5, "summary": "found 1"}'
        mock_exec.side_effect = [
            SSHResult("", "", 0),  # mkdir .claude
            SSHResult("", "", 0),  # tmpfs key write
            SSHResult("garbled output not json", "", 0),  # claude invocation
            SSHResult(fallback_json, "", 0),  # cat fallback path
            SSHResult("", "", 0),  # mkdir for output dir
        ]
        mock_write.return_value = None

        result = run_predep_discovery("test-vm", config)
        assert len(result["hidden_dependencies"]) == 1
        assert result["hidden_dependencies"][0]["type"] == "git"

    @patch("thresher.agents.predep.ssh_write_file")
    @patch("thresher.agents.predep.ssh_exec")
    def test_fallback_skipped_when_parsing_succeeds(self, mock_exec, mock_write, config):
        """When normal parsing succeeds, no fallback read should happen."""
        mock_exec.side_effect = [
            SSHResult("", "", 0),  # mkdir .claude
            SSHResult("", "", 0),  # tmpfs key write
            SSHResult(SAMPLE_OUTPUT, "", 0),  # claude invocation
            SSHResult("", "", 0),  # mkdir for output dir
        ]
        mock_write.return_value = None

        result = run_predep_discovery("test-vm", config)
        assert len(result["hidden_dependencies"]) == 2
        # Only 4 ssh_exec calls — no fallback cat
        assert mock_exec.call_count == 4

    @patch("thresher.agents.predep.ssh_write_file")
    @patch("thresher.agents.predep.ssh_exec")
    def test_handles_mkdir_failure_for_output(self, mock_exec, mock_write, config):
        """If mkdir for the output dir fails, return result without writing."""
        mock_exec.side_effect = [
            SSHResult("", "", 0),  # mkdir .claude
            SSHResult("", "", 0),  # tmpfs key write
            SSHResult(SAMPLE_OUTPUT, "", 0),  # claude invocation
            SSHResult("", "permission denied", 1),  # mkdir for output dir fails
        ]
        mock_write.return_value = None

        result = run_predep_discovery("test-vm", config)
        # Should still return parsed findings even though write failed
        assert len(result["hidden_dependencies"]) == 2
        # ssh_write_file should NOT be called for the output (only for prompt + hook)
        write_calls = [c[0] for c in mock_write.call_args_list]
        output_writes = [c for c in write_calls if "hidden_deps.json" in c[2]]
        assert len(output_writes) == 0
