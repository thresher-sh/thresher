"""Integration tests for agent pipeline with mocked SSH."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, call

from threat_scanner.agents.analyst import run_analysis
from threat_scanner.agents.adversarial import run_adversarial_verification
from threat_scanner.config import ScanConfig, VMConfig
from threat_scanner.vm.ssh import SSHResult

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _make_config() -> ScanConfig:
    return ScanConfig(
        repo_url="https://github.com/x/y",
        anthropic_api_key="sk-ant-test-key",
        model="sonnet",
    )


def _load_agent_fixture(name: str) -> str:
    return (FIXTURES / "sample_agent_output" / name).read_text()


class TestAnalystPipeline:
    @patch("threat_scanner.agents.analyst.ssh_write_file")
    @patch("threat_scanner.agents.analyst.ssh_exec")
    def test_passes_api_key(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult(
            _load_agent_fixture("analyst_clean.json"), "", 0
        )
        mock_write.return_value = None

        config = _make_config()
        run_analysis("vm", config)

        claude_call = mock_exec.call_args
        assert claude_call.kwargs.get("env") == {"ANTHROPIC_API_KEY": "sk-ant-test-key"}

    @patch("threat_scanner.agents.analyst.ssh_write_file")
    @patch("threat_scanner.agents.analyst.ssh_exec")
    def test_timeout(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult("{}", "", 0)
        mock_write.return_value = None

        run_analysis("vm", _make_config())

        claude_call = mock_exec.call_args
        assert claude_call.kwargs.get("timeout") == 3600

    @patch("threat_scanner.agents.analyst.ssh_write_file")
    @patch("threat_scanner.agents.analyst.ssh_exec")
    def test_writes_prompt_safely(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult("{}", "", 0)
        mock_write.return_value = None

        run_analysis("vm", _make_config())

        assert mock_write.called
        write_call = mock_write.call_args_list[0]
        assert write_call[0][2] == "/tmp/analyst_prompt.txt"

    @patch("threat_scanner.agents.analyst.ssh_write_file")
    @patch("threat_scanner.agents.analyst.ssh_exec")
    def test_returns_parsed_findings(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult(
            _load_agent_fixture("analyst_clean.json"), "", 0
        )
        mock_write.return_value = None

        result = run_analysis("vm", _make_config())
        assert "findings" in result


class TestAdversarialPipeline:
    @patch("threat_scanner.agents.adversarial.ssh_write_file")
    @patch("threat_scanner.agents.adversarial.ssh_exec")
    def test_passes_api_key(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult(
            _load_agent_fixture("adversarial.json"), "", 0
        )
        mock_write.return_value = None

        ai_findings = {
            "findings": [
                {"file_path": "/opt/target/setup.py", "risk_score": 7,
                 "findings": [{"description": "bad", "line_numbers": [1]}]},
            ]
        }
        config = _make_config()
        run_adversarial_verification("vm", config, ai_findings)

        claude_call = mock_exec.call_args
        assert claude_call.kwargs.get("env") == {"ANTHROPIC_API_KEY": "sk-ant-test-key"}

    @patch("threat_scanner.agents.adversarial.ssh_exec")
    def test_skips_no_high_risk(self, mock_exec):
        ai_findings = {
            "findings": [
                {"file_path": "/a.py", "risk_score": 2, "findings": []},
            ]
        }
        result = run_adversarial_verification("vm", _make_config(), ai_findings)
        assert result == ai_findings
        mock_exec.assert_not_called()

    @patch("threat_scanner.agents.adversarial.ssh_write_file")
    @patch("threat_scanner.agents.adversarial.ssh_exec")
    def test_merge_flow(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult(
            _load_agent_fixture("adversarial.json"), "", 0
        )
        mock_write.return_value = None

        ai_findings = {
            "findings": [
                {"file_path": "/opt/target/setup.py", "risk_score": 7,
                 "findings": [{"description": "bad", "line_numbers": [1]}]},
                {"file_path": "/opt/target/conftest.py", "risk_score": 5,
                 "findings": [{"description": "maybe", "line_numbers": [10]}]},
            ]
        }
        result = run_adversarial_verification("vm", _make_config(), ai_findings)

        assert "adversarial_verification" in result
        setup = [f for f in result["findings"]
                 if f["file_path"] == "/opt/target/setup.py"][0]
        assert setup["adversarial_status"] == "confirmed"

        conftest = [f for f in result["findings"]
                    if f["file_path"] == "/opt/target/conftest.py"][0]
        assert conftest["adversarial_status"] == "downgraded"
        assert conftest["risk_score"] == 2
