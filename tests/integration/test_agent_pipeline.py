"""Integration tests for agent pipeline with mocked SSH."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, call

from thresher.agents.analyst import run_analysis
from thresher.agents.adversarial import run_adversarial_verification
from thresher.config import ScanConfig, VMConfig
from thresher.vm.ssh import SSHResult

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
    @patch("thresher.agents.analyst.ssh_write_file")
    @patch("thresher.agents.analyst.ssh_exec")
    def test_passes_api_key_via_tmpfs(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult(
            _load_agent_fixture("analyst_clean.json"), "", 0
        )
        mock_write.return_value = None

        config = _make_config()
        run_analysis("vm", config)

        # API key is now written to tmpfs, then read-and-deleted inline
        cmds = [c[0][1] for c in mock_exec.call_args_list]
        # First ssh_exec writes the key to /dev/shm
        assert any("/dev/shm/.api_key" in cmd for cmd in cmds)
        # The claude command reads from tmpfs and deletes
        claude_cmd = cmds[-1]  # last call is the claude invocation
        assert "ANTHROPIC_API_KEY=$(cat /dev/shm/.api_key)" in claude_cmd
        assert "rm -f /dev/shm/.api_key" in claude_cmd

    @patch("thresher.agents.analyst.ssh_write_file")
    @patch("thresher.agents.analyst.ssh_exec")
    def test_timeout(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult("{}", "", 0)
        mock_write.return_value = None

        run_analysis("vm", _make_config())

        claude_call = mock_exec.call_args
        assert claude_call.kwargs.get("timeout") == 3600

    @patch("thresher.agents.analyst.ssh_write_file")
    @patch("thresher.agents.analyst.ssh_exec")
    def test_writes_prompt_safely(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult("{}", "", 0)
        mock_write.return_value = None

        run_analysis("vm", _make_config())

        assert mock_write.called
        write_call = mock_write.call_args_list[0]
        assert write_call[0][2] == "/tmp/analyst_prompt.txt"

    @patch("thresher.agents.analyst.ssh_write_file")
    @patch("thresher.agents.analyst.ssh_exec")
    def test_writes_findings_to_vm(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult(
            _load_agent_fixture("analyst_clean.json"), "", 0
        )
        mock_write.return_value = None

        result = run_analysis("vm", _make_config())
        # run_analysis now returns None (findings stay in VM)
        assert result is None
        # Verify findings JSON was written to VM
        write_paths = [c[0][2] for c in mock_write.call_args_list]
        assert "/opt/scan-results/analyst-findings.json" in write_paths
        assert "/opt/scan-results/analyst-findings.md" in write_paths


class TestAdversarialPipeline:
    @patch("thresher.agents.adversarial.ssh_write_file")
    @patch("thresher.agents.adversarial.ssh_exec")
    def test_passes_api_key_via_tmpfs(self, mock_exec, mock_write):
        # First call: cat analyst-findings.json (reads from VM)
        analyst_findings = json.dumps({
            "findings": [
                {"file_path": "/opt/target/setup.py", "risk_score": 7,
                 "findings": [{"description": "bad", "line_numbers": [1]}]},
            ]
        })
        mock_exec.side_effect = [
            SSHResult(analyst_findings, "", 0),  # cat analyst-findings.json
            SSHResult("", "", 0),  # write API key to tmpfs
            SSHResult(_load_agent_fixture("adversarial.json"), "", 0),  # claude
        ]
        mock_write.return_value = None

        config = _make_config()
        run_adversarial_verification("vm", config)

        # API key is now written to tmpfs, then read-and-deleted inline
        cmds = [c[0][1] for c in mock_exec.call_args_list]
        assert any("/dev/shm/.api_key" in cmd for cmd in cmds)
        claude_cmd = cmds[-1]
        assert "ANTHROPIC_API_KEY=$(cat /dev/shm/.api_key)" in claude_cmd
        assert "rm -f /dev/shm/.api_key" in claude_cmd

    @patch("thresher.agents.adversarial.ssh_write_file")
    @patch("thresher.agents.adversarial.ssh_exec")
    def test_skips_no_high_risk(self, mock_exec, mock_write):
        analyst_findings = json.dumps({
            "findings": [
                {"file_path": "/a.py", "risk_score": 2, "findings": []},
            ]
        })
        mock_exec.return_value = SSHResult(analyst_findings, "", 0)
        mock_write.return_value = None

        result = run_adversarial_verification("vm", _make_config())
        assert result is None
        # Only the cat call should have been made (no claude invocation)
        assert mock_exec.call_count == 1

    @patch("thresher.agents.adversarial.ssh_write_file")
    @patch("thresher.agents.adversarial.ssh_exec")
    def test_merge_flow(self, mock_exec, mock_write):
        analyst_findings = json.dumps({
            "findings": [
                {"file_path": "/opt/target/setup.py", "risk_score": 7,
                 "findings": [{"description": "bad", "line_numbers": [1]}]},
                {"file_path": "/opt/target/conftest.py", "risk_score": 5,
                 "findings": [{"description": "maybe", "line_numbers": [10]}]},
            ]
        })
        mock_exec.side_effect = [
            SSHResult(analyst_findings, "", 0),  # cat analyst-findings.json
            SSHResult("", "", 0),  # write API key to tmpfs
            SSHResult(_load_agent_fixture("adversarial.json"), "", 0),  # claude
        ]
        mock_write.return_value = None

        result = run_adversarial_verification("vm", _make_config())
        # run_adversarial_verification now returns None (findings stay in VM)
        assert result is None

        # Verify merged findings JSON was written to VM
        write_paths = [c[0][2] for c in mock_write.call_args_list]
        assert "/opt/scan-results/adversarial-findings.json" in write_paths
        assert "/opt/scan-results/adversarial-findings.md" in write_paths

        # Verify the merged JSON contains adversarial verification data
        json_write = [c for c in mock_write.call_args_list
                      if c[0][2] == "/opt/scan-results/adversarial-findings.json"][0]
        merged = json.loads(json_write[0][1])
        assert "adversarial_verification" in merged
        setup = [f for f in merged["findings"]
                 if f["file_path"] == "/opt/target/setup.py"][0]
        assert setup["adversarial_status"] == "confirmed"

        conftest = [f for f in merged["findings"]
                    if f["file_path"] == "/opt/target/conftest.py"][0]
        assert conftest["adversarial_status"] == "downgraded"
        assert conftest["risk_score"] == 2
