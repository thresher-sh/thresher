"""Integration tests for agent pipeline with mocked SSH."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, call

from thresher.agents.analysts import run_all_analysts, ANALYST_DEFINITIONS
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


def _make_analyst_output(number: int, name: str, findings: list, risk_score: int = 3) -> str:
    """Create a valid analyst JSON output string."""
    return json.dumps({
        "analyst": name,
        "analyst_number": number,
        "core_question": "test question",
        "files_analyzed": 10,
        "findings": findings,
        "summary": f"Assessment from {name}",
        "risk_score": risk_score,
    })


class TestAnalystsPipeline:
    @patch("thresher.agents.analysts.ssh_write_file")
    @patch("thresher.agents.analysts.ssh_exec")
    def test_runs_all_eight_analysts(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult(
            '{"findings":[],"risk_score":0}', "", 0
        )
        mock_write.return_value = None

        run_all_analysts("vm", _make_config())

        # Each analyst: 1 ssh_exec for API key write + 1 ssh_exec for claude = 2
        # Total: 8 * 2 = 16 ssh_exec calls
        assert mock_exec.call_count == 16

    @patch("thresher.agents.analysts.ssh_write_file")
    @patch("thresher.agents.analysts.ssh_exec")
    def test_all_use_bash_in_allowed_tools(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult(
            '{"findings":[],"risk_score":0}', "", 0
        )
        mock_write.return_value = None

        run_all_analysts("vm", _make_config())

        cmds = [c[0][1] for c in mock_exec.call_args_list]
        claude_cmds = [c for c in cmds if "claude -p" in c]
        assert len(claude_cmds) == 8
        for cmd in claude_cmds:
            assert '"Read,Glob,Grep,Bash"' in cmd

    @patch("thresher.agents.analysts.ssh_write_file")
    @patch("thresher.agents.analysts.ssh_exec")
    def test_all_use_tmpfs_api_key(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult(
            '{"findings":[],"risk_score":0}', "", 0
        )
        mock_write.return_value = None

        run_all_analysts("vm", _make_config())

        cmds = [c[0][1] for c in mock_exec.call_args_list]
        key_writes = [c for c in cmds if "/dev/shm/.api_key_" in c and "printf" in c]
        assert len(key_writes) == 8

    @patch("thresher.agents.analysts.ssh_write_file")
    @patch("thresher.agents.analysts.ssh_exec")
    def test_writes_findings_to_correct_paths(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult(
            '{"findings":[],"risk_score":0}', "", 0
        )
        mock_write.return_value = None

        run_all_analysts("vm", _make_config())

        write_paths = [c[0][2] for c in mock_write.call_args_list]
        for analyst_def in ANALYST_DEFINITIONS:
            n = analyst_def["number"]
            name = analyst_def["name"]
            expected_json = f"/opt/scan-results/analyst-{n}-{name}-findings.json"
            expected_md = f"/opt/scan-results/analyst-{n}-{name}-findings.md"
            assert expected_json in write_paths, f"Missing {expected_json}"
            assert expected_md in write_paths, f"Missing {expected_md}"

    @patch("thresher.agents.analysts.ssh_write_file")
    @patch("thresher.agents.analysts.ssh_exec")
    def test_returns_none(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult(
            '{"findings":[],"risk_score":0}', "", 0
        )
        mock_write.return_value = None

        result = run_all_analysts("vm", _make_config())
        assert result is None


class TestAdversarialWithMultipleAnalysts:
    @patch("thresher.agents.adversarial.ssh_write_file")
    @patch("thresher.agents.adversarial.ssh_exec")
    def test_reads_multiple_analyst_files(self, mock_exec, mock_write):
        """Adversarial agent should merge findings from multiple analysts."""
        # First call: ls to discover files
        file_list = (
            "/opt/scan-results/analyst-1-paranoid-findings.json\n"
            "/opt/scan-results/analyst-2-behaviorist-findings.json\n"
        )
        # Second/third calls: cat each file
        paranoid_output = _make_analyst_output(1, "paranoid", [
            {
                "file_path": "/opt/target/setup.py",
                "risk_score": 7,
                "title": "base64 exec",
                "severity": "high",
                "description": "bad",
                "line_numbers": [1],
            }
        ], risk_score=7)

        behaviorist_output = _make_analyst_output(2, "behaviorist", [
            {
                "file_path": "/opt/target/utils.py",
                "risk_score": 5,
                "title": "unsafe deserialization",
                "severity": "medium",
                "description": "pickle load",
                "line_numbers": [10],
            }
        ], risk_score=5)

        mock_exec.side_effect = [
            SSHResult(file_list, "", 0),              # ls analyst files
            SSHResult(paranoid_output, "", 0),         # cat paranoid
            SSHResult(behaviorist_output, "", 0),      # cat behaviorist
            SSHResult("", "", 0),                      # write API key
            SSHResult(                                 # claude adversarial
                _load_agent_fixture("adversarial.json"), "", 0
            ),
        ]
        mock_write.return_value = None

        run_adversarial_verification("vm", _make_config())

        # Verify merged findings were written
        write_paths = [c[0][2] for c in mock_write.call_args_list]
        assert "/opt/scan-results/adversarial-findings.json" in write_paths

    @patch("thresher.agents.adversarial.ssh_write_file")
    @patch("thresher.agents.adversarial.ssh_exec")
    def test_falls_back_to_legacy_file(self, mock_exec, mock_write):
        """If no multi-analyst files exist, falls back to legacy format."""
        analyst_findings = json.dumps({
            "findings": [
                {"file_path": "/opt/target/setup.py", "risk_score": 7,
                 "findings": [{"description": "bad", "line_numbers": [1]}]},
            ]
        })
        mock_exec.side_effect = [
            SSHResult("", "", 1),                      # ls finds nothing
            SSHResult(analyst_findings, "", 0),         # cat legacy file
            SSHResult("", "", 0),                      # write API key
            SSHResult(                                 # claude adversarial
                _load_agent_fixture("adversarial.json"), "", 0
            ),
        ]
        mock_write.return_value = None

        run_adversarial_verification("vm", _make_config())

        # Should still work and produce output
        write_paths = [c[0][2] for c in mock_write.call_args_list]
        assert "/opt/scan-results/adversarial-findings.json" in write_paths

    @patch("thresher.agents.adversarial.ssh_write_file")
    @patch("thresher.agents.adversarial.ssh_exec")
    def test_findings_annotated_with_source_analyst(self, mock_exec, mock_write):
        """Each finding should include which analyst produced it."""
        file_list = "/opt/scan-results/analyst-1-paranoid-findings.json\n"
        paranoid_output = _make_analyst_output(1, "paranoid", [
            {
                "file_path": "/opt/target/setup.py",
                "risk_score": 7,
                "title": "base64 exec",
                "severity": "high",
                "description": "bad",
                "line_numbers": [1],
            }
        ], risk_score=7)

        mock_exec.side_effect = [
            SSHResult(file_list, "", 0),
            SSHResult(paranoid_output, "", 0),
            SSHResult("", "", 0),  # write API key
            SSHResult(_load_agent_fixture("adversarial.json"), "", 0),
        ]
        mock_write.return_value = None

        run_adversarial_verification("vm", _make_config())

        # Find the adversarial JSON write
        json_writes = [c for c in mock_write.call_args_list
                       if c[0][2] == "/opt/scan-results/adversarial-findings.json"]
        assert len(json_writes) == 1
        merged = json.loads(json_writes[0][0][1])

        # Check that findings have source_analyst annotation
        for finding in merged.get("findings", []):
            assert "source_analyst" in finding
            assert "source_analyst_number" in finding


class TestAdversarialPipeline:
    """Preserved legacy tests updated for the new architecture."""

    @patch("thresher.agents.adversarial.ssh_write_file")
    @patch("thresher.agents.adversarial.ssh_exec")
    def test_passes_api_key_via_tmpfs(self, mock_exec, mock_write):
        # First call: ls for analyst files (empty = fallback)
        # Second call: cat legacy analyst-findings.json
        analyst_findings = json.dumps({
            "findings": [
                {"file_path": "/opt/target/setup.py", "risk_score": 7,
                 "findings": [{"description": "bad", "line_numbers": [1]}]},
            ]
        })
        mock_exec.side_effect = [
            SSHResult("", "", 1),                      # ls finds nothing
            SSHResult(analyst_findings, "", 0),         # cat legacy
            SSHResult("", "", 0),                      # write API key to tmpfs
            SSHResult(_load_agent_fixture("adversarial.json"), "", 0),
        ]
        mock_write.return_value = None

        config = _make_config()
        run_adversarial_verification("vm", config)

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
        mock_exec.side_effect = [
            SSHResult("", "", 1),                      # ls finds nothing
            SSHResult(analyst_findings, "", 0),         # cat legacy
        ]
        mock_write.return_value = None

        result = run_adversarial_verification("vm", _make_config())
        assert result is None
