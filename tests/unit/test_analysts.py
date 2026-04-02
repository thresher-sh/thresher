"""Tests for thresher.agents.analysts (multi-analyst architecture)."""

from __future__ import annotations

import json
from unittest.mock import patch, call, MagicMock

from thresher.agents.analysts import (
    ANALYST_DEFINITIONS,
    _build_analyst_prompt,
    _empty_findings,
    _extract_result_from_stream,
    _format_analyst_markdown,
    _parse_analyst_json_output,
    _run_single_analyst,
    run_all_analysts,
)
from thresher.config import ScanConfig
from thresher.vm.ssh import SSHResult


def _make_config() -> ScanConfig:
    return ScanConfig(
        repo_url="https://github.com/x/y",
        anthropic_api_key="sk-ant-test-key",
        model="sonnet",
    )


class TestAnalystDefinitions:
    def test_eight_analysts_defined(self):
        assert len(ANALYST_DEFINITIONS) == 8

    def test_numbers_are_sequential(self):
        numbers = [a["number"] for a in ANALYST_DEFINITIONS]
        assert numbers == list(range(1, 9))

    def test_names_are_unique(self):
        names = [a["name"] for a in ANALYST_DEFINITIONS]
        assert len(names) == len(set(names))

    def test_all_have_required_fields(self):
        required = {"number", "name", "title", "core_question", "tools", "max_turns", "prompt"}
        for a in ANALYST_DEFINITIONS:
            missing = required - set(a.keys())
            assert not missing, f"Analyst {a.get('name', '?')} missing: {missing}"

    def test_shadowcatcher_gets_40_turns(self):
        shadowcatcher = [a for a in ANALYST_DEFINITIONS if a["name"] == "shadowcatcher"][0]
        assert shadowcatcher["max_turns"] == 40

    def test_others_get_30_turns(self):
        non_shadow = [a for a in ANALYST_DEFINITIONS if a["name"] != "shadowcatcher"]
        for a in non_shadow:
            assert a["max_turns"] == 30, f"{a['name']} should have max_turns=30"


class TestBuildAnalystPrompt:
    def test_includes_persona(self):
        analyst = ANALYST_DEFINITIONS[0]
        prompt = _build_analyst_prompt(analyst)
        # The prompt includes the persona name (title may be paraphrased)
        assert "The Paranoid" in prompt
        assert analyst["core_question"] in prompt

    def test_includes_output_format(self):
        analyst = ANALYST_DEFINITIONS[0]
        prompt = _build_analyst_prompt(analyst)
        assert '"analyst"' in prompt
        assert '"findings"' in prompt
        assert '"risk_score"' in prompt

    def test_includes_name_in_output(self):
        analyst = ANALYST_DEFINITIONS[0]
        prompt = _build_analyst_prompt(analyst)
        assert f'"analyst": "{analyst["name"]}"' in prompt


class TestExtractResultFromStream:
    def test_stream_json(self):
        stream = (
            '{"type":"progress","message":"working"}\n'
            '{"type":"result","result":"hello world"}\n'
        )
        assert _extract_result_from_stream(stream) == "hello world"

    def test_fallback(self):
        assert _extract_result_from_stream("plain text") == "plain text"

    def test_empty(self):
        assert _extract_result_from_stream("") == ""


class TestParseAnalystJsonOutput:
    def _analyst(self):
        return ANALYST_DEFINITIONS[0]

    def test_empty_input(self):
        result = _parse_analyst_json_output("", self._analyst())
        assert "error" in result
        assert result["analyst"] == "paranoid"

    def test_direct_json(self):
        data = json.dumps({
            "analyst": "paranoid",
            "findings": [{"title": "test", "severity": "high"}],
            "risk_score": 5,
        })
        result = _parse_analyst_json_output(data, self._analyst())
        assert len(result["findings"]) == 1
        assert result["risk_score"] == 5

    def test_stream_json_with_result(self):
        findings = {
            "analyst": "paranoid",
            "findings": [{"title": "x"}],
            "risk_score": 3,
        }
        stream = (
            '{"type":"progress","message":"analyzing"}\n'
            f'{{"type":"result","result":{json.dumps(json.dumps(findings))}}}\n'
        )
        result = _parse_analyst_json_output(stream, self._analyst())
        assert len(result["findings"]) == 1

    def test_json_in_code_block(self):
        text = 'Here is my analysis:\n```json\n{"findings": [], "risk_score": 0}\n```\n'
        result = _parse_analyst_json_output(text, self._analyst())
        assert result["findings"] == []


class TestEmptyFindings:
    def test_structure(self):
        analyst = ANALYST_DEFINITIONS[0]
        result = _empty_findings(analyst, "test reason")
        assert result["analyst"] == "paranoid"
        assert result["analyst_number"] == 1
        assert result["findings"] == []
        assert result["error"] == "test reason"


class TestFormatAnalystMarkdown:
    def test_empty_findings(self):
        analyst = ANALYST_DEFINITIONS[0]
        findings = {"findings": [], "summary": "All clear", "risk_score": 0}
        md = _format_analyst_markdown(findings, analyst)
        assert "Analyst 1" in md
        assert "The Paranoid" in md
        assert "No concerns" in md

    def test_with_findings(self):
        analyst = ANALYST_DEFINITIONS[0]
        findings = {
            "findings": [
                {
                    "title": "Suspicious eval",
                    "severity": "high",
                    "confidence": 85,
                    "file_path": "/opt/target/main.py",
                    "line_numbers": [42],
                    "description": "eval with user input",
                }
            ],
            "summary": "Found issues",
            "risk_score": 7,
        }
        md = _format_analyst_markdown(findings, analyst)
        assert "[HIGH]" in md
        assert "Suspicious eval" in md
        assert "main.py" in md


class TestRunSingleAnalyst:
    @patch("thresher.agents.analysts.ssh_write_file")
    @patch("thresher.agents.analysts.ssh_exec")
    def test_writes_prompt_to_correct_path(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult('{"findings":[],"risk_score":0}', "", 0)
        mock_write.return_value = None

        analyst = ANALYST_DEFINITIONS[0]
        _run_single_analyst("vm", _make_config(), analyst)

        # Check prompt was written to /tmp/analyst_1_prompt.txt
        prompt_write = mock_write.call_args_list[0]
        assert prompt_write[0][2] == "/tmp/analyst_1_prompt.txt"

    @patch("thresher.agents.analysts.ssh_write_file")
    @patch("thresher.agents.analysts.ssh_exec")
    def test_uses_bash_in_allowed_tools(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult('{"findings":[],"risk_score":0}', "", 0)
        mock_write.return_value = None

        analyst = ANALYST_DEFINITIONS[0]
        _run_single_analyst("vm", _make_config(), analyst)

        # Find the claude invocation command
        cmds = [c[0][1] for c in mock_exec.call_args_list]
        claude_cmd = [c for c in cmds if "claude -p" in c][0]
        assert '"Read,Glob,Grep,Bash"' in claude_cmd

    @patch("thresher.agents.analysts.ssh_write_file")
    @patch("thresher.agents.analysts.ssh_exec")
    def test_api_key_uses_tmpfs_pattern(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult('{"findings":[],"risk_score":0}', "", 0)
        mock_write.return_value = None

        analyst = ANALYST_DEFINITIONS[0]
        _run_single_analyst("vm", _make_config(), analyst)

        cmds = [c[0][1] for c in mock_exec.call_args_list]
        # First ssh_exec writes key to /dev/shm
        assert any("/dev/shm/.api_key_1" in cmd for cmd in cmds)
        # Claude command reads from tmpfs and deletes
        claude_cmd = [c for c in cmds if "claude -p" in c][0]
        assert "ANTHROPIC_API_KEY=$(cat /dev/shm/.api_key_1)" in claude_cmd
        assert "rm -f /dev/shm/.api_key_1" in claude_cmd

    @patch("thresher.agents.analysts.ssh_write_file")
    @patch("thresher.agents.analysts.ssh_exec")
    def test_writes_findings_to_correct_vm_path(self, mock_exec, mock_write):
        findings = json.dumps({
            "analyst": "paranoid",
            "findings": [{"title": "test"}],
            "risk_score": 5,
        })
        mock_exec.return_value = SSHResult(findings, "", 0)
        mock_write.return_value = None

        analyst = ANALYST_DEFINITIONS[0]
        _run_single_analyst("vm", _make_config(), analyst)

        write_paths = [c[0][2] for c in mock_write.call_args_list]
        assert "/opt/scan-results/analyst-1-paranoid-findings.json" in write_paths
        assert "/opt/scan-results/analyst-1-paranoid-findings.md" in write_paths

    @patch("thresher.agents.analysts.ssh_write_file")
    @patch("thresher.agents.analysts.ssh_exec")
    def test_returns_none(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult('{"findings":[],"risk_score":0}', "", 0)
        mock_write.return_value = None

        analyst = ANALYST_DEFINITIONS[0]
        result = _run_single_analyst("vm", _make_config(), analyst)
        assert result is None

    @patch("thresher.agents.analysts.ssh_write_file")
    @patch("thresher.agents.analysts.ssh_exec")
    def test_unique_tmpfs_key_paths(self, mock_exec, mock_write):
        """Each analyst uses a unique tmpfs path to avoid race conditions."""
        mock_exec.return_value = SSHResult('{"findings":[],"risk_score":0}', "", 0)
        mock_write.return_value = None

        config = _make_config()

        # Run two different analysts
        _run_single_analyst("vm", config, ANALYST_DEFINITIONS[0])
        _run_single_analyst("vm", config, ANALYST_DEFINITIONS[1])

        cmds = [c[0][1] for c in mock_exec.call_args_list]
        key_writes = [c for c in cmds if "/dev/shm/.api_key_" in c and "printf" in c]
        assert "/dev/shm/.api_key_1" in key_writes[0]
        assert "/dev/shm/.api_key_2" in key_writes[1]


class TestRunAllAnalysts:
    @patch("thresher.agents.analysts._run_single_analyst")
    def test_launches_eight_analysts(self, mock_run):
        mock_run.return_value = None

        run_all_analysts("vm", _make_config())

        assert mock_run.call_count == 8

    @patch("thresher.agents.analysts._run_single_analyst")
    def test_passes_all_analyst_defs(self, mock_run):
        mock_run.return_value = None

        run_all_analysts("vm", _make_config())

        called_numbers = sorted(
            c[0][2]["number"] for c in mock_run.call_args_list
        )
        assert called_numbers == list(range(1, 9))

    @patch("thresher.agents.analysts._run_single_analyst")
    def test_returns_none(self, mock_run):
        mock_run.return_value = None
        result = run_all_analysts("vm", _make_config())
        assert result is None

    @patch("thresher.agents.analysts._run_single_analyst")
    def test_continues_on_analyst_failure(self, mock_run):
        """If one analyst raises, others should still complete."""
        call_count = 0

        def side_effect(vm, config, analyst_def):
            nonlocal call_count
            call_count += 1
            if analyst_def["number"] == 3:
                raise RuntimeError("analyst 3 exploded")

        mock_run.side_effect = side_effect

        # Should not raise
        run_all_analysts("vm", _make_config())
        assert call_count == 8
