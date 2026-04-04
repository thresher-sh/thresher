"""Tests for thresher.agents.analysts (multi-analyst architecture)."""

from __future__ import annotations

import json
from unittest.mock import patch, call, MagicMock

from thresher.agents.analysts import (
    ANALYST_DEFINITIONS,
    _build_analyst_prompt,
    _count_turns_from_stream,
    _empty_findings,
    _extract_result_from_stream,
    _format_analyst_markdown,
    _log_timing_summary,
    _parse_analyst_json_output,
    _run_single_analyst,
    _validate_analyst_schema,
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

    def test_error_max_turns_with_assistant_fallback(self):
        """When agent hits max_turns, use last assistant text as fallback."""
        findings_json = json.dumps({
            "analyst": "paranoid",
            "findings": [{"title": "partial", "severity": "high"}],
            "summary": "partial results",
            "risk_score": 5,
        })
        stream = (
            '{"type":"system","subtype":"init","cwd":"/opt/target","session_id":"abc"}\n'
            f'{{"type":"assistant","message":{{"content":[{{"type":"text","text":{json.dumps(findings_json)}}}]}}}}\n'
            '{"type":"result","subtype":"error_max_turns","is_error":true}\n'
        )
        result = _extract_result_from_stream(stream)
        assert result == findings_json

    def test_error_max_turns_no_text_returns_empty(self):
        """When agent hits max_turns with no text output, return empty string."""
        stream = (
            '{"type":"system","subtype":"init","cwd":"/opt/target","session_id":"abc"}\n'
            '{"type":"result","subtype":"error_max_turns","is_error":true}\n'
        )
        result = _extract_result_from_stream(stream)
        assert result == ""

    def test_successful_result_preferred_over_error_fallback(self):
        stream = (
            '{"type":"assistant","message":{"content":[{"type":"text","text":"partial"}]}}\n'
            '{"type":"result","result":"final"}\n'
        )
        assert _extract_result_from_stream(stream) == "final"


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
            "summary": "Found issues",
            "risk_score": 5,
        })
        result = _parse_analyst_json_output(data, self._analyst())
        assert len(result["findings"]) == 1
        assert result["risk_score"] == 5

    def test_stream_json_with_result(self):
        findings = {
            "analyst": "paranoid",
            "findings": [{"title": "x"}],
            "summary": "test",
            "risk_score": 3,
        }
        stream = (
            '{"type":"progress","message":"analyzing"}\n'
            f'{{"type":"result","result":{json.dumps(json.dumps(findings))}}}\n'
        )
        result = _parse_analyst_json_output(stream, self._analyst())
        assert len(result["findings"]) == 1

    def test_json_in_code_block(self):
        text = 'Here is my analysis:\n```json\n{"analyst": "paranoid", "findings": [], "summary": "clean", "risk_score": 0}\n```\n'
        result = _parse_analyst_json_output(text, self._analyst())
        assert result["findings"] == []

    def test_rejects_predep_schema(self):
        """Output with hidden_dependencies but no findings should be rejected."""
        data = json.dumps({
            "hidden_dependencies": [{"type": "npm", "source": "foo"}],
            "files_scanned": 100,
            "summary": "Found deps",
        })
        result = _parse_analyst_json_output(data, self._analyst())
        assert "error" in result
        assert result["findings"] == []

    def test_rejects_missing_required_keys(self):
        """Output missing required analyst keys should be rejected."""
        data = json.dumps({"some_other_key": "value"})
        result = _parse_analyst_json_output(data, self._analyst())
        assert "error" in result


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
    def _valid_output(self):
        return json.dumps({
            "analyst": "paranoid",
            "findings": [],
            "summary": "All clear",
            "risk_score": 0,
        })

    def _valid_output_with_findings(self):
        return json.dumps({
            "analyst": "paranoid",
            "findings": [{"title": "test", "severity": "high"}],
            "summary": "Found issues",
            "risk_score": 5,
        })

    @patch("thresher.agents.analysts.ssh_write_file")
    @patch("thresher.agents.analysts.ssh_exec")
    def test_writes_prompt_to_correct_path(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult(self._valid_output(), "", 0)
        mock_write.return_value = None

        analyst = ANALYST_DEFINITIONS[0]
        _run_single_analyst("vm", _make_config(), analyst)

        # Check prompt was written to /tmp/analyst_1_prompt.txt
        prompt_write = mock_write.call_args_list[0]
        assert prompt_write[0][2] == "/tmp/analyst_1_prompt.txt"

    @patch("thresher.agents.analysts.ssh_write_file")
    @patch("thresher.agents.analysts.ssh_exec")
    def test_global_max_turns_overrides_yaml(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult(self._valid_output(), "", 0)
        mock_write.return_value = None

        config = _make_config()
        config.analyst_max_turns = 50

        analyst = ANALYST_DEFINITIONS[0]
        _run_single_analyst("vm", config, analyst)

        cmds = [c[0][1] for c in mock_exec.call_args_list]
        claude_cmd = [c for c in cmds if "claude -p" in c][0]
        assert "--max-turns 50" in claude_cmd

    @patch("thresher.agents.analysts.ssh_write_file")
    @patch("thresher.agents.analysts.ssh_exec")
    def test_per_analyst_overrides_global(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult(self._valid_output(), "", 0)
        mock_write.return_value = None

        config = _make_config()
        config.analyst_max_turns = 50
        config.analyst_max_turns_by_name = {"paranoid": 60}

        analyst = ANALYST_DEFINITIONS[0]  # paranoid
        _run_single_analyst("vm", config, analyst)

        cmds = [c[0][1] for c in mock_exec.call_args_list]
        claude_cmd = [c for c in cmds if "claude -p" in c][0]
        assert "--max-turns 60" in claude_cmd

    @patch("thresher.agents.analysts.ssh_write_file")
    @patch("thresher.agents.analysts.ssh_exec")
    def test_unmatched_per_analyst_falls_to_global(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult(self._valid_output(), "", 0)
        mock_write.return_value = None

        config = _make_config()
        config.analyst_max_turns = 50
        config.analyst_max_turns_by_name = {"shadowcatcher": 80}

        analyst = ANALYST_DEFINITIONS[0]  # paranoid — not in by_name
        _run_single_analyst("vm", config, analyst)

        cmds = [c[0][1] for c in mock_exec.call_args_list]
        claude_cmd = [c for c in cmds if "claude -p" in c][0]
        assert "--max-turns 50" in claude_cmd

    @patch("thresher.agents.analysts.ssh_write_file")
    @patch("thresher.agents.analysts.ssh_exec")
    def test_none_max_turns_uses_yaml_default(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult(self._valid_output(), "", 0)
        mock_write.return_value = None

        config = _make_config()
        assert config.analyst_max_turns is None

        analyst = ANALYST_DEFINITIONS[0]  # paranoid, max_turns=30
        _run_single_analyst("vm", config, analyst)

        cmds = [c[0][1] for c in mock_exec.call_args_list]
        claude_cmd = [c for c in cmds if "claude -p" in c][0]
        assert "--max-turns 30" in claude_cmd

    @patch("thresher.agents.analysts.ssh_write_file")
    @patch("thresher.agents.analysts.ssh_exec")
    def test_uses_bash_in_allowed_tools(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult(self._valid_output(), "", 0)
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
        mock_exec.return_value = SSHResult(self._valid_output(), "", 0)
        mock_write.return_value = None

        analyst = ANALYST_DEFINITIONS[0]
        _run_single_analyst("vm", _make_config(), analyst)

        cmds = [c[0][1] for c in mock_exec.call_args_list]
        # First ssh_exec writes key to /dev/shm
        assert any("/dev/shm/.cred_ANTHROPIC_API_KEY_1" in cmd for cmd in cmds)
        # Claude command reads from tmpfs and deletes
        claude_cmd = [c for c in cmds if "claude -p" in c][0]
        assert "ANTHROPIC_API_KEY=$(cat /dev/shm/.cred_ANTHROPIC_API_KEY_1)" in claude_cmd
        assert "rm -f /dev/shm/.cred_ANTHROPIC_API_KEY_1" in claude_cmd

    @patch("thresher.agents.analysts.ssh_write_file")
    @patch("thresher.agents.analysts.ssh_exec")
    def test_writes_findings_to_correct_vm_path(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult(self._valid_output_with_findings(), "", 0)
        mock_write.return_value = None

        analyst = ANALYST_DEFINITIONS[0]
        _run_single_analyst("vm", _make_config(), analyst)

        write_paths = [c[0][2] for c in mock_write.call_args_list]
        assert "/opt/scan-results/analyst-1-paranoid-findings.json" in write_paths
        assert "/opt/scan-results/analyst-1-paranoid-findings.md" in write_paths

    @patch("thresher.agents.analysts.ssh_write_file")
    @patch("thresher.agents.analysts.ssh_exec")
    def test_returns_timing_dict(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult(self._valid_output(), "", 0)
        mock_write.return_value = None

        analyst = ANALYST_DEFINITIONS[0]
        result = _run_single_analyst("vm", _make_config(), analyst)
        assert result is not None
        assert result["name"] == "paranoid"
        assert isinstance(result["duration"], float)

    @patch("thresher.agents.analysts.ssh_write_file")
    @patch("thresher.agents.analysts.ssh_exec")
    def test_unique_tmpfs_key_paths(self, mock_exec, mock_write):
        """Each analyst uses a unique tmpfs path to avoid race conditions."""
        mock_exec.return_value = SSHResult(self._valid_output(), "", 0)
        mock_write.return_value = None

        config = _make_config()

        # Run two different analysts
        _run_single_analyst("vm", config, ANALYST_DEFINITIONS[0])
        _run_single_analyst("vm", config, ANALYST_DEFINITIONS[1])

        cmds = [c[0][1] for c in mock_exec.call_args_list]
        key_writes = [c for c in cmds if "/dev/shm/.cred_ANTHROPIC_API_KEY_" in c and "printf" in c]
        assert "/dev/shm/.cred_ANTHROPIC_API_KEY_1" in key_writes[0]
        assert "/dev/shm/.cred_ANTHROPIC_API_KEY_2" in key_writes[1]


class TestValidateAnalystSchema:
    def _analyst(self):
        return ANALYST_DEFINITIONS[0]

    def test_valid_schema(self):
        data = {
            "analyst": "paranoid",
            "findings": [],
            "summary": "clean",
            "risk_score": 0,
        }
        assert _validate_analyst_schema(data, self._analyst()) == data

    def test_rejects_predep_schema(self):
        data = {
            "hidden_dependencies": [{"type": "npm"}],
            "files_scanned": 10,
            "summary": "found deps",
        }
        assert _validate_analyst_schema(data, self._analyst()) is None

    def test_rejects_missing_findings(self):
        data = {"analyst": "paranoid", "summary": "ok", "risk_score": 0}
        assert _validate_analyst_schema(data, self._analyst()) is None

    def test_rejects_missing_risk_score(self):
        data = {"analyst": "paranoid", "findings": [], "summary": "ok"}
        assert _validate_analyst_schema(data, self._analyst()) is None

    def test_rejects_non_dict(self):
        assert _validate_analyst_schema("string", self._analyst()) is None
        assert _validate_analyst_schema([], self._analyst()) is None

    def test_accepts_with_extra_keys(self):
        data = {
            "analyst": "paranoid",
            "findings": [],
            "summary": "clean",
            "risk_score": 0,
            "files_analyzed": 50,
            "extra": "ok",
        }
        assert _validate_analyst_schema(data, self._analyst()) == data


class TestRunAllAnalysts:
    @patch("thresher.agents.analysts.ssh_write_file")
    @patch("thresher.agents.analysts.ssh_exec")
    @patch("thresher.agents.analysts._run_single_analyst")
    def test_launches_eight_analysts(self, mock_run, mock_exec, mock_write):
        mock_run.return_value = None
        mock_exec.return_value = SSHResult("", "", 0)
        mock_write.return_value = None

        run_all_analysts("vm", _make_config())

        assert mock_run.call_count == 8

    @patch("thresher.agents.analysts.ssh_write_file")
    @patch("thresher.agents.analysts.ssh_exec")
    @patch("thresher.agents.analysts._run_single_analyst")
    def test_installs_analyst_stop_hook(self, mock_run, mock_exec, mock_write):
        """Stop hook should be written before analysts launch."""
        mock_run.return_value = None
        mock_exec.return_value = SSHResult("", "", 0)
        mock_write.return_value = None

        run_all_analysts("vm", _make_config())

        # Check stop hook settings were written
        write_paths = [c[0][2] for c in mock_write.call_args_list]
        assert "/opt/target/.claude/settings.local.json" in write_paths

        # Verify it references the analyst validation script
        hook_write = [c for c in mock_write.call_args_list
                      if c[0][2] == "/opt/target/.claude/settings.local.json"][0]
        assert "validate_analyst_output.sh" in hook_write[0][1]

    @patch("thresher.agents.analysts.ssh_write_file")
    @patch("thresher.agents.analysts.ssh_exec")
    @patch("thresher.agents.analysts._run_single_analyst")
    def test_passes_all_analyst_defs(self, mock_run, mock_exec, mock_write):
        mock_run.return_value = None
        mock_exec.return_value = SSHResult("", "", 0)
        mock_write.return_value = None

        run_all_analysts("vm", _make_config())

        called_numbers = sorted(
            c[0][2]["number"] for c in mock_run.call_args_list
        )
        assert called_numbers == list(range(1, 9))

    @patch("thresher.agents.analysts.ssh_write_file")
    @patch("thresher.agents.analysts.ssh_exec")
    @patch("thresher.agents.analysts._run_single_analyst")
    def test_returns_none(self, mock_run, mock_exec, mock_write):
        mock_run.return_value = None
        mock_exec.return_value = SSHResult("", "", 0)
        mock_write.return_value = None
        result = run_all_analysts("vm", _make_config())
        assert result is None

    @patch("thresher.agents.analysts.ssh_write_file")
    @patch("thresher.agents.analysts.ssh_exec")
    @patch("thresher.agents.analysts._run_single_analyst")
    def test_continues_on_analyst_failure(self, mock_run, mock_exec, mock_write):
        """If one analyst raises, others should still complete."""
        mock_exec.return_value = SSHResult("", "", 0)
        mock_write.return_value = None
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


class TestCountTurnsFromStream:
    def test_counts_assistant_messages(self):
        stream = (
            '{"type":"system","subtype":"init"}\n'
            '{"type":"assistant","message":{"content":[{"type":"text","text":"turn 1"}]}}\n'
            '{"type":"assistant","message":{"content":[{"type":"text","text":"turn 2"}]}}\n'
            '{"type":"result","result":"done"}\n'
        )
        assert _count_turns_from_stream(stream) == 2

    def test_empty_stream(self):
        assert _count_turns_from_stream("") == 0

    def test_no_assistant_messages(self):
        stream = '{"type":"system","subtype":"init"}\n{"type":"result","result":"done"}\n'
        assert _count_turns_from_stream(stream) == 0

    def test_ignores_invalid_json(self):
        stream = (
            'not json\n'
            '{"type":"assistant","message":{"content":[]}}\n'
            'also not json\n'
        )
        assert _count_turns_from_stream(stream) == 1


class TestRunSingleAnalystTiming:
    def _valid_stream_output(self):
        findings = json.dumps({
            "analyst": "paranoid",
            "findings": [],
            "summary": "All clear",
            "risk_score": 0,
        })
        return (
            '{"type":"system","subtype":"init"}\n'
            f'{{"type":"assistant","message":{{"content":[{{"type":"text","text":{json.dumps(findings)}}}]}}}}\n'
            f'{{"type":"result","result":{json.dumps(findings)}}}\n'
        )

    @patch("thresher.agents.analysts.ssh_write_file")
    @patch("thresher.agents.analysts.ssh_exec")
    def test_returns_timing_metadata(self, mock_exec, mock_write):
        mock_exec.return_value = SSHResult(self._valid_stream_output(), "", 0)
        mock_write.return_value = None

        analyst = ANALYST_DEFINITIONS[0]
        result = _run_single_analyst("vm", _make_config(), analyst)

        assert result is not None
        assert result["name"] == "paranoid"
        assert isinstance(result["duration"], float)
        assert result["duration"] >= 0
        assert result["turns"] == 1

    @patch("thresher.agents.analysts.ssh_write_file")
    @patch("thresher.agents.analysts.ssh_exec")
    def test_returns_none_on_ssh_failure(self, mock_exec, mock_write):
        mock_write.return_value = None

        def ssh_side_effect(vm, cmd, **kwargs):
            # Credential writes succeed; the claude invocation fails
            if "claude -p" in cmd:
                raise RuntimeError("SSH died")
            return SSHResult("", "", 0)

        mock_exec.side_effect = ssh_side_effect

        analyst = ANALYST_DEFINITIONS[0]
        result = _run_single_analyst("vm", _make_config(), analyst)
        assert result is None

    @patch("thresher.agents.analysts.ssh_write_file")
    @patch("thresher.agents.analysts.ssh_exec")
    def test_returns_none_on_prompt_write_failure(self, mock_exec, mock_write):
        mock_write.side_effect = RuntimeError("write failed")

        analyst = ANALYST_DEFINITIONS[0]
        result = _run_single_analyst("vm", _make_config(), analyst)
        assert result is None


class TestLogTimingSummary:
    def test_logs_summary_table(self, caplog):
        import logging
        timings = [
            {"name": "paranoid", "duration": 301.2, "turns": 10},
            {"name": "behaviorist", "duration": 572.4, "turns": 15},
            {"name": "netwatch", "duration": 200.0, "turns": 8},
        ]
        with caplog.at_level(logging.INFO, logger="thresher.agents.analysts"):
            _log_timing_summary(timings)

        assert "Analyst timing summary:" in caplog.text
        assert "paranoid" in caplog.text
        assert "behaviorist" in caplog.text
        assert "[SLOWEST]" in caplog.text
        assert "572.4s" in caplog.text

    def test_warns_when_analyst_exceeds_2x_median(self, caplog):
        import logging
        timings = [
            {"name": "fast1", "duration": 100.0, "turns": 5},
            {"name": "fast2", "duration": 110.0, "turns": 6},
            {"name": "slow", "duration": 500.0, "turns": 20},
        ]
        with caplog.at_level(logging.WARNING, logger="thresher.agents.analysts"):
            _log_timing_summary(timings)

        assert "consider reducing prompt scope" in caplog.text
        assert "slow" in caplog.text

    def test_no_warning_when_all_similar(self, caplog):
        import logging
        timings = [
            {"name": "a", "duration": 100.0, "turns": 5},
            {"name": "b", "duration": 110.0, "turns": 6},
            {"name": "c", "duration": 105.0, "turns": 5},
        ]
        with caplog.at_level(logging.WARNING, logger="thresher.agents.analysts"):
            _log_timing_summary(timings)

        assert "consider reducing prompt scope" not in caplog.text

    def test_empty_timings(self, caplog):
        import logging
        with caplog.at_level(logging.INFO, logger="thresher.agents.analysts"):
            _log_timing_summary([])
        assert "timing summary" not in caplog.text

    def test_single_analyst_no_slowest_tag(self, caplog):
        import logging
        timings = [{"name": "paranoid", "duration": 300.0, "turns": 10}]
        with caplog.at_level(logging.INFO, logger="thresher.agents.analysts"):
            _log_timing_summary(timings)

        assert "paranoid" in caplog.text
        assert "[SLOWEST]" not in caplog.text
