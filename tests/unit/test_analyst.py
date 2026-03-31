"""Tests for threat_scanner.agents.analyst."""

from __future__ import annotations

import json

from threat_scanner.agents.analyst import (
    _empty_findings,
    _extract_json_from_text,
    _extract_result_from_stream,
    _parse_agent_json_output,
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
