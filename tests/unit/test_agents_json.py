"""Tests for thresher.agents._json — shared LLM-output extraction helpers."""

from __future__ import annotations

import json

from thresher.agents._json import extract_json_object, extract_stream_result

# ---------------------------------------------------------------------------
# extract_stream_result
# ---------------------------------------------------------------------------


class TestExtractStreamResult:
    def test_pulls_result_text_and_num_turns(self):
        raw = "\n".join(
            [
                json.dumps({"type": "system"}),
                json.dumps({"type": "assistant", "message": {"content": []}}),
                json.dumps({"type": "result", "result": "hello world", "num_turns": 3}),
            ]
        )
        sr = extract_stream_result(raw)
        assert sr.text == "hello world"
        assert sr.num_turns == 3

    def test_returns_zero_turns_when_no_result_line(self):
        raw = json.dumps({"type": "assistant", "message": {"content": []}})
        sr = extract_stream_result(raw)
        assert sr.num_turns == 0

    def test_extracts_token_usage(self):
        raw = json.dumps(
            {
                "type": "result",
                "result": "done",
                "num_turns": 5,
                "usage": {
                    "input_tokens": 1000,
                    "output_tokens": 500,
                    "cache_creation_input_tokens": 200,
                    "cache_read_input_tokens": 300,
                },
            }
        )
        sr = extract_stream_result(raw)
        assert sr.token_usage["input_tokens"] == 1000
        assert sr.token_usage["output_tokens"] == 500
        assert sr.token_usage["cache_creation_input_tokens"] == 200
        assert sr.token_usage["cache_read_input_tokens"] == 300

    def test_aggregates_assistant_usage_when_result_usage_missing(self):
        raw = "\n".join(
            [
                json.dumps(
                    {
                        "type": "assistant",
                        "session_id": "sess-1",
                        "message": {
                            "id": "msg-1",
                            "model": "claude-sonnet-4-6",
                            "content": [],
                            "usage": {
                                "input_tokens": 100,
                                "output_tokens": 20,
                                "cache_creation_input_tokens": 10,
                                "cache_read_input_tokens": 30,
                            },
                        },
                    }
                ),
                json.dumps(
                    {
                        "type": "assistant",
                        "session_id": "sess-1",
                        "parent_tool_use_id": "tool-1",
                        "message": {
                            "id": "msg-2",
                            "model": "claude-haiku-4-5-20251001",
                            "content": [],
                            "usage": {
                                "input_tokens": 50,
                                "output_tokens": 10,
                                "cache_creation_input_tokens": 5,
                                "cache_read_input_tokens": 15,
                            },
                        },
                    }
                ),
                json.dumps({"type": "result", "result": "done", "num_turns": 2}),
            ]
        )
        sr = extract_stream_result(raw)
        assert sr.token_usage == {
            "input_tokens": 150,
            "output_tokens": 30,
            "cache_creation_input_tokens": 15,
            "cache_read_input_tokens": 45,
        }
        assert sr.model_usage_by_model == {
            "claude-sonnet-4-6": {
                "input_tokens": 100,
                "output_tokens": 20,
                "cache_creation_input_tokens": 10,
                "cache_read_input_tokens": 30,
            },
            "claude-haiku-4-5-20251001": {
                "input_tokens": 50,
                "output_tokens": 10,
                "cache_creation_input_tokens": 5,
                "cache_read_input_tokens": 15,
            },
        }

    def test_dedupes_repeated_assistant_updates_by_message_id(self):
        raw = "\n".join(
            [
                json.dumps(
                    {
                        "type": "assistant",
                        "session_id": "sess-1",
                        "message": {
                            "id": "msg-1",
                            "model": "claude-sonnet-4-6",
                            "content": [],
                            "usage": {
                                "input_tokens": 3,
                                "output_tokens": 6,
                                "cache_creation_input_tokens": 4006,
                                "cache_read_input_tokens": 10999,
                            },
                        },
                    }
                ),
                json.dumps(
                    {
                        "type": "assistant",
                        "session_id": "sess-1",
                        "message": {
                            "id": "msg-1",
                            "model": "claude-sonnet-4-6",
                            "content": [],
                            "usage": {
                                "input_tokens": 3,
                                "output_tokens": 6,
                                "cache_creation_input_tokens": 4006,
                                "cache_read_input_tokens": 10999,
                            },
                        },
                    }
                ),
                json.dumps({"type": "result", "result": "done", "num_turns": 1}),
            ]
        )
        sr = extract_stream_result(raw)
        assert sr.token_usage == {
            "input_tokens": 3,
            "output_tokens": 6,
            "cache_creation_input_tokens": 4006,
            "cache_read_input_tokens": 10999,
        }

    def test_prefers_authoritative_result_usage_over_partial_stream_sum(self):
        raw = "\n".join(
            [
                json.dumps(
                    {
                        "type": "assistant",
                        "session_id": "sess-1",
                        "message": {
                            "id": "msg-1",
                            "model": "claude-sonnet-4-6",
                            "content": [],
                            "usage": {
                                "input_tokens": 10,
                                "output_tokens": 5,
                                "cache_creation_input_tokens": 0,
                                "cache_read_input_tokens": 0,
                            },
                        },
                    }
                ),
                json.dumps(
                    {
                        "type": "result",
                        "result": "done",
                        "num_turns": 2,
                        "modelUsage": {
                            "input_tokens": 100,
                            "output_tokens": 50,
                            "cache_creation_input_tokens": 20,
                            "cache_read_input_tokens": 30,
                        },
                    }
                ),
            ]
        )
        sr = extract_stream_result(raw)
        assert sr.token_usage == {
            "input_tokens": 100,
            "output_tokens": 50,
            "cache_creation_input_tokens": 20,
            "cache_read_input_tokens": 30,
        }
        assert sr.model_usage_by_model["claude-sonnet-4-6"]["input_tokens"] == 10

    def test_empty_token_usage_when_no_usage_field(self):
        raw = json.dumps({"type": "result", "result": "done", "num_turns": 1})
        sr = extract_stream_result(raw)
        assert sr.token_usage == {}

    def test_prefers_model_usage_when_larger_than_usage(self):
        """modelUsage often has more complete token counts than usage."""
        raw = json.dumps(
            {
                "type": "result",
                "result": "done",
                "num_turns": 3,
                "usage": {
                    "input_tokens": 100,
                    "output_tokens": 50,
                    "cache_creation_input_tokens": 10,
                    "cache_read_input_tokens": 20,
                },
                "modelUsage": {
                    "input_tokens": 1000,
                    "output_tokens": 500,
                    "cache_creation_input_tokens": 200,
                    "cache_read_input_tokens": 300,
                },
            }
        )
        sr = extract_stream_result(raw)
        # Should prefer modelUsage since sum(2000) > sum(180)
        assert sr.token_usage["input_tokens"] == 1000
        assert sr.token_usage["output_tokens"] == 500
        assert sr.token_usage["cache_creation_input_tokens"] == 200
        assert sr.token_usage["cache_read_input_tokens"] == 300

    def test_uses_usage_when_model_usage_smaller(self):
        """If modelUsage is smaller, prefer usage field."""
        raw = json.dumps(
            {
                "type": "result",
                "result": "done",
                "num_turns": 3,
                "usage": {
                    "input_tokens": 1000,
                    "output_tokens": 500,
                    "cache_creation_input_tokens": 200,
                    "cache_read_input_tokens": 300,
                },
                "modelUsage": {
                    "input_tokens": 100,
                    "output_tokens": 50,
                    "cache_creation_input_tokens": 10,
                    "cache_read_input_tokens": 20,
                },
            }
        )
        sr = extract_stream_result(raw)
        # Should prefer usage since sum(2000) > sum(180)
        assert sr.token_usage["input_tokens"] == 1000
        assert sr.token_usage["output_tokens"] == 500

    def test_uses_model_usage_when_usage_missing(self):
        """If usage is missing but modelUsage exists, use modelUsage."""
        raw = json.dumps(
            {
                "type": "result",
                "result": "done",
                "num_turns": 3,
                "modelUsage": {
                    "input_tokens": 500,
                    "output_tokens": 250,
                    "cache_creation_input_tokens": 100,
                    "cache_read_input_tokens": 150,
                },
            }
        )
        sr = extract_stream_result(raw)
        assert sr.token_usage["input_tokens"] == 500
        assert sr.token_usage["output_tokens"] == 250
        assert sr.token_usage["cache_creation_input_tokens"] == 100
        assert sr.token_usage["cache_read_input_tokens"] == 150

    def test_falls_back_to_last_assistant_text_on_error(self):
        raw = "\n".join(
            [
                json.dumps(
                    {
                        "type": "assistant",
                        "message": {
                            "content": [{"type": "text", "text": "partial output"}],
                        },
                    }
                ),
                json.dumps(
                    {
                        "type": "result",
                        "result": "",
                        "is_error": True,
                        "subtype": "max_turns",
                        "num_turns": 10,
                    }
                ),
            ]
        )
        sr = extract_stream_result(raw)
        assert sr.text == "partial output"
        assert sr.num_turns == 10

    def test_returns_empty_when_error_and_no_fallback(self):
        raw = json.dumps(
            {
                "type": "result",
                "result": "",
                "is_error": True,
                "subtype": "max_turns",
            }
        )
        sr = extract_stream_result(raw)
        assert sr.text == ""

    def test_ignores_invalid_json_lines(self):
        raw = "\n".join(
            [
                "garbage line",
                json.dumps({"type": "result", "result": "ok", "num_turns": 1}),
                "more garbage",
            ]
        )
        sr = extract_stream_result(raw)
        assert sr.text == "ok"
        assert sr.num_turns == 1

    def test_returns_raw_when_no_result_line_and_no_assistant(self):
        raw = "just some text without stream-json structure"
        sr = extract_stream_result(raw)
        assert sr.text == raw
        assert sr.num_turns == 0

    def test_stringifies_dict_result_value(self):
        """Some agent configs emit result as a dict; round-trip through json."""
        raw = json.dumps(
            {
                "type": "result",
                "result": {"hidden_dependencies": [], "summary": "ok"},
                "num_turns": 2,
            }
        )
        sr = extract_stream_result(raw)
        assert json.loads(sr.text) == {"hidden_dependencies": [], "summary": "ok"}
        assert sr.num_turns == 2


# ---------------------------------------------------------------------------
# extract_json_object
# ---------------------------------------------------------------------------


class TestExtractJsonObject:
    def test_direct_json_object(self):
        result = extract_json_object('{"a": 1, "b": 2}')
        assert result == {"a": 1, "b": 2}

    def test_unwraps_result_envelope(self):
        """If text is {'result': '<inner_json_str>'}, unwrap to inner."""
        inner = json.dumps({"hidden_dependencies": [], "summary": "ok"})
        outer = json.dumps({"result": inner})
        result = extract_json_object(outer, accept=lambda d: "hidden_dependencies" in d)
        assert result == {"hidden_dependencies": [], "summary": "ok"}

    def test_extracts_from_markdown_code_fence(self):
        text = 'Some prose here.\n```json\n{"x": 42}\n```\nmore prose'
        result = extract_json_object(text)
        assert result == {"x": 42}

    def test_extracts_from_unlabeled_code_fence(self):
        text = 'Output:\n```\n{"x": 42}\n```\n'
        result = extract_json_object(text)
        assert result == {"x": 42}

    def test_brace_scan_finds_object_in_prose(self):
        text = 'Here is the result: {"y": 7} done.'
        result = extract_json_object(text)
        assert result == {"y": 7}

    def test_brace_scan_handles_nested_braces(self):
        text = 'before {"a": {"b": 1}} after'
        result = extract_json_object(text)
        assert result == {"a": {"b": 1}}

    def test_returns_none_when_nothing_parseable(self):
        result = extract_json_object("no json here, just words")
        assert result is None

    def test_returns_none_for_empty_string(self):
        assert extract_json_object("") is None

    def test_accept_filters_candidates(self):
        """accept callback filters which dicts qualify."""
        text = '{"foo": 1}'
        result = extract_json_object(text, accept=lambda d: "bar" in d)
        assert result is None

    def test_accept_returns_first_passing_candidate(self):
        text = '{"hidden_dependencies": [], "summary": "ok"}'
        result = extract_json_object(text, accept=lambda d: "hidden_dependencies" in d)
        assert result == {"hidden_dependencies": [], "summary": "ok"}

    def test_prefers_inner_envelope_over_outer_when_filter_matches(self):
        """When both outer and unwrapped inner are dicts, the filter picks the right one."""
        inner = json.dumps({"hidden_dependencies": [], "summary": "ok"})
        outer = json.dumps({"result": inner})
        result = extract_json_object(outer, accept=lambda d: "hidden_dependencies" in d)
        assert "hidden_dependencies" in result

    def test_ignores_non_object_top_level(self):
        """Lists at top level are not returned."""
        result = extract_json_object("[1, 2, 3]")
        assert result is None
