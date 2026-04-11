"""Shared LLM-output extraction helpers for agent modules.

Each agent that runs Claude Code in headless mode does the same dance:

1. Pull the final result text out of stream-json output (and the
   authoritative ``num_turns`` from the SDK's result line).
2. Find a JSON object inside that text — direct parse, then a
   ``{"result": "..."}`` envelope unwrap, then markdown code-fence
   extraction, then a brace-balanced scan for an object embedded in
   prose.

This module owns both pieces so the parsing logic lives in exactly one
place. Per-agent schema validation stays at the call site (passed via
the ``accept`` callback).
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Callable

logger = logging.getLogger(__name__)

_FENCE_RE = re.compile(r"```(?:json)?\s*\n(.*?)\n```", re.DOTALL)


def _stringify_result(value: Any) -> str:
    """Coerce a stream-json ``result`` field to a string.

    Claude Code usually emits ``result`` as a string, but some tool
    configurations emit a dict. Round-trip dicts through ``json.dumps``
    so the downstream object extractor can re-parse them uniformly.
    """
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return json.dumps(value)
    return ""


def extract_stream_result(raw_output: str) -> tuple[str, int]:
    """Pull ``(result_text, num_turns)`` from Claude Code stream-json output.

    Returns the final result text from the ``{"type": "result"}`` line.
    On error results (e.g. ``max_turns``), falls back to the last
    assistant text block so callers still get *something* parseable.
    If neither is present the raw input is returned unchanged so
    downstream extraction can still try.

    ``num_turns`` is the SDK's authoritative turn counter from the
    result line, or 0 if no result line exists.
    """
    result_text = ""
    is_error = False
    error_reason = ""
    last_assistant_text = ""
    num_turns = 0

    for line in raw_output.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue

        obj_type = obj.get("type")
        if obj_type == "result":
            result_text = _stringify_result(obj.get("result", ""))
            is_error = obj.get("is_error", False)
            if is_error:
                error_reason = obj.get("subtype", "unknown_error")
            n = obj.get("num_turns")
            if isinstance(n, int):
                num_turns = n
        elif obj_type == "assistant":
            content = obj.get("message", {}).get("content", [])
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    last_assistant_text = block.get("text", "")
        elif "result" in obj and obj_type is None:
            # Handle bare {"result": "..."} lines without a "type" field.
            result_text = _stringify_result(obj["result"])

    if result_text:
        return result_text, num_turns

    if is_error and last_assistant_text:
        logger.warning(
            "Agent ended with %s; using last assistant text as fallback",
            error_reason,
        )
        return last_assistant_text, num_turns

    if is_error:
        logger.warning(
            "Agent ended with %s and produced no text output", error_reason,
        )
        return "", num_turns

    return raw_output, num_turns


def extract_json_object(
    text: str,
    *,
    accept: Callable[[dict[str, Any]], bool] | None = None,
) -> dict[str, Any] | None:
    """Extract a single top-level JSON object from LLM output.

    Tries, in order:

    1. Direct ``json.loads(text)`` (and unwraps a ``{"result": "<json>"}``
       envelope if present).
    2. Markdown code-fence extraction (```` ```json ... ``` ````).
    3. Brace-balanced scan from the first ``{`` to its matching ``}``.

    All candidates that parse as ``dict`` are collected. ``accept``, if
    given, filters them — the first dict for which ``accept(dict)``
    returns True is returned. With no filter, the first dict found is
    returned.
    """
    if not text or not text.strip():
        return None

    candidates: list[dict[str, Any]] = []
    text = text.strip()

    # 1. Direct parse + envelope unwrap.
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None

    if isinstance(parsed, dict):
        # Try unwrapping {"result": "<json string>"} or {"result": {...}}.
        # The inner string may itself be fenced or have prose around it,
        # so recurse through the same cascade rather than calling
        # ``json.loads`` directly.
        if "result" in parsed:
            inner = parsed["result"]
            if isinstance(inner, str):
                inner_obj = extract_json_object(inner)
                if inner_obj is not None:
                    candidates.append(inner_obj)
            elif isinstance(inner, dict):
                candidates.append(inner)
        candidates.append(parsed)

    # 2. Markdown code fence.
    fence = _FENCE_RE.search(text)
    if fence:
        try:
            parsed = json.loads(fence.group(1))
            if isinstance(parsed, dict):
                candidates.append(parsed)
        except json.JSONDecodeError:
            pass

    # 3. Brace-balanced scan.
    brace_start = text.find("{")
    if brace_start >= 0:
        depth = 0
        for i in range(brace_start, len(text)):
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[brace_start : i + 1]
                    try:
                        parsed = json.loads(candidate)
                        if isinstance(parsed, dict):
                            candidates.append(parsed)
                    except json.JSONDecodeError:
                        pass
                    break

    for candidate in candidates:
        if accept is None or accept(candidate):
            return candidate

    return None
