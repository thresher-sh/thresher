#!/usr/bin/env python3
"""Shared Claude Code stop-hook output validator.

Each Thresher agent uses a stop hook to verify the assistant's last
message conforms to its schema. The previous setup duplicated 90% of
the same shell+Python boilerplate across four ``validate_json_output.sh``
files. This module owns the shared bits — stdin parsing, JSON
extraction, and the per-agent schemas — and is invoked from each
agent's hook with its agent name as ``argv[1]``.

Exit contract (Claude Code stop hook):
  - 0  : valid output, allow stop
  - 2  : invalid output, block stop and feed stderr back to the model
  - 0  : also for "no last_assistant_message" / unparseable hook event
         (nothing to validate, don't punish the model)
"""

from __future__ import annotations

import json
import os
import re
import sys
from typing import Any, Callable

_FENCE_RE = re.compile(r"```(?:json)?\s*\n(.*?)\n```", re.DOTALL)


def _exit_invalid_json() -> None:
    print(
        "Response is not valid JSON. Output ONLY the raw JSON object, "
        "no markdown or explanation.",
        file=sys.stderr,
    )
    sys.exit(2)


def _emit_errors(errors: list[str], hint_lines: list[str]) -> None:
    print("Output validation failed:", file=sys.stderr)
    for e in errors:
        print(f"  - {e}", file=sys.stderr)
    print("", file=sys.stderr)
    for line in hint_lines:
        print(line, file=sys.stderr)
    sys.exit(2)


def _read_message() -> str | None:
    """Pull the last assistant message off the hook event on stdin."""
    try:
        event = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        # Malformed event isn't the model's fault — let it stop.
        sys.exit(0)
    msg = event.get("last_assistant_message", "")
    if not msg:
        sys.exit(0)
    return msg


def _parse_json(msg: str) -> dict | list | None:
    """Direct parse, fall back to ```json fenced block extraction."""
    try:
        return json.loads(msg)
    except json.JSONDecodeError:
        pass
    fence = _FENCE_RE.search(msg)
    if fence:
        try:
            return json.loads(fence.group(1))
        except json.JSONDecodeError:
            pass
    return None


# ---------------------------------------------------------------------------
# Per-agent validators
# ---------------------------------------------------------------------------


def _validate_predep(data: Any) -> None:
    errors: list[str] = []
    if not isinstance(data, dict):
        errors.append("Response JSON is not an object")
    else:
        if "hidden_dependencies" not in data:
            errors.append("Missing required field: hidden_dependencies")
        elif not isinstance(data["hidden_dependencies"], list):
            errors.append("hidden_dependencies must be an array")
        else:
            valid_types = (
                "git", "npm", "pypi", "cargo", "go", "url", "docker", "submodule",
            )
            valid_levels = ("high", "medium", "low")
            for i, dep in enumerate(data["hidden_dependencies"]):
                if not isinstance(dep, dict):
                    errors.append(f"hidden_dependencies[{i}] is not an object")
                    continue
                for field in ("type", "source", "found_in", "confidence", "risk"):
                    if field not in dep:
                        errors.append(
                            f"hidden_dependencies[{i}] missing field: {field}",
                        )
                if dep.get("type") not in valid_types:
                    errors.append(
                        f"hidden_dependencies[{i}] invalid type: {dep.get('type')}",
                    )
                if dep.get("confidence") not in valid_levels:
                    errors.append(
                        f"hidden_dependencies[{i}] invalid confidence: "
                        f"{dep.get('confidence')}",
                    )
                if dep.get("risk") not in valid_levels:
                    errors.append(
                        f"hidden_dependencies[{i}] invalid risk: {dep.get('risk')}",
                    )

        if "files_scanned" not in data:
            errors.append("Missing required field: files_scanned")
        if "summary" not in data:
            errors.append("Missing required field: summary")

    if errors:
        _emit_errors(
            errors,
            [
                "Fix your output to match the required schema. Ensure:",
                "  - hidden_dependencies is an array of objects",
                "  - Each object has: type, source, found_in, confidence, risk",
                "  - type is one of: git, npm, pypi, cargo, go, url, docker, submodule",
                "  - confidence and risk are: high, medium, or low",
                "  - Top-level has: files_scanned (number) and summary (string)",
            ],
        )


def _validate_analyst(data: Any) -> None:
    errors: list[str] = []
    if not isinstance(data, dict):
        errors.append("Response JSON is not an object")
    else:
        # Reject predep schema explicitly so analyst agents don't drift.
        if "hidden_dependencies" in data and "findings" not in data:
            errors.append(
                "Output uses hidden_dependencies schema — use the analyst "
                "findings schema instead",
            )

        required = (
            "analyst", "analyst_number", "core_question",
            "findings", "summary", "risk_score",
        )
        for field in required:
            if field not in data:
                errors.append(f"Missing required field: {field}")

        findings = data.get("findings")
        if findings is not None:
            if not isinstance(findings, list):
                errors.append("findings must be an array")
            else:
                for i, f in enumerate(findings):
                    if not isinstance(f, dict):
                        errors.append(f"findings[{i}] is not an object")
                        continue
                    for field in ("title", "severity", "description"):
                        if field not in f:
                            errors.append(f"findings[{i}] missing field: {field}")
                    sev = f.get("severity", "")
                    if sev not in ("critical", "high", "medium", "low"):
                        errors.append(
                            f"findings[{i}] invalid severity: {sev} "
                            "(must be critical|high|medium|low)",
                        )

        risk = data.get("risk_score")
        if risk is not None:
            try:
                r = int(risk)
                if r < 0 or r > 10:
                    errors.append(f"risk_score must be 0-10, got {r}")
            except (ValueError, TypeError):
                errors.append(
                    f"risk_score must be an integer 0-10, got {risk}",
                )

    if errors:
        _emit_errors(
            errors,
            [
                "Fix your output to match the required analyst schema:",
                "  {",
                '    "analyst": "name",',
                '    "analyst_number": N,',
                '    "core_question": "...",',
                '    "files_analyzed": N,',
                '    "findings": [{"title": "...", "severity": "high", "confidence": 90, ...}],',
                '    "summary": "...",',
                '    "risk_score": 0-10',
                "  }",
                "Do NOT use hidden_dependencies format. Use findings array.",
            ],
        )


def _validate_adversarial(data: Any) -> None:
    errors: list[str] = []
    if not isinstance(data, dict):
        errors.append("Response JSON is not an object")
    else:
        if "verification_summary" not in data:
            errors.append("Missing required field: verification_summary")

        if "total_reviewed" not in data:
            errors.append("Missing required field: total_reviewed")
        elif not isinstance(data["total_reviewed"], (int, float)):
            errors.append("total_reviewed must be a number")

        if "results" not in data:
            errors.append("Missing required field: results")
        elif not isinstance(data["results"], list):
            errors.append("results must be an array")
        else:
            for i, r in enumerate(data["results"]):
                if not isinstance(r, dict):
                    errors.append(f"results[{i}] is not an object")
                    continue
                for field in ("file_path", "verdict", "reasoning"):
                    if field not in r:
                        errors.append(f"results[{i}] missing field: {field}")
                verdict = r.get("verdict", "")
                if verdict not in ("confirmed", "downgraded"):
                    errors.append(
                        f'results[{i}] verdict must be "confirmed" or '
                        f'"downgraded", got: {verdict}',
                    )

    if errors:
        _emit_errors(
            errors,
            [
                "Fix your output to match the required schema. Ensure:",
                "  - verification_summary is a string",
                "  - total_reviewed is a number",
                "  - results is an array of objects",
                "  - Each result has: file_path, verdict, reasoning",
                '  - verdict is "confirmed" or "downgraded"',
            ],
        )


def _validate_report(data: Any) -> None:
    """Validate report-maker output against the JSON Schema file."""
    schema_path = os.environ.get("REPORT_SCHEMA_PATH")
    if not schema_path:
        candidates = [
            "/opt/templates/report/report_schema.json",
            os.path.expanduser(
                "~/github/thresher/templates/report/report_schema.json",
            ),
        ]
        for c in candidates:
            if os.path.isfile(c):
                schema_path = c
                break

    if not schema_path or not os.path.isfile(schema_path):
        print(
            "REPORT_SCHEMA_PATH is unset or points at a missing file "
            f"({schema_path!r}). The report-maker stop hook cannot validate "
            "output without a schema. Set REPORT_SCHEMA_PATH to an absolute path.",
            file=sys.stderr,
        )
        sys.exit(2)

    # jsonschema is REQUIRED — silently passing would let invalid output
    # reach the HTML template. Fail loud if it's not importable.
    try:
        import jsonschema
    except ImportError as exc:
        print(
            "jsonschema is required for report-maker output validation but "
            f"is not installed ({exc}). Install with: pip install jsonschema",
            file=sys.stderr,
        )
        sys.exit(2)

    try:
        schema = json.loads(open(schema_path).read())
        jsonschema.validate(instance=data, schema=schema)
    except jsonschema.ValidationError as e:
        path = " -> ".join(str(p) for p in e.absolute_path) or "(root)"
        print(f"Schema validation failed at {path}: {e.message}", file=sys.stderr)
        sys.exit(2)


_VALIDATORS: dict[str, Callable[[Any], None]] = {
    "predep": _validate_predep,
    "analyst": _validate_analyst,
    "adversarial": _validate_adversarial,
    "report": _validate_report,
}


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in _VALIDATORS:
        print(
            f"usage: {sys.argv[0]} <{ '|'.join(_VALIDATORS) }>",
            file=sys.stderr,
        )
        sys.exit(2)

    validator = _VALIDATORS[sys.argv[1]]
    msg = _read_message()
    data = _parse_json(msg)
    if data is None:
        _exit_invalid_json()
    validator(data)
    sys.exit(0)


if __name__ == "__main__":
    main()
