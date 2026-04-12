"""Validation rules for the report-maker stop hook.

Unlike the other agents, the report schema lives as a JSON Schema file
on disk (``REPORT_SCHEMA_PATH``) and is checked with ``jsonschema``.
The hook fails loud if either the schema file or the ``jsonschema``
library is missing — silently passing would let invalid output reach
the HTML template.
"""

from __future__ import annotations

import json
import os
from typing import Any


def _resolve_schema_path() -> str | None:
    """Return the absolute path to the report schema, or None.

    If ``REPORT_SCHEMA_PATH`` is set we honor it strictly — pointing it
    at a missing file is a configuration error and must fail loud rather
    than silently fall back to a wrong schema. Only if the env var is
    unset do we probe the standard fallback locations.
    """
    explicit = os.environ.get("REPORT_SCHEMA_PATH")
    if explicit:
        return explicit if os.path.isfile(explicit) else None
    for candidate in (
        "/opt/templates/report/report_schema.json",
        os.path.expanduser(
            "~/github/thresher/src/thresher/report/schema/report_schema.json",
        ),
    ):
        if os.path.isfile(candidate):
            return candidate
    return None


def validate(data: Any) -> tuple[list[str], list[str]]:
    """Return ``(errors, hints)``. Empty errors == valid output.

    These checks are fatal — when the schema file or ``jsonschema``
    aren't available the hook *must* block, not silently pass.
    """
    schema_path = _resolve_schema_path()
    if not schema_path:
        return (
            [
                "REPORT_SCHEMA_PATH is unset or points at a missing file. "
                "The report-maker stop hook cannot validate output without "
                "a schema. Set REPORT_SCHEMA_PATH to an absolute path.",
            ],
            [],
        )

    try:
        import jsonschema
    except ImportError as exc:
        return (
            [
                "jsonschema is required for report-maker output validation "
                f"but is not installed ({exc}). Install with: pip install jsonschema",
            ],
            [],
        )

    try:
        with open(schema_path) as f:
            schema = json.loads(f.read())
        jsonschema.validate(instance=data, schema=schema)
    except jsonschema.ValidationError as e:
        path = " -> ".join(str(p) for p in e.absolute_path) or "(root)"
        return [f"Schema validation failed at {path}: {e.message}"], []

    return [], []
