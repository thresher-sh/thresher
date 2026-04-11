#!/usr/bin/env bash
set -euo pipefail

# Stop hook for report-maker agent.
# Validates that the assistant's last message is valid JSON conforming to the report schema.
# On valid: exits 0 (allows stop).
# On invalid: exits 2 with error message on stderr (blocks stop, Claude retries).
#
# SECURITY: Entire stdin is piped directly to Python. The assistant message is NEVER
# interpolated into shell variables — it could contain shell metacharacters.

python3 -c "
import sys, json, re, os

# Read hook event from stdin
try:
    event = json.load(sys.stdin)
except (json.JSONDecodeError, ValueError):
    sys.exit(0)

msg = event.get('last_assistant_message', '')
if not msg:
    sys.exit(0)

# Resolve schema path. REPORT_SCHEMA_PATH should be set to an absolute
# path by the agent runner. If unset, try standard fallback locations
# rather than a relative path that breaks when cwd changes.
schema_path = os.environ.get('REPORT_SCHEMA_PATH')
if not schema_path:
    candidates = [
        '/opt/templates/report/report_schema.json',
        os.path.expanduser('~/github/thresher/templates/report/report_schema.json'),
    ]
    for c in candidates:
        if os.path.isfile(c):
            schema_path = c
            break

if not schema_path or not os.path.isfile(schema_path):
    print(
        'REPORT_SCHEMA_PATH is unset or points at a missing file '
        '(%r). The report-maker stop hook cannot validate output without '
        'a schema. Set REPORT_SCHEMA_PATH to an absolute path.' % schema_path,
        file=sys.stderr,
    )
    sys.exit(2)

# jsonschema is REQUIRED — silently passing would let invalid output reach
# the HTML template (the original bug). Fail loud if it's not importable.
try:
    import jsonschema
except ImportError as exc:
    print(
        'jsonschema is required for report-maker output validation but '
        'is not installed (%s). Install with: pip install jsonschema' % exc,
        file=sys.stderr,
    )
    sys.exit(2)

# Try direct JSON parse
data = None
try:
    data = json.loads(msg)
except json.JSONDecodeError:
    # Try extracting from markdown code fences
    match = re.search(r'\x60\x60\x60(?:json)?\s*\n(.*?)\n\x60\x60\x60', msg, re.DOTALL)
    if match:
        try:
            data = json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

if data is None:
    print('Response is not valid JSON. Output ONLY the raw JSON object, no markdown or explanation.', file=sys.stderr)
    sys.exit(2)

# Validate against schema
try:
    schema = json.loads(open(schema_path).read())
    jsonschema.validate(instance=data, schema=schema)
    sys.exit(0)
except jsonschema.ValidationError as e:
    path = ' -> '.join(str(p) for p in e.absolute_path) if e.absolute_path else '(root)'
    print(f'Schema validation failed at {path}: {e.message}', file=sys.stderr)
    sys.exit(2)
"
