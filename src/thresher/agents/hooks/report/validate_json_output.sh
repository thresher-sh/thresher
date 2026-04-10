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

schema_path = os.environ.get('REPORT_SCHEMA_PATH', 'templates/report/report_schema.json')

if not os.path.isfile(schema_path):
    print('Schema file not found at ' + schema_path + '. Cannot validate output.', file=sys.stderr)
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
    import jsonschema
    schema = json.loads(open(schema_path).read())
    jsonschema.validate(instance=data, schema=schema)
    sys.exit(0)
except jsonschema.ValidationError as e:
    path = ' -> '.join(str(p) for p in e.absolute_path) if e.absolute_path else '(root)'
    print(f'Schema validation failed at {path}: {e.message}', file=sys.stderr)
    sys.exit(2)
except ImportError:
    sys.exit(0)
"
