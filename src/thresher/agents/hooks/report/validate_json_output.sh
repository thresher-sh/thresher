#!/usr/bin/env bash
set -euo pipefail

# Stop hook for report-maker agent.
# Validates that the assistant's last message is valid JSON conforming to the report schema.
# On valid: exits 0 with no output (allows stop).
# On invalid: exits 0 with {"decision": "block", "reason": "..."} (blocks stop, Claude retries).
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
    print(json.dumps({'decision': 'block', 'reason': f'Schema file not found at {schema_path}'}))
    sys.exit(0)

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
    print(json.dumps({'decision': 'block', 'reason': 'Response is not valid JSON. Output ONLY the raw JSON object, no markdown or explanation.'}))
    sys.exit(0)

# Validate against schema
try:
    import jsonschema
    schema = json.loads(open(schema_path).read())
    jsonschema.validate(instance=data, schema=schema)
    sys.exit(0)
except jsonschema.ValidationError as e:
    path = ' -> '.join(str(p) for p in e.absolute_path) if e.absolute_path else '(root)'
    print(json.dumps({'decision': 'block', 'reason': f'Schema validation failed at {path}: {e.message}'}))
    sys.exit(0)
except ImportError:
    sys.exit(0)
"
