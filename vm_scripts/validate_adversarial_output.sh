#!/bin/sh
# validate_adversarial_output.sh — Claude Code stop hook for the adversarial agent.
# Validates that the agent's response contains valid JSON matching the
# expected adversarial verification schema. If invalid, blocks the stop so
# the agent continues refining its output.
#
# Input: JSON on stdin with fields:
#   - stop_hook_active: bool (true if already in forced continuation)
#   - claude_response: string (the agent's full output)
#
# Exit codes:
#   0 = allow stop (valid output or stop_hook_active)
#   2 = block stop (invalid output, agent continues)

set -eu

INPUT=$(cat)

# Prevent infinite loops — if we already blocked once, let it stop
STOP_HOOK_ACTIVE=$(echo "$INPUT" | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(str(data.get('stop_hook_active', False)).lower())
" 2>/dev/null || echo "false")

if [ "$STOP_HOOK_ACTIVE" = "true" ]; then
    exit 0
fi

# Retry tracking — after 3 failed attempts, accept whatever the agent produced
ATTEMPT_FILE="/tmp/.adversarial_hook_attempts"
ATTEMPTS=0
if [ -f "$ATTEMPT_FILE" ]; then
    ATTEMPTS=$(cat "$ATTEMPT_FILE" 2>/dev/null || echo "0")
fi
ATTEMPTS=$((ATTEMPTS + 1))
echo "$ATTEMPTS" > "$ATTEMPT_FILE"

if [ "$ATTEMPTS" -ge 3 ]; then
    echo "WARNING: adversarial stop hook has rejected output $ATTEMPTS times; accepting to avoid infinite loop" >&2
    rm -f "$ATTEMPT_FILE"
    exit 0
fi

# Extract the agent's response
RESPONSE=$(echo "$INPUT" | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(data.get('claude_response', ''))
" 2>/dev/null || echo "")

if [ -z "$RESPONSE" ]; then
    echo "No response found in stop hook input" >&2
    exit 2
fi

# Validate the response contains valid JSON with the expected schema
python3 -c "
import json, sys, re

response = '''$RESPONSE'''

# Try to extract JSON from the response
parsed = None

# Try direct parse
try:
    parsed = json.loads(response.strip())
except (json.JSONDecodeError, TypeError):
    pass

# Try code block extraction
if parsed is None:
    match = re.search(r'\`\`\`(?:json)?\s*\n(.*?)\n\`\`\`', response, re.DOTALL)
    if match:
        try:
            parsed = json.loads(match.group(1))
        except (json.JSONDecodeError, TypeError):
            pass

# Try stream-json result extraction
if parsed is None:
    for line in response.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                if obj.get('type') == 'result' and 'result' in obj:
                    inner = obj['result']
                    if isinstance(inner, str):
                        try:
                            parsed = json.loads(inner)
                        except:
                            pass
                    elif isinstance(inner, dict):
                        parsed = inner
                if parsed and 'results' in parsed:
                    break
                if 'results' in obj:
                    parsed = obj
                    break
        except:
            continue

# Try finding bare JSON object
if parsed is None:
    start = response.find('{')
    if start >= 0:
        depth = 0
        for i in range(start, len(response)):
            if response[i] == '{': depth += 1
            elif response[i] == '}':
                depth -= 1
                if depth == 0:
                    try:
                        parsed = json.loads(response[start:i+1])
                    except:
                        pass
                    break

errors = []

if parsed is None:
    errors.append('Response does not contain valid JSON')
elif not isinstance(parsed, dict):
    errors.append('Response JSON is not an object')
else:
    if 'verification_summary' not in parsed:
        errors.append('Missing required field: verification_summary')

    if 'total_reviewed' not in parsed:
        errors.append('Missing required field: total_reviewed')
    elif not isinstance(parsed['total_reviewed'], (int, float)):
        errors.append('total_reviewed must be a number')

    if 'results' not in parsed:
        errors.append('Missing required field: results')
    elif not isinstance(parsed['results'], list):
        errors.append('results must be an array')
    else:
        for i, r in enumerate(parsed['results']):
            if not isinstance(r, dict):
                errors.append(f'results[{i}] is not an object')
                continue
            for field in ('file_path', 'verdict', 'reasoning'):
                if field not in r:
                    errors.append(f'results[{i}] missing field: {field}')
            verdict = r.get('verdict', '')
            if verdict not in ('confirmed', 'downgraded'):
                errors.append(f'results[{i}] verdict must be \"confirmed\" or \"downgraded\", got: {verdict}')

if errors:
    print('Output validation failed:', file=sys.stderr)
    for e in errors:
        print(f'  - {e}', file=sys.stderr)
    print('', file=sys.stderr)
    print('Fix your output to match the required schema. Ensure:', file=sys.stderr)
    print('  - verification_summary is a string', file=sys.stderr)
    print('  - total_reviewed is a number', file=sys.stderr)
    print('  - results is an array of objects', file=sys.stderr)
    print('  - Each result has: file_path, verdict, reasoning', file=sys.stderr)
    print('  - verdict is \"confirmed\" or \"downgraded\"', file=sys.stderr)
    sys.exit(2)

sys.exit(0)
" 2>&1

RESULT=$?
if [ $RESULT -ne 0 ]; then
    exit 2
fi

# Validation passed — reset attempt counter
rm -f "$ATTEMPT_FILE"
exit 0
