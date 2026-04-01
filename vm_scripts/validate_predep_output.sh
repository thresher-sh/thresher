#!/bin/bash
# validate_predep_output.sh — Claude Code stop hook for the predep agent.
# Validates that the agent's response contains valid JSON matching the
# expected hidden_dependencies schema. If invalid, blocks the stop so
# the agent continues refining its output.
#
# Input: JSON on stdin with fields:
#   - stop_hook_active: bool (true if already in forced continuation)
#   - claude_response: string (the agent's full output)
#
# Exit codes:
#   0 = allow stop (valid output or stop_hook_active)
#   2 = block stop (invalid output, agent continues)

set -euo pipefail

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
# Strategy 1: direct JSON parse
# Strategy 2: extract from code block
# Strategy 3: find JSON object with expected key

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
                if parsed and 'hidden_dependencies' in parsed:
                    break
                if 'hidden_dependencies' in obj:
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
    if 'hidden_dependencies' not in parsed:
        errors.append('Missing required field: hidden_dependencies')
    elif not isinstance(parsed['hidden_dependencies'], list):
        errors.append('hidden_dependencies must be an array')
    else:
        for i, dep in enumerate(parsed['hidden_dependencies']):
            if not isinstance(dep, dict):
                errors.append(f'hidden_dependencies[{i}] is not an object')
                continue
            for field in ('type', 'source', 'found_in', 'confidence', 'risk'):
                if field not in dep:
                    errors.append(f'hidden_dependencies[{i}] missing field: {field}')
            if dep.get('type') not in ('git', 'npm', 'pypi', 'cargo', 'go', 'url', 'docker', 'submodule'):
                errors.append(f'hidden_dependencies[{i}] invalid type: {dep.get(\"type\")}')
            if dep.get('confidence') not in ('high', 'medium', 'low'):
                errors.append(f'hidden_dependencies[{i}] invalid confidence: {dep.get(\"confidence\")}')
            if dep.get('risk') not in ('high', 'medium', 'low'):
                errors.append(f'hidden_dependencies[{i}] invalid risk: {dep.get(\"risk\")}')

    if 'files_scanned' not in parsed:
        errors.append('Missing required field: files_scanned')
    if 'summary' not in parsed:
        errors.append('Missing required field: summary')

if errors:
    print('Output validation failed:', file=sys.stderr)
    for e in errors:
        print(f'  - {e}', file=sys.stderr)
    print('', file=sys.stderr)
    print('Fix your output to match the required schema. Ensure:', file=sys.stderr)
    print('  - hidden_dependencies is an array of objects', file=sys.stderr)
    print('  - Each object has: type, source, found_in, confidence, risk', file=sys.stderr)
    print('  - type is one of: git, npm, pypi, cargo, go, url, docker, submodule', file=sys.stderr)
    print('  - confidence and risk are: high, medium, or low', file=sys.stderr)
    print('  - Top-level has: files_scanned (number) and summary (string)', file=sys.stderr)
    sys.exit(2)

sys.exit(0)
" 2>&1

RESULT=$?
if [ $RESULT -ne 0 ]; then
    exit 2
fi

exit 0
