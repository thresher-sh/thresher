#!/bin/bash
# validate_analyst_output.sh — Claude Code stop hook for analyst agents.
# Validates that the agent's response contains valid JSON matching the
# expected analyst findings schema. If invalid, blocks the stop so
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

response = sys.stdin.read()

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
                if parsed and 'findings' in parsed:
                    break
                if 'findings' in obj:
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
    # Required top-level fields
    required = ('analyst', 'analyst_number', 'core_question', 'findings', 'summary', 'risk_score')
    for field in required:
        if field not in parsed:
            errors.append(f'Missing required field: {field}')

    # Reject pre-dep schema — this is an analyst, not predep
    if 'hidden_dependencies' in parsed:
        errors.append('Output uses hidden_dependencies schema — use the analyst findings schema instead')

    # Validate findings array
    findings = parsed.get('findings')
    if findings is not None:
        if not isinstance(findings, list):
            errors.append('findings must be an array')
        else:
            for i, f in enumerate(findings):
                if not isinstance(f, dict):
                    errors.append(f'findings[{i}] is not an object')
                    continue
                for field in ('title', 'severity', 'description'):
                    if field not in f:
                        errors.append(f'findings[{i}] missing field: {field}')
                sev = f.get('severity', '')
                if sev not in ('critical', 'high', 'medium', 'low'):
                    errors.append(f'findings[{i}] invalid severity: {sev} (must be critical|high|medium|low)')

    # Validate risk_score
    risk = parsed.get('risk_score')
    if risk is not None:
        try:
            r = int(risk)
            if r < 0 or r > 10:
                errors.append(f'risk_score must be 0-10, got {r}')
        except (ValueError, TypeError):
            errors.append(f'risk_score must be an integer 0-10, got {risk}')

if errors:
    print('Output validation failed:', file=sys.stderr)
    for e in errors:
        print(f'  - {e}', file=sys.stderr)
    print('', file=sys.stderr)
    print('Fix your output to match the required analyst schema:', file=sys.stderr)
    print('  {', file=sys.stderr)
    print('    \"analyst\": \"name\",', file=sys.stderr)
    print('    \"analyst_number\": N,', file=sys.stderr)
    print('    \"core_question\": \"...\",', file=sys.stderr)
    print('    \"files_analyzed\": N,', file=sys.stderr)
    print('    \"findings\": [{\"title\": \"...\", \"severity\": \"high\", \"confidence\": 90, ...}],', file=sys.stderr)
    print('    \"summary\": \"...\",', file=sys.stderr)
    print('    \"risk_score\": 0-10', file=sys.stderr)
    print('  }', file=sys.stderr)
    print('Do NOT use hidden_dependencies format. Use findings array.', file=sys.stderr)
    sys.exit(2)

sys.exit(0)
" <<< "$RESPONSE" 2>&1

RESULT=$?
if [ $RESULT -ne 0 ]; then
    exit 2
fi

exit 0
