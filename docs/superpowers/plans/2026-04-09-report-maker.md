# Report Maker Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace static report generation with a data-driven HTML report powered by a Claude Code headless agent, JSON schema validation via stop hooks, and Jinja templating.

**Architecture:** Synthesis output flows into a report-maker agent that produces schema-validated JSON. A Jinja render function injects the JSON into a self-contained HTML template with vanilla JS components. Stop hooks ensure the agent's output conforms to the schema before accepting.

**Tech Stack:** Python, Jinja2, JSON Schema, Claude Code headless mode, bash (stop hooks), vanilla JS

**Spec:** `docs/superpowers/specs/2026-04-09-report-maker-design.md`

---

## File Structure

### New Files

| File | Responsibility |
|------|---------------|
| `templates/report/report_schema.json` | JSON Schema enforcing report data structure |
| `templates/report/example_data_report.html` | Data-driven report, visually identical to example_report.html |
| `templates/report/template_report.html` | Jinja template (JSON area is `{{ report_data }}`) |
| `src/thresher/agents/report_maker.py` | Agent runner: builds cmd, calls thresher.run |
| `src/thresher/agents/definitions/report/report_maker.yaml` | Agent system prompt and config |
| `src/thresher/agents/hooks/report/settings.json` | Claude Code settings with Stop hook config |
| `src/thresher/agents/hooks/report/validate_json_output.sh` | Stop hook: validates JSON against schema |
| `tests/unit/test_report_maker.py` | Tests for agent runner |
| `tests/unit/test_report_schema.py` | Tests for schema validation |
| `tests/unit/test_report_render.py` | Tests for Jinja render function |
| `tests/unit/test_agent_hooks.py` | Tests for stop hook mechanism |

### Modified Files

| File | Change |
|------|--------|
| `src/thresher/config.py:97,133,166,176` | Add `report_maker_max_turns` to ScanConfig, `to_json()`, `from_json()` |
| `src/thresher/harness/report.py` | Add `render_report()`, refactor `generate_report()` to extract `finalize_output()` |
| `pyproject.toml` | Add `jsonschema>=4.0` to dependencies |
| `src/thresher/harness/pipeline.py:96-101,125` | Replace `report_path` node with `report_data` + `report_html` nodes |
| `docker/Dockerfile:161` | Add `COPY templates/ /opt/templates/` |
| `tests/unit/test_pipeline.py` | Update for new DAG nodes |
| `tests/unit/test_harness_report.py` | Update for new render function |

---

## Chunk 1: JSON Schema and Validation Tests

### Task 1: Create JSON Schema

**Files:**
- Create: `templates/report/report_schema.json`
- Modify: `pyproject.toml`

- [ ] **Step 1: Add jsonschema to project dependencies**

In `pyproject.toml`, add `"jsonschema>=4.0"` to the `dependencies` list. This is needed by the stop hook validation script and tests.

- [ ] **Step 2: Create the templates/report directory**

```bash
mkdir -p templates/report
```

- [ ] **Step 3: Copy example_report.html to templates/report/**

```bash
cp report_maker/example_report.html templates/report/example_report.html
```

- [ ] **Step 4: Write the JSON Schema**

Create `templates/report/report_schema.json` with the full JSON Schema. Key requirements:
- All leaf values are `"type": "string"` (spec requirement #4)
- `severity` fields use `"enum": ["critical", "high", "medium", "low"]`
- `meta`, `verdict`, `counts`, `config` are required objects
- `executive_summary` is a required string
- `mitigations`, `scanner_findings`, `ai_findings`, `trust_signals`, `dependency_upgrades` are required arrays (can be empty)
- `remediation` is an optional object (nullable)
- `pipeline` is a required object
- Each array item has its own object schema with required fields

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Thresher Report Data",
  "description": "Schema for the JSON data structure that drives the Thresher HTML report template",
  "type": "object",
  "required": ["meta", "verdict", "counts", "executive_summary", "mitigations", "scanner_findings", "ai_findings", "trust_signals", "dependency_upgrades", "pipeline", "config"],
  "properties": {
    "meta": {
      "type": "object",
      "required": ["scan_date", "thresher_version", "scanner_count", "analyst_count", "repo_name", "repo_url"],
      "properties": {
        "scan_date": { "type": "string" },
        "thresher_version": { "type": "string" },
        "scanner_count": { "type": "string" },
        "analyst_count": { "type": "string" },
        "repo_name": { "type": "string" },
        "repo_url": { "type": "string" }
      },
      "additionalProperties": false
    },
    "verdict": {
      "type": "object",
      "required": ["label", "severity", "callout"],
      "properties": {
        "label": { "type": "string" },
        "severity": { "type": "string", "enum": ["critical", "high", "medium", "low"] },
        "callout": { "type": "string" }
      },
      "additionalProperties": false
    },
    "counts": {
      "type": "object",
      "required": ["total_scanner", "total_ai", "p0", "critical", "high_scanner", "high_ai", "medium", "low"],
      "properties": {
        "total_scanner": { "type": "string" },
        "total_ai": { "type": "string" },
        "p0": { "type": "string" },
        "critical": { "type": "string" },
        "high_scanner": { "type": "string" },
        "high_ai": { "type": "string" },
        "medium": { "type": "string" },
        "low": { "type": "string" }
      },
      "additionalProperties": false
    },
    "executive_summary": { "type": "string" },
    "mitigations": {
      "type": "array",
      "items": { "type": "string" }
    },
    "scanner_findings": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["rank", "severity", "package", "title", "cve", "cvss"],
        "properties": {
          "rank": { "type": "string" },
          "severity": { "type": "string", "enum": ["critical", "high", "medium", "low"] },
          "package": { "type": "string" },
          "title": { "type": "string" },
          "cve": { "type": "string" },
          "cvss": { "type": "string" }
        },
        "additionalProperties": false
      }
    },
    "ai_findings": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["severity", "title", "file", "description", "confidence", "analysts"],
        "properties": {
          "severity": { "type": "string", "enum": ["critical", "high", "medium", "low"] },
          "title": { "type": "string" },
          "file": { "type": "string" },
          "description": { "type": "string" },
          "confidence": { "type": "string" },
          "analysts": { "type": "array", "items": { "type": "string" } }
        },
        "additionalProperties": false
      }
    },
    "trust_signals": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["icon", "text"],
        "properties": {
          "icon": { "type": "string" },
          "text": { "type": "string" }
        },
        "additionalProperties": false
      }
    },
    "dependency_upgrades": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["package", "old_version", "new_version", "severity", "cvss", "cves"],
        "properties": {
          "package": { "type": "string" },
          "old_version": { "type": "string" },
          "new_version": { "type": "string" },
          "severity": { "type": "string", "enum": ["critical", "high", "medium", "low"] },
          "cvss": { "type": "string" },
          "cves": { "type": "string" }
        },
        "additionalProperties": false
      }
    },
    "remediation": {
      "oneOf": [
        { "type": "null" },
        {
          "type": "object",
          "required": ["pr_title", "pr_url", "summary", "fixes"],
          "properties": {
            "pr_title": { "type": "string" },
            "pr_url": { "type": "string" },
            "summary": { "type": "string" },
            "fixes": { "type": "array", "items": { "type": "string" } }
          },
          "additionalProperties": false
        }
      ]
    },
    "pipeline": {
      "type": "object",
      "required": ["scanners", "analysts", "notes"],
      "properties": {
        "scanners": { "type": "array", "items": { "type": "string" } },
        "analysts": { "type": "array", "items": { "type": "string" } },
        "notes": { "type": "string" }
      },
      "additionalProperties": false
    },
    "config": {
      "type": "object",
      "required": ["show_cta", "show_remediation"],
      "properties": {
        "show_cta": { "type": "string", "enum": ["true", "false"] },
        "show_remediation": { "type": "string", "enum": ["true", "false"] }
      },
      "additionalProperties": false
    }
  },
  "additionalProperties": false
}
```

- [ ] **Step 5: Commit**

```bash
git add templates/report/ pyproject.toml
git commit -m "add report schema, copy example report, add jsonschema dep"
```

### Task 2: Write Schema Validation Tests

**Files:**
- Create: `tests/unit/test_report_schema.py`
- Read: `templates/report/report_schema.json`

- [ ] **Step 1: Write test file with all schema validation cases**

Create `tests/unit/test_report_schema.py`. Tests need `jsonschema` package. Use a `_valid_report_data()` helper that returns a complete valid dict, then each test mutates one thing.

```python
"""Tests for report JSON schema validation."""

import copy
import json
from pathlib import Path

import pytest
from jsonschema import validate, ValidationError

SCHEMA_PATH = Path(__file__).parent.parent.parent / "templates" / "report" / "report_schema.json"


@pytest.fixture
def schema():
    return json.loads(SCHEMA_PATH.read_text())


def _valid_report_data():
    """Return a minimal but complete valid report data dict."""
    return {
        "meta": {
            "scan_date": "2026-04-02",
            "thresher_version": "v0.2.2",
            "scanner_count": "22",
            "analyst_count": "8",
            "repo_name": "owner/repo",
            "repo_url": "https://github.com/owner/repo",
        },
        "verdict": {
            "label": "LOW RISK",
            "severity": "low",
            "callout": "No critical issues found.",
        },
        "counts": {
            "total_scanner": "0",
            "total_ai": "0",
            "p0": "0",
            "critical": "0",
            "high_scanner": "0",
            "high_ai": "0",
            "medium": "0",
            "low": "0",
        },
        "executive_summary": "<p>No issues found.</p>",
        "mitigations": [],
        "scanner_findings": [],
        "ai_findings": [],
        "trust_signals": [],
        "dependency_upgrades": [],
        "remediation": None,
        "pipeline": {
            "scanners": ["grype"],
            "analysts": [],
            "notes": "",
        },
        "config": {
            "show_cta": "true",
            "show_remediation": "false",
        },
    }


def test_valid_minimal_data_passes(schema):
    data = _valid_report_data()
    validate(instance=data, schema=schema)


def test_valid_full_data_passes(schema):
    data = _valid_report_data()
    data["scanner_findings"] = [{
        "rank": "1", "severity": "critical", "package": "foo@1.0",
        "title": "Bad thing", "cve": "CVE-2026-1234", "cvss": "9.8",
    }]
    data["ai_findings"] = [{
        "severity": "high", "title": "IDOR", "file": "src/handler.ts:42",
        "description": "Missing auth check", "confidence": "95",
        "analysts": ["Analyst 5"],
    }]
    data["trust_signals"] = [{"icon": "!", "text": "No SECURITY.md"}]
    data["dependency_upgrades"] = [{
        "package": "foo", "old_version": "1.0", "new_version": "2.0",
        "severity": "critical", "cvss": "9.8", "cves": "CVE-2026-1234",
    }]
    data["remediation"] = {
        "pr_title": "PR #1", "pr_url": "https://github.com/o/r/pull/1",
        "summary": "Fixed stuff", "fixes": ["Fix 1"],
    }
    validate(instance=data, schema=schema)


def test_missing_required_top_level_field(schema):
    data = _valid_report_data()
    del data["verdict"]
    with pytest.raises(ValidationError, match="'verdict' is a required property"):
        validate(instance=data, schema=schema)


def test_missing_required_meta_field(schema):
    data = _valid_report_data()
    del data["meta"]["repo_name"]
    with pytest.raises(ValidationError, match="'repo_name' is a required property"):
        validate(instance=data, schema=schema)


def test_invalid_severity_enum(schema):
    data = _valid_report_data()
    data["verdict"]["severity"] = "urgent"
    with pytest.raises(ValidationError):
        validate(instance=data, schema=schema)


def test_invalid_scanner_finding_severity(schema):
    data = _valid_report_data()
    data["scanner_findings"] = [{
        "rank": "1", "severity": "CRITICAL", "package": "foo@1.0",
        "title": "Bad", "cve": "CVE-1", "cvss": "9.8",
    }]
    with pytest.raises(ValidationError):
        validate(instance=data, schema=schema)


def test_integer_value_rejected(schema):
    """All leaf values must be strings, not integers."""
    data = _valid_report_data()
    data["counts"]["critical"] = 5
    with pytest.raises(ValidationError):
        validate(instance=data, schema=schema)


def test_additional_properties_rejected(schema):
    data = _valid_report_data()
    data["extra_field"] = "unexpected"
    with pytest.raises(ValidationError):
        validate(instance=data, schema=schema)


def test_remediation_null_is_valid(schema):
    data = _valid_report_data()
    data["remediation"] = None
    validate(instance=data, schema=schema)


def test_remediation_object_is_valid(schema):
    data = _valid_report_data()
    data["remediation"] = {
        "pr_title": "PR #1", "pr_url": "https://example.com/pull/1",
        "summary": "Fixed", "fixes": ["Fix A"],
    }
    validate(instance=data, schema=schema)


def test_invalid_config_show_cta(schema):
    data = _valid_report_data()
    data["config"]["show_cta"] = "yes"
    with pytest.raises(ValidationError):
        validate(instance=data, schema=schema)


def test_empty_arrays_valid(schema):
    """Report with zero findings should pass schema."""
    data = _valid_report_data()
    assert data["scanner_findings"] == []
    assert data["ai_findings"] == []
    validate(instance=data, schema=schema)
```

- [ ] **Step 2: Run tests to verify they pass**

```bash
python -m pytest tests/unit/test_report_schema.py -v
```

Expected: All tests PASS (schema file exists from Task 1).

- [ ] **Step 3: Commit**

```bash
git add tests/unit/test_report_schema.py
git commit -m "add report schema validation tests"
```

---

## Chunk 2: Stop Hook Infrastructure

### Task 3: Create Stop Hook Validation Script

**Files:**
- Create: `src/thresher/agents/hooks/report/validate_json_output.sh`
- Create: `src/thresher/agents/hooks/report/settings.json`

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p src/thresher/agents/hooks/report
```

- [ ] **Step 2: Write the stop hook settings.json**

Create `src/thresher/agents/hooks/report/settings.json`:

```json
{
  "hooks": {
    "Stop": [
      {
        "type": "command",
        "command": "src/thresher/agents/hooks/report/validate_json_output.sh",
        "timeout": 15
      }
    ]
  }
}
```

- [ ] **Step 3: Write the validation script**

Create `src/thresher/agents/hooks/report/validate_json_output.sh`. The script:
1. Reads the hook event JSON from stdin
2. Passes the entire event to a Python validation script (avoids shell injection — never interpolate message content into shell or Python source)
3. Python extracts `last_assistant_message`, tries to parse JSON (handles markdown fences), validates against schema
4. Exits 0 with `{"decision": "block", "reason": "..."}` on failure
5. Exits 0 with no block on success

The script accepts an optional `REPORT_SCHEMA_PATH` env var for the schema location, defaulting to `templates/report/report_schema.json`. This makes the pattern reusable — other agents set their own schema path.

```bash
#!/usr/bin/env bash
set -euo pipefail

# Schema path: configurable via env var, defaults to report schema
SCHEMA_PATH="${REPORT_SCHEMA_PATH:-templates/report/report_schema.json}"

# Pass entire stdin to Python — NEVER interpolate message content into shell variables.
# The Python script reads the hook event JSON directly from stdin, avoiding shell injection.
python3 -c "
import sys, json, re

# Read hook event from stdin
try:
    event = json.load(sys.stdin)
except (json.JSONDecodeError, ValueError):
    # Can't parse hook event — allow stop
    sys.exit(0)

msg = event.get('last_assistant_message', '')
if not msg:
    # No message to validate — allow stop
    sys.exit(0)

# Schema path from env
schema_path = '$SCHEMA_PATH'

import os
if not os.path.isfile(schema_path):
    print(json.dumps({'decision': 'block', 'reason': f'Schema file not found at {schema_path}'}))
    sys.exit(0)

# Try direct JSON parse first
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
    # Valid — allow Claude to stop (no output = no block)
    sys.exit(0)
except jsonschema.ValidationError as e:
    path = ' -> '.join(str(p) for p in e.absolute_path) if e.absolute_path else '(root)'
    print(json.dumps({'decision': 'block', 'reason': f'Schema validation failed at {path}: {e.message}'}))
    sys.exit(0)
except ImportError:
    # jsonschema not installed — allow stop, can't validate
    sys.exit(0)
"
```

- [ ] **Step 4: Make script executable**

```bash
chmod +x src/thresher/agents/hooks/report/validate_json_output.sh
```

- [ ] **Step 5: Commit**

```bash
git add src/thresher/agents/hooks/
git commit -m "add stop hook infrastructure for report-maker agent"
```

### Task 4: Write Stop Hook Tests

**Files:**
- Create: `tests/unit/test_agent_hooks.py`
- Read: `src/thresher/agents/hooks/report/validate_json_output.sh`

- [ ] **Step 1: Write hook test file**

Create `tests/unit/test_agent_hooks.py`. Tests invoke the shell script via `subprocess.run()` with crafted stdin input. Each test constructs a hook event JSON with a specific `last_assistant_message` and checks the exit code and stdout.

```python
"""Tests for agent stop hook validation."""

import json
import os
import subprocess
from pathlib import Path

import pytest

HOOK_SCRIPT = Path(__file__).parent.parent.parent / "src" / "thresher" / "agents" / "hooks" / "report" / "validate_json_output.sh"
SCHEMA_PATH = Path(__file__).parent.parent.parent / "templates" / "report" / "report_schema.json"


def _valid_report_json():
    """Minimal valid report JSON string."""
    return json.dumps({
        "meta": {
            "scan_date": "2026-04-02", "thresher_version": "v0.2.2",
            "scanner_count": "22", "analyst_count": "8",
            "repo_name": "owner/repo", "repo_url": "https://github.com/owner/repo",
        },
        "verdict": {"label": "LOW RISK", "severity": "low", "callout": "No issues."},
        "counts": {
            "total_scanner": "0", "total_ai": "0", "p0": "0", "critical": "0",
            "high_scanner": "0", "high_ai": "0", "medium": "0", "low": "0",
        },
        "executive_summary": "<p>Clean.</p>",
        "mitigations": [],
        "scanner_findings": [],
        "ai_findings": [],
        "trust_signals": [],
        "dependency_upgrades": [],
        "remediation": None,
        "pipeline": {"scanners": ["grype"], "analysts": [], "notes": ""},
        "config": {"show_cta": "true", "show_remediation": "false"},
    })


def _run_hook(last_assistant_message, schema_path=None):
    """Run the hook script with a crafted stdin event."""
    event = json.dumps({"last_assistant_message": last_assistant_message})
    env = os.environ.copy()
    if schema_path:
        env["REPORT_SCHEMA_PATH"] = str(schema_path)
    else:
        env["REPORT_SCHEMA_PATH"] = str(SCHEMA_PATH)
    result = subprocess.run(
        ["bash", str(HOOK_SCRIPT)],
        input=event.encode(),
        capture_output=True,
        timeout=10,
        env=env,
    )
    return result


def test_valid_json_allows_stop():
    result = _run_hook(_valid_report_json())
    assert result.returncode == 0
    stdout = result.stdout.decode().strip()
    # Should not contain a block decision
    if stdout:
        data = json.loads(stdout)
        assert data.get("decision") != "block"


def test_invalid_json_blocks_stop():
    result = _run_hook("this is not json at all")
    assert result.returncode == 0
    stdout = result.stdout.decode().strip()
    data = json.loads(stdout)
    assert data["decision"] == "block"
    assert "JSON" in data["reason"]


def test_missing_required_field_blocks():
    report = json.loads(_valid_report_json())
    del report["verdict"]
    result = _run_hook(json.dumps(report))
    assert result.returncode == 0
    stdout = result.stdout.decode().strip()
    data = json.loads(stdout)
    assert data["decision"] == "block"
    assert "verdict" in data["reason"]


def test_invalid_severity_blocks():
    report = json.loads(_valid_report_json())
    report["verdict"]["severity"] = "URGENT"
    result = _run_hook(json.dumps(report))
    assert result.returncode == 0
    stdout = result.stdout.decode().strip()
    data = json.loads(stdout)
    assert data["decision"] == "block"


def test_json_in_markdown_code_fence():
    fenced = "```json\n" + _valid_report_json() + "\n```"
    result = _run_hook(fenced)
    assert result.returncode == 0
    stdout = result.stdout.decode().strip()
    if stdout:
        data = json.loads(stdout)
        assert data.get("decision") != "block"


def test_empty_message_allows_stop():
    result = _run_hook("")
    assert result.returncode == 0


def test_integer_value_blocks():
    """Schema requires all leaf values as strings."""
    report = json.loads(_valid_report_json())
    report["counts"]["critical"] = 5  # integer, not string
    result = _run_hook(json.dumps(report))
    assert result.returncode == 0
    stdout = result.stdout.decode().strip()
    data = json.loads(stdout)
    assert data["decision"] == "block"


def test_custom_schema_path():
    """Hook respects REPORT_SCHEMA_PATH env var."""
    result = _run_hook(_valid_report_json(), schema_path=SCHEMA_PATH)
    assert result.returncode == 0
```

- [ ] **Step 2: Run tests**

```bash
python -m pytest tests/unit/test_agent_hooks.py -v
```

Expected: All PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/unit/test_agent_hooks.py
git commit -m "add stop hook tests"
```

### Task 4.5: Stop Hook Proof of Concept (Early Validation)

The `--bare --settings` pattern is novel — no existing agent uses it. Validate it works before building on it.

**Files:**
- Read: `src/thresher/agents/hooks/report/settings.json`
- Read: `src/thresher/agents/hooks/report/validate_json_output.sh`

- [ ] **Step 1: Manual test — valid JSON allows stop**

Create a minimal valid JSON and ask Claude to output it:

```bash
VALID_JSON='{"meta":{"scan_date":"2026-04-02","thresher_version":"v0.2.2","scanner_count":"22","analyst_count":"8","repo_name":"test/repo","repo_url":"https://github.com/test/repo"},"verdict":{"label":"LOW RISK","severity":"low","callout":"Clean."},"counts":{"total_scanner":"0","total_ai":"0","p0":"0","critical":"0","high_scanner":"0","high_ai":"0","medium":"0","low":"0"},"executive_summary":"<p>Clean.</p>","mitigations":[],"scanner_findings":[],"ai_findings":[],"trust_signals":[],"dependency_upgrades":[],"remediation":null,"pipeline":{"scanners":["grype"],"analysts":[],"notes":""},"config":{"show_cta":"true","show_remediation":"false"}}'

echo "Output this exact JSON and nothing else: $VALID_JSON" | claude -p /dev/stdin --bare --settings src/thresher/agents/hooks/report/settings.json --output-format stream-json --max-turns 3
```

Expected: Claude outputs the JSON, stop hook validates, Claude exits cleanly.

- [ ] **Step 2: Manual test — invalid JSON triggers block**

```bash
echo 'Output this exact text: {"invalid": true}' | claude -p /dev/stdin --bare --settings src/thresher/agents/hooks/report/settings.json --output-format stream-json --max-turns 3
```

Expected: Stop hook blocks first attempt. Claude retries or hits max_turns.

- [ ] **Step 3: Document results and fix any issues**

If `--bare --settings` doesn't work (hook doesn't fire, path resolution fails), adjust before proceeding. If the hook command path needs to be absolute, update `settings.json` and the `report_maker.py` runner to dynamically generate a `settings.json` with the resolved absolute path.

- [ ] **Step 4: Commit any fixes**

```bash
git add src/thresher/agents/hooks/
git commit -m "verify stop hook PoC works with --bare --settings"
```

---

## Chunk 3: Data-Driven HTML Template

### Task 5: Create example_data_report.html

**Files:**
- Create: `templates/report/example_data_report.html`
- Read: `templates/report/example_report.html` (reference for visual parity)
- Read: `templates/report/report_schema.json` (for the data structure)

- [ ] **Step 1: Build the data-driven report**

Create `templates/report/example_data_report.html`. This is the most substantial file. It must:

1. **Copy all CSS from `example_report.html`** verbatim (lines 10-796) into a `<style>` block
2. **Add a `<div id="app"></div>`** mount point in the body
3. **Add a `<script>` section** with:

   a. **`REPORT_DATA` constant** — a JSON object matching the schema, populated with the exact same data visible in `example_report.html` (the BuilderIO/agent-native scan data)

   b. **Component functions** — each returns an HTML string:
   - `renderNav(d)` — fixed nav bar with section anchor links
   - `renderHero(d)` — meta line, h1 repo name, subtitle, verdict box, severity counts
   - `renderExecSummary(d)` — prose (innerHTML from `executive_summary`), verdict callout, mitigations list
   - `renderFindingsBar(d)` — two stacked bar tracks (scanner + AI) using flex segments
   - `renderScannerTable(d)` — table from `scanner_findings` array, severity CSS mapping
   - `renderAiFindings(d)` — cards grouped by severity (critical/high rendered individually, medium in collapsible `<details>`), confidence bars, analyst tags
   - `renderTrustSignals(d)` — grid of trust items
   - `renderUpgrades(d)` — dependency upgrade table with old/new version coloring
   - `renderRemediation(d)` — fix card, hidden by default via `config.show_remediation`, JS toggle button
   - `renderPipeline(d)` — collapsible details with scanner grid + analyst grid + notes
   - `renderCta(d)` — conditional on `config.show_cta`, ASCII art + install box
   - `renderFooter(d)` — links and disclaimer

   c. **`renderReport(data)`** — assembles all components: `document.getElementById('app').innerHTML = [renderNav(data), '<div class="container">', renderHero(data), ..., '</div>', renderCta(data), renderFooter(data)].join('')`

   d. **Interactivity:**
   - `copyCmd(el)` — clipboard copy for install box
   - Remediation toggle: a button in the remediation section header that toggles visibility. Default state driven by `REPORT_DATA.config.show_remediation`

   e. **Severity CSS mapping helper:**
   ```javascript
   function sevClass(sev) {
     return { critical: 'crit', high: 'high', medium: 'med', low: 'low' }[sev] || '';
   }
   ```

4. **Visual parity requirement:** When opened in a browser, this file must look identical to `example_report.html`. Same colors, same layout, same data, same collapsible sections.

- [ ] **Step 2: Open both files in browser and verify visual parity**

Open `templates/report/example_report.html` and `templates/report/example_data_report.html` side by side. Verify they look identical.

- [ ] **Step 3: Add automated test for embedded REPORT_DATA**

Add to `tests/unit/test_report_schema.py`:

```python
def test_example_data_report_json_passes_schema(schema):
    """The REPORT_DATA embedded in example_data_report.html must pass the schema."""
    import re
    html_path = Path(__file__).parent.parent.parent / "templates" / "report" / "example_data_report.html"
    content = html_path.read_text()
    # Extract the JSON object from: const REPORT_DATA = {...};
    match = re.search(r"const\s+REPORT_DATA\s*=\s*(\{.*?\});\s*$", content, re.DOTALL | re.MULTILINE)
    assert match, "Could not find REPORT_DATA in example_data_report.html"
    data = json.loads(match.group(1))
    validate(instance=data, schema=schema)
```

Run: `python -m pytest tests/unit/test_report_schema.py::test_example_data_report_json_passes_schema -v`

- [ ] **Step 4: Test with minimal data**

Temporarily replace `REPORT_DATA` with a minimal object (empty arrays, null remediation, low-severity verdict). Verify the page still renders without errors — empty sections hidden, no JS errors in console.

- [ ] **Step 4: Restore full data and commit**

```bash
git add templates/report/example_data_report.html
git commit -m "add data-driven report template with vanilla JS components"
```

### Task 6: Create Jinja template_report.html

**Files:**
- Create: `templates/report/template_report.html`
- Read: `templates/report/example_data_report.html`

- [ ] **Step 1: Copy example_data_report.html to template_report.html**

```bash
cp templates/report/example_data_report.html templates/report/template_report.html
```

- [ ] **Step 2: Replace the REPORT_DATA JSON blob with Jinja placeholder**

In `template_report.html`, find the line that starts with `const REPORT_DATA = {` and replace the entire JSON object (up to the closing `};`) with:

```javascript
const REPORT_DATA = {{ report_data }};
```

This is the only Jinja substitution point in the file. The `report_data` variable will be a `json.dumps()` output injected by the Python render function.

- [ ] **Step 3: Commit**

```bash
git add templates/report/template_report.html
git commit -m "add Jinja template with report_data placeholder"
```

---

## Chunk 4: Render Function and Tests

### Task 7: Implement render_report() in harness/report.py

**Files:**
- Modify: `src/thresher/harness/report.py`
- Read: `templates/report/template_report.html`

- [ ] **Step 1: Write the failing test first**

Create `tests/unit/test_report_render.py`:

```python
"""Tests for the Jinja report render function."""

import json
from pathlib import Path

import pytest


def _valid_report_data():
    """Minimal valid report data dict."""
    return {
        "meta": {
            "scan_date": "2026-04-02", "thresher_version": "v0.2.2",
            "scanner_count": "22", "analyst_count": "8",
            "repo_name": "owner/repo", "repo_url": "https://github.com/owner/repo",
        },
        "verdict": {"label": "LOW RISK", "severity": "low", "callout": "No issues."},
        "counts": {
            "total_scanner": "0", "total_ai": "0", "p0": "0", "critical": "0",
            "high_scanner": "0", "high_ai": "0", "medium": "0", "low": "0",
        },
        "executive_summary": "<p>Clean scan.</p>",
        "mitigations": [],
        "scanner_findings": [],
        "ai_findings": [],
        "trust_signals": [],
        "dependency_upgrades": [],
        "remediation": None,
        "pipeline": {"scanners": ["grype"], "analysts": [], "notes": ""},
        "config": {"show_cta": "true", "show_remediation": "false"},
    }


def test_render_report_produces_html(tmp_path):
    from thresher.harness.report import render_report
    output = render_report(_valid_report_data(), str(tmp_path))
    html_path = Path(output)
    assert html_path.exists()
    content = html_path.read_text()
    assert "<!DOCTYPE html>" in content
    assert "owner/repo" in content


def test_render_report_embeds_json(tmp_path):
    from thresher.harness.report import render_report
    data = _valid_report_data()
    output = render_report(data, str(tmp_path))
    content = Path(output).read_text()
    assert '"scan_date"' in content
    assert '"LOW RISK"' in content


def test_render_report_show_cta_false(tmp_path):
    from thresher.harness.report import render_report
    data = _valid_report_data()
    data["config"]["show_cta"] = "false"
    output = render_report(data, str(tmp_path))
    content = Path(output).read_text()
    # The CTA section should not appear (renderCta returns "" when show_cta is false)
    assert "show_cta" in content  # config is embedded in JSON
    # The JS component handles hiding — just verify no crash
    assert "<!DOCTYPE html>" in content


def test_render_report_with_findings(tmp_path):
    from thresher.harness.report import render_report
    data = _valid_report_data()
    data["scanner_findings"] = [{
        "rank": "1", "severity": "critical", "package": "foo@1.0",
        "title": "Bad vuln", "cve": "CVE-2026-9999", "cvss": "9.8",
    }]
    output = render_report(data, str(tmp_path))
    content = Path(output).read_text()
    assert "CVE-2026-9999" in content


def test_render_report_null_remediation(tmp_path):
    from thresher.harness.report import render_report
    data = _valid_report_data()
    data["remediation"] = None
    output = render_report(data, str(tmp_path))
    content = Path(output).read_text()
    assert "<!DOCTYPE html>" in content
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/unit/test_report_render.py -v
```

Expected: FAIL — `render_report` function doesn't exist yet (or has wrong signature).

- [ ] **Step 3: Implement render_report()**

Add to `src/thresher/harness/report.py` (keep existing functions, add new one):

```python
def render_report(
    report_data: dict,
    output_dir: str,
    *,
    template_dir: str | None = None,
) -> str:
    """Render HTML report by injecting report_data JSON into the Jinja template.

    Returns the path to the generated report.html.
    """
    import json
    from jinja2 import Environment, FileSystemLoader

    if template_dir is None:
        # Default: templates/report/ relative to project root
        # In Docker: /opt/templates/report/
        # In direct mode: relative to package
        candidates = [
            Path("/opt/templates/report"),
            Path(__file__).parent.parent.parent.parent / "templates" / "report",
        ]
        for candidate in candidates:
            if (candidate / "template_report.html").exists():
                template_dir = str(candidate)
                break
        if template_dir is None:
            raise FileNotFoundError(
                "template_report.html not found. Checked: "
                + ", ".join(str(c) for c in candidates)
            )

    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=False,  # Template contains raw HTML/JS
    )
    template = env.get_template("template_report.html")

    html = template.render(report_data=json.dumps(report_data, indent=2))

    out_path = Path(output_dir) / "report.html"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html)

    logger.info("Report written to %s", out_path)
    return str(out_path)
```

Ensure `from pathlib import Path` and `logger` are available at the top of the file (they likely already are).

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/unit/test_report_render.py -v
```

Expected: All PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/unit/test_report_render.py src/thresher/harness/report.py
git commit -m "add render_report function with Jinja template injection"
```

### Task 8: Implement build_fallback_report_data()

**Note:** The spec says this function lives in `report_maker.py`. We place it in `harness/report.py` instead because the pipeline node imports it there (avoids circular import — pipeline.py imports from harness/report.py, not from agents/). This is an intentional deviation.

**Files:**
- Modify: `src/thresher/harness/report.py`
- Create test cases in: `tests/unit/test_report_render.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/test_report_render.py`:

```python
def test_build_fallback_report_data_minimal():
    from thresher.harness.report import build_fallback_report_data
    from thresher.config import ScanConfig

    config = ScanConfig(repo_url="https://github.com/owner/repo")
    findings = []
    data = build_fallback_report_data(config, findings)

    assert data["meta"]["repo_name"] == "owner/repo"
    assert data["verdict"]["severity"] == "low"
    assert data["counts"]["critical"] == "0"
    assert data["remediation"] is None
    assert data["config"]["show_remediation"] == "false"


def test_build_fallback_report_data_with_critical():
    from thresher.harness.report import build_fallback_report_data
    from thresher.config import ScanConfig

    config = ScanConfig(repo_url="https://github.com/owner/repo")
    findings = [
        {
            "id": "1", "source_tool": "grype", "category": "sca",
            "severity": "critical", "title": "Bad vuln",
            "description": "Very bad", "cvss_score": 9.8,
            "cve_id": "CVE-2026-1234", "package_name": "foo",
            "package_version": "1.0", "fix_version": "2.0",
            "composite_priority": "critical",
        },
    ]
    data = build_fallback_report_data(config, findings)

    assert data["verdict"]["severity"] == "critical"
    assert data["counts"]["critical"] == "1"
    assert len(data["scanner_findings"]) == 1
    assert data["scanner_findings"][0]["cvss"] == "9.8"


def test_build_fallback_validates_against_schema():
    """Fallback output must pass the JSON schema."""
    import json
    from jsonschema import validate
    from thresher.harness.report import build_fallback_report_data
    from thresher.config import ScanConfig

    schema = json.loads(
        (Path(__file__).parent.parent.parent / "templates" / "report" / "report_schema.json").read_text()
    )
    config = ScanConfig(repo_url="https://github.com/owner/repo")
    data = build_fallback_report_data(config, [])
    validate(instance=data, schema=schema)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/unit/test_report_render.py::test_build_fallback_report_data_minimal -v
```

Expected: FAIL — function doesn't exist.

- [ ] **Step 3: Implement build_fallback_report_data()**

Add to `src/thresher/harness/report.py`:

```python
def build_fallback_report_data(config, enriched_findings: list) -> dict:
    """Build report JSON programmatically when the AI agent is unavailable.

    Used for --skip-ai mode or when the report-maker agent fails.
    """
    from datetime import date

    # Extract repo name from URL
    repo_name = config.repo_url.rstrip("/").rstrip(".git")
    repo_name = "/".join(repo_name.split("/")[-2:]) if "/" in repo_name else repo_name

    # Count findings by severity
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in enriched_findings:
        sev = (f.get("composite_priority") or f.get("severity", "low")).lower()
        if sev in counts:
            counts[sev] += 1

    # Determine verdict
    if counts["critical"] > 0:
        verdict_label = "FIX BEFORE USE"
        verdict_severity = "critical"
    elif counts["high"] > 0:
        verdict_label = "REVIEW BEFORE USE"
        verdict_severity = "high"
    elif counts["medium"] > 0:
        verdict_label = "LOW RISK"
        verdict_severity = "medium"
    else:
        verdict_label = "LOW RISK"
        verdict_severity = "low"

    total = sum(counts.values())
    callout = f"{total} findings detected." if total > 0 else "No significant issues found."

    # Build scanner findings (top 10 by CVSS)
    scanner = [f for f in enriched_findings if f.get("source_tool") != "ai"]
    scanner.sort(key=lambda f: float(f.get("cvss_score") or 0), reverse=True)
    scanner_top = []
    for i, f in enumerate(scanner[:10], 1):
        pkg = f.get("package_name", "unknown")
        ver = f.get("package_version", "")
        scanner_top.append({
            "rank": str(i),
            "severity": (f.get("composite_priority") or f.get("severity", "low")).lower(),
            "package": f"{pkg}@{ver}" if ver else pkg,
            "title": f.get("title", ""),
            "cve": f.get("cve_id", ""),
            "cvss": str(f.get("cvss_score", "")),
        })

    # Mitigations: one per critical/high finding
    mitigations = []
    for f in enriched_findings:
        sev = (f.get("composite_priority") or f.get("severity", "")).lower()
        if sev in ("critical", "high"):
            cve = f.get("cve_id", "")
            pkg = f.get("package_name", "unknown")
            mitigations.append(f"Resolve {cve} in {pkg}" if cve else f"Remediate {pkg}: {f.get('title', '')}")

    return {
        "meta": {
            "scan_date": date.today().isoformat(),
            "thresher_version": "v0.3.0",
            "scanner_count": "22",
            "analyst_count": "0" if config.skip_ai else "8",
            "repo_name": repo_name,
            "repo_url": config.repo_url,
        },
        "verdict": {
            "label": verdict_label,
            "severity": verdict_severity,
            "callout": callout,
        },
        "counts": {
            "total_scanner": str(total),
            "total_ai": "0",
            "p0": "0",
            "critical": str(counts["critical"]),
            "high_scanner": str(counts["high"]),
            "high_ai": "0",
            "medium": str(counts["medium"]),
            "low": str(counts["low"]),
        },
        "executive_summary": f"<p>Automated scanning of <strong>{repo_name}</strong> produced <strong>{total} findings</strong> across 22 tools.</p>",
        "mitigations": mitigations[:10],
        "scanner_findings": scanner_top,
        "ai_findings": [],
        "trust_signals": [],
        "dependency_upgrades": [],
        "remediation": None,
        "pipeline": {
            "scanners": ["grype", "trivy", "osv-scanner", "semgrep", "gitleaks", "checkov", "bandit", "clamav", "guarddog", "yara", "entropy", "install-hooks"],
            "analysts": [],
            "notes": "AI analysts were not run." if config.skip_ai else "AI agent failed; using fallback report.",
        },
        "config": {
            "show_cta": "true",
            "show_remediation": "false",
        },
    }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/unit/test_report_render.py -v
```

Expected: All PASS.

- [ ] **Step 5: Commit**

```bash
git add src/thresher/harness/report.py tests/unit/test_report_render.py
git commit -m "add fallback report data builder for skip-ai mode"
```

---

## Chunk 5: Agent Definition and Runner

### Task 9: Create Agent YAML Definition

**Files:**
- Create: `src/thresher/agents/definitions/report/report_maker.yaml`

- [ ] **Step 1: Create directory**

```bash
mkdir -p src/thresher/agents/definitions/report
```

- [ ] **Step 2: Write the YAML definition**

Create `src/thresher/agents/definitions/report/report_maker.yaml`:

```yaml
name: report_maker
title: Report Data Compiler
core_question: Can you transform these scan findings into a structured JSON report?
tools:
- Read
- Glob
- Grep
max_turns: 15
prompt: |
  You are a security report data compiler for Thresher, a supply chain security scanner.

  ## Your Task

  Read the scan results and produce a single JSON object that conforms exactly to the
  report schema. Output ONLY the raw JSON — no markdown, no explanation, no code fences.

  ## Input Files

  Read these files to understand the scan results:
  1. `findings.json` — enriched findings (scanner + AI, with composite priorities)
  2. `executive-summary.md` — AI-generated narrative (if it exists)
  3. `scan-results/` directory — raw scanner outputs

  Read these files to understand the expected output format:
  4. `templates/report/report_schema.json` — the JSON Schema your output must conform to
  5. `templates/report/example_data_report.html` — reference report showing what the data looks like in practice (look at the REPORT_DATA constant in the script section)

  ## Output Requirements

  1. **All leaf values must be strings** — no integers, no booleans, no nulls in string fields
  2. **Severity values** must be exactly one of: "critical", "high", "medium", "low"
  3. **executive_summary** may contain these HTML tags ONLY: <p>, <strong>, <code>, <ul>, <li>
     Write a compelling multi-paragraph summary that highlights the most important findings.
  4. **scanner_findings** — include the top 10 by CVSS score
  5. **ai_findings** — include ALL AI analyst findings, grouped logically by severity
  6. **verdict** — determine based on highest severity:
     - Any critical → "FIX BEFORE USE" / severity "critical"
     - High only → "REVIEW BEFORE USE" / severity "high"
     - Medium/low → "LOW RISK" / severity "low"
  7. **remediation** — set to null (first pass, not yet available)
  8. **config.show_remediation** — set to "false"
  9. **config.show_cta** — set to "true"
  10. **mitigations** — list 3-6 concrete, actionable items based on the findings

  ## Critical

  Your output will be validated against the JSON Schema. If validation fails, you will
  be asked to fix it. Output ONLY valid JSON. No markdown. No explanation.
```

- [ ] **Step 3: Commit**

```bash
git add src/thresher/agents/definitions/report/
git commit -m "add report-maker agent YAML definition"
```

### Task 10: Implement report_maker.py Agent Runner

**Files:**
- Create: `src/thresher/agents/report_maker.py`
- Read: `src/thresher/agents/analyst.py` (pattern reference)

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_report_maker.py`:

```python
"""Tests for the report-maker agent runner."""

import json
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from thresher.config import ScanConfig


def _mock_stream_output(report_data: dict) -> bytes:
    """Build stream-json output containing a result with report data."""
    lines = [
        json.dumps({"type": "assistant", "message": {"content": [{"text": "Working..."}]}}),
        json.dumps({"type": "result", "result": json.dumps(report_data)}),
    ]
    return "\n".join(lines).encode()


def _valid_report_data():
    return {
        "meta": {
            "scan_date": "2026-04-02", "thresher_version": "v0.2.2",
            "scanner_count": "22", "analyst_count": "8",
            "repo_name": "owner/repo", "repo_url": "https://github.com/owner/repo",
        },
        "verdict": {"label": "LOW RISK", "severity": "low", "callout": "No issues."},
        "counts": {
            "total_scanner": "0", "total_ai": "0", "p0": "0", "critical": "0",
            "high_scanner": "0", "high_ai": "0", "medium": "0", "low": "0",
        },
        "executive_summary": "<p>Clean.</p>",
        "mitigations": [],
        "scanner_findings": [],
        "ai_findings": [],
        "trust_signals": [],
        "dependency_upgrades": [],
        "remediation": None,
        "pipeline": {"scanners": ["grype"], "analysts": [], "notes": ""},
        "config": {"show_cta": "true", "show_remediation": "false"},
    }


@patch("thresher.agents.report_maker.run_cmd")
def test_builds_correct_cmd(mock_run):
    from thresher.agents.report_maker import run_report_maker

    mock_run.return_value = MagicMock(
        stdout=_mock_stream_output(_valid_report_data()),
        returncode=0,
    )
    config = ScanConfig(repo_url="https://github.com/owner/repo", model="sonnet")
    run_report_maker(config, "/tmp/output")

    cmd = mock_run.call_args[0][0]
    assert "claude" in cmd[0]
    assert "--bare" in cmd
    assert "--settings" in cmd
    assert "--output-format" in cmd
    assert "stream-json" in cmd
    assert "--verbose" in cmd


@patch("thresher.agents.report_maker.run_cmd")
def test_parses_valid_output(mock_run):
    from thresher.agents.report_maker import run_report_maker

    expected = _valid_report_data()
    mock_run.return_value = MagicMock(
        stdout=_mock_stream_output(expected),
        returncode=0,
    )
    config = ScanConfig(repo_url="https://github.com/owner/repo")
    result = run_report_maker(config, "/tmp/output")

    assert result is not None
    assert result["meta"]["repo_name"] == "owner/repo"
    assert result["verdict"]["severity"] == "low"


@patch("thresher.agents.report_maker.run_cmd")
def test_returns_none_on_failure(mock_run):
    from thresher.agents.report_maker import run_report_maker

    mock_run.side_effect = subprocess.TimeoutExpired(cmd="claude", timeout=3600)
    config = ScanConfig(repo_url="https://github.com/owner/repo")
    result = run_report_maker(config, "/tmp/output")

    assert result is None


@patch("thresher.agents.report_maker.run_cmd")
def test_uses_custom_max_turns(mock_run):
    from thresher.agents.report_maker import run_report_maker

    mock_run.return_value = MagicMock(
        stdout=_mock_stream_output(_valid_report_data()),
        returncode=0,
    )
    config = ScanConfig(
        repo_url="https://github.com/owner/repo",
        report_maker_max_turns=25,
    )
    run_report_maker(config, "/tmp/output")

    cmd = mock_run.call_args[0][0]
    turns_idx = cmd.index("--max-turns") + 1
    assert cmd[turns_idx] == "25"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
python -m pytest tests/unit/test_report_maker.py -v
```

Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Implement report_maker.py**

Create `src/thresher/agents/report_maker.py`:

```python
"""Report-maker agent: transforms synthesis output into structured JSON for the HTML report."""

import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml

from thresher.config import ScanConfig
from thresher.run import run as run_cmd

logger = logging.getLogger(__name__)

_DEFINITIONS_DIR = Path(__file__).parent / "definitions" / "report"
_HOOKS_DIR = Path(__file__).parent / "hooks" / "report"
_DEFAULT_MAX_TURNS = 15


def _resolve_hooks_settings() -> Path:
    """Write a temporary settings.json with the absolute path to the hook script.

    The hook script path must be absolute to work in both direct and Docker modes.
    The base settings.json has a relative path; we resolve it at runtime.
    """
    hook_script = _HOOKS_DIR / "validate_json_output.sh"
    if not hook_script.exists():
        raise FileNotFoundError(f"Hook script not found: {hook_script}")

    settings = {
        "hooks": {
            "Stop": [{
                "type": "command",
                "command": str(hook_script.resolve()),
                "timeout": 15,
            }]
        }
    }
    settings_path = Path(tempfile.mktemp(suffix="_report_hooks_settings.json"))
    settings_path.write_text(json.dumps(settings))
    return settings_path


def _load_definition() -> dict:
    """Load the report-maker YAML definition."""
    yaml_path = _DEFINITIONS_DIR / "report_maker.yaml"
    return yaml.safe_load(yaml_path.read_text())


def _extract_result_from_stream(raw_output: str) -> str | None:
    """Extract the result text from stream-json output."""
    last_assistant_text = None
    for line in raw_output.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("type") == "result":
            result = obj.get("result", "")
            if result:
                return result
        elif obj.get("type") == "assistant":
            content = obj.get("message", {}).get("content", [])
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    last_assistant_text = block.get("text", "")
    return last_assistant_text


def _parse_report_json(raw_output: str) -> dict | None:
    """Parse the agent's stream-json output into a report data dict."""
    import re

    text = _extract_result_from_stream(raw_output)
    if not text:
        logger.warning("No result text found in agent output")
        return None

    # Try direct JSON parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try extracting from markdown code fences
    match = re.search(r"```(?:json)?\s*\n(.*?)\n```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass

    logger.warning("Could not parse report JSON from agent output")
    return None


def run_report_maker(
    config: ScanConfig,
    output_dir: str,
    *,
    target_dir: str = "/opt/scan-results",
) -> dict[str, Any] | None:
    """Run the report-maker agent to produce structured JSON for the HTML report.

    Returns the report data dict, or None on failure.
    """
    definition = _load_definition()
    max_turns = config.report_maker_max_turns or definition.get("max_turns", _DEFAULT_MAX_TURNS)
    model = config.model or "sonnet"

    # Build the prompt: definition prompt + instruction to read the output dir
    prompt_text = definition["prompt"] + f"\n\n## Working Directory\n\nYour working directory is `{target_dir}`. Read files from there.\n"

    # Write prompt to temp file
    prompt_path = Path(tempfile.mktemp(suffix="_report_maker_prompt.txt"))
    prompt_path.write_text(prompt_text)

    # Resolve hooks settings path.
    # In Docker, the hook script path in settings.json may not resolve correctly
    # if it's relative. We write a temporary settings.json with the absolute path
    # to the hook script, ensuring it works in both direct and Docker modes.
    hooks_settings = _resolve_hooks_settings()

    # Build allowed tools from definition
    tools = ",".join(definition.get("tools", ["Read", "Glob", "Grep"]))

    cmd = [
        "claude",
        "-p", str(prompt_path),
        "--model", model,
        "--bare",
        "--settings", str(hooks_settings),
        "--allowedTools", tools,
        "--output-format", "stream-json",
        "--verbose",
        "--max-turns", str(max_turns),
    ]

    # Environment: pass API key
    env = os.environ.copy()
    if config.anthropic_api_key:
        env["ANTHROPIC_API_KEY"] = config.anthropic_api_key
    if config.oauth_token:
        env["CLAUDE_CODE_OAUTH_TOKEN"] = config.oauth_token

    logger.info("Running report-maker agent (max_turns=%s, model=%s)", max_turns, model)

    try:
        proc = run_cmd(
            cmd,
            label="report-maker",
            env=env,
            timeout=3600,
            cwd=target_dir,
        )
        raw_output = proc.stdout.decode(errors="replace")
        result = _parse_report_json(raw_output)

        if result is None:
            logger.error("Report-maker agent produced no parseable output")
            return None

        logger.info("Report-maker agent completed successfully")
        return result

    except subprocess.TimeoutExpired:
        logger.error("Report-maker agent timed out")
        return None
    except Exception:
        logger.exception("Report-maker agent failed")
        return None
    finally:
        prompt_path.unlink(missing_ok=True)
        hooks_settings.unlink(missing_ok=True)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
python -m pytest tests/unit/test_report_maker.py -v
```

Expected: All PASS.

- [ ] **Step 5: Commit**

```bash
git add src/thresher/agents/report_maker.py tests/unit/test_report_maker.py
git commit -m "add report-maker agent runner"
```

---

## Chunk 6: Pipeline Integration

### Task 11: Add report_maker_max_turns to ScanConfig

**Files:**
- Modify: `src/thresher/config.py:97,133,166,176`
- Modify: `tests/unit/test_config.py`

- [ ] **Step 1: Add field to ScanConfig dataclass**

In `src/thresher/config.py`, after line 96 (`predep_max_turns`), add:

```python
    report_maker_max_turns: int | None = None  # Override report-maker agent max_turns (default 15)
```

- [ ] **Step 2: Add to `to_json()` method**

In the `to_json()` method (around line 133), add `report_maker_max_turns` to the data dict, following the pattern of existing max_turns fields:

```python
        "report_maker_max_turns": self.report_maker_max_turns,
```

- [ ] **Step 3: Add to `from_json()` method**

In the `from_json()` classmethod (around line 166), add `"report_maker_max_turns"` to the `known_fields` set (around line 176). The generic field loading loop will handle it automatically since it's a simple `int | None`.

- [ ] **Step 4: Add config loading from TOML**

In the config loading section (around line 235 where `analysts_data` is parsed), add loading for the report_maker section:

```python
    report_maker_data = data.get("report_maker", {})
    if "max_turns" in report_maker_data:
        config.report_maker_max_turns = report_maker_data["max_turns"]
```

- [ ] **Step 5: Add roundtrip test**

Add to `tests/unit/test_config.py`:

```python
def test_report_maker_max_turns_roundtrip_json():
    config = ScanConfig(repo_url="https://github.com/test/repo", report_maker_max_turns=25)
    json_str = config.to_json()
    restored = ScanConfig.from_json(json_str)
    assert restored.report_maker_max_turns == 25
```

- [ ] **Step 6: Run config tests**

```bash
python -m pytest tests/unit/test_config.py -v
```

Expected: All PASS.

- [ ] **Step 7: Commit**

```bash
git add src/thresher/config.py tests/unit/test_config.py
git commit -m "add report_maker_max_turns to ScanConfig with serialization"
```

### Task 12: Update Pipeline DAG

**Files:**
- Modify: `src/thresher/harness/pipeline.py:96-101,125`
- Modify: `tests/unit/test_pipeline.py`

- [ ] **Step 1: Read current pipeline.py to understand exact state**

Read `src/thresher/harness/pipeline.py` in full before modifying.

- [ ] **Step 2: Refactor generate_report() to extract finalize_output()**

Before modifying the pipeline, first refactor `src/thresher/harness/report.py`. Read the current `generate_report()` function (lines 101-205). Extract its file-management responsibilities into a new `finalize_output()` function:

`finalize_output(enriched_findings, scan_results, config, analyst_findings=None)`:
- Writes `findings.json` to output directory
- Saves per-analyst findings as individual JSON files in `scan-results/`
- Copies raw scanner output files from `/opt/scan-results`
- Calls `validate_report_output()`

The old `generate_report()` is kept temporarily for backward compatibility but its HTML generation path is no longer called by the pipeline.

- [ ] **Step 3: Replace report_path node with report_data + report_html**

In `src/thresher/harness/pipeline.py`, replace the `report_path` function (lines 96-101) with:

```python
def report_data(enriched_findings: dict, scan_results: list,
                analyst_findings: list, config: ScanConfig) -> dict:
    """Run report-maker agent to produce structured JSON for the HTML report.

    Note: Uses config.output_dir rather than a Hamilton-wired output_dir input.
    This matches the pattern used by other agent-calling nodes in this pipeline.
    """
    if config.skip_ai:
        from thresher.harness.report import build_fallback_report_data
        findings = enriched_findings.get("findings", [])
        return build_fallback_report_data(config, findings)

    from thresher.agents.report_maker import run_report_maker
    result = run_report_maker(config, config.output_dir or "/opt/scan-results")
    if result is None:
        from thresher.harness.report import build_fallback_report_data
        findings = enriched_findings.get("findings", [])
        return build_fallback_report_data(config, findings)
    return result


def report_html(report_data: dict, enriched_findings: dict,
                scan_results: list, analyst_findings: list,
                config: ScanConfig) -> str:
    """Render final HTML report and finalize output directory."""
    from thresher.harness.report import render_report, finalize_output

    output_dir = config.output_dir or "/opt/scan-results"

    # Render the new data-driven HTML report
    html_path = render_report(report_data, output_dir)

    # Handle file management: findings.json, scanner copies, validation
    finalize_output(enriched_findings, scan_results, config,
                    analyst_findings=analyst_findings)

    return html_path
```

This cleanly separates concerns: `render_report()` generates HTML, `finalize_output()` handles all other file outputs. No double generation.

- [ ] **Step 3: Update final_vars**

Change line 125 from:
```python
        final_vars=["report_path"],
```
to:
```python
        final_vars=["report_html"],
```

Also update line 129:
```python
    report = result["report_html"]
```

- [ ] **Step 5: Update pipeline tests**

Read `tests/unit/test_pipeline.py` and make these specific changes:
- In `test_pipeline_module_has_required_functions`: replace `"report_path"` in the `required` list with `"report_data"` and `"report_html"`
- In `test_run_pipeline_calls_hamilton_execute`: update the `final_vars` assertion from `["report_path"]` to `["report_html"]`, and update `result["report_path"]` to `result["report_html"]`
- Add a test verifying skip-ai path calls `build_fallback_report_data` instead of the agent

- [ ] **Step 5: Run all tests**

```bash
python -m pytest tests/unit/test_pipeline.py tests/unit/test_harness_report.py -v
```

Expected: All PASS.

- [ ] **Step 6: Commit**

```bash
git add src/thresher/harness/pipeline.py tests/unit/test_pipeline.py
git commit -m "wire report-maker into Hamilton DAG pipeline"
```

### Task 13: Update Dockerfile

**Files:**
- Modify: `docker/Dockerfile:161`

- [ ] **Step 1: Add COPY for templates**

In `docker/Dockerfile`, after line 161 (`COPY rules/ /opt/rules/`), add:

```dockerfile
COPY templates/ /opt/templates/
```

- [ ] **Step 2: Commit**

```bash
git add docker/Dockerfile
git commit -m "copy report templates into Docker image"
```

### Task 14: Update existing harness report tests

**Files:**
- Modify: `tests/unit/test_harness_report.py`

- [ ] **Step 1: Read current test file**

Read `tests/unit/test_harness_report.py` to understand what exists.

- [ ] **Step 2: Update tests for the new render_report function**

Ensure existing tests still pass. Add or modify tests that reference `generate_report()` to account for the new `render_report()` being the HTML generation path. Keep tests for `validate_report_output()` and `enrich_all_findings()` unchanged.

- [ ] **Step 3: Run full test suite**

```bash
python -m pytest tests/unit/ -v
```

Expected: All PASS.

- [ ] **Step 4: Commit**

```bash
git add tests/unit/test_harness_report.py
git commit -m "update harness report tests for new render function"
```

---

## Chunk 7: Integration Smoke Test

### Task 15: Full Integration Smoke Test

- [ ] **Step 1: Run full unit test suite**

```bash
python -m pytest tests/unit/ -v
```

Expected: All PASS.

- [ ] **Step 2: Visual verification**

Open `templates/report/example_data_report.html` in a browser. Verify:
- Looks identical to `templates/report/example_report.html`
- Remediation section is hidden
- JS console shows no errors
- Copy button works

- [ ] **Step 3: Test Jinja render end-to-end**

```bash
python3 -c "
from thresher.harness.report import render_report, build_fallback_report_data
from thresher.config import ScanConfig
config = ScanConfig(repo_url='https://github.com/test/repo')
data = build_fallback_report_data(config, [])
path = render_report(data, '/tmp/test-report')
print(f'Report written to {path}')
"
```

Open `/tmp/test-report/report.html` in browser. Verify it renders a clean minimal report.

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "report-maker implementation complete"
```
