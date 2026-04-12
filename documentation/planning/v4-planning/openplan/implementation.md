# MCP Server for Agent Structured Output - Implementation Spec

## Overview

This spec implements the MCP submission architecture from `plan.md`.

Core outcomes:

1. Agents submit structured data through MCP `submit_*` tools.
2. Validation happens at tool call time.
3. Stop hooks only verify that this invocation submitted.
4. Pipeline reads MCP output files first and stdout parsing second.

## 0) Shared Contracts

### 0.1 Output roots

Use explicit output roots by stage:

- `SCAN_OUTPUT_DIR`: `/opt/scan-results`
  - predep
  - analysts
  - adversarial
- `REPORT_DIR`: `config.output_dir` (typically `/output` in-container)
  - synthesize
  - report-maker

### 0.2 Invocation identity

Every agent invocation generates a unique `submission_id` (uuid4 hex).

- Stop hook args include `submission_id`
- MCP server env includes `submission_id`
- Receipt filename includes `submission_id`

This prevents stale receipt files from older runs passing new runs.

### 0.3 Labels

Canonical labels:

- analyst: `analyst-{number:02d}-{name}`
- predep: `predep`
- adversarial: `adversarial`
- synthesize: `synthesize`
- report-maker hook label: `report`

## 1) File Structure

Add:

```text
src/thresher/mcp/
  __init__.py
  server.py
  analyst_server.py
  adversarial_server.py
  predep_server.py
  synthesize_server.py
  report_server.py
```

Modify:

- `src/thresher/agents/_runner.py`
- `src/thresher/agents/analysts.py`
- `src/thresher/agents/adversarial.py`
- `src/thresher/agents/predep.py`
- `src/thresher/agents/synthesize.py`
- `src/thresher/agents/report_maker.py`
- `src/thresher/agents/hooks/_common/validate_json_output.sh` (replace behavior)
- `pyproject.toml`

No YAML edits required for prompts; add MCP submit instructions programmatically in agent modules.

## 2) `src/thresher/mcp/server.py` (base infrastructure)

### 2.1 Responsibilities

`server.py` provides shared behavior:

- FastMCP setup and stdio runner
- atomic JSON writes
- receipt file creation
- validator wiring
- MCP settings JSON helper

### 2.2 Base class

```python
class MCPServerBase:
    tool_name: str
    label: str

    def __init__(self, *, output_dir: str, submission_id: str, label: str):
        ...

    def _write_json_atomic(self, rel_path: str, payload: dict[str, Any]) -> Path:
        ...

    def _receipt_path(self) -> Path:
        ...

    def _write_receipt(self, *, tool_name: str, output_path: str) -> Path:
        ...

    def run(self) -> None:
        self.mcp.run(transport="stdio")
```

### 2.3 Receipt format

Write JSON receipt files with:

```json
{
  "label": "analyst-01-paranoid",
  "submission_id": "<uuid4hex>",
  "tool": "submit_analyst_findings",
  "output_path": "/opt/scan-results/scan-results/analyst-01-paranoid.json",
  "submitted_at": "2026-04-11T22:10:03Z"
}
```

### 2.4 Receipt path helper

`server.py` should expose one shared helper for receipt location so server code and hook code agree:

```python
def receipt_relpath(label: str, submission_id: str) -> str:
    if label.startswith("analyst-"):
        return f"scan-results/.{label}.{submission_id}.submitted.json"
    return f".{label}.{submission_id}.submitted.json"
```

### 2.5 Settings helper

```python
def create_mcp_settings(
    *,
    server_name: str,
    server_module: str,
    env_vars: dict[str, str],
) -> str:
    settings = {
        "mcpServers": {
            server_name: {
                "command": sys.executable,
                "args": ["-m", server_module],
                "env": env_vars,
            }
        }
    }
    return json.dumps(settings)
```

Use `sys.executable`, not hard-coded `python`.

## 3) Per-agent MCP servers

All servers should import existing validators from:

- `thresher.agents.hooks._common.schemas.analyst`
- `thresher.agents.hooks._common.schemas.adversarial`
- `thresher.agents.hooks._common.schemas.predep`
- `thresher.agents.hooks._common.schemas.report`

### 3.1 `analyst_server.py`

- Tool: `submit_analyst_findings`
- Env required:
  - `OUTPUT_DIR`
  - `ANALYST_NAME`
  - `ANALYST_NUMBER`
  - `AGENT_LABEL`
  - `SUBMISSION_ID`
- Behavior:
  - build payload from typed args
  - validate with analyst schema
  - enforce submitted `analyst`/`analyst_number` matches env identity
  - write `scan-results/analyst-{number:02d}-{name}.json`
  - write receipt

### 3.2 `adversarial_server.py`

- Tool: `submit_adversarial_findings`
- Writes `adversarial-verification.json`
- Writes receipt `.adversarial.<submission_id>.submitted.json`

### 3.3 `predep_server.py`

- Tool: `submit_hidden_dependencies`
- Writes `scan-results/hidden_deps_agent.json`
- Writes receipt `.predep.<submission_id>.submitted.json`

### 3.4 `synthesize_server.py`

- Tool: `submit_synthesis_report`
- Does not write a JSON payload file
- Verifies both files exist in `OUTPUT_DIR`:
  - `executive-summary.md`
  - `detailed-report.md`
- Writes receipt `.synthesize.<submission_id>.submitted.json`

### 3.5 `report_server.py`

- Tool: `submit_report`
- Payload: report data dict
- Validates with report schema validator
- Writes `report_data.json`
- Writes receipt `.report.<submission_id>.submitted.json`

### 3.6 `__main__` pattern (all servers)

```python
if __name__ == "__main__":
    output_dir = os.environ["OUTPUT_DIR"]
    label = os.environ["AGENT_LABEL"]
    submission_id = os.environ["SUBMISSION_ID"]
    server = ConcreteServer(output_dir=output_dir, label=label, submission_id=submission_id)
    server.run()
```

## 4) Stop hook replacement

### 4.1 Replace shared hook script behavior

`src/thresher/agents/hooks/_common/validate_json_output.sh` becomes a submission checker wrapper (name can remain for minimal churn, behavior changes).

Expected usage:

```bash
validate_json_output.sh <label> <submission_id> <output_dir>
```

Behavior:

1. parse stdin event JSON and read `stop_hook_active` (default `false`)
2. compute expected receipt path from `label + submission_id`
3. if receipt exists -> `exit 0`
4. if receipt missing and `stop_hook_active=false` -> `exit 2` + guidance
5. if receipt missing and `stop_hook_active=true` -> warn + `exit 0`

### 4.2 Guidance text

Use explicit actionable guidance:

`You must call the submit MCP tool for this agent before finishing. Your work has not been recorded.`

### 4.3 Why this logic

Claude Stop hook payload includes `stop_hook_active` but does not provide a reliable max-turn counter.
Using `stop_hook_active` avoids endless loop behavior while preserving one blocking retry.

## 5) `_runner.py` changes

### 5.1 AgentSpec

Add field:

```python
mcp_settings_json: str | None = None
```

### 5.2 build_stop_hook_settings

Change signature:

```python
def build_stop_hook_settings(label: str, submission_id: str, output_dir: str) -> str:
```

Generate quoted command arguments (use `shlex.quote`) so path/label safety is preserved.

### 5.3 run_agent merge behavior

Merge hook + MCP settings into one settings object:

```python
merged_settings: dict[str, Any] = {}
if spec.hooks_settings_json:
    merged_settings.update(json.loads(spec.hooks_settings_json))
if spec.mcp_settings_json:
    merged_settings.update(json.loads(spec.mcp_settings_json))
```

Then pass a single `--settings` file.

## 6) Agent module updates

### 6.1 Shared pattern

For each agent invocation:

1. `submission_id = uuid.uuid4().hex`
2. build hook settings with label/submission_id/output_dir
3. build MCP settings with matching env vars
4. add MCP tool to `allowed_tools`
5. append submit instruction suffix to prompt

### 6.2 Analyst (`analysts.py`)

- fix label to zero-padded: `analyst-{number:02d}-{name}`
- add tool `mcp__thresher-submit__submit_analyst_findings`
- output root: `/opt/scan-results`
- primary result path:
  - `/opt/scan-results/scan-results/analyst-{number:02d}-{name}.json`
- fallback: existing `_parse_analyst_json_output`

### 6.3 Predep (`predep.py`)

- add tool `mcp__thresher-submit__submit_hidden_dependencies`
- output root: `/opt/scan-results`
- primary result path:
  - `/opt/scan-results/scan-results/hidden_deps_agent.json`
- fallback: existing `_parse_predep_output`

### 6.4 Adversarial (`adversarial.py`)

- add tool `mcp__thresher-submit__submit_adversarial_findings`
- output root: `/opt/scan-results`
- primary result path:
  - `/opt/scan-results/adversarial-verification.json`
- fallback: existing `_parse_adversarial_output`

### 6.5 Synthesize (`synthesize.py`)

- add tool `mcp__thresher-submit__submit_synthesis_report`
- output root: report dir (`report_dir` argument)
- keep existing markdown file existence checks
- Stop hook now verifies submission receipt, not markdown schema

### 6.6 Report maker (`report_maker.py`)

- add tool `mcp__thresher-submit__submit_report`
- output root: report dir (`output_dir` argument)
- primary result path:
  - `{output_dir}/report_data.json`
- fallback: existing `_parse_report_output`

Pass `REPORT_SCHEMA_PATH` into report MCP server env for deterministic schema location.

## 7) Prompt instruction suffixes

Append one explicit instruction in code for each agent type.

Example (analyst):

```text
IMPORTANT: When your analysis is complete, call submit_analyst_findings.
This is required for your findings to be recorded.
```

Do this in module prompt builders, not YAML files.

## 8) Pipeline integration

### 8.1 Read MCP output first

For analyst/predep/adversarial/report-maker:

1. try MCP output file
2. if missing, fallback to stdout parse
3. log warning on fallback

### 8.2 Stage artifact behavior

`stage_artifacts` should avoid redundant writes when an artifact already exists in destination.
At minimum, avoid overwriting with lower-fidelity data.

## 9) Dependency update

Add `mcp` dependency in `pyproject.toml`.

Use repo tooling:

```bash
uv add mcp
```

Do not use `pip install` in implementation instructions.

## 10) Tests

### 10.1 New unit tests

Add `tests/unit/test_mcp_servers.py` covering:

1. valid submit writes payload + receipt
2. invalid submit returns validation error and does not write receipt
3. analyst identity mismatch is rejected
4. synthesize server rejects missing markdown files

### 10.2 Hook tests

Update `tests/unit/test_agent_hooks.py`:

1. receipt exists -> stop allowed
2. receipt missing + `stop_hook_active=false` -> blocked
3. receipt missing + `stop_hook_active=true` -> allowed with warning
4. stale receipt (wrong submission_id) -> blocked

### 10.3 Runner tests

Update `tests/unit/test_agents_runner.py`:

1. `--settings` present when either hooks or MCP settings exist
2. merged settings contain both `hooks` and `mcpServers`

### 10.4 Integration tests

Update `tests/integration/test_agent_pipeline.py`:

1. MCP output path is preferred over stdout
2. fallback path still works when MCP output is absent
3. analyst label zero-padding is consistent

## 11) Implementation order

1. add `mcp` dependency
2. create `src/thresher/mcp/server.py`
3. implement analyst server
4. implement predep, adversarial, synthesize, report servers
5. update hook script behavior
6. update `_runner.py` (`AgentSpec`, stop hook builder, settings merge)
7. wire analyst module
8. wire predep + adversarial modules
9. wire synthesize + report-maker modules
10. switch pipeline reads to MCP-first with fallback
11. update/add tests
12. run `uv run pytest` and `uv run ruff`

## 12) Rollback plan

Rollback is low risk because parsing fallback remains:

- disable `mcp_settings_json` wiring
- keep hooks enabled
- stdout parse continues as before

Receipts and MCP payload files are additive artifacts and do not break old paths.
