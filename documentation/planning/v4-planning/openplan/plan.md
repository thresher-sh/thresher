# MCP Server for Agent Structured Output - Plan

## Problem

Today, agents submit structured JSON by printing to stdout and relying on Stop hooks
to validate at the end of the turn. This has two major costs:

1. Validation happens late (after the model tries to stop), so failures create retry loops.
2. The pipeline must parse free-form model output to recover JSON.

## Goal

Move structured submission to MCP tools so validation happens at tool call time, not at stop time.

- Each agent type gets an MCP server with one `submit_*` tool.
- The tool validates payloads and writes canonical output files.
- A thin Stop hook checks whether this specific invocation submitted.
- Pipeline code reads MCP-written files first and uses stdout parsing only as fallback.

## Non-goals

- This is not a security hard-boundary against a malicious model process.
- This does not remove stdout parsing immediately; fallback remains during migration.
- This does not require changing scanner output formats.

## Architecture

```text
Agent (claude -p)
  -> MCP submit tool (stdio, per-agent-type server)
     -> schema validation
     -> atomic write of canonical output file
     -> write invocation-scoped submission receipt

Stop hook (thin)
  -> checks receipt for this invocation
  -> if missing, blocks once with guidance
  -> if still missing when stop_hook_active=true, logs warning and allows stop
```

## Key Decisions

1. **Per-agent-type MCP servers**
   - Analyst, adversarial, predep, synthesize, and report-maker each get their own server module and tool.

2. **Invocation-scoped submission receipts (anti-stale markers)**
   - Every agent invocation gets a unique `submission_id`.
   - Receipt filenames include `submission_id` so old files cannot satisfy new runs.

3. **Thin Stop hook semantics**
   - Hook checks for receipt presence only (not JSON schema).
   - Missing receipt on first stop attempt: exit 2 with guidance.
   - Missing receipt when `stop_hook_active=true`: exit 0 and warn, to avoid infinite loops.
   - Rationale: Stop hook payload does not expose reliable max-turn metadata.

4. **Canonical write paths stay aligned with existing pipeline expectations**
   - Scan-stage agents write under `/opt/scan-results`.
   - Report-stage agents write under the report directory (`config.output_dir`, usually `/output`).

5. **Reuse existing schema validation functions**
   - Import existing validators from `agents/hooks/_common/schemas/*.py`.
   - Do not duplicate validation logic.

6. **Use official Python MCP SDK with stdio transport**
   - Add `mcp` dependency.
   - Launch servers as `sys.executable -m thresher.mcp.<server_module>`.

## Server Matrix

### 1) Analyst MCP

- Tool: `submit_analyst_findings`
- Validates analyst schema
- Writes: `{SCAN_OUTPUT_DIR}/scan-results/analyst-{nn}-{name}.json`
- Receipt: `{SCAN_OUTPUT_DIR}/scan-results/.analyst-{nn}-{name}.{submission_id}.submitted.json`
- Supports multiple submissions per run (last write wins)

### 2) Adversarial MCP

- Tool: `submit_adversarial_findings`
- Validates adversarial schema
- Writes: `{SCAN_OUTPUT_DIR}/adversarial-verification.json`
- Receipt: `{SCAN_OUTPUT_DIR}/.adversarial.{submission_id}.submitted.json`

### 3) Predep MCP

- Tool: `submit_hidden_dependencies`
- Validates predep schema
- Writes: `{SCAN_OUTPUT_DIR}/scan-results/hidden_deps_agent.json`
- Receipt: `{SCAN_OUTPUT_DIR}/.predep.{submission_id}.submitted.json`

### 4) Synthesize MCP

- Tool: `submit_synthesis_report`
- No JSON payload write; verifies required markdown files exist
- Verifies:
  - `{REPORT_DIR}/executive-summary.md`
  - `{REPORT_DIR}/detailed-report.md`
- Receipt: `{REPORT_DIR}/.synthesize.{submission_id}.submitted.json`

### 5) Report Maker MCP

- Tool: `submit_report`
- Validates report schema
- Writes: `{REPORT_DIR}/report_data.json`
- Receipt: `{REPORT_DIR}/.report.{submission_id}.submitted.json`

## Output Directory Contract

Use explicit output roots by stage:

- `SCAN_OUTPUT_DIR` for predep/analyst/adversarial: `/opt/scan-results`
- `REPORT_DIR` for synthesize/report-maker: `config.output_dir` (in container this is `/output`)

This removes ambiguity between scan artifacts and staged report artifacts.

## Stop Hook Replacement

Current: `validate_json_output.sh <schema>` parses and validates output JSON.

New (same script path, new behavior): `validate_json_output.sh <label> <submission_id> <output_dir>`

- Derives receipt path from label and submission_id.
- Reads Stop event JSON from stdin to inspect `stop_hook_active`.
- Behavior:
  - receipt exists -> exit 0
  - receipt missing and `stop_hook_active=false` -> exit 2 with "call submit tool"
  - receipt missing and `stop_hook_active=true` -> exit 0 and warn

## Runner / AgentSpec Integration

`AgentSpec` gains `mcp_settings_json`.

```python
@dataclass
class AgentSpec:
    label: str
    prompt: str
    allowed_tools: list[str]
    max_turns: int
    timeout: int = 3600
    cwd: str | None = None
    hooks_settings_json: str | None = None
    mcp_settings_json: str | None = None
    extra_env: dict[str, str] = field(default_factory=dict)
```

`run_agent()` merges hook + MCP settings into one `--settings` file.

## Agent Wiring

For each invocation:

1. Generate `submission_id` (uuid4 hex)
2. Build Stop hook settings with `label`, `submission_id`, and output root
3. Build MCP settings for that agent type (same submission_id in env)
4. Add MCP tool to `allowed_tools` (`mcp__<server>__<tool>`)
5. Append prompt instruction: "You must call submit_* when done"

Analyst labels should be zero-padded for consistency: `analyst-{number:02d}-{name}`.

## Pipeline Data Flow

Primary path:

1. Agent calls MCP submit tool
2. MCP server validates and writes canonical file
3. Pipeline reads canonical file

Fallback path (during migration):

1. If canonical file is missing, parse stdout as before
2. Emit warning so fallback usage is visible in logs

## Security Considerations

- stdio transport means no network listener is exposed
- validation at tool boundary prevents malformed payloads in normal operation
- invocation-scoped receipts prevent stale-file false positives
- receipt checks are workflow gating, not strong anti-tamper guarantees

## What Changes

### Added

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

### Replaced

- `agents/hooks/_common/validate_json_output.sh` -> thin submission checker

### Kept for rollout fallback

- `agents/_json.py` and stdout extraction path
- existing schema validator modules (reused by MCP servers)

## Migration Phases

1. Build `thresher.mcp` package and server base
2. Add `mcp_settings_json` support in runner
3. Replace Stop hook with submission checker
4. Wire all five agent types to MCP submit tools
5. Update pipeline reads: MCP file first, stdout fallback second
6. Add/adjust tests for hook behavior, MCP writes, and fallback behavior

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| Agent forgets to call submit tool | Stop hook blocks first stop with explicit instruction |
| Infinite stop-hook loops | If `stop_hook_active=true` and still no receipt, hook warns and allows stop |
| Old markers satisfy new run | Receipt includes per-invocation `submission_id` |
| MCP server crash during submission | Receipt written only after successful canonical write |
| Schema drift | MCP imports existing schema validators directly |
| Directory confusion (`/opt/scan-results` vs `/output`) | Per-agent output root is explicit and documented |
