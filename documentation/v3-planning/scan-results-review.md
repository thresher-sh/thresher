# Run Inspection Report: aegra-20260409-002216

**Target:** ibbybuilds/aegra | **Mode:** Docker | **Duration:** ~26 min

---

## CRITICAL Issues

### 1. Grype & Trivy failed — no CVE coverage

Both vulnerability scanners failed with `no space left on device` when downloading their vulnerability DBs into `/home/thresher/.cache/` (tmpfs). Zero CVE scan results. The reports document this but the scan has incomplete vulnerability coverage.

**Root cause:** Container tmpfs too small for ~90MB vulnerability DB downloads.

### 2. analyst-investigator failed — silent data loss

Hit `error_max_turns` (16/15 turns) and produced 0 findings. The investigator persona (git forensics, contributor trust, provenance analysis) is entirely missing from the scan. No report mentions this failure — it's silent data loss.

**Root cause:** Global `analyst_max_turns=15` overrides the YAML default of 30. The investigator needs more turns for its git forensics workflow.

### 3. Adversarial merge bug — file_path collision

The `_merge_adversarial_results()` function in `src/thresher/agents/adversarial.py` matches by `file_path`. When multiple findings share a path (e.g., `main.py` has 9 findings), only the last verdict overwrites the dict, then gets applied to all findings at that path. Result:

- Adversarial reviewed 36 findings -> confirmed 15, downgraded 21
- Merge applied verdicts to 46 findings (inflated by shared paths)
- 8 findings were never adversarially reviewed (missing all adversarial fields)
- Copy-paste errors: "Rate Limiting" finding has CORS-related adversarial reasoning

### 4. Per-analyst findings not saved to scan-results/

Individual analyst result JSONs (`analyst-01-paranoid.json`, `analyst-02-behaviorist.json`, etc.) are completely missing from `scan-results/`. Only the merged `findings.json` exists, which loses per-analyst structure (analyst name, risk_score, summary, core_question).

**Root cause:** `run_all_analysts()` in `src/thresher/agents/analysts.py` returns findings as in-memory Python dicts (line 533) — they are never serialized to disk. The pipeline DAG in `harness/pipeline.py` passes only the merged `enriched_findings` to `generate_report()`, not the per-analyst list. And `generate_report()` in `harness/report.py` only writes `findings.json` (merged) and copies scanner files from `/opt/scan-results/` (lines 159-167). There is no code anywhere to save individual analyst outputs.

### 5. report.html not generated

The HTML report is completely missing from the output. Only markdown reports (`executive-summary.md`, `detailed-report.md`, `synthesis-findings.md`) are present.

**Root cause:** `_generate_html_report()` exists in `src/thresher/report/synthesize.py` (line 868) and is called from the OLD `synthesize.py:generate_report()` at line 245. But the NEW `harness/report.py:generate_report()` (which the harness pipeline actually uses) only calls `_generate_agent_report` and `_generate_template_report` — it never calls `_generate_html_report`. The HTML generation step was lost during the migration from the legacy pipeline to the harness pipeline.

---

## HIGH Issues

### 6. Scanner output JSON corruption (8 of 18 files)

Scanners writing JSON to stdout have their output corrupted by intermixed stderr/progress output. Affected: semgrep, semgrep-supply-chain, grype, trivy, osv, bandit, sbom/syft, guarddog. Scanners using file-path output (checkov, scancode) are fine.

**Root cause:** Harness captures raw stdout without separating stderr/log lines.

### 7. synthesis_input.md is broken

- Important Findings array is empty despite 1 critical + 9 high findings
- All 54 findings attributed to source "unknown"
- Only 556 bytes — no per-finding detail
- The synthesis agent compensated by reading raw scan-results files directly

### 8. findings.json contains only AI findings

Zero deterministic scanner findings in `findings.json`. The synthesis agent had to read raw scan-result files to incorporate scanner data into the final reports.

---

## MEDIUM Issues

### 9. Dependency download failed

`pip3-download` failed all 3 retries — the target repo has a non-standard flat layout. Python dependencies were NOT downloaded, reducing dependency-focused scanner coverage.

### 10. Most analysts used 3/15 turns

This is not a bug — agents use Claude Code's task tool to batch many operations per turn. 3 turns is the normal pattern (plan -> execute -> output). The harness "turns" count (84, 114, etc.) reflects streamed JSON messages, not API turns.

---

## INFO

| Item | Status |
|------|--------|
| predep agent | 3/15 turns, success, 22 hidden deps. 1 expected Bash permission denial (Bash not in allowedTools) |
| 7/8 analysts | All success, 3-13 findings each, risk scores 1-9 |
| adversarial agent | 20/20 turns, completed (not cut short), reviewed all 36 findings |
| synthesize agent | 12/75 turns, success, $0.88 cost |
| clamav | 0 bytes output = no infections (expected) |
| yara | No rules directory found, no output |
| Reports | detailed-report.md, executive-summary.md, synthesis-findings.md all well-structured with substantive content |

---

## Recommended Fixes (priority order)

1. **Save per-analyst findings** — write each analyst's result dict to `scan-results/analyst-{NN}-{name}.json`. Either save in `run_all_analysts()` to `/opt/scan-results/` (picked up by existing copy), or pass `analyst_findings` through the DAG to `generate_report()` and save directly.
2. **Generate report.html** — add `_generate_html_report()` call to `harness/report.py:generate_report()` after the markdown reports are written (matching what the old `synthesize.py:generate_report()` does at line 245).
3. **Increase investigator max_turns** — set per-agent override to 30 in config, or raise global to match YAML defaults.
4. **Fix adversarial merge** — use finding ID instead of `file_path` for matching in `_merge_adversarial_results()`.
5. **Fix scanner output capture** — separate stdout/stderr, or use file-path output for all scanners.
6. **Increase container tmpfs** — allow space for grype/trivy DB downloads.
7. **Fix synthesis_input.md generation** — populate Important Findings array and source attribution.
8. **Include scanner findings in findings.json** — don't rely on synthesis agent reading raw files.

---

## Missing Tests

### Tests that would fail today (exposing current bugs)

1. **`test_generate_report_writes_analyst_files`** (`test_harness_report.py`)
   Call `generate_report()` with analyst findings data, assert `scan-results/analyst-01-paranoid.json` etc. exist.
   *Would fail: no code saves per-analyst files.*

2. **`test_generate_report_creates_html`** (`test_harness_report.py`)
   Call `generate_report()`, assert `report.html` exists in output.
   *Would fail: `harness/report.py` never calls `_generate_html_report()`.*

3. **`test_adversarial_merge_multiple_findings_same_path`** (`test_adversarial.py`)
   Two findings with same `file_path` but different titles, two verification results for the same path.
   *Would fail: dict keyed by `file_path` overwrites — last verdict wins, first finding gets wrong verdict.*

4. **`test_run_all_analysts_reports_failures`** (`test_analysts.py`)
   Mock one analyst to return None (failure), verify `run_all_analysts()` logs which analyst failed at ERROR level.
   *Would fail: failures return None silently, no error-level log with analyst name.*

5. **`test_synthesis_input_populates_important_findings`** (`test_synthesize.py`)
   Call `_build_synthesis_input()` with high-severity findings, extract JSON, assert Important Findings is not empty.
   *Would fail: Important Findings array is always empty.*

6. **`test_synthesis_input_source_attribution`** (`test_synthesize.py`)
   Call `_build_synthesis_input()` with findings that have `source_tool` set, assert source is not "unknown".
   *Would fail: all findings get source "unknown".*

### Additional tests to add

7. **`test_generate_report_analyst_files_content`** (`test_harness_report.py`)
   Verify per-analyst JSON contains expected keys: `analyst`, `analyst_number`, `findings`, `summary`, `risk_score`.

8. **`test_generate_report_skips_analyst_files_when_skip_ai`** (`test_harness_report.py`)
   With `skip_ai=True`, verify no analyst files are written to `scan-results/`.

9. **`test_adversarial_merge_unreviewed_findings_flagged`** (`test_adversarial.py`)
   Findings not in the adversarial review set should have a clear `"not_reviewed"` status, not just missing fields.

10. **`test_findings_json_includes_scanner_findings`** (`test_harness_report.py`)
    Call `generate_report()` with both scanner `ScanResults` and AI findings, verify `findings.json` contains both types.

11. **`test_scanner_output_valid_json`** (`test_scanner_pipeline.py`)
    Mock subprocess stdout with stderr lines mixed in before JSON, verify the saved output is valid JSON.

12. **`test_generate_report_html_matches_markdown`** (`test_harness_report.py`)
    When agent reports exist, verify `report.html` incorporates `executive-summary.md` and `synthesis-findings.md` content.
