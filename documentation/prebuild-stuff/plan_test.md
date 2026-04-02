# Test Implementation Plan

## Principles

- **Unit tests** mock all external dependencies (subprocess, network, filesystem). They test logic in isolation: parsing, scoring, validation, data transforms.
- **Integration tests** mock only the VM boundary (ssh_exec, ssh_copy_to). They test multi-module workflows: scanner orchestration, agent pipelines, report generation.
- **E2E tests** require a real Lima VM and are gated behind a `@pytest.mark.e2e` marker so they don't run in CI or casual `pytest` invocations.
- Use real scanner output fixtures (JSON files) rather than hand-crafting dicts. This catches schema drift.
- Keep tests fast. The unit + integration suite should complete in < 10 seconds.

## Directory Structure

```
tests/
  conftest.py                          # shared fixtures, markers, mock helpers
  fixtures/
    sample_scanner_output/
      grype.json                       # real Grype JSON output
      osv.json                         # real OSV-Scanner JSON output
      semgrep.json                     # real Semgrep JSON output
      guarddog.json                    # real GuardDog JSON output
      gitleaks.json                    # real Gitleaks JSON output
      sbom.json                        # minimal CycloneDX SBOM
    sample_agent_output/
      analyst_clean.json               # agent output: clean JSON
      analyst_codeblock.txt            # agent output: JSON inside ```json``` block
      analyst_envelope.json            # agent output: Claude Code envelope wrapping
      adversarial.json                 # adversarial agent output
  unit/
    test_config.py                     # ScanConfig validation and load_config
    test_models.py                     # Finding/ScanResults dataclass + to_dict
    test_ssh.py                        # SSHResult, _shell_quote, ssh_write_file
    test_firewall.py                   # generate_firewall_rules output correctness
    test_sandbox.py                    # ecosystem detection, package name parsing
    test_grype.py                      # parse_grype_output
    test_osv.py                        # parse_osv_output (CVE + MAL entries)
    test_semgrep.py                    # parse_semgrep_output
    test_guarddog.py                   # parse_guarddog_output (dict + list formats)
    test_gitleaks.py                   # parse_gitleaks_output
    test_runner.py                     # aggregate_findings de-duplication + _richness
    test_analyst.py                    # triage list building, prompt construction, JSON parsing
    test_adversarial.py                # risk filtering, merge logic, output parsing
    test_scoring.py                    # compute_composite_priority, EPSS/KEV enrichment
    test_synthesize.py                 # _collect_findings, template context, priority grouping
  integration/
    test_scanner_pipeline.py           # scanner runner with mocked ssh_exec
    test_agent_pipeline.py             # analyst + adversarial with mocked ssh_exec
    test_report_pipeline.py            # end-to-end report generation with mocked VM
    test_cli.py                        # Click CLI invocation with CliRunner
  e2e/
    test_full_scan.py                  # real Lima VM scan of a small test repo
```

## Shared Fixtures (conftest.py)

```
Fixtures to define:
  sample_finding()          -> Finding with all fields populated
  sample_finding_minimal()  -> Finding with only required fields
  sample_scan_results()     -> ScanResults with a few findings
  sample_config()           -> ScanConfig with defaults + fake API key
  sample_config_skip_ai()   -> ScanConfig with skip_ai=True
  mock_ssh_exec             -> monkeypatch for ssh_exec returning configurable SSHResult
  fixture_dir               -> Path to tests/fixtures/
  load_fixture(name)        -> helper to read and parse JSON fixture files
```

pytest configuration in pyproject.toml:
```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
markers = ["e2e: end-to-end tests requiring a Lima VM (deselect with '-m not e2e')"]
filterwarnings = ["error"]
```

## Unit Tests

### test_config.py
| Test | What it verifies |
|------|-----------------|
| test_validate_missing_repo_url | validate() returns error when repo_url is empty |
| test_validate_missing_api_key | validate() returns error when skip_ai=False and no API key |
| test_validate_skip_ai_no_key | validate() passes when skip_ai=True and no API key |
| test_validate_bad_depth | validate() returns error when depth < 1 |
| test_validate_happy_path | validate() returns empty list for valid config |
| test_load_config_defaults | load_config sets correct defaults (depth=2, cpus=4, etc.) |
| test_load_config_cli_overrides | CLI args override config file values |
| test_load_config_file | YAML config file values are loaded correctly |
| test_load_config_env_api_key | ANTHROPIC_API_KEY read from environment |

### test_models.py
| Test | What it verifies |
|------|-----------------|
| test_finding_to_dict | to_dict() produces correct keys and values |
| test_finding_to_dict_roundtrip | to_dict output can reconstruct a Finding |
| test_scan_results_to_dict | ScanResults.to_dict() includes nested findings |
| test_scan_results_defaults | Default values for optional fields (empty lists, None) |

### test_ssh.py
| Test | What it verifies |
|------|-----------------|
| test_ssh_result_named_tuple | SSHResult supports both attribute access and destructuring |
| test_shell_quote_simple | _shell_quote handles simple strings |
| test_shell_quote_single_quotes | _shell_quote escapes embedded single quotes |
| test_shell_quote_special_chars | _shell_quote handles $, `, \, etc. |
| test_ssh_exec_builds_export_env | env dict produces `export VAR=val;` prefix (not inline) |
| test_ssh_exec_no_env | Without env dict, command is passed directly |
| test_ssh_exec_timeout | TimeoutExpired raised as SSHError |
| test_ssh_exec_limactl_missing | FileNotFoundError raised as SSHError |
| test_ssh_write_file | Writes to temp, copies via ssh_copy_to, cleans up temp |
| test_ssh_copy_from_recursive | -r flag present in limactl copy command |

### test_firewall.py
| Test | What it verifies |
|------|-----------------|
| test_generates_valid_bash | Output starts with shebang, has set -euo pipefail |
| test_allows_loopback | Contains -o lo -j ACCEPT |
| test_allows_dns | Contains --dport 53 ACCEPT |
| test_whitelists_all_domains | Every WHITELISTED_DOMAINS entry has a 443 rule |
| test_drops_by_default | Default OUTPUT policy is DROP |
| test_logs_blocked | Contains LOG --log-prefix "BLOCKED:" |
| test_static_crates_io_included | static.crates.io is in whitelist |

### test_sandbox.py
| Test | What it verifies |
|------|-----------------|
| test_detect_ecosystems_python | requirements.txt or pyproject.toml -> "python" |
| test_detect_ecosystems_node | package.json -> "node" |
| test_detect_ecosystems_rust | Cargo.toml -> "rust" |
| test_detect_ecosystems_go | go.mod -> "go" |
| test_detect_ecosystems_multi | Multiple indicators -> sorted unique list |
| test_detect_ecosystems_none | No indicators -> empty list |
| test_parse_package_name_python_tar | "requests-2.31.0.tar.gz" -> ("requests", "2.31.0") |
| test_parse_package_name_python_zip | "foo-1.0.zip" -> ("foo", "1.0") |
| test_parse_package_name_node_tgz | "express-4.18.2.tgz" -> ("express", "4.18.2") |
| test_parse_package_name_rust_dir | "serde-1.0.193" -> ("serde", "1.0.193") |
| test_parse_package_name_no_version | "serde" -> ("serde", "unknown") |
| test_docker_run_uses_sudo | Command starts with "sudo docker run" |
| test_docker_run_network_none | network=False adds --network=none |

### test_grype.py
| Test | What it verifies |
|------|-----------------|
| test_parse_empty_matches | Empty matches array -> empty findings list |
| test_parse_single_vuln | Single match parsed with correct CVE, severity, CVSS, package |
| test_parse_severity_mapping | All Grype severity strings map correctly |
| test_parse_fix_version | Fix version extracted from vulnerability.fix.versions |
| test_parse_no_cve_prefix | Non-CVE IDs (e.g. GHSA) -> cve_id=None |
| test_extract_cvss_highest | Multiple CVSS entries -> highest score returned |
| test_parse_from_fixture | Full fixture file parses without error |

### test_osv.py
| Test | What it verifies |
|------|-----------------|
| test_parse_cve_finding | Standard CVE finding parsed correctly |
| test_parse_mal_finding | MAL-prefixed ID -> category="supply_chain", severity="critical" |
| test_extract_severity_from_db_specific | database_specific.severity extracted |
| test_extract_severity_from_cvss_v3 | CVSS_V3 score -> severity mapping |
| test_extract_severity_default | Missing severity -> "medium" |
| test_extract_fix_version | Fixed event in ranges extracted |
| test_parse_from_fixture | Full fixture file parses without error |

### test_semgrep.py
| Test | What it verifies |
|------|-----------------|
| test_parse_basic_finding | check_id, file_path, line_number extracted |
| test_severity_mapping | ERROR->high, WARNING->medium, INFO->low |
| test_cwe_in_title | CWE metadata included in title |
| test_cve_metadata | cve_id extracted from metadata |
| test_parse_from_fixture | Full fixture file parses without error |

### test_guarddog.py
| Test | What it verifies |
|------|-----------------|
| test_parse_dict_format | Package->results dict format parsed |
| test_parse_list_format | List-of-results format parsed |
| test_parse_empty_results | Empty results -> empty findings |
| test_parse_rule_matches_with_location | File path extracted from match location |
| test_all_findings_supply_chain | Category is always "supply_chain" |
| test_parse_from_fixture | Full fixture file parses without error |

### test_gitleaks.py
| Test | What it verifies |
|------|-----------------|
| test_parse_single_leak | RuleID, File, StartLine extracted correctly |
| test_match_truncated | Match field truncated to 20 chars in description |
| test_all_findings_secrets | Category is always "secrets" |
| test_exit_code_0_no_findings | Exit 0 -> empty findings, no error |
| test_parse_from_fixture | Full fixture file parses without error |

### test_runner.py
| Test | What it verifies |
|------|-----------------|
| test_aggregate_dedup_same_cve_package | Two findings with same (CVE, package) -> one kept |
| test_aggregate_keeps_richer | Richer finding (more fields) kept during dedup |
| test_aggregate_no_cve_always_included | Findings without cve_id are never deduped |
| test_aggregate_sorted_by_severity | Output sorted: critical, high, medium, low, info |
| test_richness_scoring | _richness counts populated optional fields |

### test_analyst.py
| Test | What it verifies |
|------|-----------------|
| test_extract_flagged_paths | File paths extracted from scanner findings dicts |
| test_extract_flagged_paths_ignores_none | None/missing file_path values skipped |
| test_limit_init_files | Only MAX_INIT_FILES shallowest __init__.py kept |
| test_limit_init_files_preserves_non_init | Non-init files always preserved |
| test_format_scanner_summary | Output contains tool names and finding counts |
| test_build_analyst_prompt_contains_system | Prompt starts with ANALYST_SYSTEM_PROMPT |
| test_build_analyst_prompt_contains_files | Triage files listed in prompt |
| test_parse_agent_json_clean | Valid JSON parsed directly |
| test_parse_agent_json_envelope | Claude Code {"result": "..."} envelope unwrapped |
| test_parse_agent_json_codeblock | JSON extracted from ```json ... ``` block |
| test_parse_agent_json_embedded | JSON extracted from surrounding text |
| test_parse_agent_json_empty | Empty input -> _empty_findings structure |
| test_empty_findings_structure | _empty_findings has required keys |

### test_adversarial.py
| Test | What it verifies |
|------|-----------------|
| test_extract_scanner_high_risk_critical | critical severity -> risk 9, included (>= 4) |
| test_extract_scanner_high_risk_low | low severity -> risk 2, excluded (< 4) |
| test_extract_scanner_high_risk_medium | medium severity -> risk 5, included |
| test_extract_ai_high_risk | risk_score >= 4 findings included |
| test_extract_ai_high_risk_below_threshold | risk_score < 4 findings excluded |
| test_filter_combines_sources | Scanner + AI high-risk findings merged |
| test_merge_confirmed | confirmed verdict preserves risk_score |
| test_merge_downgraded | downgraded verdict updates risk_score |
| test_merge_adds_metadata | adversarial_verification summary added |
| test_parse_adversarial_json_clean | Valid JSON parsed |
| test_parse_adversarial_json_envelope | Envelope unwrapped |
| test_parse_adversarial_json_empty | Empty -> {"results": [], "error": ...} |

### test_scoring.py
| Test | What it verifies |
|------|-----------------|
| test_priority_p0_kev | CVE in KEV set -> "P0" |
| test_priority_p0_ai_exfil | ai_confidence >= 90 + exfiltration category -> "P0" |
| test_priority_critical_cvss | CVSS >= 9.0 -> "critical" |
| test_priority_critical_epss | EPSS > 0.9 -> "critical" |
| test_priority_critical_ai_confirmed | AI risk 9+ confirmed -> "critical" |
| test_priority_high_cvss | CVSS 7.0-8.9 -> "high" |
| test_priority_high_epss | EPSS > 0.75 -> "high" |
| test_priority_high_ai | AI risk 7-8 -> "high" |
| test_priority_medium_cvss | CVSS 4.0-6.9 -> "medium" |
| test_priority_medium_epss | EPSS > 0.5 -> "medium" |
| test_priority_low_default | No signals -> "low" |
| test_enrich_adds_epss_fields | epss_score and epss_percentile added |
| test_enrich_adds_kev_field | in_kev boolean added |
| test_enrich_adds_composite_priority | composite_priority string added |
| test_fetch_epss_empty_input | Empty CVE list -> empty dict |
| test_fetch_epss_batching | > EPSS_BATCH_SIZE CVEs batched into multiple requests |

### test_synthesize.py
| Test | What it verifies |
|------|-----------------|
| test_collect_scanner_findings | Scanner dict->list findings extracted |
| test_collect_ai_findings_mapped | AI findings get ai_risk_score, source_tool, ai_confidence |
| test_collect_no_ai | ai_findings=None -> only scanner findings |
| test_template_context_do_not_use | P0 or critical -> risk_assessment="DO NOT USE" |
| test_template_context_caution | High only -> "CAUTION" |
| test_template_context_go | Medium/low only -> "GO" |
| test_template_context_top_10 | Top findings limited to 10, sorted by priority |
| test_build_synthesis_input_format | Contains priority counts, tool coverage, top risks |

## Integration Tests

### test_scanner_pipeline.py

Mock `ssh_exec` to return fixture data. Verify the full scanner runner orchestrates correctly.

| Test | What it verifies |
|------|-----------------|
| test_run_all_scanners_happy_path | Syft runs first, then 5 scanners in parallel; all results collected |
| test_run_all_scanners_syft_failure | Syft failure still returns results (with error); Grype gets default SBOM path |
| test_run_all_scanners_partial_failure | One scanner exception -> error ScanResults; others succeed |
| test_scanner_exit_code_1_is_findings | Grype/OSV/Gitleaks exit=1 treated as success with findings |

### test_agent_pipeline.py

Mock `ssh_exec` and `ssh_write_file`. Verify agent orchestration flows.

| Test | What it verifies |
|------|-----------------|
| test_analyst_writes_prompt_safely | Prompt written via ssh_write_file (not heredoc) |
| test_analyst_passes_api_key | ssh_exec called with env containing ANTHROPIC_API_KEY |
| test_analyst_timeout | ssh_exec called with timeout=3600 |
| test_analyst_empty_triage | Empty triage list -> skip agent, return empty findings |
| test_adversarial_skips_no_high_risk | No findings >= threshold -> returns ai_findings unchanged |
| test_adversarial_passes_api_key | ssh_exec called with env containing ANTHROPIC_API_KEY |
| test_adversarial_merge_flow | Verification results merged back into findings |

### test_report_pipeline.py

Mock SSH layer. Verify report generation end-to-end.

| Test | What it verifies |
|------|-----------------|
| test_generate_report_skip_ai | Template-based report generated, ssh_write_file called for each output |
| test_generate_report_agent_fallback | Agent fails -> falls back to template report |
| test_generate_report_enrichment | Findings enriched with EPSS/KEV before report |
| test_report_dir_timestamped | Report directory contains UTC timestamp |

### test_cli.py

Use Click's `CliRunner` for isolated CLI testing.

| Test | What it verifies |
|------|-----------------|
| test_cli_missing_repo_url | Exit 2 (Click usage error) |
| test_cli_missing_api_key | Exit 1 with "ANTHROPIC_API_KEY" in error message |
| test_cli_skip_ai_no_key | Proceeds without API key error |
| test_cli_repo_url_quoted | repo_url passed through shlex.quote (verify no injection) |
| test_cli_keyboard_interrupt | Exit 130 on KeyboardInterrupt |
| test_cli_custom_options | --cpus, --memory, --disk, --depth, --output parsed correctly |

## E2E Tests

### test_full_scan.py

Marked with `@pytest.mark.e2e`. Requires Lima installed and ~10 minutes to run.

| Test | What it verifies |
|------|-----------------|
| test_scan_skip_ai_small_repo | Full deterministic scan of a tiny test repo. VM created, provisioned, scanners run, report generated, VM destroyed. Verifies report files exist and contain expected structure. |
| test_vm_lifecycle | Create, start, provision, destroy cycle completes without error. VM no longer exists after destroy. |
| test_firewall_blocks_unwhitelisted | Inside VM, curl to a non-whitelisted domain is blocked. curl to api.anthropic.com succeeds. |

## Implementation Order

1. **conftest.py + pyproject.toml config** -- fixtures and markers
2. **Fixture files** -- sample scanner JSON outputs (grype.json, osv.json, etc.)
3. **Unit: models, config, ssh** -- foundational data types
4. **Unit: scanner parsers** -- all 6 parsers against fixtures
5. **Unit: runner** -- aggregation and dedup
6. **Unit: analyst + adversarial** -- triage, filtering, JSON parsing, merge
7. **Unit: scoring** -- composite priority computation
8. **Unit: synthesize** -- findings collection, template context
9. **Unit: firewall + sandbox** -- rule generation, ecosystem detection
10. **Integration: scanner pipeline** -- mocked ssh_exec end-to-end
11. **Integration: agent pipeline** -- mocked agent invocations
12. **Integration: report pipeline** -- mocked report generation
13. **Integration: CLI** -- CliRunner tests
14. **E2E: full scan** -- real VM tests (manual verification)

## Notes

- All SSH-dependent tests use `monkeypatch` or `unittest.mock.patch` to replace `subprocess.run`. No real VMs in unit/integration tests.
- Scanner fixture files should be realistic but minimal (2-3 findings each). Capture from real tool runs if possible.
- E2E tests are opt-in only (`pytest -m e2e`). They are slow, require Lima, and consume real resources.
- EPSS/KEV tests mock `urllib.request.urlopen` to avoid network calls.
