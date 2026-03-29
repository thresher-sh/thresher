"""Agent-driven report synthesis orchestration."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from threat_scanner.config import ScanConfig
from threat_scanner.report.scoring import enrich_findings
from threat_scanner.vm.ssh import ssh_exec, ssh_write_file

logger = logging.getLogger(__name__)

# Report output base inside the VM
REPORT_BASE_DIR = "/opt/security-reports"

# Scan results and SBOM locations inside the VM
SCAN_RESULTS_DIR = "/opt/scan-results"
SBOM_PATH = "/opt/scan-results/sbom.json"

# Priority ordering for display
PRIORITY_ORDER = ["P0", "critical", "high", "medium", "low"]


def generate_report(
    vm_name: str,
    config: ScanConfig,
    scanner_results: Any,
    ai_findings: dict[str, Any] | None,
) -> str:
    """Generate the full security report inside the VM.

    Creates a timestamped report directory, enriches findings with EPSS/KEV
    data, and either invokes the Claude synthesis agent (default) or falls
    back to Jinja2 templates (when --skip-ai is set).

    Args:
        vm_name: Lima VM name for SSH execution.
        config: Scan configuration.
        scanner_results: Aggregated scanner output (normalized findings).
        ai_findings: AI analysis + adversarial verification results,
                     or None if --skip-ai was used.

    Returns:
        Path to the report directory inside the VM.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    report_dir = f"{REPORT_BASE_DIR}/{timestamp}"

    # Create report directory structure inside the VM
    ssh_exec(vm_name, f"mkdir -p {report_dir}/scan-results")

    # Gather all findings into a flat list
    all_findings = _collect_findings(scanner_results, ai_findings)

    # Enrich findings with EPSS scores, KEV status, and composite priority
    enriched = enrich_findings(all_findings, vm_name)
    logger.info(
        "Enriched %d findings with EPSS/KEV data",
        len(enriched),
    )

    # Copy raw scan results and SBOM into report directory
    ssh_exec(
        vm_name,
        f"cp -r {SCAN_RESULTS_DIR}/* {report_dir}/scan-results/ 2>/dev/null || true",
    )
    ssh_exec(
        vm_name,
        f"cp {SBOM_PATH} {report_dir}/sbom.json 2>/dev/null || true",
    )

    # Write enriched findings JSON (via safe copy to avoid heredoc injection)
    findings_json = json.dumps(enriched, indent=2, default=str)
    ssh_write_file(vm_name, findings_json, f"{report_dir}/findings.json")

    if config.skip_ai:
        # Fallback: use Jinja2 templates for report generation
        _generate_template_report(vm_name, config, enriched, scanner_results, report_dir)
    else:
        # Agent-driven synthesis via Claude Code headless
        _generate_agent_report(
            vm_name, config, scanner_results, ai_findings, enriched, report_dir
        )

    logger.info("Report generated at %s", report_dir)
    return report_dir


def _collect_findings(
    scanner_results: Any,
    ai_findings: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Collect all findings from scanner results and AI analysis into a flat list."""
    findings: list[dict[str, Any]] = []

    # Extract findings from scanner results
    if isinstance(scanner_results, dict):
        # Scanner results may be keyed by tool name
        for tool_name, tool_output in scanner_results.items():
            if isinstance(tool_output, list):
                findings.extend(tool_output)
            elif isinstance(tool_output, dict) and "findings" in tool_output:
                findings.extend(tool_output["findings"])
    elif isinstance(scanner_results, list):
        findings.extend(scanner_results)

    # Merge AI findings if present, mapping field names so composite
    # priority scoring can find the expected ai_risk_score field.
    if ai_findings:
        ai_finding_list = ai_findings.get("findings", [])
        if isinstance(ai_finding_list, list):
            for af in ai_finding_list:
                if isinstance(af, dict):
                    enriched_af = dict(af)
                    # Map AI-specific fields for downstream scoring
                    if "risk_score" in enriched_af and "ai_risk_score" not in enriched_af:
                        enriched_af["ai_risk_score"] = enriched_af["risk_score"]
                    enriched_af.setdefault("source_tool", "ai_analysis")
                    enriched_af.setdefault("category", "ai_analysis")
                    # Extract confidence from sub-findings if present
                    sub_findings = enriched_af.get("findings", [])
                    if isinstance(sub_findings, list) and sub_findings:
                        max_conf = max(
                            (sf.get("confidence", 0) for sf in sub_findings
                             if isinstance(sf, dict)),
                            default=0,
                        )
                        if max_conf and "ai_confidence" not in enriched_af:
                            enriched_af["ai_confidence"] = max_conf
                    findings.append(enriched_af)

    return findings


def _build_synthesis_input(
    scanner_results: Any,
    ai_findings: dict[str, Any] | None,
    enriched: list[dict[str, Any]],
) -> str:
    """Build the input text for the synthesis agent.

    Summarizes total findings by severity, top risks, and tool coverage,
    then includes all findings as JSON.
    """
    lines: list[str] = []
    lines.append("# Security Scan Synthesis Input")
    lines.append("")

    # Summary counts by priority
    priority_counts: dict[str, int] = {}
    for f in enriched:
        p = f.get("composite_priority", "low")
        priority_counts[p] = priority_counts.get(p, 0) + 1

    lines.append("## Finding Counts by Priority")
    for priority in PRIORITY_ORDER:
        count = priority_counts.get(priority, 0)
        lines.append(f"- **{priority.upper()}**: {count}")
    lines.append(f"- **Total**: {len(enriched)}")
    lines.append("")

    # Tool coverage summary
    tools_seen: set[str] = set()
    for f in enriched:
        tool = f.get("source_tool")
        if tool:
            tools_seen.add(tool)

    lines.append("## Tool Coverage")
    if tools_seen:
        for tool in sorted(tools_seen):
            tool_count = sum(1 for f in enriched if f.get("source_tool") == tool)
            lines.append(f"- {tool}: {tool_count} findings")
    else:
        lines.append("- No tool attribution found in findings")
    lines.append("")

    # Top risks (P0 and critical findings)
    top_risks = [
        f for f in enriched if f.get("composite_priority") in ("P0", "critical")
    ]
    if top_risks:
        lines.append("## Top Risks")
        for risk in top_risks[:20]:
            title = risk.get("title", "Unknown")
            cve = risk.get("cve_id", "N/A")
            priority = risk.get("composite_priority", "unknown")
            lines.append(f"- [{priority.upper()}] {title} ({cve})")
        lines.append("")

    # AI findings summary
    if ai_findings:
        lines.append("## AI Analysis Summary")
        ai_list = ai_findings.get("findings", [])
        confirmed = sum(
            1 for f in ai_list if f.get("adversarial_status") == "confirmed"
        )
        downgraded = sum(
            1 for f in ai_list if f.get("adversarial_status") == "downgraded"
        )
        lines.append(f"- AI findings: {len(ai_list)}")
        lines.append(f"- Adversarially confirmed: {confirmed}")
        lines.append(f"- Adversarially downgraded: {downgraded}")
        lines.append("")

    # Full findings JSON
    lines.append("## All Enriched Findings (JSON)")
    lines.append("```json")
    lines.append(json.dumps(enriched, indent=2, default=str))
    lines.append("```")

    return "\n".join(lines)


def _generate_agent_report(
    vm_name: str,
    config: ScanConfig,
    scanner_results: Any,
    ai_findings: dict[str, Any] | None,
    enriched: list[dict[str, Any]],
    report_dir: str,
) -> None:
    """Invoke Claude Code headless inside the VM to synthesize the final report."""
    synthesis_input = _build_synthesis_input(scanner_results, ai_findings, enriched)

    # Write synthesis input via safe copy (avoids heredoc injection)
    input_path = f"{report_dir}/synthesis_input.md"
    ssh_write_file(vm_name, synthesis_input, input_path)

    # Build the synthesis prompt and write it to a file in the VM
    # (avoids shell quoting issues with inline multi-line prompts)
    synthesis_prompt = _build_synthesis_prompt(report_dir, input_path)
    ssh_write_file(vm_name, synthesis_prompt, "/tmp/synthesis_prompt.txt")

    # Invoke Claude Code headless inside the VM
    claude_cmd = (
        'claude -p "$(cat /tmp/synthesis_prompt.txt)" '
        "--allowedTools 'Read,Write,Glob,Grep' "
        "--output-format text "
        "--max-turns 15"
    )

    env: dict[str, str] = {}
    if config.anthropic_api_key:
        env["ANTHROPIC_API_KEY"] = config.anthropic_api_key

    _stdout, _stderr, exit_code = ssh_exec(
        vm_name, claude_cmd, timeout=1800, env=env or None
    )
    logger.info("Synthesis agent completed: exit_code=%d", exit_code)

    # Verify expected output files exist; fall back to templates if agent failed
    check_cmd = (
        f"test -f {report_dir}/executive-summary.md "
        f"&& test -f {report_dir}/detailed-report.md"
    )
    _, _, check_exit_code = ssh_exec(vm_name, check_cmd)
    agent_succeeded = check_exit_code == 0

    if not agent_succeeded:
        logger.warning(
            "Synthesis agent did not produce expected files; "
            "falling back to template-based report"
        )
        _generate_template_report(
            vm_name, config, enriched, scanner_results, report_dir
        )


def _build_synthesis_prompt(report_dir: str, input_path: str) -> str:
    """Build the prompt for the Claude synthesis agent."""
    return (
        "You are a security report synthesis agent. Your job is to produce a "
        "clear, actionable security assessment from scan findings.\n\n"
        f"Read the synthesis input at {input_path}. It contains all enriched "
        "findings from deterministic scanners and AI analysis, with EPSS scores, "
        "CISA KEV status, and composite priority levels.\n\n"
        "Produce three files:\n\n"
        f"1. {report_dir}/executive-summary.md — A concise executive summary with:\n"
        "   - Overall risk assessment: GO / CAUTION / DO NOT USE\n"
        "   - Decision criteria: any P0 or Critical = DO NOT USE, "
        "High only = CAUTION, otherwise = GO\n"
        "   - Finding counts by priority level\n"
        "   - Top 10 findings table (priority, title, source tool, CVE, CVSS)\n"
        "   - SBOM summary\n\n"
        f"2. {report_dir}/detailed-report.md — Full detailed report with:\n"
        "   - All findings grouped by priority (P0 first, then Critical, High, "
        "Medium, Low)\n"
        "   - Each finding: title, description, source tool, CVE, CVSS, EPSS "
        "percentile, KEV status, AI risk score, adversarial status, file path, "
        "remediation\n"
        "   - Appendix with scanner execution summary\n\n"
        f"3. {report_dir}/findings.json already exists — do not overwrite it.\n\n"
        "Write clear, professional prose. Use markdown tables where appropriate. "
        "Be specific about remediation steps."
    )


def _generate_template_report(
    vm_name: str,
    config: ScanConfig,
    enriched: list[dict[str, Any]],
    scanner_results: Any,
    report_dir: str,
) -> None:
    """Generate reports using Jinja2 templates (fallback for --skip-ai)."""
    import os

    templates_dir = os.path.join(os.path.dirname(__file__), "templates")
    env = Environment(
        loader=FileSystemLoader(templates_dir),
        autoescape=select_autoescape([]),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    # Compute template context
    context = _build_template_context(config, enriched, scanner_results)

    # Render executive summary
    exec_template = env.get_template("executive_summary.md.j2")
    exec_summary = exec_template.render(**context)

    # Render detailed report
    detail_template = env.get_template("detailed_report.md.j2")
    detailed_report = detail_template.render(**context)

    # Write rendered reports into the VM (via safe copy)
    ssh_write_file(vm_name, exec_summary, f"{report_dir}/executive-summary.md")
    ssh_write_file(vm_name, detailed_report, f"{report_dir}/detailed-report.md")


def _build_template_context(
    config: ScanConfig,
    enriched: list[dict[str, Any]],
    scanner_results: Any,
) -> dict[str, Any]:
    """Build the template rendering context from enriched findings."""
    scan_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Count findings by priority
    priority_counts: dict[str, int] = {}
    for f in enriched:
        p = f.get("composite_priority", "low")
        priority_counts[p] = priority_counts.get(p, 0) + 1

    # Determine overall risk assessment
    has_p0 = priority_counts.get("P0", 0) > 0
    has_critical = priority_counts.get("critical", 0) > 0
    has_high = priority_counts.get("high", 0) > 0

    if has_p0 or has_critical:
        risk_assessment = "DO NOT USE"
    elif has_high:
        risk_assessment = "CAUTION"
    else:
        risk_assessment = "GO"

    # Top 10 findings (sorted by priority)
    priority_rank = {p: i for i, p in enumerate(PRIORITY_ORDER)}
    sorted_findings = sorted(
        enriched,
        key=lambda f: priority_rank.get(f.get("composite_priority", "low"), 99),
    )
    top_findings = sorted_findings[:10]

    # Group findings by priority
    findings_by_priority: dict[str, list[dict[str, Any]]] = {}
    for p in PRIORITY_ORDER:
        findings_by_priority[p] = [
            f for f in enriched if f.get("composite_priority") == p
        ]

    # Tool coverage
    tools_seen: dict[str, dict[str, Any]] = {}
    if isinstance(scanner_results, dict):
        for tool_name, tool_output in scanner_results.items():
            exit_code = None
            duration = None
            if isinstance(tool_output, dict):
                exit_code = tool_output.get("exit_code")
                duration = tool_output.get("duration")
            tools_seen[tool_name] = {
                "exit_code": exit_code,
                "duration": duration,
            }

    # SBOM summary (extract from findings if available)
    packages: set[str] = set()
    ecosystems: set[str] = set()
    for f in enriched:
        pkg = f.get("package_name")
        if pkg:
            packages.add(pkg)
        eco = f.get("ecosystem")
        if eco:
            ecosystems.add(eco)

    return {
        "scan_date": scan_date,
        "repo_url": config.repo_url,
        "depth": config.depth,
        "skip_ai": config.skip_ai,
        "risk_assessment": risk_assessment,
        "priority_counts": priority_counts,
        "total_findings": len(enriched),
        "top_findings": top_findings,
        "findings_by_priority": findings_by_priority,
        "priority_order": PRIORITY_ORDER,
        "tools": tools_seen,
        "total_packages": len(packages),
        "ecosystems": sorted(ecosystems),
        "config": config,
    }
