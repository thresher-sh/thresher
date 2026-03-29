"""CLI entry point for threat-scanner."""

from __future__ import annotations

import shlex
import sys
from pathlib import Path

import click

from threat_scanner.config import ScanConfig, load_config


def print_stage(stage: int, total: int, message: str) -> None:
    click.secho(f"[{stage}/{total}] {message}", fg="cyan", bold=True)


def print_error(message: str) -> None:
    click.secho(f"ERROR: {message}", fg="red", err=True)


def print_success(message: str) -> None:
    click.secho(message, fg="green", bold=True)


@click.command()
@click.argument("repo_url")
@click.option("--depth", type=int, default=None, help="Transitive dependency depth (default: 2)")
@click.option("--skip-ai", is_flag=True, help="Deterministic scanners only (no AI agents)")
@click.option("--verbose", is_flag=True, help="Show detailed tool output")
@click.option("--output", "output_dir", default=None, help="Host directory for report output")
@click.option("--cpus", type=int, default=None, help="VM CPU count (default: 4)")
@click.option("--memory", type=int, default=None, help="VM memory in GB (default: 8)")
@click.option("--disk", type=int, default=None, help="VM disk in GB (default: 50)")
def main(
    repo_url: str,
    depth: int | None,
    skip_ai: bool,
    verbose: bool,
    output_dir: str | None,
    cpus: int | None,
    memory: int | None,
    disk: int | None,
) -> None:
    """Scan an open source repository for security threats and supply chain risks."""
    config = load_config(
        repo_url=repo_url,
        depth=depth,
        skip_ai=skip_ai,
        verbose=verbose,
        output_dir=output_dir,
        cpus=cpus,
        memory=memory,
        disk=disk,
    )

    errors = config.validate()
    if errors:
        for err in errors:
            print_error(err)
        sys.exit(1)

    try:
        run_scan(config)
    except KeyboardInterrupt:
        click.echo("\nScan interrupted.")
        sys.exit(130)
    except Exception as e:
        print_error(str(e))
        sys.exit(1)


def run_scan(config: ScanConfig) -> None:
    """Execute the full scan pipeline."""
    total_stages = 5 if not config.skip_ai else 3

    # Stage 1: Create and provision VM
    print_stage(1, total_stages, "Creating isolated VM...")
    from threat_scanner.vm.lima import create_vm, destroy_vm, provision_vm

    vm_name = None
    try:
        vm_name = create_vm(config)
        provision_vm(vm_name, config)

        # Stage 2: Clone repo and download dependencies
        print_stage(2, total_stages, "Cloning repo and downloading dependencies...")
        from threat_scanner.vm.ssh import ssh_exec
        from threat_scanner.docker.sandbox import download_dependencies

        safe_url = shlex.quote(config.repo_url)
        stdout, stderr, rc = ssh_exec(vm_name, f"git clone --depth=1 {safe_url} /opt/target")
        if rc != 0:
            raise RuntimeError(f"git clone failed (exit {rc}): {stderr}")
        download_dependencies(vm_name, config)

        # Stage 3: Run deterministic scanners
        stage_num = 3
        print_stage(stage_num, total_stages, "Running deterministic scanners...")
        from threat_scanner.scanners.runner import run_all_scanners

        scanner_results_raw = run_all_scanners(vm_name, config)
        # Convert list[ScanResults] to dict[str, list[dict]] for downstream consumers
        scanner_results = {
            sr.tool_name: [f.to_dict() for f in sr.findings]
            for sr in scanner_results_raw
        }

        if not config.skip_ai:
            # Stage 4: AI analysis
            stage_num = 4
            print_stage(stage_num, total_stages, "Running AI analysis agents...")
            from threat_scanner.agents.analyst import run_analysis
            from threat_scanner.agents.adversarial import run_adversarial_verification

            ai_findings = run_analysis(vm_name, config, scanner_results)
            verified_findings = run_adversarial_verification(
                vm_name, config, ai_findings, scanner_results
            )
        else:
            verified_findings = None

        # Final stage: Generate report
        print_stage(total_stages, total_stages, "Generating report...")
        from threat_scanner.report.synthesize import generate_report

        report_path = generate_report(vm_name, config, scanner_results, verified_findings)

        # Retrieve report from VM
        from threat_scanner.vm.ssh import ssh_copy_from

        output = Path(config.output_dir)
        output.mkdir(parents=True, exist_ok=True)
        ssh_copy_from(vm_name, report_path, str(output))

        print_success(f"\nScan complete. Report saved to: {output}")

    finally:
        # Always destroy the ephemeral VM
        if vm_name:
            click.echo("Destroying VM...")
            destroy_vm(vm_name)


if __name__ == "__main__":
    main()
