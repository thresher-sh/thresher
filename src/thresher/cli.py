"""CLI entry point for thresher."""

from __future__ import annotations

import logging
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import click

from thresher.branding import (
    ANALYST_DISPLAY_NAMES,
    FinSpinner,
    print_report_path,
    print_scan_header,
    print_splash,
    print_stage_fail,
    print_stage_ok,
    print_swim_divider,
    print_analyst_status,
)
from thresher.config import ScanConfig, load_config

_DEFAULT_LOG_DIR = Path(tempfile.gettempdir()) / "thresher" / "logs"
LOG_DIR: Path = _DEFAULT_LOG_DIR
LOG_FILE: Path = _DEFAULT_LOG_DIR / "scan.log"  # symlink to latest, for tmux tail

_TMUX_SESSION = "thresher"
_TMUX_ENV_FLAG = "_THRESHER_IN_TMUX"


def print_error(message: str) -> None:
    click.secho(f"ERROR: {message}", fg="red", err=True)


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

def _get_version() -> str:
    from importlib.metadata import version as pkg_version
    return pkg_version("thresher")


@click.group(invoke_without_command=True)
@click.version_option(package_name="thresher", prog_name="thresher")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """Thresher — supply chain security scanner."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# thresher scan <url>
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("repo_url")
@click.option("--depth", type=int, default=None, help="Transitive dependency depth (default: 2)")
@click.option("--skip-ai", is_flag=True, help="Deterministic scanners only (no AI agents)")
@click.option("--verbose", is_flag=True, help="Show detailed tool output")
@click.option("--output", "output_dir", default=None, help="Host directory for report output")
@click.option("--cpus", type=int, default=None, help="VM CPU count (default: 4)")
@click.option("--memory", type=int, default=None, help="VM memory in GB (default: 8)")
@click.option("--disk", type=int, default=None, help="VM disk in GB (default: 50)")
@click.option("--tmux", is_flag=True, help="Enable tmux split-pane UI")
@click.option("--high-risk-dep", is_flag=True, help="Download high-risk hidden dependencies (binaries, tarballs)")
def scan(
    repo_url: str,
    depth: int | None,
    skip_ai: bool,
    verbose: bool,
    output_dir: str | None,
    cpus: int | None,
    memory: int | None,
    disk: int | None,
    tmux: bool,
    high_risk_dep: bool,
) -> None:
    """Scan a repository for security threats and supply chain risks."""
    config = load_config(
        repo_url=repo_url,
        depth=depth,
        skip_ai=skip_ai,
        verbose=verbose,
        output_dir=output_dir,
        cpus=cpus,
        memory=memory,
        disk=disk,
        high_risk_dep=high_risk_dep,
    )

    import datetime
    repo_short = repo_url.rstrip("/").rsplit("/", 1)[-1]
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    _setup_logging(verbose, config.log_dir, scan_id=f"{repo_short}-{ts}")

    errors = config.validate()
    if errors:
        for err in errors:
            print_error(err)
        sys.exit(1)

    # Launch under tmux if enabled (CLI flag or config) and not already inside
    use_tmux = tmux or config.tmux
    if use_tmux and not os.environ.get(_TMUX_ENV_FLAG):
        _exec_in_tmux(sys.argv)
        return  # unreachable if exec succeeds

    if not config.skip_ai:
        if config.anthropic_api_key:
            click.secho("Auth: using ANTHROPIC_API_KEY", fg="blue")
        elif config.oauth_token:
            click.secho("Auth: using OAuth token from macOS Keychain", fg="blue")

    try:
        _run_scan(config)
    except KeyboardInterrupt:
        click.echo("\nScan interrupted.")
        sys.exit(130)
    except Exception as e:
        print_error(str(e))
        sys.exit(1)


# ---------------------------------------------------------------------------
# thresher build
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--cpus", type=int, default=None, help="VM CPU count (default: 4)")
@click.option("--memory", type=int, default=None, help="VM memory in GB (default: 8)")
@click.option("--disk", type=int, default=None, help="VM disk in GB (default: 50)")
@click.option("--verbose", is_flag=True, help="Show detailed output")
@click.option("--tmux", is_flag=True, help="Enable tmux split-pane UI")
def build(
    cpus: int | None,
    memory: int | None,
    disk: int | None,
    verbose: bool,
    tmux: bool,
) -> None:
    """Build (or rebuild) the cached base VM image."""
    config = load_config(
        repo_url="",  # not scanning, just building
        skip_ai=True,
        verbose=verbose,
        cpus=cpus,
        memory=memory,
        disk=disk,
    )

    _setup_logging(verbose, config.log_dir)

    # Launch under tmux if enabled (CLI flag or config)
    use_tmux = tmux or config.tmux
    if use_tmux and not os.environ.get(_TMUX_ENV_FLAG):
        _exec_in_tmux(sys.argv)
        return

    from thresher.vm.lima import (
        BASE_VM_NAME,
        _PROJECT_ROOT,
        _TEMPLATE_PATH,
        _run_limactl,
        base_exists,
        destroy_vm,
        provision_vm,
        start_vm,
        stop_vm,
    )

    try:
        print_splash("v0.2.0", "thresher.sh")

        if base_exists():
            with FinSpinner("Removing existing base VM"):
                destroy_vm(BASE_VM_NAME)

        with FinSpinner("Creating base VM"):
            # Inline the create logic so we can show granular progress
            if not _TEMPLATE_PATH.exists():
                raise RuntimeError("Lima template not found")
            create_cmd = [
                "limactl", "create",
                "--name", BASE_VM_NAME,
                f"--cpus={config.vm.cpus}",
                f"--memory={config.vm.memory}",
                f"--disk={config.vm.disk}",
                "--plain",
                str(_TEMPLATE_PATH),
            ]
            result = _run_limactl(create_cmd, timeout=300)
            if result.returncode != 0:
                raise RuntimeError(f"Failed to create VM: {result.stderr}")

        with FinSpinner("Starting VM (first boot may take a minute)"):
            start_vm(BASE_VM_NAME)

        # Provisioning gets its own progress bar (inside provision_vm)
        provision_vm(BASE_VM_NAME, config)

        with FinSpinner("Stopping base VM"):
            stop_vm(BASE_VM_NAME)

        print_stage_ok("Base VM image built successfully")

    except KeyboardInterrupt:
        click.echo("\nBuild interrupted.")
        # Destroy the incomplete VM so scan doesn't try to use it
        if base_exists():
            click.echo("Cleaning up incomplete VM...")
            destroy_vm(BASE_VM_NAME)
        sys.exit(130)
    except Exception as e:
        print_error(str(e))
        # Destroy the incomplete VM so scan doesn't try to use it
        if base_exists():
            click.echo("Cleaning up incomplete VM...")
            try:
                destroy_vm(BASE_VM_NAME)
            except Exception:
                pass  # best-effort cleanup
        sys.exit(1)


# ---------------------------------------------------------------------------
# thresher stop
# ---------------------------------------------------------------------------

@cli.command()
def stop() -> None:
    """Stop all thresher VMs and tmux session."""
    _stop_all()


# ---------------------------------------------------------------------------
# thresher list
# ---------------------------------------------------------------------------

@cli.command(name="list")
def list_images() -> None:
    """List available pre-built VM images from GitHub releases."""
    import json
    import urllib.request
    import urllib.error

    from thresher.branding import VIOLET, ARCTIC, GRAY, GREEN, RESET, BOLD, DIM

    GITHUB_REPO = "thresher-sh/thresher"
    ASSET_NAME = "thresher-base.qcow2"
    API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases"

    print(f"\n  {BOLD}{ARCTIC}Available Thresher VM Images{RESET}\n")

    try:
        req = urllib.request.Request(
            API_URL,
            headers={"User-Agent": "thresher/0.2.0", "Accept": "application/vnd.github+json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            releases = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        print_error(f"GitHub API error: {e.code} {e.reason}")
        sys.exit(1)
    except (urllib.error.URLError, TimeoutError) as e:
        print_error(f"Cannot reach GitHub: {e}")
        sys.exit(1)

    if not releases:
        click.echo(f"  {GRAY}No releases found.{RESET}")
        click.echo(f"  Build locally with: thresher build")
        return

    found = 0
    for release in releases:
        tag = release.get("tag_name", "")
        name = release.get("name", tag)
        published = release.get("published_at", "")[:10]
        prerelease = release.get("prerelease", False)
        is_latest = release == releases[0]

        # Check if this release has a VM image asset
        assets = release.get("assets", [])
        image_asset = next((a for a in assets if a.get("name") == ASSET_NAME), None)

        if image_asset:
            size_mb = image_asset.get("size", 0) / (1024 * 1024)
            downloads = image_asset.get("download_count", 0)
            tag_display = f"{VIOLET}{tag}{RESET}"
            if is_latest:
                tag_display += f"  {GREEN}(latest){RESET}"
            if prerelease:
                tag_display += f"  {DIM}(pre-release){RESET}"

            print(f"  {tag_display}")
            print(f"    {GRAY}{name} | {published} | {size_mb:.0f} MB | {downloads} downloads{RESET}")
            print(f"    {DIM}thresher import {tag}{RESET}")
            print()
            found += 1
        else:
            # Release exists but no image attached
            tag_display = f"{DIM}{tag}{RESET}"
            print(f"  {tag_display}")
            print(f"    {GRAY}{name} | {published} | no VM image{RESET}")
            print()

    if found == 0:
        click.echo(f"  {GRAY}No releases have VM images attached.{RESET}")
        click.echo(f"  Build locally with: thresher build")
    else:
        print(f"  {GRAY}Import with: thresher import latest{RESET}")
        print(f"  {GRAY}Or specific: thresher import <tag>{RESET}")
        print()


# ---------------------------------------------------------------------------
# thresher export
# ---------------------------------------------------------------------------

@cli.command(name="export")
@click.option("--output", "output_path", default=None,
              help="Output path for the disk image (default: ./thresher-base.qcow2)")
def export_image(output_path: str | None) -> None:
    """Export the base VM disk image for distribution.

    Creates a compressed qcow2 image that others can import with
    `thresher import` instead of building from scratch.
    """
    from thresher.vm.lima import BASE_VM_NAME, base_exists, vm_status

    if not base_exists():
        print_error("No base VM found. Run `thresher build` first.")
        sys.exit(1)

    status = vm_status(BASE_VM_NAME)
    if status == "Running":
        print_error("Base VM is running. Run `thresher stop` first.")
        sys.exit(1)

    disk_path = Path.home() / ".lima" / BASE_VM_NAME / "disk"
    if not disk_path.exists():
        # Try basedisk
        disk_path = Path.home() / ".lima" / BASE_VM_NAME / "basedisk"
    if not disk_path.exists():
        print_error(f"Cannot find VM disk at {disk_path}")
        sys.exit(1)

    dest = Path(output_path) if output_path else Path("thresher-base.qcow2")

    with FinSpinner(f"Exporting base image to {dest}"):
        result = subprocess.run(
            ["qemu-img", "convert", "-f", "raw", "-O", "qcow2", "-c",
             str(disk_path), str(dest)],
            capture_output=True, text=True, timeout=600,
        )
        if result.returncode != 0:
            raise RuntimeError(f"qemu-img failed: {result.stderr}")

    size_mb = dest.stat().st_size / (1024 * 1024)
    print_stage_ok(f"Exported to {dest} ({size_mb:.0f} MB)")
    click.echo(f"\n  Share this file. Others can import with:")
    click.echo(f"    thresher import {dest}")


# ---------------------------------------------------------------------------
# thresher import
# ---------------------------------------------------------------------------

@cli.command(name="import")
@click.argument("image_source")
@click.option("--cpus", type=int, default=None)
@click.option("--memory", type=int, default=None)
@click.option("--disk", type=int, default=None)
def import_image(image_source: str, cpus: int | None, memory: int | None, disk: int | None) -> None:
    """Import a pre-built base VM image (skips the build step).

    IMAGE_SOURCE can be:
      - A local file path: thresher-base.qcow2
      - A URL: https://github.com/thresher-sh/thresher/releases/download/v0.2.0/thresher-base.qcow2
      - A GitHub release shorthand: latest (downloads from latest release)
      - A GitHub release tag: v0.2.0
    """
    import urllib.request
    import urllib.error
    import tempfile

    from thresher.vm.lima import (
        BASE_VM_NAME, _TEMPLATE_PATH, _run_limactl,
        base_exists, destroy_vm,
    )

    config = load_config(repo_url="", skip_ai=True, cpus=cpus, memory=memory, disk=disk)

    GITHUB_REPO = "thresher-sh/thresher"
    ASSET_NAME = "thresher-base.qcow2"

    # Resolve the image source
    if image_source.startswith("http://") or image_source.startswith("https://"):
        download_url = image_source
    elif image_source == "latest":
        download_url = (
            f"https://github.com/{GITHUB_REPO}/releases/latest/download/{ASSET_NAME}"
        )
    elif image_source.startswith("v"):
        download_url = (
            f"https://github.com/{GITHUB_REPO}/releases/download/{image_source}/{ASSET_NAME}"
        )
    elif Path(image_source).exists():
        download_url = None  # local file
    else:
        print_error(
            f"Cannot resolve '{image_source}'. Use a file path, URL, 'latest', or a version tag (v0.2.0)."
        )
        sys.exit(1)

    try:
        # Download if needed
        if download_url:
            print_splash("v0.2.0", "thresher.sh")
            local_image = Path(tempfile.mkdtemp()) / ASSET_NAME

            def _download() -> None:
                req = urllib.request.Request(
                    download_url,
                    headers={"User-Agent": "thresher/0.2.0"},
                )
                try:
                    with urllib.request.urlopen(req, timeout=600) as resp:
                        total = int(resp.headers.get("Content-Length", 0))
                        downloaded = 0
                        with open(local_image, "wb") as f:
                            while True:
                                chunk = resp.read(1024 * 1024)  # 1MB chunks
                                if not chunk:
                                    break
                                f.write(chunk)
                                downloaded += len(chunk)
                except urllib.error.HTTPError as e:
                    if e.code == 404:
                        raise RuntimeError(
                            f"Image not found at {download_url}. "
                            f"Check the release exists."
                        ) from e
                    raise RuntimeError(f"Download failed: {e}") from e

            with FinSpinner(f"Downloading image from {download_url}"):
                _download()

            size_mb = local_image.stat().st_size / (1024 * 1024)
            print_stage_ok(f"Downloaded ({size_mb:.0f} MB)")
        else:
            print_splash("v0.2.0", "thresher.sh")
            local_image = Path(image_source)

        if base_exists():
            with FinSpinner("Removing existing base VM"):
                destroy_vm(BASE_VM_NAME)

        with FinSpinner("Creating VM from template"):
            result = _run_limactl([
                "limactl", "create",
                "--name", BASE_VM_NAME,
                f"--cpus={config.vm.cpus}",
                f"--memory={config.vm.memory}",
                f"--disk={config.vm.disk}",
                "--plain",
                str(_TEMPLATE_PATH),
            ], timeout=300)
            if result.returncode != 0:
                raise RuntimeError(f"Failed to create VM: {result.stderr}")

        disk_path = Path.home() / ".lima" / BASE_VM_NAME / "disk"

        with FinSpinner("Importing disk image"):
            result = subprocess.run(
                ["qemu-img", "convert", "-f", "qcow2", "-O", "raw",
                 str(local_image), str(disk_path)],
                capture_output=True, text=True, timeout=600,
            )
            if result.returncode != 0:
                raise RuntimeError(f"qemu-img failed: {result.stderr}")

        print_stage_ok("Base VM imported successfully")
        click.echo("\n  Run `thresher scan <url>` to start scanning.")

        # Clean up downloaded temp file
        if download_url and local_image.exists():
            local_image.unlink()

    except KeyboardInterrupt:
        click.echo("\nImport interrupted.")
        sys.exit(130)
    except Exception as e:
        print_error(str(e))
        sys.exit(1)


# ---------------------------------------------------------------------------
# Legacy entry points (for backward compat with thresher-build, thresher-stop)
# ---------------------------------------------------------------------------

def main() -> None:
    """Main entry point — invokes the CLI group."""
    cli()


def build_entry() -> None:
    """Legacy entry point for thresher-build."""
    cli(["build"] + sys.argv[1:], standalone_mode=True)


def stop_entry() -> None:
    """Legacy entry point for thresher-stop."""
    cli(["stop"], standalone_mode=True)


# ---------------------------------------------------------------------------
# Tmux helper
# ---------------------------------------------------------------------------

def _exec_in_tmux(argv: list[str]) -> None:
    """Re-exec the current command inside a tmux split-pane layout."""
    if not shutil.which("tmux"):
        click.secho("tmux not found — running without split-pane UI.", fg="yellow")
        click.secho("Install with: brew install tmux", fg="yellow")
        os.environ[_TMUX_ENV_FLAG] = "1"
        return

    log_dir = LOG_DIR
    log_file = log_dir / "scan.log"
    log_dir.mkdir(parents=True, exist_ok=True)
    if log_file.is_symlink():
        target = log_file.resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            target.write_text("")
    elif not log_file.exists():
        log_file.write_text("")

    subprocess.run(
        ["tmux", "kill-session", "-t", _TMUX_SESSION],
        capture_output=True,
    )

    inner_cmd = " ".join(shlex.quote(a) for a in argv)
    scan_cmd = (
        f"export {_TMUX_ENV_FLAG}=1; "
        f"{inner_cmd}; "
        f"echo ''; echo 'Scan finished. Press Ctrl-b + q to exit.'; read -r"
    )

    subprocess.run(
        ["tmux", "new-session", "-d", "-s", _TMUX_SESSION, "bash", "-c", scan_cmd],
        check=True,
    )
    subprocess.run(
        ["tmux", "split-window", "-h", "-t", _TMUX_SESSION, "-p", "40",
         "tail", "-F", str(LOG_FILE)],
        check=True,
    )
    for pane, title in [("0.0", "Scan"), ("0.1", "Logs")]:
        subprocess.run(
            ["tmux", "select-pane", "-t", f"{_TMUX_SESSION}:{pane}", "-T", title],
            check=True,
        )
    subprocess.run(
        ["tmux", "set-option", "-t", _TMUX_SESSION, "pane-border-status", "top"],
        check=True,
    )
    subprocess.run(
        ["tmux", "set-option", "-t", _TMUX_SESSION, "pane-border-format",
         " #{pane_title} "],
        check=True,
    )
    subprocess.run(
        ["tmux", "set-option", "-t", _TMUX_SESSION, "mouse", "on"],
        check=True,
    )
    subprocess.run(["tmux", "bind-key", "-T", "prefix", "h", "select-pane", "-L"])
    subprocess.run(["tmux", "bind-key", "-T", "prefix", "l", "select-pane", "-R"])
    subprocess.run(
        ["tmux", "bind-key", "-T", "prefix", "q",
         "kill-session", "-t", _TMUX_SESSION],
    )
    subprocess.run(
        ["tmux", "select-pane", "-t", f"{_TMUX_SESSION}:0.0"],
        check=True,
    )
    subprocess.run(["tmux", "attach-session", "-t", _TMUX_SESSION])
    _stop_all()


# ---------------------------------------------------------------------------
# Scan pipeline
# ---------------------------------------------------------------------------

def _run_scan(config: ScanConfig) -> None:
    """Execute the full scan pipeline."""
    from thresher.vm.lima import (
        BASE_VM_NAME,
        base_exists,
        clean_working_dirs,
        create_vm,
        destroy_vm,
        ensure_base_running,
        provision_vm,
        stop_vm,
    )

    scan_id = _SCAN_TIMESTAMP

    print_splash("v0.2.0", "thresher.sh")
    print_scan_header(config.repo_url)

    using_base = base_exists()

    vm_name = None
    try:
        if using_base:
            with FinSpinner("Starting cached base VM"):
                vm_name = ensure_base_running()
            # Verify the base VM was fully provisioned before using it
            from thresher.vm.ssh import ssh_exec as _ssh_exec
            _, _, rc = _ssh_exec(vm_name, "test -x /usr/local/bin/scanner-docker")
            if rc != 0:
                raise RuntimeError(
                    "Base VM is incomplete (scanner-docker not found). "
                    "Run `thresher build` to rebuild it."
                )
            with FinSpinner("Cleaning working directories"):
                clean_working_dirs(vm_name)
        else:
            with FinSpinner("Creating isolated VM"):
                vm_name = create_vm(config)
            with FinSpinner("Provisioning VM (installing scanners)"):
                provision_vm(vm_name, config)

        from thresher.vm.ssh import ssh_exec
        from thresher.docker.sandbox import download_dependencies

        with FinSpinner("Cloning repository (hardened)"):
            safe_url = shlex.quote(config.repo_url)
            stdout, stderr, rc = ssh_exec(
                vm_name,
                f"bash /opt/thresher/bin/safe_clone.sh {safe_url} /opt/target",
                timeout=300,
            )
            if rc != 0:
                raise RuntimeError(f"git clone failed (exit {rc}): {stderr}")

        if not config.skip_ai:
            from thresher.agents.predep import run_predep_discovery
            with FinSpinner("Discovering hidden dependencies"):
                run_predep_discovery(vm_name, config)

        with FinSpinner("Resolving dependencies"):
            download_dependencies(vm_name, config)

        from thresher.scanners.runner import run_all_scanners

        with FinSpinner("Vulnerability scanners (22 tools)"):
            scanner_status = run_all_scanners(vm_name, config)

        if not config.skip_ai:
            from thresher.agents.analysts import run_all_analysts, ANALYST_DEFINITIONS
            from thresher.agents.adversarial import run_adversarial_verification

            print_stage_ok("AI analyst panel")
            print()

            with FinSpinner("Running 8 analyst agents"):
                run_all_analysts(vm_name, config)

            for analyst_def in ANALYST_DEFINITIONS:
                num = analyst_def["number"]
                name = analyst_def["name"]
                display = ANALYST_DISPLAY_NAMES.get(name, name)
                print_analyst_status(num, display, "done")

            print()
            with FinSpinner("Adversarial verification"):
                run_adversarial_verification(vm_name, config)

        from thresher.report.synthesize import generate_report

        with FinSpinner("Report synthesis"):
            report_path = generate_report(vm_name, config)

        from thresher.vm.safe_io import ssh_copy_from_safe, validate_report_structure

        output = Path(config.output_dir) / scan_id
        output.mkdir(parents=True, exist_ok=True)
        ssh_copy_from_safe(vm_name, report_path, str(output))
        validate_report_structure(output)

        print_stage_ok("Report synthesis")

        print()
        print_swim_divider()
        print_report_path(str(output))
        print_swim_divider()

    finally:
        if vm_name:
            if using_base:
                click.echo("Stopping base VM...")
                stop_vm(vm_name)
            else:
                click.echo("Destroying VM...")
                destroy_vm(vm_name)


# ---------------------------------------------------------------------------
# Stop helper
# ---------------------------------------------------------------------------

def _stop_all() -> None:
    """Kill all thresher VMs and the tmux session."""
    import subprocess as sp

    from thresher.vm.lima import BASE_VM_NAME

    sp.run(["tmux", "kill-session", "-t", _TMUX_SESSION], capture_output=True)

    result = sp.run(
        ["limactl", "list", "--format", "{{.Name}}"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        click.echo("No Lima VMs found.")
        return

    vms = [name for name in result.stdout.strip().splitlines() if name.startswith("thresher-")]
    if not vms:
        click.echo("No thresher VMs running.")
        return

    count = 0
    for vm in vms:
        if vm == BASE_VM_NAME:
            click.echo(f"Stopping {vm} (preserving base image)...")
            sp.run(["limactl", "stop", vm], capture_output=True, timeout=120)
        else:
            click.echo(f"Destroying {vm}...")
            sp.run(["limactl", "delete", "-f", vm], capture_output=True)
        count += 1

    click.secho(f"Stopped {count} VM(s).", fg="green")


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

_SCAN_TIMESTAMP: str = ""


def _setup_logging(verbose: bool, log_dir: str = "", scan_id: str = "") -> None:
    """Configure logging to file (always) and stderr (if verbose)."""
    global LOG_DIR, LOG_FILE, _SCAN_TIMESTAMP
    import datetime

    if log_dir:
        LOG_DIR = Path(log_dir)

    _SCAN_TIMESTAMP = scan_id or datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    run_dir = LOG_DIR / _SCAN_TIMESTAMP
    run_dir.mkdir(parents=True, exist_ok=True)

    run_log = run_dir / "scan.log"
    run_log.write_text("")

    LOG_FILE = LOG_DIR / "scan.log"
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    LOG_FILE.unlink(missing_ok=True)
    relative_target = run_log.relative_to(LOG_DIR)
    LOG_FILE.symlink_to(relative_target)

    root = logging.getLogger("thresher")
    root.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    fh = logging.FileHandler(run_log)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    root.addHandler(fh)

    if verbose:
        sh = logging.StreamHandler(sys.stderr)
        sh.setLevel(logging.DEBUG)
        sh.setFormatter(fmt)
        root.addHandler(sh)


if __name__ == "__main__":
    cli()
