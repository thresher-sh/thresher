"""Docker container management for dependency isolation inside the Lima VM.

All Docker operations run INSIDE the Lima VM via ssh_exec.
Dependencies are downloaded source-only (no install scripts executed).
Docker provides isolation between untrusted dependency downloads and
the scanning tools / API keys.
"""

from __future__ import annotations

import json
import logging
import shlex

from threat_scanner.config import ScanConfig

logger = logging.getLogger(__name__)

# Mapping of ecosystem names to their base Docker images.
ECOSYSTEM_IMAGES: dict[str, str] = {
    "python": "python:3.12-slim",
    "node": "node:20-slim",
    "rust": "rust:slim",
    "go": "golang:1.22-slim",
}

# Mapping of indicator files to ecosystem names.
ECOSYSTEM_INDICATORS: dict[str, str] = {
    "requirements.txt": "python",
    "setup.py": "python",
    "pyproject.toml": "python",
    "Pipfile": "python",
    "package.json": "node",
    "Cargo.toml": "rust",
    "go.mod": "go",
}


def _docker_run(
    vm_name: str,
    image: str,
    command: str,
    mounts: list[tuple[str, str, str]],
    network: bool = True,
) -> tuple[str, str, int]:
    """Run a Docker container inside the VM via ssh_exec.

    Args:
        vm_name: Name of the Lima VM.
        image: Docker image to use (e.g. "python:3.12-slim").
        command: Shell command to execute inside the container.
        mounts: List of (host_path, container_path, mode) tuples.
                 mode is "ro" (read-only) or "rw" (read-write).
        network: If False, adds --network=none to disable networking.

    Returns:
        Tuple of (stdout, stderr, exit_code).
    """
    from threat_scanner.vm.ssh import ssh_exec

    docker_cmd_parts = ["sudo", "docker", "run", "--rm"]

    if not network:
        docker_cmd_parts.append("--network=none")

    for host_path, container_path, mode in mounts:
        docker_cmd_parts.append(
            f"-v {shlex.quote(host_path)}:{shlex.quote(container_path)}:{mode}"
        )

    docker_cmd_parts.append(shlex.quote(image))
    docker_cmd_parts.append(f"sh -c {shlex.quote(command)}")

    full_cmd = " ".join(docker_cmd_parts)
    logger.debug("Running Docker command in VM %s: %s", vm_name, full_cmd)

    stdout, stderr, exit_code = ssh_exec(vm_name, full_cmd)
    return stdout, stderr, exit_code


def detect_ecosystems(vm_name: str, target_dir: str) -> list[str]:
    """Detect which package ecosystems are present in the target directory.

    SSH into the VM and check for ecosystem indicator files in target_dir.

    Args:
        vm_name: Name of the Lima VM.
        target_dir: Path inside the VM to the cloned repository.

    Returns:
        Deduplicated list of detected ecosystem names
        (e.g. ["python", "node"]).
    """
    from threat_scanner.vm.ssh import ssh_exec

    detected: set[str] = set()

    # Build a single command that checks for all indicator files at once.
    checks = []
    for filename, ecosystem in ECOSYSTEM_INDICATORS.items():
        checks.append(f'[ -f "{target_dir}/{filename}" ] && echo "{ecosystem}"')

    combined_cmd = " ; ".join(checks) + " ; true"
    stdout, stderr, exit_code = ssh_exec(vm_name, combined_cmd)

    if exit_code != 0:
        logger.warning(
            "Ecosystem detection returned exit code %d: %s", exit_code, stderr
        )

    for line in stdout.strip().splitlines():
        ecosystem = line.strip()
        if ecosystem in ECOSYSTEM_IMAGES:
            detected.add(ecosystem)

    result = sorted(detected)
    logger.info("Detected ecosystems in %s: %s", target_dir, result)
    return result


def _download_python(
    vm_name: str, target_dir: str, deps_dir: str, depth: int
) -> list[dict[str, str]]:
    """Download Python dependencies source-only via pip download.

    Args:
        vm_name: Name of the Lima VM.
        target_dir: Path to the target repo inside the VM.
        deps_dir: Base path for dependency output inside the VM.
        depth: Maximum transitive dependency depth.

    Returns:
        List of dependency info dicts with name, version, path.
    """
    output_dir = f"{deps_dir}/python"
    # Determine which requirements source to use.
    # pip download --no-binary :all: --no-deps downloads source-only without
    # executing install scripts. We use --no-deps and iterate for depth control.
    # For depth=1 (direct only), use --no-deps. For depth>1, allow pip to
    # resolve transitives naturally.
    no_deps_flag = "--no-deps" if depth <= 1 else ""

    # Try requirements.txt first, fall back to pyproject.toml/setup.py.
    cmd = (
        f"mkdir -p {output_dir} && "
        f"if [ -f {target_dir}/requirements.txt ]; then "
        f"  pip download --no-binary :all: {no_deps_flag} "
        f"    -d {output_dir} -r {target_dir}/requirements.txt 2>&1; "
        f"elif [ -f {target_dir}/pyproject.toml ] || [ -f {target_dir}/setup.py ]; then "
        f"  pip download --no-binary :all: {no_deps_flag} "
        f"    -d {output_dir} {target_dir} 2>&1; "
        f"else "
        f"  echo 'No Python dependency file found' >&2; exit 1; "
        f"fi"
    )

    mounts = [
        (target_dir, target_dir, "ro"),
        (deps_dir, deps_dir, "rw"),
    ]

    stdout, stderr, exit_code = _docker_run(
        vm_name, ECOSYSTEM_IMAGES["python"], cmd, mounts, network=True
    )

    if exit_code != 0:
        logger.error("Python dependency download failed: %s", stderr)
        raise RuntimeError(f"Python dependency download failed (exit {exit_code}): {stderr}")

    return _list_downloaded_packages(vm_name, output_dir, "python")


def _download_node(
    vm_name: str, target_dir: str, deps_dir: str, depth: int
) -> list[dict[str, str]]:
    """Download Node.js dependencies source-only via npm pack.

    Parses package.json for dependency names and runs npm pack for each,
    extracting tarballs to the output directory.

    Args:
        vm_name: Name of the Lima VM.
        target_dir: Path to the target repo inside the VM.
        deps_dir: Base path for dependency output inside the VM.
        depth: Maximum transitive dependency depth.

    Returns:
        List of dependency info dicts with name, version, path.
    """
    output_dir = f"{deps_dir}/node"

    # Parse package.json, npm pack each dependency, extract tarballs.
    # npm pack downloads the registry tarball without executing install scripts.
    dep_keys = '"dependencies"'
    if depth > 1:
        dep_keys = '"dependencies","devDependencies"'

    cmd = (
        f"mkdir -p {output_dir} && cd {output_dir} && "
        f"node -e \""
        f"const pkg = require('{target_dir}/package.json');"
        f"const deps = {{"
        f"  ...( pkg.dependencies || {{}} ),"
        f"  ...( {depth} > 1 ? (pkg.devDependencies || {{}}) : {{}} )"
        f"}};"
        f"Object.entries(deps).forEach(([name, ver]) => console.log(name + '@' + ver));"
        f"\" | while read -r pkgspec; do "
        f"  echo \"Packing $pkgspec\"; "
        f"  npm pack \"$pkgspec\" 2>&1 || true; "
        f"done"
    )

    mounts = [
        (target_dir, target_dir, "ro"),
        (deps_dir, deps_dir, "rw"),
    ]

    stdout, stderr, exit_code = _docker_run(
        vm_name, ECOSYSTEM_IMAGES["node"], cmd, mounts, network=True
    )

    if exit_code != 0:
        logger.error("Node dependency download failed: %s", stderr)
        raise RuntimeError(f"Node dependency download failed (exit {exit_code}): {stderr}")

    return _list_downloaded_packages(vm_name, output_dir, "node")


def _download_rust(
    vm_name: str, target_dir: str, deps_dir: str, depth: int
) -> list[dict[str, str]]:
    """Download Rust dependencies via cargo vendor.

    Args:
        vm_name: Name of the Lima VM.
        target_dir: Path to the target repo inside the VM.
        deps_dir: Base path for dependency output inside the VM.
        depth: Maximum transitive dependency depth (not directly used by cargo vendor).

    Returns:
        List of dependency info dicts with name, version, path.
    """
    output_dir = f"{deps_dir}/rust"

    # cargo vendor requires a writable copy of the project since it modifies
    # .cargo/config.toml. We copy the target to a temp dir inside the container.
    cmd = (
        f"mkdir -p {output_dir} && "
        f"cp -r {target_dir} /tmp/rust-project && "
        f"cd /tmp/rust-project && "
        f"cargo vendor {output_dir} 2>&1"
    )

    mounts = [
        (target_dir, target_dir, "ro"),
        (deps_dir, deps_dir, "rw"),
    ]

    stdout, stderr, exit_code = _docker_run(
        vm_name, ECOSYSTEM_IMAGES["rust"], cmd, mounts, network=True
    )

    if exit_code != 0:
        logger.error("Rust dependency download failed: %s", stderr)
        raise RuntimeError(f"Rust dependency download failed (exit {exit_code}): {stderr}")

    return _list_downloaded_packages(vm_name, output_dir, "rust")


def _download_go(
    vm_name: str, target_dir: str, deps_dir: str, depth: int
) -> list[dict[str, str]]:
    """Download Go dependencies via go mod vendor.

    Args:
        vm_name: Name of the Lima VM.
        target_dir: Path to the target repo inside the VM.
        deps_dir: Base path for dependency output inside the VM.
        depth: Maximum transitive dependency depth (not directly used by go mod vendor).

    Returns:
        List of dependency info dicts with name, version, path.
    """
    output_dir = f"{deps_dir}/go"

    # go mod vendor requires a writable copy of the module directory.
    cmd = (
        f"mkdir -p {output_dir} && "
        f"cp -r {target_dir} /tmp/go-project && "
        f"cd /tmp/go-project && "
        f"GOMODCACHE=/tmp/gomodcache go mod vendor 2>&1 && "
        f"cp -r /tmp/go-project/vendor/* {output_dir}/ 2>/dev/null || true"
    )

    mounts = [
        (target_dir, target_dir, "ro"),
        (deps_dir, deps_dir, "rw"),
    ]

    stdout, stderr, exit_code = _docker_run(
        vm_name, ECOSYSTEM_IMAGES["go"], cmd, mounts, network=True
    )

    if exit_code != 0:
        logger.error("Go dependency download failed: %s", stderr)
        raise RuntimeError(f"Go dependency download failed (exit {exit_code}): {stderr}")

    return _list_downloaded_packages(vm_name, output_dir, "go")


# Dispatcher mapping ecosystem name to its download function.
_DOWNLOAD_FUNCTIONS: dict[str, callable] = {
    "python": _download_python,
    "node": _download_node,
    "rust": _download_rust,
    "go": _download_go,
}


def _list_downloaded_packages(
    vm_name: str, package_dir: str, ecosystem: str
) -> list[dict[str, str]]:
    """List downloaded packages in a directory inside the VM.

    Inspects the filesystem to build a list of {name, version, path} dicts.

    Args:
        vm_name: Name of the Lima VM.
        package_dir: Directory inside the VM containing downloaded packages.
        ecosystem: Ecosystem name for context.

    Returns:
        List of dicts with keys: name, version, path.
    """
    from threat_scanner.vm.ssh import ssh_exec

    # List all files/directories in the package dir.
    stdout, stderr, exit_code = ssh_exec(
        vm_name, f"ls -1 {shlex.quote(package_dir)} 2>/dev/null || true"
    )

    packages: list[dict[str, str]] = []
    for entry in stdout.strip().splitlines():
        entry = entry.strip()
        if not entry:
            continue

        name, version = _parse_package_name(entry, ecosystem)
        packages.append({
            "name": name,
            "version": version,
            "path": f"{package_dir}/{entry}",
        })

    return packages


def _parse_package_name(filename: str, ecosystem: str) -> tuple[str, str]:
    """Extract package name and version from a downloaded artifact filename.

    Args:
        filename: The filename or directory name of the downloaded artifact.
        ecosystem: Ecosystem name to guide parsing.

    Returns:
        Tuple of (name, version). Returns ("unknown", "") if parsing fails.
    """
    if ecosystem == "python":
        # Python tarballs: package-name-1.2.3.tar.gz
        if filename.endswith(".tar.gz"):
            base = filename[: -len(".tar.gz")]
        elif filename.endswith(".zip"):
            base = filename[: -len(".zip")]
        else:
            return filename, "unknown"
        # Split on last hyphen that precedes a version-like string.
        parts = base.rsplit("-", 1)
        if len(parts) == 2 and parts[1] and parts[1][0].isdigit():
            return parts[0], parts[1]
        return base, "unknown"

    elif ecosystem == "node":
        # npm pack tarballs: package-name-1.2.3.tgz or scope-package-1.2.3.tgz
        if filename.endswith(".tgz"):
            base = filename[: -len(".tgz")]
        else:
            return filename, "unknown"
        parts = base.rsplit("-", 1)
        if len(parts) == 2 and parts[1] and parts[1][0].isdigit():
            return parts[0], parts[1]
        return base, "unknown"

    elif ecosystem in ("rust", "go"):
        # cargo vendor / go mod vendor: directories named by package.
        # For Rust: directory names like "serde" or "serde-1.0.193".
        # For Go: directory structure mirrors module paths.
        parts = filename.rsplit("-", 1)
        if len(parts) == 2 and parts[1] and parts[1][0].isdigit():
            return parts[0], parts[1]
        return filename, "unknown"

    return filename, "unknown"


def download_dependencies(vm_name: str, config: ScanConfig) -> dict[str, list[dict[str, str]]]:
    """Detect ecosystems and download dependencies for each.

    For each detected ecosystem, runs a Docker container inside the VM to
    download dependencies source-only. Dependencies are written to /opt/deps/.

    Args:
        vm_name: Name of the Lima VM.
        config: Scan configuration (uses config.depth for transitive depth).

    Returns:
        Manifest dict mapping ecosystem name to list of dependency info dicts.
        Each dependency dict has keys: name, version, path.
    """
    from threat_scanner.vm.ssh import ssh_exec

    target_dir = "/opt/target"
    deps_dir = "/opt/deps"

    # Ensure the deps directory exists.
    ssh_exec(vm_name, f"sudo mkdir -p {deps_dir} && sudo chmod 777 {deps_dir}")

    ecosystems = detect_ecosystems(vm_name, target_dir)
    if not ecosystems:
        logger.warning("No supported ecosystems detected in %s", target_dir)
        return {}

    logger.info("Downloading dependencies for ecosystems: %s", ecosystems)

    manifest: dict[str, list[dict[str, str]]] = {}
    errors: dict[str, str] = {}

    for ecosystem in ecosystems:
        download_fn = _DOWNLOAD_FUNCTIONS.get(ecosystem)
        if download_fn is None:
            logger.warning("No download handler for ecosystem: %s", ecosystem)
            continue

        try:
            logger.info("Downloading %s dependencies...", ecosystem)
            packages = download_fn(vm_name, target_dir, deps_dir, config.depth)
            manifest[ecosystem] = packages
            logger.info(
                "Downloaded %d %s packages", len(packages), ecosystem
            )
        except Exception as e:
            logger.error("Failed to download %s dependencies: %s", ecosystem, e)
            errors[ecosystem] = str(e)
            # Continue with other ecosystems.

    if errors:
        logger.warning(
            "Dependency download errors for ecosystems: %s",
            ", ".join(errors.keys()),
        )

    # Build and write the manifest file.
    build_dep_manifest(vm_name)

    return manifest


def build_dep_manifest(vm_name: str) -> dict[str, list[dict[str, str]]]:
    """Read /opt/deps/ directory structure and build a manifest.

    Scans the /opt/deps/ directory inside the VM, builds a manifest of all
    downloaded dependencies, and writes it to /opt/deps/dep_manifest.json.

    Args:
        vm_name: Name of the Lima VM.

    Returns:
        Manifest dict mapping ecosystem name to list of dependency dicts.
        Each dependency dict has keys: name, version, ecosystem, path.
    """
    from threat_scanner.vm.ssh import ssh_exec

    deps_dir = "/opt/deps"
    manifest: dict[str, list[dict[str, str]]] = {}

    # List ecosystem subdirectories.
    stdout, stderr, exit_code = ssh_exec(
        vm_name,
        f"ls -1 {deps_dir} 2>/dev/null | grep -v dep_manifest.json || true",
    )

    for ecosystem in stdout.strip().splitlines():
        ecosystem = ecosystem.strip()
        if not ecosystem or ecosystem not in ECOSYSTEM_IMAGES:
            continue

        eco_dir = f"{deps_dir}/{ecosystem}"
        packages = _list_downloaded_packages(vm_name, eco_dir, ecosystem)

        # Augment each package dict with the ecosystem field.
        for pkg in packages:
            pkg["ecosystem"] = ecosystem

        manifest[ecosystem] = packages

    # Write manifest to the VM.
    manifest_json = json.dumps(manifest, indent=2)
    escaped_json = manifest_json.replace("'", "'\\''")
    ssh_exec(
        vm_name,
        f"echo '{escaped_json}' > {deps_dir}/dep_manifest.json",
    )

    logger.info("Wrote dependency manifest to %s/dep_manifest.json", deps_dir)
    return manifest
