# Dependency Resolution Spec

Moves all dependency detection and download logic into a single Docker container, invoked by the locked-down `scanner-docker` wrapper. The VM and host Python code no longer make decisions about ecosystems, package managers, or download strategies — the container handles everything.

## Problem

The current system splits dependency resolution across three layers:

1. **`sandbox.py` (host-side Python)** — detects ecosystems via SSH, dispatches per-ecosystem Docker containers, parses results
2. **Per-ecosystem Docker containers** — `python:3.12-slim`, `node:20-slim`, `rust:slim`, `golang:1.22-slim` run individually with `sudo docker run`
3. **`download_deps.sh` (VM-side script)** — duplicates ecosystem detection and download logic in bash

This creates problems:
- Ecosystem logic is duplicated between Python and bash
- The scan user needs `sudo docker run` with arbitrary flags (images, mounts, network toggle)
- Each ecosystem spawns a separate container with separate `sudo docker` calls — more attack surface
- Adding a new ecosystem requires changes in `sandbox.py`, `download_deps.sh`, and potentially the VM provisioning

## Solution: Single Container, Single Invocation

Build one Docker image (`scanner-deps:latest`) during provisioning that contains all ecosystem tooling. At scan time, the locked-down wrapper (`/usr/local/bin/scanner-docker`) runs it exactly once with no arguments. The container's `/scripts/run.sh` handles everything.

### Container Image

**Built during provisioning** (as root, before lockdown):

```dockerfile
# Dockerfile.scanner-deps
FROM ubuntu:22.04

# All ecosystem tools in one image
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip \
    nodejs npm \
    cargo \
    golang-go \
    git \
    jq \
    && rm -rf /var/lib/apt/lists/*

COPY scripts/ /scripts/
RUN chmod +x /scripts/*.sh

ENTRYPOINT ["/scripts/run.sh"]
```

The image is built once during `threat-scan-build` and baked into the base VM. No registry pulls at scan time.

### `/scripts/run.sh` — The Entrypoint

This is where all the logic lives. The container receives the work directory as a volume mount at `/work`, which contains the cloned target repository.

```bash
#!/bin/bash
# /scripts/run.sh — Detect ecosystems, download deps, write manifest
set -euo pipefail

WORK_DIR="/work"
TARGET_DIR="${WORK_DIR}/target"
DEPS_DIR="${WORK_DIR}/deps"
MANIFEST="${DEPS_DIR}/dep_manifest.json"

mkdir -p "$DEPS_DIR"

# ── Ecosystem Detection ─────────────────────────────────────────────
source /scripts/detect.sh
detect_ecosystems "$TARGET_DIR"

if [ ${#DETECTED_ECOSYSTEMS[@]} -eq 0 ]; then
    echo '{"ecosystems":[],"dependencies":[]}' > "$MANIFEST"
    echo "No supported ecosystems detected."
    exit 0
fi

echo "Detected ecosystems: ${DETECTED_ECOSYSTEMS[*]}"

# ── Download Dependencies ───────────────────────────────────────────
for eco in "${DETECTED_ECOSYSTEMS[@]}"; do
    source "/scripts/download_${eco}.sh"
    "download_${eco}" "$TARGET_DIR" "$DEPS_DIR"
done

# ── Write Manifest ──────────────────────────────────────────────────
source /scripts/manifest.sh
write_manifest "$DEPS_DIR" "$MANIFEST"

echo "Dependency resolution complete."
```

### `/scripts/detect.sh` — Ecosystem Detection

Consolidates the detection logic currently split between `sandbox.py:detect_ecosystems()` and `download_deps.sh`:

```bash
#!/bin/bash
# /scripts/detect.sh — Detect ecosystems from indicator files
# Sets DETECTED_ECOSYSTEMS array

detect_ecosystems() {
    local target_dir="$1"
    DETECTED_ECOSYSTEMS=()

    # Python
    if [ -f "${target_dir}/requirements.txt" ] || \
       [ -f "${target_dir}/setup.py" ] || \
       [ -f "${target_dir}/pyproject.toml" ] || \
       [ -f "${target_dir}/Pipfile" ]; then
        DETECTED_ECOSYSTEMS+=("python")
    fi

    # Node.js
    if [ -f "${target_dir}/package.json" ]; then
        DETECTED_ECOSYSTEMS+=("node")
    fi

    # Rust
    if [ -f "${target_dir}/Cargo.toml" ]; then
        DETECTED_ECOSYSTEMS+=("rust")
    fi

    # Go
    if [ -f "${target_dir}/go.mod" ]; then
        DETECTED_ECOSYSTEMS+=("go")
    fi
}
```

### Per-Ecosystem Download Scripts

Each lives at `/scripts/download_<ecosystem>.sh` inside the container. The logic is essentially what's in the current `_download_python()`, `_download_node()`, etc. from `sandbox.py` and the corresponding functions in `download_deps.sh`, but consolidated into one place.

**Key difference from current**: These scripts run directly inside the container — no SSH, no `docker run` wrapping, no mount negotiation. They just call `pip download`, `npm pack`, `cargo vendor`, `go mod vendor` directly.

Example — `/scripts/download_python.sh`:

```bash
#!/bin/bash
download_python() {
    local target_dir="$1"
    local deps_dir="$2"
    local output_dir="${deps_dir}/python"
    mkdir -p "$output_dir"

    local req_args=()
    if [ -f "${target_dir}/requirements.txt" ]; then
        req_args+=("-r" "${target_dir}/requirements.txt")
    elif [ -f "${target_dir}/pyproject.toml" ] || [ -f "${target_dir}/setup.py" ]; then
        req_args+=("${target_dir}")
    elif [ -f "${target_dir}/Pipfile" ]; then
        # Simple Pipfile extraction
        local tmp_req="${output_dir}/_pipfile_reqs.txt"
        awk '/^\[packages\]/{flag=1; next} /^\[/{flag=0} flag && /=/' \
            "${target_dir}/Pipfile" | sed 's/ *= *".*"//' > "$tmp_req"
        [ -s "$tmp_req" ] && req_args+=("-r" "$tmp_req")
    fi

    [ ${#req_args[@]} -eq 0 ] && return

    pip3 download --no-binary :all: -d "$output_dir" "${req_args[@]}" 2>&1 || {
        echo "WARNING: Some Python packages failed to download"
    }
}
```

Same pattern for `download_node.sh`, `download_rust.sh`, `download_go.sh`.

### `/scripts/manifest.sh` — Manifest Writer

Writes the `dep_manifest.json` that downstream scanners and analysis consume:

```bash
#!/bin/bash
write_manifest() {
    local deps_dir="$1"
    local manifest="$2"

    # Use python3 (available in the image) for reliable JSON generation
    python3 /scripts/build_manifest.py "$deps_dir" > "$manifest"
}
```

With a small Python helper (`/scripts/build_manifest.py`) that walks the deps directory and produces clean JSON — avoids the fragile bash JSON construction in the current `download_deps.sh`.

## What Changes in `sandbox.py`

`sandbox.py` simplifies dramatically. It no longer:

- Detects ecosystems (container does it)
- Dispatches per-ecosystem Docker containers (single wrapper call)
- Constructs Docker commands with flags, mounts, network toggles
- Parses package filenames from SSH output

It becomes a thin caller:

```python
def download_dependencies(vm_name: str, config: ScanConfig) -> dict:
    """Invoke the scanner-docker wrapper and read back the manifest."""
    from threat_scanner.vm.ssh import ssh_exec

    # Single invocation — the wrapper and container handle everything
    stdout, stderr, exit_code = ssh_exec(
        vm_name, "sudo /usr/local/bin/scanner-docker"
    )

    if exit_code != 0:
        raise RuntimeError(f"Dependency resolution failed: {stderr}")

    # Read the manifest the container wrote
    manifest_out, _, _ = ssh_exec(
        vm_name, "cat /home/scanner/work/deps/dep_manifest.json"
    )
    return json.loads(manifest_out)
```

## What Gets Removed

| Current File | Disposition |
|---|---|
| `vm_scripts/download_deps.sh` | **Removed** — logic moves into container scripts |
| `sandbox.py` ecosystem detection | **Removed** — container's `detect.sh` handles it |
| `sandbox.py` per-ecosystem `_download_*` functions | **Removed** — container's `download_*.sh` scripts |
| `sandbox.py` `_docker_run()` helper | **Removed** — no more arbitrary Docker invocations |
| `sandbox.py` `_find_package_dirs()` | **Moved** into container's detect script |
| `sandbox.py` `_parse_package_name()` | **Moved** into container's `build_manifest.py` |
| `sandbox.py` `_list_downloaded_packages()` | **Moved** into container's `build_manifest.py` |

## Container Security Properties

Since the wrapper in the network hardening spec forces these flags:

| Flag | Effect |
|------|--------|
| `--network=none` | No network access — deps must be pre-downloaded or... see open question |
| `--read-only` | Container filesystem is immutable |
| `--cap-drop=ALL` | No Linux capabilities |
| `--security-opt=no-new-privileges` | Cannot escalate privileges |
| `-v /home/scanner/work:/work` | Only the work directory is mounted |

The container can only read from `/work/target` (the cloned repo) and write to `/work/deps` (the output).

## Open Question: Network Access for Dependency Downloads

The network hardening spec sets `--network=none` on the container. But dependency downloads (pip, npm, cargo, go mod) need network access to reach package registries.

Options:

1. **Two-phase approach**: The wrapper runs the container twice — first with network (for downloads), then without (for any post-processing). This requires two hardcoded wrapper invocations.

2. **Download outside container, resolve inside**: Download raw archives via the VM's firewalled network (which already whitelists registries), then run the container with `--network=none` to detect, extract, and build the manifest. The container never touches the network.

3. **Allow network in the container**: Change the wrapper to use `--network=bridge` instead of `--network=none`. The VM's iptables still enforces the domain whitelist, so the container can only reach approved registries. The container's network access is bounded by the VM's egress rules.

**Recommendation**: Option 3 is simplest and the security posture is unchanged — the VM's iptables whitelist is the enforcement layer, not Docker's network mode. The `--network=none` flag in the wrapper would change to allow bridge networking for dep downloads.

## Files Modified/Created

| File | Change |
|------|--------|
| `docker/Dockerfile.scanner-deps` (new) | Multi-ecosystem container image |
| `docker/scripts/run.sh` (new) | Entrypoint — orchestrates detect/download/manifest |
| `docker/scripts/detect.sh` (new) | Ecosystem detection |
| `docker/scripts/download_python.sh` (new) | Python dep download |
| `docker/scripts/download_node.sh` (new) | Node.js dep download |
| `docker/scripts/download_rust.sh` (new) | Rust dep download |
| `docker/scripts/download_go.sh` (new) | Go dep download |
| `docker/scripts/manifest.sh` (new) | Manifest generation wrapper |
| `docker/scripts/build_manifest.py` (new) | JSON manifest builder |
| `src/threat_scanner/docker/sandbox.py` | Gut and simplify to single wrapper call |
| `vm_scripts/download_deps.sh` | Remove (logic moves into container) |
| `vm_scripts/scanner-docker` | Docker wrapper (from network hardening spec) |
| `vm_scripts/provision.sh` | Add `docker build` step for scanner-deps image |

## Implementation Order

1. Create `docker/` directory with Dockerfile and scripts
2. Port detection logic from `sandbox.py` and `download_deps.sh` into `detect.sh`
3. Port per-ecosystem download logic into `download_*.sh` scripts
4. Create `build_manifest.py` for clean JSON output
5. Update `provision.sh` to build the `scanner-deps:latest` image
6. Simplify `sandbox.py` to single wrapper invocation + manifest read
7. Remove `download_deps.sh`
8. Test end-to-end with each ecosystem
