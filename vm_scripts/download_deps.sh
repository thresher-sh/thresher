#!/bin/bash
# download_deps.sh — Source-only dependency downloader
# Detects ecosystems in the target project and downloads dependencies
# as source archives (no binary wheels, no executed install scripts).
set -euo pipefail

LOG_PREFIX="[download_deps]"

log() {
    echo "${LOG_PREFIX} $(date '+%H:%M:%S') $*"
}

# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------
TARGET_DIR="${1:?Usage: download_deps.sh <TARGET_DIR> [DEPTH]}"
DEPTH="${2:-2}"

DEPS_BASE="/opt/deps"
MANIFEST="${DEPS_BASE}/dep_manifest.json"

log "Target directory: ${TARGET_DIR}"
log "Transitive dependency depth: ${DEPTH}"

if [ ! -d "$TARGET_DIR" ]; then
    echo "ERROR: Target directory does not exist: ${TARGET_DIR}" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Initialize manifest
# ---------------------------------------------------------------------------
mkdir -p "$DEPS_BASE"

# Start building the manifest as a JSON structure
# We accumulate entries and write the file at the end
declare -a MANIFEST_ENTRIES=()

add_manifest_entry() {
    local name="$1"
    local version="$2"
    local ecosystem="$3"
    local depth_level="$4"
    local path="$5"
    MANIFEST_ENTRIES+=("{\"name\":\"${name}\",\"version\":\"${version}\",\"ecosystem\":\"${ecosystem}\",\"depth\":${depth_level},\"path\":\"${path}\"}")
}

# ---------------------------------------------------------------------------
# Ecosystem detection
# ---------------------------------------------------------------------------
DETECTED_ECOSYSTEMS=()

# Python
if [ -f "${TARGET_DIR}/requirements.txt" ] || \
   [ -f "${TARGET_DIR}/setup.py" ] || \
   [ -f "${TARGET_DIR}/pyproject.toml" ] || \
   [ -f "${TARGET_DIR}/Pipfile" ]; then
    DETECTED_ECOSYSTEMS+=("python")
    log "Detected ecosystem: Python"
fi

# Node.js
if [ -f "${TARGET_DIR}/package.json" ]; then
    DETECTED_ECOSYSTEMS+=("node")
    log "Detected ecosystem: Node.js"
fi

# Rust
if [ -f "${TARGET_DIR}/Cargo.toml" ]; then
    DETECTED_ECOSYSTEMS+=("rust")
    log "Detected ecosystem: Rust"
fi

# Go
if [ -f "${TARGET_DIR}/go.mod" ]; then
    DETECTED_ECOSYSTEMS+=("go")
    log "Detected ecosystem: Go"
fi

if [ ${#DETECTED_ECOSYSTEMS[@]} -eq 0 ]; then
    log "No supported ecosystems detected. Nothing to download."
    echo '{"ecosystems":[],"dependencies":[],"depth":'"${DEPTH}"'}' > "$MANIFEST"
    exit 0
fi

log "Detected ecosystems: ${DETECTED_ECOSYSTEMS[*]}"

# ---------------------------------------------------------------------------
# Python dependency download (source-only, no binaries)
# ---------------------------------------------------------------------------
download_python_deps() {
    local deps_dir="${DEPS_BASE}/python"
    mkdir -p "$deps_dir"
    log "Downloading Python dependencies (source-only)..."

    # Determine the requirements source
    local req_args=()
    if [ -f "${TARGET_DIR}/requirements.txt" ]; then
        req_args+=("-r" "${TARGET_DIR}/requirements.txt")
        log "  Using requirements.txt"
    elif [ -f "${TARGET_DIR}/pyproject.toml" ]; then
        # pip can install from pyproject.toml directly
        req_args+=("${TARGET_DIR}")
        log "  Using pyproject.toml"
    elif [ -f "${TARGET_DIR}/setup.py" ]; then
        req_args+=("${TARGET_DIR}")
        log "  Using setup.py"
    elif [ -f "${TARGET_DIR}/Pipfile" ]; then
        # Convert Pipfile to requirements format using a simple grep
        # (full Pipfile parsing would require pipenv, this handles the common case)
        log "  Pipfile detected. Extracting packages..."
        local tmp_req="${deps_dir}/_requirements_from_pipfile.txt"
        # Extract package names from [packages] section
        awk '/^\[packages\]/{flag=1; next} /^\[/{flag=0} flag && /=/' \
            "${TARGET_DIR}/Pipfile" | \
            sed 's/ *= *".*"//' > "$tmp_req"
        if [ -s "$tmp_req" ]; then
            req_args+=("-r" "$tmp_req")
        else
            log "  WARNING: Could not parse Pipfile. Skipping Python deps."
            return
        fi
    fi

    if [ ${#req_args[@]} -eq 0 ]; then
        log "  No Python dependency source found. Skipping."
        return
    fi

    # Download source-only, no binary wheels, respecting depth
    # --no-deps prevents pip from pulling transitive deps (we control depth manually)
    # For depth=1, just direct deps. For depth>1, allow pip to resolve transitively.
    if [ "$DEPTH" -le 1 ]; then
        pip3 download --no-binary :all: --no-deps -d "$deps_dir" "${req_args[@]}" 2>&1 || {
            log "  WARNING: Some Python packages failed to download (source-only may not be available for all)."
        }
    else
        # Allow transitive deps but source-only
        pip3 download --no-binary :all: -d "$deps_dir" "${req_args[@]}" 2>&1 || {
            log "  WARNING: Some Python packages failed to download (source-only may not be available for all)."
        }
    fi

    # Record downloaded packages in manifest
    for archive in "$deps_dir"/*.tar.gz "$deps_dir"/*.zip; do
        [ -f "$archive" ] || continue
        local filename
        filename=$(basename "$archive")
        # Extract name and version from filename (format: name-version.tar.gz)
        local pkg_name pkg_version
        pkg_name=$(echo "$filename" | sed -E 's/^(.+)-([0-9][^-]*)\.(tar\.gz|zip)$/\1/')
        pkg_version=$(echo "$filename" | sed -E 's/^(.+)-([0-9][^-]*)\.(tar\.gz|zip)$/\2/')
        add_manifest_entry "$pkg_name" "$pkg_version" "python" 1 "$archive"
    done

    log "Python dependency download complete. Files in: ${deps_dir}"
}

# ---------------------------------------------------------------------------
# Node.js dependency download (npm pack for each dep)
# ---------------------------------------------------------------------------
download_node_deps() {
    local deps_dir="${DEPS_BASE}/node"
    mkdir -p "$deps_dir"
    log "Downloading Node.js dependencies (source tarballs via npm pack)..."

    local package_json="${TARGET_DIR}/package.json"

    if [ ! -f "$package_json" ]; then
        log "  No package.json found. Skipping."
        return
    fi

    # Extract dependency names and versions from package.json
    # Handles both "dependencies" and "devDependencies"
    local deps
    deps=$(python3 -c "
import json, sys
with open('${package_json}') as f:
    pkg = json.load(f)
deps = {}
deps.update(pkg.get('dependencies', {}))
# Include devDependencies for security scanning
deps.update(pkg.get('devDependencies', {}))
for name, version in deps.items():
    print(f'{name}@{version}')
" 2>/dev/null) || {
        log "  WARNING: Failed to parse package.json."
        return
    }

    if [ -z "$deps" ]; then
        log "  No dependencies found in package.json."
        return
    fi

    # Download each dependency as a tarball using npm pack
    while IFS= read -r dep_spec; do
        [ -z "$dep_spec" ] && continue
        local dep_name
        dep_name=$(echo "$dep_spec" | sed 's/@[^@]*$//')
        log "  Packing: ${dep_spec}"
        (cd "$deps_dir" && npm pack "$dep_spec" 2>/dev/null) || {
            log "  WARNING: Failed to pack ${dep_spec}. Skipping."
            continue
        }
    done <<< "$deps"

    # Extract tarballs to inspectable directories
    for tarball in "$deps_dir"/*.tgz; do
        [ -f "$tarball" ] || continue
        local tarball_name
        tarball_name=$(basename "$tarball" .tgz)
        local extract_dir="${deps_dir}/${tarball_name}"
        mkdir -p "$extract_dir"
        tar xzf "$tarball" -C "$extract_dir" 2>/dev/null || {
            log "  WARNING: Failed to extract ${tarball}."
        }

        # Record in manifest
        local pkg_name pkg_version
        pkg_name=$(echo "$tarball_name" | sed -E 's/^(.+)-([0-9].*)$/\1/')
        pkg_version=$(echo "$tarball_name" | sed -E 's/^(.+)-([0-9].*)$/\2/')
        add_manifest_entry "$pkg_name" "$pkg_version" "node" 1 "$extract_dir"
    done

    log "Node.js dependency download complete. Files in: ${deps_dir}"
}

# ---------------------------------------------------------------------------
# Rust dependency download (cargo vendor)
# ---------------------------------------------------------------------------
download_rust_deps() {
    local deps_dir="${DEPS_BASE}/rust"
    mkdir -p "$deps_dir"
    log "Downloading Rust dependencies (cargo vendor)..."

    if [ ! -f "${TARGET_DIR}/Cargo.toml" ]; then
        log "  No Cargo.toml found. Skipping."
        return
    fi

    # Ensure cargo is on PATH
    if [ -f "$HOME/.cargo/env" ]; then
        # shellcheck source=/dev/null
        source "$HOME/.cargo/env"
    fi

    # cargo vendor downloads all dependencies as source
    (cd "$TARGET_DIR" && cargo vendor "$deps_dir" 2>&1) || {
        log "  WARNING: cargo vendor failed. Some Rust deps may be missing."
    }

    # Record vendored crates in manifest
    for crate_dir in "$deps_dir"/*/; do
        [ -d "$crate_dir" ] || continue
        local crate_name
        crate_name=$(basename "$crate_dir")

        # Try to extract version from Cargo.toml inside the vendored crate
        local crate_version="unknown"
        if [ -f "${crate_dir}/Cargo.toml" ]; then
            crate_version=$(python3 -c "
import re
with open('${crate_dir}/Cargo.toml') as f:
    content = f.read()
m = re.search(r'version\s*=\s*\"([^\"]+)\"', content)
if m:
    print(m.group(1))
else:
    print('unknown')
" 2>/dev/null) || crate_version="unknown"
        fi

        add_manifest_entry "$crate_name" "$crate_version" "rust" 1 "$crate_dir"
    done

    log "Rust dependency download complete. Files in: ${deps_dir}"
}

# ---------------------------------------------------------------------------
# Go dependency download (go mod vendor)
# ---------------------------------------------------------------------------
download_go_deps() {
    local deps_dir="${DEPS_BASE}/go"
    mkdir -p "$deps_dir"
    log "Downloading Go dependencies (go mod vendor)..."

    if [ ! -f "${TARGET_DIR}/go.mod" ]; then
        log "  No go.mod found. Skipping."
        return
    fi

    # go mod vendor places deps in the project's vendor/ directory
    # We copy them to our deps directory afterward
    (cd "$TARGET_DIR" && go mod vendor 2>&1) || {
        log "  WARNING: go mod vendor failed. Some Go deps may be missing."
    }

    # Move vendored deps to our standard location
    if [ -d "${TARGET_DIR}/vendor" ]; then
        cp -r "${TARGET_DIR}/vendor/." "$deps_dir/"

        # Record vendored modules in manifest
        # Parse modules.txt which go mod vendor creates
        if [ -f "${deps_dir}/modules.txt" ]; then
            while IFS= read -r line; do
                # Lines starting with "# " contain module info: # module version
                if [[ "$line" =~ ^#\ ([^\ ]+)\ v(.+)$ ]]; then
                    local mod_name="${BASH_REMATCH[1]}"
                    local mod_version="${BASH_REMATCH[2]}"
                    local mod_path="${deps_dir}/${mod_name}"
                    add_manifest_entry "$mod_name" "$mod_version" "go" 1 "$mod_path"
                fi
            done < "${deps_dir}/modules.txt"
        fi
    fi

    log "Go dependency download complete. Files in: ${deps_dir}"
}

# ---------------------------------------------------------------------------
# Run downloads for each detected ecosystem
# ---------------------------------------------------------------------------
for ecosystem in "${DETECTED_ECOSYSTEMS[@]}"; do
    case "$ecosystem" in
        python) download_python_deps ;;
        node)   download_node_deps ;;
        rust)   download_rust_deps ;;
        go)     download_go_deps ;;
        *)      log "WARNING: Unknown ecosystem: ${ecosystem}" ;;
    esac
done

# ---------------------------------------------------------------------------
# Write manifest
# ---------------------------------------------------------------------------
log "Writing dependency manifest to ${MANIFEST}..."

{
    echo '{'
    echo '  "ecosystems": ['
    # Write detected ecosystems as JSON array
    _first=true
    for eco in "${DETECTED_ECOSYSTEMS[@]}"; do
        if [ "$_first" = true ]; then
            echo "    \"${eco}\""
            _first=false
        else
            echo "    ,\"${eco}\""
        fi
    done
    echo '  ],'
    echo "  \"depth\": ${DEPTH},"
    echo '  "dependencies": ['
    # Write all manifest entries
    _efirst=true
    for entry in "${MANIFEST_ENTRIES[@]+"${MANIFEST_ENTRIES[@]}"}"; do
        if [ "$_efirst" = true ]; then
            echo "    ${entry}"
            _efirst=false
        else
            echo "    ,${entry}"
        fi
    done
    echo '  ]'
    echo '}'
} > "$MANIFEST"

log "Dependency manifest written with ${#MANIFEST_ENTRIES[@]} entries."
log "Download complete for ecosystems: ${DETECTED_ECOSYSTEMS[*]}"
