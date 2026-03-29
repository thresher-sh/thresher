#!/bin/bash
# run_scanners.sh — Deterministic scanner orchestrator
# Runs all security scanners against the target project and collects JSON output.
# Syft runs first (generates SBOM), then remaining scanners run in parallel.
set -euo pipefail

LOG_PREFIX="[scanners]"

log() {
    echo "${LOG_PREFIX} $(date '+%H:%M:%S') $*"
}

# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------
TARGET_DIR="${1:?Usage: run_scanners.sh <TARGET_DIR> <SCAN_OUTPUT_DIR>}"
SCAN_OUTPUT_DIR="${2:?Usage: run_scanners.sh <TARGET_DIR> <SCAN_OUTPUT_DIR>}"

log "Target directory: ${TARGET_DIR}"
log "Output directory: ${SCAN_OUTPUT_DIR}"

if [ ! -d "$TARGET_DIR" ]; then
    echo "ERROR: Target directory does not exist: ${TARGET_DIR}" >&2
    exit 1
fi

mkdir -p "$SCAN_OUTPUT_DIR"

# Ensure Go and Cargo tools are on PATH
export PATH="${PATH}:$(go env GOPATH 2>/dev/null)/bin:/usr/local/go/bin:${HOME}/.cargo/bin"

# ---------------------------------------------------------------------------
# Track results for summary
# ---------------------------------------------------------------------------
declare -A TOOL_STATUS=()

# ---------------------------------------------------------------------------
# Phase 1: Syft (SBOM generation) — must complete before Grype
# ---------------------------------------------------------------------------
SBOM_FILE="${SCAN_OUTPUT_DIR}/syft.json"

log "Phase 1: Running Syft (SBOM generation)..."
if syft scan "dir:${TARGET_DIR}" -o json --file "$SBOM_FILE" 2>/dev/null; then
    TOOL_STATUS["syft"]="success"
    log "  Syft completed successfully. SBOM written to ${SBOM_FILE}"
else
    exit_code=$?
    # Syft may exit non-zero on warnings but still produce output
    if [ -f "$SBOM_FILE" ] && [ -s "$SBOM_FILE" ]; then
        TOOL_STATUS["syft"]="success (exit code ${exit_code}, output produced)"
        log "  Syft exited with code ${exit_code} but produced output."
    else
        TOOL_STATUS["syft"]="failed (exit code ${exit_code})"
        log "  WARNING: Syft failed (exit code ${exit_code}). Grype will scan directory instead."
    fi
fi

# ---------------------------------------------------------------------------
# Phase 2: Parallel scanners
# Each scanner runs in the background; we wait for all to finish.
# Non-zero exit codes from scanners are expected (they exit non-zero
# when findings are discovered — that is not an error).
# ---------------------------------------------------------------------------
log "Phase 2: Running parallel scanners..."

# Array to hold background PIDs and their tool names
declare -A PIDS=()

# --- Grype (vulnerability scanner using SBOM or directory) ---
run_grype() {
    local output_file="${SCAN_OUTPUT_DIR}/grype.json"
    log "  Starting Grype..."
    if [ -f "$SBOM_FILE" ] && [ -s "$SBOM_FILE" ]; then
        # Use SBOM for more accurate results
        grype "sbom:${SBOM_FILE}" -o json --file "$output_file" 2>/dev/null
    else
        # Fall back to directory scan
        grype "dir:${TARGET_DIR}" -o json --file "$output_file" 2>/dev/null
    fi
}

# --- Semgrep (SAST) ---
run_semgrep() {
    local output_file="${SCAN_OUTPUT_DIR}/semgrep.json"
    log "  Starting Semgrep..."
    semgrep scan --config auto --json --output "$output_file" "$TARGET_DIR" 2>/dev/null
}

# --- GuardDog (supply chain behavioral analysis) ---
run_guarddog() {
    local output_file="${SCAN_OUTPUT_DIR}/guarddog.json"
    log "  Starting GuardDog..."
    # GuardDog scans individual packages; scan the deps directory if available
    local deps_dir="/opt/deps"
    local tmp_dir
    tmp_dir=$(mktemp -d)
    local scan_index=0

    # Scan Python deps if present
    if [ -d "${deps_dir}/python" ]; then
        for archive in "${deps_dir}/python"/*.tar.gz "${deps_dir}/python"/*.zip; do
            [ -f "$archive" ] || continue
            local result_file="${tmp_dir}/scan_${scan_index}.json"
            if guarddog pypi verify "$archive" --output-format json > "$result_file" 2>/dev/null; then
                ((scan_index++)) || true
            else
                # GuardDog may exit non-zero on findings; keep the output if produced
                if [ -s "$result_file" ]; then
                    ((scan_index++)) || true
                else
                    rm -f "$result_file"
                fi
            fi
        done
    fi

    # Scan npm deps if present
    if [ -d "${deps_dir}/node" ]; then
        for pkg_dir in "${deps_dir}/node"/*/package; do
            [ -d "$pkg_dir" ] || continue
            local result_file="${tmp_dir}/scan_${scan_index}.json"
            if guarddog npm verify "$pkg_dir" --output-format json > "$result_file" 2>/dev/null; then
                ((scan_index++)) || true
            else
                if [ -s "$result_file" ]; then
                    ((scan_index++)) || true
                else
                    rm -f "$result_file"
                fi
            fi
        done
    fi

    # Merge all individual scan results into a single JSON file
    python3 -c "
import json, glob, os
scans = []
for f in sorted(glob.glob(os.path.join('${tmp_dir}', 'scan_*.json'))):
    try:
        with open(f) as fh:
            scans.append(json.load(fh))
    except (json.JSONDecodeError, IOError):
        pass
with open('${output_file}', 'w') as out:
    json.dump({'scans': scans}, out, indent=2)
" 2>/dev/null || echo '{"scans":[]}' > "$output_file"

    rm -rf "$tmp_dir"
}

# --- OSV-Scanner (vulnerability scanner with MAL advisory support) ---
run_osv_scanner() {
    local output_file="${SCAN_OUTPUT_DIR}/osv-scanner.json"
    log "  Starting OSV-Scanner..."
    osv-scanner scan --recursive --format json --output "$output_file" "$TARGET_DIR" 2>/dev/null
}

# --- Gitleaks (secrets detection) ---
run_gitleaks() {
    local output_file="${SCAN_OUTPUT_DIR}/gitleaks.json"
    log "  Starting Gitleaks..."
    gitleaks detect --source "$TARGET_DIR" --report-format json --report-path "$output_file" 2>/dev/null
}

# Launch all parallel scanners in background subshells
# We use a temp directory for exit code tracking since background processes
# cannot update the parent shell's associative arrays directly
EXITCODE_DIR=$(mktemp -d)

(run_grype; echo $? > "${EXITCODE_DIR}/grype") &
PIDS["grype"]=$!

(run_semgrep; echo $? > "${EXITCODE_DIR}/semgrep") &
PIDS["semgrep"]=$!

(run_guarddog; echo $? > "${EXITCODE_DIR}/guarddog") &
PIDS["guarddog"]=$!

(run_osv_scanner; echo $? > "${EXITCODE_DIR}/osv-scanner") &
PIDS["osv-scanner"]=$!

(run_gitleaks; echo $? > "${EXITCODE_DIR}/gitleaks") &
PIDS["gitleaks"]=$!

# ---------------------------------------------------------------------------
# Wait for all parallel scanners to complete
# ---------------------------------------------------------------------------
log "Waiting for all scanners to complete..."

for tool in "${!PIDS[@]}"; do
    pid="${PIDS[$tool]}"
    # wait returns the exit code of the background process
    # We use || true because set -e would abort on non-zero
    wait "$pid" || true

    # Read the actual exit code from the temp file
    local_exit_code=0
    if [ -f "${EXITCODE_DIR}/${tool}" ]; then
        local_exit_code=$(cat "${EXITCODE_DIR}/${tool}")
    fi

    output_file="${SCAN_OUTPUT_DIR}/${tool}.json"

    if [ -f "$output_file" ] && [ -s "$output_file" ]; then
        if [ "$local_exit_code" -eq 0 ]; then
            TOOL_STATUS["$tool"]="success"
        else
            # Non-zero exit but output was produced — scanner found issues (expected)
            TOOL_STATUS["$tool"]="success (findings detected, exit code ${local_exit_code})"
        fi
    else
        TOOL_STATUS["$tool"]="failed (exit code ${local_exit_code}, no output)"
    fi

    log "  ${tool}: ${TOOL_STATUS[$tool]}"
done

# Clean up temp directory
rm -rf "$EXITCODE_DIR"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
log ""
log "=========================================="
log "  Scanner Execution Summary"
log "=========================================="

succeeded=0
failed=0

for tool in syft grype semgrep guarddog osv-scanner gitleaks; do
    status="${TOOL_STATUS[$tool]:-not run}"
    if [[ "$status" == failed* ]]; then
        log "  FAIL  ${tool}: ${status}"
        ((failed++)) || true
    else
        log "  OK    ${tool}: ${status}"
        ((succeeded++)) || true
    fi
done

log ""
log "  Total: $((succeeded + failed)) scanners, ${succeeded} succeeded, ${failed} failed"
log "=========================================="
log ""
log "Scan results written to: ${SCAN_OUTPUT_DIR}"
log "Scanner orchestration complete."
