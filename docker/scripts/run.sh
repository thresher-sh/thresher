#!/bin/bash
# run.sh — Container entrypoint. Detects ecosystems, downloads deps,
# writes manifest. No arguments needed — everything comes from /work.
set -euo pipefail

WORK_DIR="/work"
TARGET_DIR="${WORK_DIR}/target"
DEPS_DIR="${WORK_DIR}/deps"
MANIFEST="${DEPS_DIR}/dep_manifest.json"

mkdir -p "$DEPS_DIR"

# ── Retry Helper ───────────────────────────────────────────────────
# retry_cmd MAX_RETRIES COMMAND [ARGS...]
# Retries a command with exponential backoff (2s, 4s, 8s, ...).
# Returns 0 on success, or the last exit code after all retries fail.
retry_cmd() {
    local max_retries="$1"; shift
    local delay=2
    local attempt=0
    while [ $attempt -lt "$max_retries" ]; do
        if "$@" 2>&1; then
            return 0
        fi
        attempt=$((attempt + 1))
        if [ $attempt -lt "$max_retries" ]; then
            echo "  Retry $attempt/$max_retries in ${delay}s..."
            sleep $delay
            delay=$((delay * 2))
        fi
    done
    return 1
}
export -f retry_cmd

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

# ── Hidden Dependencies (from Stage 1 AI agent) ────────────────────
HIDDEN_DEPS="${DEPS_DIR}/hidden_deps.json"
if [ -f "$HIDDEN_DEPS" ]; then
    source /scripts/download_hidden.sh
    download_hidden "$HIDDEN_DEPS" "$DEPS_DIR"
fi

# ── Write Manifest ──────────────────────────────────────────────────
source /scripts/manifest.sh
write_manifest "$DEPS_DIR" "$MANIFEST"

echo "Dependency resolution complete."
