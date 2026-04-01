#!/bin/bash
# detect.sh — Detect ecosystems from indicator files.
# Sets DETECTED_ECOSYSTEMS array.

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
