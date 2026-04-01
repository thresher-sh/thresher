#!/bin/bash
# download_rust.sh — Download Rust dependencies via cargo vendor.

download_rust() {
    local target_dir="$1"
    local deps_dir="$2"
    local output_dir="${deps_dir}/rust"
    mkdir -p "$output_dir"

    if [ ! -f "${target_dir}/Cargo.toml" ]; then
        return
    fi

    echo "Downloading Rust dependencies..."
    # cargo vendor requires a writable copy of the project
    cp -r "$target_dir" /tmp/rust-project
    cd /tmp/rust-project
    cargo vendor "$output_dir" 2>&1 || {
        echo "WARNING: cargo vendor failed"
    }
}
