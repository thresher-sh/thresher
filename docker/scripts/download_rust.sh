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

    # Try stable cargo vendor first, fall back to nightly for v4 lockfiles
    if ! retry_cmd 3 cargo vendor "$output_dir"; then
        if grep -q '"version"' Cargo.lock 2>/dev/null && \
           cargo vendor "$output_dir" 2>&1 | grep -q "Znext-lockfile-bump"; then
            echo "  Lockfile v4 detected, retrying with nightly flag..."
            retry_cmd 3 cargo -Znext-lockfile-bump vendor "$output_dir" || {
                echo "WARNING: cargo vendor failed (lockfile v4 incompatible)"
            }
        else
            echo "WARNING: cargo vendor failed"
        fi
    fi
}
