#!/bin/bash
# download_go.sh — Download Go dependencies via go mod vendor.

download_go() {
    local target_dir="$1"
    local deps_dir="$2"
    local output_dir="${deps_dir}/go"
    mkdir -p "$output_dir"

    if [ ! -f "${target_dir}/go.mod" ]; then
        return
    fi

    echo "Downloading Go dependencies..."
    # go mod vendor requires a writable copy of the module directory
    cp -r "$target_dir" /tmp/go-project
    cd /tmp/go-project
    retry_cmd 3 env GOMODCACHE=/tmp/gomodcache go mod vendor || {
        echo "WARNING: go mod vendor failed"
    }
    cp -r /tmp/go-project/vendor/* "$output_dir/" 2>/dev/null || true
}
