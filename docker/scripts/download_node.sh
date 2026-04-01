#!/bin/bash
# download_node.sh — Download Node.js dependencies source-only via npm pack.

download_node() {
    local target_dir="$1"
    local deps_dir="$2"
    local output_dir="${deps_dir}/node"
    mkdir -p "$output_dir"

    if [ ! -f "${target_dir}/package.json" ]; then
        return
    fi

    echo "Downloading Node.js dependencies..."
    cd "$output_dir"

    # Extract dependency names from package.json and npm pack each one.
    # npm pack downloads the registry tarball without executing install scripts.
    node -e "
        const pkg = require('${target_dir}/package.json');
        const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
        Object.entries(deps).forEach(([name, ver]) => console.log(name + '@' + ver));
    " | while read -r pkgspec; do
        echo "  Packing ${pkgspec}"
        npm pack "${pkgspec}" 2>&1 || echo "  WARNING: Failed to pack ${pkgspec}"
    done
}
