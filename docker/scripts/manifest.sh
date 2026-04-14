#!/bin/bash
# manifest.sh — Write dep_manifest.json from the deps directory.

write_manifest() {
    local deps_dir="$1"
    local manifest="$2"

    # Use python3 for reliable JSON generation
    python3 /scripts/build_manifest.py "$deps_dir" > "$manifest"
    echo "Wrote manifest to ${manifest}"
}
