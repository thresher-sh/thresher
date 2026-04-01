#!/usr/bin/env python3
"""Build a JSON manifest of downloaded dependencies.

Walks the deps directory, extracts package name/version from filenames,
and writes a clean JSON manifest to stdout.
"""

import json
import os
import re
import sys


def parse_package_name(filename: str, ecosystem: str) -> tuple[str, str]:
    """Extract (name, version) from a downloaded artifact filename."""
    if ecosystem == "python":
        for suffix in (".tar.gz", ".zip"):
            if filename.endswith(suffix):
                base = filename[: -len(suffix)]
                parts = base.rsplit("-", 1)
                if len(parts) == 2 and parts[1] and parts[1][0].isdigit():
                    return parts[0], parts[1]
                return base, "unknown"
        return filename, "unknown"

    elif ecosystem == "node":
        if filename.endswith(".tgz"):
            base = filename[: -len(".tgz")]
            parts = base.rsplit("-", 1)
            if len(parts) == 2 and parts[1] and parts[1][0].isdigit():
                return parts[0], parts[1]
            return base, "unknown"
        return filename, "unknown"

    elif ecosystem in ("rust", "go"):
        parts = filename.rsplit("-", 1)
        if len(parts) == 2 and parts[1] and parts[1][0].isdigit():
            return parts[0], parts[1]
        return filename, "unknown"

    return filename, "unknown"


def build_manifest(deps_dir: str) -> dict:
    """Walk deps directory and build the manifest."""
    manifest = {}

    if not os.path.isdir(deps_dir):
        return {"ecosystems": [], "dependencies": []}

    for ecosystem in sorted(os.listdir(deps_dir)):
        eco_path = os.path.join(deps_dir, ecosystem)
        if not os.path.isdir(eco_path):
            continue
        if ecosystem not in ("python", "node", "rust", "go"):
            continue

        packages = []
        for entry in sorted(os.listdir(eco_path)):
            if entry.startswith("_"):
                continue  # skip temp files like _pipfile_reqs.txt
            name, version = parse_package_name(entry, ecosystem)
            packages.append({
                "name": name,
                "version": version,
                "ecosystem": ecosystem,
                "path": os.path.join(eco_path, entry),
            })

        manifest[ecosystem] = packages

    return manifest


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <deps_dir>", file=sys.stderr)
        sys.exit(1)

    result = build_manifest(sys.argv[1])
    json.dump(result, sys.stdout, indent=2)
    print()  # trailing newline
