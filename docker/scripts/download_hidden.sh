#!/bin/bash
# download_hidden.sh — Download hidden dependencies discovered by the
# Stage 1 pre-dep AI agent. Reads hidden_deps.json and fetches each
# entry based on its type classification.

download_hidden() {
    local hidden_deps_file="$1"
    local deps_dir="$2"
    local output_dir="${deps_dir}/hidden"
    mkdir -p "$output_dir"

    local count
    count=$(python3 -c "
import json, sys
with open('${hidden_deps_file}') as f:
    data = json.load(f)
deps = data.get('hidden_dependencies', [])
print(len(deps))
" 2>/dev/null || echo "0")

    if [ "$count" = "0" ]; then
        echo "No hidden dependencies to download."
        return
    fi

    echo "Downloading ${count} hidden dependencies..."

    # Process each hidden dependency entry
    python3 -c "
import json, subprocess, os, sys, shlex

with open('${hidden_deps_file}') as f:
    data = json.load(f)

deps = data.get('hidden_dependencies', [])
high_risk_dep = data.get('high_risk_dep', False)
output_dir = '${output_dir}'
skipped_high_risk = []

for i, dep in enumerate(deps):
    dep_type = dep.get('type', 'unknown')
    source = dep.get('source', '')
    confidence = dep.get('confidence', 'low')
    risk = dep.get('risk', 'medium')
    found_in = dep.get('found_in', 'unknown')

    if not source:
        print(f'  [{i+1}/{len(deps)}] SKIP: no source URL')
        continue

    # Only fetch high/medium confidence entries
    if confidence == 'low':
        print(f'  [{i+1}/{len(deps)}] SKIP (low confidence): {source}')
        continue

    # Skip high-risk entries unless --high-risk-dep flag was set
    if risk == 'high' and not high_risk_dep:
        print(f'  [{i+1}/{len(deps)}] SKIP (high-risk, use --high-risk-dep to download): {source}')
        skipped_high_risk.append(dep)
        continue

    risk_label = f' [RISK:{risk}]' if risk == 'high' else ''
    print(f'  [{i+1}/{len(deps)}] {dep_type}{risk_label}: {source} (from {found_in})')

    try:
        if dep_type == 'git':
            # Hardened git clone — no checkout hooks, depth=1
            dest = os.path.join(output_dir, f'git-{i}')
            subprocess.run([
                'git', 'clone',
                '--no-checkout', '--depth=1', '--single-branch',
                '-c', 'core.hooksPath=/dev/null',
                '-c', 'core.fsmonitor=false',
                '-c', 'protocol.file.allow=never',
                '-c', 'protocol.ext.allow=never',
                source, dest
            ], timeout=120, capture_output=True)
            # Safe checkout
            subprocess.run(
                ['git', 'checkout'],
                cwd=dest, timeout=60, capture_output=True,
                env={**os.environ, 'GIT_LFS_SKIP_SMUDGE': '1', 'GIT_TERMINAL_PROMPT': '0'}
            )
            print(f'    -> cloned to {dest}')

        elif dep_type == 'submodule':
            # Same as git but source might be a relative path
            dest = os.path.join(output_dir, f'submodule-{i}')
            subprocess.run([
                'git', 'clone',
                '--no-checkout', '--depth=1',
                '-c', 'core.hooksPath=/dev/null',
                '-c', 'core.fsmonitor=false',
                source, dest
            ], timeout=120, capture_output=True)
            subprocess.run(
                ['git', 'checkout'],
                cwd=dest, timeout=60, capture_output=True,
                env={**os.environ, 'GIT_LFS_SKIP_SMUDGE': '1', 'GIT_TERMINAL_PROMPT': '0'}
            )
            print(f'    -> cloned submodule to {dest}')

        elif dep_type in ('npm', 'pypi', 'cargo', 'go'):
            # Package manager install — download source only
            pkg_dir = os.path.join(output_dir, f'{dep_type}-{i}')
            os.makedirs(pkg_dir, exist_ok=True)

            if dep_type == 'npm':
                subprocess.run(
                    ['npm', 'pack', source],
                    cwd=pkg_dir, timeout=120, capture_output=True
                )
            elif dep_type == 'pypi':
                subprocess.run(
                    ['pip3', 'download', '--no-binary', ':all:', '-d', pkg_dir, source],
                    timeout=120, capture_output=True
                )
            elif dep_type == 'cargo':
                # cargo doesn't have a direct download-only; skip for now
                print(f'    -> cargo hidden deps not yet supported, flagged for scanning')
            elif dep_type == 'go':
                # go get without install
                print(f'    -> go hidden deps not yet supported, flagged for scanning')
            print(f'    -> downloaded to {pkg_dir}')

        elif dep_type == 'url':
            # Download a URL — could be a tarball, script, or binary
            dest_file = os.path.join(output_dir, f'url-{i}')
            os.makedirs(dest_file, exist_ok=True)
            # Use curl with safe defaults — no following redirects to file://
            subprocess.run([
                'curl', '-fsSL',
                '--max-time', '60',
                '--max-filesize', str(50 * 1024 * 1024),  # 50MB limit
                '-o', os.path.join(dest_file, 'download'),
                '--proto', '=https,http',
                source
            ], timeout=90, capture_output=True)
            print(f'    -> downloaded to {dest_file}')

        elif dep_type == 'docker':
            # Docker base images — just log for scanner awareness
            print(f'    -> Docker image noted for analysis: {source}')

        else:
            print(f'    -> unknown type, skipped')

    except subprocess.TimeoutExpired:
        print(f'    -> TIMEOUT downloading {source}')
    except Exception as e:
        print(f'    -> ERROR: {e}')

# Write skipped high-risk entries to a separate file for the report
if skipped_high_risk:
    skipped_path = os.path.join(output_dir, 'skipped_high_risk.json')
    with open(skipped_path, 'w') as f:
        json.dump(skipped_high_risk, f, indent=2)
    print(f'')
    print(f'WARNING: {len(skipped_high_risk)} high-risk dependencies were NOT downloaded.')
    print(f'These will be flagged in the final report.')
    print(f'Use --high-risk-dep to download them if you are confident.')
    for dep in skipped_high_risk:
        print(f'  - [{dep.get(\"type\")}] {dep.get(\"source\")} (from {dep.get(\"found_in\")})')
"
}
